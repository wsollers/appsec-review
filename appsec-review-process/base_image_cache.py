#!/usr/bin/env python3
"""Host-side base-image cache and offline OS-package inventory (P41).

``fetch`` is the only network code. It runs on the host OUTSIDE B13 (orchestrator/prepare-host.sh),
like the OSV/NVD feed sync: each Dockerfile ``FROM`` reference is resolved against the OCI distribution
API over plain HTTPS (an anonymous bearer token wherever the registry asks for one: Docker Hub, gcr.io),
and every index, manifest, config and layer blob is stored content-addressed:

    <root>/blobs/sha256/<hex>     the blob; its name is the sha256 of its bytes
    <root>/current.json           {"refs_digest": "sha256:..."}: the reference table, itself a blob

``current.json`` is replaced last, so a reader sees one hash-bound snapshot (pointer -> refs -> manifest
-> layers) and every blob is re-hashed on read. A tag-only reference is resolved to a digest here and
recorded as mutable; a digest-pinned one must hash to its pin. A reference that cannot be fetched is
recorded with its cause, and stays a gap downstream.

``inventory`` never touches the network: 02-iac-config-scan reads the published cache, applies the
layers in order (with whiteouts) to the few paths that identify the OS and its packages, and returns
CycloneDX-like components with ``pkg:deb`` / ``pkg:apk`` purls and distro qualifiers. An image we could
not read is reported as not inventoried, never as an empty inventory.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
from typing import Any, Callable, Iterable
from urllib.parse import quote, urlencode, urlsplit
import urllib.error
import urllib.request

import iac_files
from execution_state import atomic_bytes, atomic_json

REFS_SCHEMA = "appsec-review/base-image-cache-refs/1"
POINTER_SCHEMA = "appsec-review/base-image-cache-current/1"
DEFAULT_PLATFORM = "linux/amd64"
DOCKER_HUB, API_HOSTS = "docker.io", {"docker.io": "registry-1.docker.io", "index.docker.io": "registry-1.docker.io"}
USER_AGENT = "appsec-review-base-image-cache/1"
ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json"])
MAX_BLOB_BYTES = 2 * 1024 ** 3
MAX_MEMBER_BYTES = 64 * 1024 ** 2
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EOL_TABLE = Path(__file__).resolve().parents[1] / "data" / "base-image-eol.json"
FROM = re.compile(r"\s*FROM\s+(.*)", re.I)

Transport = Callable[[str, str, dict], tuple[int, dict, bytes]]


class FetchFailed(RuntimeError):
    """A reference could not be resolved; ``str()`` is the recorded cause slug."""


class CacheInvalid(RuntimeError):
    """The published cache does not verify; ``str()`` is the reason slug."""


def cache_root() -> Path:
    configured = os.environ.get("APPSEC_BASE_IMAGE_ROOT")
    return Path(configured) if configured else Path(__file__).resolve().parents[1] / "data" / "feeds" / "base-images"


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- references -----------------------------------------------------------------------------------

def parse_reference(token: str) -> dict[str, Any]:
    """``[registry/]repository[:tag][@digest]``. The digest is split off first and a tag is looked for
    only after the last '/', so neither ``repo:tag@sha256:...`` (P41: the tag ended up in the repository)
    nor a registry port (``host:5000/x``) is misread. ``name`` is the reference as declared, without
    tag or digest; ``registry``/``path`` are the normalized pull coordinates."""
    name, _, digest = token.partition("@")
    head, slash, last = name.rpartition("/")
    last, colon, tag = last.partition(":")
    name = head + slash + last
    first = name.split("/", 1)[0]
    if "/" in name and ("." in first or ":" in first or first == "localhost"):
        registry, path = name.split("/", 1)
    else:
        registry, path = DOCKER_HUB, name
    registry = DOCKER_HUB if registry in API_HOSTS else registry
    if registry == DOCKER_HUB and "/" not in path:
        path = "library/" + path
    return {"name": name, "registry": registry, "path": path, "tag": tag if colon else None,
            "digest": digest or None}


def reference_key(reference: dict, platform: str) -> str:
    return (f"{reference['registry']}/{reference['path']}" + (f":{reference['tag']}" if reference["tag"] else "")
            + (f"@{reference['digest']}" if reference["digest"] else "") + f"|{platform}")


def from_lines(text: str) -> list[tuple[int, str, str]]:
    """(line, form, token) per FROM: ``literal``, ``scratch``, ``build-arg-parameterized`` or
    ``build-stage-alias`` (a name an earlier ``FROM ... AS name`` introduced). ``--platform=`` and other
    flags are skipped, never taken for the image."""
    values, aliases = [], set()
    for line_no, line in enumerate(text.splitlines(), 1):
        match = FROM.match(line)
        if not match:
            continue
        words = [w for w in match.group(1).split() if not w.startswith("--")]
        if not words:
            continue
        token = words[0]
        if token.lower() == "scratch": form = "scratch"
        elif "$" in token: form = "build-arg-parameterized"
        elif token.lower() in aliases: form = "build-stage-alias"
        else: form = "literal"
        if len(words) >= 3 and words[1].lower() == "as":
            aliases.add(words[2].lower())
        values.append((line_no, form, token))
    return values


def dockerfile_references(sources: Iterable[Path]) -> list[str]:
    tokens = set()
    for source in sources:
        for path in sorted(Path(source).rglob("*")):
            relative = path.relative_to(source).as_posix()
            if path.is_file() and not path.is_symlink() and "/.git/" not in f"/{relative}" and iac_files.containerfile(relative):
                tokens |= {t for _, form, t in from_lines(path.read_text(errors="replace")) if form == "literal"}
    return sorted(tokens)


# ---- the published cache --------------------------------------------------------------------------

def _blob_path(root: Path, digest: str) -> Path:
    if not DIGEST.fullmatch(digest):
        raise CacheInvalid("digest-malformed")
    return Path(root) / "blobs" / "sha256" / digest.split(":", 1)[1]


def read_blob(root: Path, digest: str) -> bytes:
    path = _blob_path(root, digest)
    if not path.is_file():
        raise CacheInvalid("blob-missing")
    data = path.read_bytes()
    if _sha(data) != digest:
        raise CacheInvalid("blob-hash-mismatch")
    return data


def write_blob(root: Path, data: bytes) -> str:
    digest = _sha(data)
    path = _blob_path(root, digest)
    if not (path.is_file() and _sha(path.read_bytes()) == digest):
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_bytes(path, data)
    return digest


def load_refs(root: Path) -> tuple[dict, str] | None:
    """The published reference table and its digest; None when nothing was published. Raises
    CacheInvalid when the pointer or table does not verify."""
    pointer = Path(root) / "current.json"
    if not pointer.is_file():
        return None
    try:
        value = json.loads(pointer.read_text(encoding="utf-8"))
    except ValueError:
        raise CacheInvalid("pointer-invalid") from None
    if value.get("schema") != POINTER_SCHEMA or not DIGEST.fullmatch(str(value.get("refs_digest"))):
        raise CacheInvalid("pointer-invalid")
    refs = json.loads(read_blob(root, value["refs_digest"]))
    if refs.get("schema") != REFS_SCHEMA or not isinstance(refs.get("entries"), dict):
        raise CacheInvalid("refs-invalid")
    return refs, value["refs_digest"]


def publish_refs(root: Path, entries: dict[str, dict], now: str) -> dict:
    refs = {"schema": REFS_SCHEMA, "published_at": now, "entries": dict(sorted(entries.items()))}
    digest = write_blob(root, (json.dumps(refs, sort_keys=True, indent=2) + "\n").encode())
    atomic_json(Path(root) / "current.json", {"schema": POINTER_SCHEMA, "refs_digest": digest, "published_at": now})
    return refs


def lookup(root: Path, token: str, platform: str = DEFAULT_PLATFORM) -> tuple[dict | None, str | None]:
    """(entry, None) for a published reference, or (None, reason): cache-unavailable, not-in-cache, or
    the CacheInvalid reason."""
    try:
        loaded = load_refs(root)
    except CacheInvalid as exc:
        return None, str(exc)
    if loaded is None:
        return None, "cache-unavailable"
    entry = loaded[0]["entries"].get(reference_key(parse_reference(token), platform))
    return (entry, None) if entry else (None, "not-in-cache")


def identity(root: Path) -> dict | None:
    """What a job binds into its evidence and fingerprint: the published table digest, or None."""
    try:
        loaded = load_refs(root)
    except CacheInvalid as exc:
        return {"refs_digest": None, "invalid": str(exc)}
    return None if loaded is None else {"refs_digest": loaded[1], "published_at": loaded[0]["published_at"]}


# ---- fetch (host only, network) -------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def urllib_transport(method: str, url: str, headers: dict) -> tuple[int, dict, bytes]:
    """One HTTPS request, redirects NOT followed (the caller decides which headers survive a hop)."""
    if urlsplit(url).scheme != "https":
        raise FetchFailed("non-https-url")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        response = opener.open(request, timeout=300)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        declared = response.headers.get("Content-Length")
        if declared is not None and int(declared) > MAX_BLOB_BYTES:
            raise FetchFailed("blob-size-limit")
        body = response.read(MAX_BLOB_BYTES + 1)
        if len(body) > MAX_BLOB_BYTES:
            raise FetchFailed("blob-size-limit")
        return response.status, {k.lower(): v for k, v in response.headers.items()}, body


class _Registry:
    def __init__(self, reference: dict, transport: Transport, host: str | None = None):
        self.host = host or API_HOSTS.get(reference["registry"], reference["registry"])
        self.base, self.transport, self.token = f"https://{self.host}/v2/{reference['path']}", transport, None

    def _hop(self, url: str, headers: dict) -> tuple[int, dict, bytes]:
        origin = urlsplit(url).netloc
        for _ in range(6):
            status, got, body = self.transport("GET", url, headers)
            got = {k.lower(): v for k, v in got.items()}
            if status not in (301, 302, 303, 307, 308):
                return status, got, body
            url = got.get("location", "")
            if urlsplit(url).scheme != "https":
                raise FetchFailed("redirect-not-https")
            if urlsplit(url).netloc != origin:   # a presigned CDN URL: the registry token stays home
                headers = {k: v for k, v in headers.items() if k != "Authorization"}
        raise FetchFailed("redirect-loop")

    def _bearer(self, challenge: str) -> str:
        if not challenge.lower().startswith("bearer "):
            raise FetchFailed("auth-unsupported")
        params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        if urlsplit(params.get("realm", "")).scheme != "https":
            raise FetchFailed("auth-unsupported")
        query = urlencode({k: params[k] for k in ("service", "scope") if k in params})
        status, _, body = self._hop(params["realm"] + ("?" + query if query else ""), {"User-Agent": USER_AGENT})
        if status != 200:
            raise FetchFailed(f"auth-http-{status}")
        value = json.loads(body)
        token = value.get("token") or value.get("access_token")
        if not token:
            raise FetchFailed("auth-no-token")
        return token

    def get(self, suffix: str, accept: str | None = None) -> tuple[dict, bytes]:
        for _ in range(2):
            headers = {"User-Agent": USER_AGENT, **({"Accept": accept} if accept else {}),
                       **({"Authorization": "Bearer " + self.token} if self.token else {})}
            status, got, body = self._hop(self.base + suffix, headers)
            if status == 401 and self.token is None:
                self.token = self._bearer(got.get("www-authenticate", ""))
                continue
            break
        if status != 200:
            raise FetchFailed(f"http-{status}")
        return got, body

    def blob(self, root: Path, digest: str, *, manifest: bool = False) -> bytes:
        try:
            return read_blob(root, digest)
        except CacheInvalid:
            pass
        _, body = self.get(("/manifests/" if manifest else "/blobs/") + digest, ACCEPT if manifest else None)
        if _sha(body) != digest:
            raise FetchFailed("digest-mismatch")
        write_blob(root, body)
        return body


def _platform_match(entry: dict, platform: str) -> bool:
    os_name, arch, *variant = platform.split("/")
    found = entry.get("platform") or {}
    return (found.get("os"), found.get("architecture")) == (os_name, arch) and (
        not variant or found.get("variant") == variant[0])


def fetch_one(token: str, root: Path, *, platform: str, transport: Transport, now: str,
              mirrors: dict[str, str] | None = None) -> dict:
    """The registry first; on failure, a configured mirror of it (``docker.io=mirror.gcr.io`` when Docker
    Hub rate-limits the host). Every blob is hash-checked either way; ``served_by`` records the host."""
    reference = parse_reference(token)
    hosts = [None] + ([mirrors[reference["registry"]]] if (mirrors or {}).get(reference["registry"]) else [])
    tried = []
    for host in hosts:
        tried.append(_fetch_from(reference, token, root, platform=platform, transport=transport, now=now, host=host))
        if tried[-1]["status"] == "resolved":
            return tried[-1]
    return tried[0]   # the registry's own cause (e.g. http-429), not the mirror's


def _fetch_from(reference: dict, token: str, root: Path, *, platform: str, transport: Transport, now: str,
                host: str | None) -> dict:
    registry = _Registry(reference, transport, host)
    entry = {"reference": token, "registry": reference["registry"], "repository": reference["path"],
             "tag": reference["tag"], "declared_digest": reference["digest"], "platform": platform,
             "mutable": reference["digest"] is None, "status": "failed", "cause": None, "index_digest": None,
             "manifest_digest": None, "config_digest": None, "layers": [], "resolved_at": now,
             "served_by": registry.host}
    try:
        if reference["digest"] and not DIGEST.fullmatch(reference["digest"]):
            raise FetchFailed("digest-unsupported")
        target = reference["digest"] or reference["tag"] or "latest"
        if reference["digest"]:
            top = registry.blob(root, target, manifest=True)
        else:
            _, top = registry.get("/manifests/" + target, ACCEPT)
            write_blob(root, top)
        document, top_digest = json.loads(top), _sha(top)
        if document.get("schemaVersion") != 2:
            raise FetchFailed("manifest-schema-unsupported")
        if "manifests" in document:
            chosen = [m for m in document["manifests"] if _platform_match(m, platform)]
            if not chosen:
                raise FetchFailed("platform-not-found")
            entry["index_digest"], digest = top_digest, chosen[0]["digest"]
            document = json.loads(registry.blob(root, digest, manifest=True))
        else:
            digest = top_digest
        entry["manifest_digest"] = digest
        entry["config_digest"] = document["config"]["digest"]
        registry.blob(root, entry["config_digest"])
        for item in document["layers"]:
            registry.blob(root, item["digest"])
            entry["layers"].append({"digest": item["digest"], "media_type": item.get("mediaType"),
                                    "size": item.get("size")})
        entry.update(status="resolved")
    except FetchFailed as exc:
        entry.update(cause=str(exc), index_digest=None, manifest_digest=None, config_digest=None, layers=[])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        entry.update(cause=re.sub(r"[^0-9a-z]+", "-", type(exc).__name__.lower()).strip("-")[:40],
                     index_digest=None, manifest_digest=None, config_digest=None, layers=[])
    return entry


def fetch(tokens: Iterable[str], root: Path, *, platform: str = DEFAULT_PLATFORM,
          transport: Transport | None = None, now: str | None = None, mirrors: dict[str, str] | None = None) -> dict:
    """Resolve and store each reference, then publish the merged table. A digest-pinned reference
    already resolved is kept (its content cannot change); a tag is re-resolved every time."""
    root, now, transport = Path(root), now or _now(), transport or urllib_transport
    try:
        loaded = load_refs(root)
    except CacheInvalid:
        loaded = None
    entries = dict(loaded[0]["entries"]) if loaded else {}
    for token in tokens:
        key = reference_key(parse_reference(token), platform)
        previous = entries.get(key)
        if previous and previous["status"] == "resolved" and not previous["mutable"]:
            try:
                for digest in [previous["manifest_digest"], previous["config_digest"]] + [l["digest"] for l in previous["layers"]]:
                    read_blob(root, digest)
                continue
            except CacheInvalid:
                pass
        entry = fetch_one(token, root, platform=platform, transport=transport, now=now, mirrors=mirrors)
        # A tag that fails to re-resolve keeps its last good resolution (and its resolved_at).
        entries[key] = previous if entry["status"] != "resolved" and previous and previous["status"] == "resolved" else entry
    return publish_refs(root, entries, now)


# ---- inventory (offline) --------------------------------------------------------------------------

WANTED = ("etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status", "lib/apk/db/installed")
WANTED_DIRS = ("var/lib/dpkg/status.d/", "var/lib/rpm/", "usr/lib/sysimage/rpm/")


def _wanted(name: str) -> bool:
    return name in WANTED or name.startswith(WANTED_DIRS)


def _norm(name: str) -> str:
    return PurePosixPath("/" + name).as_posix().lstrip("/")


def _layer_files(data: bytes, files: dict[str, bytes], links: dict[str, str]) -> None:
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError:
        raise CacheInvalid("layer-format-unsupported") from None
    added, linked, removed, opaque = {}, {}, [], []
    with tar:
        for member in tar:
            name = _norm(member.name)
            parent, base = name.rpartition("/")[0], name.rpartition("/")[2]
            if base == ".wh..wh..opq":
                opaque.append(parent + "/" if parent else "")
            elif base.startswith(".wh."):
                removed.append((parent + "/" if parent else "") + base[4:])
            elif _wanted(name) and member.isfile():
                if member.size > MAX_MEMBER_BYTES:
                    raise CacheInvalid("package-database-size-limit")
                added[name] = b"" if "/rpm/" in f"/{name}" else tar.extractfile(member).read()
            elif _wanted(name) and member.issym():
                linked[name] = member.linkname
    for prefix in opaque:
        for store in (files, links):
            for name in [n for n in store if n.startswith(prefix)]: del store[name]
    for gone in removed:
        for store in (files, links):
            for name in [n for n in store if n == gone or n.startswith(gone + "/")]: del store[name]
    for name in list(added) + list(linked):
        files.pop(name, None); links.pop(name, None)
    files.update(added); links.update(linked)


def _os_release(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        key, eq, value = line.strip().partition("=")
        if eq and re.fullmatch(r"[A-Z_]+", key):
            values[key] = value.strip().strip("'\"")
    return values


def _paragraphs(text: str) -> Iterable[dict[str, str]]:
    for block in re.split(r"\n\s*\n", text):
        fields, key = {}, None
        for line in block.splitlines():
            if line[:1] in (" ", "\t") and key:
                continue
            key, _, value = line.partition(":")
            fields[key] = value.strip()
        if fields:
            yield fields


def _purl(kind: str, namespace: str, name: str, version: str, arch: str | None, distro: str) -> str:
    qualifiers = "&".join(f"{k}={quote(v, safe='.-_~')}" for k, v in (("arch", arch), ("distro", distro)) if v)
    return f"pkg:{kind}/{namespace}/{quote(name, safe='.-_~+')}@{quote(version, safe='.-_~:')}" + (
        f"?{qualifiers}" if qualifiers else "")


def _dpkg(text: str, system: dict, distro: str, *, status_file: bool) -> list[dict]:
    """``status_file``: the dpkg status database, where only ``Status: ... installed`` counts. A
    distroless ``status.d/<package>`` entry carries no Status field and is installed by being there."""
    values = []
    for fields in _paragraphs(text):
        installed = fields.get("Status", "").split()[-1:] == ["installed"] or not status_file and "Status" not in fields
        if not installed or not fields.get("Package") or not fields.get("Version"):
            continue
        source = fields.get("Source", "").split(" ")[0] or None
        values.append({"name": fields["Package"], "version": fields["Version"], "source_package": source,
                       "purl": _purl("deb", system["ID"], fields["Package"].lower(), fields["Version"],
                                     fields.get("Architecture"), distro)})
    return values


def _apk(text: str, system: dict, distro: str) -> list[dict]:
    return [{"name": f["P"], "version": f["V"], "source_package": f.get("o") or None,
             "purl": _purl("apk", system["ID"], f["P"].lower(), f["V"], f.get("A"), distro)}
            for f in _paragraphs(text) if f.get("P") and f.get("V")]


def inventory(root: Path, entry: dict) -> dict:
    """Offline inventory of one resolved cache entry. Returns {"status", "reason", "os", "components"};
    status is ``inventoried``, ``no-package-database`` (examined; the image has none) or
    ``not-inventoried`` (a gap: the reason says why). Raises CacheInvalid on any hash failure."""
    manifest = json.loads(read_blob(root, entry["manifest_digest"]))
    layers = [item["digest"] for item in manifest["layers"]]
    if layers != [item["digest"] for item in entry["layers"]]:
        raise CacheInvalid("manifest-layers-mismatch")
    read_blob(root, manifest["config"]["digest"])
    files: dict[str, bytes] = {}; links: dict[str, str] = {}; origin: dict[str, str] = {}
    for digest in layers:
        before = dict(files)
        _layer_files(read_blob(root, digest), files, links)
        origin.update({n: digest for n, d in files.items() if before.get(n) is not d})
    for name, target in links.items():   # /etc/os-release -> ../usr/lib/os-release
        resolved = _norm(str(PurePosixPath(name).parent / target) if not target.startswith("/") else target)
        if resolved in files and name not in files:
            files[name] = files[resolved]; origin[name] = origin[resolved]
    text = (files.get("etc/os-release") or files.get("usr/lib/os-release") or b"").decode(errors="replace")
    system = _os_release(text)
    os_record = ({"id": system["ID"], "version_id": system.get("VERSION_ID")} if system.get("ID") else None)
    has_rpm = any(n.startswith(("var/lib/rpm/", "usr/lib/sysimage/rpm/")) for n in files)
    databases = [n for n in files if n in ("var/lib/dpkg/status", "lib/apk/db/installed")
                 or n.startswith("var/lib/dpkg/status.d/") and not n.endswith(".md5sums")]
    result = {"status": "not-inventoried", "reason": None, "os": os_record, "components": []}
    if not databases:
        result.update(reason="rpm-database-not-parsed") if has_rpm else result.update(status="no-package-database")
        return result
    if os_record is None or not system.get("VERSION_ID"):
        result.update(reason="os-release-missing")
        return result
    distro = f"{system['ID']}-{system['VERSION_ID']}"
    components = []
    for name in sorted(databases):
        text = files[name].decode(errors="replace")
        found = (_apk(text, system, distro) if name == "lib/apk/db/installed"
                 else _dpkg(text, system, distro, status_file=name == "var/lib/dpkg/status"))
        components += [{**item, "layer_digest": origin[name]} for item in found]
    components = list({c["purl"]: c for c in components}.values())
    result.update(status="inventoried", components=sorted(components, key=lambda c: c["purl"]))
    if has_rpm:
        result.update(status="not-inventoried", reason="rpm-database-not-parsed")
    return result


def load_eol_table(path: Path = EOL_TABLE) -> tuple[dict, str]:
    data = Path(path).read_bytes()
    return json.loads(data), _sha(data)


def eol_status(table: dict, system: dict | None, on: str) -> dict:
    """{"status": end-of-life | supported | not-listed, "support_end", "source_url"} for an os-release
    id/version on date ``on`` (YYYY-MM-DD). A release absent from the table is not-listed, never supported."""
    unknown = {"status": "not-listed", "support_end": None, "source_url": None}
    if not system or not system.get("version_id"):
        return unknown
    distribution = table["distributions"].get(system["id"])
    if distribution is None:
        return unknown
    version = system["version_id"]
    key = {"major": version.split(".")[0], "branch": ".".join(version.split(".")[:2])}.get(distribution["match"], version)
    release = next((r for r in distribution["releases"] if r["version"] == key), None)
    if release is None:
        return unknown
    return {"status": "end-of-life" if release["support_end"] < on else "supported",
            "support_end": release["support_end"], "source_url": release["source_url"]}


# ---- command line (host) --------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=("fetch", "status"))
    parser.add_argument("sources", nargs="+", type=Path, help="checkouts whose Dockerfiles name the images")
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--platform", default=DEFAULT_PLATFORM)
    parser.add_argument("--mirror", action="append", default=[], metavar="REGISTRY=HOST",
                        help="fallback host for a registry, e.g. docker.io=mirror.gcr.io (content is hash-checked)")
    args = parser.parse_args(argv)
    root = (args.root or cache_root()).absolute()
    tokens = dockerfile_references([s for s in args.sources if s.is_dir()])
    if args.command == "fetch":
        fetch(tokens, root, platform=args.platform, mirrors=dict(m.split("=", 1) for m in args.mirror))
    missing = 0
    for token in tokens:
        entry, reason = lookup(root, token, args.platform)
        state = entry["status"] if entry else reason
        cause = f" ({entry['cause']})" if entry and entry["cause"] else ""
        digest = f" {entry['manifest_digest']}" if entry and entry["manifest_digest"] else ""
        missing += state != "resolved"
        print(f"{state:<16} {token}{digest}{cause}")
    print(f"{len(tokens) - missing}/{len(tokens)} base images resolved in {root}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
