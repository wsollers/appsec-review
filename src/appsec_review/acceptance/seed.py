"""Known-good seed snapshots of an application run, taken after each accepted job.

A seed freezes ``runs/<app-run>/`` exactly as it stood after job N was accepted, plus the shared
host inputs a job can read (``runs/metadata/`` and ``data/``). Bytes live once in a
content-addressed blob store outside git; the committed manifest lists every entry (path, type,
sha256, size, mode, owner role) as a delta against the previous seed of the same walk, so a chain
of manifests resolves to the full per-file listing.

Restoring keeps the original run id. The run id is embedded in hashed artifacts (the retrieval
manifests a handoff names carry ``run_id``), so rewriting it would change artifact digests, handoff
digests and every downstream upstream-handoff identity; a different ``runtime.runs_dir`` changes
the resolved configuration a run is bound to. Restoration therefore recreates ``runs/<app-run>/``
byte-for-byte, after the caller has moved any existing tree of that id aside.

Paths in a manifest are POSIX paths relative to the repository root. Entries under
``runs/<app-run>/`` are the run tree: restored exactly, and on verify any extra entry is a finding.
Other entries are shared inputs: verified, and restored only on request.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat as stat_module
import tempfile
from typing import Any, Callable

SCHEMA = "appsec-review/acceptance-seed/1"
DEPLOYMENT_OWNER = "deployment"
SHARED_BYTES_LIMIT = 1024 * 1024


class SeedError(ValueError):
    """A seed cannot be written, resolved or restored as asked."""


@dataclass(frozen=True, order=True)
class SeedIssue:
    kind: str  # missing | extra | type | sha256 | size | mode | owner | symlink | unrestorable
    path: str
    detail: str = ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def owner_role(uid: int, gid: int, expected_uid: int, expected_gid: int) -> str:
    return DEPLOYMENT_OWNER if (uid, gid) == (expected_uid, expected_gid) else f"{uid}:{gid}"


class BlobStore:
    """Content-addressed, read-only blobs: ``<root>/blobs/<aa>/<sha256>``."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def path(self, digest: str) -> Path:
        return self.root / "blobs" / digest[:2] / digest

    def has(self, digest: str) -> bool:
        return self.path(digest).is_file()

    def put(self, source: Path, digest: str) -> bool:
        """Copy ``source`` in when absent; returns whether bytes were added."""
        destination = self.path(digest)
        if destination.is_file():
            return False
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=destination.parent)
        os.close(descriptor)
        try:
            shutil.copyfile(source, temporary)
            if _sha256(Path(temporary)) != digest:
                raise SeedError(f"{source} changed while it was being captured")
            os.chmod(temporary, 0o444)
            os.replace(temporary, destination)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise
        return True


def scan(repository_root: Path, relative_roots: Iterable[str], *, expected_uid: int, expected_gid: int,
         exclude: Iterable[str] = (), cache: Mapping[str, Mapping[str, Any]] | None = None,
         lstat: Callable[[str], os.stat_result] = os.lstat) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Per-entry listing of ``relative_roots`` and a stat cache that skips rehashing unchanged files."""

    repository_root = Path(repository_root)
    excluded = {item.rstrip("/") for item in exclude}
    entries: dict[str, dict[str, Any]] = {}
    new_cache: dict[str, Any] = {}
    cache = cache or {}

    def record(relative: str) -> None:
        info = lstat(str(repository_root / relative))
        entry: dict[str, Any] = {"mode": f"{stat_module.S_IMODE(info.st_mode):04o}",
                                 "owner": owner_role(info.st_uid, info.st_gid, expected_uid, expected_gid)}
        if stat_module.S_ISLNK(info.st_mode):
            entry.update(type="symlink", target=os.readlink(repository_root / relative))
        elif stat_module.S_ISDIR(info.st_mode):
            entry["type"] = "dir"
        elif stat_module.S_ISREG(info.st_mode):
            key = [info.st_size, info.st_mtime_ns, info.st_ino]
            cached = cache.get(relative)
            digest = (cached["sha256"] if cached and cached.get("key") == key
                      else _sha256(repository_root / relative))
            new_cache[relative] = {"key": key, "sha256": digest}
            entry.update(type="file", sha256=digest, size=info.st_size)
        else:
            entry["type"] = "special"
        entries[relative] = entry

    for root in relative_roots:
        root = root.strip("/")
        if not (repository_root / root).exists() or root in excluded:
            continue
        record(root)
        for current, directories, files in os.walk(repository_root / root):
            base = Path(current).relative_to(repository_root).as_posix()
            directories[:] = sorted(name for name in directories if f"{base}/{name}" not in excluded)
            for name in [*directories, *sorted(files)]:
                record(f"{base}/{name}")
    return dict(sorted(entries.items())), new_cache


def delta(previous: Mapping[str, Mapping[str, Any]], current: Mapping[str, Mapping[str, Any]]):
    changed = {path: dict(entry) for path, entry in current.items() if previous.get(path) != entry}
    removed = sorted(set(previous) - set(current))
    return changed, removed


def full_digest(entries: Mapping[str, Mapping[str, Any]]) -> str:
    return hashlib.sha256(canonical(dict(sorted(entries.items())))).hexdigest()


def manifest_name(job_id: str) -> str:
    return f"after-{job_id}.manifest.json"


def write_manifest(path: Path, document: Mapping[str, Any]) -> None:
    """One entry per line so committed manifests diff and review well."""
    lines = ["{"]
    header = {key: value for key, value in document.items() if key not in {"entries", "removed"}}
    for key, value in sorted(header.items()):
        lines.append(f"{json.dumps(key)}: {json.dumps(value, sort_keys=True)},")
    lines.append('"removed": [')
    lines.append(",\n".join(json.dumps(item) for item in document.get("removed", [])))
    lines.append("],")
    lines.append('"entries": {')
    lines.append(",\n".join(f"{json.dumps(name)}: {json.dumps(entry, sort_keys=True)}"
                            for name, entry in sorted(document.get("entries", {}).items())))
    lines.append("}}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(line for line in lines if line != "") + "\n", encoding="utf-8")


def load_manifest(path: Path) -> dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA:
        raise SeedError(f"unsupported seed manifest schema: {path}")
    return document


def resolve_chain(manifest_root: Path, job_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Return the named seed's header and its full entry listing, verified link by link."""

    chain = []
    current: str | None = job_id
    while current is not None:
        document = load_manifest(Path(manifest_root) / manifest_name(current))
        chain.append(document)
        current = document.get("base")
        if len(chain) > 1000:
            raise SeedError("seed manifest chain does not terminate")
    entries: dict[str, dict[str, Any]] = {}
    for document in reversed(chain):
        if document.get("base") is not None and document.get("base_full_sha256") != full_digest(entries):
            raise SeedError(f"seed after-{document['after_job']} does not extend its recorded base")
        for path in document.get("removed", ()):
            entries.pop(path, None)
        entries.update({path: dict(entry) for path, entry in document.get("entries", {}).items()})
        if full_digest(entries) != document.get("full_sha256"):
            raise SeedError(f"seed after-{document['after_job']} entries do not match full_sha256")
    return chain[0], dict(sorted(entries.items()))


def snapshot(repository_root: Path, store: BlobStore, manifest_root: Path, *, tag: str, job_id: str,
             app_run_id: str, base_job: str | None, expected_uid: int, expected_gid: int,
             shared_roots: Iterable[str] = ("runs/metadata", "data"), exclude: Iterable[str] = (),
             extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Capture the run (and shared inputs) after ``job_id`` into ``store`` and write its manifest."""

    run_root = f"runs/{app_run_id}"
    cache_path = store.root / "stat-cache.json"
    cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.is_file() else {}
    entries, new_cache = scan(repository_root, [run_root, *shared_roots], expected_uid=expected_uid,
                              expected_gid=expected_gid, exclude=exclude, cache=cache)
    added_bytes = 0
    for path, entry in entries.items():
        if entry["type"] != "file":
            continue
        shared = not (path == run_root or path.startswith(run_root + "/"))
        if shared and entry["size"] > SHARED_BYTES_LIMIT:
            entry["stored"] = False
            continue
        if store.put(Path(repository_root) / path, entry["sha256"]):
            added_bytes += entry["size"]
    base_entries: dict[str, dict[str, Any]] = {}
    if base_job is not None:
        base_header, base_entries = resolve_chain(manifest_root, base_job)
        if base_header["application_run_id"] != app_run_id:
            raise SeedError("a seed's base must come from the same application run")
    changed, removed = delta(base_entries, entries)
    files = [entry for entry in entries.values() if entry["type"] == "file"]
    document = {
        "schema": SCHEMA, "corpus_tag": tag, "after_job": job_id, "application_run_id": app_run_id,
        "run_root": run_root, "shared_roots": sorted(shared_roots), "base": base_job,
        "base_full_sha256": full_digest(base_entries) if base_job is not None else None,
        "full_sha256": full_digest(entries),
        "totals": {"entries": len(entries), "files": len(files), "bytes": sum(item["size"] for item in files),
                   "run_bytes": sum(entries[path]["size"] for path in entries
                                    if entries[path]["type"] == "file" and path.startswith(run_root + "/")),
                   "added_blob_bytes": added_bytes},
        **dict(extra or {}),
        "removed": removed, "entries": changed,
    }
    write_manifest(Path(manifest_root) / manifest_name(job_id), document)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(new_cache, separators=(",", ":")), encoding="utf-8")
    return document


def _is_run_entry(path: str, run_root: str) -> bool:
    return path == run_root or path.startswith(run_root + "/")


def verify(repository_root: Path, header: Mapping[str, Any], entries: Mapping[str, Mapping[str, Any]], *,
           expected_uid: int, expected_gid: int, include_shared: bool = True,
           lstat: Callable[[str], os.stat_result] = os.lstat) -> list[SeedIssue]:
    """Compare the tree on disk with a resolved seed listing."""

    repository_root = Path(repository_root)
    run_root = header["run_root"]
    issues: list[SeedIssue] = []
    for path, entry in entries.items():
        if not include_shared and not _is_run_entry(path, run_root):
            continue
        try:
            info = lstat(str(repository_root / path))
        except FileNotFoundError:
            issues.append(SeedIssue("missing", path))
            continue
        kind = ("symlink" if stat_module.S_ISLNK(info.st_mode) else "dir" if stat_module.S_ISDIR(info.st_mode)
                else "file" if stat_module.S_ISREG(info.st_mode) else "special")
        if kind != entry["type"]:
            issues.append(SeedIssue("type", path, f"{kind} expected {entry['type']}"))
            continue
        if kind == "symlink":
            if os.readlink(repository_root / path) != entry["target"]:
                issues.append(SeedIssue("symlink", path, f"expected -> {entry['target']}"))
            continue
        mode = f"{stat_module.S_IMODE(info.st_mode):04o}"
        if mode != entry["mode"]:
            issues.append(SeedIssue("mode", path, f"{mode} expected {entry['mode']}"))
        role = owner_role(info.st_uid, info.st_gid, expected_uid, expected_gid)
        if role != entry["owner"]:
            issues.append(SeedIssue("owner", path, f"{role} expected {entry['owner']}"))
        if kind == "file":
            if info.st_size != entry["size"]:
                issues.append(SeedIssue("size", path, f"{info.st_size} expected {entry['size']}"))
            elif _sha256(repository_root / path) != entry["sha256"]:
                issues.append(SeedIssue("sha256", path))
    run_path = repository_root / run_root
    if run_path.is_dir():
        for current, directories, files in os.walk(run_path):
            base = Path(current).relative_to(repository_root).as_posix()
            for name in [*directories, *files]:
                if f"{base}/{name}" not in entries:
                    issues.append(SeedIssue("extra", f"{base}/{name}"))
    return sorted(issues)


def restore(repository_root: Path, store: BlobStore, header: Mapping[str, Any],
            entries: Mapping[str, Mapping[str, Any]], *, expected_uid: int, expected_gid: int,
            restore_shared: bool = False,
            chown: Callable[[str, int, int], None] = os.lchown) -> list[SeedIssue]:
    """Recreate the run tree (and, on request, drifted shared inputs) from the store, then verify.

    The run tree must not exist. Returns the remaining verification issues; shared inputs that
    drifted and were not restored are reported, never silently accepted.
    """

    repository_root = Path(repository_root)
    run_root = header["run_root"]
    if (repository_root / run_root).exists():
        raise SeedError(f"{run_root} exists; move it aside before restoring")
    missing_blobs = sorted(entry["sha256"] for entry in entries.values()
                           if entry["type"] == "file" and entry.get("stored", True)
                           and not store.has(entry["sha256"]))
    if missing_blobs:
        raise SeedError(f"seed store lacks {len(missing_blobs)} blobs, e.g. {missing_blobs[0]}")
    shared_drift = {issue.path for issue in verify(repository_root, header, {
        path: entry for path, entry in entries.items() if not _is_run_entry(path, run_root)},
        expected_uid=expected_uid, expected_gid=expected_gid)} if restore_shared else set()
    selected = {path: entry for path, entry in entries.items()
                if _is_run_entry(path, run_root) or path in shared_drift}
    unrestorable = []
    for path, entry in selected.items():  # sorted: parents precede children
        destination = repository_root / path
        if entry["type"] == "dir":
            destination.mkdir(parents=True, exist_ok=True)
        elif entry["type"] == "symlink":
            if destination.is_symlink() or destination.exists():
                destination.unlink()
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(entry["target"], destination)
        elif entry["type"] == "file":
            if not entry.get("stored", True):
                unrestorable.append(SeedIssue("unrestorable", path, "shared input recorded by digest only"))
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                os.chmod(destination, 0o600)
                destination.unlink()
            shutil.copyfile(store.path(entry["sha256"]), destination)
        else:
            unrestorable.append(SeedIssue("unrestorable", path, f"cannot recreate {entry['type']}"))
            continue
        if entry["type"] != "symlink":
            if entry["type"] == "file":
                os.chmod(destination, int(entry["mode"], 8))
        uid, gid = ((expected_uid, expected_gid) if entry["owner"] == DEPLOYMENT_OWNER
                    else tuple(int(part) for part in entry["owner"].split(":")))
        try:
            chown(str(destination), uid, gid)
        except PermissionError:
            unrestorable.append(SeedIssue("owner", path, f"cannot set owner {uid}:{gid}"))
    # Directory modes last, deepest first, so a read-only directory does not block its children.
    for path in sorted((path for path, entry in selected.items() if entry["type"] == "dir"), reverse=True):
        os.chmod(repository_root / path, int(selected[path]["mode"], 8))
    issues = verify(repository_root, header, entries, expected_uid=expected_uid, expected_gid=expected_gid)
    return sorted(set(issues) | set(unrestorable))
