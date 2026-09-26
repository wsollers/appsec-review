#!/usr/bin/env python3
"""Pin, check and smoke-test the per-tool images (``images/tool-<name>/``).

One image per tool, so a tool is updated by itself. Each tool folder holds:

    tool.json      appsec-review/tool-image/1: tool, version, vendor asset URLs and how each one is
                   verified, the executable, a version probe and offline smoke runs
    image.json     appsec-review/image-build/1 (images/image_build.py): the checksummed download
                   steps are WRITTEN BY ``pin`` from tool.json, never by hand
    pin-record.json what ``pin`` verified, against what, when (committed; the audit trail)
    Dockerfile     digest-pinned base; installs only the downloaded, verified assets
    requirements.txt  (pip tools only) a hash-locked lock file; ``pin`` also downloads the exact wheels
                   (pip download --require-hashes) and declares each as a checksummed download, so
                   the image installs with --no-index and never reaches a package index

Commands (the tool never runs a downloaded asset; it hashes and verifies it):

    python -B images/tool_pins.py list
    python -B images/tool_pins.py check [<image_id> ...]          offline: files agree with each other
    python -B images/tool_pins.py pin <image_id> [--version V]    download, verify, rewrite image.json
    python -B images/tool_pins.py smoke <image_id> [--target DIR] run the built image inside the B13 boundary

Verification kinds (``assets[].verify.kind``):

    vendor-checksums   the release's own checksums file lists the asset's sha256
    vendor-sha256-file a file next to the asset holds its sha256 (Go, Maven Central)
    sigstore-checksums vendor-checksums, and the checksums file is verified with ``cosign verify-blob``
                       against the vendor's sigstore bundle, certificate identity and OIDC issuer
    sigstore-cert-checksums  the same, for vendors that publish a detached ``.sig`` and ``.pem``
    sigstore-key-checksums   the same, for vendors that sign with a key: the public key is committed
                       in ``keys/`` and pinned by sha256
    pgp                a detached ``.asc`` signature checked with ``gpg`` against a public key committed
                       in the tool folder (``keys/<fingerprint>.asc``) whose fingerprint is pinned

``pin`` fails closed: a missing checksum entry, a mismatch, a missing verifier (cosign, gpg) or a
signature that does not verify writes nothing.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any
import urllib.request

IMAGES = Path(__file__).resolve().parent
REPO = IMAGES.parent
TOOL_SCHEMA = "appsec-review/tool-image/1"
PIN_SCHEMA = "appsec-review/tool-pin-record/1"
BUILD_SCHEMA = "appsec-review/image-build/1"
DOWNLOADS = "downloads"

ID_RE = re.compile(r"^tool-[a-z0-9][a-z0-9-]*\Z")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z")
SHA_RE = re.compile(r"^[0-9a-f]{64}\Z")
FPR_RE = re.compile(r"^[0-9A-F]{40}\Z")
DIGEST_FROM_RE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$", re.I | re.M)
PINNED_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}\Z")
TOOL_KEYS = {"schema", "image_id", "tool", "version", "purpose", "feeds", "executable",
             "version_argv", "version_expect", "assets", "smoke"}
OPTIONAL_TOOL_KEYS = {"bundles", "pip_lock", "pip_package", "notes"}
VERIFY_KINDS = {"vendor-checksums", "vendor-sha256-file", "sigstore-checksums", "sigstore-cert-checksums",
                "sigstore-key-checksums", "pgp"}
SMOKE_KEYS = {"name", "argv", "exit_codes", "workspace"}
OPTIONAL_SMOKE_KEYS = {"expect_files", "stdout_contains", "file_contains", "config"}
CONTAINER_USER = "10001:10001"


class PinError(RuntimeError):
    """A pin, check or smoke precondition failed; nothing was written."""


# --------------------------------------------------------------------------- loading

def tool_dirs() -> list[Path]:
    return sorted(p for p in IMAGES.glob("tool-*") if p.is_dir() and (p / "tool.json").is_file())


def folder_of(image_id: str) -> Path:
    if not ID_RE.match(image_id):
        raise PinError(f"not a tool image id: {image_id!r}")
    folder = IMAGES / image_id
    if not (folder / "tool.json").is_file():
        raise PinError(f"{image_id}: no tool.json")
    return folder


def expand(value: str, version: str) -> str:
    return value.replace("{version}", version)


def load_tool(folder: Path) -> dict[str, Any]:
    tool = json.loads((folder / "tool.json").read_text(encoding="utf-8"))
    errors = tool_errors(tool, folder)
    if errors:
        raise PinError(f"{folder.name}/tool.json: " + "; ".join(errors))
    return tool


def tool_errors(tool: Any, folder: Path) -> list[str]:
    """Structural rules for tool.json (pure: reads nothing but the committed key files)."""
    if not isinstance(tool, dict):
        return ["not an object"]
    errors: list[str] = []
    missing = TOOL_KEYS - set(tool)
    unknown = set(tool) - TOOL_KEYS - OPTIONAL_TOOL_KEYS
    if missing:
        errors.append(f"missing keys {sorted(missing)}")
    if unknown:
        errors.append(f"unknown keys {sorted(unknown)}")
    if errors:
        return errors
    if tool["schema"] != TOOL_SCHEMA:
        errors.append("wrong schema")
    if tool["image_id"] != folder.name:
        errors.append("image_id must equal the folder name")
    if not isinstance(tool["version"], str) or not VERSION_RE.match(tool["version"]):
        errors.append("bad version")
    if not isinstance(tool["executable"], str) or not tool["executable"].startswith("/"):
        errors.append("executable must be an absolute path (B13 runs argv[0] as the entrypoint)")
    for key in ("version_argv",):
        argv = tool[key]
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv) \
                or not argv[0].startswith("/"):
            errors.append(f"{key} must be an argv list whose first member is absolute")
    if not isinstance(tool["feeds"], list) or not all(isinstance(f, str) for f in tool["feeds"]):
        errors.append("feeds must list graph job ids")
    assets = tool["assets"]
    if not isinstance(assets, list):
        errors.append("assets must be a list")
        assets = []
    if not assets and "pip_lock" not in tool:
        errors.append("a tool needs downloaded assets or a pip lock")
    dests = set()
    for index, asset in enumerate(assets):
        where = f"assets[{index}]"
        if not isinstance(asset, dict) or set(asset) != {"name", "url", "dest", "verify"}:
            errors.append(f"{where} needs exactly name, url, dest, verify")
            continue
        if not asset["url"].startswith("https://"):
            errors.append(f"{where}.url must be https")
        if not asset["dest"].startswith(DOWNLOADS + "/") or ".." in asset["dest"]:
            errors.append(f"{where}.dest must be under {DOWNLOADS}/")
        if asset["dest"] in dests:
            errors.append(f"{where}.dest is duplicated")
        dests.add(asset["dest"])
        errors += [f"{where}.verify: {e}" for e in verify_errors(asset["verify"], folder)]
    smoke = tool["smoke"]
    if not isinstance(smoke, list) or not smoke:
        errors.append("smoke needs at least one offline run")
        smoke = []
    for index, run in enumerate(smoke):
        where = f"smoke[{index}]"
        if not isinstance(run, dict) or not SMOKE_KEYS <= set(run) \
                or set(run) - SMOKE_KEYS - OPTIONAL_SMOKE_KEYS:
            errors.append(f"{where} needs {sorted(SMOKE_KEYS)} (optional {sorted(OPTIONAL_SMOKE_KEYS)})")
            continue
        if not isinstance(run["argv"], list) or not run["argv"] or not run["argv"][0].startswith("/"):
            errors.append(f"{where}.argv must start with an absolute executable")
        if not isinstance(run["exit_codes"], list) or not all(isinstance(c, int) for c in run["exit_codes"]):
            errors.append(f"{where}.exit_codes must be integers")
        if "config" in run and not (run["config"] == "smoke-config" and (folder / "smoke-config").is_dir()):
            errors.append(f"{where}.config must be \"smoke-config\" (a committed folder, mounted read-only at /config)")
        if run["workspace"] not in ("none", "target") and not (
                isinstance(run["workspace"], str) and re.match(r"^images/test/[a-z0-9-]+\Z", run["workspace"])
                and (REPO / run["workspace"]).is_dir()):
            errors.append(f"{where}.workspace must be none, target or an images/test/<lang> fixture")
    if "pip_lock" in tool and not (folder / tool["pip_lock"]).is_file():
        errors.append("pip_lock file is missing")
    if ("pip_lock" in tool) != ("pip_package" in tool):
        errors.append("pip_lock and pip_package go together")
    return errors


def verify_errors(verify: Any, folder: Path) -> list[str]:
    if not isinstance(verify, dict) or verify.get("kind") not in VERIFY_KINDS:
        return [f"kind must be one of {sorted(VERIFY_KINDS)}"]
    kind = verify["kind"]
    wanted = {
        "vendor-checksums": {"kind", "checksums_url", "entry"},
        "vendor-sha256-file": {"kind", "sha256_url"},
        "sigstore-checksums": {"kind", "checksums_url", "entry", "bundle_url",
                               "certificate_identity_regexp", "certificate_oidc_issuer"},
        "sigstore-cert-checksums": {"kind", "checksums_url", "entry", "signature_url", "certificate_url",
                                    "certificate_identity_regexp", "certificate_oidc_issuer"},
        "sigstore-key-checksums": {"kind", "checksums_url", "entry", "bundle_url", "public_key", "public_key_sha256"},
        "pgp": {"kind", "signature_url", "fingerprint"},
    }[kind]
    if set(verify) != wanted:
        return [f"{kind} needs exactly {sorted(wanted)}"]
    errors = [f"{k} must be https" for k in wanted if k.endswith("_url") and not verify[k].startswith("https://")]
    if kind == "sigstore-key-checksums":
        key = folder / "keys" / str(verify["public_key"])
        if "/" in str(verify["public_key"]) or not key.is_file():
            errors.append(f"keys/{verify['public_key']} is not committed")
        elif hashlib.sha256(key.read_bytes()).hexdigest() != verify["public_key_sha256"]:
            errors.append("the committed public key does not match public_key_sha256")
    if kind == "pgp":
        if not FPR_RE.match(verify["fingerprint"]):
            errors.append("fingerprint must be 40 upper-case hex characters")
        elif not (folder / "keys" / f"{verify['fingerprint']}.asc").is_file():
            errors.append(f"keys/{verify['fingerprint']}.asc is not committed")
    return errors


def load_build(folder: Path) -> dict[str, Any]:
    document = json.loads((folder / "image.json").read_text(encoding="utf-8"))
    if document.get("schema") != BUILD_SCHEMA or len(document.get("builds", [])) != 1:
        raise PinError(f"{folder.name}/image.json must declare exactly one build")
    return document


# --------------------------------------------------------------------------- check (offline)

def check(folder: Path) -> list[str]:
    """Every rule that needs no network: tool.json, image.json, pin record and Dockerfile agree."""
    try:
        tool = json.loads((folder / "tool.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"tool.json unreadable: {exc}"]
    errors = tool_errors(tool, folder)
    if errors:
        return errors
    try:
        document = load_build(folder)
    except (OSError, ValueError, PinError) as exc:
        return [f"image.json: {exc}"]
    build = document["builds"][0]
    if build["image_id"] != tool["image_id"] or build["tag"] != f"{tool['image_id']}:local":
        errors.append("image.json image_id/tag must be <image_id> and <image_id>:local")
    if build["build_args"].get("TOOL_VERSION") != tool["version"]:
        errors.append("image.json build_args.TOOL_VERSION differs from tool.json version (run pin)")
    steps = build["prebuild"]
    expected = [(expand(a["url"], tool["version"]), a["dest"]) for a in tool["assets"]]
    if "pip_lock" in tool and (folder / "pin-record.json").is_file():
        wheels = json.loads((folder / "pin-record.json").read_text(encoding="utf-8")).get("pip_lock", {}).get("wheels", [])
        if not wheels:
            errors.append("pin-record.json lists no wheel for the pip lock (run pin)")
        expected += [(w["url"], w["dest"]) for w in wheels]
    actual = [(s.get("url"), s.get("dest")) for s in steps if s.get("kind") == "download"]
    if expected != actual or len(steps) != len(actual):
        errors.append("image.json download steps differ from tool.json assets (run pin)")
    record_path = folder / "pin-record.json"
    if tool["assets"] or "pip_lock" in tool:
        if not record_path.is_file():
            errors.append("pin-record.json missing (run pin)")
        else:
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if record.get("schema") != PIN_SCHEMA or record.get("version") != tool["version"]:
                errors.append("pin-record.json is for another version (run pin)")
            else:
                if "pip_lock" in tool:
                    lock_bytes = (folder / tool["pip_lock"]).read_bytes()
                    if record.get("pip_lock", {}).get("lock_sha256") != hashlib.sha256(lock_bytes).hexdigest():
                        errors.append("pip lock differs from the one pin wrote (run pin)")
                pinned = {(a["url"], a["sha256"], a["bytes"]) for a in record.get("assets", [])}
                pinned |= {(w["url"], w["sha256"], w["bytes"]) for w in record.get("pip_lock", {}).get("wheels", [])}
                for step in steps:
                    if (step["url"], step["sha256"], step["bytes"]) not in pinned:
                        errors.append(f"{step['dest']}: image.json hash is not the verified pin")
    dockerfile = folder / build["dockerfile"]
    if not dockerfile.is_file():
        errors.append("Dockerfile missing")
    else:
        text = dockerfile.read_text(encoding="utf-8")
        stages = set(re.findall(r"^FROM\s+\S+\s+AS\s+(\S+)", text, re.I | re.M))
        for ref in DIGEST_FROM_RE.findall(text):
            if ref not in stages and not PINNED_REF_RE.match(ref):
                errors.append(f"Dockerfile base {ref} is not pinned by digest")
        if "ARG TOOL_VERSION" not in text:
            errors.append("Dockerfile must declare ARG TOOL_VERSION")
        if re.search(r"^\s*(ENTRYPOINT|CMD)\b", text, re.M):
            errors.append("tool images declare no ENTRYPOINT or CMD (B13 sets argv[0])")
        if re.search(r"\b(curl|wget)\b", text):
            errors.append("Dockerfile may not download; declare an asset and let pin verify it")
        if re.search(r"^\s*COPY\s+(?!--from)", text, re.M | re.I):
            for source in re.findall(r"^\s*COPY\s+(?!--from)(?:--\S+\s+)*(\S+)", text, re.M | re.I):
                if not (source.startswith(DOWNLOADS + "/") or source == tool.get("pip_lock")):
                    errors.append(f"Dockerfile COPYs {source}: only verified downloads and the pip lock")
        if "USER 10001" not in text:
            errors.append("Dockerfile must end as the non-root worker (USER 10001)")
    if "pip_lock" in tool:
        lock = (folder / tool["pip_lock"]).read_text(encoding="utf-8")
        requirements = [line for line in lock.splitlines() if re.match(r"^[A-Za-z0-9]", line)]
        if not requirements:
            errors.append("pip lock lists no requirement")
        for line in requirements:
            if not re.match(r"^[A-Za-z0-9._-]+(\[[^\]]*\])?==\S+", line):
                errors.append(f"pip lock line is not pinned with ==: {line.split()[0]}")
        if "--hash=sha256:" not in lock:
            errors.append("pip lock carries no hashes")
        if "--require-hashes" not in (dockerfile.read_text(encoding="utf-8") if dockerfile.is_file() else ""):
            errors.append("Dockerfile must pip install with --require-hashes")
    gitignore = (REPO / ".gitignore").read_text(encoding="utf-8") if (REPO / ".gitignore").is_file() else ""
    if "/images/tool-*/downloads/" not in gitignore:
        errors.append(".gitignore must ignore /images/tool-*/downloads/")
    return errors


# --------------------------------------------------------------------------- pin (network)

def fetch(url: str, dest: Path) -> tuple[str, int]:
    part = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(url, headers={"User-Agent": "appsec-review-tool-pins/1"})
    try:
        with urllib.request.urlopen(request, timeout=180) as response, part.open("wb") as stream:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
                stream.write(chunk)
    except Exception as exc:
        part.unlink(missing_ok=True)
        raise PinError(f"download failed: {url}: {type(exc).__name__}: {exc}") from exc
    part.replace(dest)
    return digest.hexdigest(), size


def fetch_text(url: str, limit: int = 4 * 1024 * 1024) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "appsec-review-tool-pins/1"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(limit + 1)
    except Exception as exc:
        raise PinError(f"download failed: {url}: {type(exc).__name__}: {exc}") from exc
    if len(data) > limit:
        raise PinError(f"{url}: larger than {limit} bytes")
    return data.decode("utf-8", "replace")


def checksum_entry(text: str, entry: str) -> str:
    """The sha256 the vendor lists for ``entry`` (``<hash>  <name>`` or ``<hash> *<name>``)."""
    found = set()
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].lstrip("*").lstrip("./") == entry and SHA_RE.match(parts[0].lower()):
            found.add(parts[0].lower())
    if len(found) != 1:
        raise PinError(f"checksums file lists {len(found)} sha256 values for {entry}")
    return found.pop()


def single_hash(text: str) -> str:
    token = text.strip().split()[0].lower() if text.strip() else ""
    if not SHA_RE.match(token):
        raise PinError("sha256 file does not start with a sha256")
    return token


def run_verifier(argv: list[str]) -> str:
    if not shutil.which(argv[0]):
        raise PinError(f"{argv[0]} is required for this asset's verification and is not on PATH")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
    if done.returncode != 0:
        raise PinError(f"{argv[0]} verification failed: {(done.stderr or done.stdout).strip()[-600:]}")
    return (done.stdout + done.stderr).strip()


def verify_asset(asset: dict[str, Any], version: str, path: Path, sha: str, folder: Path,
                 work: Path) -> dict[str, Any]:
    verify = {k: expand(v, version) if isinstance(v, str) else v for k, v in asset["verify"].items()}
    kind = verify["kind"]
    evidence: dict[str, Any] = {"kind": kind}
    if kind in ("vendor-checksums", "sigstore-checksums", "sigstore-cert-checksums", "sigstore-key-checksums"):
        checksums = work / "checksums.txt"
        checksums_sha, _ = fetch(verify["checksums_url"], checksums)
        expected = checksum_entry(checksums.read_text(encoding="utf-8", errors="replace"), verify["entry"])
        evidence.update(checksums_url=verify["checksums_url"], checksums_sha256=checksums_sha,
                        entry=verify["entry"])
        if kind == "sigstore-checksums":
            bundle = work / "checksums.bundle.json"
            bundle_sha, _ = fetch(verify["bundle_url"], bundle)
            output = run_verifier(["cosign", "verify-blob", "--bundle", str(bundle),
                                   "--certificate-identity-regexp", verify["certificate_identity_regexp"],
                                   "--certificate-oidc-issuer", verify["certificate_oidc_issuer"],
                                   str(checksums)])
            evidence.update(bundle_url=verify["bundle_url"], bundle_sha256=bundle_sha,
                            certificate_identity_regexp=verify["certificate_identity_regexp"],
                            certificate_oidc_issuer=verify["certificate_oidc_issuer"],
                            cosign_output=output[-300:])
        if kind == "sigstore-key-checksums":
            bundle = work / "checksums.bundle.json"
            bundle_sha, _ = fetch(verify["bundle_url"], bundle)
            key = folder / "keys" / verify["public_key"]
            if hashlib.sha256(key.read_bytes()).hexdigest() != verify["public_key_sha256"]:
                raise PinError("the committed public key does not match public_key_sha256")
            output = run_verifier(["cosign", "verify-blob", "--key", str(key), "--bundle", str(bundle),
                                   str(checksums)])
            evidence.update(bundle_url=verify["bundle_url"], bundle_sha256=bundle_sha,
                            public_key=verify["public_key"], public_key_sha256=verify["public_key_sha256"],
                            cosign_output=output[-300:])
        if kind == "sigstore-cert-checksums":
            signature = work / "checksums.sig"
            certificate = work / "checksums.pem"
            signature_sha, _ = fetch(verify["signature_url"], signature)
            certificate_sha, _ = fetch(verify["certificate_url"], certificate)
            output = run_verifier(["cosign", "verify-blob", "--signature", str(signature),
                                   "--certificate", str(certificate),
                                   "--certificate-identity-regexp", verify["certificate_identity_regexp"],
                                   "--certificate-oidc-issuer", verify["certificate_oidc_issuer"],
                                   str(checksums)])
            evidence.update(signature_url=verify["signature_url"], signature_sha256=signature_sha,
                            certificate_url=verify["certificate_url"], certificate_sha256=certificate_sha,
                            certificate_identity_regexp=verify["certificate_identity_regexp"],
                            certificate_oidc_issuer=verify["certificate_oidc_issuer"],
                            cosign_output=output[-300:])
    elif kind == "vendor-sha256-file":
        expected = single_hash(fetch_text(verify["sha256_url"]))
        evidence.update(sha256_url=verify["sha256_url"])
    else:  # pgp
        signature = work / "asset.asc"
        signature_sha, _ = fetch(verify["signature_url"], signature)
        key = folder / "keys" / f"{verify['fingerprint']}.asc"
        home = work / "gnupg"
        home.mkdir(mode=0o700)
        run_verifier(["gpg", "--batch", "--homedir", str(home), "--import", str(key)])
        status = run_verifier(["gpg", "--batch", "--homedir", str(home), "--status-fd", "1",
                               "--verify", str(signature), str(path)])
        valid = re.findall(r"\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) .* ([0-9A-F]{40})$|\[GNUPG:\] VALIDSIG ([0-9A-F]{40})",
                           status, re.M)
        fingerprints = {x for match in valid for x in match if x}
        if verify["fingerprint"] not in fingerprints:
            raise PinError(f"{asset['name']}: signature is not by the pinned key {verify['fingerprint']}")
        expected = sha
        evidence.update(signature_url=verify["signature_url"], signature_sha256=signature_sha,
                        fingerprint=verify["fingerprint"])
    if expected != sha:
        raise PinError(f"{asset['name']}: downloaded sha256 {sha} does not match the vendor's {expected}")
    return evidence


def pin(folder: Path, version: str | None = None) -> dict[str, Any]:
    tool = load_tool(folder)
    if version:
        if not VERSION_RE.match(version):
            raise PinError("bad --version")
        tool["version"] = version
    version = tool["version"]
    document = load_build(folder)
    build = document["builds"][0]
    downloads = folder / DOWNLOADS
    downloads.mkdir(exist_ok=True)
    steps, verified = [], []
    with tempfile.TemporaryDirectory(prefix="tool-pin-") as tmp:
        for index, asset in enumerate(tool["assets"]):
            url = expand(asset["url"], version)
            work = Path(tmp, str(index))
            work.mkdir()
            staged = work / "asset"
            sha, size = fetch(url, staged)
            evidence = verify_asset(asset, version, staged, sha, folder, work)
            final = folder / asset["dest"]
            final.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(staged, final)
            steps.append({"kind": "download", "url": url, "dest": asset["dest"], "sha256": sha, "bytes": size})
            verified.append({"name": asset["name"], "url": url, "sha256": sha, "bytes": size,
                             "verification": evidence})
    lock = None
    if "pip_lock" in tool:
        lock = lock_pip(folder, tool)
        steps += [{"kind": "download", "url": w["url"], "dest": w["dest"], "sha256": w["sha256"],
                   "bytes": w["bytes"]} for w in lock["wheels"]]
    build["prebuild"] = steps
    build["build_args"] = {**build["build_args"], "TOOL_VERSION": version}
    record = {"schema": PIN_SCHEMA, "image_id": tool["image_id"], "tool": tool["tool"], "version": version,
              "pinned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "assets": verified}
    if lock:
        record["pip_lock"] = lock
    write_json(folder / "tool.json", tool)
    write_json(folder / "image.json", document)
    write_json(folder / "pin-record.json", record)
    return record


PIP_PYTHON = "3.12"
PIP_PLATFORM = "x86_64-manylinux_2_36"   # python:3.12-slim-bookworm (glibc 2.36)
# Every wheel platform tag that glibc 2.36 x86_64 accepts: pip download does not expand
# --platform to older compatible tags by itself.
PIP_WHEEL_PLATFORMS = (*(f"manylinux_2_{minor}_x86_64" for minor in range(36, 4, -1)),
                       "manylinux2014_x86_64", "manylinux2010_x86_64", "manylinux1_x86_64", "linux_x86_64", "any")


def lock_pip(folder: Path, tool: dict[str, Any]) -> dict[str, Any]:
    """Resolve ``<pip_package>==<version>`` for the image's Python and platform into a lock with
    every distribution's sha256 (uv pip compile --generate-hashes). Wheels only: the Dockerfile
    installs with --only-binary=:all: --require-hashes, so an sdist-only dependency fails here,
    not silently at build time."""
    if not shutil.which("uv"):
        raise PinError("uv is required to lock a pip tool (https://docs.astral.sh/uv/) and is not on PATH")
    requirement = f"{tool['pip_package']}=={tool['version']}"
    lock_path = folder / tool["pip_lock"]
    with tempfile.TemporaryDirectory(prefix="tool-lock-") as tmp:
        source = Path(tmp, "requirements.in")
        source.write_text(requirement + "\n", encoding="utf-8")
        out = Path(tmp, "requirements.txt")
        run_verifier(["uv", "pip", "compile", str(source), "--output-file", str(out), "--generate-hashes",
                      "--python-version", PIP_PYTHON, "--python-platform", PIP_PLATFORM,
                      "--only-binary", ":all:", "--no-header", "--no-annotate", "--quiet"])
        body = out.read_text(encoding="utf-8")
    header = (f"# {tool['image_id']}: {requirement} for Python {PIP_PYTHON} on {PIP_PLATFORM}.\n"
              f"# Written by `python -B images/tool_pins.py pin {tool['image_id']}` (uv pip compile\n"
              "# --generate-hashes); do not edit by hand. pip installs it with --require-hashes.\n")
    lock_path.write_text(header + body, encoding="utf-8", newline="\n")
    packages = [line.split("==")[0] for line in body.splitlines() if re.match(r"^[A-Za-z0-9]", line)]
    wheels = download_wheels(folder, lock_path)
    return {"requirement": requirement, "python": PIP_PYTHON, "platform": PIP_PLATFORM,
            "packages": len(packages), "lock_sha256": hashlib.sha256((header + body).encode()).hexdigest(),
            "wheels": wheels}


def download_wheels(folder: Path, lock_path: Path) -> list[dict[str, Any]]:
    """The exact wheels pip would install in the image, fetched on the host with the lock's hashes
    enforced (pip download --require-hashes for the image's interpreter and platform), each with
    its PyPI URL, sha256 and size. The image then installs them with --no-index: no package index is
    reached from inside a build."""
    wheel_dir = folder / DOWNLOADS / "wheels"
    shutil.rmtree(wheel_dir, ignore_errors=True)
    wheel_dir.mkdir(parents=True)
    python = sys.executable
    run_verifier([python, "-m", "pip", "download", "--quiet", "--disable-pip-version-check", "--no-deps",
                  "--require-hashes", "--only-binary=:all:", "--implementation", "cp",
                  "--python-version", PIP_PYTHON.replace(".", ""), "--abi", "cp" + PIP_PYTHON.replace(".", ""),
                  *[arg for tag in PIP_WHEEL_PLATFORMS for arg in ("--platform", tag)],
                  "-r", str(lock_path), "-d", str(wheel_dir)])
    wheels = []
    for wheel in sorted(wheel_dir.glob("*.whl")):
        name, version = wheel.name.split("-")[:2]
        data = json.loads(fetch_text(f"https://pypi.org/pypi/{name}/{version}/json", 64 * 1024 * 1024))
        urls = [u for u in data.get("urls", []) if u.get("filename") == wheel.name]
        sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if len(urls) != 1 or urls[0]["digests"]["sha256"] != sha:
            raise PinError(f"{wheel.name}: PyPI does not list this file with this sha256")
        wheels.append({"name": wheel.name, "url": urls[0]["url"], "sha256": sha, "bytes": wheel.stat().st_size,
                       "dest": f"{DOWNLOADS}/wheels/{wheel.name}"})
    if not wheels:
        raise PinError("pip download produced no wheel")
    return wheels


def write_json(path: Path, value: Any) -> None:
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    part = path.with_name(path.name + ".part")
    part.write_text(text, encoding="utf-8", newline="\n")
    part.replace(path)


# --------------------------------------------------------------------------- smoke (docker)

def boundary_flags() -> tuple[str, ...]:
    """The exact B13 boundary (appsec-review/container-boundary/1.0), imported, never copied."""
    sys.path.insert(0, str(REPO / "appsec-review-process"))
    import container_execution  # noqa: E402  (stdlib-only module chain)
    return container_execution.BOUNDARY_FLAGS


def smoke(folder: Path, target: Path | None, docker: str = "docker") -> list[dict[str, Any]]:
    tool = load_tool(folder)
    tag = f"{tool['image_id']}:local"
    flags = boundary_flags()
    results = []
    runs = [{"name": "version", "argv": tool["version_argv"], "exit_codes": [0], "workspace": "none",
             "stdout_contains": expand(tool["version_expect"], tool["version"])}] + tool["smoke"]
    for run in runs:
        with tempfile.TemporaryDirectory(prefix="tool-smoke-") as scratch:
            os.chmod(scratch, 0o777)
            argv = [docker, "run", "--rm", *flags, "--user", CONTAINER_USER,
                    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=1073741824",
                    "--mount", f"type=bind,source={scratch},target=/scratch"]
            source = None
            if run["workspace"] == "target":
                if target is None:
                    raise PinError(f"{run['name']}: needs --target")
                source = target.resolve()
            elif run["workspace"] != "none":
                source = (REPO / run["workspace"]).resolve()
            if source is not None:
                argv += ["--mount", f"type=bind,source={source},target=/workspace,readonly"]
            if run.get("config"):
                # How a scan job hands a tool its configuration: a read-only mount, never baked in.
                argv += ["--mount", f"type=bind,source={(folder / run['config']).resolve()},target=/config,readonly"]
            argv += ["--entrypoint=" + run["argv"][0], tag, *run["argv"][1:]]
            done = subprocess.run(argv, capture_output=True, text=True, timeout=1800, check=False)
            problems = []
            if done.returncode not in run["exit_codes"]:
                problems.append(f"exit {done.returncode} not in {run['exit_codes']}")
            needle = run.get("stdout_contains")
            if needle and needle not in done.stdout + done.stderr:
                problems.append(f"output lacks {needle!r}")
            for name in run.get("expect_files", []):
                produced = Path(scratch, name)
                if not produced.is_file() or produced.stat().st_size == 0:
                    problems.append(f"/scratch/{name} missing or empty")
            for name, needle in run.get("file_contains", {}).items():
                produced = Path(scratch, name)
                if not produced.is_file() or needle not in produced.read_text(encoding="utf-8", errors="replace"):
                    problems.append(f"/scratch/{name} lacks {needle!r}")
            results.append({"name": run["name"], "exit": done.returncode, "ok": not problems,
                            "problems": problems, "tail": (done.stderr or done.stdout)[-800:]})
    return results


# --------------------------------------------------------------------------- CLI

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    p_check = sub.add_parser("check")
    p_check.add_argument("image_ids", nargs="*")
    p_pin = sub.add_parser("pin")
    p_pin.add_argument("image_id")
    p_pin.add_argument("--version")
    p_smoke = sub.add_parser("smoke")
    p_smoke.add_argument("image_id")
    p_smoke.add_argument("--target", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            for folder in tool_dirs():
                tool = json.loads((folder / "tool.json").read_text(encoding="utf-8"))
                print(f"{folder.name:24} {tool.get('tool', '?'):12} {tool.get('version', '?'):14} "
                      f"{', '.join(tool.get('feeds', []))}")
            return 0
        if args.command == "check":
            folders = [folder_of(i) for i in args.image_ids] or tool_dirs()
            failed = 0
            for folder in folders:
                errors = check(folder)
                print(f"{folder.name:24} {'OK' if not errors else 'FAIL'}")
                for error in errors:
                    print(f"    {error}")
                failed += bool(errors)
            return 1 if failed else 0
        if args.command == "pin":
            record = pin(folder_of(args.image_id), args.version)
            for asset in record["assets"]:
                print(f"{asset['name']}: {asset['sha256']} {asset['bytes']} bytes "
                      f"[{asset['verification']['kind']}]")
            print(f"{args.image_id} pinned to {record['version']}; image.json and pin-record.json rewritten")
            return 0
        results = smoke(folder_of(args.image_id), args.target)
        for result in results:
            print(f"{args.image_id:24} {result['name']:24} {'PASS' if result['ok'] else 'FAIL'} exit={result['exit']}")
            for problem in result["problems"]:
                print(f"    {problem}")
            if not result["ok"]:
                print("    " + result["tail"].replace("\n", "\n    "))
        return 0 if all(r["ok"] for r in results) else 1
    except PinError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
