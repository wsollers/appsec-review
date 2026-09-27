#!/usr/bin/env python3
"""Bounded, permissioned publisher for offline Grype and OSV database mirrors.

This operations utility is deliberately outside every analysis worker. It downloads one pinned
archive into registry-owned staging, validates its bytes, safely extracts a bounded file set,
validates required content and closed metadata, then delegates the sole publication step to the
immutable dependency snapshot registry.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import container_execution as ce
import dependency_snapshot_registry as snapshots
import permission_capabilities as pc

JOB = "dependency-database-snapshot-sync"
HARD_MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024
HARD_MAX_EXTRACTED_BYTES = 16 * 1024 * 1024 * 1024
HARD_MAX_FILES = 2_000_000


class SyncBlocked(RuntimeError): pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _capability(host: str) -> dict[str, Any]:
    parameters = {name: None for name in pc.PARAMETER_NAMES}
    parameters.update({"scheme": "https", "host": host, "port": 443})
    return {"kind": "fixed-network-destination", "version": "1.0", "origin": "registry",
            "parameters": parameters}


def _authorize(url: str, grants: Any, *, run_id: str, source: str, now: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    try: port = parsed.port
    except ValueError: raise SyncBlocked("sync URL has an invalid port") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or
            parsed.query or parsed.fragment or port not in (None, 443)):
        raise SyncBlocked("sync URL must be one fixed credential-free HTTPS destination")
    capability = _capability(parsed.hostname)
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": JOB,
                   "capabilities": [capability]}
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source,
               "now": now, "registry_ceiling": [capability]}
    try:
        decision = pc.evaluate(requirement, grants, context)
        pc.require_granted(decision, requirement=requirement, grants=grants, context=context)
    except (pc.PermissionDenied, pc.PermissionModelError):
        raise SyncBlocked("snapshot sync lacks an exact active network permission grant") from None


def _spec(value: Any) -> dict[str, Any]:
    fields = {"database_kind", "url", "sha256", "bytes", "archive", "metadata",
              "required_paths", "max_extracted_bytes", "max_files"}
    present = set(value) if isinstance(value, dict) else set()
    if (not isinstance(value, dict) or present not in (fields, fields | {"target_path"}) or
            value.get("database_kind") not in snapshots.KINDS or
            value.get("archive") not in {"file", "tar", "tar.gz", "tar.zst", "zip"} or
            not isinstance(value.get("url"), str) or
            not snapshots.SHA.fullmatch(str(value.get("sha256"))) or isinstance(value.get("bytes"), bool) or
            not isinstance(value.get("bytes"), int) or not 0 < value["bytes"] <= HARD_MAX_ARCHIVE_BYTES or
            isinstance(value.get("max_extracted_bytes"), bool) or not isinstance(value.get("max_extracted_bytes"), int) or
            not 0 < value["max_extracted_bytes"] <= HARD_MAX_EXTRACTED_BYTES or
            isinstance(value.get("max_files"), bool) or not isinstance(value.get("max_files"), int) or
            not 0 < value["max_files"] <= HARD_MAX_FILES or not isinstance(value.get("required_paths"), list)):
        raise SyncBlocked("snapshot sync specification is not a closed bounded declaration")
    try: snapshots._metadata(value.get("metadata"), value["database_kind"])
    except snapshots.SnapshotInvalid as exc: raise SyncBlocked("snapshot sync metadata is invalid") from exc
    required = []
    for name in value["required_paths"]:
        path = _safe_member(name); required.append(path.as_posix())
    if not required or len(required) != len(set(required)):
        raise SyncBlocked("snapshot sync requires a unique non-empty required path set")
    if value["archive"] == "file":
        target = _safe_member(value.get("target_path"))
        if target.as_posix() not in required:
            raise SyncBlocked("file snapshot target must be one of the required paths")
    elif "target_path" in value:
        raise SyncBlocked("target_path is valid only for a file snapshot")
    return value


def _safe_member(name: Any) -> PurePosixPath:
    if not isinstance(name, str): raise SyncBlocked("snapshot archive path is not text")
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise SyncBlocked("snapshot archive contains an unsafe path")
    return path


def _copy_member(incoming, target: Path, state: dict[str, int], spec: dict[str, Any]) -> None:
    target.parent.mkdir(parents=True, exist_ok=True); state["files"] += 1
    if state["files"] > spec["max_files"]: raise SyncBlocked("snapshot archive exceeds its file limit")
    with target.open("xb") as output:
        while True:
            chunk = incoming.read(1024 * 1024)
            if not chunk: break
            state["bytes"] += len(chunk)
            if state["bytes"] > spec["max_extracted_bytes"]:
                raise SyncBlocked("snapshot archive exceeds its extracted byte limit")
            output.write(chunk)


def _extract(archive: Path, destination: Path, spec: dict[str, Any]) -> None:
    state = {"files": 0, "bytes": 0}
    if spec["archive"] == "file":
        with archive.open("rb") as incoming:
            _copy_member(incoming, destination.joinpath(*_safe_member(spec["target_path"]).parts), state, spec)
    elif spec["archive"] == "zip":
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                path = _safe_member(item.filename)
                if item.is_dir(): continue
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise SyncBlocked("snapshot archive contains a symbolic link")
                with source.open(item) as incoming:
                    _copy_member(incoming, destination.joinpath(*path.parts), state, spec)
    else:
        expanded = archive
        if spec["archive"] == "tar.zst":
            expanded = archive.with_name("archive.tar")
            limit = spec["max_extracted_bytes"] + (spec["max_files"] + 2) * 512
            try:
                process = subprocess.Popen(["/usr/bin/zstd", "--decompress", "--stdout", str(archive)],
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            except OSError as exc:
                raise SyncBlocked("zstd decompressor is unavailable") from exc
            written = 0
            try:
                assert process.stdout is not None
                with expanded.open("xb") as output:
                    while True:
                        chunk = process.stdout.read(1024 * 1024)
                        if not chunk: break
                        written += len(chunk)
                        if written > limit:
                            process.kill()
                            raise SyncBlocked("snapshot archive exceeds its decompressed tar limit")
                        output.write(chunk)
                if process.wait() != 0:
                    raise SyncBlocked("snapshot archive zstd decompression failed")
            finally:
                if process.poll() is None:
                    process.kill(); process.wait()
        with tarfile.open(expanded, "r:gz" if spec["archive"] == "tar.gz" else "r:") as source:
            for item in source:
                path = _safe_member(item.name)
                if item.isdir(): continue
                if not item.isfile(): raise SyncBlocked("snapshot archive contains a non-regular member")
                incoming = source.extractfile(item)
                if incoming is None: raise SyncBlocked("snapshot archive member is unreadable")
                with incoming: _copy_member(incoming, destination.joinpath(*path.parts), state, spec)
    present = {item["path"] for item in snapshots.inventory(destination)}
    if not set(spec["required_paths"]).issubset(present):
        raise SyncBlocked("snapshot archive lacks required database content")


def _activate_grype(archive: Path, destination: Path, spec: dict[str, Any]) -> None:
    """Activate a verified vendor archive with the pinned Grype image, entirely offline."""
    try:
        defaults = ce.host_defaults()
        executable = defaults["docker_executable"]
        image = ce.load_image_registry(ce.IMAGES_DIR)["tool-grype"]["digest"]
    except (KeyError, OSError, ce.ContainerRequestError) as exc:
        raise SyncBlocked("pinned Grype image identity is unavailable") from exc
    if executable is None:
        raise SyncBlocked("Docker is unavailable for pinned Grype database activation")
    destination.chmod(0o777)
    common = [str(executable), "run", "--rm", "--network", "none", "--read-only",
              "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
              "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
              "-e", "GRYPE_DB_CACHE_DIR=/scratch/grype/db",
              "-v", f"{archive.resolve()}:/input/db.tar.zst:ro",
              "-v", f"{destination.resolve()}:/scratch:rw",
              "--entrypoint", "/opt/tool/bin/grype", image]
    try:
        imported = subprocess.run([*common, "db", "import", "/input/db.tar.zst"],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=900, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SyncBlocked("pinned Grype database activation failed") from exc
    if imported.returncode != 0:
        raise SyncBlocked("pinned Grype database activation failed")
    try:
        checked = subprocess.run([*common, "db", "status", "-o", "json"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=120, check=False)
        status = json.loads(checked.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise SyncBlocked("pinned Grype database status validation failed") from exc
    expected_schema = "v" + spec["metadata"]["schema_version"]
    if (checked.returncode != 0 or not isinstance(status, dict) or status.get("valid") is not True or
            status.get("schemaVersion") != expected_schema or
            status.get("built") != spec["metadata"]["data_timestamp"]):
        raise SyncBlocked("activated Grype database identity differs from the pinned declaration")
    present = {item["path"] for item in snapshots.inventory(destination)}
    if not set(spec["required_paths"]).issubset(present):
        raise SyncBlocked("activated Grype database lacks required cache content")


def sync_one(spec: Any, grants: Any, *, run_id: str, source_snapshot_sha256: str, now: str,
             registry_root: Path, opener: Callable[..., Any] | None = None) -> dict[str, Any]:
    spec = _spec(spec); _authorize(spec["url"], grants, run_id=run_id, source=source_snapshot_sha256, now=now)
    root = Path(registry_root).resolve()
    if root == Path(root.anchor) or len(root.parts) < 3: raise SyncBlocked("unsafe snapshot registry root")
    staging_parent = root / "staging"; staging_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=spec["database_kind"] + "-", dir=staging_parent))
    opener = opener or urllib.request.build_opener(NoRedirect()).open
    try:
        archive = staging / "archive"; digest = hashlib.sha256(); size = 0
        request = urllib.request.Request(spec["url"], headers={
            "Accept": "application/octet-stream",
            "User-Agent": "appsec-review-snapshot-sync/1.0",
        })
        try:
            with opener(request, timeout=300) as response, archive.open("xb") as output:
                if getattr(response, "status", 200) != 200: raise SyncBlocked("snapshot server did not return HTTP 200")
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk: break
                    size += len(chunk)
                    if size > spec["bytes"]: raise SyncBlocked("snapshot archive exceeded its pinned byte count")
                    digest.update(chunk); output.write(chunk)
                output.flush(); os.fsync(output.fileno())
        except (OSError, urllib.error.URLError) as exc: raise SyncBlocked("snapshot archive download failed") from exc
        if size != spec["bytes"] or "sha256:" + digest.hexdigest() != spec["sha256"]:
            raise SyncBlocked("snapshot archive bytes differ from the pinned declaration")
        mirror = staging / "mirror"; mirror.mkdir()
        if spec["database_kind"] == "grype-db" and spec["archive"] == "tar.zst":
            _activate_grype(archive, mirror, spec)
        else:
            _extract(archive, mirror, spec)
        metadata = staging / "metadata.json"; metadata.write_text(json.dumps(spec["metadata"], sort_keys=True) + "\n")
        # register() re-inventories the extracted bytes, stages a new immutable generation and
        # atomically replaces only the small current pointer after full validation.
        return snapshots.register(spec["database_kind"], mirror, metadata, root)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def sync_periodic_references(*, nvd_sync: Callable[..., Any], nvd_kwargs: dict[str, Any],
                             dependency_specs: list[dict[str, Any]], grants: Any, run_id: str,
                             source_snapshot_sha256: str, now: str, registry_root: Path,
                             opener: Callable[..., Any] | None = None) -> dict[str, Any]:
    """Callable extension point for the existing periodic NVD reference job."""
    nvd = nvd_sync(**nvd_kwargs)
    dependencies = [sync_one(spec, grants, run_id=run_id, source_snapshot_sha256=source_snapshot_sha256,
        now=now, registry_root=registry_root, opener=opener) for spec in dependency_specs]
    return {"nvd": nvd, "dependencies": dependencies}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True); parser.add_argument("--grants", type=Path, required=True)
    parser.add_argument("--run-id", required=True); parser.add_argument("--source-snapshot-sha256", required=True)
    parser.add_argument("--now", required=True); parser.add_argument("--registry-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = sync_one(json.loads(args.spec.read_text()), json.loads(args.grants.read_text()), run_id=args.run_id,
            source_snapshot_sha256=args.source_snapshot_sha256, now=args.now, registry_root=args.registry_root)
        print(json.dumps(result, sort_keys=True)); return 0
    except (OSError, ValueError, SyncBlocked, snapshots.SnapshotBlocked, snapshots.SnapshotInvalid) as exc:
        print(json.dumps({"status": "BLOCKED", "cause": str(exc)}, sort_keys=True)); return 2


if __name__ == "__main__": raise SystemExit(main())
