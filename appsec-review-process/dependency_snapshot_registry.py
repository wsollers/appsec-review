#!/usr/bin/env python3
"""Register and verify supplied offline Grype/OSV database mirrors.

This module has no network client.  Synchronization is deliberately a separate, permissioned
operation that leaves a directory and a closed metadata record for ``register`` to consume.
Registration copies regular files into an immutable content-addressed snapshot, publishes a
manifest, and advances a tiny current pointer.  Resolution re-hashes every byte and applies the
caller's explicit age ceiling; missing and stale are distinct terminal reasons.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
from typing import Any

from schema_validate import validate_document
import tunables

KINDS = {"grype-db", "osv"}
SCHEMA = "appsec-review/dependency-database-snapshot/1.0"
POINTER_SCHEMA = "appsec-review/dependency-database-current/1.0"
SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENT = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,95}\Z")


class SnapshotBlocked(RuntimeError): pass
class SnapshotStale(RuntimeError): pass
class SnapshotInvalid(RuntimeError): pass


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256(); size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk); size += len(chunk)
    return "sha256:" + digest.hexdigest(), size


def _time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise SnapshotInvalid(f"{label} must be a UTC second timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _metadata(value: Any, kind: str) -> dict[str, str]:
    fields = {"database_kind", "vendor_build", "schema_version", "snapshot_id", "data_timestamp"}
    if (not isinstance(value, dict) or set(value) != fields or value.get("database_kind") != kind or
            not all(isinstance(value[key], str) for key in fields) or
            not all(IDENT.fullmatch(value[key]) for key in ("vendor_build", "schema_version", "snapshot_id"))):
        raise SnapshotInvalid("snapshot metadata is not a closed identity record")
    _time(value["data_timestamp"], "data_timestamp")
    return value


def inventory(source: Path) -> list[dict[str, Any]]:
    source = Path(source)
    if not source.is_absolute() or not source.is_dir() or source.is_symlink():
        raise SnapshotBlocked("supplied mirror directory is absent")
    records = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink(): raise SnapshotInvalid("supplied mirror contains a symbolic link")
        if path.is_dir(): continue
        if not path.is_file(): raise SnapshotInvalid("supplied mirror contains a non-regular entry")
        relative = path.relative_to(source).as_posix(); pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
            raise SnapshotInvalid("supplied mirror contains an unsafe path")
        digest, size = _hash_file(path)
        records.append({"path": relative, "sha256": digest, "bytes": size})
    if not records: raise SnapshotBlocked("supplied mirror directory is empty")
    return records


def register(kind: str, source: Path, metadata_path: Path, registry_root: Path, *,
             link_files: bool = False) -> dict[str, Any]:
    # link_files is only for a staging tree whose files are themselves hard links to already immutable
    # bytes (register_osv_feed); a caller-supplied mirror is always copied.
    if kind not in KINDS: raise SnapshotInvalid("unknown database kind")
    try: metadata = _metadata(json.loads(Path(metadata_path).read_text()), kind)
    except (OSError, ValueError) as exc: raise SnapshotInvalid("snapshot metadata is unreadable") from exc
    files = inventory(Path(source)); tree_sha = _sha(_canonical(files))
    manifest = {"schema": SCHEMA, **metadata, "sha256": tree_sha, "files": files}
    if validate_document(manifest, "dependency-database-snapshot.schema.json"):
        raise SnapshotInvalid("generated snapshot manifest violates its closed schema")
    snapshot_id = metadata["snapshot_id"]; root = Path(registry_root).resolve()
    if root == Path(root.anchor) or len(root.parts) < 3: raise SnapshotInvalid("unsafe registry root")
    destination = root / "snapshots" / kind / snapshot_id
    if destination.exists():
        existing = json.loads((destination / "manifest.json").read_text())
        if existing != manifest: raise SnapshotInvalid("snapshot id already names different bytes")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".snapshot-", dir=destination.parent))
        try:
            data = staging / "data"; data.mkdir()
            for record in files:
                source_path = Path(source).joinpath(*PurePosixPath(record["path"]).parts)
                target = data.joinpath(*PurePosixPath(record["path"]).parts); target.parent.mkdir(parents=True, exist_ok=True)
                if link_files:
                    try: os.link(source_path, target)
                    except OSError: shutil.copyfile(source_path, target)
                else: shutil.copyfile(source_path, target)
                if _hash_file(target) != (record["sha256"], record["bytes"]):
                    raise SnapshotInvalid("supplied mirror changed during registration")
            (staging / "manifest.json").write_bytes(_canonical(manifest)); os.replace(staging, destination)
        except BaseException:
            if staging.exists(): shutil.rmtree(staging)
            raise
    pointer_dir = root / "current"; pointer_dir.mkdir(parents=True, exist_ok=True)
    pointer = {"schema": POINTER_SCHEMA, "database_kind": kind, "snapshot_id": snapshot_id,
               "manifest_sha256": _sha(_canonical(manifest))}
    temporary = pointer_dir / ("." + kind + ".json.tmp"); temporary.write_bytes(_canonical(pointer))
    os.replace(temporary, pointer_dir / (kind + ".json"))
    return {**manifest, "data_root": str(destination / "data")}


def register_osv_feed(feed_root: Path, registry_root: Path, *, max_age_seconds: int, now: datetime) -> dict[str, Any]:
    """Bind the multi-ecosystem OSV bulk snapshot published by ``osv_feed.py`` into this registry as
    the ``osv`` database (replacing a hand-supplied single-ecosystem mirror).

    The feed is resolved read-only through ``osv_snapshot`` (hash-verified, age-checked): an over-age or
    missing feed raises ``SnapshotStale`` / ``SnapshotBlocked`` exactly as ``resolve`` would, so the SCA
    job fails on it. Ecosystems the publisher could not fetch are recorded as gaps in
    ``source-provenance.json`` (part of the hashed snapshot); they are absent from the mirror, and OSV-Scanner
    reports them as a coverage gap (see ``osv_exit_accepted``), never as "no vulnerabilities".
    """
    import osv_snapshot
    from datetime import timedelta
    resolution = osv_snapshot.resolve_snapshot(feed_root, max_age=timedelta(seconds=max_age_seconds), now=now)
    if not resolution.usable:
        if resolution.outcome == osv_snapshot.BLOCKED: raise SnapshotBlocked(f"osv feed: {resolution.reason}")
        if resolution.reason == "SNAPSHOT_TOO_OLD": raise SnapshotStale("osv snapshot is stale")
        raise SnapshotInvalid(f"osv feed: {resolution.reason}")
    identity = resolution.identity
    root = Path(registry_root).resolve()
    if root == Path(root.anchor) or len(root.parts) < 3: raise SnapshotInvalid("unsafe registry root")
    staging_parent = root / "staging"; staging_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="osv-feed-", dir=staging_parent))
    try:
        mirror = staging / "mirror"
        for ecosystem in identity["ecosystems"]:
            target = mirror / "osv-scanner" / ecosystem / "all.zip"; target.parent.mkdir(parents=True)
            source = Path(resolution.mount_dir) / "osv-scanner" / ecosystem / "all.zip"
            try: os.link(source, target)
            except OSError: shutil.copyfile(source, target)
        provenance = {"schema": "appsec-review/dependency-snapshot-source-provenance/1.0", "database_kind": "osv",
                      "feed_snapshot_id": identity["snapshot_id"], "feed_manifest_sha256": identity["manifest_sha256"],
                      "ecosystems": {k: {"sha256": v["sha256"], "fetched_at": v["fetched_at"], "record_count": v["record_count"]}
                                     for k, v in sorted(identity["ecosystems"].items())},
                      "gaps": identity["gaps"]}
        (mirror / "source-provenance.json").write_bytes(_canonical(provenance))
        metadata = staging / "metadata.json"
        metadata.write_text(json.dumps({"database_kind": "osv", "vendor_build": "osv-bulk-gcs", "schema_version": "osv-1",
                                        "snapshot_id": identity["snapshot_id"],
                                        "data_timestamp": identity["data_timestamp"]}, sort_keys=True) + "\n")
        return register("osv", mirror, metadata, root, link_files=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def resolve(kind: str, registry_root: Path, *, max_age_seconds: int, now: datetime,
            warn_age_seconds: int | None = None, snapshot_id: str | None = None) -> dict[str, Any]:
    """The current snapshot of ``kind`` (or, with ``snapshot_id``, that registered snapshot, which a
    run bound earlier), every byte re-hashed against its manifest and the age ceiling applied at ``now``."""
    if kind not in KINDS: raise SnapshotInvalid("unknown database kind")
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds < 0:
        raise SnapshotInvalid("an explicit non-negative age ceiling is required")
    if (warn_age_seconds is not None and (isinstance(warn_age_seconds, bool) or
            not isinstance(warn_age_seconds, int) or warn_age_seconds < 0 or
            warn_age_seconds > max_age_seconds)):
        raise SnapshotInvalid("warning age must be non-negative and no greater than the age ceiling")
    pointer_path = Path(registry_root).resolve() / "current" / (kind + ".json")
    if snapshot_id is not None:
        if not isinstance(snapshot_id, str) or not IDENT.fullmatch(snapshot_id):
            raise SnapshotInvalid(f"{kind} bound snapshot id is invalid")
        pointer = {"snapshot_id": snapshot_id, "manifest_sha256": None}
    else:
        if not pointer_path.is_file() or pointer_path.is_symlink(): raise SnapshotBlocked(f"{kind} snapshot is absent")
        try: pointer = json.loads(pointer_path.read_text())
        except (OSError, ValueError) as exc: raise SnapshotInvalid(f"{kind} pointer is unreadable") from exc
        if set(pointer) != {"schema", "database_kind", "snapshot_id", "manifest_sha256"} or pointer.get("schema") != POINTER_SCHEMA or pointer.get("database_kind") != kind:
            raise SnapshotInvalid(f"{kind} pointer is invalid")
    snapshot = pointer_path.parents[1] / "snapshots" / kind / pointer["snapshot_id"]
    manifest_path = snapshot / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink(): raise SnapshotBlocked(f"{kind} snapshot is absent")
    try: manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError) as exc: raise SnapshotInvalid(f"{kind} manifest is unreadable") from exc
    if ((pointer["manifest_sha256"] is not None and _sha(_canonical(manifest)) != pointer["manifest_sha256"]) or
            manifest.get("schema") != SCHEMA or manifest.get("database_kind") != kind or
            manifest.get("snapshot_id") != pointer["snapshot_id"]):
        raise SnapshotInvalid(f"{kind} pointer and manifest differ")
    data = snapshot / "data"; actual = inventory(data)
    if actual != manifest.get("files") or _sha(_canonical(actual)) != manifest.get("sha256"):
        raise SnapshotInvalid(f"{kind} snapshot bytes changed")
    current = now.astimezone(timezone.utc)
    age = int((current - _time(manifest["data_timestamp"], "data_timestamp")).total_seconds())
    if age < 0: raise SnapshotInvalid(f"{kind} snapshot timestamp is in the future")
    if age > max_age_seconds: raise SnapshotStale(f"{kind} snapshot is stale")
    warning = warn_age_seconds is not None and age > warn_age_seconds
    return {**{key: manifest[key] for key in ("database_kind", "vendor_build", "schema_version", "snapshot_id", "sha256", "data_timestamp")},
            "data_root": str(data), "age_seconds": age, "warn_age_seconds": warn_age_seconds,
            "max_age_seconds": max_age_seconds, "freshness": "warning" if warning else "fresh",
            "warnings": ([f"{kind} snapshot is within the allowed range but exceeds its warning age"] if warning else [])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("register"); add.add_argument("--kind", choices=sorted(KINDS), required=True)
    add.add_argument("--source", type=Path, required=True); add.add_argument("--metadata", type=Path, required=True)
    add.add_argument("--registry-root", type=Path, required=True)
    feed = sub.add_parser("register-osv-feed"); feed.add_argument("--feed-root", type=Path, required=True)
    feed.add_argument("--registry-root", type=Path, required=True); feed.add_argument("--max-age-seconds", type=int,
                      default=tunables.shared("reference_snapshot_max_age_seconds"))
    feed.add_argument("--now", required=True)
    get = sub.add_parser("resolve"); get.add_argument("--kind", choices=sorted(KINDS), required=True)
    get.add_argument("--registry-root", type=Path, required=True); get.add_argument("--max-age-seconds", type=int, required=True)
    get.add_argument("--warn-age-seconds", type=int)
    get.add_argument("--now", required=True)
    args = parser.parse_args()
    try:
        if args.command == "register-osv-feed":
            value = register_osv_feed(args.feed_root, args.registry_root, max_age_seconds=args.max_age_seconds,
                                      now=_time(args.now, "now")); print(json.dumps(value, sort_keys=True)); return 0
        value = (register(args.kind, args.source, args.metadata, args.registry_root) if args.command == "register" else
                 resolve(args.kind, args.registry_root, max_age_seconds=args.max_age_seconds,
                         warn_age_seconds=args.warn_age_seconds, now=_time(args.now, "now")))
        print(json.dumps(value, sort_keys=True)); return 0
    except SnapshotBlocked as exc: print(json.dumps({"status": "BLOCKED", "cause": str(exc)})); return 2
    except SnapshotStale as exc: print(json.dumps({"status": "FAILED", "cause": str(exc)})); return 3
    except SnapshotInvalid as exc: print(json.dumps({"status": "FAILED", "cause": str(exc)})); return 4


if __name__ == "__main__": raise SystemExit(main())
