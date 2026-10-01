#!/usr/bin/env python3
"""cve-bin-tool's offline database, DERIVED from the pinned NVD snapshot (no download of its own).

`build()` runs outside every engagement run (Dagster `nvd_reference_sync`, after the NVD op). It
resolves the NVD snapshot `nvd_feed.py` published (`sca_nvd_snapshot.resolve_snapshot`: every
manifest and blob re-hashed), copies the layer blobs in replay order (bootstrap yearly feeds, then
each delta's API pages, oldest first), and runs the pinned `tool-cve-bin-tool` image with
`--network none` over them: `scripts/tool-cve-bin-tool/build_db.py`, mounted read-only (AGENTS.md
exception approved by William, 2026-10-01), loads them through cve-bin-tool's own
`format_data_api2` + `populate_db`. The result is published immutably under
`data/feeds/cve-bin-tool/snapshots/<id>/` and `current.json` advances last. The same NVD snapshot,
image and builder give the same id, so a rebuild of unchanged inputs is a no-op.

There is no second staleness check: the database is exactly as fresh as the NVD snapshot it names.
`resolve_db()` (the scan node's preflight) re-hashes the files and checks that the database was built
from the NVD snapshot the run is bound to and with the pinned image; anything else is BLOCKED.

Only NVD is loaded. cve-bin-tool's other sources (curl, EPSS, GitLab, OSV, PURL2CPE, RedHat, RSD) and
its CISA KEV download are never used; the scan disables them and records the limitation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
from typing import Any, Callable
import uuid

import container_execution as ce
from execution_state import Blocked, Lock, atomic_json, now as now_text
import sca_nvd_snapshot as nvd
from schema_validate import validate_document

SCHEMA = "appsec-review/cve-bin-tool-db-manifest/1"
SCHEMA_FILE = "cve-bin-tool-db-manifest.schema.json"
POINTER_SCHEMA = "appsec-review/cve-bin-tool-db-pointer/1"
IMAGE_ID = "tool-cve-bin-tool"
REPO = Path(__file__).resolve().parents[1]
BUILDER_DIR = REPO / "scripts" / "tool-cve-bin-tool"
TOOL_RECORD = REPO / "images" / IMAGE_ID / "tool.json"
FILES = ("cve.db", "version_map.db")
SOURCES = ("NVD",)
# Every data source the scan must disable (cve-bin-tool 3.4 `--disable-data-source` names).
DISABLED_SOURCES = ("CURL", "EPSS", "GAD", "OSV", "PURL2CPE", "REDHAT", "RSD")
# The sqlite checker refreshes its version map from sqlite.org when its datestamp is this old.
VERSION_MAP_REFRESH = timedelta(days=30)
BUILD_TIMEOUT_SECONDS = 3600
LIMITATIONS = (
    "Only NVD is loaded; cve-bin-tool's curl, EPSS, GitLab, OSV, PURL2CPE, RedHat and RSD sources are not used.",
    "The sqlite checker's SQLITE_SOURCE_ID map is empty (it needs sqlite.org); sqlite is detected only by its version string.",
    "Matches are vendor/product/version-range leads from NVD CPE data, never a finding or reachability claim.",
)


class DbUnavailable(Blocked):
    """The database cannot be used for this run; `reason` names why."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


def feed_root() -> Path:
    configured = os.environ.get("APPSEC_CVE_BIN_TOOL_DB_ROOT")
    return Path(configured) if configured else REPO / "data" / "feeds" / "cve-bin-tool"


def nvd_root() -> Path:
    configured = os.environ.get("APPSEC_NVD_ROOT")
    return Path(configured) if configured else REPO / "data" / "feeds" / "nvd"


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def pinned_tool() -> dict[str, str]:
    """The pinned image digest (B16 registry record) and the tool version (images/<id>/tool.json)."""
    try:
        record = ce.load_image_registry(ce.IMAGES_DIR)[IMAGE_ID]
        version = json.loads(TOOL_RECORD.read_text(encoding="utf-8"))["version"]
    except (KeyError, OSError, ValueError, ce.ContainerRequestError) as exc:
        raise DbUnavailable("IMAGE_UNAVAILABLE", f"{IMAGE_ID} has no registered image record") from exc
    return {"image_digest": record["digest"], "tool_version": version}


def builder_sha256() -> str:
    """One hash over every file the builder mount exposes, so a builder edit is a new identity."""
    listing = [(path.relative_to(BUILDER_DIR).as_posix(), _sha_file(path))
               for path in sorted(BUILDER_DIR.rglob("*")) if path.is_file() and "__pycache__" not in path.parts]
    return hashlib.sha256(_canonical(listing)).hexdigest()


def replay_layers(root: Path, identity: dict) -> list[tuple[Path, str, int]]:
    """Blob paths of the resolved NVD snapshot in replay order: the bootstrap's layers, then each
    incremental snapshot's pages, oldest snapshot first. Each snapshot id is content-derived, so a
    manifest that is not the one the resolver verified cannot carry the same id."""
    ordered = []
    for snapshot_id in reversed(identity["chain_snapshot_ids"]):
        manifest = json.loads((root / "snapshots" / snapshot_id / "manifest.json").read_bytes())
        if nvd.snapshot_id_of(manifest) != snapshot_id:
            raise DbUnavailable("NVD_CHANGED", f"snapshot {snapshot_id} no longer matches its id")
        # _layer_blobs is the resolver's own reading of a manifest's layers (one rule, not two).
        ordered += [(root / path, sha, size) for path, sha, size in nvd._layer_blobs(manifest, snapshot_id)]
    return ordered


def run_builder(input_dir: Path, output_dir: Path, *, image_digest: str) -> None:
    """The pinned image over the staged layers, no network, read-only root, builder mounted read-only."""
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None or not defaults["container_user"]:
        raise DbUnavailable("DOCKER_UNAVAILABLE", "Docker or a bounded container user is unavailable")
    argv = [str(defaults["docker_executable"]), "run", "--rm", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
            "--user", defaults["container_user"], "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m",
            "-e", "HOME=/scratch/home", "-e", "TMPDIR=/scratch/tmp",
            "-v", f"{input_dir.resolve()}:/input:ro", "-v", f"{BUILDER_DIR.resolve()}:/builder:ro",
            "-v", f"{output_dir.resolve()}:/scratch:rw",
            "--entrypoint", "/opt/tool/bin/python", image_digest, "-B", "/builder/build_db.py", "/input", "/scratch/db"]
    (output_dir / "home").mkdir()
    (output_dir / "tmp").mkdir()
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=BUILD_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DbUnavailable("BUILD_FAILED", type(exc).__name__) from None
    (output_dir / "builder-stderr.log").write_bytes(completed.stderr[-1_000_000:])
    if completed.returncode != 0:
        raise DbUnavailable("BUILD_FAILED", f"builder exited {completed.returncode}")


def _readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)


def _check_database(directory: Path, tool_version: str) -> dict[str, Any]:
    try:
        build = json.loads((directory / "build.json").read_bytes())
        with _readonly(directory / "cve.db") as connection:
            healthy = connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            count = connection.execute("SELECT COUNT(*) FROM cve_severity WHERE data_source = 'NVD'").fetchone()[0]
            others = connection.execute("SELECT COUNT(*) FROM cve_severity WHERE data_source != 'NVD'").fetchone()[0]
        with _readonly(directory / "version_map.db") as mapping:
            stamp = mapping.execute("SELECT MAX(datestamp) FROM latest_update_sqlite").fetchone()[0]
    except (OSError, ValueError, sqlite3.Error) as exc:
        raise DbUnavailable("BUILD_INVALID", f"built database cannot be read: {type(exc).__name__}") from None
    if not healthy or others or count <= 0 or count != build.get("cve_count") or build.get("sources") != list(SOURCES):
        raise DbUnavailable("BUILD_INVALID", "built database is damaged, empty, or holds a source other than NVD")
    if build.get("tool_version") != tool_version or not isinstance(stamp, (int, float)):
        raise DbUnavailable("BUILD_INVALID", "built database names another tool version or has no version-map stamp")
    return {"cve_count": count, "range_count": build.get("range_count"), "layer_records": build.get("layer_records"),
            "version_map_stamp": datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")}


def build(root: Path | None = None, nvd_data_root: Path | None = None, *, clock: Callable[[], datetime] | None = None,
          runner: Callable[..., None] = run_builder, tool: dict[str, str] | None = None) -> dict[str, Any]:
    """Derive and publish the database for the current NVD snapshot; returns the current pointer."""
    root = Path(root or feed_root()).absolute()
    source_root = Path(nvd_data_root or nvd_root()).absolute()
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    tool = tool or pinned_tool()
    resolved = nvd.resolve_snapshot(source_root, max_age=nvd.NO_AGE_LIMIT, now=moment)
    if not resolved.usable:
        raise DbUnavailable(f"NVD_{resolved.reason}", resolved.detail)
    identity = resolved.identity
    inputs = {"nvd_snapshot_id": identity["snapshot_id"], "nvd_manifest_sha256": identity["manifest_sha256"],
              "nvd_content_sha256": identity["content_sha256"], "nvd_cursor": identity["cursor"],
              "image_digest": tool["image_digest"], "tool_version": tool["tool_version"],
              "builder_sha256": builder_sha256(), "sources": list(SOURCES)}
    snapshot_id = "sha256-" + hashlib.sha256(_canonical(inputs)).hexdigest()[:16]
    with Lock(root / "locks" / "writer.lock"):
        current = root / "current.json"
        if current.is_file() and json.loads(current.read_bytes()).get("snapshot_id") == snapshot_id:
            return json.loads(current.read_bytes())
        staging = root / "staging" / (moment.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
        layers_dir, output = staging / "input" / "layers", staging / "output"
        layers_dir.mkdir(parents=True)
        output.mkdir()
        try:
            for index, (path, sha, size) in enumerate(replay_layers(source_root, identity)):
                target = layers_dir / f"{index:06d}.json.gz"
                shutil.copyfile(path, target)
                if target.stat().st_size != size or _sha_file(target) != sha:
                    raise DbUnavailable("NVD_CHANGED", f"{path.name} changed after it was verified")
            runner(staging / "input", output, image_digest=tool["image_digest"])
            built = output / "db"
            facts = _check_database(built, tool["tool_version"])
            files = {name: {"sha256": _sha_file(built / name), "size_bytes": (built / name).stat().st_size}
                     for name in FILES}
            manifest = {"schema": SCHEMA, "snapshot_id": snapshot_id, **inputs, "nvd_retrieved_at": identity["retrieved_at"],
                        "built_at": moment.isoformat(timespec="seconds").replace("+00:00", "Z"), **facts,
                        "files": files, "disabled_sources": list(DISABLED_SOURCES), "limitations": list(LIMITATIONS)}
            errors = validate_document(manifest, SCHEMA_FILE)
            if errors:
                raise DbUnavailable("BUILD_INVALID", f"manifest violates {SCHEMA_FILE}: {errors[0]}")
            directory = root / "snapshots" / snapshot_id
            directory.mkdir(parents=True, exist_ok=False)
            for name in FILES:
                shutil.copyfile(built / name, directory / name)
                (directory / name).chmod(0o444)
            atomic_json(directory / "manifest.json", manifest)
            pointer = {"schema": POINTER_SCHEMA, "snapshot_id": snapshot_id,
                       "manifest_sha256": _sha_file(directory / "manifest.json"), "published_at": now_text()}
            atomic_json(current, pointer)   # the sole commit point
        except BaseException:
            atomic_json(staging / "attempt.json", {"status": "FAILED", "snapshot_id": snapshot_id})
            raise
        shutil.rmtree(staging, ignore_errors=True)
        return pointer


def resolve_db(root: Path, *, nvd_identity: dict, tool: dict[str, str], now: datetime) -> dict[str, Any]:
    """The scan node's preflight: the published manifest, re-verified from bytes, or DbUnavailable.
    `nvd_identity` is the identity record of the NVD snapshot this run is bound to."""
    root = Path(root).absolute()
    pointer_path = root / "current.json"
    if not pointer_path.is_file():
        raise DbUnavailable("DB_MISSING", "no cve-bin-tool database has been published")
    try:
        pointer = json.loads(pointer_path.read_bytes())
        directory = root / "snapshots" / pointer["snapshot_id"]
        data = (directory / "manifest.json").read_bytes()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise DbUnavailable("DB_INVALID", f"current.json or its manifest is unreadable: {type(exc).__name__}") from None
    if hashlib.sha256(data).hexdigest() != pointer.get("manifest_sha256"):
        raise DbUnavailable("DB_INVALID", "manifest hash differs from current.json")
    manifest = json.loads(data)
    if validate_document(manifest, SCHEMA_FILE) or manifest["snapshot_id"] != pointer["snapshot_id"]:
        raise DbUnavailable("DB_INVALID", f"manifest violates {SCHEMA_FILE}")
    for name in FILES:
        entry = manifest["files"][name]
        path = directory / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size != entry["size_bytes"] or _sha_file(path) != entry["sha256"]:
            raise DbUnavailable("DB_INVALID", f"{name} differs from its manifest")
    if (manifest["nvd_snapshot_id"], manifest["nvd_manifest_sha256"]) != (nvd_identity["snapshot_id"], nvd_identity["manifest_sha256"]):
        raise DbUnavailable("DB_STALE_FOR_NVD_SNAPSHOT",
                            f"database was built from NVD {manifest['nvd_snapshot_id']}, the run is bound to {nvd_identity['snapshot_id']}")
    if (manifest["image_digest"], manifest["tool_version"]) != (tool["image_digest"], tool["tool_version"]):
        raise DbUnavailable("DB_STALE_FOR_IMAGE", "database was built with another cve-bin-tool image or version")
    stamp = datetime.fromisoformat(manifest["version_map_stamp"].replace("Z", "+00:00"))
    if now - stamp >= VERSION_MAP_REFRESH:
        raise DbUnavailable("DB_VERSION_MAP_EXPIRED",
                            "the sqlite checker would try to reach sqlite.org (its map is 30 days old); rebuild the database")
    return {**manifest, "directory": str(directory)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=["build"])
    parser.add_argument("--root", type=Path)
    parser.add_argument("--nvd-root", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(build(args.root, args.nvd_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
