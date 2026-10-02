"""Stage only accepted ``02-native-build`` ELF artifacts for binary hardening.

The native build attempt contains logs and scratch data as well as its published binaries.  This
adapter creates a small immutable projection containing only the binaries named by the accepted
``native-build.json`` and binds every copied byte to the accepted pointer, envelope and result.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from execution_state import Blocked, atomic_json, data_path, digest, file_hash, read_json, run_path
import native_build
from schema_validate import validate_document

JOB = "02-binary-hardening"
MANIFEST = "binary-input.json"
SCHEMA = "appsec-review/binary-hardening-input/1"


def _snapshot(run_id: str) -> str:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not path.is_file() or path.is_symlink():
        raise Blocked(f"{JOB}: staged artifact manifest is required")
    return "sha256:" + file_hash(path)


def _relative(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise Blocked(f"{JOB}: {label} is missing")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise Blocked(f"{JOB}: {label} is not a normalized relative path")
    return path


def _expected(run_id: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    attempt = native_build.validate(run_id)
    result_path = attempt / native_build.RESULT
    envelope_path = attempt / "result.json"
    pointer_path = native_build.root(run_id) / "accepted.json"
    result = read_json(result_path)
    pointer = read_json(pointer_path)
    binaries: list[dict[str, Any]] = []
    for unit in result.get("units", []):
        unit_id = unit.get("unit_id")
        if not isinstance(unit_id, str) or not unit_id:
            raise Blocked(f"{JOB}: native build has an invalid unit id")
        for record in unit.get("binaries", []):
            source_rel = _relative(record.get("artifact_path"), "native binary artifact path")
            source = attempt / source_rel
            try:
                source.resolve().relative_to(attempt.resolve())
            except ValueError as exc:
                raise Blocked(f"{JOB}: native binary leaves its accepted attempt") from exc
            expected_sha = record.get("sha256")
            if (not source.is_file() or source.is_symlink() or
                    expected_sha != "sha256:" + file_hash(source) or
                    record.get("size_bytes") != source.stat().st_size):
                raise Blocked(f"{JOB}: accepted native binary changed")
            suffix = source_rel.parts
            try:
                marker = suffix.index("binaries")
                published_rel = Path(*suffix[marker + 1:])
            except (ValueError, IndexError):
                published_rel = Path(source.name)
            # Build unit IDs are semantic identifiers (for example ``dir:.``), not path segments.
            # Project them through a stable filesystem-safe identity and retain the original unit
            # in the accepted native-build lineage rather than weakening the path contract.
            target_rel = Path("binaries") / ("unit-" + digest(unit_id)[:12]) / published_rel
            binaries.append({"path": target_rel.as_posix(), "source_artifact_path": source_rel.as_posix(),
                "sha256": expected_sha, "bytes": source.stat().st_size})
    # ADR-0014: no binaries is not a failure; the worker's probe finds no candidates and the job is
    # SKIPPED with not-applicable-no-matching-inputs (freeciv21, doom3-bfg: zero built units).
    manifest = {"schema": SCHEMA, "run_id": run_id, "source_snapshot_sha256": _snapshot(run_id),
        "native_build": {"attempt_id": attempt.name,
            "pointer_sha256": "sha256:" + file_hash(pointer_path),
            "result_sha256": "sha256:" + file_hash(result_path),
            "envelope_sha256": "sha256:" + file_hash(envelope_path)},
        "binaries": sorted(binaries, key=lambda row: row["path"])}
    errors = validate_document(manifest, "binary-hardening-input.schema.json")
    if errors:
        raise Blocked(f"{JOB}: binary input manifest is invalid ({len(errors)} errors)")
    return attempt, manifest, pointer


def stage(run_id: str, job: str = JOB) -> Path:
    """Return an immutable run-owned directory containing accepted native binaries only. ``job`` is
    the consuming job whose namespace holds the copy (02-binary-component-cve-match stages its own,
    so two jobs never race on one directory)."""
    attempt, manifest, _pointer = _expected(run_id)
    base = data_path(run_id, "jobs", job, "inputs")
    destination = base / (manifest["native_build"]["attempt_id"] + "-v2")
    if destination.exists():
        validate(run_id, destination / "binaries")
        return destination / "binaries"
    base.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".binary-input-", dir=base))
    try:
        (staging / "binaries").mkdir()  # present even when the native build published none
        for record in manifest["binaries"]:
            source = attempt / record["source_artifact_path"]
            target = staging / record["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        atomic_json(staging / MANIFEST, manifest)
        os.replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    validate(run_id, destination / "binaries")
    return destination / "binaries"


def validate(run_id: str, source_root: Path) -> dict[str, Any]:
    source_root = Path(source_root).absolute()
    manifest_path = source_root.parent / MANIFEST
    if source_root.name != "binaries" or not source_root.is_dir() or source_root.is_symlink():
        raise Blocked(f"{JOB}: binary input root is not canonical")
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise Blocked(f"{JOB}: binary input manifest is absent")
    observed = read_json(manifest_path)
    errors = validate_document(observed, "binary-hardening-input.schema.json")
    if errors:
        raise Blocked(f"{JOB}: binary input manifest fails validation")
    _attempt, expected, _pointer = _expected(run_id)
    if observed != expected:
        raise Blocked(f"{JOB}: binary input lineage is stale")
    expected_paths = set()
    for record in observed["binaries"]:
        path = source_root.parent / record["path"]
        try:
            path.resolve().relative_to(source_root.resolve())
        except ValueError as exc:
            raise Blocked(f"{JOB}: staged binary leaves its input root") from exc
        if (not path.is_file() or path.is_symlink() or path.stat().st_size != record["bytes"] or
                "sha256:" + file_hash(path) != record["sha256"]):
            raise Blocked(f"{JOB}: staged binary changed")
        expected_paths.add(path.resolve())
    observed_paths = {path.resolve() for path in source_root.rglob("*") if path.is_file()}
    if observed_paths != expected_paths:
        raise Blocked(f"{JOB}: binary input contains undeclared files")
    return observed


def stage_request(run_id: str, dagster_run_id: str) -> Path:
    source = stage(run_id)
    path = data_path(run_id, "jobs", JOB, "requests", dagster_run_id + ".json")
    if path.exists() and not path.is_symlink():
        observed = read_json(path)
        if (not isinstance(observed, dict) or set(observed) != {"schema", "run_id", "job_id",
                "source_generation", "generated_at", "source_root"} or
                observed.get("schema") != "appsec-review/vendor-evidence-orchestration-request/1.0" or
                observed.get("run_id") != run_id or observed.get("job_id") != JOB or
                observed.get("source_generation") != _snapshot(run_id) or
                observed.get("source_root") != str(source)):
            raise Blocked(f"{JOB}: existing request has stale or invalid lineage")
        return path
    request = {"schema": "appsec-review/vendor-evidence-orchestration-request/1.0",
        "run_id": run_id, "job_id": JOB, "source_generation": _snapshot(run_id),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_root": str(source)}
    if path.is_symlink():
        raise Blocked(f"{JOB}: request path is linked")
    atomic_json(path, request)
    return path
