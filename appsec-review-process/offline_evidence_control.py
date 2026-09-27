#!/usr/bin/env python3
"""Stage the run-owned binding to pre-synchronized dependency reference data.

This command never downloads data.  It verifies both immutable dependency database generations,
the closed lifecycle table, and their age ceilings before publishing the small engagement control
consumed by ``automatic_evidence_inputs``.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import automatic_evidence_inputs as automatic
import dependency_snapshot_registry as snapshots
from execution_state import Blocked, atomic_json, data_path, identifier, run_path
from schema_validate import validate_document


def _regular(path: Path, label: str, *, directory: bool = False) -> Path:
    value = Path(path)
    present = value.is_dir() if directory else value.is_file()
    if not value.is_absolute() or not present or value.is_symlink():
        raise Blocked(f"offline evidence control: {label} must be an absolute real {'directory' if directory else 'file'}")
    return value.resolve()


def stage_control(run_id: str, *, snapshot_registry: Path, max_database_age_seconds: int,
                  reference_table: Path, max_reference_age_days: int,
                  now: datetime | None = None) -> Path:
    run_id = identifier(run_id)
    root = run_path(run_id)
    manifest = root / "inputs" / "artifact-manifest.json"
    if not root.is_dir() or root.is_symlink() or not manifest.is_file() or manifest.is_symlink():
        raise Blocked("offline evidence control: staged engagement is required")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in
           (max_database_age_seconds, max_reference_age_days)):
        raise Blocked("offline evidence control: explicit non-negative age ceilings are required")
    registry = _regular(snapshot_registry, "snapshot registry", directory=True)
    evaluated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    for kind in sorted(snapshots.KINDS):
        try:
            snapshots.resolve(kind, registry, max_age_seconds=max_database_age_seconds, now=evaluated)
        except (snapshots.SnapshotBlocked, snapshots.SnapshotInvalid, snapshots.SnapshotStale) as exc:
            raise Blocked(f"offline evidence control: {kind} is not a current verified snapshot") from exc
    table_path = _regular(reference_table, "lifecycle reference table")
    try:
        table: Any = json.loads(table_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise Blocked("offline evidence control: lifecycle reference table is unreadable") from exc
    if validate_document(table, "dependency-lifecycle-reference-table.schema.json"):
        raise Blocked("offline evidence control: lifecycle reference table violates its closed schema")
    as_of = datetime.strptime(table["as_of"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    age_days = (evaluated - as_of).days
    if age_days < 0 or age_days > max_reference_age_days:
        raise Blocked("offline evidence control: lifecycle reference table is stale or from the future")
    value = {"schema": automatic.CONTROL_SCHEMA,
        "offline_snapshots": {"registry_path": str(registry),
                              "max_database_age_seconds": max_database_age_seconds},
        "dependency_lifecycle": {"reference_table_path": str(table_path),
                                 "max_reference_age_days": max_reference_age_days}}
    if validate_document(value, "automatic-evidence-input-control.schema.json"):
        raise Blocked("offline evidence control: generated control violates its closed schema")
    target = data_path(run_id, "controls", automatic.CONTROL)
    if target.exists():
        try: existing = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise Blocked("offline evidence control: existing control is unreadable") from None
        if target.is_symlink() or existing != value:
            raise Blocked("offline evidence control: existing control names different references")
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(target, value)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["stage-control"]); parser.add_argument("run_id")
    parser.add_argument("--snapshot-registry", type=Path, required=True)
    parser.add_argument("--max-database-age-seconds", type=int, required=True)
    parser.add_argument("--reference-table", type=Path, required=True)
    parser.add_argument("--max-reference-age-days", type=int, required=True)
    args = parser.parse_args()
    try:
        print(stage_control(args.run_id, snapshot_registry=args.snapshot_registry,
            max_database_age_seconds=args.max_database_age_seconds,
            reference_table=args.reference_table, max_reference_age_days=args.max_reference_age_days))
        return 0
    except (Blocked, OSError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "cause": str(exc)}, sort_keys=True)); return 2


if __name__ == "__main__":
    raise SystemExit(main())
