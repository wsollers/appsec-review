#!/usr/bin/env python3
"""Validate that a lane produced the minimum expected output shape.

Extended 2026-09-19 to also run status.json through schema_validate.py's lane-status schema (the
"on write" half of the schema-validator wiring -- see claude project TODO). This does NOT yet gate
review_cli.py's cmd_run/final_status -- it's still a standalone check you run by hand, same as
before this change, so it's safe to run against every existing archived run without breaking
anything. Schema warnings (findings[]/artifacts_read[] not yet populated) do not fail the run;
schema errors (a populated field that's actually malformed, e.g. a bad classification/taxonomy
pairing) do.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from schema_validate import SchemaStore, validate_lane_status

ROOT = Path(__file__).resolve().parent
REQUIRED_MD_HEADINGS = ("## Budget", "## Summary", "## Inputs Used", "## Recommended Next Step")


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def process_names() -> list[str]:
    return sorted(p.name for p in ROOT.iterdir() if p.is_dir() and p.name[:2].isdigit() and "-" in p.name)


def resolve_process(name: str) -> str:
    names = process_names()
    if name in names:
        return name
    matches = [n for n in names if n.startswith(name) or n[3:] == name]
    if len(matches) == 1:
        return matches[0]
    raise SystemExit(f"unknown or ambiguous process {name!r}; valid: {', '.join(names)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--process", required=True)
    args = ap.parse_args()

    process = resolve_process(args.process)
    out_dir = ROOT / "runs" / args.run_id / "outputs" / process
    result_md = out_dir / "result.md"
    status_json = out_dir / "status.json"
    failures: list[str] = []
    warnings: list[str] = []

    if not result_md.exists():
        failures.append(f"missing {result_md}")
    else:
        text = result_md.read_text(encoding="utf-8", errors="replace")
        for heading in REQUIRED_MD_HEADINGS:
            if heading not in text:
                failures.append(f"result.md missing heading {heading!r}")

    if not status_json.exists():
        failures.append(f"missing {status_json}")
    else:
        data = load_json(status_json)
        if data.get("process") not in ("", process):
            failures.append("status.json process does not match")
        if data.get("status") not in {"OK", "FAILED", "BLOCKED", "SKIPPED"}:
            failures.append("status.json status must be OK, FAILED, BLOCKED, or SKIPPED")
        if not data.get("budget"):
            failures.append("status.json missing budget")

        try:
            store = SchemaStore()
            schema_errors, schema_warnings = validate_lane_status(data, store)
            failures.extend(f"schema: {e}" for e in schema_errors)
            warnings.extend(f"schema: {w}" for w in schema_warnings)
        except FileNotFoundError as exc:
            failures.append(f"schema validation could not run: {exc}")

    payload = {
        "process": process,
        "output_dir": str(out_dir),
        "status": "FAILED" if failures else "OK",
        "failures": failures,
        "warnings": warnings,
    }
    print(json.dumps(payload, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
