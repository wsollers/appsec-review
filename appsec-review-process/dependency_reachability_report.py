#!/usr/bin/env python3
"""Report projection of the correlated dependency reachability for ``10-synthesis-report`` (ADR-0023).

Reads the accepted ``06-cve-reachability`` summary ``outputs/dependency-reachability-summary.json``
(full envelope and hash verification) and projects one row per SCA match: advisory, component,
verdict, tier, the engines' own verdicts, the entry point and call site of the witness. ``conflict``
(engines disagree) and ``unknown`` are shown as such, with their reason; neither is "not
vulnerable". An absent 06 publication is a limitation, never a report failure. Every field comes
from the Python correlator; nothing here decides reachability.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import bounded_analysis_workers

SCHEMA = "appsec-review/dependency-reachability-report/1.0"
RESULT = "dependency-reachability-section.json"
JOB = "06-cve-reachability"
CONTRACT = "cve-reachability"
ARTIFACT = "outputs/dependency-reachability-summary.json"
ARTIFACT_SCHEMA = "dependency-reachability-summary.schema.json"
ORDER = ("reachable", "conflict", "unknown", "unreachable")
NOTE = ("Dependency reachability is decided by deterministic engines, never by a model: reachable needs a "
        "hash-bound witness from CodeQL or the IR/CPG engine; unreachable only from the complete IR/CPG "
        "engine with the dependency source analysed; conflict means the engines disagree and is left for "
        "review; unknown is a coverage gap, not 'not vulnerable'. A Critical dependency finding requires "
        "reachable (ADR-0020).")
LABEL_CHARS = 200


def _sha_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _pointer(run_root: Path) -> Path:
    return Path(run_root) / "data" / "jobs" / JOB / "accepted.json"


def input_binding(run_root: Path) -> dict[str, Any] | None:
    """What the report reads from 06, by hash, for the synthesis input fingerprint."""
    pointer = _pointer(run_root)
    if not pointer.is_file() or pointer.is_symlink():
        return None
    value = json.loads(pointer.read_text(encoding="utf-8"))
    return {"job_id": JOB, "status": value.get("status"), "attempt_id": value.get("attempt_id"),
            "accepted_pointer_sha256": _sha_file(pointer)}


def _clip(text: Any, limit: int = LABEL_CHARS) -> str:
    text = " ".join(str(text if text is not None else "").split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _empty(report: dict[str, Any], status: str, reason: str, gaps: list[str]) -> dict[str, Any]:
    return {"schema": SCHEMA, "run_id": report["run_id"], "status": status, "reason": reason, "binding": None,
            "counts": {verdict: 0 for verdict in ORDER}, "rows": [], "engines": [], "gaps": gaps, "note": NOTE}


def build(report: dict[str, Any], run_root: Path) -> dict[str, Any]:
    """The report's dependency-reachability section (pure function of the report and the accepted 06)."""
    binding = input_binding(run_root)
    if binding is None or binding["status"] not in {"OK", "OK_WITH_GAPS"}:
        status = "no accepted publication" if binding is None else f"ended {binding['status']}"
        return {**_empty(report, "ABSENT", f"06-cve-reachability has {status} in this run",
                         [f"dependency-reachability: 06-cve-reachability {status}; every dependency match is "
                          "unknown (recorded gap, not a failure)"]), "binding": binding}
    summary, loaded = bounded_analysis_workers.load_accepted(_pointer(run_root), run_id=report["run_id"], job_id=JOB,
        contract=CONTRACT, artifact=ARTIFACT, schema=ARTIFACT_SCHEMA)
    rows = []
    for row in sorted(summary["matches"], key=lambda item: (ORDER.index(item["verdict"]), item["match_id"])):
        engines = ", ".join(f"{item['engine']}: {item['verdict']}" for item in row["engines"])
        rows.append({"match_id": row["match_id"], "advisory_id": row["advisory_id"],
                     "component": _clip(row["component"] or row["component_ref"], 120),
                     "ecosystem": row["ecosystem"], "verdict": row["verdict"], "tier": row["tier"],
                     "engines": _clip(engines, 300),
                     "entry": (f"{_clip(row['entry']['function'], 80)} ({_clip(row['entry']['file'], 120)}:"
                               f"{row['entry']['line']})") if row["entry"] else None,
                     "call_site": f"{_clip(row['call_site']['file'], 120)}:{row['call_site']['line']}"
                     if row["call_site"] else None,
                     "reason": _clip(row["reason"], 400)})
    gaps = [f"dependency-reachability: {row['match_id']} {row['advisory_id']} engines disagree (conflict); "
            "left for review" for row in rows if row["verdict"] == "conflict"]
    return {"schema": SCHEMA, "run_id": report["run_id"], "status": "PUBLISHED",
            "reason": None if rows else "06-cve-reachability had no SCA match to decide",
            "binding": {**binding, "artifact_sha256": loaded["artifact_sha256"]},
            "counts": {verdict: summary["counts"][verdict] for verdict in ORDER}, "rows": rows,
            "engines": [{"engine": item["engine"], "status": item["status"]} for item in summary["engines"]],
            "gaps": gaps, "note": NOTE}
