#!/usr/bin/env python3
"""Report projection of lane 12b (``12b-poc-and-fix``) for ``10-synthesis-report`` (brief F).

Lane 12b is an optional input of the report. This module reads the accepted ``poc-fix.json`` (full
envelope and hash verification), checks it was built from the 12 result the report consumes, and
projects one PoC-and-fix block per finding the report itself holds eligible: a verified finding
whose enrichment says final severity CRITICAL and reachability REACHABLE. A record for a finding
the report does not hold eligible is dropped (gap); an eligible finding without a record is a gap.
Every displayed text is re-scanned with the lane-12b denylist; a hit withholds it (gap).

The block is labelled as unvalidated static text: the PoC was never executed and the fix is
``PATCH_PROPOSED_UNVALIDATED``. An absent or failed lane is a limitation, never a report failure.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import bounded_analysis_workers
import poc_fix_denylist as denylist

SCHEMA = "appsec-review/poc-fix-report/1.0"
RESULT = "poc-fix-section.json"
JOB = "12b-poc-and-fix"
CONTRACT = "12b-poc-and-fix"
ARTIFACT = "poc-fix.json"
ARTIFACT_SCHEMA = "poc-fix.schema.json"
SCORING_JOB = "12-scoring-prioritization"
LABEL = ("UNVALIDATED static text: this proof of concept was never executed by the pipeline; the fix is "
         "PATCH_PROPOSED_UNVALIDATED and was not applied or retested.")
NOTE = ("Light PoCs and proposed fixes are written only for findings that are verified, Critical and REACHABLE. "
        "They show how the defect happens and one way to remove it; neither is validated.")


def _sha_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _pointer(run_root: Path, job: str = JOB) -> Path:
    return Path(run_root) / "data" / "jobs" / job / "accepted.json"


def input_binding(run_root: Path) -> dict[str, Any] | None:
    """What the report reads from lane 12b, by hash, for the synthesis input fingerprint."""
    pointer = _pointer(run_root)
    if not pointer.is_file() or pointer.is_symlink():
        return None
    value = json.loads(pointer.read_text(encoding="utf-8"))
    return {"job_id": JOB, "status": value.get("status"), "attempt_id": value.get("attempt_id"),
            "reason": value.get("reason"), "accepted_pointer_sha256": _sha_file(pointer)}


def eligible_claims(enrichment: dict[str, Any] | None) -> list[str]:
    """Claims the report itself holds eligible: final severity CRITICAL (so REACHABLE, ADR-0020)."""
    return sorted(row["claim_id"] for row in (enrichment or {}).get("findings", [])
                  if row["severity"]["final"] == "CRITICAL" and row["reachability"]["state"] == "REACHABLE")


def _section(report: dict[str, Any], status: str, reason: str | None, binding: Any, gaps: list[str]) -> dict[str, Any]:
    return {"schema": SCHEMA, "run_id": report["run_id"], "status": status, "reason": reason, "binding": binding,
            "label": LABEL, "note": NOTE, "by_claim": {}, "gaps": gaps}


def _clean(text: str | None, rules: tuple[str, ...]) -> str | None:
    return None if text is None or denylist.scan(text, rules) else text


def project(record: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The renderer block of one record; texts that fail the denylist re-scan are withheld."""
    gaps: list[str] = []
    poc = record["poc"]
    text = _clean(poc["text"], denylist.FULL)
    trigger = _clean(poc["trigger_condition"], denylist.FULL)
    explanation = _clean(record["explanation"], denylist.PROSE)
    fix = record["fix"]
    diff = fix["diff"] if fix["diff"] is not None and not denylist.scan(denylist.added_lines(fix["diff"])) else None
    rationale = _clean(fix["rationale"], denylist.PROSE)
    for original, kept, name in ((poc["text"], text, "PoC text"), (poc["trigger_condition"], trigger, "trigger"),
                                 (record["explanation"], explanation, "explanation"), (fix["diff"], diff, "fix diff"),
                                 (fix["rationale"], rationale, "fix rationale")):
        if original is not None and kept is None:
            gaps.append(f"poc-fix: {record['claim_id']} {name} withheld at report time by the denylist re-scan")
    if poc["status"] == "PROPOSED_UNVALIDATED" and text is not None:
        poc_note = None
    elif poc["status"] == "NOT_PROVIDED":
        poc_note = f"No PoC was written: {poc['reason']}"
    else:
        poc_note = "PoC withheld: the text matched the lane-12b denylist (" + ", ".join(
            sorted({hit["rule"] for hit in poc["denylist_hits"]})) + "); recorded as a gap."
    fix_note = None if diff is not None else "Proposed fix withheld: it matched the lane-12b denylist; recorded as a gap."
    block = {"poc_fix_id": record["poc_fix_id"], "label": "UNVALIDATED", "label_text": LABEL,
             "poc": {"status": poc["status"], "kind": poc["kind"], "language": poc["language"],
                     "expected_effect": poc["expected_effect"], "text": text,
                     "lines": text.splitlines() if text is not None else [], "trigger_condition": trigger,
                     "note": poc_note},
             "explanation": explanation or "Explanation withheld (denylist).",
             "cited_lines": [{"path": row["path"], "start": row["start_line"], "end": row["end_line"],
                              "role": row["role"], "source_sha256": row["source_sha256"],
                              "display": f"{row['role']}: {row['path']}:{row['start_line']}"
                                         + (f"-{row['end_line']}" if row["end_line"] != row["start_line"] else "")
                                         + f" ({row['source_sha256'][:19]})"}
                             for row in record["cited_lines"]],
             "fix": {"status": fix["status"], "files": fix["files"], "diff": diff,
                     "lines": diff.splitlines() if diff is not None else [], "rationale": rationale, "note": fix_note}}
    return block, gaps


def build(report: dict[str, Any], enrichment: dict[str, Any] | None, run_root: Path) -> dict[str, Any]:
    """The report's PoC-and-fix section (pure function of the report, its enrichment and lane 12b)."""
    eligible = eligible_claims(enrichment)
    binding = input_binding(run_root)
    missing_all = [f"poc-fix: {claim_id} is Critical and REACHABLE but has no PoC or proposed fix" for claim_id in eligible]
    if binding is None:
        return _section(report, "ABSENT", "12b-poc-and-fix has no accepted publication in this run", None,
                        ["poc-fix: lane 12b did not publish; no PoC or proposed fix rendered (recorded gap, not a failure)"]
                        + missing_all)
    if binding["status"] == "SKIPPED":
        return _section(report, "SKIPPED", binding["reason"] or "skipped", binding, missing_all)
    if binding["status"] not in {"OK", "OK_WITH_GAPS"}:
        return _section(report, "ABSENT", f"12b-poc-and-fix ended {binding['status']}", binding,
                        [f"poc-fix: lane 12b ended {binding['status']}; no PoC or proposed fix rendered"] + missing_all)
    document, loaded = bounded_analysis_workers.load_accepted(_pointer(run_root), run_id=report["run_id"], job_id=JOB,
        contract=CONTRACT, artifact=ARTIFACT, schema=ARTIFACT_SCHEMA)
    scoring_pointer = _pointer(run_root, SCORING_JOB)
    current = json.loads(scoring_pointer.read_text(encoding="utf-8")) if scoring_pointer.is_file() else {}
    binding = {**binding, "artifact_sha256": loaded["artifact_sha256"]}
    if document["scoring"].get("attempt_id") != current.get("attempt_id"):
        return _section(report, "STALE", "lane 12b was built from another 12-scoring-prioritization attempt", binding,
                        ["poc-fix: lane 12b is stale (built from another 12 attempt); no PoC or proposed fix rendered"]
                        + missing_all)
    findings = {row["claim_id"] for row in report["verified_findings"]}
    gaps = [f"poc-fix: {gap['reason']} ({gap['scope']} {gap['id']}): {gap['detail']}" for gap in document["gaps"]
            if gap["reason"] != "not-reachable"]
    by_claim: dict[str, dict[str, Any]] = {}
    for record in document["records"]:
        claim_id = record["claim_id"]
        if claim_id not in findings or claim_id not in eligible:
            gaps.append(f"poc-fix: record {record['poc_fix_id']} names {claim_id}, which the report does not hold "
                        f"verified, Critical and REACHABLE; not rendered")
            continue
        block, notes = project(record)
        by_claim[claim_id] = block
        gaps.extend(notes)
    for claim_id in eligible:
        if claim_id not in by_claim:
            gaps.append(f"poc-fix: {claim_id} is Critical and REACHABLE but lane 12b published no record for it")
    section = _section(report, "PUBLISHED", None if by_claim else "lane 12b published no record for an eligible finding",
                       binding, sorted(set(gaps)))
    section["by_claim"] = by_claim
    return section
