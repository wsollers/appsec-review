#!/usr/bin/env python3
"""Deterministic SARIF 2.1.0 projection of independently verified synthesis findings."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from execution_state import Blocked, atomic_json, file_hash, read_json

LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
LINE = re.compile(r"^(?:line:)?(?P<start>[1-9][0-9]*)(?:-(?P<end>[1-9][0-9]*))?$")


def _location(citation: dict[str, Any]) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": citation["artifact_path"]}}
    locator = citation.get("locator_json")
    match = LINE.fullmatch(locator) if isinstance(locator, str) else None
    if match:
        region = {"startLine": int(match.group("start"))}
        if match.group("end"):
            region["endLine"] = int(match.group("end"))
        physical["region"] = region
    return {"physicalLocation": physical}


def build(report: dict[str, Any], trace: dict[str, Any], *, report_sha256: str,
          trace_sha256: str) -> dict[str, Any]:
    if report.get("status") != "DRAFT_EVIDENCE_BACKED":
        raise Blocked("synthesis SARIF: source is not an evidence-backed draft")
    if report.get("claim_limits", {}).get("final") is not False:
        raise Blocked("synthesis SARIF: source report has an invalid claim ceiling")
    trace_claims = {row.get("claim_id") for row in trace.get("citations", []) if isinstance(row, dict)}
    rules, results = [], []
    seen = set()
    for finding in sorted(report.get("verified_findings", []), key=lambda row: row["claim_id"]):
        claim_id = finding.get("claim_id")
        if not isinstance(claim_id, str) or claim_id in seen or claim_id not in trace_claims:
            raise Blocked("synthesis SARIF: finding identity is duplicate or absent from the trace")
        seen.add(claim_id); severity = finding.get("severity")
        if severity not in LEVELS:
            raise Blocked("synthesis SARIF: verified finding severity is unsupported")
        citations = finding.get("verification_citations") or finding.get("citations") or []
        if not citations:
            raise Blocked("synthesis SARIF: verified finding has no citation")
        rules.append({"id": claim_id, "name": "VerifiedSecurityClaim",
            "shortDescription": {"text": finding["title"]},
            "properties": {"security-severity": str(finding.get("score", 0)),
                           "tags": ["independently-verified", severity.lower()]}})
        results.append({"ruleId": claim_id, "level": LEVELS[severity],
            "message": {"text": finding["title"]},
            "locations": [_location(citation) for citation in citations],
            "properties": {"claimId": claim_id, "severity": severity,
                "priority": finding.get("priority"), "confidence": finding.get("confidence"),
                "componentIds": finding.get("component_ids", []),
                "reportSha256": report_sha256, "traceSha256": trace_sha256}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "appsec-review-synthesis",
            "informationUri": "", "version": "1.0.0", "rules": rules}}, "results": results,
            "properties": {"sourceReportSha256": report_sha256, "sourceTraceSha256": trace_sha256}}]}


def convert(report_path: Path, trace_path: Path, output_path: Path) -> dict[str, Any]:
    report_path, trace_path = Path(report_path), Path(trace_path)
    if any(path.is_symlink() or not path.is_file() for path in (report_path, trace_path)):
        raise Blocked("synthesis SARIF: source report or trace is unsafe")
    report_sha, trace_sha = "sha256:" + file_hash(report_path), "sha256:" + file_hash(trace_path)
    value = build(read_json(report_path), read_json(trace_path), report_sha256=report_sha,
                  trace_sha256=trace_sha)
    atomic_json(output_path, value)
    return value


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True); parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    print(json.dumps(convert(args.report, args.trace, args.output), indent=2))
