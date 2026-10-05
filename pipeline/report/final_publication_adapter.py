#!/usr/bin/env python3
"""Convert one retained final-publication package into the report renderer's review JSON.

Only verified findings already present in ``report.json`` become renderer findings.  Optional
supplemental qualification is retained under its own top-level key and never contributes findings,
process credit, severity, or target-evidence records.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any


class AdapterError(ValueError):
    pass


SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9:-]+$")
SEVERITIES = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
              "LOW": "Low", "NONE": "None"}


def _read(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"required retained artifact is absent or linked: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterError(f"retained artifact is unreadable: {path}") from exc
    if not isinstance(value, dict):
        raise AdapterError(f"retained artifact must contain an object: {path}")
    return value


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def _relative_file(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative:
        raise AdapterError("final publication contains an invalid artifact path")
    candidate = Path(relative)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise AdapterError("final publication contains an unsafe artifact path")
    path = root.joinpath(*candidate.parts)
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"final publication artifact is absent or linked: {relative}")
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise AdapterError(f"final publication artifact escapes its package: {relative}") from exc
    return path


def _verified_package(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    root = Path(root).absolute()
    if root.is_symlink() or not root.is_dir():
        raise AdapterError("final publication root is absent or linked")
    publication = _read(root / "final-publication.json")
    if (publication.get("schema") != "appsec-review/final-publication/1.0" or
            publication.get("status") != "FINAL_APPROVED" or
            publication.get("final") is not True or publication.get("human_signoff") is not True):
        raise AdapterError("package is not an approved final publication")
    artifacts = publication.get("artifacts")
    if not isinstance(artifacts, list):
        raise AdapterError("final publication artifact inventory is invalid")
    indexed: dict[str, str] = {}
    for record in artifacts:
        if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
            raise AdapterError("final publication artifact record is invalid")
        path, expected = record["path"], record["sha256"]
        if path in indexed or not isinstance(expected, str) or not SHA.fullmatch(expected):
            raise AdapterError("final publication artifact identity is invalid")
        actual = _hash(_relative_file(root, path))
        if actual != expected:
            raise AdapterError(f"final publication artifact hash mismatch: {path}")
        indexed[path] = expected
    for required in ("report.json", "evidence-trace-index.json", "human-signoff-ledger.json",
                     "completion/completeness-audit.json",
                     "completion/synthetic-hypothesis-resynthesis.json"):
        if required not in indexed:
            raise AdapterError(f"final publication omits required retained artifact: {required}")
    report = _read(root / "report.json")
    trace = _read(root / "evidence-trace-index.json")
    if (report.get("schema") != "appsec-review/synthesis-report/1.0" or
            report.get("run_id") != publication.get("run_id") or
            trace.get("schema") != "appsec-review/evidence-trace-index/1.0" or
            trace.get("run_id") != publication.get("run_id")):
        raise AdapterError("retained report identity does not match final publication")
    return publication, report, trace


def _structural(citation: dict[str, Any]) -> bool:
    """A tool-evidence citation (ADR-0035): a re-run-verified code query, shown by its Python summary."""
    return (str(citation.get("citation_id") or "").startswith("tev:") and
            str(citation.get("artifact_path") or "").startswith("tool-evidence/"))


def _location(citation: dict[str, Any], fallback: str) -> str:
    """Where a finding's first citation points: a structural query reads as its summary
    (``code_callers(f) -> a.c:42 [complete]``), anything else as artifact#locator."""
    if _structural(citation):
        return "structural query: " + str(citation.get("observed_fact"))
    locator = citation.get("locator_json") or ""
    return (citation.get("artifact_path") or fallback) + (f"#{locator}" if locator else "")


def _evidence(trace: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    rows, identifiers = [], {}
    citations = trace.get("citations")
    if not isinstance(citations, list):
        raise AdapterError("evidence trace citations are invalid")
    for index, citation in enumerate(citations, 1):
        if not isinstance(citation, dict):
            raise AdapterError("evidence trace citation is invalid")
        citation_id = citation.get("citation_id")
        if not isinstance(citation_id, str) or not citation_id or citation_id in identifiers:
            raise AdapterError("evidence trace citation identity is invalid")
        producer = citation.get("producer_job_id")
        artifact = citation.get("artifact_path")
        artifact_sha256 = citation.get("artifact_sha256")
        observed = citation.get("observed_fact")
        if (not isinstance(producer, str) or not producer or not isinstance(artifact, str) or not artifact or
                not isinstance(artifact_sha256, str) or not SHA.fullmatch(artifact_sha256) or
                not isinstance(observed, str) or not observed):
            raise AdapterError("evidence trace citation content is invalid")
        eid = f"E-{index:03d}"
        identifiers[citation_id] = eid
        rows.append({"id": eid, "producer": producer, "artifact": artifact,
            "sha256": artifact_sha256,
            "kind": "structural query record (re-run verified)" if _structural(citation) else "retained verified citation",
            "citation_id": citation_id, "locator": citation.get("locator_json"), "observed_fact": observed})
    return rows, identifiers


def _findings(report: dict[str, Any], identifiers: dict[str, str]) -> list[dict[str, Any]]:
    findings = report.get("verified_findings")
    if not isinstance(findings, list):
        raise AdapterError("retained verified findings are invalid")
    result = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise AdapterError("retained verified finding is invalid")
        severity = SEVERITIES.get(finding.get("severity"))
        if severity is None:
            raise AdapterError("retained verified finding has an unsupported severity")
        citations = finding.get("verification_citations") or finding.get("citations") or []
        if not isinstance(citations, list) or not citations:
            raise AdapterError("retained verified finding has no verification citation")
        evidence_ids = []
        for citation in citations:
            citation_id = citation.get("citation_id") if isinstance(citation, dict) else None
            if citation_id not in identifiers:
                raise AdapterError("verified finding references a citation absent from the retained trace")
            if identifiers[citation_id] not in evidence_ids:
                evidence_ids.append(identifiers[citation_id])
        first = citations[0]
        location = _location(first, "retained report")
        confidence = finding.get("confidence", "not asserted")
        claim_id = finding.get("claim_id")
        title = finding.get("title")
        component_ids = finding.get("component_ids")
        if (not isinstance(claim_id, str) or not SAFE_ID.fullmatch(claim_id) or
                not isinstance(title, str) or not title or not isinstance(component_ids, list) or
                any(not isinstance(item, str) or not item for item in component_ids)):
            raise AdapterError("retained verified finding has an unsafe presentation identity")
        score = finding.get("score")
        priority = finding.get("priority")
        if (isinstance(score, bool) or not isinstance(score, (int, float)) or score < 0 or
                not isinstance(priority, str) or not SAFE_ID.fullmatch(priority)):
            raise AdapterError("retained verified finding has an invalid authoritative score or priority")
        result.append({"id": claim_id, "title": title,
            "cwe": "Not asserted by retained publication", "location": location,
            "component": ", ".join(component_ids) or "Not asserted",
            "cvss": None, "authoritative_score": score, "priority_label": priority,
            "severity_override": severity, "evidence_strength": "DIRECT_EVIDENCE",
            "verification": "VERIFIED", "reachability": "unknown", "epss": None, "kev": False,
            "snippets": [], "trail": [["synthesis", f"retained verified claim; confidence {confidence}"],
                ["publication", "FINAL_APPROVED with human signoff"]], "evidence": evidence_ids,
            "summary": first.get("observed_fact") or title,
            "remediation": "No remediation assertion is present in the retained publication."})
    return result


def _processes(root: Path, publication: dict[str, Any], trace: dict[str, Any],
               evidence: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    evidence_by_artifact = {row["artifact"]: row["id"] for row in evidence}
    processes = []
    seen = set()
    upstream = trace.get("upstream")
    if not isinstance(upstream, list):
        raise AdapterError("retained upstream trace is invalid")
    for record in upstream:
        if (not isinstance(record, dict) or not isinstance(record.get("job_id"), str) or
                not isinstance(record.get("contract_id"), str) or
                not isinstance(record.get("artifact_path"), str)):
            raise AdapterError("retained upstream record is invalid")
        job = record["job_id"]
        if job in seen:
            continue
        seen.add(job)
        eid = evidence_by_artifact.get(record.get("artifact_path"))
        processes.append({"id": job, "family": "retained", "kind": "retained accepted output",
            "status": "OK", "tools": record["contract_id"],
            "evidence": [eid] if eid else []})
    controls = [("completeness-audit", "completion/completeness-audit.json"),
                ("synthetic-hypothesis-resynthesis", "completion/synthetic-hypothesis-resynthesis.json"),
                ("final-publication-gate", "final-publication.json")]
    for job, artifact in controls:
        processes.append({"id": job, "family": "completion", "kind": "verified publication control",
            "status": "OK", "tools": artifact, "receipt": publication.get("status"), "evidence": []})
    families = [{"id": "retained", "name": "Retained accepted lifecycle evidence",
                 "note": "Accepted producer references preserved by the final evidence-trace index."},
                {"id": "completion", "name": "Completion and publication controls",
                 "note": "Completeness, resynthesis, human signoff, and immutable final publication."}]
    return processes, families


def convert(final_root: Path, supplemental_path: Path | None = None) -> dict[str, Any]:
    root = Path(final_root).absolute()
    publication, report, trace = _verified_package(root)
    evidence, identifiers = _evidence(trace)
    findings = _findings(report, identifiers)
    processes, families = _processes(root, publication, trace, evidence)
    ledger = _read(root / "human-signoff-ledger.json")
    entries = ledger.get("entries")
    if not isinstance(entries, list) or not entries:
        raise AdapterError("retained human signoff ledger is empty")
    latest = entries[-1]
    if latest.get("decision") != "APPROVED":
        raise AdapterError("retained human signoff does not approve the report")
    supplemental = None
    if supplemental_path is not None:
        supplemental = _read(Path(supplemental_path).absolute())
        supplemental_families = supplemental.get("families")
        if (supplemental.get("run_id") != report.get("run_id") or
                not isinstance(supplemental_families, list) or
                any(not isinstance(row, dict) or
                    row.get("classification") != "SUPPLEMENTAL_IMPLEMENTATION_AND_TEST_COVERAGE_ONLY" or
                    row.get("report_effect") != "NOT_A_FINDING_AND_NOT_VERIFIED_TARGET_EVIDENCE"
                    for row in supplemental_families)):
            raise AdapterError("supplemental qualification is not safely non-promotional")
    scope = report.get("scope") if isinstance(report.get("scope"), dict) else {}
    target = scope.get("target")
    reviewer = latest.get("reviewer_id")
    if not isinstance(target, str) or not target or not isinstance(reviewer, str) or not reviewer:
        raise AdapterError("retained target or approving reviewer is invalid")
    signed_at = latest.get("signed_at", "")
    return {"report": {"title": "Application Security Review", "target": target,
        "target_commit": "not asserted", "engagement": "Retained final publication",
        "run_id": report["run_id"], "sat_id": publication.get("signoff_id", "not asserted"),
        "pipeline_commit": "not asserted",
        "report_date": signed_at[:10] if isinstance(signed_at, str) and len(signed_at) >= 10 else "not asserted",
        "classification": "Internal", "native_tier": "N/A",
        "native_tier_note": "Native build tier is not asserted by the retained publication.",
        "authors": [reviewer], "sample": bool(supplemental and supplemental.get("demo")),
        "source_root": None}, "finding_scoring": "authoritative_retained_publication",
        "process_assurance": "not_asserted", "families": families, "processes": processes, "findings": findings,
        "evidence": evidence, "provenance": {"images": [], "models": [],
            "ledger_head": ledger.get("head_hash", report.get("ledger_head_sha256"))},
        "scoring": {"evidence_weight": {"DIRECT_EVIDENCE": 1.0, "STRONG_INFERENCE": 0.8,
            "WEAK_INFERENCE": 0.5}, "verification_weight": {"VERIFIED": 1.0, "UNRESOLVED": 0.7,
            "REFUTED": 0.0}, "reachability_weight": {"reachable-default": 1.0,
            "reachable-flag": 0.85, "reachable-build-config": 0.75, "unknown": 0.7,
            "unreachable": 0.3}, "status_credit": {"OK": 1.0, "OK_WITH_GAPS": None,
            "FAILED": 0.0, "BLOCKED": 0.0, "NOT_BUILT": 0.0, "SKIPPED_NA": None},
            "family_weight": {"retained": 1, "completion": 1},
            "tier_cap": {"A": 1.0, "B": 0.85, "C": 0.6, "N/A": 1.0},
            "assurance_floor_for_clean": 0.85, "kev_bonus": 0.5, "epss_bonus": 0.5},
        "supplemental_qualification": supplemental}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("final_root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--supplemental", type=Path)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("output already exists")
    try:
        value = convert(args.final_root, args.supplemental)
    except AdapterError as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
