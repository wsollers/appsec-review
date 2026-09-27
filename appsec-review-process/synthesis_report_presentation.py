#!/usr/bin/env python3
"""Create bounded renderer input from an evidence-backed synthesis draft.

This adapter is deliberately presentation-only.  It copies verified findings and their
authoritative lifecycle scores; it never derives a CVSS vector, process assurance, final status,
or remediation state.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from typing import Any

from execution_state import Blocked, ROOT, atomic_json, file_hash


PIPELINE_REPORT = ROOT.parent / "pipeline" / "report"
RENDER_INPUT = "report.review.json"
RENDER_MANIFEST = "render-publication-manifest.json"
RENDERED = ("report.tex", "report.html", "report.fragment.html",
            "workbench.html", "workbench.fragment.html")
SEVERITIES = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
              "LOW": "Low", "NONE": "None"}


def _renderer():
    path = PIPELINE_REPORT / "render.py"
    spec = importlib.util.spec_from_file_location("appsec_review_report_renderer", path)
    if spec is None or spec.loader is None:
        raise Blocked("10-synthesis-report: report renderer cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _evidence(trace: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str]]:
    records: dict[str, dict[str, Any]] = {}
    identities: dict[str, tuple[Any, ...]] = {}
    for citation in trace.get("citations", []):
        citation_id = citation.get("citation_id")
        identity = tuple(citation.get(key) for key in ("producer_job_id", "producer_attempt_id",
            "artifact_path", "artifact_sha256", "locator_json", "observed_fact"))
        if not isinstance(citation_id, str) or not citation_id:
            raise Blocked("10-synthesis-report: presentation citation identity is invalid")
        if citation_id in identities and identities[citation_id] != identity:
            raise Blocked("10-synthesis-report: presentation citation identity is contradictory")
        identities[citation_id] = identity
        records[citation_id] = citation
    ordered = []
    mapping = {}
    for index, citation_id in enumerate(sorted(records), 1):
        citation = records[citation_id]; evidence_id = f"E-{index:03d}"
        mapping[citation_id] = evidence_id
        ordered.append({"id": evidence_id, "producer": citation["producer_job_id"],
            "artifact": citation["artifact_path"], "sha256": citation["artifact_sha256"],
            "kind": "retained verified citation", "citation_id": citation_id,
            "locator": citation.get("locator_json"), "observed_fact": citation["observed_fact"]})
    return ordered, mapping


def _findings(report: dict[str, Any], evidence_ids: dict[str, str]) -> list[dict[str, Any]]:
    result = []
    for finding in report["verified_findings"]:
        severity = SEVERITIES.get(finding.get("severity"))
        citations = finding.get("verification_citations") or finding.get("citations") or []
        if severity is None or not citations:
            raise Blocked("10-synthesis-report: verified presentation finding is incomplete")
        linked = []
        for citation in citations:
            evidence_id = evidence_ids.get(citation.get("citation_id"))
            if evidence_id is None:
                raise Blocked("10-synthesis-report: finding citation is absent from evidence trace")
            if evidence_id not in linked:
                linked.append(evidence_id)
        first = citations[0]
        locator = first.get("locator_json") or ""
        location = first["artifact_path"] + (f"#{locator}" if locator else "")
        result.append({"id": finding["claim_id"], "title": finding["title"],
            "cwe": "Not asserted by retained draft", "location": location,
            "component": ", ".join(finding["component_ids"]) or "Not asserted",
            "cvss": None, "authoritative_score": finding["score"],
            "priority_label": finding["priority"], "severity_override": severity,
            "evidence_strength": "DIRECT_EVIDENCE", "verification": "VERIFIED",
            "reachability": "unknown", "epss": None, "kev": False, "snippets": [],
            "trail": [["synthesis", "retained independently verified claim"],
                      ["publication", "DRAFT_EVIDENCE_BACKED; human decision required"]],
            "evidence": linked, "summary": first["observed_fact"],
            "remediation": "No remediation assertion is present in the retained draft."})
    return result


def build_review(report: dict[str, Any], trace: dict[str, Any]) -> dict[str, Any]:
    if (report.get("schema") != "appsec-review/synthesis-report/1.0" or
            report.get("status") != "DRAFT_EVIDENCE_BACKED" or
            report.get("claim_limits", {}).get("final") is not False or
            trace.get("schema") != "appsec-review/evidence-trace-index/1.0" or
            trace.get("run_id") != report.get("run_id") or
            trace.get("ledger_head_sha256") != report.get("ledger_head_sha256")):
        raise Blocked("10-synthesis-report: presentation inputs are not the exact draft and trace")
    evidence, evidence_ids = _evidence(trace)
    processes = []
    for upstream in sorted(trace["upstream"], key=lambda item: (item["job_id"], item["attempt_id"])):
        processes.append({"id": upstream["job_id"], "family": "retained",
            "kind": "retained accepted output", "status": "OK",
            "tools": upstream["contract_id"], "evidence": []})
    if report["limitations"]:
        processes.append({"id": "reported-limitations", "family": "limitations",
            "kind": "preserved synthesis limitations", "status": "OK_WITH_GAPS", "coverage": 0.0,
            "tools": "report.json", "gap": "; ".join(report["limitations"]), "evidence": []})
    family_weight = {"retained": 1}
    families = [{"id": "retained", "name": "Accepted lifecycle inputs",
        "note": "Exact accepted upstreams retained by the evidence trace."}]
    if report["limitations"]:
        family_weight["limitations"] = 1
        families.append({"id": "limitations", "name": "Unresolved coverage and assumptions",
            "note": "Preserved without promotion or omission."})
    return {"report": {"title": "Application Security Review Draft",
        "target": report["scope"]["target"], "target_commit": "not asserted",
        "engagement": "Evidence-backed draft; human decision required", "run_id": report["run_id"],
        "sat_id": "not asserted", "pipeline_commit": "not asserted", "report_date": "not asserted",
        "classification": "Internal - DRAFT_EVIDENCE_BACKED", "native_tier": "N/A",
        "native_tier_note": "Native build tier is not asserted by this synthesis input.",
        "authors": ["appsec-review pipeline"], "sample": False, "source_root": None},
        "finding_scoring": "authoritative_retained_publication", "process_assurance": "not_asserted",
        "families": families, "processes": processes,
        "findings": _findings(report, evidence_ids), "evidence": evidence,
        "provenance": {"images": [], "models": [], "ledger_head": report["ledger_head_sha256"]},
        "scoring": {"evidence_weight": {"DIRECT_EVIDENCE": 1.0, "STRONG_INFERENCE": 0.8,
            "WEAK_INFERENCE": 0.5}, "verification_weight": {"VERIFIED": 1.0,
            "UNRESOLVED": 0.7, "REFUTED": 0.0}, "reachability_weight": {"reachable-default": 1.0,
            "reachable-flag": 0.85, "reachable-build-config": 0.75, "unknown": 0.7,
            "unreachable": 0.3}, "status_credit": {"OK": 1.0, "OK_WITH_GAPS": None,
            "FAILED": 0.0, "BLOCKED": 0.0, "NOT_BUILT": 0.0, "SKIPPED_NA": None},
            "family_weight": family_weight, "tier_cap": {"A": 1.0, "B": 0.85, "C": 0.6,
            "N/A": 1.0}, "assurance_floor_for_clean": 0.85, "kev_bonus": 0.5,
            "epss_bonus": 0.5}}


def render(report: dict[str, Any], trace: dict[str, Any], output_root: Path,
           generator_sha256: str) -> dict[str, Any]:
    output_root = Path(output_root)
    review = build_review(report, trace)
    atomic_json(output_root / RENDER_INPUT, review)
    render_root = output_root / "presentation"
    _renderer().render(output_root / RENDER_INPUT, render_root)
    artifacts = [{"path": f"presentation/{name}",
                  "sha256": "sha256:" + file_hash(render_root / name)} for name in RENDERED]
    manifest = {"schema": "appsec-review/report-render-publication/1.0",
        "run_id": report["run_id"], "status": "DRAFT_EVIDENCE_BACKED",
        "report_sha256": "sha256:" + file_hash(output_root / "report.json"),
        "trace_sha256": "sha256:" + file_hash(output_root / "evidence-trace-index.json"),
        "render_input_sha256": "sha256:" + file_hash(output_root / RENDER_INPUT),
        "generator_sha256": generator_sha256, "artifacts": artifacts,
        "final": False, "human_signoff": False}
    atomic_json(output_root / RENDER_MANIFEST, manifest)
    return manifest
