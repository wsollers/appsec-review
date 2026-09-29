#!/usr/bin/env python3
"""Create bounded renderer input from an evidence-backed synthesis draft.

This adapter is deliberately presentation-only.  It copies verified findings, their authoritative
lifecycle scores and the deterministic ``finding-enrichment.json`` (CWE, pinned CVSS v4.0 score,
reachability verdict and witness, reachability-capped severity, EPSS/KEV as of the pinned snapshot,
verified snippets, remediation objectives/proposals; ADR-0020) and, under each Critical REACHABLE
finding, the lane-12b PoC-and-fix block labelled as unvalidated static text (``poc_fix_report``; an
absent block is stated as a gap).  The ``threat_workbench`` section lists the 03 workbench records
(data classes, LINDDUN privacy threats, deployment zones, attack-tree summaries; ADR-0019) as
candidates, never findings.  It never computes a CVSS score,
process assurance, final status, or remediation state itself.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

import container_execution
from execution_state import Blocked, ROOT, atomic_json, file_hash


PIPELINE_REPORT = ROOT.parent / "pipeline" / "report"
RENDER_INPUT = "report.review.json"
RENDER_MANIFEST = "render-publication-manifest.json"
RENDERED = ("report.tex", "report.pdf", "report.html", "report.fragment.html",
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


def _compile_pdf(render_root: Path) -> None:
    """Compile the retained TeX with the exact locally pinned report image."""
    render_root = Path(render_root).resolve(strict=True)
    defaults = container_execution.host_defaults()
    docker = defaults.get("docker_executable")
    if docker is None:
        raise Blocked("10-synthesis-report: Docker is unavailable for pinned PDF rendering")
    records = container_execution.load_image_registry(container_execution.IMAGES_DIR)
    record = records.get("audit-report")
    if not isinstance(record, dict):
        raise Blocked("10-synthesis-report: pinned audit-report image record is absent")
    reference = container_execution.image_reference(record)
    inspect = subprocess.run(
        [str(docker), "image", "inspect", "--format", "{{.Id}}", reference],
        capture_output=True, text=True, timeout=60, check=False,
        env=container_execution.docker_client_environment(os.environ, None))
    if inspect.returncode != 0 or inspect.stdout.strip() != record["digest"]:
        raise Blocked("10-synthesis-report: pinned audit-report image is unavailable or drifted")
    name = "appsec-report-" + re.sub(r"[^a-z0-9]", "", file_hash(render_root / "report.tex"))[:24]
    mount = str(render_root)
    argv = [str(docker), "run", "--name", name, "--rm", "--pull", "never",
        "--log-driver", "none", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", defaults["container_user"], "--pids-limit", "256",
        "--memory", "2g", "--memory-swap", "2g", "--cpus", "2",
        "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=512m", "--workdir", "/out",
        "--env", "HOME=/tmp", "--env", "SOURCE_DATE_EPOCH=0", "--env", "TZ=UTC",
        "--env", "TEXINPUTS=/src//:", "--volume", f"{mount}:/src:ro",
        "--volume", f"{mount}:/out:rw", reference, "latexmk", "-pdf",
        "-interaction=nonstopmode", "-halt-on-error", "-quiet", "-outdir=/out",
        "/src/report.tex"]
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=900, check=False,
            env=container_execution.docker_client_environment(os.environ, None))
    except subprocess.TimeoutExpired as exc:
        subprocess.run([str(docker), "rm", "-f", name], capture_output=True, timeout=60,
            env=container_execution.docker_client_environment(os.environ, None), check=False)
        raise Blocked("10-synthesis-report: pinned PDF rendering timed out") from exc
    if completed.returncode != 0:
        raise Blocked("10-synthesis-report: pinned PDF rendering failed")
    pdf = render_root / "report.pdf"
    if pdf.is_symlink() or not pdf.is_file() or pdf.stat().st_size < 1024 or not pdf.read_bytes().startswith(b"%PDF-"):
        raise Blocked("10-synthesis-report: renderer did not produce a valid PDF artifact")


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


def _reachability_text(reach: dict[str, Any], cap: str | None) -> str:
    state = reach["state"]
    if state == "REACHABLE":
        steps = [f"{step['function']}() {step['file']}:{step['line']}" if step["function"] != "(finding location)"
                 else f"{step['file']}:{step['line']}" for step in reach.get("witness", [])]
        return "REACHABLE via " + " -> ".join(steps)
    label = "UNREACHABLE (no call path from any analysed entry point)" if state == "UNREACHABLE" else "UNKNOWN"
    return f"{label}: {reach.get('reason', 'not analysed')}" + (f"; {cap}" if cap else "")


def _exploit_text(value: dict[str, Any] | None, identity: dict[str, Any]) -> str:
    if value is None:
        return "EPSS/KEV not applicable (not a dependency finding)"
    if not value["assessed"]:
        return "EPSS/KEV not assessed (no pinned snapshot imported)"
    epss = (f"EPSS {value['epss']:.4f} (percentile {value['epss_percentile']:.2f}, {value['epss_cve']})"
            if value["epss"] is not None else "EPSS: no score for " + (", ".join(value["cves"]) or "this advisory"))
    return f"EPSS/KEV as of {identity.get('as_of')}: {epss}; KEV {'listed' if value['kev'] else 'not listed'}"


def _findings(report: dict[str, Any], evidence_ids: dict[str, str],
              enrichment: dict[str, Any] | None = None, poc_fix: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    result = []
    poc_blocks = (poc_fix or {}).get("by_claim", {})
    enriched = {row["claim_id"]: row for row in (enrichment or {}).get("findings", [])}
    exploit_identity = (enrichment or {}).get("epss_kev", {})
    for finding in report["verified_findings"]:
        extra = enriched.get(finding["claim_id"])
        severity = SEVERITIES.get(extra["severity"]["final"] if extra else finding.get("severity"))
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
        row = {"id": finding["claim_id"], "title": finding["title"],
            "cwe": "Not asserted by retained draft", "location": location,
            "component": ", ".join(finding["component_ids"]) or "Not asserted",
            "cvss": None, "authoritative_score": finding["score"],
            "priority_label": finding["priority"], "severity_override": severity,
            "evidence_strength": "DIRECT_EVIDENCE", "verification": "VERIFIED",
            "reachability": "unknown", "epss": None, "kev": False, "snippets": [],
            "trail": [["synthesis", "retained independently verified claim"],
                      ["publication", "DRAFT_EVIDENCE_BACKED; human decision required"]],
            "evidence": linked, "summary": first["observed_fact"],
            "remediation": "No remediation assertion is present in the retained draft."}
        if extra:
            cvss, reach, cap = extra["cvss_v4"], extra["reachability"], extra["severity"]["reachability_cap"]
            exploit = extra["epss_kev"]
            code_locations = [item for item in extra["locations"] if "path" in item]
            row.update(cwe=extra["cwe"]["display"],
                cvss=cvss["vector"] if cvss else None, cvss_score=cvss["score"] if cvss else None,
                reachability=_reachability_text(reach, cap),
                epss=exploit["epss"] if exploit and exploit["assessed"] else None,
                kev=bool(exploit and exploit["assessed"] and exploit["kev"]),
                exploit_signal=_exploit_text(exploit, exploit_identity),
                snippets=[{key: item[key] for key in ("path", "flaw", "note", "start", "source")}
                          for item in extra["snippets"] if item["status"] == "VERIFIED"],
                remediation=extra["remediation"]["display"])
            if code_locations:
                row["location"] = f"{code_locations[0]['path']}:{code_locations[0]['line']}"
            trail = [["tool/lead", "; ".join(sorted({source for item in extra["cwe"]["ids"]
                                                      for source in item["sources"] if source.startswith("tool")}))
                      or "no mapped tool rule"]]
            trail += [[item["stage"][:2], f"CWE judgment {item['cwe_id']}"] for item in finding.get("cwe_judgments", [])]
            if cvss:
                trail.append(["12", f"CVSS {cvss['score']} {cvss['severity']} (pinned cvss4.py)"])
            trail.append(["reachability", reach["state"] + (f" ({cap})" if cap else "")])
            row["trail"] = trail + row["trail"]
            if extra["severity"]["final"] == "CRITICAL":
                block = poc_blocks.get(finding["claim_id"])
                row["poc_fix"] = block
                if block is None:   # brief F: absence is a gap, stated under the finding
                    row["poc_fix_note"] = ("No light PoC or proposed fix: " +
                        ((poc_fix or {}).get("reason") or "lane 12b published no record for this finding") + ".")
        result.append(row)
    return result


def _attack_chains(section: dict[str, Any] | None) -> dict[str, Any]:
    """The renderer's attack-chain section (ADR-0016 decision 9); absent input renders as a gap."""
    if section is None:
        return {"status": "ABSENT", "reason": "no attack-chain section was built", "chains": [], "appendix": [],
                "refuted_count": 0, "note": ""}
    return {key: section[key] for key in ("status", "reason", "chains", "appendix", "refuted_count", "note")}


def _dependency_reachability(section: dict[str, Any] | None) -> dict[str, Any]:
    """The renderer's dependency-reachability section (ADR-0023); absent input renders as a gap."""
    if section is None:
        return {"status": "ABSENT", "reason": "no dependency-reachability section was built",
                "counts": {"reachable": 0, "conflict": 0, "unknown": 0, "unreachable": 0}, "rows": [], "note": ""}
    return {key: section[key] for key in ("status", "reason", "counts", "rows", "note")}


WORKBENCH_NOTE = ("Candidate threat-model records from 03-threat-model-dfd-stride (ADR-0019 workbench and "
                  "L13 privacy cell). They are hypotheses for review, not findings: exposure is declared, "
                  "never observed, and regulatory notes are candidates, not a conclusion about compliance.")


def _records(threat_model: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return [json.loads(item) for item in threat_model.get(key, [])]


def _ids(values: list[str] | None) -> str:
    return ", ".join(values or [])


def _tree_summary(tree: dict[str, Any]) -> dict[str, Any]:
    nodes = tree.get("nodes", [])
    leaves = [node for node in nodes if node.get("kind") == "leaf"]
    support = {kind: sum(node.get("leaf_support") == kind for node in leaves)
               for kind in ("evidence", "assumption", "unresolved")}
    return {"id": tree["tree_id"], "objective": tree["objective"], "nodes": len(nodes),
            "gates": sum(node.get("kind") in {"AND", "OR"} for node in nodes), "leaves": len(leaves),
            "leaf_support": support, "evidence": tree.get("evidence_class"), "confidence": tree.get("confidence"),
            "verification_items": sorted({item for node in nodes for item in node.get("verification_item_ids", [])})}


def _threat_workbench(threat_model: dict[str, Any] | None) -> dict[str, Any]:
    """The renderer's workbench section (ADR-0019 open decision 4); a pre-workbench report is a gap."""
    empty = {"data_classes": 0, "privacy_threats": 0, "deployment_zones": 0, "attack_trees": 0}
    if threat_model is None or not {"data_classes", "privacy_threats", "deployment_zones"} <= set(threat_model):
        return {"status": "ABSENT", "reason": "the synthesis report carries no workbench record families",
                "counts": empty, "data_classes": [], "privacy_threats": [], "deployment_zones": [],
                "attack_trees": [], "note": WORKBENCH_NOTE}
    data_classes = [{"id": item["data_class_id"], "category": item["category"], "sensitivity": item["sensitivity"],
                     "stores": _ids(item.get("store_element_ids")), "flows": _ids(item.get("flow_ids")),
                     "handling": "; ".join(f"{label}: {item[key]}" for label, key in
                                          (("retention", "retention_hint"), ("export", "export_hint"),
                                           ("delete", "delete_hint")) if item.get(key)),
                     "evidence": item["evidence_class"], "confidence": item["confidence"]}
                    for item in _records(threat_model, "data_classes")]
    privacy = [{"id": item["privacy_threat_id"], "category": item["linddun_category"],
                "statement": item["statement"],
                "targets": _ids(item.get("target_element_ids", []) + item.get("target_flow_ids", [])),
                "data_classes": _ids(item.get("data_class_ids")),
                "regulatory_notes": "; ".join(item.get("regulatory_candidate_notes", [])),
                "evidence": item["evidence_class"], "confidence": item["confidence"]}
               for item in _records(threat_model, "privacy_threats")]
    zones = [{"id": item["zone_id"], "kind": item["kind"], "name": item["name"], "exposure": item["exposure_label"],
              "evidence": item["evidence_class"], "confidence": item["confidence"]}
             for item in _records(threat_model, "deployment_zones")]
    trees = [_tree_summary(item) for item in _records(threat_model, "attack_trees")]
    counts = {"data_classes": len(data_classes), "privacy_threats": len(privacy),
              "deployment_zones": len(zones), "attack_trees": len(trees)}
    return {"status": "PUBLISHED", "reason": "" if any(counts.values()) else
            "the threat workbench published no data class, privacy threat, deployment zone or attack tree",
            "counts": counts, "data_classes": data_classes, "privacy_threats": privacy,
            "deployment_zones": zones, "attack_trees": trees, "note": WORKBENCH_NOTE}


def build_review(report: dict[str, Any], trace: dict[str, Any],
                 enrichment: dict[str, Any] | None = None,
                 attack_chains: dict[str, Any] | None = None,
                 poc_fix: dict[str, Any] | None = None,
                 dependency_reachability: dict[str, Any] | None = None) -> dict[str, Any]:
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
    if enrichment is not None and (enrichment.get("gaps") or []):
        report = {**report, "limitations": sorted(set(report["limitations"]) | set(enrichment["gaps"]))}
    if enrichment is not None and enrichment["run_id"] != report["run_id"]:
        raise Blocked("10-synthesis-report: finding enrichment belongs to another run")
    if attack_chains is not None and attack_chains["run_id"] != report["run_id"]:
        raise Blocked("10-synthesis-report: attack-chain section belongs to another run")
    if attack_chains is not None and attack_chains["gaps"]:
        report = {**report, "limitations": sorted(set(report["limitations"]) | set(attack_chains["gaps"]))}
    if poc_fix is not None and poc_fix["run_id"] != report["run_id"]:
        raise Blocked("10-synthesis-report: PoC-and-fix section belongs to another run")
    if poc_fix is not None and poc_fix["gaps"]:
        report = {**report, "limitations": sorted(set(report["limitations"]) | set(poc_fix["gaps"]))}
    if dependency_reachability is not None and dependency_reachability["run_id"] != report["run_id"]:
        raise Blocked("10-synthesis-report: dependency-reachability section belongs to another run")
    if dependency_reachability is not None and dependency_reachability["gaps"]:
        report = {**report, "limitations": sorted(set(report["limitations"]) | set(dependency_reachability["gaps"]))}
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
        "target": report["scope"]["target"], "target_commit": report["scope"].get("source_revision") or "not asserted",
        "engagement": "Evidence-backed draft; human decision required", "run_id": report["run_id"],
        "sat_id": "not asserted", "pipeline_commit": "not asserted", "report_date": "not asserted",
        "classification": "Internal - DRAFT_EVIDENCE_BACKED", "native_tier": "N/A",
        "native_tier_note": "Native build tier is not asserted by this synthesis input.",
        "authors": ["appsec-review pipeline"], "sample": False, "source_root": None},
        "finding_scoring": "authoritative_retained_publication", "process_assurance": "not_asserted",
        "families": families, "processes": processes,
        "findings": _findings(report, evidence_ids, enrichment, poc_fix), "evidence": evidence,
        "attack_chains": _attack_chains(attack_chains),
        "dependency_reachability": _dependency_reachability(dependency_reachability),
        "threat_workbench": _threat_workbench(report.get("threat_model")),
        "target_context": {"source_snapshot_sha256": report["scope"].get("source_snapshot_sha256", "not asserted"),
            "components": report["scope"]["components"],
            "relationships": report.get("component_relationships", []),
            "elements": report.get("threat_model", {}).get("elements", []),
            "flows": report.get("threat_model", {}).get("flows", []),
            "trust_boundaries": report.get("threat_model", {}).get("trust_boundaries", []),
            "data_classes": report.get("threat_model", {}).get("data_classes", []),
            "deployment_zones": report.get("threat_model", {}).get("deployment_zones", []),
            "privacy_threats": report.get("threat_model", {}).get("privacy_threats", []),
            "abuse_scenarios": report.get("threat_model", {}).get("abuse_scenarios", []),
            "attack_trees": report.get("threat_model", {}).get("attack_trees", []),
            "stride_hypotheses": report.get("threat_model", {}).get("stride_hypotheses", []),
            "assumptions": report.get("threat_model", {}).get("assumptions", []),
            "gaps": report.get("threat_model", {}).get("gaps", []),
            "unresolved_candidates": report["unresolved_candidates"],
            "owasp_coverage": report["owasp_coverage"]},
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
           generator_sha256: str, enrichment: dict[str, Any] | None = None,
           attack_chains: dict[str, Any] | None = None, poc_fix: dict[str, Any] | None = None,
           dependency_reachability: dict[str, Any] | None = None) -> dict[str, Any]:
    output_root = Path(output_root)
    review = build_review(report, trace, enrichment, attack_chains, poc_fix, dependency_reachability)
    atomic_json(output_root / RENDER_INPUT, review)
    render_root = output_root / "presentation"
    _renderer().render(output_root / RENDER_INPUT, render_root)
    _compile_pdf(render_root)
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
