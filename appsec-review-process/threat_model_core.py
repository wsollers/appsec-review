#!/usr/bin/env python3
"""Deterministic nominal core for ``03-threat-model-dfd-stride``.

The worker consumes the current accepted F03 component map and the exact F02 evidence assembly
bound by that map.  It publishes static DFD records and candidate STRIDE hypotheses only.  It does
not make findings, severity assignments, runtime observations, or verification claims.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import component_characterization as cc
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json, run_path
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

JOB = "03-threat-model-dfd-stride"
DAGSTER_JOB = "threat_model_dfd_stride"
CONTRACT = "threat-model-core"
RESULT = "integrated-threat-model.json"
SUMMARY = "threat-model-summary.md"
PERMISSIONS = ["read-source", "read-run-data", "write-run-data"]
STRIDE = (
    "spoofing", "tampering", "repudiation", "information_disclosure",
    "denial_of_service", "elevation_of_privilege",
)
PROHIBITED_KEYS = {
    "finding", "findings", "severity", "cvss", "verified", "verification_status",
    "runtime_state", "observed_runtime", "exploitability", "compliance_status",
    "remediation_status", "malicious_intent",
}
PROHIBITED_TEXT = (
    re.compile(r"(?i)(?<!not a )(?<!no )\bverified[- ]finding\b"),
    re.compile(r"(?i)(?<!not a )(?<!no )\bconfirmed[- ]vulnerabilit(?:y|ies)\b"),
    re.compile(r"(?i)\bseverity\s*(?:is|=|:)\s*(?:critical|high|medium|low)\b"),
    re.compile(r"(?i)\bobserved[- ]runtime\b|\bruntime[- ]verified\b"),
    re.compile(r"(?i)\b(?:is|are)\s+(?:fully\s+)?(?:compliant|certified)\b|\bcompliance verdict\b"),
    re.compile(r"(?i)\bremediation status\b|\b(?:is|was|has been)\s+(?:fixed|remediated)\b"),
)
CODE_FILES = (
    "threat_model_core.py", "component_characterization.py", "publish_job_output.py",
    "validate_job_output.py", "registry/job-templates/03-threat-model-dfd-stride.json",
    "registry/roles/threat-model-core.json", "registry/domains/threat-model-core.json",
    "registry/tooling-profiles/threat-model-static-evidence.json",
    "registry/output-contracts/threat-model-core.json",
    "03-threat-model-dfd-stride/task-threat-model-core.md",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in (
        "integrated-threat-model.schema.json", "threat-model-citation.schema.json",
        "threat-model-element.schema.json", "threat-model-flow.schema.json",
        "threat-model-trust-boundary.schema.json", "threat-model-stride-hypothesis.schema.json",
        "threat-model-assumption.schema.json", "threat-model-gap.schema.json",
    ):
        values[f"schemas/{name}"] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _slug(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", value.lower())).strip("-") or "unknown"


def _run_relative(run_id: str, path: Path) -> str:
    try:
        return path.resolve().relative_to(run_path(run_id).resolve()).as_posix()
    except ValueError as exc:
        raise Blocked(f"{JOB}: accepted evidence is outside the run root") from exc


def current_inputs(run_id: str) -> dict[str, Any]:
    """Resolve F03 through its own validator, which re-derives current F02/source identity."""
    component_attempt = cc.validate(run_id)
    component_pointer_path = cc.root(run_id) / "accepted.json"
    component_pointer = read_json(component_pointer_path)
    component_file = component_attempt / cc.RESULT
    component_map = read_json(component_file)
    lineage = component_map["evidence_manifest_lineage"]
    evidence_attempt = data_path(run_id, "jobs", cc.UPSTREAM_JOB, "attempts", lineage["producer_attempt_id"])
    evidence_manifest = evidence_attempt / cc.UPSTREAM_MANIFEST
    if (not evidence_manifest.is_file() or evidence_manifest.is_symlink() or
            "sha256:" + file_hash(evidence_manifest) != lineage["manifest_sha256"]):
        raise Blocked(f"{JOB}: F03-bound F02 evidence manifest changed")
    manifest = read_json(evidence_manifest)
    administrative = {"permission.json", "lineage.json", "status.json", "result.json", "b13-receipt.json"}
    artifacts = {item["path"]: item for producer in manifest["producers"] for item in producer["artifacts"]
                 if Path(item["producer_path"]).name not in administrative}
    cited_paths = sorted({citation["path"] for citation in _component_citations(component_map)
                          if citation.get("source_type") == "upstream_lane" and citation.get("path") in artifacts})
    if len(cited_paths) != 1:
        raise Blocked(f"{JOB}: F03 must cite exactly one substantive F02 assembly artifact; found {len(cited_paths)}")
    evidence = artifacts[cited_paths[0]]
    evidence_file = evidence_attempt / evidence["path"]
    if (not evidence_file.is_file() or evidence_file.is_symlink() or
            "sha256:" + file_hash(evidence_file) != evidence["sha256"]):
        raise Blocked(f"{JOB}: cited F02 evidence artifact changed")
    return {
        "run_id": run_id,
        "source_snapshot_sha256": component_map["source_snapshot_sha256"],
        "component_attempt_id": component_pointer["attempt_id"],
        "component_pointer_sha256": "sha256:" + file_hash(component_pointer_path),
        "component_envelope_sha256": "sha256:" + component_pointer["envelope_sha256"],
        "component_map_path": _run_relative(run_id, component_file),
        "component_map_sha256": file_hash(component_file),
        "evidence_attempt_id": lineage["producer_attempt_id"],
        "evidence_manifest_sha256": lineage["manifest_sha256"],
        "evidence_path": _run_relative(run_id, evidence_file),
        "evidence_sha256": evidence["sha256"].removeprefix("sha256:"),
        "component_map": component_map,
        "code": _code_hashes(),
    }


def _citations(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"source_class": "accepted_lane", "producer": cc.JOB,
         "attempt_id": inputs["component_attempt_id"], "path": inputs["component_map_path"],
         "sha256": inputs["component_map_sha256"], "line_range": None,
         "index_record_id": None, "note": "accepted F03 component and relationship evidence"},
        {"source_class": "derived", "producer": cc.UPSTREAM_JOB,
         "attempt_id": inputs["evidence_attempt_id"], "path": inputs["evidence_path"],
         "sha256": inputs["evidence_sha256"], "line_range": None,
         "index_record_id": None, "note": "dereferenced artifact from the exact F02 assembly bound by F03"},
    ]


def _component_citations(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "evidence_citations" and isinstance(item, list):
                yield from (citation for citation in item if isinstance(citation, dict))
            else:
                yield from _component_citations(item)
    elif isinstance(value, list):
        for item in value:
            yield from _component_citations(item)


def _element_kind(component: dict[str, Any]) -> str:
    text = " ".join((component["name"], component["component_type"],
                     component["observed_purpose"])).lower()
    if component["deployability"] == "build-time":
        return "support_workflow"
    if any(word in text for word in ("database", "store", "repository", "cache")):
        return "store"
    if any(word in text for word in ("client", "cli", "frontend")):
        return "client"
    if any(word in text for word in ("service", "server", "api")):
        return "service"
    return "process"


def build_model(inputs: dict[str, Any], attempt_id: str) -> dict[str, Any]:
    source = inputs["component_map"]
    citations = _citations(inputs)
    elements, flows, boundaries, hypotheses, coverage = [], [], [], [], []
    components = sorted(source["functional_components"], key=lambda item: item["component_id"])
    for component in components:
        elements.append({
            "element_id": "element-" + component["component_id"], "kind": _element_kind(component),
            "name": component["name"], "component_id": component["component_id"], "zone_id": None,
            "identities": [], "tenancy": None, "description": component["observed_purpose"],
            "evidence_class": "STRONG_INFERENCE", "confidence": component["confidence"],
            "citations": citations, "originating_workcell_id": "deterministic-dfd-core",
        })
    component_ids = {item["component_id"] for item in components}
    for relationship in sorted(source["component_relationships"], key=lambda item: item["relationship_id"]):
        if relationship["from_component_id"] not in component_ids or relationship["to_component_id"] not in component_ids:
            raise Blocked(f"{JOB}: F03 relationship has a dangling component reference")
        flow_id = "flow-" + relationship["relationship_id"]
        boundary_id = "boundary-" + relationship["relationship_id"]
        boundary_kind = "build_release" if relationship["relationship_type"] in {"builds", "deploys"} else "process"
        boundaries.append({"boundary_id": boundary_id, "kind": boundary_kind,
            "reason": f"The {relationship['relationship_type']} relationship crosses component ownership/execution context.",
            "evidence_class": "STRONG_INFERENCE", "confidence": relationship["confidence"],
            "citations": citations, "originating_workcell_id": "deterministic-dfd-core"})
        flows.append({"flow_id": flow_id,
            "source_element_id": "element-" + relationship["from_component_id"],
            "destination_element_id": "element-" + relationship["to_component_id"],
            "protocol": None, "auth_context": None, "data_class_ids": [],
            "boundary_ids": [boundary_id], "direction": "push",
            "evidence_class": "STRONG_INFERENCE", "confidence": relationship["confidence"],
            "citations": citations, "originating_workcell_id": "deterministic-dfd-core"})
        decisions = {}
        for category in STRIDE:
            threat_id = f"threat-{relationship['relationship_id']}-{category.replace('_', '-')}"
            decisions[category] = "hypothesis"
            hypotheses.append({"threat_id": threat_id, "target_kind": "flow", "target_id": flow_id,
                "stride_category": category,
                "statement": f"Candidate {category.replace('_', ' ')} condition at {flow_id}; verification is required.",
                "evidence_class": "FOLLOW_ON_REQUIRED", "confidence": "low", "citations": citations,
                "proof_obligations": [f"Determine whether {category.replace('_', ' ')} controls cover {flow_id}."],
                "minimum_verification": "source_review", "downstream_owner": "09-independent-verification",
                "contested": False, "originating_workcell_id": "deterministic-stride-core"})
        coverage.append({"flow_id": flow_id, "decisions": decisions})
    assumptions, gaps, triggers = [], [], []
    for unknown in sorted(source["unknowns"], key=lambda item: item["unknown_id"]):
        affected = ["element-" + value for value in unknown["affected_component_ids"] if value in component_ids]
        assumptions.append({"assumption_id": "assumption-" + unknown["unknown_id"],
            "topic": unknown["subject"], "statement": unknown["question"], "affected_record_ids": affected,
            "status": "unresolved", "confidence": "low", "evidence_class": "FOLLOW_ON_REQUIRED",
            "originating_workcell_id": "deterministic-dfd-core", "intercom_record_id": None,
            "citations": citations})
    for item in sorted(source["classification_gaps"], key=lambda item: item["gap_id"]):
        gap_id = "gap-" + item["gap_id"]
        gaps.append({"gap_id": gap_id, "kind": "missing_evidence", "statement": item["reason"],
            "affected_record_ids": [], "originating_workcell_id": "deterministic-dfd-core",
            "intercom_record_id": None, "evidence_class": "FOLLOW_ON_REQUIRED", "confidence": "low",
            "citations": citations})
        triggers.append({"trigger_id": "trigger-" + item["gap_id"], "kind": "component_without_evidence",
            "statement": item["resolution_action"], "affected_record_ids": [gap_id]})
    for item in sorted(source["rescope_triggers"], key=lambda item: item["trigger_id"]):
        affected = ["element-" + value for value in item["affected_component_ids"] if value in component_ids]
        triggers.append({"trigger_id": "trigger-f03-" + item["trigger_id"],
            "kind": "boundary_crossing_follow_on_required",
            "statement": (item["condition"] + " Required evidence: " + "; ".join(item["required_evidence"]) +
                          ". Actions: " + "; ".join(item["actions"]) +
                          f". Re-entry is bounded to {item['max_reentry_rounds']} round(s)."),
            "affected_record_ids": affected})
    return {"schema": "appsec-review/integrated-threat-model/0.1", "run_id": inputs["run_id"],
        "job_id": JOB, "attempt_id": attempt_id, "source_snapshot": inputs["source_snapshot_sha256"],
        "component_map_attempt_id": inputs["component_attempt_id"], "budget_class": "standard",
        "elements": elements, "flows": flows, "trust_boundaries": boundaries, "data_classes": [],
        "deployment_zones": [], "abuse_scenarios": [], "attack_trees": [],
        "stride_hypotheses": hypotheses, "stride_coverage": coverage, "assumptions": assumptions,
        "gaps": gaps, "rescope_triggers": triggers,
        "coverage": {"unmodeled_components": [], "workcells": [{"workcell_id": "deterministic-dfd-core",
            "instance_id": attempt_id, "wave": "join", "selection": "selected", "omission_reason": None,
            "terminal_status": "OK_WITH_GAPS" if gaps or assumptions else "OK", "persona_id": None,
            "prompt_hash": None, "model_identity_hash": None}], "wave_4": "omitted_budget"},
        "dissent": []}


def _walk_keys(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower().replace("-", "_") in PROHIBITED_KEYS:
                errors.append(f"{path}.{key}: prohibited claim promotion")
            errors.extend(_walk_keys(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_walk_keys(item, f"{path}[{index}]"))
    elif isinstance(value, str) and any(pattern.search(value) for pattern in PROHIBITED_TEXT):
        errors.append(f"{path}: text promotes a threat hypothesis to a prohibited conclusion")
    return errors


def validate_model(value: dict[str, Any], inputs: dict[str, Any] | None = None) -> list[str]:
    errors = list(validate_document(value, "integrated-threat-model.schema.json"))
    if errors:
        return errors
    errors.extend(_walk_keys(value))
    ids = {item["element_id"] for item in value["elements"]}
    boundary_ids = {item["boundary_id"] for item in value["trust_boundaries"]}
    flow_ids = {item["flow_id"] for item in value["flows"]}
    if len(ids) != len(value["elements"]) or len(flow_ids) != len(value["flows"]) or len(boundary_ids) != len(value["trust_boundaries"]):
        errors.append("DFD identifiers must be unique")
    expected_citations = _citations(inputs) if inputs is not None else None
    records = [*value["elements"], *value["flows"], *value["trust_boundaries"],
               *value["stride_hypotheses"], *value["assumptions"], *value["gaps"]]
    for record in records:
        if expected_citations is not None and record["citations"] != expected_citations:
            errors.append("record citations do not match exact accepted F03/F02 lineage")
    for flow in value["flows"]:
        if flow["source_element_id"] not in ids or flow["destination_element_id"] not in ids:
            errors.append(f"{flow['flow_id']}: dangling flow endpoint")
        if not set(flow["boundary_ids"]) <= boundary_ids:
            errors.append(f"{flow['flow_id']}: dangling trust boundary")
    crossing = {item["flow_id"] for item in value["flows"] if item["boundary_ids"]}
    coverage = {item["flow_id"]: item["decisions"] for item in value["stride_coverage"]}
    if set(coverage) != crossing:
        errors.append("STRIDE coverage must account for every and only boundary-crossing flow")
    threats = {(item["target_id"], item["stride_category"]) for item in value["stride_hypotheses"]}
    for flow_id in crossing:
        for category in STRIDE:
            decision = coverage.get(flow_id, {}).get(category)
            if decision == "hypothesis" and (flow_id, category) not in threats:
                errors.append(f"{flow_id}: {category} hypothesis decision has no candidate threat")
            if decision == "unresolved" and not any(flow_id in item["affected_record_ids"] for item in value["gaps"]):
                errors.append(f"{flow_id}: {category} unresolved decision has no explicit gap")
    if inputs is not None:
        expected_components = {item["component_id"] for item in inputs["component_map"]["functional_components"]}
        modeled = {item["component_id"] for item in value["elements"] if item["component_id"] is not None}
        unmodeled = {item["component_id"] for item in value["coverage"]["unmodeled_components"]}
        if modeled | unmodeled != expected_components or modeled & unmodeled:
            errors.append("component coverage does not exactly partition the accepted F03 map")
    return errors


def _validate_attempt(attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable inputs changed")
    value = read_json(attempt / RESULT)
    if value != build_model(inputs, attempt.name):
        raise Blocked(f"{JOB}: result differs from deterministic immutable inputs")
    errors = validate_model(value, inputs)
    if errors:
        raise Blocked(f"{JOB}: threat model validation failed ({len(errors)} errors)")
    permission, lineage = _receipts(inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: permission or lineage receipt differs from canonical immutable inputs")


def _receipts(inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB,
        "source_snapshot_sha256": inputs["source_snapshot_sha256"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB,
        "source_snapshot_sha256": inputs["source_snapshot_sha256"],
        "build_lineage_sha256": "sha256:" + digest({"component_pointer": inputs["component_pointer_sha256"],
            "component_envelope": inputs["component_envelope_sha256"],
            "component_map": inputs["component_map_sha256"], "f02": inputs["evidence_manifest_sha256"]})}
    return permission, lineage


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = f"python -B appsec-review-process/threat_model_core.py --run-id {run_id}"

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        attempt, attempt_id = allocation["attempt"], allocation["attempt_id"]
        model = build_model(inputs, attempt_id)
        errors = validate_model(model, inputs)
        if errors:
            raise ValueError("; ".join(errors))
        atomic_json(attempt / RESULT, model)
        gaps = [item["statement"] for item in model["gaps"]] + [item["statement"] for item in model["assumptions"]]
        status_name = "OK_WITH_GAPS" if gaps else "OK"
        atomic_bytes(attempt / SUMMARY, ("# Threat model\n\n"
            f"{len(model['elements'])} elements, {len(model['flows'])} flows, "
            f"{len(model['stride_hypotheses'])} candidate STRIDE hypotheses.\n\n"
            "Hypotheses require downstream verification and are not findings or severity assessments.\n").encode())
        permission, lineage = _receipts(inputs)
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", lineage)
        status = {"process": JOB, "status": status_name, "elements": len(model["elements"]),
            "flows": len(model["flows"]), "candidate_hypotheses": len(model["stride_hypotheses"]),
            "coverage_gaps": len(gaps), "claim_limit": "candidate-hypotheses-only"}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_id, worker_kind="deterministic_python", output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"], execution_status=status_name,
            summary="Deterministic DFD and candidate STRIDE model produced.", status_record=status,
            artifact_paths=[RESULT, SUMMARY, "permission.json", "lineage.json", "status.json"], gaps=gaps,
            pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Threat-model inputs were not current and complete.",
        failed_summary="Threat-model core did not publish; no older result may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    inputs = current_inputs(run_id)
    attempt, _ = validate_published(root(run_id), pointer or read_json(root(run_id) / "accepted.json"),
        "sha256:" + digest(inputs), expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-threat-model-core")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))
