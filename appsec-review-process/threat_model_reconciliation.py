#!/usr/bin/env python3
"""Executable L6B reconciliation for the accepted L6A threat-model snapshot."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

import component_characterization as cc
from execution_state import (Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest,
                             file_hash, read_json, run_path, tree_hashes)
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document
import threat_model_core as tm
from worker_result import validate_worker_result

JOB = "03-threat-model-reconciliation"
CONTRACT = "threat-model-reconciliation"
RESULT = "threat-model-reconciliation.json"
SUMMARY = "threat-model-reconciliation-summary.md"
CONTROL = "threat-model-reconciliation-input.json"
PERMISSIONS = ["read-source", "read-run-data", "write-run-data"]
CODE_FILES = (
    "threat_model_reconciliation.py", "threat_model_core.py", "component_characterization.py",
    "publish_job_output.py", "validate_job_output.py",
    "registry/job-templates/03-threat-model-reconciliation.json",
    "registry/output-contracts/threat-model-reconciliation.json",
    "registry/roles/threat-model-reconciler.json",
    "registry/domains/threat-model-reconciliation.json",
    "registry/tooling-profiles/threat-model-reconciliation.json",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _sha(path: Path) -> str:
    return "sha256:" + file_hash(path)


def _relative(run_id: str, path: Path) -> str:
    try:
        return path.resolve().relative_to(run_path(run_id).resolve()).as_posix()
    except ValueError as exc:
        raise Blocked(f"{JOB}: accepted artifact is outside the run root") from exc


def _safe(root_path: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise Blocked(f"{JOB}: accepted artifact path is invalid")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise Blocked(f"{JOB}: accepted artifact path is invalid")
    path = root_path.joinpath(*pure.parts)
    try:
        path.resolve().relative_to(root_path.resolve())
    except ValueError as exc:
        raise Blocked(f"{JOB}: accepted artifact path escapes its attempt") from exc
    return path


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in ("threat-model-reconciliation.schema.json",
                 "threat-model-reconciliation-input.schema.json",
                 "threat-model-reconciliation-sha.schema.json",
                 "threat-model-reconciliation-binding.schema.json",
                 "threat-model-reconciliation-citation.schema.json",
                 "threat-model-reconciliation-delta.schema.json",
                 "threat-model-reconciliation-unresolved.schema.json",
                 "threat-model-reconciliation-external.schema.json",
                 "threat-model-reconciliation-conflict.schema.json",
                 "threat-model-reconciliation-action.schema.json",
                 "integrated-threat-model.schema.json", "component-purpose-map.schema.json"):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def _accepted_l6a(run_id: str) -> tuple[Path, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate an accepted L6A snapshot internally without requiring it to match newer F03 bytes."""
    base = tm.root(run_id); pointer_path = base / "accepted.json"; latest_path = base / "latest.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked(f"{JOB}: accepted L6A pointer is required")
    pointer = read_json(pointer_path); latest = read_json(latest_path) if latest_path.is_file() else {}
    expected = {"schema", "status", "run_id", "job", "attempt_id", "fingerprint",
                "envelope_path", "envelope_sha256", "hashes", "accepted_at"}
    if (set(pointer) != expected or pointer.get("schema") != "appsec-review/accepted-worker-result/1.0" or
            pointer.get("run_id") != run_id or pointer.get("job") != tm.JOB or
            pointer.get("status") not in {"OK", "OK_WITH_GAPS"} or
            latest.get("attempt_id") != pointer.get("attempt_id")):
        raise Blocked(f"{JOB}: L6A pointer is not a current accepted snapshot")
    attempt_id = pointer["attempt_id"]
    if not isinstance(attempt_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,119}", attempt_id):
        raise Blocked(f"{JOB}: L6A attempt id is invalid")
    attempt = base / "attempts" / attempt_id; envelope_path = attempt / pointer["envelope_path"]
    if (not attempt.is_dir() or attempt.is_symlink() or not envelope_path.is_file() or
            file_hash(envelope_path) != pointer["envelope_sha256"] or tree_hashes(attempt) != pointer["hashes"]):
        raise Blocked(f"{JOB}: accepted L6A snapshot changed")
    envelope = read_json(envelope_path)
    if (validate_worker_result(envelope) or envelope.get("run_id") != run_id or
            envelope.get("job_id") != tm.JOB or envelope.get("attempt_id") != attempt_id or
            envelope.get("acceptance_status") != "CURRENT" or
            envelope.get("execution_status") != pointer["status"] or
            envelope.get("input_fingerprint") != pointer["fingerprint"] or
            envelope.get("output_contract") != tm.CONTRACT or pointer["envelope_path"] != "result.json"):
        raise Blocked(f"{JOB}: accepted L6A envelope is invalid")
    artifacts = {item["path"]: item["sha256"] for item in envelope["artifacts"]}
    for relative, expected_sha in artifacts.items():
        path = _safe(attempt, relative)
        if not path.is_file() or path.is_symlink() or file_hash(path) != expected_sha:
            raise Blocked(f"{JOB}: accepted L6A artifact changed")
    result_path = attempt / tm.RESULT; inputs_path = attempt / "inputs.json"
    if artifacts.get(tm.RESULT) != file_hash(result_path) or not inputs_path.is_file():
        raise Blocked(f"{JOB}: accepted L6A result or immutable inputs are not bound")
    inputs = read_json(inputs_path); tm._validate_attempt(attempt, inputs)
    model = read_json(result_path)
    return attempt, model, inputs, {"job_id":tm.JOB, "attempt_id":attempt_id,
        "accepted_pointer_sha256":_sha(pointer_path), "envelope_sha256":_sha(envelope_path),
        "result_sha256":_sha(result_path), "input_fingerprint":pointer["fingerprint"],
        "component_map_sha256":"sha256:" + inputs["component_map_sha256"],
        "evidence_manifest_sha256":inputs["evidence_manifest_sha256"],
        "source_snapshot_sha256":inputs["source_snapshot_sha256"]}


def _current_component(run_id: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    attempt = cc.validate(run_id); result_path = attempt / cc.RESULT
    pointer_path = cc.root(run_id) / "accepted.json"; pointer = read_json(pointer_path)
    value = read_json(result_path); lineage = value["evidence_manifest_lineage"]
    return attempt, value, {"job_id":cc.JOB, "attempt_id":pointer["attempt_id"],
        "accepted_pointer_sha256":_sha(pointer_path),
        "envelope_sha256":"sha256:" + pointer["envelope_sha256"],
        "result_sha256":_sha(result_path), "input_fingerprint":pointer["fingerprint"],
        "component_map_sha256":_sha(result_path),
        "evidence_manifest_sha256":lineage["manifest_sha256"],
        "source_snapshot_sha256":value["source_snapshot_sha256"]}


def _control(run_id: str) -> tuple[dict[str, Any], str | None, str | None]:
    try:
        path = data_path(run_id, "controls", CONTROL)
    except ValueError as exc:
        raise Blocked(f"{JOB}: reconciliation control must be a regular file") from exc
    if not path.exists():
        return {"schema":"appsec-review/threat-model-reconciliation-input/1.0", "inputs":[]}, None, None
    if not path.is_file() or path.is_symlink():
        raise Blocked(f"{JOB}: reconciliation control must be a regular file")
    value = read_json(path); errors = validate_document(value, "threat-model-reconciliation-input.schema.json")
    if errors:
        raise Blocked(f"{JOB}: reconciliation control fails its closed schema ({len(errors)} errors)")
    ids = [item["input_id"] for item in value["inputs"]]
    if len(ids) != len(set(ids)):
        raise Blocked(f"{JOB}: reconciliation control repeats an input id")
    for item in value["inputs"]:
        model_fields = (item["model_identity_sha256"], item["prompt_sha256"])
        if ((item["origin"] == "model" and not all(isinstance(field, str) for field in model_fields)) or
                (item["origin"] == "reviewer" and model_fields != (None, None))):
            raise Blocked(f"{JOB}: reconciliation input origin conflicts with model identity fields")
    return value, _relative(run_id, path), _sha(path)


def current_inputs(run_id: str) -> dict[str, Any]:
    l6a_attempt, model, baseline_inputs, baseline = _accepted_l6a(run_id)
    component_attempt, component, current = _current_component(run_id)
    prospective_inputs = tm.current_inputs(run_id)
    if (prospective_inputs["component_attempt_id"] != current["attempt_id"] or
            "sha256:" + prospective_inputs["component_map_sha256"] != current["component_map_sha256"]):
        raise Blocked(f"{JOB}: current L6A input derivation differs from accepted F03")
    control, control_path, control_sha = _control(run_id)
    return {"run_id":run_id, "source_snapshot_sha256":current["source_snapshot_sha256"],
        "baseline":baseline, "baseline_model":model, "baseline_inputs":baseline_inputs,
        "baseline_model_path":_relative(run_id, l6a_attempt / tm.RESULT),
        "current":current, "current_component":component,
        "current_component_path":_relative(run_id, component_attempt / cc.RESULT),
        "prospective_inputs":prospective_inputs, "control":control,
        "control_path":control_path, "control_sha256":control_sha, "code":_code_hashes()}


def _records(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {item[key]:item for item in items}


def _delta(before: dict[str, Any], after: dict[str, Any], citations: list[str]) -> dict[str, Any]:
    common = set(before) & set(after)
    return {"added":sorted(set(after)-set(before)), "removed":sorted(set(before)-set(after)),
        "changed":sorted(key for key in common if digest(before[key]) != digest(after[key])),
        "citation_ids":citations}


def _model_records(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for collection, key in (("elements","element_id"),("flows","flow_id"),
            ("trust_boundaries","boundary_id"),("stride_hypotheses","threat_id"),
            ("assumptions","assumption_id"),("gaps","gap_id")):
        for item in model[collection]:
            result[item[key]] = item
    return result


def build_result(inputs: dict[str, Any], attempt_id: str) -> dict[str, Any]:
    baseline_model = inputs["baseline_model"]; current_component = inputs["current_component"]
    preview = tm.build_model(inputs["prospective_inputs"], "reconciliation-preview")
    citation_ids = ["l6a-model", "current-component"]
    citations = [{"citation_id":"l6a-model", "producer_job_id":tm.JOB,
        "attempt_id":inputs["baseline"]["attempt_id"], "path":inputs["baseline_model_path"],
        "sha256":inputs["baseline"]["result_sha256"], "purpose":"accepted reproducible L6A baseline"},
        {"citation_id":"current-component", "producer_job_id":cc.JOB,
        "attempt_id":inputs["current"]["attempt_id"], "path":inputs["current_component_path"],
        "sha256":inputs["current"]["result_sha256"], "purpose":"current accepted F03 component and evidence generation"}]
    if inputs["control_path"] is not None:
        citation_ids.append("reconciliation-input")
        citations.append({"citation_id":"reconciliation-input", "producer_job_id":"operator-control",
            "attempt_id":attempt_id, "path":inputs["control_path"], "sha256":inputs["control_sha256"],
            "purpose":"bounded reviewer and model input; retained as unresolved and non-authoritative"})
    before_components = _records(inputs["baseline_inputs"]["component_map"]["functional_components"], "component_id")
    after_components = _records(current_component["functional_components"], "component_id")
    before_relationships = _records(inputs["baseline_inputs"]["component_map"]["component_relationships"], "relationship_id")
    after_relationships = _records(current_component["component_relationships"], "relationship_id")
    component_delta = _delta(before_components, after_components, ["l6a-model","current-component"])
    relationship_delta = _delta(before_relationships, after_relationships, ["l6a-model","current-component"])
    model_delta = _delta(_model_records(baseline_model), _model_records(preview), ["l6a-model","current-component"])
    source_changed = inputs["baseline"]["source_snapshot_sha256"] != inputs["current"]["source_snapshot_sha256"]
    component_changed = inputs["baseline"]["component_map_sha256"] != inputs["current"]["component_map_sha256"]
    evidence_changed = inputs["baseline"]["evidence_manifest_sha256"] != inputs["current"]["evidence_manifest_sha256"]
    external = [{**item, "disposition":"unresolved", "claim_effect":"none",
                 "citation_ids":["reconciliation-input"]} for item in inputs["control"]["inputs"]]
    related = {item["target_record_id"]:[] for item in external if item["target_record_id"] is not None}
    for item in external:
        if item["target_record_id"] is not None:
            related.setdefault(item["target_record_id"], []).append(item["input_id"])
    assumptions_by_id = _records(baseline_model["assumptions"], "assumption_id")
    assumptions_by_id.update(_records(preview["assumptions"], "assumption_id"))
    assumptions = [{"assumption_id":key, "statement":item["statement"],
        "affected_record_ids":item["affected_record_ids"], "related_input_ids":sorted(related.get(key,[])),
        "status":"unresolved", "citation_ids":["l6a-model","current-component"]}
        for key,item in sorted(assumptions_by_id.items())]
    conflicts: list[dict[str, Any]] = []
    def conflict(kind: str, records: list[str], input_ids: list[str], statement: str, refs: list[str]) -> None:
        conflicts.append({"conflict_id":"conflict-" + digest([kind,records,input_ids,statement])[:16],
            "kind":kind, "record_ids":records, "input_ids":input_ids, "statement":statement,
            "status":"unresolved", "citation_ids":refs})
    if source_changed:
        conflict("source-generation-change", [], [], "The current source generation differs from the L6A baseline.", ["l6a-model","current-component"])
    if evidence_changed:
        conflict("evidence-generation-change", [], [], "The current evidence manifest generation differs from the L6A baseline.", ["l6a-model","current-component"])
    changed_components = component_delta["added"] + component_delta["removed"] + component_delta["changed"]
    if changed_components:
        conflict("component-change", changed_components, [], "Current components differ from the L6A component generation.", ["l6a-model","current-component"])
    changed_relationships = relationship_delta["added"] + relationship_delta["removed"] + relationship_delta["changed"]
    if changed_relationships:
        conflict("relationship-change", changed_relationships, [], "Current component relationships differ from the L6A generation.", ["l6a-model","current-component"])
    for item in external:
        conflict("review-input", [item["target_record_id"]] if item["target_record_id"] else [],
                 [item["input_id"]], "Reviewer/model input requires independent evidence review; it has no claim effect.",
                 ["reconciliation-input"])
    actions=[]
    regenerate = (source_changed or component_changed or evidence_changed or
                  any(model_delta[key] for key in ("added","removed","changed")))
    if regenerate:
        actions.append({"action_id":"action-regenerate-l6a", "kind":"regenerate-l6a", "record_ids":[],
            "statement":"Regenerate L6A from the current accepted component/evidence generation before downstream reliance.",
            "citation_ids":["l6a-model","current-component"]})
    for item in assumptions:
        actions.append({"action_id":"action-review-"+item["assumption_id"], "kind":"review-assumption",
            "record_ids":[item["assumption_id"]], "statement":"Obtain independently accepted evidence before resolving this assumption.",
            "citation_ids":item["citation_ids"]})
    for item in external:
        actions.append({"action_id":"action-review-"+item["input_id"], "kind":"review-external-input",
            "record_ids":[item["target_record_id"]] if item["target_record_id"] else [],
            "statement":"Evaluate this non-authoritative input against accepted evidence.",
            "citation_ids":["reconciliation-input"]})
    gaps = bool(assumptions or external or conflicts or regenerate)
    return {"schema":"appsec-review/threat-model-reconciliation/1.0", "run_id":inputs["run_id"],
        "job_id":JOB, "attempt_id":attempt_id, "source_snapshot_sha256":inputs["source_snapshot_sha256"],
        "status":"OK_WITH_GAPS" if gaps else "OK", "baseline":inputs["baseline"], "current":inputs["current"],
        "citations":citations, "comparison":{"baseline_reproducible":True,
            "source_generation_changed":source_changed, "component_generation_changed":component_changed,
            "evidence_generation_changed":evidence_changed, "components":component_delta,
            "relationships":relationship_delta, "model_records":model_delta},
        "unresolved_assumptions":assumptions, "external_inputs":external, "conflicts":conflicts,
        "actions":actions, "coverage":{"baseline_elements":len(baseline_model["elements"]),
            "baseline_flows":len(baseline_model["flows"]), "baseline_hypotheses":len(baseline_model["stride_hypotheses"]),
            "current_components":len(current_component["functional_components"]),
            "current_relationships":len(current_component["component_relationships"]),
            "unresolved_assumptions":len(assumptions), "external_inputs":len(external),
            "external_inputs_accounted":len(external)==len(inputs["control"]["inputs"]),
            "citation_ids":citation_ids}}


def validate_result(value: dict[str, Any], inputs: dict[str, Any]) -> list[str]:
    errors = list(validate_document(value, "threat-model-reconciliation.schema.json"))
    if errors:
        return errors
    errors.extend(tm._walk_keys(value))
    citations = {item["citation_id"] for item in value["citations"]}
    for collection in (value["unresolved_assumptions"], value["external_inputs"], value["conflicts"], value["actions"]):
        for item in collection:
            if not set(item["citation_ids"]) <= citations:
                errors.append("reconciliation record has a dangling citation id")
    model_ids = set(_model_records(inputs["baseline_model"])) | set(_model_records(
        tm.build_model(inputs["prospective_inputs"], "reconciliation-preview")))
    component_ids = {item["component_id"] for item in inputs["current_component"]["functional_components"]}
    relationship_ids = {item["relationship_id"] for item in inputs["current_component"]["component_relationships"]}
    known = model_ids | component_ids | relationship_ids
    for item in value["external_inputs"]:
        target = item["target_record_id"]
        if target is not None and target not in known:
            errors.append(f"external input {item['input_id']} targets an unknown record")
    if not value["coverage"]["external_inputs_accounted"]:
        errors.append("external inputs are not completely accounted")
    return errors


def _receipts(inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = {"schema":"appsec-review/producer-permission-receipt/1.0", "run_id":inputs["run_id"],
        "job_id":JOB, "source_snapshot_sha256":inputs["source_snapshot_sha256"], "permissions":PERMISSIONS}
    lineage = {"schema":"appsec-review/producer-lineage-receipt/1.0", "run_id":inputs["run_id"],
        "job_id":JOB, "source_snapshot_sha256":inputs["source_snapshot_sha256"],
        "build_lineage_sha256":"sha256:"+digest({"baseline":inputs["baseline"], "current":inputs["current"],
            "control_sha256":inputs["control_sha256"]})}
    return permission, lineage


def _validate_attempt(attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable inputs changed")
    value = read_json(attempt / RESULT)
    if value != build_result(inputs, attempt.name):
        raise Blocked(f"{JOB}: result differs from deterministic immutable inputs")
    errors = validate_result(value, inputs)
    if errors:
        raise Blocked(f"{JOB}: result validation failed ({len(errors)} errors)")
    permission, lineage = _receipts(inputs)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: permission or lineage receipt changed")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        attempt = allocation["attempt"]; value = build_result(inputs, allocation["attempt_id"])
        errors = validate_result(value, inputs)
        if errors:
            raise ValueError("; ".join(errors))
        atomic_json(attempt / RESULT, value)
        atomic_bytes(attempt / SUMMARY, ("# Threat-model reconciliation\n\n"
            f"- component delta: {sum(len(value['comparison']['components'][key]) for key in ('added','removed','changed'))}\n"
            f"- evidence generation changed: {str(value['comparison']['evidence_generation_changed']).lower()}\n"
            f"- unresolved assumptions: {len(value['unresolved_assumptions'])}\n"
            f"- reviewer/model inputs retained without claim effect: {len(value['external_inputs'])}\n"
            f"- unresolved conflicts: {len(value['conflicts'])}\n").encode())
        permission, lineage = _receipts(inputs); atomic_json(attempt/"permission.json",permission); atomic_json(attempt/"lineage.json",lineage)
        component_changes=sum(len(value["comparison"]["components"][key]) for key in ("added","removed","changed"))
        status={"process":JOB,"status":value["status"],"component_changes":component_changes,
            "evidence_generation_changed":value["comparison"]["evidence_generation_changed"],
            "unresolved_assumptions":len(value["unresolved_assumptions"]),"external_inputs":len(value["external_inputs"]),
            "conflicts":len(value["conflicts"]),"claim_limit":"reconciliation-only-no-promotion"}
        gaps=[item["statement"] for item in value["conflicts"]] + [item["statement"] for item in value["unresolved_assumptions"]]
        return record_terminal_current(base,attempt,run_id=run_id,job_id=JOB,dagster_run_id=dagster_id,
            worker_kind="deterministic_python",output_contract=CONTRACT,input_fingerprint=fingerprint,
            started_at=allocation["started_at"],execution_status=value["status"],
            summary="Reconciled accepted L6A with current component/evidence and non-authoritative inputs.",
            status_record=status,artifact_paths=[RESULT,SUMMARY,"permission.json","lineage.json","status.json"],
            gaps=gaps or None,pre_envelope_validate=lambda path,_status:_validate_attempt(path,inputs))
    return coordinate_worker_lifecycle(base,run_id=run_id,job_id=JOB,dagster_run_id=dagster_id,
        worker_kind="deterministic_python",output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/threat_model_reconciliation.py --run-id {run_id}",
        derive_inputs=lambda:current_inputs(run_id),fingerprint_inputs=lambda value:"sha256:"+digest(value),
        execute_attempt=execute,preflight_failure_inputs=lambda exc:{"run_id":run_id,"job":JOB,
            "preflight_error":f"{type(exc).__name__}: {exc}","code":_code_hashes()},force=force,
        post_validate=lambda attempt,_envelope,inputs:_validate_attempt(attempt,inputs),
        blocked_summary="Threat-model reconciliation inputs were unavailable or stale.",
        failed_summary="Threat-model reconciliation did not publish.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    inputs=current_inputs(run_id); attempt,_=validate_published(root(run_id),pointer or read_json(root(run_id)/"accepted.json"),
        "sha256:"+digest(inputs),expected_run_id=run_id,expected_job_id=JOB)
    _validate_attempt(attempt,inputs); return attempt


if __name__ == "__main__":
    import argparse
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--run-id",required=True)
    parser.add_argument("--dagster-run-id",default="standalone-threat-model-reconciliation"); parser.add_argument("--force",action="store_true")
    args=parser.parse_args(); print(json.dumps(run(args.run_id,args.dagster_run_id,args.force),indent=2))
