#!/usr/bin/env python3
"""Automatic, run-owned lifecycle inputs for separate standards processes."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

import bounded_analysis_workers as workers
import component_characterization as cc
import deployment_hardening
from execution_state import Blocked, atomic_json, beneath, data_path, digest, file_hash, identifier, now, read_json, run_path
import model_version_registry as mvr
import owasp_applicability
import owasp_component_routing
import owasp_dispatch
import owasp_validation_worklist
from publish_job_output import mark_attempt_started, publish_validated, validate_published
import persona_invocation
import review_cli
import stig_srg_validation_worklist

COMPONENT = ("01-component-characterization", "component-map", "component-purpose-map.json",
             "component-purpose-map.schema.json")
STANDARDS = ("02-standards-source-ingest", "standards-source-extract", "standards-source.json",
             "standards-source-extract.schema.json")
IAC = ("02-iac-config-scan", "iac-config-evidence", "outputs/iac-config-evidence.json",
       "iac-config-evidence.schema.json")
ROUTING = (owasp_component_routing.JOB, owasp_component_routing.CONTRACT, owasp_component_routing.REQUEST,
           "owasp-applicability-request.schema.json")


def _base(run_id: str, job: str) -> Path:
    direct = data_path(run_id, "jobs", job)
    for value in (direct, direct / "whole"):
        if (value / "accepted.json").is_file():
            return value
    return direct


def _load(run_id: str, spec: tuple[str, str, str, str]):
    job, contract, artifact, schema = spec
    return workers.load_accepted(_base(run_id, job) / "accepted.json", run_id=run_id,
        job_id=job, contract=contract, artifact=artifact, schema=schema)


def _generation(run_id: str) -> str:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if path.is_symlink() or not path.is_file():
        raise Blocked("standards lifecycle: artifact manifest is unavailable")
    return "sha256:" + file_hash(path)


def _attempt_id(job: str, generation: str, payload: Any) -> str:
    return "auto-" + digest({"job": job, "generation": generation, "payload": payload})[:24]


def _record_documents(run_id: str, standards: dict[str, Any]) -> list[tuple[dict, dict]]:
    base = _base(run_id, STANDARDS[0])
    pointer = read_json(base / "accepted.json")
    attempt = base / "attempts" / pointer["attempt_id"]
    rows = []
    for record in standards["records"]:
        try:
            path = beneath(attempt, attempt.joinpath(*PurePosixPath(record["path"]).parts))
        except ValueError as exc:
            raise Blocked("standards lifecycle: standards record path escapes its attempt") from exc
        if path.is_symlink() or not path.is_file() or "sha256:" + file_hash(path) != record["sha256"]:
            raise Blocked("standards lifecycle: referenced standards record changed")
        wrapper = read_json(path)
        if wrapper.get("record_id") != record["record_id"] or wrapper.get("family") != record["family"]:
            raise Blocked("standards lifecycle: standards index and record identity differ")
        rows.append((record, wrapper))
    return rows


def _component_targets(component: dict[str, Any], lane: str) -> list[dict[str, Any]]:
    """Only components the accepted map routes to ``lane``; an unrouted component is not assessed by fallback."""
    return [row for row in component["functional_components"] if lane in row["downstream_lanes"]]


def _owasp_routing(run_id: str, component_binding: dict[str, Any]) -> dict[str, Any]:
    """P39: the accepted T04 routing request (components and rules), bound to this exact component map."""
    routed, _binding = _load(run_id, ROUTING)
    bound = routed.get("component_map") or {}
    if (bound.get("attempt_id") != component_binding["attempt_id"] or
            "sha256:" + str(bound.get("artifact_sha256")) != component_binding["artifact_sha256"]):
        raise Blocked("standards lifecycle: accepted OWASP routing is bound to a different component map")
    return routed


def _routed_rule(routed: dict[str, Any], component_id: str, wrapper: dict[str, Any]) -> dict[str, Any] | None:
    """T04's precedence: the unique most specific matching rule decides; none or a tie stays undecided."""
    control = {"standard_family": wrapper["family"], "control_id": wrapper["record_id"],
               "group": wrapper["record"].get("group", {})}
    ranked = [(owasp_applicability._rule_priority(rule, control), rule) for rule in routed["rules"]
              if rule["component_id"] == component_id]
    top = max((priority for priority, _ in ranked), default=0)
    winners = [rule for priority, rule in ranked if top and priority == top]
    return winners[0] if len(winners) == 1 else None


def _component_path(component: dict[str, Any], path: Any) -> bool:
    """A hit path lies in a component by its path_patterns (repo-root anchored globs) or representative locations."""
    if not isinstance(path, str) or not path:
        return False
    return (any(cc._matches(path, pattern) for pattern in component.get("path_patterns", [])) or
            path in {cc._location_path(value) for value in component.get("representative_locations", [])})


def prepare_worklist(run_id: str, job_id: str) -> dict[str, Any]:
    """Derive a closed worker input from current accepted component and standards evidence."""
    run_id = identifier(run_id)
    if job_id not in {owasp_validation_worklist.JOB, stig_srg_validation_worklist.JOB}:
        raise Blocked("standards lifecycle: unsupported worklist job")
    component, component_binding = _load(run_id, COMPONENT)
    standards, standards_binding = _load(run_id, STANDARDS)
    family = "owasp" if job_id == owasp_validation_worklist.JOB else "stig_srg"
    lane = "04-asvs-masvs" if family == "owasp" else "15-deployment-hardening"
    upstream = [COMPONENT, STANDARDS]
    if family == "owasp":
        # P39: OWASP targets and applicability come from the accepted T04 routing; STIG/SRG has no
        # routing equivalent and keeps the component map's downstream_lanes.
        routed = _owasp_routing(run_id, component_binding)
        targets = [row for row in routed["components"] if row["scope_status"] == "in_scope"]
        upstream.append(ROUTING)
    else:
        routed, targets = None, _component_targets(component, lane)
    controls = []
    for index, wrapper in _record_documents(run_id, standards):
        record = wrapper["record"]
        if family == "owasp" and wrapper["family"] not in {"owasp_asvs", "owasp_masvs"}:
            continue
        if family == "stig_srg" and not (wrapper["family"].startswith("stig") or
                                           wrapper["family"].startswith("disa")):
            continue
        if wrapper["record_type"] != "control":
            continue
        for target in targets:
            modes = sorted({mode for obligation in record.get("proof_obligations", [])
                            for mode in obligation.get("minimum_evidence_modes", [])})
            needs_runtime = "dynamic_runtime" in modes
            citation = "std-" + digest({"record": index, "component": target["component_id"]})[:20]
            rule = _routed_rule(routed, target["component_id"], wrapper) if routed else None
            status = rule["decision"]["status"] if rule else "cannot_determine"
            row = {"control_id": wrapper["record_id"],
                "standard_family": "OWASP" if family == "owasp" else "DISA_STIG_SRG",
                "standard_version": wrapper["edition"], "target_id": target["component_id"],
                "applicability": status,
                "tailoring": "Target-derived component; applicability awaits control-specific assessment.",
                "evidence_mode": "hybrid" if needs_runtime else "manual",
                "citation_ids": [citation] + ([rule["rule_id"]] if rule else []),
                "gaps": ["runtime evidence unavailable"] if needs_runtime else []}
            if status == "not_applicable":
                # Accounted, not assessed: the routing rule is the citation and nothing remains to examine.
                row.update(tailoring=f"Routed not applicable by {rule['rule_id']}: {rule['decision']['rationale']}",
                           evidence_mode="static", gaps=[])
            elif rule:
                condition = rule["decision"]["conditional_expression"]
                row["tailoring"] = (f"Routed {status} by {rule['rule_id']}" + (f" if {condition}" if condition else "") +
                                    "; control-specific assessment pending.")
            elif routed:
                row["tailoring"] = "No unique OWASP routing rule decides this target; applicability awaits reviewer resolution."
            controls.append(row)
    # P26: every row is NOT_ASSESSED; one summary gap carries the count instead of one gap per row.
    # An N/A-routed row is accounted with its rule citation and needs no assessment.
    pending = sum(row["applicability"] != "not_applicable" for row in controls)
    undecided = sum(row["applicability"] == "cannot_determine" for row in controls) if routed else 0
    if not targets:
        source = "the accepted OWASP routing" if routed else lane
        gaps = [f"No functional component is routed to {source}; the {family} worklist is empty."]
    else:
        gaps = [f"Control-specific assessment has not been performed for {pending} control x component work items."] if pending else []
        if undecided:
            gaps.append(f"The accepted OWASP routing decides no applicability for {undecided} control x component work items; reviewer resolution is required.")
    generation = _generation(run_id)
    payload = {"controls": controls, "gaps": gaps}
    request = {"schema": "appsec-review/bounded-transform-request/1.0", "run_id": run_id,
        "job_id": job_id, "source_generation": generation,
        "upstream": [{"pointer_path": str(_base(run_id, spec[0]) / "accepted.json"), "job_id": spec[0],
                      "contract": spec[1], "artifact": spec[2], "schema": spec[3]} for spec in upstream],
        "payload": payload}
    path = data_path(run_id, "jobs", job_id, "inputs", _attempt_id(job_id, generation, payload) + ".json")
    if path.exists() and read_json(path) != request:
        raise Blocked("standards lifecycle: immutable derived request changed")
    if not path.exists(): atomic_json(path, request)
    return {"request_path": path, "attempt_id": _attempt_id(job_id, generation, payload),
            "control_count": len(controls), "target_count": len(targets), "generation": generation}


def _publish_bounded(run_id: str, job_id: str, attempt_id: str) -> dict[str, Any]:
    base = _base(run_id, job_id)
    attempt = base / "attempts" / attempt_id
    envelope = read_json(attempt / "result.json")
    mark_attempt_started(base, attempt_id, envelope["input_fingerprint"])
    return publish_validated(base, attempt, attempt / "result.json", envelope["input_fingerprint"],
                             expected_run_id=run_id, expected_job_id=job_id)


def _reusable(base: Path, run_id: str, job_id: str, attempt_id: str) -> dict[str, Any] | None:
    path = base / "accepted.json"
    if not path.is_file(): return None
    pointer = read_json(path)
    if pointer.get("attempt_id") != attempt_id: return None
    validate_published(base, pointer, pointer.get("fingerprint"), expected_run_id=run_id,
                       expected_job_id=job_id, reuse=True)
    return pointer


def _route_owasp(run_id: str, dagster_run_id: str) -> None:
    """P39: produce, or reuse on unchanged inputs, the T03 lane-in and routing the OWASP worklist reads.

    The join's T03-T06 chain runs the same deterministic workers later and reuses these publications;
    ``force`` stays with the worklist itself.
    """
    import owasp_lane_in
    import owasp_workbench_lifecycle as workbench
    owasp_lane_in.admit(run_id, workbench._write_request(run_id, "owasp-lane-in-request.json",
                                                         workbench.lane_in_request(run_id)))
    owasp_component_routing.run(run_id, dagster_run_id)


def run_worklist(run_id: str, dagster_run_id: str, job_id: str, force: bool = False) -> dict[str, Any]:
    import bounded_transform_orchestration as orchestration
    if job_id == owasp_validation_worklist.JOB:
        _route_owasp(run_id, dagster_run_id)
    prepared = prepare_worklist(run_id, job_id)
    # No routed component publishes an empty worklist with its reason; routed components without
    # accepted controls are a failure to examine.
    if prepared["target_count"] and prepared["control_count"] == 0:
        raise Blocked("standards lifecycle: no accepted controls exist for the requested standards family")
    base = data_path(run_id, "jobs", job_id)
    if not force and (pointer := _reusable(base, run_id, job_id, prepared["attempt_id"])):
        return pointer
    orchestration.execute(job_id=job_id, run_id=run_id, input_path=str(prepared["request_path"]),
                          output_root=str(base), attempt_id=prepared["attempt_id"])
    return _publish_bounded(run_id, job_id, prepared["attempt_id"])


def prepare_owasp_join(run_id: str) -> owasp_dispatch.DispatchFacts:
    """Derive qualified join facts; never creates the approval-bearing OWASP selection."""
    component, _ = _load(run_id, COMPONENT)
    _load(run_id, STANDARDS)
    snapshot = component["source_snapshot_sha256"]
    mvr.resolve_run_model_versions(run_id)
    resolved = review_cli.resolve_model("04-owasp-validator-cell", "standard")
    model = mvr.model_identity_for(run_id, resolved["model"])
    return owasp_dispatch.DispatchFacts(registry_dir=persona_invocation.REGISTRY_DIR,
        allowed_models=(model,), invoker_id="claude-cli", source_snapshot_sha256=snapshot,
        registry_ceiling=None)


def run_owasp_join(run_id: str, dagster_run_id: str, force: bool = False) -> dict[str, Any]:
    """Publish T14 only after the existing accepted T03--T10 chain verifies."""
    import owasp_join_publisher
    facts = prepare_owasp_join(run_id)
    return owasp_join_publisher.run(run_id, dagster_run_id, facts, force)


def prepare_deployment(run_id: str) -> dict[str, Any]:
    """Derive deployment assessments only from accepted IaC hits and STIG work items."""
    run_id = identifier(run_id)
    component, component_binding = _load(run_id, COMPONENT)
    stig, stig_binding = _load(run_id, (stig_srg_validation_worklist.JOB,
        "stig-srg-validation-worklist", stig_srg_validation_worklist.RESULT,
        "stig-srg-validation-worklist.schema.json"))
    # ADR-0014: an evidence-supported IaC skip (doom3-bfg: no IaC inputs) leaves nothing to assess;
    # record it as a gap instead of refusing the skipped pointer.
    iac_pointer_path = _base(run_id, IAC[0]) / "accepted.json"
    iac_pointer = read_json(iac_pointer_path) if iac_pointer_path.is_file() else {}
    if iac_pointer.get("status") == "SKIPPED":
        hits, iac_binding = [], None
        iac_gap = f"IaC config scan was skipped ({iac_pointer.get('reason') or 'no reason recorded'}); no declared deployment state was assessed."
    else:
        iac, iac_binding = _load(run_id, IAC)
        hits, iac_gap = iac["rule_hits"], None
    components = {row["component_id"]: row for row in component["functional_components"]}
    targets = []
    for work in stig["work_items"]:
        # P28: hits carry only location.path; match it against the work item's component paths.
        owner = components.get(work["target_id"], {})
        matching = [hit for hit in hits if _component_path(owner, (hit.get("location") or {}).get("path"))]
        if not matching:
            continue
        targets.append({"target_id": work["target_id"], "platform": "declared-iac",
            "control_id": work["control_id"], "standard_family": work["standard_family"],
            "standard_version": work["standard_version"], "applicability": work["applicability"],
            "tailoring": work["tailoring"], "static_state": "present",
            "citation_ids": list(work["citation_ids"]),
            "runtime_gaps": ["runtime deployment state was not observed"]})
    generation = _generation(run_id)
    bindings = [b for b in (component_binding, iac_binding, stig_binding) if b is not None]
    attempt_id = _attempt_id(deployment_hardening.JOB, generation, targets)
    result = deployment_hardening.analyze(run_id=run_id, attempt_id=attempt_id,
        source_generation=generation, bindings=bindings, targets=targets)
    if not targets:
        result["gaps"] = [iac_gap or "Accepted IaC and STIG/SRG evidence produced no matching deployment assessment target."]
    return {"result": result, "attempt_id": attempt_id, "generation": generation}


def run_deployment(run_id: str, dagster_run_id: str, force: bool = False) -> dict[str, Any]:
    prepared = prepare_deployment(run_id); base = data_path(run_id, "jobs", deployment_hardening.JOB)
    if not force and (pointer := _reusable(base, run_id, deployment_hardening.JOB,
                                           prepared["attempt_id"])):
        return pointer
    started = now()
    workers.publish_attempt(base, prepared["result"], started_at=started, finished_at=now())
    return _publish_bounded(run_id, deployment_hardening.JOB, prepared["attempt_id"])


def run(run_id: str, dagster_run_id: str, job_id: str, force: bool = False) -> dict[str, Any]:
    """Zero-config full-review entry point while keeping all three processes separate."""
    if job_id in {owasp_validation_worklist.JOB, stig_srg_validation_worklist.JOB}:
        return run_worklist(run_id, dagster_run_id, job_id, force)
    if job_id == "04-asvs-masvs":
        return run_owasp_join(run_id, dagster_run_id, force)
    if job_id == deployment_hardening.JOB:
        return run_deployment(run_id, dagster_run_id, force)
    raise Blocked("standards lifecycle: unsupported lifecycle job")


def prepare(run_id: str, job_id: str) -> Any:
    if job_id in {owasp_validation_worklist.JOB, stig_srg_validation_worklist.JOB}:
        return prepare_worklist(run_id, job_id)
    if job_id == "04-asvs-masvs": return prepare_owasp_join(run_id)
    if job_id == deployment_hardening.JOB: return prepare_deployment(run_id)
    raise Blocked("standards lifecycle: unsupported lifecycle job")
