#!/usr/bin/env python3
"""Automatic full-review producer for the OWASP workbench chain T03 -> routing -> T04 -> T05 -> T06
-> T10, so that the ``04-asvs-masvs`` join (T11-T14) finds an accepted
``04-owasp-validator-dispatch`` accounting (ADR-0013: run to report first).

Every step is the existing standalone worker, called with a request this module derives from
accepted run evidence exactly the way ``tests/test_owasp_chain_qualification.py`` does:

* T03 ``owasp_lane_in.admit``: the accepted component map (locator-only derived intelligence) and
  the standards selection. The selection is ``inputs/owasp-standard-selection.json`` when the run
  has one (an engagement-lead approved selection); otherwise the ADR-0009 decided baseline (ASVS
  5.0.0 Level 2, conservative ``server`` scope) recorded with approver ``adr-0009-baseline``.
* routing ``owasp_component_routing.run`` and T04 ``owasp_applicability.build``.
* T05 ``owasp_batching.build`` with the tracked default batch config and one static-offline route.
* T06 ``owasp_validator_handoff.build`` with the tracked default handoff config, ``standard`` budget.
* T10 ``owasp_dispatch.dispatch`` under the SAME ``DispatchFacts`` the join derives
  (``standards_lifecycle.prepare_owasp_join``) and the live ``ClaudeCliInvoker``.

An empty handoff set is not a failure: T10 publishes an accepted ``EMPTY`` accounting
(``upstream_produced_no_work``) that the join consumes. Every worker keeps its own reuse rule, so a
re-run with unchanged inputs reuses each accepted publication and dispatches nothing again.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Callable

from execution_state import Blocked, atomic_json, data_path, digest, file_hash, identifier, read_json, run_path
import owasp_applicability
import owasp_batching
import owasp_component_routing as routing
import owasp_dispatch
import owasp_lane_in
import owasp_validator_handoff
import pool_rendezvous

PROCESS_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROCESS_ROOT.parent
COMPONENT_JOB = routing.COMPONENT_JOB
SELECTION_INPUT = "owasp-standard-selection.json"
BASELINE_APPROVER = "adr-0009-baseline"
BASELINE_APPROVED_AT = "2026-09-20T00:00:00Z"
BASELINE_SCOPE = ["server"]
BUDGET = "standard"
BATCH_CONFIG = "appsec-review-process/config/owasp-batching/default-v1.json"
HANDOFF_CONFIG = "appsec-review-process/config/owasp-validator-handoff/default-v1.json"
DISPATCH_CONFIG = "appsec-review-process/config/owasp-dispatch/default-v1.json"
STATIC_ROUTE = {
    "route_id": "static-offline-all",
    "selector": {"standard_family": "owasp_asvs", "obligation_ids": [], "control_ids": [], "domain_ids": [],
                 "all_controls": True, "component_ids": [], "all_components": True},
    "primary_evidence_mode": "static_source", "authorization_boundary": "static_offline",
    "tooling_profile_id": "read-only-source", "validator_role": "owasp-validator", "linked_test_ids": [],
}


def _utc(value: str) -> str:
    """An ISO instant as ``YYYY-MM-DDTHH:MM:SSZ`` (deterministic, so request fingerprints are stable)."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _config_reference(relative: str) -> dict[str, str]:
    return {"path": relative, "config_digest": digest(read_json(REPO_ROOT / relative))}


def _write_request(run_id: str, name: str, request: dict[str, Any]) -> Path:
    path = run_path(run_id) / "inputs" / name
    if not path.exists() or read_json(path) != request:
        atomic_json(path, request)
    return path


def _asvs_snapshot(reference_root: Path) -> tuple[str, str]:
    edition = reference_root / "owasp" / "owasp_asvs" / "5.0.0"
    snapshots = sorted(path for path in edition.iterdir() if path.is_dir()) if edition.is_dir() else []
    if len(snapshots) != 1:
        raise Blocked("OWASP workbench: exactly one pinned ASVS 5.0.0 reference snapshot is required")
    return snapshots[0].name, file_hash(snapshots[0] / "manifest.json")


def selection(run_id: str, *, reference_root: Path | None = None) -> dict[str, Any]:
    """The run's approved selection, or the ADR-0009 decided baseline."""
    supplied = run_path(run_id) / "inputs" / SELECTION_INPUT
    if supplied.is_file() and not supplied.is_symlink():
        return read_json(supplied)
    snapshot_id, manifest_sha256 = _asvs_snapshot(Path(reference_root or owasp_lane_in.DEFAULT_REFERENCE_ROOT))
    return {"schema": "appsec-review/standard-selection/1.0", "selection_id": "adr-0009-asvs-5-0-0-l2",
            "engagement_id": run_id,
            "selections": [{"family": "owasp_asvs", "snapshot_id": snapshot_id, "manifest_sha256": manifest_sha256,
                            "edition": "5.0.0", "enabled_scope": list(BASELINE_SCOPE), "profile_or_level": "L2",
                            "tailoring": []}],
            "approver": BASELINE_APPROVER, "approved_at": BASELINE_APPROVED_AT}


def _component(run_id: str) -> tuple[dict[str, Any], dict[str, Any], Path]:
    component_map, binding = routing._accepted_component(run_id)
    pointer = read_json(data_path(run_id, "jobs", COMPONENT_JOB, "accepted.json"))
    return component_map, {**binding, "accepted_at": pointer.get("accepted_at")}, data_path(run_id, *binding["artifact_path"].split("/"))


def lane_in_request(run_id: str, *, reference_root: Path | None = None) -> dict[str, Any]:
    component_map, binding, path = _component(run_id)
    instant = _utc(binding["accepted_at"]) if binding.get("accepted_at") else BASELINE_APPROVED_AT
    artifact = {"path": binding["artifact_path"], "sha256": binding["artifact_sha256"]}
    return {
        "schema": owasp_lane_in.REQUEST_SCHEMA, "run_id": run_id,
        "selection": selection(run_id, reference_root=reference_root),
        "permissions": {"static_inspection": True, "dynamic_execution": False, "manual_observation": False,
                        "network_access": False, "target_mutation": False},
        "entries": [{
            "input_id": "component-map", "evidence_class": "derived_intelligence", "kind": "component_map",
            "admission": "accepted_run_output", "artifact": artifact,
            "producer": {"job_id": COMPONENT_JOB, "attempt_id": binding["attempt_id"],
                         "accepted_pointer_path": binding["accepted_pointer_path"],
                         "accepted_pointer_sha256": binding["accepted_pointer_sha256"]},
            "source_artifacts": [artifact],
            "source_snapshot": {"snapshot_id": component_map["source_snapshot_sha256"], "captured_at": instant},
            "derivation_status": "complete",
            "freshness": {"assessed_at": instant, "status": "current"},
            "redaction_status": "not_required",
            "caveats": ["Classification is routing context, not proof."],
            "use": "locator_only", "component_scope": None,
        }],
        "nvd": {"requested": False, "snapshot_id": None, "manifest_sha256": None, "advisory_freshness_seconds": 86400},
        "completeness_gaps": [{
            "gap_id": "no-canonical-component-evidence", "kind": "coverage",
            "summary": "Only the accepted component map was admitted automatically; no canonical source evidence is bound to a component.",
            "affected_scope": ["owasp_asvs"]}],
    }


def _whole_pointer(run_id: str, job_id: str) -> Path:
    return data_path(run_id, "jobs", job_id, "whole", "accepted.json")


def batch_request(run_id: str, t04: dict[str, Any], applicability_request: Path) -> dict[str, Any]:
    component_map, _, _ = _component(run_id)
    source = {row["component_id"]: row for row in component_map["functional_components"]}
    projected = read_json(applicability_request)["components"]
    model_path = data_path(run_id, "jobs", owasp_applicability.JOB_ID, "whole", "attempts", t04["attempt_id"],
                           "outputs", "owasp-applicability-model.json")
    contexts = [{
        "component_id": row["component_id"],
        "component_group_id": source[row["component_id"]]["parallel_review_group"],
        "trust_role": source[row["component_id"]]["component_type"],
        "evidence_root_input_ids": row.get("evidence_input_ids", row["input_ids"]),
    } for row in sorted(projected, key=lambda value: value["component_id"])]
    return {
        "schema": "appsec-review/owasp-batch-request/1.0", "run_id": run_id,
        "applicability": {"attempt_id": t04["attempt_id"],
                          "accepted_pointer_path": f"jobs/{owasp_applicability.JOB_ID}/whole/accepted.json",
                          "accepted_pointer_sha256": file_hash(_whole_pointer(run_id, owasp_applicability.JOB_ID)),
                          "model_path": model_path.relative_to(data_path(run_id)).as_posix(),
                          "model_sha256": file_hash(model_path)},
        "batch_config": _config_reference(BATCH_CONFIG),
        "component_contexts": contexts, "routing_rules": [dict(STATIC_ROUTE)],
    }


def handoff_request(run_id: str, t05: dict[str, Any]) -> dict[str, Any]:
    attempt = data_path(run_id, "jobs", owasp_batching.JOB_ID, "whole", "attempts", t05["attempt_id"])
    batching = {"attempt_id": t05["attempt_id"],
                "accepted_pointer_path": f"jobs/{owasp_batching.JOB_ID}/whole/accepted.json",
                "accepted_pointer_sha256": file_hash(_whole_pointer(run_id, owasp_batching.JOB_ID))}
    for key, name in (("worklist", "owasp-validation-worklist.json"), ("batch_manifest", "owasp-batch-manifest.json"),
                      ("summary", "batch-summary.md")):
        path = attempt / "outputs" / name
        batching[key + "_path"] = path.relative_to(data_path(run_id)).as_posix()
        batching[key + "_sha256"] = file_hash(path)
    return {"schema": "appsec-review/owasp-validator-handoff-request/1.0", "run_id": run_id, "batching": batching,
            "handoff_config": _config_reference(HANDOFF_CONFIG), "budget": BUDGET, "operation": "build",
            "batch_id": None}


def dispatch_request(run_id: str, t06: dict[str, Any], model: dict[str, Any]) -> dict[str, Any]:
    root = data_path(run_id, "jobs", owasp_validator_handoff.JOB_ID, "whole")
    handoff_set = root / "attempts" / t06["attempt_id"] / "outputs" / "owasp-validator-handoff-set.json"
    return {"schema": owasp_dispatch.REQUEST_ID, "run_id": run_id,
            "handoffs": {"attempt_id": t06["attempt_id"],
                         "accepted_pointer_path": f"jobs/{owasp_validator_handoff.JOB_ID}/whole/accepted.json",
                         "accepted_pointer_sha256": file_hash(root / "accepted.json"),
                         "handoff_set_path": handoff_set.relative_to(data_path(run_id)).as_posix(),
                         "handoff_set_sha256": file_hash(handoff_set)},
            "dispatch_config": _config_reference(DISPATCH_CONFIG), "model": dict(model)}


def prepare_handoffs(run_id: str, dagster_run_id: str, force: bool = False, *,
                     reference_root: Path | None = None) -> dict[str, Any]:
    """T03 -> routing -> T04 -> T05 -> T06, deterministic and model-free. Returns each pointer."""
    run_id = identifier(run_id)
    t03 = owasp_lane_in.admit(run_id, _write_request(run_id, "owasp-lane-in-request.json",
                                                     lane_in_request(run_id, reference_root=reference_root)),
                              reference_root=reference_root, force=force)
    routed = routing.run(run_id, dagster_run_id, reference_root=reference_root, force=force)
    applicability_request = routing.request_path(run_id, routed)
    t04 = owasp_applicability.build(run_id, applicability_request, reference_root=reference_root, force=force)
    t05 = owasp_batching.build(run_id, _write_request(run_id, "owasp-batch-request.json",
                                                      batch_request(run_id, t04, applicability_request)),
                               reference_root=reference_root, force=force)
    t06 = owasp_validator_handoff.build(run_id, _write_request(run_id, "owasp-validator-handoff-request.json",
                                                               handoff_request(run_id, t05)),
                                        reference_root=reference_root, force=force)
    return {"lane_in": t03, "routing": routed, "applicability": t04, "batching": t05, "handoffs": t06}


def live_invoker(budget: str = BUDGET):
    """The live B14 invoker every other model pool uses: the strict Claude CLI invoker."""
    import review_cli
    from claude_cli_invoker import ClaudeCliInvoker
    template_id = read_json(REPO_ROOT / DISPATCH_CONFIG)["job_template_id"]
    resolved = review_cli.resolve_model(template_id, budget)
    budget_usd = (review_cli.load_model_config().get("budget_max_usd_per_call") or {}).get(budget)
    return ClaudeCliInvoker(effort=resolved["effort"], budget_usd=budget_usd)


def run_dispatch(run_id: str, dagster_run_id: str, force: bool = False, *,
                 facts: owasp_dispatch.DispatchFacts | None = None, invoker: Any = None,
                 clock: Callable[[], str] = _now, max_parallel: int = 1,
                 wait_limit_seconds: float = 4 * 3600) -> dict[str, Any]:
    """T10 over the newest accepted T06 publication, under the join's own facts."""
    import standards_lifecycle
    run_id = identifier(run_id)
    t06_pointer = read_json(_whole_pointer(run_id, owasp_validator_handoff.JOB_ID))
    if t06_pointer.get("status") not in owasp_dispatch.SUCCESS:
        raise Blocked("OWASP workbench: the T06 handoff publication is not accepted")
    facts = facts or standards_lifecycle.prepare_owasp_join(run_id)
    request = dispatch_request(run_id, t06_pointer, facts.allowed_models[0])
    runtime = owasp_dispatch.DispatchRuntime(
        facts=facts, invoker=invoker or live_invoker(), clock=clock, cancel=pool_rendezvous.PoolCancel(),
        stop_grace_seconds=5, max_parallel=max_parallel, wait_limit_seconds=wait_limit_seconds, drain_seconds=10)
    return owasp_dispatch.dispatch(run_id, _write_request(run_id, "owasp-dispatch-request.json", request),
                                   runtime=runtime, force=force)


def run(run_id: str, dagster_run_id: str, force: bool = False, **dispatch_options: Any) -> dict[str, Any]:
    prepare_handoffs(run_id, dagster_run_id, force)
    return run_dispatch(run_id, dagster_run_id, force, **dispatch_options)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--prepare-only", action="store_true", help="T03-T06 only; no model call")
    args = parser.parse_args(argv)
    if args.prepare_only:
        result = prepare_handoffs(args.run_id, "standalone-owasp-workbench", args.force)
        print(json.dumps({key: value.get("status") for key, value in result.items()}, sort_keys=True))
    else:
        result = run(args.run_id, "standalone-owasp-workbench", args.force)
        print(json.dumps({key: result.get(key) for key in ("attempt_id", "status", "reused")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
