#!/usr/bin/env python3
"""Automatic full-review producer for the OWASP workbench chain T03 -> routing -> T04 -> T05 -> T06
-> T10, so that the ``04-asvs-masvs`` join (T11-T14) finds an accepted
``04-owasp-validator-dispatch`` accounting (ADR-0013: run to report first).

ADR-0034: the work is the accepted ``04-owasp-universe`` (deterministic Python), never a model's
component list. Every step is the existing standalone worker, called with a request this module
derives from accepted run evidence:

* T03 ``owasp_lane_in.admit``: the accepted universe (``asvs-universe``, locator-only derived
  intelligence), each participating chapter's ``asvs-participants-V<n>`` bundle (canonical source
  evidence), the accepted component map when one exists (report context only) and the standards
  selection. The selection is ``inputs/owasp-standard-selection.json`` when the run has one (an
  engagement-lead approved selection); otherwise the ADR-0009 decided baseline (ASVS 5.0.0 Level 2,
  conservative ``server`` scope) recorded with approver ``adr-0009-baseline``.
* routing ``owasp_component_routing.run`` (the universe projected as one ``asvs-V<n>`` component
  per chapter) and T04 ``owasp_applicability.build``.
* T05 ``owasp_batching.build`` with batch config v2 (40 rows, one component per batch) and one
  static-offline route, so T05's batch count is the universe's planned validator calls.
* T06 ``owasp_validator_handoff.build`` with the tracked default handoff config, ``standard`` budget.
* T10 ``owasp_dispatch.dispatch`` under the SAME ``DispatchFacts`` the join derives
  (``standards_lifecycle.prepare_owasp_join``) and the live ``ClaudeCliInvoker``; it refuses
  without an accepted, within-budget universe whose plan equals the handoff count.

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
import owasp_universe
import owasp_validator_handoff
import pool_rendezvous
import tunables

PROCESS_ROOT = Path(__file__).resolve().parent
REPO_ROOT = PROCESS_ROOT.parent
COMPONENT_JOB = routing.COMPONENT_JOB
SELECTION_INPUT = "owasp-standard-selection.json"
BASELINE_APPROVER = "adr-0009-baseline"
BASELINE_APPROVED_AT = "2026-09-20T00:00:00Z"
BASELINE_SCOPE = ["server"]
BUDGET = "standard"
BATCH_CONFIG = "appsec-review-process/config/owasp-batching/default-v2.json"
HANDOFF_CONFIG = "appsec-review-process/config/owasp-validator-handoff/default-v2.json"
DISPATCH_CONFIG = "appsec-review-process/config/owasp-dispatch/default-v1.json"
# One static-offline route for every obligation of every chapter target: with batch config v2 each
# chapter is its own batch key, so T05 cuts exactly ceil(chapter rows / 40) batches per chapter.
STATIC_ROUTE = {
    "route_id": "static-offline-asvs-chapter",
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


def _component_entry(run_id: str) -> dict[str, Any] | None:
    """The accepted component map as report context (locator-only), or None when there is none."""
    if not data_path(run_id, "jobs", COMPONENT_JOB, "accepted.json").is_file():
        return None
    component_map, binding = routing._accepted_component(run_id)
    pointer = read_json(data_path(run_id, "jobs", COMPONENT_JOB, "accepted.json"))
    instant = _utc(pointer["accepted_at"]) if pointer.get("accepted_at") else BASELINE_APPROVED_AT
    artifact = {"path": binding["artifact_path"], "sha256": binding["artifact_sha256"]}
    return {
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
        "caveats": ["Report context only; the component map does not route OWASP work (ADR-0034)."],
        "use": "locator_only", "component_scope": None,
    }


def _universe_entries(run_id: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """``asvs-universe`` and every ``asvs-participants-V<n>`` bundle of the accepted universe, plus its gaps."""
    universe, binding = owasp_universe.accepted(run_id)
    pointer = read_json(data_path(run_id, *binding["accepted_pointer_path"].split("/")))
    instant = _utc(pointer["accepted_at"]) if pointer.get("accepted_at") else BASELINE_APPROVED_AT
    producer = {"job_id": owasp_universe.JOB, "attempt_id": binding["attempt_id"],
                "accepted_pointer_path": binding["accepted_pointer_path"],
                "accepted_pointer_sha256": binding["accepted_pointer_sha256"]}
    snapshot = {"snapshot_id": binding["source_snapshot_sha256"], "captured_at": instant}
    artifact = {"path": binding["artifact_path"], "sha256": binding["artifact_sha256"]}
    entries = [{
        "input_id": owasp_universe.UNIVERSE_INPUT, "evidence_class": "derived_intelligence",
        "kind": owasp_universe.UNIVERSE_KIND, "admission": "accepted_run_output", "artifact": artifact,
        "producer": producer, "source_artifacts": [artifact], "source_snapshot": snapshot,
        "derivation_status": "partial" if universe["gaps"] else "complete",
        "freshness": {"assessed_at": instant, "status": "current"}, "redaction_status": "not_required",
        "caveats": ["The deterministic validation universe is routing context; the participants bundles are the evidence."],
        "use": "locator_only", "component_scope": None,
    }]
    attempt = binding["artifact_path"].rsplit("/outputs/", 1)[0]
    for target in universe["targets"]:
        bundle = target["evidence_bundle"]
        if bundle is None:
            continue
        entries.append({
            "input_id": bundle["input_id"], "evidence_class": "raw_evidence",
            "kind": owasp_universe.BUNDLE_KIND, "admission": "accepted_run_output",
            "artifact": {"path": f"{attempt}/{bundle['path']}", "sha256": bundle["sha256"]},
            "producer": producer, "source_artifacts": [], "source_snapshot": snapshot, "derivation_status": None,
            "freshness": {"assessed_at": instant, "status": "current"}, "redaction_status": "not_required",
            "caveats": [], "use": "canonical_evidence", "component_scope": None,
        })
    gaps = [{"gap_id": gap["gap_id"], "kind": gap["kind"], "summary": gap["statement"],
             "affected_scope": [f"asvs-{chapter}" for chapter in gap["chapter_ids"]]} for gap in universe["gaps"]]
    return entries, gaps


def lane_in_request(run_id: str, *, reference_root: Path | None = None) -> dict[str, Any]:
    entries, gaps = _universe_entries(run_id)
    component = _component_entry(run_id)
    return {
        "schema": owasp_lane_in.REQUEST_SCHEMA, "run_id": run_id,
        "selection": selection(run_id, reference_root=reference_root),
        "permissions": {"static_inspection": True, "dynamic_execution": False, "manual_observation": False,
                        "network_access": False, "target_mutation": False},
        "entries": [*([component] if component else []), *entries],
        "nvd": {"requested": False, "snapshot_id": None, "manifest_sha256": None, "advisory_freshness_seconds": 86400},
        "completeness_gaps": gaps,
    }


def _whole_pointer(run_id: str, job_id: str) -> Path:
    return data_path(run_id, "jobs", job_id, "whole", "accepted.json")


def batch_request(run_id: str, t04: dict[str, Any], applicability_request: Path) -> dict[str, Any]:
    """Batch config v2 over the projected chapter targets: each chapter is its own group (one batch key)."""
    projected = read_json(applicability_request)["components"]
    model_path = data_path(run_id, "jobs", owasp_applicability.JOB_ID, "whole", "attempts", t04["attempt_id"],
                           "outputs", "owasp-applicability-model.json")
    contexts = [{
        "component_id": row["component_id"], "component_group_id": row["component_id"],
        "trust_role": row.get("trust_role") or "asvs-chapter",
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
    """T03 -> routing -> T04 -> T05 -> T06, deterministic and model-free. Returns each pointer.

    Refuses (``Blocked``) without an accepted, within-budget universe, and when T05 cuts a batch count
    other than the universe's planned validator calls."""
    run_id = identifier(run_id)
    _universe, universe_binding = owasp_universe.accepted(run_id)
    t03 = owasp_lane_in.admit(run_id, _write_request(run_id, "owasp-lane-in-request.json",
                                                     lane_in_request(run_id, reference_root=reference_root)),
                              reference_root=reference_root, force=force)
    routed = routing.run(run_id, dagster_run_id, reference_root=reference_root, force=force)
    applicability_request = routing.request_path(run_id, routed)
    t04 = owasp_applicability.build(run_id, applicability_request, reference_root=reference_root, force=force)
    t05 = owasp_batching.build(run_id, _write_request(run_id, "owasp-batch-request.json",
                                                      batch_request(run_id, t04, applicability_request)),
                               reference_root=reference_root, force=force)
    batches = _batch_count(run_id, t05)
    if batches != universe_binding["planned_validator_calls"]:
        raise Blocked(f"OWASP workbench: T05 cut {batches} batch(es) but the universe planned "
                      f"{universe_binding['planned_validator_calls']} validator call(s)")
    t06 = owasp_validator_handoff.build(run_id, _write_request(run_id, "owasp-validator-handoff-request.json",
                                                               handoff_request(run_id, t05)),
                                        reference_root=reference_root, force=force)
    return {"lane_in": t03, "routing": routed, "applicability": t04, "batching": t05, "handoffs": t06}


def _batch_count(run_id: str, t05: dict[str, Any]) -> int:
    path = data_path(run_id, "jobs", owasp_batching.JOB_ID, "whole", "attempts", t05["attempt_id"], "outputs",
                     "owasp-batch-manifest.json")
    if file_hash(path) != t05["artifacts"]["outputs/owasp-batch-manifest.json"]:
        raise Blocked("OWASP workbench: the T05 batch manifest is not hash-bound")
    return read_json(path)["batch_count"]


def dispatch_parallelism(max_parallel: int | None) -> int:
    """Validator cells in flight: the requested ``max_parallel`` capped by ``pool_persona_llm_slots``."""
    slots = int(tunables.shared("pool_persona_llm_slots"))
    value = slots if max_parallel is None else min(int(max_parallel), slots)
    if value < 1:
        raise ValueError("OWASP workbench: validator max_parallel must be at least 1")
    return value


def live_invoker(budget: str = BUDGET):
    """The live B14 invoker every other model pool uses: the strict Claude CLI invoker."""
    import review_cli
    template_id = read_json(REPO_ROOT / DISPATCH_CONFIG)["job_template_id"]
    resolved = review_cli.resolve_model(template_id, budget)
    budget_usd = (review_cli.load_model_config().get("budget_max_usd_per_call") or {}).get(budget)
    # B3: the validator cell replies with reduced citations; Python derives the rest (ADR-0013)
    return owasp_dispatch.CellInvoker(effort=resolved["effort"], budget_usd=budget_usd)


def run_dispatch(run_id: str, dagster_run_id: str, force: bool = False, *,
                 facts: owasp_dispatch.DispatchFacts | None = None, invoker: Any = None,
                 clock: Callable[[], str] = _now, max_parallel: int | None = None,
                 wait_limit_seconds: float = 4 * 3600) -> dict[str, Any]:
    """T10 over the newest accepted T06 publication, under the join's own facts.

    Before any validator call it requires an accepted, within-budget ``04-owasp-universe`` and a T06
    handoff count equal to the universe's planned validator calls (``Blocked`` otherwise).
    ``max_parallel`` (the 04-owasp-validator-cell tunable; None = the pool size) is capped by
    ``pool_persona_llm_slots``."""
    import standards_lifecycle
    run_id = identifier(run_id)
    _universe, universe_binding = owasp_universe.accepted(run_id)
    parallel = dispatch_parallelism(max_parallel)
    t06_path = _whole_pointer(run_id, owasp_validator_handoff.JOB_ID)
    if not t06_path.is_file():
        raise Blocked("OWASP workbench: no accepted T06 handoff publication exists")
    t06_pointer = read_json(t06_path)
    if t06_pointer.get("status") not in owasp_dispatch.SUCCESS:
        raise Blocked("OWASP workbench: the T06 handoff publication is not accepted")
    handoff_set = data_path(run_id, "jobs", owasp_validator_handoff.JOB_ID, "whole", "attempts",
                            t06_pointer["attempt_id"], "outputs", "owasp-validator-handoff-set.json")
    if (not handoff_set.is_file() or
            file_hash(handoff_set) != (t06_pointer.get("artifacts") or {}).get("outputs/owasp-validator-handoff-set.json")):
        raise Blocked("OWASP workbench: the accepted T06 handoff set is missing or not hash-bound")
    handoffs = read_json(handoff_set)["handoff_count"]
    if handoffs != universe_binding["planned_validator_calls"]:
        raise Blocked(f"OWASP workbench: {handoffs} validator handoff(s) differ from the universe's planned "
                      f"{universe_binding['planned_validator_calls']} call(s); no validator call may start")
    facts = facts or standards_lifecycle.prepare_owasp_join(run_id)
    request = dispatch_request(run_id, t06_pointer, facts.allowed_models[0])
    runtime = owasp_dispatch.DispatchRuntime(
        facts=facts, invoker=invoker or live_invoker(), clock=clock, cancel=pool_rendezvous.PoolCancel(),
        stop_grace_seconds=5, max_parallel=parallel, wait_limit_seconds=wait_limit_seconds, drain_seconds=10)
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
