"""job_build_iteration: the declared inputs and outputs are the job's contract.

The job is one bounded production transaction: it inherits every language-build input as optional,
requires exactly one transaction input (the controller's immutable iteration request), and claims
only protected operational state (controller records and workspace custody), never a review-graph
publication. These tests pin the contract, the declarations, the files the handler reads and
writes under the run root, and that every retained controller record lands inside its declared
artifact glob with the declared request schema.
"""
from __future__ import annotations

from fnmatch import fnmatch
import json
from pathlib import Path

import pytest

from appsec_review.jobs.build_iterations import REQUEST_SCHEMA, SCHEMA, read_reference, retain
from appsec_review.jobs.job_build_iteration.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_build_iteration.job import build_job, iteration_input_identity
from appsec_review.jobs.job_language_build.datasets import CONTRACT as LANGUAGE_CONTRACT
from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, MissingPolicy, TargetAccess,
)
from appsec_review.runtime.datasets import METADATA_ROUTE
from appsec_review.storage.atomic import canonical_json_sha256

RETAINED_CATEGORIES = ("graphs", "configurations", "requests", "receipts", "prepared", "failures", "completed",
                       "invalidations", "failure-generation-selections", "contexts", "selections")


def _declared() -> dict[str, object]:
    return {item.output_kind: item for item in DATASETS}


def _claimed(path: str) -> list[str]:
    return [item.output_kind for item in DATASETS if any(fnmatch(path, pattern) for pattern in item.artifacts)]


# --- inputs ----------------------------------------------------------------------------------------

def test_inputs_are_the_language_build_inputs_made_optional_plus_one_required_transaction() -> None:
    inherited = CONTRACT.inputs[:-1]
    assert len(inherited) == len(LANGUAGE_CONTRACT.inputs) == len(CONTRACT.inputs) - 1
    for ours, theirs in zip(inherited, LANGUAGE_CONTRACT.inputs, strict=True):
        assert (ours.producer, ours.output_kind, ours.schema, ours.authority, ours.channel, ours.coverage) == (
            theirs.producer, theirs.output_kind, theirs.schema, theirs.authority, theirs.channel, theirs.coverage)
        assert ours.availability is Availability.OPTIONAL and ours.missing is MissingPolicy.GAP, ours
    by_job: dict[str, set[str]] = {}
    for requirement in inherited:
        by_job.setdefault(requirement.producer, set()).add(requirement.output_kind)
    assert by_job == {
        "job_build_environment_analysis": {"handoff", "build_environment"},
        "job_project_build": {"handoff", "topology_refinement_inputs", "project_build_dispatch",
                              "probe_workspaces", "image_build_streams"},
        "job_review_intake": {"handoff", "model_preflight", "binary_evidence", "review_intake"},
        "job_target_analysis_plan": {"handoff", "planning_feedback_cache", "analysis_plan",
                                     "analysis_plan_documents"},
        "job_target_catalog": {"handoff", "target_artifact_inputs", "source_files", "declaration_symbols",
                               "components", "target_documents", "build_units", "catalog_documents"},
    }
    request = CONTRACT.inputs[-1]
    assert (request.producer, request.output_kind, request.schema) == (
        "build_controller", "iteration_request", "appsec-review/build-iteration-request/1")
    assert request.schema == REQUEST_SCHEMA
    assert request.channel is InputChannel.TRANSACTION and request.authority is EvidenceAuthority.OPERATIONAL
    assert request.availability is Availability.REQUIRED and request.missing is MissingPolicy.REJECT
    required = [(item.producer, item.output_kind) for item in CONTRACT.inputs
                if item.availability is Availability.REQUIRED or item.missing is MissingPolicy.REJECT]
    assert required == [("build_controller", "iteration_request")]


def test_the_transaction_is_dispatched_internally_and_never_propagates_a_graph_handoff() -> None:
    assert CONTRACT.dispatch is DispatchClass.INTERNAL_TRANSACTION
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.schedule_after == ()
    assert CONTRACT.always_execute is True and CONTRACT.propagate_handoff is False
    # consumption names handoff producers only: the controller request is a transaction, not a handoff
    assert CONTRACT.consumes == CONSUMES == tuple(sorted(by for by in {
        item.producer for item in CONTRACT.inputs if item.channel is InputChannel.HANDOFF}))
    assert "build_controller" not in CONSUMES
    assert CONSUMES == LANGUAGE_CONTRACT.consumes


# --- outputs ---------------------------------------------------------------------------------------

def test_outputs_are_protected_operational_state_of_the_execute_step() -> None:
    declared = _declared()
    assert [(k, v.step, v.family, v.disposition, v.schema) for k, v in declared.items()] == [
        ("iteration_records", "execute", "build", "protected", "appsec-review/build-iterations/1"),
        ("workspace_records", "execute", "build", "protected", "application/json"),
    ]
    assert declared["iteration_records"].schema == SCHEMA
    for item in DATASETS:
        assert item.sensitivity == "sensitive" and item.authority is EvidenceAuthority.OPERATIONAL, item.output_kind
        assert item.indexes == () and item.shard_prefixes == () and item.query_route == METADATA_ROUTE
        assert item.required is False and item.artifacts, item.output_kind
    assert "not an accepted top-level build result" in declared["iteration_records"].reason
    assert "only the language-build producer publishes accepted review evidence" in declared["workspace_records"].reason
    steps = {unit.unit_id.split(".")[0] for unit in build_job().units}
    assert {item.step for item in DATASETS} == steps == {"execute"}


def test_controller_pointers_and_every_retained_category_are_claimed_by_iteration_records() -> None:
    for pointer in ("ledger.json", "controller.lock", "pending.json", "pending-invalidation.json",
                    "retention.json", "selection.json"):
        assert _claimed(f"data/build/iterations/{pointer}") == ["iteration_records"], pointer
    for folder in ("prepared", "failures", "recompositions"):
        assert _claimed(f"data/build/iterations/{folder}/{'a' * 64}.json") == ["iteration_records"], folder
    assert _claimed(f"data/build/iterations/leases/build-unit-{'a' * 20}/lease-1.json") == ["iteration_records"]
    for category in RETAINED_CATEGORIES:
        assert _claimed(f"artifacts/build/iterations/{category}/{'b' * 64}.json") == ["iteration_records"], category
    assert _claimed("artifacts/build/iterations/unknown/x.json") == []
    assert _claimed("data/jobs/job_build_iteration/attempts/attempt_0001/result.json") == [], \
        "the attempt tree is the runner's, not a dataset"


def test_workspace_custody_files_are_claimed_by_workspace_records_and_not_by_the_language_lanes() -> None:
    for path in ("data/build/workspace.lock", "data/build/workspace/owner.json", "data/build/workspace/state.json",
                 "data/build/workspace/deletion.json", "data/build/workspace/replays/replay-1/owner.json",
                 "data/build/workspace/replays/replay-1/state.json", "data/build/workspace/replays/replay-1/writer.lock",
                 "artifacts/build/workspace/input.json", f"artifacts/build/workspace/generations/{'c' * 64}.json",
                 f"artifacts/build/workspace/products/{'c' * 64}.json",
                 f"artifacts/build/workspace/invalidations/{'c' * 64}.json",
                 f"artifacts/build/workspace/invalidations/operations/{'c' * 64}.json",
                 "artifacts/build/workspace/attempts/iteration-1/intent.json",
                 "artifacts/build/workspace/attempts/iteration-1/failure.json",
                 "artifacts/build/workspace/attempts/iteration-1/recovery.json"):
        assert _claimed(path) == ["workspace_records"], path
    # the materialized tree itself (target/, install/) is the language-build workspace, not a record
    assert _claimed("data/build/workspace/target/src/main.c") == []
    assert _claimed("artifacts/build/workspace/attempts/iteration-1/stdout.log") == []


def test_a_retained_request_lands_inside_its_glob_carries_the_request_schema_and_rereads_verbatim(
        tmp_path: Path) -> None:
    run_root = tmp_path / "2026-11-12-0001"
    run_root.mkdir()
    value = {"schema": REQUEST_SCHEMA, "run_id": run_root.name, "node_id": "build-unit-" + "a" * 20,
             "target": str(tmp_path / "target"), "binding": {"source_identity": "f" * 64}}
    reference = {**retain(run_root, "requests", value), "run_id": run_root.name}
    assert set(reference) == {"path", "sha256", "size_bytes", "run_id"}
    assert reference["path"].startswith("artifacts/build/iterations/requests/") and reference["path"].endswith(".json")
    assert _claimed(reference["path"]) == ["iteration_records"]
    written = run_root / reference["path"]
    assert written.stat().st_size == reference["size_bytes"]
    assert json.loads(written.read_bytes())["schema"] == REQUEST_SCHEMA == CONTRACT.inputs[-1].schema
    assert read_reference(run_root, reference) == value
    completion = retain(run_root, "completed", {"request": reference, "terminal_status": "SUCCEEDED"})
    assert _claimed(completion["path"]) == ["iteration_records"]
    written.write_text(json.dumps({**value, "node_id": "build-unit-" + "b" * 20}), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity mismatch"):
        read_reference(run_root, reference)
    with pytest.raises(ValueError, match="integrity mismatch"):
        read_reference(run_root, {**reference, "path": "artifacts/build/iterations/requests/missing.json"})


def test_the_run_input_identity_is_the_claimed_request_or_an_explicit_absence(tmp_path: Path) -> None:
    run_root = tmp_path / "2026-11-12-0001"
    (run_root / "data/build/iterations").mkdir(parents=True)
    assert iteration_input_identity(None, run_root) == canonical_json_sha256({"iteration_request": None})
    value = {"schema": REQUEST_SCHEMA, "run_id": run_root.name, "node_id": "n"}
    reference = {**retain(run_root, "requests", value), "run_id": run_root.name}
    pending = run_root / "data/build/iterations/pending.json"
    pending.write_text(json.dumps({"request": reference, "before_generation": "g0"}), encoding="utf-8")
    assert _claimed("data/build/iterations/pending.json") == ["iteration_records"]
    identity = iteration_input_identity(tmp_path / "target", run_root)
    assert identity == canonical_json_sha256({"iteration_request": reference})
    assert identity != canonical_json_sha256({"iteration_request": None})
    other = {**reference, "sha256": "0" * 64}
    pending.write_text(json.dumps({"request": other}), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity mismatch"):
        iteration_input_identity(None, run_root)


def test_the_job_carries_the_contract_and_declarations_it_was_built_from() -> None:
    job = build_job()
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert job.consumes == CONTRACT.consumes
    assert (job.job_id, job.name) == ("job_build_iteration", "build_iteration")
    assert job.always_execute is True and job.propagate_handoff is False and job.strict_gaps is True
    assert job.run_input_identity is iteration_input_identity
    assert [unit.unit_id for unit in job.units] == ["execute.node"]
