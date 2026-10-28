"""Job execution, coverage and publication admission remain independent authorities."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.interchange import HANDOFF_SCHEMA, decode_handoff, handoff_input_projection, input_set_sha256
from appsec_review.retrieval.index import INDEX_SCHEMA, IndexBuilder, IndexIdentity, write_manifest
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.datasets import artifact_only, indexed
from appsec_review.runtime.handoff import (
    build_outcomes, collect_artifacts, frozen_job_config_sha256, verify_handoff_integrity, verify_outcomes,
)
from appsec_review.runtime.resume import ResumePlanner, job_config_sha256
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import reference, verify_handoff
from tests.test_job_runtime import write_config


def setup(tmp_path, handler=lambda unit: {"value": 7}, *, units=None, datasets=(), extra_jobs=()):
    path = write_config(tmp_path)
    with path.open("a", encoding="utf-8") as stream:
        stream.write('\n[review_policy.releases]\nplatform = "fixture/1"\nvalidation = "fixture/1"\n')
        for job_id in extra_jobs:
            stream.write(f'\n[jobs.{job_id}]\nname = "{job_id}"\nworkers = 1\n')
    config = load_config(path)
    job = Job("job_fixture", "fixture", handler, units=units or (Unit("work.only", handler),),
              datasets=datasets)
    return config, job, JobRunner(config)


def publish(tmp_path, handler=lambda unit: {"value": 7}, **kwargs):
    config, job, runner = setup(tmp_path, handler, **kwargs)
    outcome = runner.run(job, source_fingerprint="snapshot")
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    return config, job, runner, outcome, root


def rehash(handoff):
    handoff["input_set_sha256"] = input_set_sha256(handoff_input_projection(handoff))


def test_common_envelope_binds_verified_outcomes_without_copying_task_payload(tmp_path):
    config, job, runner, outcome, root = publish(
        tmp_path, lambda unit: {"payload": {"status": "FAILED", "coverage": "unavailable"}, "item_count": 0})
    handoff = outcome["handoff"]
    assert handoff["schema"] == HANDOFF_SCHEMA
    assert handoff["run_id"] == root.name
    assert handoff["source_fingerprint"] == handoff["target_snapshot"] == "snapshot"
    assert handoff["input_manifest"] is None
    assert handoff["status"] == "ACCEPTED" and handoff["execution_status"] == "SUCCEEDED"
    assert handoff["coverage"] == {"disposition": "complete", "gap_count": 0, "retry_required": False}
    assert handoff["input_set_sha256"] == input_set_sha256(handoff_input_projection(handoff))
    accounting = verify_outcomes(root, handoff)
    assert accounting["units"][0]["producer_status"] is None
    assert accounting["units"][0]["result_reference"]["size_bytes"] > 0
    assert "payload" not in handoff["outputs"]["work.only"]
    assert frozen_job_config_sha256(json.loads(config.resolved_json), job.job_id) == job_config_sha256(config, job.job_id)
    verify_handoff(root, handoff)
    claim = runner.begin_or_reuse_attempt(job, run_id=root.name, source_fingerprint="snapshot")
    assert claim["reused"]
    assert claim["evidence_target_snapshot"] == "snapshot"


@pytest.mark.parametrize(("producer", "expected", "retry"), [
    ({}, "complete", False),
    ({"terminal_status": "SUCCEEDED", "item_count": 0}, "complete", False),
    ({"terminal_status": "NOT_APPLICABLE"}, "not_applicable", False),
    ({"terminal_status": "SKIPPED_POLICY"}, "skipped_policy", False),
    ({"terminal_status": "COMPLETED_WITH_GAPS", "gaps": ["bounded deterministic limitation"]}, "partial", False),
    ({"terminal_status": "INVALID_COMPILE_DATABASE"}, "unavailable", False),
    ({"terminal_status": "FAILED"}, "unavailable", True),
    ({"terminal_status": "future-status"}, "unavailable", False),
])
def test_producer_coverage_does_not_override_successful_execution(tmp_path, producer, expected, retry):
    _, _, _, outcome, root = publish(tmp_path, lambda unit: producer)
    handoff = outcome["handoff"]
    assert handoff["execution_status"] == "SUCCEEDED" and handoff["status"] == "ACCEPTED"
    assert handoff["coverage"]["disposition"] == expected
    assert handoff["coverage"]["retry_required"] is retry
    document = verify_outcomes(root, handoff)
    assert document["units"][0]["producer_status"] == producer.get("terminal_status")
    if producer.get("terminal_status") == "future-status":
        assert any(gap["code"] == "unknown_producer_status" for gap in document["gaps"])


def test_mixed_operational_failure_requires_retry_but_deterministic_gaps_do_not(tmp_path):
    def produce(unit):
        return {"terminal_status": "COMPLETED_WITH_GAPS", "dispositions": [
            {"scope_id": "one", "terminal_status": "SUCCEEDED"},
            {"scope_id": "two", "terminal_status": "FAILED"},
        ]}
    config, job, _, outcome, root = publish(tmp_path, produce)
    assert outcome["handoff"]["coverage"]["retry_required"]
    assert outcome["handoff"]["coverage"]["disposition"] == "partial"
    assert "accepted job contains a retriable failed producer" in ResumePlanner(
        config, root, (job,), "snapshot").accepted(job, {})[0]


@pytest.mark.parametrize("field,value", [
    ("target_snapshot", "another-target"), ("source_fingerprint", "another-source"),
    ("dataset_contract_sha256", "0" * 64), ("job_config_sha256", "0" * 64),
    ("resolved_config_sha256", "0" * 64), ("input_identity", "forged-input"),
    ("upstream_handoff_sha256", {"job_other": "0" * 64}),
    ("implementation_identity", "forged-release"),
])
def test_rehashed_envelope_cannot_change_pinned_claim_identities(tmp_path, field, value):
    _, _, _, outcome, root = publish(tmp_path)
    handoff = deepcopy(outcome["handoff"])
    handoff[field] = value
    if field == "target_snapshot":
        handoff["evidence_target_snapshot"] = value
    rehash(handoff)
    with pytest.raises(ValueError):
        verify_handoff_integrity(root, handoff)


@pytest.mark.parametrize("damage", ["missing", "hash", "size", "escaping", "duplicate"])
def test_artifact_reference_admission_is_strict(tmp_path, damage):
    _, _, _, outcome, root = publish(tmp_path)
    handoff = deepcopy(outcome["handoff"])
    ref = handoff["artifacts"][0]
    if damage == "missing":
        (root / ref["path"]).unlink()
    elif damage == "hash":
        ref["sha256"] = "0" * 64
    elif damage == "size":
        ref["size_bytes"] += 1
    elif damage == "escaping":
        ref["path"] = "../outside"
    else:
        handoff["artifacts"].append(dict(ref))
    with pytest.raises((ValueError, OSError)):
        verify_handoff_integrity(root, handoff)


def test_real_symlink_reference_is_rejected(tmp_path):
    _, _, _, outcome, root = publish(tmp_path)
    handoff = deepcopy(outcome["handoff"])
    ref = handoff["artifacts"][0]
    path = root / ref["path"]
    retained = path.with_suffix(".retained")
    path.rename(retained)
    try:
        path.symlink_to(retained)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows host does not grant symbolic-link creation")
        raise
    with pytest.raises(ValueError, match="symlink"):
        verify_handoff_integrity(root, handoff)


def test_symlink_component_check_applies_even_when_bytes_and_size_match(tmp_path, monkeypatch):
    _, _, _, outcome, root = publish(tmp_path)
    original = Path.is_symlink
    ref = outcome["handoff"]["artifacts"][0]
    linked_parent = (root / ref["path"]).parent
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == linked_parent or original(path))
    with pytest.raises(ValueError, match="symlink"):
        verify_handoff_integrity(root, outcome["handoff"])


def test_rehashed_outcomes_cannot_invent_execution_or_hide_producer_failure(tmp_path):
    _, _, _, outcome, root = publish(tmp_path, lambda unit: {"terminal_status": "FAILED"})
    handoff = deepcopy(outcome["handoff"])
    ref = handoff["outcomes"]
    document = json.loads((root / ref["path"]).read_bytes())
    document["coverage"] = {"disposition": "complete", "gap_count": 0, "retry_required": False}
    document["gaps"] = []
    document["units"][0]["gap_ids"] = []
    document["units"][0]["coverage_disposition"] = "complete"
    atomic_json(root / ref["path"], document)
    updated = reference(root, root / ref["path"])
    handoff["outcomes"] = updated
    handoff["artifacts"] = [updated if artifact["path"] == ref["path"] else artifact
                            for artifact in handoff["artifacts"]]
    handoff["coverage"] = document["coverage"]
    with pytest.raises(ValueError, match="outcomes differ"):
        verify_outcomes(root, handoff)


def test_legacy_handoff_requires_fresh_execution(tmp_path):
    config, job, _, outcome, root = publish(tmp_path)
    handoff = deepcopy(outcome["handoff"])
    handoff["schema"] = "appsec-review/job-handoff/1"
    path = Path(outcome["attempt_root"]) / "handoff.json"
    atomic_json(path, handoff)
    pointer = path.parent.parent.parent / "latest.json"
    current = json.loads(pointer.read_bytes())
    atomic_json(pointer, {**current, "handoff_sha256": file_sha256(path)})
    reasons, _ = ResumePlanner(config, root, (job,), "snapshot").accepted(job, {})
    assert reasons == ("handoff_schema_changed",)


@pytest.mark.parametrize("reference_value", [
    {"path": "missing.json", "sha256": "0" * 64},
    {"path": "../escape", "sha256": "0" * 64},
])
def test_missing_referenced_result_forbids_accepted_pointer_and_publishes_rejection(tmp_path, reference_value):
    config, job, runner = setup(tmp_path, lambda unit: {"artifact": reference_value})
    with pytest.raises(ValueError):
        runner.run(job, source_fingerprint="snapshot")
    attempt, = config.runtime.runs_dir.glob("*/data/jobs/job_fixture/attempts/attempt_0001")
    assert not (attempt.parent.parent / "latest.json").exists()
    rejected = json.loads((attempt / "rejected-handoff.json").read_bytes())
    assert rejected["status"] == "REJECTED"
    with pytest.raises(ValueError, match="not accepted"):
        decode_handoff(rejected)


def test_failure_retains_previous_accepted_state_and_only_receipts_supply_execution_status(tmp_path):
    def good(unit):
        return {"value": 7}
    config, job, runner, first, root = publish(tmp_path, good)
    pointer = Path(first["attempt_root"]).parent.parent / "latest.json"
    original = pointer.read_bytes()
    def fail(unit):
        raise RuntimeError("original operational failure")
    failed_job = replace(job, units=(Unit("work.only", fail),))
    with pytest.raises(RuntimeError, match="original operational failure"):
        runner.run(failed_job, run_id=root.name, source_fingerprint="snapshot")
    rejected_path = root / "data/jobs/job_fixture/attempts/attempt_0002/rejected-handoff.json"
    rejected = json.loads(rejected_path.read_bytes())
    assert rejected["execution_status"] == "FAILED"
    assert rejected["coverage"]["retry_required"]
    assert pointer.read_bytes() == original
    verify_handoff_integrity(root, rejected, accepted_only=False)
    events = [json.loads(line) for line in rejected_path.parent.joinpath("logs/events.jsonl").read_text().splitlines()]
    event, = [event for event in events if event["event"] == "HANDOFF_REJECTED"]
    assert event["handoff_reference"] == reference(root, rejected_path)
    assert "original operational failure" not in json.dumps(event)


def test_diagnostic_failure_never_masks_original_error(tmp_path, monkeypatch):
    def fail(unit):
        raise RuntimeError("original failure")
    _, job, runner = setup(tmp_path, fail)
    def unavailable(*args, **kwargs):
        raise OSError("diagnostic failure")
    monkeypatch.setattr("appsec_review.runtime.runner.build_outcomes", unavailable)
    with pytest.raises(RuntimeError, match="original failure") as error:
        runner.run(job)
    assert any("rejected handoff unavailable" in note for note in error.value.__notes__)


DECLARATION = indexed(
    "required_source", "work", "source", INDEX_SCHEMA, "Required source dataset.",
    indexes=("source",), route="find/search", required=True)


def _index_output(unit, *, producer="job_fixture", gap=None):
    root = unit.job.run_root
    path = root / "data/indices/source" / f"{unit.job.attempt_id}.sqlite"
    builder = IndexBuilder(path, name="source", fingerprint="a" * 64,
                           target_snapshot=unit.job.evidence_target_snapshot)
    if gap:
        builder.add_coverage("source", "unavailable", gap)
    digest = builder.build()
    identity = IndexIdentity("source", INDEX_SCHEMA, digest, "a" * 64, path.relative_to(root).as_posix(),
                             {"job": producer, "unit": unit.unit_id}, gaps=(gap,) if gap else ())
    manifest_path = unit.unit_root / "manifest.json"
    write_manifest(manifest_path, run_id=root.name, target_snapshot=unit.job.evidence_target_snapshot,
                   target_root=unit.job.target_root or root, indexes=(identity,))
    return {"index_manifest": reference(root, manifest_path), "index_identity": {
        "name": identity.name, "schema": identity.schema, "sha256": identity.sha256,
        "fingerprint": identity.fingerprint, "relative_path": identity.relative_path,
        "producer": dict(identity.producer), "gaps": list(identity.gaps), "shard_id": identity.shard_id}}


@pytest.mark.parametrize("gap", [None, "producer unavailable"])
def test_empty_or_coverage_only_current_shard_satisfies_required_dataset(tmp_path, gap):
    _, _, _, outcome, root = publish(tmp_path, lambda unit: _index_output(unit, gap=gap),
                                    datasets=(DECLARATION,))
    verify_handoff(root, outcome["handoff"])
    assert outcome["handoff"]["status"] == "ACCEPTED"


@pytest.mark.parametrize("mode", ["missing", "empty_manifest", "inherited"])
def test_required_missing_or_inherited_dataset_cannot_advance_pointers(tmp_path, mode):
    def produce(unit):
        if mode == "missing":
            return {"terminal_status": "NOT_APPLICABLE"}
        if mode == "inherited":
            return _index_output(unit, producer="job_upstream")
        path = unit.unit_root / "manifest.json"
        write_manifest(path, run_id=unit.job.run_id, target_snapshot="snapshot",
                       target_root=unit.job.run_root, indexes=())
        return {"index_manifest": reference(unit.job.run_root, path)}
    config, job, runner = setup(tmp_path, produce, datasets=(DECLARATION,))
    with pytest.raises(ValueError, match="required dataset output missing"):
        runner.run(job, source_fingerprint="snapshot")
    assert not list(config.runtime.runs_dir.glob("*/data/jobs/job_fixture/latest.json"))
    assert not list(config.runtime.runs_dir.glob("*/data/indices/accepted.json"))


def test_handoff_events_are_hash_bound_closed_metadata_and_not_reemitted_on_reuse(tmp_path):
    config, job, runner, outcome, root = publish(tmp_path)
    path = Path(outcome["attempt_root"]) / "logs/events.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    publication = [event for event in events if event["event"] in {"HANDOFF_VALIDATED", "HANDOFF_ACCEPTED"}]
    assert [event["event"] for event in publication] == ["HANDOFF_VALIDATED", "HANDOFF_ACCEPTED"]
    ref = reference(root, Path(outcome["attempt_root"]) / "handoff.json")
    for event in publication:
        assert event["handoff_reference"] == ref
        assert event["unit_count"] == 1 and event["gap_count"] == 0
        assert event["duration_ms"] >= 0
        assert event["admission_status"] == "ACCEPTED" and event["coverage_disposition"] == "complete"
    claim = runner.begin_or_reuse_attempt(job, run_id=root.name, source_fingerprint="snapshot")
    runner.finalize_attempt(job, claim)
    after = [json.loads(line) for line in path.read_text().splitlines()]
    assert sum(event["event"] == "HANDOFF_VALIDATED" for event in after) == 1


def test_source_inventory_and_pinned_configuration_layers_are_metadata_not_artifact_refs(tmp_path):
    def produce(unit):
        manifest = json.loads((unit.job.run_root / "data/configuration/manifest.json").read_bytes())
        return {"source_inventory": [{"path": "source.py", "sha256": "a" * 64, "size_bytes": 4},
                                     {"path": "data/customer.json", "sha256": "a" * 64, "size_bytes": 4}],
                "artifact_candidates": [{"path": "customer.bin", "sha256": "b" * 64, "size_bytes": 4}],
                "layers": manifest["sources"]}
    _, _, _, outcome, root = publish(tmp_path, produce)
    assert outcome["handoff"]["coverage"]["disposition"] == "complete"
    assert all(not ref["path"].startswith(("source.py", "customer.bin"))
               for ref in outcome["handoff"]["artifacts"])
    with pytest.raises(ValueError):
        collect_artifacts(root, {"artifact": {"path": "source.py", "sha256": "a" * 64, "size_bytes": 4}})
    with pytest.raises(ValueError):
        collect_artifacts(root, {"artifact": {"path": str(tmp_path / "not-a-frozen-layer"), "sha256": "a" * 64}})


def test_scoped_binary_inventory_binds_explicit_run_path_not_display_path(tmp_path):
    def produce(unit):
        binary = unit.job.run_root / "data/builds/case/build/app"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"binary fixture")
        artifact = {**reference(unit.job.run_root, binary), "kind": "executable",
                    "artifact_id": "a" * 64}
        return {"artifacts": [{**artifact, "run_path": artifact["path"], "path": "build/app"}]}
    _, _, _, outcome, root = publish(tmp_path, produce)
    binary_ref = next(ref for ref in outcome["handoff"]["artifacts"]
                      if ref["path"] == "data/builds/case/build/app")
    verify_handoff_integrity(root, outcome["handoff"])
    assert collect_artifacts(root, {"artifacts": [{**binary_ref, "path": "build/app",
                                                  "run_path": binary_ref["path"]}]}) == [binary_ref]
    for changed in ({"run_path": "data/missing/app"}, {"run_path": "../app"},
                    {"sha256": "0" * 64}, {"size_bytes": 1}):
        with pytest.raises(ValueError):
            collect_artifacts(root, {"artifacts": [{**binary_ref, "path": "build/app",
                                                    "run_path": binary_ref["path"], **changed}]})
    with pytest.raises(ValueError):
        collect_artifacts(root, {"artifacts": [{**binary_ref, "path": "build/app"}]})


def test_strict_target_independent_consumer_preserves_unique_upstream_evidence_without_source_access(tmp_path):
    job_id = "job_final_report_publication"
    config, producer, runner = setup(tmp_path, _index_output, extra_jobs=(job_id,))
    first = runner.run(producer, source_fingerprint="snapshot")
    root = config.runtime.runs_dir / first["status"]["run_id"]
    consumer = Job(job_id, job_id, lambda unit: {}, units=(Unit("work.only", lambda unit: {}),))
    result = runner.run(consumer, run_id=root.name, source_fingerprint="none",
                        upstream_handoffs={"job_fixture": first["handoff_sha256"]})
    handoff = result["handoff"]
    assert handoff["source_fingerprint"] == "none"
    assert handoff["target_snapshot"] == handoff["evidence_target_snapshot"] == "snapshot"
    assert handoff["input_manifest"] is not None
    verify_handoff_integrity(root, handoff)
    tampered = deepcopy(handoff)
    tampered["input_manifest"] = dict(handoff["artifacts"][0])
    rehash(tampered)
    with pytest.raises(ValueError, match="claimed input manifest"):
        verify_handoff_integrity(root, tampered)
    assert ResumePlanner(config, root, (consumer,), "none").accepted(
        consumer, {"job_fixture": first["handoff_sha256"]})[0] == ()


def test_strict_target_independent_missing_origin_is_named_rejection(tmp_path):
    job_id = "job_final_report_publication"
    config, _, runner = setup(tmp_path, extra_jobs=(job_id,))
    consumer = Job(job_id, job_id, lambda unit: pytest.fail("no evidence"),
                   units=(Unit("work.only", lambda unit: pytest.fail("no evidence")),))
    with pytest.raises(ValueError, match="verified target origin"):
        runner.run(consumer)
    rejected_path, = config.runtime.runs_dir.glob(f"*/data/jobs/{job_id}/attempts/*/rejected-handoff.json")
    handoff = json.loads(rejected_path.read_bytes())
    assert handoff["execution_status"] == "SKIPPED"
    assert handoff["coverage"]["disposition"] == "unavailable"
    assert handoff["status"] == "REJECTED"
    assert not list(config.runtime.runs_dir.glob(f"*/data/jobs/{job_id}/latest.json"))


def test_strict_target_independent_rejects_disagreeing_verified_upstream_targets(tmp_path):
    job_id = "job_final_report_publication"
    config, producer, runner = setup(tmp_path, extra_jobs=(job_id, "job_other"))
    first = runner.run(producer, source_fingerprint="snapshot-one")
    root = config.runtime.runs_dir / first["status"]["run_id"]
    second = runner.run(replace(producer, job_id="job_other", name="job_other"),
                        run_id=root.name, source_fingerprint="snapshot-two")
    consumer = Job(job_id, job_id, lambda unit: {}, units=(Unit("work.only", lambda unit: {}),))
    with pytest.raises(ValueError, match="disagree"):
        runner.run(consumer, run_id=root.name,
                   upstream_handoffs={"job_fixture": first["handoff_sha256"],
                                      "job_other": second["handoff_sha256"]})


def test_verified_skipped_task_retains_skipped_execution_and_blocked_coverage(tmp_path):
    config, job, runner = setup(tmp_path)
    claim = runner.begin_attempt(job)
    root = config.runtime.runs_dir / claim["run_id"]
    path = root / claim["attempt_path"] / "steps/work/tasks/only/status.json"
    atomic_json(path, {"unit_id": "work.only", "step_id": "work", "task_id": "only", "status": "SKIPPED"})
    outcomes = build_outcomes(root, run_id=root.name, job_id=job.job_id, attempt_id=claim["attempt_id"],
                              target_snapshot="none", unit_ids=claim["unit_ids"])
    assert outcomes["units"][0]["execution_status"] == "SKIPPED"
    assert outcomes["units"][0]["result_reference"] is None
    assert outcomes["coverage"]["retry_required"]
    assert outcomes["gaps"][0]["code"] == "producer_blocked"


def test_previous_same_job_shard_in_manifest_is_not_current_required_output(tmp_path):
    config, job, runner, first, root = publish(tmp_path, _index_output, datasets=(DECLARATION,))
    original = first["result"]["outputs"]["work.only"]
    def inherit(unit):
        return {"index_manifest": original["index_manifest"]}
    with pytest.raises(ValueError, match="required dataset output missing"):
        runner.run(replace(job, units=(Unit("work.only", inherit),)),
                   run_id=root.name, source_fingerprint="snapshot")


def test_required_current_artifact_satisfies_contract_but_inherited_artifact_does_not(tmp_path):
    declaration = replace(artifact_only(
        "required_fixture", "work", "inventory", "fixture/1", "Required fixture.",
        artifacts=("data/jobs/job_fixture/attempts/*/fixture.json",), reason="fixture"), required=True)
    def produce(unit):
        path = unit.job.attempt_root / "fixture.json"
        atomic_json(path, {"value": 7})
        return {"artifact": reference(unit.job.run_root, path)}
    config, job, runner, first, root = publish(tmp_path, produce, datasets=(declaration,))
    prior = first["result"]["outputs"]["work.only"]
    with pytest.raises(ValueError, match="required dataset output missing"):
        runner.run(replace(job, units=(Unit("work.only", lambda unit: prior),)),
                   run_id=root.name, source_fingerprint="snapshot")


def test_pointer_write_failure_restores_both_previous_publications(tmp_path, monkeypatch):
    config, job, runner, first, root = publish(tmp_path, _index_output)
    latest = root / "data/jobs/job_fixture/latest.json"
    accepted = root / "data/indices/accepted.json"
    previous = {path: path.read_bytes() for path in (latest, accepted)}
    real_atomic = atomic_json
    def fail_latest(path, value):
        if path == latest:
            raise OSError("pointer publication failed")
        real_atomic(path, value)
    monkeypatch.setattr("appsec_review.runtime.runner.atomic_json", fail_latest)
    with pytest.raises(OSError, match="pointer publication failed"):
        runner.run(job, run_id=root.name, source_fingerprint="snapshot")
    assert all(path.read_bytes() == payload for path, payload in previous.items())
    rejected = root / "data/jobs/job_fixture/attempts/attempt_0002/rejected-handoff.json"
    assert json.loads(rejected.read_bytes())["status"] == "REJECTED"


def test_attempt_id_and_reference_location_do_not_change_input_set_hash(tmp_path):
    config, job, runner, first, root = publish(tmp_path)
    second = runner.run(job, run_id=root.name, source_fingerprint="snapshot")
    assert first["handoff"]["attempt_id"] != second["handoff"]["attempt_id"]
    assert first["handoff"]["input_set_sha256"] == second["handoff"]["input_set_sha256"]


@pytest.mark.parametrize("producer", [
    {"dispositions": {"terminal_status": "FAILED"}},
    {"gaps": "not a declared gap array"},
    {"terminal_status": {"status": "FAILED"}},
    {"gaps": [{"schema": "appsec-review/producer-gap/1", "gap_id": "a" * 64,
               "code": "producer_reported_gap", "unit_id": "work.only", "scope_id": None,
               "reason": "missing external proof", "retryable": False,
               "evidence_refs": [{"path": "data/missing.json", "sha256": "b" * 64, "size_bytes": 4}]}]},
])
def test_invalid_producer_declarations_publish_rejected_verified_execution_not_success(tmp_path, producer):
    config, job, runner = setup(tmp_path, lambda unit: producer)
    with pytest.raises(ValueError):
        runner.run(job, source_fingerprint="snapshot")
    rejected_path, = config.runtime.runs_dir.glob("*/data/jobs/job_fixture/attempts/*/rejected-handoff.json")
    root = rejected_path.parent.parents[4]
    handoff = json.loads(rejected_path.read_bytes())
    assert handoff["status"] == "REJECTED" and handoff["execution_status"] == "SUCCEEDED"
    assert handoff["coverage"] == {"disposition": "unavailable", "gap_count": 1, "retry_required": False}
    outcomes = verify_outcomes(root, handoff)
    assert outcomes["gaps"][0]["code"] == "unknown_producer_status"
    assert not list(config.runtime.runs_dir.glob("*/data/jobs/job_fixture/latest.json"))


@pytest.mark.parametrize("field,value", [
    ("source_fingerprint", "different-target"), ("evidence_target_snapshot", "different-snapshot"),
    ("input_manifest_path", "data/missing.json"), ("input_manifest_sha256", "0" * 64),
    ("upstream_handoffs", {"job_other": "a" * 64}), ("resolved_config_sha256", "0" * 64),
    ("job_config_sha256", "0" * 64),
])
def test_changed_prepared_claim_is_rejected_before_unit_execution(tmp_path, field, value):
    executed = []
    _, job, runner = setup(tmp_path, lambda unit: executed.append(True) or {})
    claim = runner.begin_attempt(job, source_fingerprint="snapshot")
    changed = {**claim, field: value}
    with pytest.raises(ValueError, match="claim"):
        runner.execute_or_reuse_unit(job, changed, "work.only")
    assert not executed


def test_prepared_claim_allows_only_scheduling_annotations_and_json_normalization(tmp_path):
    _, job, runner = setup(tmp_path, lambda unit: {"value": 7}, datasets=(DECLARATION,))
    claim = runner.begin_attempt(job, source_fingerprint="snapshot",
                                 orchestration={"system": "dagster", "run_id": "dagster-run", "node": "prepare"})
    changed = json.loads(canonical_json(claim))
    changed["orchestration"]["node"] = "work.only"
    changed["graph_started_at"] = "scheduling annotation"
    assert runner.execute_or_reuse_unit(job, changed, "work.only") == {"value": 7}


def test_reused_strict_attempt_reverifies_terminal_bytes_at_dispatch(tmp_path):
    _, job, runner, outcome, root = publish(tmp_path)
    claim = runner.begin_or_reuse_attempt(job, run_id=root.name, source_fingerprint="snapshot")
    assert claim["reused"]
    result = Path(outcome["attempt_root"]) / "steps/work/tasks/only/result.json"
    result.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity"):
        runner.execute_or_reuse_unit(job, claim, "work.only")


def test_finalization_retry_preserves_accepted_immutable_handoff(tmp_path):
    _, job, runner, first, root = publish(tmp_path)
    attempt = Path(first["attempt_root"])
    claim = json.loads((attempt / "claim.json").read_bytes())
    original = (attempt / "handoff.json").read_bytes()
    retried = runner.finalize_attempt(job, claim)
    assert retried["reused"]
    assert retried["handoff_sha256"] == first["handoff_sha256"]
    assert (attempt / "handoff.json").read_bytes() == original
    events = [json.loads(line) for line in (attempt / "logs/events.jsonl").read_text().splitlines()]
    assert sum(event["event"] == "HANDOFF_ACCEPTED" for event in events) == 1
