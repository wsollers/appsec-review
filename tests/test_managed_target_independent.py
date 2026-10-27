"""Fake-only launch/Dagster regressions; admission is issued by real producer publication."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import re

import pytest

from appsec_review.config import load_config
from appsec_review.retrieval.index import write_manifest
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.launch import (
    TARGET_INDEPENDENT_JOBS, TARGET_INDEPENDENT_METADATA_JOBS, TARGET_JOBS,
    LaunchInputs, begin, configured_target, launch, launch_inputs,
)
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.admission import admit_upstreams, consume_admission
from appsec_review.storage.shared import put_private_file, reference, verify_reference
from appsec_review.storage.validation import current_validation, validation_scope
from tests.test_job_runtime import write_config


pytestmark = pytest.mark.skipif(os.name != "posix", reason="managed custody requires POSIX")
CONSUMERS = tuple(sorted(TARGET_INDEPENDENT_JOBS - TARGET_INDEPENDENT_METADATA_JOBS))


def _setup(tmp_path, *, managed=True):
    target = tmp_path / "target"
    target.mkdir()
    (target / "customer.py").write_text("print('customer')\n", encoding="utf-8")
    path = write_config(tmp_path)
    with path.open("a", encoding="utf-8") as stream:
        for job_id in (*sorted(TARGET_INDEPENDENT_JOBS), "job_target_catalog", "job_target_analysis_plan"):
            stream.write(f'\n[jobs.{job_id}]\nname = "{job_id}"\nworkers = 1\n'
                         f'\n[jobs.{job_id}.steps.work]\nworkers = 1\n'
                         f'\n[jobs.{job_id}.steps.work.tasks.only]\nworkers = 1\n')
        # Keep the real typed contracts while replacing only execution with fake units.
        prefixes = tuple(f"jobs.{job_id}.settings" for job_id in (
            "job_image_pin_verification", "job_target_catalog", "job_inference_security_review"))
        canonical = (Path(__file__).parents[1] / "appsec-review.toml").read_text(encoding="utf-8")
        selected = False
        for line in canonical.splitlines():
            header = re.fullmatch(r"\[{1,2}([A-Za-z0-9_.]+)\]{1,2}\s*(?:#.*)?", line.strip())
            if header is not None:
                table = header.group(1)
                selected = any(table == prefix or table.startswith(prefix + ".") for prefix in prefixes)
            if selected:
                stream.write(line + "\n")
        stream.write(
            f'\n[review_policy]\nmode = "{("first_party_managed" if managed else "strict")}"\n'
            'project_id = "fixture"\napproved_first_party_projects = ["fixture"]\n'
            'custody = "application_private_v1"\n'
            f'target_root = {json.dumps(str(target))}\n'
            '\n[review_policy.releases]\nplatform = "fixture/1"\nvalidation = "fixture/1"\n')
    return load_config(path), target


def _job(job_id, handler):
    return Job(job_id, job_id, lambda context: {}, units=(Unit("work.only", handler),))


def _produce(config, target, *, run_id=None, job_id="job_target_catalog", manifest=True):
    def produce(unit):
        source = unit.unit_root / "evidence.bin"
        source.write_bytes(b"customer evidence")
        output = {"artifact": put_private_file(unit.job.run_root, source)}
        if manifest:
            path = unit.unit_root / "manifest.json"
            write_manifest(path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                           target_root=unit.job.target_root, indexes=())
            output["index_manifest"] = reference(unit.job.run_root, path)
        return output

    job = _job(job_id, produce)
    return launch(JobRunner(config), job, launch_inputs(job, target=target, upstream_handoffs={}),
                  run_id=run_id)


def _selection(outcome):
    return {outcome["handoff"]["job_id"]: outcome["handoff_sha256"]}


def _deny_target_access(monkeypatch, target):
    for name in ("resolve", "stat", "lstat", "open", "iterdir"):
        original = getattr(Path, name)

        def guarded(path, *args, _original=original, **kwargs):
            if path == target or target in path.parents:
                pytest.fail(f"target-independent launch accessed target: {path}")
            return _original(path, *args, **kwargs)

        monkeypatch.setattr(Path, name, guarded)


def _consumer(job_id, snapshot, artifact, seen):
    def consume(unit):
        context = unit.job
        assert context.target_root is None
        assert context.source_fingerprint == "none"
        assert context.evidence_target_snapshot == snapshot
        assert current_validation(context.run_root).target_snapshot == snapshot
        verify_reference(context.run_root, artifact)
        seen.append((context.attempt_id, dict(context.orchestration)))
        return {"artifact": artifact, "terminal_status": "SUCCEEDED"}

    return _job(job_id, consume)


@pytest.mark.parametrize("job_id", CONSUMERS)
def test_launch_restores_target_binding_without_target_access(tmp_path, monkeypatch, job_id):
    config, target = _setup(tmp_path)
    producer = _produce(config, target)
    run_id = producer["status"]["run_id"]
    snapshot = producer["handoff"]["source_fingerprint"]
    artifact = producer["result"]["outputs"]["work.only"]["artifact"]
    seen = []
    job = _consumer(job_id, snapshot, artifact, seen)
    _deny_target_access(monkeypatch, target)
    inputs = launch_inputs(job, target=target, upstream_handoffs=_selection(producer))
    assert inputs.target_root is None and inputs.source_fingerprint == "none"

    claim = begin(JobRunner(config), job, inputs, run_id=run_id, trigger="manual",
                  orchestration={"system": "dagster", "run_id": "fixture", "node": "begin"})
    # Serialization and new runners exercise the begin/unit/finalize process boundary.
    claim = json.loads(json.dumps(claim))
    unit_claim = {**claim, "orchestration": {**claim["orchestration"], "node": "work"},
                  "graph_started_at": claim["started_at"], "completed_handoffs": {},
                  "prior_graph_completion_status": "SUCCEEDED", "resume_decisions": []}
    JobRunner(config).execute_or_reuse_unit(job, unit_claim, "work.only")
    outcome = JobRunner(config).finalize_attempt(job, claim)
    assert outcome["handoff"]["source_fingerprint"] == "none"
    assert outcome["handoff"]["evidence_target_snapshot"] == snapshot
    assert outcome["handoff"]["validation_record"]
    assert len(seen) == 1
    reused = launch(JobRunner(config), job, inputs, run_id=run_id)
    assert reused["reused"] is True and len(seen) == 1
    assert current_validation(config.runtime.runs_dir / run_id) is None


def test_target_independent_chain_preserves_authenticated_origin(tmp_path, monkeypatch):
    config, target = _setup(tmp_path)
    outcome = _produce(config, target)
    run_id = outcome["status"]["run_id"]
    snapshot = outcome["handoff"]["source_fingerprint"]
    artifact = outcome["result"]["outputs"]["work.only"]["artifact"]
    _deny_target_access(monkeypatch, target)
    for job_id in ("job_inference_security_review", "job_final_publication_gate",
                   "job_poc_generation", "job_final_report_publication"):
        job = _consumer(job_id, snapshot, artifact, [])
        outcome = launch(JobRunner(config), job,
                         launch_inputs(job, target=target, upstream_handoffs=_selection(outcome)),
                         run_id=run_id)
        assert outcome["handoff"]["source_fingerprint"] == "none"
        assert outcome["handoff"]["evidence_target_snapshot"] == snapshot


def test_composed_inputs_and_publication_restore_evidence_not_source_access(tmp_path, monkeypatch):
    from appsec_review.storage import admission, validation

    config, target = _setup(tmp_path)
    one = _produce(config, target)
    run_id = one["status"]["run_id"]
    two = _produce(config, target, run_id=run_id, job_id="job_target_analysis_plan")
    artifact = one["result"]["outputs"]["work.only"]["artifact"]
    snapshot = one["handoff"]["source_fingerprint"]
    job = _consumer("job_final_report_publication", snapshot, artifact, [])
    original_hash = validation.file_sha256

    def no_evidence_rehash(path):
        if path == config.runtime.runs_dir / run_id / artifact["path"]:
            pytest.fail("consumer rehashed already authenticated upstream evidence")
        return original_hash(path)

    def no_evidence_detach(*args):
        pytest.fail("consumer detached an admitted upstream payload again")

    _deny_target_access(monkeypatch, target)
    monkeypatch.setattr(validation, "file_sha256", no_evidence_rehash)
    monkeypatch.setattr(admission, "_detach_payload", no_evidence_detach)
    outcome = launch(JobRunner(config), job,
                     LaunchInputs(None, "none", {**_selection(one), **_selection(two)}), run_id=run_id)
    claim = json.loads((Path(outcome["attempt_root"]) / "claim.json").read_bytes())
    manifest = json.loads((config.runtime.runs_dir / run_id / claim["input_manifest_path"]).read_bytes())
    assert manifest["target_snapshot"] == snapshot
    assert len(manifest["upstream_manifests"]) == 2
    assert claim["source_fingerprint"] == "none" and claim["target_root"] is None


def test_dagster_target_independent_begin_unit_finalize_and_reuse(tmp_path, monkeypatch):
    dagster = pytest.importorskip("dagster")
    from appsec_review.orchestration.dagster.adapter import _build_dagster_graph
    from appsec_review.orchestration.topology import UPSTREAM_HANDOFFS_TAG

    config, target = _setup(tmp_path)
    producer = _produce(config, target)
    run_id = producer["status"]["run_id"]
    seen = []
    job = _consumer("job_inference_security_review", producer["handoff"]["source_fingerprint"],
                    producer["result"]["outputs"]["work.only"]["artifact"], seen)
    graph = _build_dagster_graph("managed_target_independent", (job,), config, JobRunner)
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    _deny_target_access(monkeypatch, target)
    assert configured_target(config.runtime.repository_root) == target
    tags = {"appsec/application_run_id": run_id,
            UPSTREAM_HANDOFFS_TAG: json.dumps(_selection(producer))}
    storage = tmp_path / "dagster"
    storage.mkdir()
    with dagster.DagsterInstance.ephemeral(tempdir=str(storage)) as instance:
        assert graph.execute_in_process(instance=instance, tags=tags).success
        assert graph.execute_in_process(instance=instance, tags=tags).success
    assert len(seen) == 1
    assert seen[0][1]["node"].endswith("work__only")


@pytest.mark.parametrize("job_id", sorted(TARGET_INDEPENDENT_METADATA_JOBS))
def test_readiness_authenticates_metadata_without_granting_target_trust(tmp_path, monkeypatch, job_id):
    config, target = _setup(tmp_path)
    _deny_target_access(monkeypatch, target)
    job = _job(job_id, lambda unit: {"ready": True})
    result = launch(JobRunner(config), job, LaunchInputs(None, "none"), run_id=None)
    run_root = config.runtime.runs_dir / result["status"]["run_id"]
    assert result["handoff"]["evidence_target_snapshot"] == "none"
    with validation_scope(run_root) as validation:
        assert consume_admission(run_root, result["handoff"])
        assert validation.target_snapshot == "unknown"
        assert not validation.admitted
    consumer = _job("job_inference_security_review", lambda unit: pytest.fail("missing target origin"))
    with pytest.raises(ValueError, match="authenticated target origin"):
        launch(JobRunner(config), consumer, LaunchInputs(None, "none", _selection(result)),
               run_id=run_root.name)


@pytest.mark.parametrize("upstreams", [{}, {"job_target_catalog": "0" * 64}])
def test_missing_origin_fails_preparation_terminally(tmp_path, upstreams):
    config, _ = _setup(tmp_path)
    job = _job("job_inference_security_review", lambda unit: pytest.fail("preparation failed"))
    with pytest.raises(ValueError):
        launch(JobRunner(config), job, LaunchInputs(None, "none", upstreams), run_id=None)
    attempt, = config.runtime.runs_dir.glob(
        "*/data/jobs/job_inference_security_review/attempts/attempt_0001")
    claim = json.loads((attempt / "claim.json").read_bytes())
    assert "managed_claim_authentication" not in claim
    assert json.loads((attempt / "status.json").read_bytes())["status"] == "FAILED"
    assert not (attempt / "handoff.json").exists()
    assert not (attempt.parent.parent / "latest.json").exists()
    assert not list((config.runtime.runs_dir / "metadata" / "evidence-admission").glob("*/*.json"))


@pytest.mark.parametrize("change", [
    "missing_record", "forged_record", "wrong_project", "wrong_config", "wrong_run", "changed_upstreams",
])
def test_target_independent_rejects_unauthenticated_or_rebound_origin(tmp_path, change):
    config, target = _setup(tmp_path)
    producer = _produce(config, target)
    run_root = config.runtime.runs_dir / producer["status"]["run_id"]
    handoff = deepcopy(producer["handoff"])
    if change == "missing_record":
        del handoff["validation_record"]
    elif change in {"forged_record", "wrong_project"}:
        record_ref = handoff["validation_record"]
        path = run_root.parent / "metadata" / record_ref["path"]
        record = json.loads(path.read_bytes())
        if change == "wrong_project":
            record["policy"]["project_id"] = "other-project"
        else:
            record["target_snapshot"] = "forged-target"
        atomic_json(path, record)
        record_ref.update(sha256=file_sha256(path), size_bytes=path.stat().st_size)
    elif change == "wrong_config":
        handoff["resolved_config_sha256"] = "0" * 64
    elif change == "wrong_run":
        handoff["validation_record"]["path"] = "evidence-admission/other-run/record.json"
    else:
        handoff["upstream_handoff_sha256"] = {"job_missing": "0" * 64}
    path = Path(producer["attempt_root"]) / "handoff.json"
    atomic_json(path, handoff)
    job = _job("job_final_publication_gate", lambda unit: pytest.fail("invalid origin executed"))
    with pytest.raises(ValueError):
        launch(JobRunner(config), job,
               LaunchInputs(None, "none", {"job_target_catalog": file_sha256(path)}), run_id=run_root.name)
    attempt = run_root / "data/jobs/job_final_publication_gate/attempts/attempt_0001"
    assert json.loads((attempt / "status.json").read_bytes())["status"] == "FAILED"
    assert not (attempt / "handoff.json").exists()
    assert current_validation(run_root) is None


def test_mixed_authenticated_targets_leave_no_provisional_admission(tmp_path):
    config, target = _setup(tmp_path)
    one = _produce(config, target)
    run_id = one["status"]["run_id"]
    job = _job("job_inference_security_review", lambda unit: {})
    runner = JobRunner(config)
    claim = runner.begin_attempt(job, run_id=run_id, upstream_handoffs=_selection(one))
    context = runner._context_from_claim(job, claim)
    (target / "customer.py").write_text("print('new snapshot')\n", encoding="utf-8")
    two = _produce(config, target, run_id=run_id, job_id="job_target_analysis_plan")
    assert one["handoff"]["source_fingerprint"] != two["handoff"]["source_fingerprint"]
    with validation_scope(context.run_root) as validation:
        with pytest.raises(ValueError, match="different target"):
            admit_upstreams(context, {**_selection(one), **_selection(two)})
        assert validation.target_snapshot == "unknown"
        assert not validation.admitted and not validation.records


@pytest.mark.parametrize("field,value", [
    ("source_fingerprint", "forged"), ("evidence_target_snapshot", "forged"),
    ("target_root", "/not-an-approved-target"), ("upstream_handoffs", {}),
    ("resolved_config_sha256", "0" * 64), ("job_id", "job_final_publication_gate"),
    ("managed_claim_authentication", None), ("input_manifest_sha256", "0" * 64),
])
def test_changed_transport_claim_cannot_restore_managed_context(tmp_path, field, value):
    config, target = _setup(tmp_path)
    producer = _produce(config, target)
    job = _job("job_inference_security_review", lambda unit: pytest.fail("forged claim executed"))
    claim = JobRunner(config).begin_attempt(job, run_id=producer["status"]["run_id"],
                                           upstream_handoffs=_selection(producer))
    claim[field] = value
    with pytest.raises(ValueError):
        JobRunner(config).execute_or_reuse_unit(job, claim, "work.only")


def test_changed_persisted_claim_and_legacy_policy_are_rejected(tmp_path):
    config, target = _setup(tmp_path)
    producer = _produce(config, target)
    job = _job("job_inference_security_review", lambda unit: {})
    runner = JobRunner(config)
    claim = runner.begin_attempt(job, run_id=producer["status"]["run_id"],
                                 upstream_handoffs=_selection(producer))
    path = config.runtime.runs_dir / claim["run_id"] / claim["attempt_path"] / "claim.json"
    changed = {**claim, "upstream_handoffs": {}}
    atomic_json(path, changed)
    with pytest.raises(ValueError, match="authentication"):
        JobRunner(config)._context_from_claim(job, claim)
    legacy = dict(claim)
    del legacy["review_policy"]
    with pytest.raises(ValueError, match="legacy attempt"):
        JobRunner(config)._context_from_claim(job, legacy)


def test_managed_absent_target_is_not_a_general_policy_bypass(tmp_path):
    config, _ = _setup(tmp_path)
    job = Job("job_fixture", "fixture", lambda context: {}, units=(Unit("work.only", lambda unit: {}),))
    with pytest.raises(ValueError, match="absent-target"):
        JobRunner(config).begin_attempt(job)
    assert TARGET_INDEPENDENT_JOBS.isdisjoint(TARGET_JOBS)


def test_frozen_policy_and_manifest_snapshot_are_checked(tmp_path):
    config, target = _setup(tmp_path)
    producer = _produce(config, target)
    job = _job("job_inference_security_review", lambda unit: {})
    runner = JobRunner(config)
    claim = runner.begin_attempt(job, run_id=producer["status"]["run_id"],
                                 upstream_handoffs=_selection(producer))
    context = runner._context_from_claim(job, claim)
    with validation_scope(context.run_root):
        with pytest.raises(ValueError, match="frozen policy"):
            admit_upstreams(replace(context, review_policy=replace(
                config.review_policy, project_id="other",
                approved_first_party_projects=("other",))), _selection(producer))
    from appsec_review.retrieval.core import materialize_attempt_input_manifest
    with pytest.raises(ValueError, match="authenticated evidence binding"):
        materialize_attempt_input_manifest(
            run_root=context.run_root, attempt_root=context.attempt_root, run_id=context.run_id,
            target_snapshot="none", target_root=None, upstream_handoffs=_selection(producer),
            evidence_target_snapshot="different-snapshot")


def test_strict_target_independent_launch_keeps_legacy_behavior(tmp_path, monkeypatch):
    config, target = _setup(tmp_path, managed=False)
    producer = _produce(config, target)
    seen = []

    def consume(unit):
        assert unit.job.source_fingerprint == "none" and unit.job.target_root is None
        assert unit.job.evidence_target_snapshot is None
        seen.append(True)
        return {"ok": True}

    job = _job("job_inference_security_review", consume)
    _deny_target_access(monkeypatch, target)
    result = launch(JobRunner(config), job, LaunchInputs(None, "none", _selection(producer)),
                    run_id=producer["status"]["run_id"])
    assert seen == [True]
    assert "validation_record" not in result["handoff"]
