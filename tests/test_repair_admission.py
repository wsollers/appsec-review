from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.runtime import GraphRunner, Job, JobRunner, Unit
from appsec_review.runtime.failure_replay import failure_manifest
from appsec_review.runtime.repair import (
    admit_repair, current_binding, plan_repair, stopped_reasons, worker_scope,
)
from appsec_review.runtime.release import MANIFEST_NAME, load_release
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import FileLock, LockUnavailable, atomic_json, canonical_json
from tests.release_support import write_release
from tests.test_job_runtime import write_config


def fixture(root, ids=("job_fixture",)):
    config_path = write_config(root)
    with config_path.open("a") as stream:
        for job_id in ids:
            if job_id != "job_fixture":
                stream.write(f'\n[jobs.{job_id}]\nname = "{job_id}"\nworkers = 1\n')
    write_release(root, ids)
    config = load_config(config_path)
    calls = []
    def build(job_id):
        def produce(context):
            calls.append((job_id, context.unit_id, context.job.attempt_id))
            return {"value": 7}
        return Job(job_id, "fixture" if job_id == "job_fixture" else job_id, produce,
                   units=(Unit("work.only", produce),))
    return config, tuple(build(job_id) for job_id in ids), calls


def test_undeclared_labels_do_not_substitute_for_source_identity(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    labels = ComponentReleases({"platform": "same", "validation": "same"})
    before = job.identities(tmp_path, labels)
    (tmp_path / "release-src/job_fixture/job.py").write_text("VERSION = 2\n")
    # Review-time lookup only reads the release, never scans changed installed/source payloads.
    assert job.identities(tmp_path, labels) == before
    write_release(tmp_path, (job.job_id,))
    assert job.identities(tmp_path, labels) != before
    (tmp_path / MANIFEST_NAME).unlink()
    assert job.identities(tmp_path, labels)["implementation"] == "undeclared"


@pytest.mark.parametrize("path", [
    "release-src/job_fixture/job.py", "release-src/shared.py",
    "release-src/validator.json", "release-src/mounted.sh",
])
def test_each_declared_dependency_changes_build_identity(tmp_path, path):
    config, (job,), _ = fixture(tmp_path)
    before = load_release(tmp_path)
    target = tmp_path / path
    target.write_text(target.read_text() + ("\n# changed\n" if target.suffix == ".py" else "\n "))
    after = write_release(tmp_path, (job.job_id,))
    assert before["jobs"][job.job_id] != after["jobs"][job.job_id]
    assert canonical_json(after) == canonical_json(write_release(tmp_path, (job.job_id,)))
    assert (before["scripts_sha256"] != after["scripts_sha256"]) is (target.suffix == ".sh")


def test_release_lookup_never_opens_payloads(tmp_path, monkeypatch):
    config, (job,), _ = fixture(tmp_path)
    original = Path.open
    def bounded(path, *args, **kwargs):
        assert path.name == MANIFEST_NAME
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", bounded)
    assert job.identities(tmp_path)["implementation"] != "undeclared"


def test_branch_selective_force_and_repaired_job_preserve_independent_branch(tmp_path):
    config, jobs, calls = fixture(tmp_path, ("job_a", "job_b", "job_c", "job_d"))
    dependencies = {"job_a": (), "job_b": ("job_a",), "job_c": (), "job_d": ("job_b", "job_c")}
    graph = GraphRunner(config, jobs, dependencies=dependencies)
    first = graph.run(target_root=tmp_path, source_fingerprint="none")
    root = config.runtime.runs_dir / first["run_id"]
    forced = graph.plan(first["run_id"], "none", force_from="job_b")
    assert [item.action for item in forced] == ["REUSE", "RUN", "REUSE", "INVALIDATE"]
    old = (root / "data/configuration/resolved.json").read_bytes()
    old_claim = (root / "data/jobs/job_b/attempts/attempt_0001/claim.json").read_bytes()
    (tmp_path / "release-src/job_b/job.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (job.job_id for job in jobs))
    plan = plan_repair(config, root, jobs, "none", dependencies=dependencies)
    assert plan["admissible"] is True
    assert [item["action"] for item in plan["decisions"]] == ["REUSE", "RUN", "REUSE", "INVALIDATE"]
    assert canonical_json(plan) == canonical_json(plan_repair(config, root, jobs, "none", dependencies=dependencies))
    with pytest.raises(ValueError, match="plan-repair"):
        graph.run(target_root=tmp_path, source_fingerprint="none", run_id=first["run_id"])
    binding = admit_repair(config, root, jobs, plan, dependencies=dependencies)
    assert binding["repair"]
    second = graph.run(target_root=tmp_path, source_fingerprint="none", run_id=first["run_id"])
    assert [item["action"] for item in second["decisions"]] == ["REUSE", "RUN", "REUSE", "INVALIDATE"]
    assert old == (root / "data/configuration/resolved.json").read_bytes()
    assert old_claim == (root / "data/jobs/job_b/attempts/attempt_0001/claim.json").read_bytes()
    assert calls.count(("job_c", "work.only", "attempt_0001")) == 1
    assert len(calls) == 6


def test_failed_job_does_not_fall_back_to_older_accepted_attempt(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    runner = JobRunner(config)
    first = runner.run(job)
    def fail(context):
        raise RuntimeError("reproduce")
    with pytest.raises(RuntimeError, match="partial failure"):
        runner.run(replace(job, units=(Unit("work.only", fail),)), run_id=first["status"]["run_id"])
    root = config.runtime.runs_dir / first["status"]["run_id"]
    reasons, _ = ResumePlanner(config, root, (job,), "none").accepted(job, {})
    assert reasons == ("a newer unaccepted attempt supersedes the accepted job",)


def test_successful_portable_unit_is_admitted_into_fresh_attempt(tmp_path):
    config, (job,), calls = fixture(tmp_path)
    def bad(context):
        raise RuntimeError("external boundary failed")
    broken = replace(job, units=(*job.units, Unit("work.bad", bad)))
    runner = JobRunner(config)
    with pytest.raises(RuntimeError, match="partial failure"):
        runner.run(broken)
    root = next(path for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")
    old = root / "data/jobs/job_fixture/attempts/attempt_0001"
    old_claim = (old / "claim.json").read_bytes()
    fixed = replace(job, units=(*job.units, Unit("work.bad", lambda context: {"fixed": True})))
    plan = plan_repair(config, root, (fixed,), "none")
    assert plan["unit_decisions"]["job_fixture"]["work.only"]["action"] == "REUSE"
    assert plan["unit_decisions"]["job_fixture"]["work.bad"]["action"] == "RUN"
    admit_repair(config, root, (fixed,), plan)
    result = runner.run(fixed, run_id=root.name)
    assert result["status"]["attempt_id"] == "attempt_0002"
    assert len(calls) == 1
    assert (old / "claim.json").read_bytes() == old_claim
    assert json.loads((old / "status.json").read_bytes())["status"] == "FAILED"


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_checkpoint_corruption_fails_closed(tmp_path, damage):
    config, (job,), _ = fixture(tmp_path)
    def fail(context):
        raise RuntimeError("failed")
    broken = replace(job, units=(*job.units, Unit("work.bad", fail)))
    with pytest.raises(RuntimeError):
        JobRunner(config).run(broken)
    root = next(path for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")
    path = root / "data/jobs/job_fixture/attempts/attempt_0001/steps/work/tasks/only/result.json"
    path.unlink() if damage == "missing" else path.write_text("{}")
    plan = plan_repair(config, root, (broken,), "none")
    assert plan["unit_decisions"]["job_fixture"]["work.only"]["action"] == "RUN"


@pytest.mark.parametrize("stage", ["status", "latest", "published"])
def test_failed_publication_stage_never_reuses_partial_handoff(tmp_path, monkeypatch, stage):
    import appsec_review.runtime.runner as module
    config, (job,), _ = fixture(tmp_path)
    original = module.atomic_json
    fired = False
    def write(path, value):
        nonlocal fired
        match = (stage == "status" and path.name == "status.json" and value.get("status") == "SUCCEEDED"
                 and "job_id" in value or stage == "latest" and path.name == "latest.json"
                 or stage == "published" and path.name == "published.json")
        if match and not fired:
            fired = True
            raise OSError("publication interruption")
        return original(path, value)
    monkeypatch.setattr(module, "atomic_json", write)
    with pytest.raises(OSError, match="publication interruption"):
        JobRunner(config).run(job)
    root = next(path for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")
    assert ResumePlanner(config, root, (job,), "none").plan(emit_event=False)[0].action == "RUN"
    attempt = root / "data/jobs/job_fixture/attempts/attempt_0001"
    assert json.loads((attempt / "status.json").read_bytes())["status"] == "FAILED"
    assert not (attempt / "published.json").exists()


def test_missing_commit_marker_refuses_even_an_otherwise_valid_handoff(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    result = JobRunner(config).run(job)
    (Path(result["attempt_root"]) / "published.json").unlink()
    root = config.runtime.runs_dir / result["status"]["run_id"]
    reasons, _ = ResumePlanner(config, root, (job,), "none").accepted(job, {})
    assert reasons and "corrupt" in reasons[0]


def test_config_schema_and_unknown_release_refuse_repair(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    outcome = JobRunner(config).run(job)
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    changed = replace(config, resolved_sha256="f" * 64)
    plan = plan_repair(changed, root, (job,), "none")
    assert not plan["admissible"]
    assert any("frozen configuration" in reason for reason in plan["refusals"])
    assert not plan_repair(config, root, (replace(job, schema_identity="new"),), "none")["admissible"]
    (tmp_path / MANIFEST_NAME).unlink()
    assert not plan_repair(config, root, (job,), "none")["admissible"]


def test_historical_run_requires_explicit_rerun_and_supports_successor(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    (tmp_path / MANIFEST_NAME).unlink()
    result = JobRunner(config).run(job)
    root = config.runtime.runs_dir / result["status"]["run_id"]
    write_release(tmp_path, (job.job_id,))
    assert not plan_repair(config, root, (job,), "none")["admissible"]
    plan = plan_repair(config, root, (job,), "none", historical_rerun=True, successor=True)
    assert plan["admissible"]
    result = admit_repair(config, root, (job,), plan)
    assert result["successor_run_id"] != root.name
    assert result["imported_successes"] == []
    assert root.exists()
    successor = config.runtime.runs_dir / result["successor_run_id"]
    assert (successor / "data/configuration/resolved.json").read_bytes() == (
        root / "data/configuration/resolved.json").read_bytes()


def test_active_workers_and_cleanup_uncertainty_refuse(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    result = JobRunner(config).run(job)
    root = config.runtime.runs_dir / result["status"]["run_id"]
    with worker_scope(config, root):
        assert "a registered worker is still active" in stopped_reasons(config, root)
        assert not plan_repair(config, root, (job,), "none")["admissible"]
    ledger = config.runtime.metadata_dir / "resource-admission/leases.json"
    atomic_json(ledger, {"schema": "appsec-review/resource-leases/1",
                         "leases": {"x": {"quarantine": "cleanup uncertain"}}})
    assert any("leases" in value for value in stopped_reasons(config, root))


def test_failure_manifest_is_reference_only_and_redacts_environment(tmp_path, monkeypatch):
    config, (job,), _ = fixture(tmp_path)
    monkeypatch.setenv("MODEL_TOKEN", "do-not-disclose")
    def fail(context):
        raise RuntimeError("do-not-disclose")
    with pytest.raises(RuntimeError):
        JobRunner(config).run(replace(job, units=(Unit("work.only", fail),)))
    root = next(path for path in config.runtime.runs_dir.iterdir() if path.name != "metadata")
    value = failure_manifest(config, root, job.job_id, "attempt_0001")
    assert "do-not-disclose" not in json.dumps(value)
    assert value["automatic_execution"] is False
    assert any(item["path"].endswith("traceback.txt") for item in value["references"])
    assert value["environment_requirements"][-1] == {"name": "MODEL_TOKEN", "value": "[REDACTED]"}


def test_concurrent_or_stale_repair_claims_are_rejected(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    result = JobRunner(config).run(job)
    root = config.runtime.runs_dir / result["status"]["run_id"]
    plan = plan_repair(config, root, (job,), "none", force_from=job.job_id)
    with FileLock(root / "data/recovery/admission.lock"):
        with pytest.raises(LockUnavailable):
            admit_repair(config, root, (job,), plan)
    admit_repair(config, root, (job,), plan)
    with pytest.raises(ValueError, match="changed"):
        admit_repair(config, root, (job,), plan)


def test_two_concurrent_repair_claimants_have_one_winner(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    outcome = JobRunner(config).run(job)
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    plan = plan_repair(config, root, (job,), "none", force_from=job.job_id)
    barrier = threading.Barrier(2)
    results = []
    def claim():
        barrier.wait()
        try:
            admit_repair(config, root, (job,), plan)
            results.append("admitted")
        except (ValueError, LockUnavailable):
            results.append("refused")
    workers = [threading.Thread(target=claim) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(10)
        assert not worker.is_alive()
    assert sorted(results) == ["admitted", "refused"]


@pytest.mark.parametrize("status", ["RUNNING", "UNKNOWN", "FAILED"])
def test_launcher_stop_must_be_verified_not_asserted(tmp_path, status):
    from appsec_review.runtime.repair import verify_dispatch_stop
    config, (job,), _ = fixture(tmp_path)
    outcome = JobRunner(config).run(job)
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    instance = SimpleNamespace(
        get_run_by_id=lambda run_id: SimpleNamespace(tags={"appsec/application_run_id": root.name},
                                                     is_finished=True),
        run_launcher=SimpleNamespace(supports_check_run_worker_health=True,
            check_run_worker_health=lambda run: SimpleNamespace(status=SimpleNamespace(value=status))))
    with pytest.raises(ValueError, match="unconfirmed"):
        verify_dispatch_stop(config, root, "fixture-dispatch", instance=instance)
    instance.run_launcher.supports_check_run_worker_health = False
    with pytest.raises(ValueError, match="cannot verify"):
        verify_dispatch_stop(config, root, "fixture-dispatch", instance=instance)
    assert not (root / "data/recovery/dispatches/fixture-dispatch.json").exists()


def test_native_cancellation_is_not_silently_enabled(tmp_path, monkeypatch):
    from appsec_review.config import native_dagster
    config, (job,), _ = fixture(tmp_path)
    outcome = JobRunner(config).run(job)
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    monkeypatch.setattr(native_dagster, "native_execution_requested", lambda: True)
    plan = plan_repair(config, root, (job,), "none")
    assert not plan["admissible"]
    assert any("not commissioned" in reason for reason in plan["refusals"])


def test_checkpoint_reuse_is_never_implicit_on_a_new_attempt(tmp_path):
    config, (job,), calls = fixture(tmp_path)
    def fail(context):
        raise RuntimeError("transient")
    broken = replace(job, units=(*job.units, Unit("work.bad", fail)))
    with pytest.raises(RuntimeError):
        JobRunner(config).run(broken)
    root, = config.runtime.runs_dir.glob("????-??-??-????")
    JobRunner(config).run(job, run_id=root.name)
    assert len(calls) == 2


def test_plan_is_read_only_and_contains_exact_input_snapshots(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    outcome = JobRunner(config).run(job)
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    before = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    plan = plan_repair(config, root, (job,), "none")
    after = {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert before == after
    assert plan["attempt_snapshots"]["job_fixture"]["claim"]["sha256"]


@pytest.mark.parametrize("output", [
    {"terminal_status": "FAILED"}, {"retry_required": True}, {"path": "somewhere"},
    {"budget": {"spent": 1}}, {"value": "/attempt-owned/file"},
])
def test_path_state_and_retriable_results_are_not_portable(output):
    from appsec_review.runtime.checkpoints import portable
    assert not portable(output)
    assert portable({"terminal_status": "COMPLETED_WITH_GAPS", "gaps": ["explicit missing coverage"]})


def test_safety_successor_waits_for_fresh_authorized_envelope(tmp_path):
    from uuid import uuid4
    from appsec_review.runtime.execution_safety import policy
    from appsec_review.runtime.repair import check_successor
    config, (job,), _ = fixture(tmp_path)
    outcome = JobRunner(config).run(job)
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    submission = {"source_commit": "a" * 40, "target_commit": "b" * 40, "configuration": {}}
    envelope = policy(str(uuid4()), submission)
    atomic_json(root / "data/configuration/execution-safety.json", envelope)
    atomic_json(config.runtime.metadata_dir / "dagster-safety" / f"{envelope['dagster_run_id']}.json", {
        "policy": envelope, "application_run_id": root.name, "status": "STOPPED",
        "active": {}, "completed_at": "fixture-completed", "cancellation": "NOT_REQUESTED"})
    assert not plan_repair(config, root, (job,), "none")["admissible"]
    plan = plan_repair(config, root, (job,), "none", successor=True)
    assert plan["admissible"]
    result = admit_repair(config, root, (job,), plan)
    successor = config.runtime.runs_dir / result["successor_run_id"]
    assert result["requires_execution_safety"]
    assert not (successor / "data/configuration/manifest.json").exists()
    for value in (None, envelope):
        with pytest.raises(ValueError, match="fresh authorized"):
            check_successor(config, successor, value)
    check_successor(config, successor, policy(str(uuid4()), submission))


def test_inspected_checkpoint_cannot_change_after_new_attempt_claim(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    def fail(context):
        raise RuntimeError("failed")
    broken = replace(job, units=(*job.units, Unit("work.bad", fail)))
    runner = JobRunner(config)
    with pytest.raises(RuntimeError):
        runner.run(broken)
    root, = config.runtime.runs_dir.glob("????-??-??-????")
    plan = plan_repair(config, root, (broken,), "none")
    admit_repair(config, root, (broken,), plan)
    claim = runner.begin_attempt(broken, run_id=root.name)
    assert claim["unit_reuse"]["work.only"]["action"] == "REUSE"
    old_result = root / "data/jobs/job_fixture/attempts/attempt_0001/steps/work/tasks/only/result.json"
    old_result.write_text('{"changed": true}\n')
    with pytest.raises(ValueError):
        runner.execute_or_reuse_unit(broken, claim, "work.only")
    assert not (root / claim["attempt_path"] / "published.json").exists()

def test_partial_repair_publication_does_not_change_binding(tmp_path, monkeypatch):
    import appsec_review.runtime.repair as repair
    config, (job,), _ = fixture(tmp_path)
    result = JobRunner(config).run(job)
    root = config.runtime.runs_dir / result["status"]["run_id"]
    old = current_binding(root)
    plan = plan_repair(config, root, (job,), "none", force_from=job.job_id)
    def interrupted(*args, **kwargs):
        raise OSError("admission commit interrupted")
    monkeypatch.setattr(repair, "atomic_json", interrupted)
    with pytest.raises(OSError):
        admit_repair(config, root, (job,), plan)
    assert current_binding(root) == old


def test_cli_can_force_post_index_jobs_and_exposes_nonexecuting_recovery():
    from appsec_review.cli import POST_INDEX_JOB_IDS, parser
    for job_id in POST_INDEX_JOB_IDS:
        args = parser().parse_args(["plan-resume", "--run-id", "2026-11-06-0001",
                                    "--target", ".", "--force-from", job_id])
        assert args.force_from == job_id
    assert parser().parse_args(["failure-replay", "--run-id", "2026-11-06-0001",
                                "--job-id", "job_fixture", "--attempt-id", "attempt_0001"]).command == "failure-replay"
