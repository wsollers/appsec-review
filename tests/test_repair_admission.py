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


def _published_planning_context(tmp_path, orchestration):
    from appsec_review.jobs.job_build_environment_analysis import build_job as environment_job
    from appsec_review.jobs.job_review_intake import build_job as intake_job
    from appsec_review.jobs.job_target_analysis_plan import build_job as planning_job
    from appsec_review.jobs.job_target_catalog import build_job as catalog_job
    from tests.test_build_environment_analysis import _published

    ids = ("job_review_intake", "job_target_catalog", "job_build_environment_analysis",
           "job_target_analysis_plan", "job_cpp_compiled_analysis")
    write_release(tmp_path, ids)
    config, root, source, _ = _published(tmp_path, reusable=True, mode="first_party_managed")
    target = tmp_path / "target"
    planner = planning_job(infer=lambda *_args, **_kwargs: pytest.fail("unexpected model call"))
    output = JobRunner(config).run(planner, run_id=root.name, target_root=target,
                                   source_fingerprint=source, orchestration=orchestration)
    jobs = (intake_job(), catalog_job(), environment_job(), planner)
    return config, root, target, source, jobs, output, ids


@pytest.mark.parametrize("orchestration", [
    {"workflow": "target_analysis_plan"},
    {"workflow": "wave1_review"},
    {"workflow": "standalone"},
], ids=["single-job", "graph", "standalone"])
def test_repair_preserves_verified_planning_launch_context(tmp_path, orchestration):
    config, root, target, source, jobs, output, ids = _published_planning_context(
        tmp_path, orchestration)
    claim_path = Path(output["attempt_root"]) / "claim.json"
    original = claim_path.read_bytes()
    (tmp_path / "release-src/job_cpp_compiled_analysis/job.py").write_text("VERSION = 2\n")
    write_release(tmp_path, ids)

    plan = plan_repair(config, root, jobs, source, target_root=target)

    assert plan["admissible"], plan["refusals"]
    assert [row["action"] for row in plan["decisions"]] == ["REUSE"] * len(jobs)
    assert plan["decisions"][-1]["handoff_sha256"] == output["handoff_sha256"]
    binding = admit_repair(config, root, jobs, plan, target_root=target)
    assert binding["repair"] and claim_path.read_bytes() == original
    assert not (claim_path.parent.parent / "attempt_0002").exists()


@pytest.mark.parametrize("damage", ["claim", "environment"])
def test_repair_context_does_not_authorize_changed_claim_or_environment(tmp_path, damage):
    config, root, target, source, jobs, output, _ = _published_planning_context(
        tmp_path, {"workflow": "target_analysis_plan"})
    if damage == "claim":
        path = Path(output["attempt_root"]) / "claim.json"
        path.write_bytes(path.read_bytes() + b"\n")
        with pytest.raises(ValueError, match="identity|changed|mismatch"):
            plan_repair(config, root, jobs, source, target_root=target)
    else:
        changed = JobRunner(config).run(
            jobs[2], run_id=root.name, target_root=target, source_fingerprint=source)
        assert changed["handoff_sha256"] != output["handoff"]["upstream_handoff_sha256"][jobs[2].job_id]
        plan = plan_repair(config, root, jobs, source, target_root=target)
        assert plan["decisions"][-1]["action"] in {"RUN", "INVALIDATE"}
    assert current_binding(root)["repair"] is None


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


@pytest.mark.parametrize("stage", ["outcomes", "handoff", "validated_event", "status", "latest",
                                  "accepted_event", "published"])
def test_failed_publication_stage_never_reuses_partial_handoff(tmp_path, monkeypatch, stage):
    import appsec_review.runtime.runner as module
    config, (job,), _ = fixture(tmp_path)
    original = module.atomic_json
    original_immutable = module.immutable_bytes
    original_event = module.JobRunner._handoff_event
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
    def immutable(root, path, data):
        nonlocal fired
        if not fired and ((stage == "outcomes" and path.endswith("/outcomes.json"))
                          or (stage == "handoff" and path.endswith("/handoff.json"))):
            fired = True
            raise OSError("publication interruption")
        return original_immutable(root, path, data)
    def event(context, name, *args):
        nonlocal fired
        if not fired and ((stage == "validated_event" and name == "HANDOFF_VALIDATED")
                          or (stage == "accepted_event" and name == "HANDOFF_ACCEPTED")):
            fired = True
            raise OSError("publication interruption")
        return original_event(context, name, *args)
    monkeypatch.setattr(module, "atomic_json", write)
    monkeypatch.setattr(module, "immutable_bytes", immutable)
    monkeypatch.setattr(module.JobRunner, "_handoff_event", staticmethod(event))
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


@pytest.mark.parametrize("status", ["FAILED", "SUCCEEDED", "COMPLETED_WITH_GAPS", "RUNNING"])
def test_legacy_terminal_status_is_not_proof_that_workers_stopped(tmp_path, status):
    config, (job,), _ = fixture(tmp_path)
    outcome = JobRunner(config).run(job)
    root = config.runtime.runs_dir / outcome["status"]["run_id"]
    legacy = root / "data/jobs/job_fixture/attempts/attempt_0002"
    atomic_json(legacy / "claim.json", {
        "run_id": root.name, "job_id": job.job_id, "attempt_id": "attempt_0002",
        "orchestration": {"system": "local"}})
    atomic_json(legacy / "status.json", {"status": status})
    assert "historical worker stop state is unknown" in stopped_reasons(config, root)
    with pytest.raises(ValueError, match="historical worker stop state is unknown"):
        JobRunner(config).begin_attempt(job, run_id=root.name)


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


def test_default_run_launcher_workers_are_verified_through_the_code_server(tmp_path, monkeypatch):
    """HAL5000, first gate run: DefaultRunLauncher has no check_run_worker_health, so every relaunch after a
    failed attempt was refused. Its workers are subprocesses of the code server, whose GetCurrentRuns lists
    exactly the ones still alive; a terminal run the server no longer lists has a stopped worker."""
    from appsec_review.runtime import repair
    config, (job,), _ = fixture(tmp_path)
    outcome = JobRunner(config).run(job)
    root = config.runtime.runs_dir / outcome["status"]["run_id"]

    class DefaultRunLauncher:  # the class name is the launcher's identity; it has no health API
        supports_check_run_worker_health = False

    current_runs = ["other-dispatch"]
    monkeypatch.setattr(repair, "code_server_worker_status",
                        lambda run: "RUNNING" if run.run_id in current_runs else "NOT_FOUND")
    run = SimpleNamespace(run_id="fixture-dispatch", is_finished=True,
                          tags={"appsec/application_run_id": root.name, ".dagster/grpc_info": '{"host": "code-location", "port": 4000}'})
    instance = SimpleNamespace(get_run_by_id=lambda run_id: run, run_launcher=DefaultRunLauncher())
    receipt = repair.verify_dispatch_stop(config, root, "fixture-dispatch", instance=instance)
    assert receipt["worker_status"] == "NOT_FOUND" and receipt["terminal"] is True
    assert (root / "data/recovery/dispatches/fixture-dispatch.json").exists()
    current_runs.append("fixture-dispatch")
    with pytest.raises(ValueError, match="unconfirmed: RUNNING"):
        repair.verify_dispatch_stop(config, root, "fixture-dispatch", instance=instance)


def test_code_server_worker_status_asks_the_server_and_fails_closed():
    from appsec_review.runtime.repair import code_server_worker_status
    from dagster._grpc.types import GetCurrentRunsResult
    from dagster._serdes import serialize_value

    def client(current, error=None):
        return lambda: SimpleNamespace(get_current_runs=lambda: serialize_value(
            GetCurrentRunsResult(current_runs=current, serializable_error_info=error)))

    run = SimpleNamespace(run_id="d1", tags={".dagster/grpc_info": '{"host": "code-location", "port": 4000}'})
    assert code_server_worker_status(run, client_factory=client(["d2"])) == "NOT_FOUND"
    assert code_server_worker_status(run, client_factory=client(["d1", "d2"])) == "RUNNING"
    with pytest.raises(ValueError, match="did not answer"):
        code_server_worker_status(run, client_factory=lambda: SimpleNamespace(
            get_current_runs=lambda: (_ for _ in ()).throw(ConnectionError("refused"))))
    with pytest.raises(ValueError, match="no code-server address"):
        code_server_worker_status(SimpleNamespace(run_id="d1", tags={}), client_factory=client([]))


def test_code_server_worker_status_behind_the_proxy_uses_can_cancel_execution():
    """`dagster code-server start` fronts the server with a proxy that has no GetCurrentRuns (HAL5000:
    UNIMPLEMENTED) but forwards CanCancelExecution, answered from the fronted server's executions table."""
    from appsec_review.runtime.repair import code_server_worker_status
    from dagster._core.errors import DagsterUserCodeUnreachableError
    from dagster._grpc.types import CanCancelExecutionRequest, CanCancelExecutionResult
    from dagster._serdes import serialize_value

    def proxy(executing: set[str]):
        def unimplemented():
            raise DagsterUserCodeUnreachableError("Could not reach user code server. gRPC Error code: UNIMPLEMENTED")

        def can_cancel(request):
            assert isinstance(request, CanCancelExecutionRequest)
            return serialize_value(CanCancelExecutionResult(can_cancel=request.run_id in executing))

        return lambda: SimpleNamespace(get_current_runs=unimplemented, can_cancel_execution=can_cancel)

    run = SimpleNamespace(run_id="d1", tags={".dagster/grpc_info": '{"host": "code-location", "port": 4000}'})
    assert code_server_worker_status(run, client_factory=proxy(set())) == "NOT_FOUND"
    assert code_server_worker_status(run, client_factory=proxy({"d1"})) == "RUNNING"


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
    {"terminal_status": 7}, {"terminal_status": ""},
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


def test_repair_does_not_relabel_an_old_shared_computation_as_new_code(tmp_path):
    from appsec_review.runtime.datasets import artifact_only
    from appsec_review.storage.shared import RECEIPT_SCHEMA, SharedArtifacts, put_bytes, verify_receipt
    from appsec_review.runtime.release import digest
    config, (job,), _ = fixture(tmp_path)
    computed = []
    fingerprint = digest({"request": "same application inputs"})
    def implementation(version):
        def produce(unit):
            owner = SharedArtifacts.for_job(unit.job)
            hit = owner.lookup("fixture", fingerprint)
            if hit is None:
                computed.append(version)
                receipt = owner.computed("fixture", fingerprint, put_bytes(unit.job.run_root, str(version).encode()),
                                         computation={"request": "same application inputs"})
            else:
                _, receipt = hit
            return {"artifact": receipt}
        return produce
    declaration = artifact_only(
        "cache", "work", "inventory", RECEIPT_SCHEMA, "Fixture computations",
        artifacts=("data/jobs/job_fixture/attempts/*/shared/fixture/*.json",), reason="offline fixture")
    first_job = replace(job, units=(Unit("work.only", implementation(1)),), datasets=(declaration,))
    first = JobRunner(config).run(first_job)
    root = config.runtime.runs_dir / first["status"]["run_id"]
    (tmp_path / "release-src/shared.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (job.job_id,))
    repaired = replace(first_job, units=(Unit("work.only", implementation(2)),))
    plan = plan_repair(config, root, (repaired,), "none")
    admit_repair(config, root, (repaired,), plan)
    result = JobRunner(config).run(repaired, run_id=root.name)
    receipt = verify_receipt(root, result["result"]["outputs"]["work.only"]["artifact"])
    assert (root / receipt["object"]["path"]).read_bytes() == b"2"
    assert computed == [1, 2]


def test_missing_original_release_evidence_rejects_predecessor_reuse(tmp_path):
    config, jobs, _ = fixture(tmp_path, ("job_a", "job_b"))
    edges = {"job_a": (), "job_b": ()}
    graph = GraphRunner(config, jobs, dependencies=edges)
    first = graph.run(target_root=tmp_path, source_fingerprint="none")
    root = config.runtime.runs_dir / first["run_id"]
    old_release = current_binding(root)["release"]
    (tmp_path / "release-src/job_b/job.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (job.job_id for job in jobs))
    plan = plan_repair(config, root, jobs, "none", dependencies=edges)
    admit_repair(config, root, jobs, plan, dependencies=edges)
    (root / old_release["path"]).unlink()
    decisions = graph.plan(root.name, "none")
    assert decisions[0].action == "RUN"
    assert any("implementation release" in reason for reason in decisions[0].reasons)


def test_explicit_release_dependency_cannot_be_silently_missing(tmp_path):
    from appsec_review.runtime.release import build_release
    fixture(tmp_path)
    manifest = {"schema": "appsec-review/release-dependencies/1",
                "common": ["release-src/shared.py", "missing-runtime.lock"],
                "validators": ["release-src/validator.json"], "scripts": ["release-src/mounted.sh"],
                "job_pattern": "release-src/{job_id}/*.py"}
    with pytest.raises(ValueError, match="missing.*dependency"):
        build_release(tmp_path, manifest, ("job_fixture",))


def test_application_image_stages_declared_release_inputs():
    dockerfile = (Path(__file__).parents[1] / "deploy/dagster/Dockerfile").read_text()
    assert "COPY deploy/dagster/Dockerfile deploy/dagster/requirements*.txt ./deploy/dagster/" in dockerfile
    assert dockerfile.index("COPY deploy/dagster/Dockerfile") < dockerfile.index(
        "&& python -m appsec_review.runtime.release")


def test_compatible_shared_computation_survives_explicit_repair(tmp_path):
    from appsec_review.runtime.datasets import artifact_only
    from appsec_review.runtime.release import digest
    from appsec_review.storage.shared import RECEIPT_SCHEMA, SharedArtifacts, put_bytes, verify_receipt
    config, (job,), _ = fixture(tmp_path)
    computations = []
    def produce(unit):
        owner = SharedArtifacts.for_job(unit.job)
        key = digest({"request": "stable"})
        hit = owner.lookup("fixture", key)
        if hit is None:
            computations.append(unit.job.attempt_id)
            ref = owner.computed("fixture", key, put_bytes(unit.job.run_root, b"stable"),
                                 computation={"request": "stable"})
        else:
            _, ref = hit
        return {"artifact": ref}
    declaration = artifact_only(
        "cache", "work", "inventory", RECEIPT_SCHEMA, "Fixture computations",
        artifacts=("data/jobs/job_fixture/attempts/*/shared/fixture/*.json",), reason="offline fixture")
    job = replace(job, units=(Unit("work.only", produce),), datasets=(declaration,))
    first = JobRunner(config).run(job)
    root = config.runtime.runs_dir / first["status"]["run_id"]
    plan = plan_repair(config, root, (job,), "none", force_from=job.job_id)
    admit_repair(config, root, (job,), plan)
    second = JobRunner(config).run(job, run_id=root.name)
    receipt = verify_receipt(root, second["result"]["outputs"]["work.only"]["artifact"])
    assert receipt["mode"] == "reused"
    assert computations == ["attempt_0001"]
    assert receipt["producer_receipt"] == first["result"]["outputs"]["work.only"]["artifact"]


def test_publication_refuses_incompatible_receipt_even_when_lookup_is_bypassed(tmp_path):
    from appsec_review.runtime.datasets import artifact_only
    from appsec_review.runtime.release import digest
    from appsec_review.storage.shared import RECEIPT_SCHEMA, SharedArtifacts, put_bytes, verify_receipt
    config, (job,), _ = fixture(tmp_path)
    key = digest({"request": "stable"})
    def original(unit):
        ref = SharedArtifacts.for_job(unit.job).computed(
            "fixture", key, put_bytes(unit.job.run_root, b"old"), computation={"request": "stable"})
        return {"artifact": ref}
    declaration = artifact_only(
        "cache", "work", "inventory", RECEIPT_SCHEMA, "Fixture computations",
        artifacts=("data/jobs/job_fixture/attempts/*/shared/fixture/*.json",), reason="offline fixture")
    job = replace(job, units=(Unit("work.only", original),), datasets=(declaration,))
    first = JobRunner(config).run(job)
    root = config.runtime.runs_dir / first["status"]["run_id"]
    producer_ref = first["result"]["outputs"]["work.only"]["artifact"]
    producer = verify_receipt(root, producer_ref)
    (tmp_path / "release-src/shared.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (job.job_id,))
    def bypass(unit):
        _, ref = SharedArtifacts.for_job(unit.job)._record(
            "fixture", key, producer["object"], computation=producer["computation"],
            mode="reused", producer=producer_ref)
        return {"artifact": ref}
    changed = replace(job, units=(Unit("work.only", bypass),))
    plan = plan_repair(config, root, (changed,), "none")
    admit_repair(config, root, (changed,), plan)
    with pytest.raises(ValueError, match="incompatible"):
        JobRunner(config).run(changed, run_id=root.name)
    assert not (root / "data/jobs/job_fixture/attempts/attempt_0002/published.json").exists()
    assert json.loads((root / "data/jobs/job_fixture/latest.json").read_bytes())["handoff_sha256"] == first["handoff_sha256"]


def test_shared_producer_change_invalidates_its_real_consumer_not_an_independent_job(tmp_path):
    from appsec_review.runtime.datasets import artifact_only
    from appsec_review.runtime.release import digest
    from appsec_review.storage.shared import RECEIPT_SCHEMA, SharedArtifacts, put_bytes
    config, jobs, _ = fixture(tmp_path, ("job_a", "job_b", "job_c"))
    key = digest({"request": "shared calculation"})
    def shared(unit):
        owner = SharedArtifacts.for_job(unit.job)
        hit = owner.lookup("fixture", key)
        ref = (hit[1] if hit is not None else owner.computed(
            "fixture", key, put_bytes(unit.job.run_root, b"value"), computation={"request": "shared calculation"}))
        return {"artifact": ref}
    measured = []
    for job in jobs[:2]:
        declaration = artifact_only(
            "cache", "work", "inventory", RECEIPT_SCHEMA, "Fixture computations",
            artifacts=(f"data/jobs/{job.job_id}/attempts/*/shared/fixture/*.json",), reason="offline fixture")
        measured.append(replace(job, units=(Unit("work.only", shared),), datasets=(declaration,)))
    measured.append(jobs[2])
    edges = {job.job_id: () for job in jobs}
    graph = GraphRunner(config, measured, dependencies=edges)
    first = graph.run(target_root=tmp_path, source_fingerprint="none")
    (tmp_path / "release-src/job_a/job.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (job.job_id for job in jobs))
    decisions = graph.plan(first["run_id"], "none")
    assert [item.action for item in decisions] == ["RUN", "RUN", "REUSE"]
    assert any("cached computation from job_a" in reason for reason in decisions[1].reasons)


def test_named_cache_cannot_hide_an_incompatible_producer_as_legacy(tmp_path):
    from appsec_review.runtime.datasets import artifact_only
    from appsec_review.storage.shared import RECEIPT_SCHEMA, SharedArtifacts
    config, (job,), _ = fixture(tmp_path)
    def build(unit):
        path = unit.job.run_root / "data/indices/fixture.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"value": 1}\n')
        return {"artifact": SharedArtifacts.for_job(unit.job).named(
            "index-shard", path, computed=True, computation={"request": "fixture"})}
    declaration = artifact_only(
        "cache", "work", "inventory", RECEIPT_SCHEMA, "Fixture computations",
        artifacts=("data/jobs/job_fixture/attempts/*/shared/index-shard/*.json",), reason="offline fixture")
    job = replace(job, units=(Unit("work.only", build),), datasets=(declaration,))
    first = JobRunner(config).run(job)
    root = config.runtime.runs_dir / first["status"]["run_id"]
    (tmp_path / "release-src/shared.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (job.job_id,))
    def reuse(unit):
        return {"artifact": SharedArtifacts.for_job(unit.job).named(
            "index-shard", root / "data/indices/fixture.json", computed=False,
            computation={"request": "fixture"})}
    changed = replace(job, units=(Unit("work.only", reuse),))
    plan = plan_repair(config, root, (changed,), "none")
    admit_repair(config, root, (changed,), plan)
    with pytest.raises(RuntimeError, match="regenerate"):
        JobRunner(config).run(changed, run_id=root.name)
    assert not (root / "data/jobs/job_fixture/attempts/attempt_0002/published.json").exists()

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
