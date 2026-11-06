"""Manual only: real local/Dagster lifecycle and crash boundaries, no live inference."""
from dataclasses import replace
import json
import multiprocessing
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.runtime import JobRunner, Unit
from appsec_review.runtime.repair import admit_repair, plan_repair, verify_dispatch_stop
from appsec_review.runtime.resume import ResumePlanner
from tests.release_support import write_release
from tests.test_repair_admission import fixture


def _crash_at_pointer(config_path: str) -> None:
    import appsec_review.runtime.runner as module
    from appsec_review.runtime import Job
    config = load_config(Path(config_path))
    def handler(context):
        return {"value": 1}
    original = module.atomic_json
    def publish(path, value):
        original(path, value)
        if path.name == "latest.json":
            os._exit(71)
    module.atomic_json = publish
    JobRunner(config).run(Job("job_fixture", "fixture", handler, units=(Unit("work.only", handler),)))


def test_process_interruption_between_pointer_and_commit_is_not_admitted(tmp_path):
    config, (job,), _ = fixture(tmp_path)
    process = multiprocessing.get_context("spawn").Process(
        target=_crash_at_pointer, args=(str(config.source_path),))
    process.start()
    process.join(30)
    if process.is_alive():
        process.terminate()
        process.join()
        pytest.fail("bounded publication worker did not reach its interruption point")
    assert process.exitcode == 71
    root, = config.runtime.runs_dir.glob("????-??-??-????")
    reasons, _ = ResumePlanner(config, root, (job,), "none").accepted(job, {})
    assert reasons
    assert not (root / "data/jobs/job_fixture/attempts/attempt_0001/published.json").exists()


def test_real_dagster_failure_then_admitted_local_repair(tmp_path, monkeypatch):
    from appsec_review.orchestration.dagster.adapter import build_definitions
    from appsec_review.runtime.registry import JobRegistry
    from appsec_review.reporting import telemetry_finalize
    monkeypatch.setattr(telemetry_finalize, "render_telemetry_report", lambda *args, **kwargs: None)
    config, (job,), _ = fixture(tmp_path)
    with config.source_path.open("a") as stream:
        stream.write("\n[jobs.job_fixture.steps.work.tasks.only]\nworkers = 1\n"
                     "\n[jobs.job_fixture.steps.work.tasks.failure]\nworkers = 1\n")
    config = load_config(config.source_path)
    def fail(context):
        raise RuntimeError("deterministic external failure")
    broken = replace(job, units=(*job.units, Unit("work.failure", fail)))
    registry = JobRegistry()
    registry.register(job.job_id, lambda: broken)
    dagster_job = build_definitions(config.source_path, registry=registry).get_job_def("fixture")
    result = dagster_job.execute_in_process(raise_on_error=False)
    assert not result.success
    root, = config.runtime.runs_dir.glob("????-??-??-????")
    fixed = replace(job, units=(*job.units, Unit("work.failure", lambda context: {"fixed": True})))
    assert not plan_repair(config, root, (fixed,), "none")["admissible"]
    # Only the external launcher health boundary is faked: execute_in_process returned.
    stopped = SimpleNamespace(
        get_run_by_id=lambda run_id: SimpleNamespace(
            tags={"appsec/application_run_id": root.name}, is_finished=run_id == result.run_id),
        run_launcher=SimpleNamespace(
            supports_check_run_worker_health=True,
            check_run_worker_health=lambda run: SimpleNamespace(status=SimpleNamespace(value="SUCCESS"))))
    verify_dispatch_stop(config, root, result.run_id, instance=stopped)
    plan = plan_repair(config, root, (fixed,), "none")
    assert plan["admissible"]
    admit_repair(config, root, (fixed,), plan)
    repaired = JobRunner(config).run(fixed, run_id=root.name)
    assert repaired["status"]["attempt_id"] == "attempt_0002"
    assert repaired["result"]["outputs"]["work.only"] == {"value": 7}
    assert json.loads((root / "data/jobs/job_fixture/attempts/attempt_0001/status.json").read_bytes())["status"] == "FAILED"


def test_repaired_shared_dependency_invalidates_both_drivers(tmp_path):
    from appsec_review.runtime.launch import LaunchInputs, launch
    config, (job,), _ = fixture(tmp_path)
    first = JobRunner(config).run(job)
    root = config.runtime.runs_dir / first["status"]["run_id"]
    (tmp_path / "release-src/shared.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (job.job_id,))
    with pytest.raises(ValueError, match="implementation changed"):
        launch(JobRunner(config), job, LaunchInputs(None, "none"), run_id=root.name)
    plan = plan_repair(config, root, (job,), "none")
    assert plan["decisions"][0]["action"] == "RUN"
    admit_repair(config, root, (job,), plan)
    second = launch(JobRunner(config), job, LaunchInputs(None, "none"), run_id=root.name)
    assert second["status"]["attempt_id"] == "attempt_0002"
