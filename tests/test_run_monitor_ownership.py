from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from appsec_review.observability.events import PipelineLog
from appsec_review.observability.monitor import poll_run
from tests.test_run_monitor import DAGSTER, configured
from tests.test_run_monitor_epochs import OTHER, select


def event(root, kind, job="-", attempt="-", *, owner=None, nested=False, **details):
    if owner is not None:
        if nested:
            details["orchestration"] = {"system": "dagster", "run_id": owner}
        else:
            details["dagster_run_id"] = owner
    return PipelineLog(root).write(kind, run_id=root.name, job_id=job, attempt_id=attempt,
                                    orchestrator="dagster" if owner is not None else "application",
                                    details=details)


@pytest.mark.parametrize("explicit", [False, True], ids=["inferred", "explicit"])
@pytest.mark.parametrize("graph_state", ["valid", "missing", "invalid"])
def test_effective_dispatch_always_requires_owned_terminal(tmp_path, explicit, graph_state):
    configured(tmp_path, graph=False)
    event(tmp_path, "RUN_STARTED", owner=DAGSTER)
    if graph_state != "missing":
        ref = select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=DAGSTER)
        if graph_state == "invalid":
            (tmp_path / ref["path"]).write_text("{}")
    event(tmp_path, "RUN_COMPLETED", completion_status="SUCCEEDED")
    kwargs = {"dagster_run_id": DAGSTER} if explicit else {}
    report = poll_run(tmp_path, **kwargs)
    assert not report["state"]["terminal_confirmed"]
    assert report["state"]["status"] != "SUCCEEDED"
    event(tmp_path, "RUN_COMPLETED", owner=DAGSTER, completion_status="SUCCEEDED")
    positive = poll_run(tmp_path, **kwargs)
    assert positive["state"]["terminal_confirmed"] is (graph_state == "valid")


@pytest.mark.parametrize("explicit", [False, True], ids=["inferred", "explicit"])
def test_actual_fresh_adapter_order_keeps_initial_admission_and_progress(tmp_path, explicit):
    from dagster import DagsterRun
    from appsec_review.config import load_config
    from appsec_review.orchestration.dagster.adapter import _build_dagster_graph
    from appsec_review.runtime import Job, JobRunner, Unit
    from tests.test_repair_admission import fixture

    config, _, _ = fixture(tmp_path, ("job_a", "job_b"))
    with config.source_path.open("a") as stream:
        for job in ("job_a", "job_b"):
            stream.write(f"\n[jobs.{job}.steps.work.tasks.only]\nworkers = 1\n")
    config = load_config(config.source_path)
    during_task = []
    kwargs = {"dagster_run_id": DAGSTER} if explicit else {}

    def produce(unit):
        during_task.append(poll_run(unit.job.run_root, **kwargs))
        return {"value": 7}

    jobs = tuple(Job(job, job, produce, units=(Unit("work.only", produce),)) for job in ("job_a", "job_b"))
    definition = _build_dagster_graph(
        "monitor_fresh_order", jobs, config, JobRunner, job_dependencies={"job_a": (), "job_b": ("job_a",)})
    begin = definition.graph.node_named("a__begin").definition
    run = DagsterRun(job_name=definition.name, run_id=DAGSTER)
    # Only Dagster's metadata/tag sinks are external fakes; execute the actual adapter and JobRunner.
    context = SimpleNamespace(job_def=definition, dagster_run=run, run_id=DAGSTER, op=begin,
                              instance=SimpleNamespace(add_run_tags=Mock()), add_output_metadata=Mock())
    claim = begin.compute_fn.decorated_fn(context)
    runner = JobRunner(config)
    root = runner.runs.resolve(claim["run_id"])
    events, _ = PipelineLog(root).read()
    kinds = [row["event_type"] for row in events]
    assert kinds.index("RUN_STARTED") < kinds.index("JOB_STARTED") < kinds.index("RUN_GRAPH_SNAPSHOT")
    initial = poll_run(root, save=True, **kwargs)
    assert (initial["state"]["jobs"]["running"], initial["state"]["jobs"]["remaining"]) == (1, 1)
    assert initial["state"]["run_epoch_sequence"] == next(
        row["sequence"] for row in events if row["event_type"] == "RUN_STARTED")
    runner.execute_or_reuse_unit(jobs[0], claim, "work.only")
    assert during_task[0]["state"]["current_steps"][0]["task"] == "only"
    runner.finalize_attempt(jobs[0], claim)
    final = poll_run(root, **kwargs)
    assert (final["state"]["jobs"]["completed"], final["state"]["jobs"]["remaining"]) == (1, 1)
    assert "prior_epoch_job_event_without_current_admission" not in final["state"]["gaps"]


@pytest.mark.parametrize("kind", ["JOB_STARTED", "JOB_QUEUED", "JOB_REUSED"])
@pytest.mark.parametrize("ownership", ["foreign", "missing", "current"])
def test_current_admission_and_reuse_require_same_dispatch(tmp_path, kind, ownership):
    configured(tmp_path, graph=False)
    event(tmp_path, "RUN_STARTED", owner=DAGSTER)
    select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=DAGSTER)
    event(tmp_path, "JOB_STARTED", "job_a", "attempt-1", owner=DAGSTER, nested=True)
    event(tmp_path, "JOB_SUCCEEDED", "job_a", "attempt-1", owner=DAGSTER)
    event(tmp_path, "RUN_COMPLETED", owner=DAGSTER, completion_status="SUCCEEDED")
    select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=OTHER)
    owner = {"foreign": DAGSTER, "missing": None, "current": OTHER}[ownership]
    event(tmp_path, kind, "job_a", "attempt-1", owner=owner, nested=True)
    report = poll_run(tmp_path, dagster_run_id=OTHER)
    state = report["state"]
    if ownership == "current":
        assert state["epoch_attempts"]["total_observed"] == 1
        if kind == "JOB_REUSED":
            assert state["jobs"]["completed"] == 1 and state["epoch_attempts"]["reused"] == 1
    else:
        assert state["jobs"]["completed"] == 0 and state["jobs"]["running"] == 0
        assert state["epoch_attempts"]["total_observed"] == 0
        assert state["epoch_attempts"]["reused_observed"] == 0
        assert not state["jobs"]["accounting_complete"] and state["gaps"]


def test_foreign_progress_cannot_override_owned_attempt(tmp_path):
    configured(tmp_path, graph=False)
    event(tmp_path, "RUN_STARTED", owner=OTHER)
    select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=OTHER)
    event(tmp_path, "JOB_STARTED", "job_a", "attempt-1", owner=OTHER, nested=True)
    event(tmp_path, "JOB_SUCCEEDED", "job_a", "attempt-1", owner=DAGSTER)
    report = poll_run(tmp_path, dagster_run_id=OTHER)
    assert report["state"]["jobs"]["running"] == 1 and report["state"]["jobs"]["completed"] == 0
    # Real EventLog task/job terminals omit per-event UUIDs; the owned current attempt supplies it.
    event(tmp_path, "JOB_SUCCEEDED", "job_a", "attempt-1")
    assert poll_run(tmp_path, dagster_run_id=OTHER)["state"]["jobs"]["completed"] == 1


@pytest.mark.parametrize("nested_owner", [DAGSTER, "invalid-dispatch"], ids=["conflicting", "invalid"])
def test_conflicting_or_invalid_identity_cannot_inherit_admission(tmp_path, nested_owner):
    configured(tmp_path, graph=False)
    event(tmp_path, "RUN_STARTED", owner=OTHER)
    select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=OTHER)
    event(tmp_path, "JOB_STARTED", "job_a", "attempt-1", owner=OTHER, nested=True)
    event(tmp_path, "JOB_SUCCEEDED", "job_a", "attempt-1", owner=OTHER,
          orchestration={"system": "dagster", "run_id": nested_owner, "workflow": "PRIVATE_SCOPE_PROSE"})
    report = poll_run(tmp_path, dagster_run_id=OTHER, save=True)
    assert report["state"]["jobs"]["completed"] == 0 and report["state"]["jobs"]["running"] == 1
    assert "progress_dispatch_identity_unconfirmed" in report["state"]["gaps"]
    assert "PRIVATE_SCOPE_PROSE" not in (tmp_path / "data/telemetry/monitor/checkpoint.json").read_text()


def test_late_old_graph_metadata_does_not_reopen_closed_foreign_scope(tmp_path):
    configured(tmp_path)
    event(tmp_path, "RUN_COMPLETED", owner=DAGSTER, completion_status="SUCCEEDED")
    select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=OTHER)
    event(tmp_path, "JOB_STARTED", "job_a", "attempt-1", owner=OTHER, nested=True)
    epoch = poll_run(tmp_path)["state"]["run_epoch_sequence"]
    select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=DAGSTER)
    report = poll_run(tmp_path)
    assert report["dagster_run_id"] == OTHER and report["state"]["run_epoch_sequence"] == epoch
    assert report["state"]["jobs"]["running"] == 1
    assert "late_foreign_dispatch_boundary_ignored" in report["gaps"]


def test_snapshot_uuid_without_matching_emitter_is_not_application_authority(tmp_path):
    configured(tmp_path, graph=False, dagster_run_id=None)
    ref = select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=DAGSTER)
    # Contradictory emitter ownership cannot turn a failed binding into a direct application success.
    event(tmp_path, "RUN_STARTED")
    event(tmp_path, "GRAPH_STARTED", graph_reference=ref)
    event(tmp_path, "RUN_COMPLETED", completion_status="SUCCEEDED")
    report = poll_run(tmp_path)
    assert report["dagster_run_id"] == DAGSTER
    assert not report["state"]["terminal_confirmed"] and report["state"]["status"] != "SUCCEEDED"
