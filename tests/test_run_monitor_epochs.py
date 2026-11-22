from __future__ import annotations

import hashlib
import json

import pytest

from appsec_review.observability.events import PipelineLog
from appsec_review.observability.monitor import MonitorFollower, poll_run, render_report
from appsec_review.observability.monitor_inputs import freeze_run_graph
from appsec_review.storage import canonical_json
from tests.test_run_monitor import DAGSTER, configured, emit

OTHER = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def select(root, jobs, *, dispatch=None, partial=()):
    config = json.loads((root / "data/configuration/manifest.json").read_bytes())
    binding = json.loads((root / "data/recovery/current.json").read_bytes())
    ref = freeze_run_graph(
        root, {job: () for job in jobs}, config_sha256=config["resolved_sha256"],
        profile=config["selection"]["profile"], source_sha256=binding["release_sha256"],
        dagster_run_id=dispatch, partial_jobs=partial)
    emit(root, "RUN_GRAPH_SNAPSHOT", graph_reference=ref, dagster_run_id=dispatch)
    return ref


@pytest.mark.parametrize("graph_state", ["matching", "missing", "corrupt", "unbound", "other"])
def test_explicit_dispatch_terminal_requires_positive_graph_binding(tmp_path, graph_state):
    configured(tmp_path, graph=graph_state != "missing")
    if graph_state == "corrupt":
        next((tmp_path / "data/configuration/graphs").glob("*.json")).write_text("{}")
    elif graph_state == "unbound":
        select(tmp_path, ("job_a", "job_b", "job_c"))
    emit(tmp_path, "RUN_COMPLETED", completion_status="SUCCEEDED", dagster_run_id=DAGSTER)
    requested = DAGSTER if graph_state == "matching" else OTHER
    report = poll_run(tmp_path, dagster_run_id=requested)
    if graph_state == "matching":
        assert report["state"]["terminal_confirmed"] and report["state"]["status"] == "SUCCEEDED"
    else:
        assert not report["state"]["terminal_confirmed"]
        assert report["state"]["status"] == "UNKNOWN" and not report["coverage"]["complete"]
        assert any(gap.startswith("dagster_graph_identity_") for gap in report["gaps"])


@pytest.mark.parametrize("graph_state", ["missing", "unbound"])
def test_default_monitor_does_not_adopt_unbound_dispatch_terminal(tmp_path, graph_state):
    configured(tmp_path, graph=False, dagster_run_id=None)
    if graph_state == "unbound":
        select(tmp_path, ("job_a", "job_b", "job_c"))
    emit(tmp_path, "RUN_COMPLETED", completion_status="SUCCEEDED", dagster_run_id=DAGSTER)
    report = poll_run(tmp_path)
    assert not report["state"]["terminal_confirmed"]
    assert report["state"]["gaps"]["terminal_dispatch_identity_unconfirmed"] == 1
    assert report["dagster_run_id"] is None


def test_matching_new_dispatch_does_not_inherit_late_old_terminal(tmp_path):
    configured(tmp_path)
    emit(tmp_path, "RUN_COMPLETED", completion_status="SUCCEEDED", dagster_run_id=DAGSTER)
    select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=OTHER)
    emit(tmp_path, "JOB_STARTED", "job_a", "attempt-2", dagster_run_id=OTHER)
    emit(tmp_path, "RUN_COMPLETED", completion_status="SUCCEEDED", dagster_run_id=DAGSTER)
    waiting = poll_run(tmp_path, dagster_run_id=OTHER)
    assert not waiting["state"]["terminal_confirmed"]
    assert waiting["state"]["status"] == "ACTIVE_UNCONFIRMED"
    assert waiting["state"]["gaps"]["terminal_dispatch_identity_unconfirmed"] == 1
    epoch = waiting["state"]["run_epoch_sequence"]
    # Another begin's identical metadata must not let the old terminal reset the current epoch.
    select(tmp_path, ("job_a", "job_b", "job_c"), dispatch=OTHER)
    assert poll_run(tmp_path, dagster_run_id=OTHER)["state"]["run_epoch_sequence"] == epoch
    emit(tmp_path, "RUN_COMPLETED", completion_status="FAILED", dagster_run_id=OTHER)
    finished = poll_run(tmp_path, dagster_run_id=OTHER)
    assert finished["state"]["terminal_confirmed"] and finished["state"]["status"] == "FAILED"


def test_real_forced_restart_requires_current_admission_for_each_prior_job(tmp_path):
    from appsec_review.inference.execution import CallContext, Execution
    from appsec_review.runtime import GraphRunner, Job, Unit
    from tests.test_bounded_execution import answer, request
    from tests.test_repair_admission import fixture

    config, _, _ = fixture(tmp_path, ("job_a", "job_b"))
    snapshots = []

    def produce(unit):
        if unit.job.attempt_id == "attempt_0001" and unit.job.config.job_id == "job_a":
            engine = Execution(timeout_seconds=10, max_calls=1, context=CallContext(
                unit.job.run_root, unit.job.run_id, "job_a", unit.job.attempt_id, "work", "only"))
            engine.call(lambda *_args, **_kwargs: answer(), request(), timeout_seconds=10)
        if unit.job.attempt_id == "attempt_0002" and unit.job.config.job_id == "job_a":
            snapshots.append(poll_run(unit.job.run_root))
        return {"value": 7}

    jobs = tuple(Job(job_id, job_id, produce, units=(Unit("work.only", produce),))
                 for job_id in ("job_a", "job_b"))
    runner = GraphRunner(config, jobs, dependencies={"job_a": (), "job_b": ("job_a",)})
    first = runner.run(target_root=tmp_path, source_fingerprint="none")
    second = runner.run(target_root=tmp_path, source_fingerprint="none", run_id=first["run_id"], force_from="job_a")
    assert second["status"] == "SUCCEEDED" and len(snapshots) == 1
    state = snapshots[0]["state"]
    assert (state["jobs"]["completed"], state["jobs"]["running"], state["jobs"]["remaining"]) == (0, 1, 1)
    assert state["jobs"]["accounting_complete"]
    assert state["attempts"]["total_observed"] == 3 and state["epoch_attempts"]["total_observed"] == 1
    assert all(row["job"] == "job_a" for row in state["current"])
    assert snapshots[0]["models"]["scope"] == "application_run_all_epochs"
    assert snapshots[0]["models"]["totals"]["fresh_calls"] == 1
    assert snapshots[0]["models"]["totals"]["usage"]["input_tokens"]["known_sum"] == 10


@pytest.mark.parametrize("selection", ["whole", "partial", "missing"])
def test_current_subset_or_missing_graph_never_uses_old_denominator(tmp_path, selection):
    configured(tmp_path, ("job_a", "job_b"))
    for job in ("job_a", "job_b"):
        emit(tmp_path, "JOB_SUCCEEDED", job, "attempt-1")
    emit(tmp_path, "RUN_COMPLETED", completion_status="SUCCEEDED")
    emit(tmp_path, "RUN_STARTED", dagster_run_id=None)
    if selection != "missing":
        select(tmp_path, ("job_a",), partial=("job_a",) if selection == "partial" else ())
    emit(tmp_path, "JOB_STARTED", "job_a", "attempt-2", dagster_run_id=None)
    report = poll_run(tmp_path)
    state = report["state"]
    assert not state["terminal_confirmed"]
    assert state["attempts"]["total_observed"] == 3 and state["epoch_attempts"]["total_observed"] == 1
    if selection == "whole":
        assert (state["jobs"]["total"], state["jobs"]["completed"], state["jobs"]["running"]) == (1, 0, 1)
        assert "observed_jobs_outside_frozen_graph" not in state["gaps"]
    else:
        assert state["jobs"]["total"] is None and state["jobs"]["completed"] is None
        assert not state["jobs"]["accounting_complete"]


@pytest.mark.parametrize("dispatch", [None, OTHER], ids=["application", "dagster"])
def test_real_direct_graph_reuse_is_observed_and_legacy_absence_is_unknown(tmp_path, dispatch):
    from appsec_review.runtime import GraphRunner
    from tests.test_repair_admission import fixture

    config, jobs, calls = fixture(tmp_path, ("job_a", "job_b"))
    runner = GraphRunner(config, jobs, dependencies={"job_a": (), "job_b": ("job_a",)})
    first = runner.run(target_root=tmp_path, source_fingerprint="none")
    call_count = len(calls)
    root = config.runtime.runs_dir / first["run_id"]
    second = runner.run(target_root=tmp_path, source_fingerprint="none", run_id=first["run_id"],
                        orchestration={"system": "dagster", "run_id": dispatch} if dispatch else None)
    assert len(calls) == call_count and all(row["action"] == "REUSE" for row in second["decisions"])
    report = poll_run(root, dagster_run_id=dispatch)
    state = report["state"]
    assert state["terminal_confirmed"] and state["jobs"]["completed"] == 2
    assert state["epoch_attempts"]["reused"] == 2 and state["attempts"]["total_observed"] == 2
    assert state["epoch_attempts"]["reused_tasks"] is None
    assert "whole_job_task_reuse_unmeasured" in state["epoch_attempts"]["reuse_gaps"]
    events, _ = PipelineLog(root).read()
    actual = [event for event in events if event["event_type"] == "JOB_REUSED"]
    assert len(actual) == 2 and all(event["details"]["completion_status"] == "SUCCEEDED" for event in actual)
    # Reproduce a historical writer: keep its real RESUME_PLANNED records but remove only the new observations.
    historical = [event for event in events if event["event_type"] != "JOB_REUSED"]
    for sequence, event in enumerate(historical, 1):
        event["sequence"] = sequence
        event["event_id"] = hashlib.sha256(f"{root.name}:{sequence}:{event['event_type']}".encode()).hexdigest()
    PipelineLog(root).path.write_bytes(b"".join(canonical_json(event) for event in historical))
    legacy = poll_run(root, dagster_run_id=dispatch)
    assert legacy["state"]["jobs"]["completed"] == 0 and not legacy["state"]["jobs"]["accounting_complete"]
    reuse = legacy["state"]["epoch_attempts"]
    assert reuse["reused"] is None and reuse["reused_tasks"] is None
    assert "planned_reuse_without_observed_consumption" in reuse["reuse_gaps"]
    assert "Historical attempts" in render_report(legacy) and "Model totals (all epochs)" in render_report(legacy)


def test_old_checkpoint_missing_structured_resume_observations_names_gap(tmp_path):
    configured(tmp_path)
    emit(tmp_path, "RESUME_PLANNED", decisions=[{"job_id": "job_a", "action": "REUSE",
                                               "handoff_sha256": "a" * 64, "reasons": ["PRIVATE_PLAN_PROSE"]}])
    follower = MonitorFollower(tmp_path)
    follower.poll()
    follower.records = {key: event for key, event in follower.records.items()
                        if event["event_type"] != "RESUME_PLANNED"}
    follower.save_checkpoint(tmp_path / "data/telemetry/monitor/checkpoint.json")
    report = poll_run(tmp_path, save=True)
    assert report["state"]["attempts"]["reused"] is None
    assert "resume_observation_coverage_incomplete" in report["state"]["attempts"]["reuse_gaps"]
    assert "PRIVATE_PLAN_PROSE" not in (tmp_path / "data/telemetry/monitor/checkpoint.json").read_text()
