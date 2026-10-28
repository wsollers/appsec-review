from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import dagster
import pytest

from appsec_review.orchestration.dagster.error_state import (
    STEP_FAILURE_SENSOR, build_error_state_definitions, record_step_failures, step_failure_path,
)


@dagster.op(retry_policy=dagster.RetryPolicy(max_retries=1))
def syft_scan(context):
    raise TimeoutError("scanner.tool-syft admission timed out;\noutstanding leases require reconciliation")


@dagster.op
def cppcheck_scan():
    raise RuntimeError("cppcheck failed")


@dagster.op
def downstream(value):  # pragma: no cover - skipped after the upstream failure
    return value


@dagster.job(name="wave1_review")
def wave_job():
    downstream(syft_scan())
    cppcheck_scan()


@dagster.job(name="other_job")
def other_job():
    cppcheck_scan()


@pytest.fixture
def instance():
    with dagster.instance_for_test() as test_instance:
        yield test_instance


def _failed_run(instance, job, tags=None) -> str:
    result = job.execute_in_process(instance=instance, raise_on_error=False, tags=tags or {})
    assert not result.success
    return result.run_id


def test_step_failures_write_one_stable_file_per_failed_step(instance, tmp_path: Path) -> None:
    run_id = _failed_run(instance, wave_job, {"appsec/application_run_id": "2026-10-27-0001"})
    # The run finished between ticks; a cursor that tracked it while active drains it once.
    written, cursor = record_step_failures(instance, tmp_path, json.dumps({run_id: None}))

    syft = step_failure_path(tmp_path, run_id, "syft_scan", 2)
    cppcheck = step_failure_path(tmp_path, run_id, "cppcheck_scan", 1)
    assert sorted(written) == sorted([syft, cppcheck])
    assert syft == (tmp_path / "metadata" / "dagster-error-state" / run_id / "steps"
                    / "syft_scan.attempt-2.log")
    fields = dict(line.split("=", 1) for line in syft.read_text(encoding="utf-8").splitlines())
    assert fields["dagster_run_id"] == run_id
    assert fields["application_run_id"] == "2026-10-27-0001"
    assert fields["step_key"] == "syft_scan" and fields["attempt"] == "2"
    assert int(fields["event_storage_id"]) > 0 and fields["timestamp"].endswith("+00:00")
    assert fields["message"] == ("TimeoutError: scanner.tool-syft admission timed out; "
                                 "outstanding leases require reconciliation")
    assert not (tmp_path / "metadata" / "dagster-error-state" / run_id / "steps"
                / "downstream.attempt-1.log").exists()
    # The run is terminal and drained, so it is no longer tracked.
    assert json.loads(cursor) == {}


def test_step_failures_are_idempotent_across_cursor_loss(instance, tmp_path: Path) -> None:
    run_id = _failed_run(instance, wave_job)
    written, _ = record_step_failures(instance, tmp_path, json.dumps({run_id: None}))
    before = {path: path.stat().st_mtime_ns for path in written}
    again, _ = record_step_failures(instance, tmp_path, json.dumps({run_id: None}))
    assert sorted(again) == sorted(written)
    assert {path: path.stat().st_mtime_ns for path in again} == before
    assert "application_run_id=unallocated" in written[0].read_text(encoding="utf-8")


def test_step_failure_sensor_ignores_inactive_and_other_runs(instance, tmp_path: Path) -> None:
    _failed_run(instance, wave_job)
    _failed_run(instance, other_job)
    written, cursor = record_step_failures(instance, tmp_path, None)
    assert written == [] and json.loads(cursor) == {}
    assert not (tmp_path / "metadata").exists()


def test_step_failure_sensor_tracks_active_run_incrementally(instance, tmp_path: Path) -> None:
    run_id = _failed_run(instance, wave_job, {"appsec/application_run_id": "app-run"})
    terminal = instance.get_run_by_id(run_id)
    records = instance.get_records_for_run(
        run_id, of_type=dagster.DagsterEventType.STEP_FAILURE).records
    assert len(records) == 2

    class ActiveInstance:
        """Present the real run as still STARTED while exposing one failure per tick."""

        visible = 1

        def get_runs(self, filters, limit):
            assert filters.job_name == "wave1_review" and limit
            return [terminal.with_status(dagster.DagsterRunStatus.STARTED)]

        def get_run_by_id(self, wanted):  # pragma: no cover - active runs are listed
            return instance.get_run_by_id(wanted)

        def get_records_for_run(self, wanted, cursor=None, of_type=None, limit=None, ascending=True):
            if of_type != dagster.DagsterEventType.STEP_FAILURE:
                return instance.get_records_for_run(wanted, cursor=cursor, of_type=of_type, limit=limit)
            done = int(cursor or 0)
            batch = records[done:self.visible]
            return SimpleNamespace(records=batch, cursor=str(done + len(batch)), has_more=False)

    active = ActiveInstance()
    first, cursor = record_step_failures(active, tmp_path, None)
    assert len(first) == 1 and json.loads(cursor) == {run_id: "1"}
    unchanged, cursor = record_step_failures(active, tmp_path, cursor)
    assert unchanged == [] and json.loads(cursor) == {run_id: "1"}
    active.visible = 2
    second, cursor = record_step_failures(active, tmp_path, cursor)
    assert len(second) == 1 and second != first and json.loads(cursor) == {run_id: "2"}


def test_step_failure_sensor_evaluates_and_advances_cursor(instance, tmp_path: Path) -> None:
    run_id = _failed_run(instance, wave_job)
    _, sensors = build_error_state_definitions(wave_job, tmp_path)
    sensor = next(item for item in sensors if item.name == STEP_FAILURE_SENSOR)
    assert sensor.default_status is dagster.DefaultSensorStatus.RUNNING
    context = dagster.build_sensor_context(instance=instance, cursor=json.dumps({run_id: None}))
    result = sensor.evaluate_tick(context)
    assert not result.run_requests
    assert "recorded 2" in result.skip_message
    assert json.loads(result.cursor) == {}
    assert len(list((tmp_path / "metadata" / "dagster-error-state" / run_id / "steps").iterdir())) == 2


def test_unsafe_step_keys_are_sanitized() -> None:
    path = step_failure_path(Path("runs"), "run", "scan[a/b c]", 1)
    assert path.name == "scan_a_b_c_.attempt-1.log"
