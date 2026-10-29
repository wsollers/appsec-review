"""Record Dagster review failures in short, tail-friendly files."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from dagster import (
    DagsterEventType, DagsterRunStatus, DefaultSensorStatus, RunRequest,
    RunsFilter, SkipReason, job, op, run_status_sensor, sensor,
)

from appsec_review.config.telemetry_report import TelemetryReportSettings
from appsec_review.observability import PipelineLog, write_run_metrics
from appsec_review.reporting.telemetry_finalize import finalize_telemetry_report
from appsec_review.storage import FileLock, atomic_bytes, atomic_json
from appsec_review.storage.shared import safe_path

WAVE_JOB = "wave1_review"
STEP_FAILURE_SENSOR = "wave1_step_failure_state"
_ACTIVE_STATUSES = [DagsterRunStatus.STARTING, DagsterRunStatus.STARTED, DagsterRunStatus.CANCELING]
_MAX_ACTIVE_RUNS = 20
_MAX_FAILURES_PER_RUN = 50
_MAX_RETRY_RECORDS = 1000
_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")


def _one_line(value: object, limit: int = 700) -> str:
    return " ".join(str(value).split())[:limit]


def _event_message(entry) -> str:
    event = entry.dagster_event
    error = getattr(getattr(event, "event_specific_data", None), "error", None)
    while error is not None and getattr(error, "cause", None) is not None:
        error = error.cause
    return _one_line(error.message if error is not None else entry.message)


def record_error_state(instance, source_run_id: str, runs_dir: Path, *,
                       telemetry_report: TelemetryReportSettings | None = None,
                       repository_root: Path | None = None) -> Path:
    """Summarize a failed or canceled wave from bounded Dagster event records.

    With ``telemetry_report`` settings, a finalized run also gets its best-effort telemetry report
    after its terminal metrics are written (outside the receipt lock)."""
    source = instance.get_run_by_id(source_run_id)
    if source is None or source.job_name != "wave1_review":
        raise ValueError(f"unknown wave1_review run: {source_run_id}")
    if source.status not in {DagsterRunStatus.FAILURE, DagsterRunStatus.CANCELED}:
        raise ValueError(f"review run is not in an error state: {source_run_id}: {source.status.value}")
    events = instance.get_records_for_run(
        source_run_id, of_type={DagsterEventType.STEP_FAILURE,
                                DagsterEventType.PIPELINE_FAILURE,
                                DagsterEventType.PIPELINE_CANCELED},
        limit=5, ascending=False).records
    application_run_id = source.tags.get("appsec/application_run_id", "unallocated")
    lines = [f"dagster_run_id={source_run_id} application_run_id={application_run_id} "
             f"status={source.status.value}"]
    for record in reversed(events):
        entry = record.event_log_entry
        event = entry.dagster_event
        lines.append(f"event={event.event_type_value} step={event.step_key or '-'} "
                     f"message={_event_message(entry)}")
    if not events:
        lines.append("event=UNAVAILABLE step=- message=Dagster recorded no failure event")
    path = runs_dir / "metadata" / "dagster-error-state" / f"{source_run_id}.log"
    if not path.exists():
        atomic_bytes(path, ("\n".join(lines) + "\n").encode("utf-8"))
    root = _finalize_failed_run(source, runs_dir, path)
    if root is not None and telemetry_report is not None:
        finalize_telemetry_report(root, telemetry_report, repository_root=repository_root)
    return path


def _finalize_failed_run(source, runs_dir: Path, error_path: Path) -> Path | None:
    """Record the terminal status and metrics; returns the run root when its metrics were written."""
    application_id = source.tags.get("appsec/application_run_id")
    if application_id is None:
        return None
    root = safe_path(runs_dir, application_id)
    manifest_path = root / "data/configuration/manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = json.loads(manifest_path.read_bytes())
    # Never backfill or mutate historical runs created before this lifecycle contract.
    if manifest.get("failure_finalization") != "appsec-review/split-failure-finalization/1":
        return None
    receipt = safe_path(root, f"data/orchestration/dagster/{source.run_id}.json")
    with FileLock(receipt.with_suffix(".lock")):
        if receipt.exists():
            prior = json.loads(receipt.read_bytes())
            if prior["status"] != source.status.value:
                raise ValueError("terminal Dagster receipt conflicts with authoritative run status")
            write_run_metrics(root)
            return root
        log = PipelineLog(root)
        details = {"dagster_run_id": source.run_id, "completion_status": source.status.value,
                   "error_state_file": str(error_path)}
        trigger = source.tags.get("appsec/trigger", "manual")
        records, _ = log.read()
        for event in ("GRAPH_FAILED" if source.status is DagsterRunStatus.FAILURE else "GRAPH_CANCELED",
                      "RUN_COMPLETED"):
            if not any(record["event_type"] == event and record.get("details", {}).get(
                    "dagster_run_id") == source.run_id for record in records):
                log.write(event, run_id=application_id, trigger=trigger,
                          orchestrator="dagster", details=details)
        atomic_json(receipt, {
            "schema": "appsec-review/orchestration-receipt/1",
            "status": source.status.value, "completion_status": source.status.value,
            "application_run_id": application_id,
            "orchestrator": {"system": "dagster", "run_id": source.run_id},
            "error_state_file": str(error_path),
        })
        write_run_metrics(root)
    return root


def step_failure_path(runs_dir: Path, dagster_run_id: str, step_key: str, attempt: int) -> Path:
    """Return the stable per-failure file for one step attempt of one Dagster run."""
    safe_step = _UNSAFE.sub("_", step_key)[:150] or "_"
    return (runs_dir / "metadata" / "dagster-error-state" / dagster_run_id / "steps"
            / f"{safe_step}.attempt-{attempt}.log")


def _step_attempt(instance, dagster_run_id: str, step_key: str) -> int:
    # STEP_FAILURE is terminal for a step, so its attempt follows every earlier retry of that step.
    retries = instance.get_records_for_run(
        dagster_run_id, of_type=DagsterEventType.STEP_UP_FOR_RETRY, limit=_MAX_RETRY_RECORDS).records
    return 1 + sum(1 for record in retries
                   if record.event_log_entry.dagster_event.step_key == step_key)


def record_step_failure(instance, run, record, runs_dir: Path) -> Path:
    """Write one STEP_FAILURE record once; an existing file is never rewritten."""
    entry = record.event_log_entry
    step_key = entry.dagster_event.step_key or "-"
    attempt = _step_attempt(instance, run.run_id, step_key)
    path = step_failure_path(runs_dir, run.run_id, step_key, attempt)
    if path.exists():
        return path
    timestamp = datetime.fromtimestamp(entry.timestamp, timezone.utc).isoformat()
    lines = [
        f"dagster_run_id={run.run_id}",
        f"application_run_id={run.tags.get('appsec/application_run_id', 'unallocated')}",
        f"step_key={_one_line(step_key, 300)}",
        f"attempt={attempt}",
        f"event_storage_id={record.storage_id}",
        f"timestamp={timestamp}",
        f"message={_event_message(entry)}",
    ]
    atomic_bytes(path, ("\n".join(lines) + "\n").encode("utf-8"))
    return path


def record_step_failures(instance, runs_dir: Path, cursor: str | None) -> tuple[list[Path], str]:
    """Record new step failures of active review runs and return the advanced sensor cursor.

    The cursor maps each tracked Dagster run id to its event-log cursor. A run stays tracked while
    it is active and is drained once more after it leaves the active statuses.
    """
    try:
        state = json.loads(cursor) if cursor else {}
    except ValueError:
        state = {}
    if not isinstance(state, dict):
        state = {}
    runs = {run.run_id: run for run in instance.get_runs(
        RunsFilter(job_name=WAVE_JOB, statuses=_ACTIVE_STATUSES), limit=_MAX_ACTIVE_RUNS)}
    for run_id in state:
        if run_id not in runs and (run := instance.get_run_by_id(run_id)) is not None:
            runs[run_id] = run
    written: list[Path] = []
    next_state: dict[str, str] = {}
    for run_id, run in runs.items():
        connection = instance.get_records_for_run(
            run_id, cursor=state.get(run_id), of_type=DagsterEventType.STEP_FAILURE,
            limit=_MAX_FAILURES_PER_RUN)
        for record in connection.records:
            written.append(record_step_failure(instance, run, record, runs_dir))
        if run.status in _ACTIVE_STATUSES or connection.has_more:
            next_state[run_id] = connection.cursor
    return written, json.dumps(next_state, sort_keys=True, separators=(",", ":"))


def build_error_state_definitions(wave_job, runs_dir: Path, *,
                                  telemetry_report: TelemetryReportSettings | None = None,
                                  repository_root: Path | None = None) -> tuple[object, list[object]]:
    @op(name="record_wave1_error_state")
    def record(context) -> str:
        source_run_id = context.dagster_run.tags["appsec/source_dagster_run_id"]
        path = record_error_state(context.instance, source_run_id, runs_dir,
                                  telemetry_report=telemetry_report, repository_root=repository_root)
        context.add_output_metadata({"source_dagster_run_id": source_run_id,
                                     "error_state_file": str(path)})
        return str(path)

    @job(name="wave1_error_state")
    def error_job():
        record()

    sensors = []
    for status in (DagsterRunStatus.FAILURE, DagsterRunStatus.CANCELED):
        @run_status_sensor(
            run_status=status, name=f"wave1_{status.value.lower()}_state",
            monitored_jobs=[wave_job], request_job=error_job,
            default_status=DefaultSensorStatus.RUNNING,
        )
        def on_error(context):
            source = context.dagster_run
            return RunRequest(
                run_key=f"{source.run_id}:{source.status.value}",
                tags={"appsec/source_dagster_run_id": source.run_id,
                      "appsec/source_status": source.status.value},
            )

        sensors.append(on_error)

    # Sensor evaluation runs in the code location, which mounts runs/, so it writes directly
    # instead of launching a Dagster run per failed step.
    @sensor(name=STEP_FAILURE_SENSOR, minimum_interval_seconds=15,
            default_status=DefaultSensorStatus.RUNNING)
    def on_step_failure(context):
        written, cursor = record_step_failures(context.instance, runs_dir, context.cursor)
        if cursor != context.cursor:
            context.update_cursor(cursor)
        if not written:
            return SkipReason("no new wave1_review step failures")
        return SkipReason(f"recorded {len(written)} wave1_review step failure file(s)")

    sensors.append(on_step_failure)
    return error_job, sensors
