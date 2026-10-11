"""Record terminal Dagster review failures in a short, tail-friendly file."""

from __future__ import annotations

from pathlib import Path

from dagster import (
    DagsterEventType, DagsterRunStatus, DefaultSensorStatus,
    RunRequest, job, op, run_status_sensor,
)

from appsec_review.storage import atomic_bytes


def _one_line(value: object, limit: int = 700) -> str:
    return " ".join(str(value).split())[:limit]


def record_error_state(instance, source_run_id: str, runs_dir: Path) -> Path:
    """Summarize a failed or canceled wave from bounded Dagster event records."""
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
                     f"message={_one_line(entry.message)}")
    if not events:
        lines.append("event=UNAVAILABLE step=- message=Dagster recorded no failure event")
    path = runs_dir / "metadata" / "dagster-error-state" / f"{source_run_id}.log"
    atomic_bytes(path, ("\n".join(lines) + "\n").encode("utf-8"))
    return path


def build_error_state_definitions(wave_job, runs_dir: Path) -> tuple[object, list[object]]:
    @op(name="record_wave1_error_state")
    def record(context) -> str:
        source_run_id = context.dagster_run.tags["appsec/source_dagster_run_id"]
        path = record_error_state(context.instance, source_run_id, runs_dir)
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
    return error_job, sensors
