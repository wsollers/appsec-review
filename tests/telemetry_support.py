"""Shared assertions for a job's telemetry and metrics, used by every job-pass test file.

A job test proves three things about observability, on the success path and on every failure path:

1. the run's ``pipeline.jsonl`` events validate and the job's lifecycle events are complete and
   consistent (``JOB_STARTED`` per attempt, exactly one terminal event per attempt, the terminal
   level is ``ERROR`` for a failure);
2. the attempt's ``status.json`` carries the same terminal status and a measured duration;
3. the run-wide metrics summary (``data/telemetry/summary.json``, ``write_run_metrics``) exists
   after the run ended and counts those events.

Job-specific events are asserted by the job's own tests through :func:`job_events`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from appsec_review.observability import validate_event

TERMINALS = {"SUCCEEDED": "JOB_SUCCEEDED", "COMPLETED_WITH_GAPS": "JOB_COMPLETED_WITH_GAPS", "FAILED": "JOB_FAILED"}


def pipeline_events(run_root: Path) -> list[dict[str, Any]]:
    """Every event of the run, validated against the telemetry event contract."""
    path = Path(run_root) / "data" / "logs" / "pipeline.jsonl"
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for record in records:
        validate_event(record)
    return records


def job_events(run_root: Path, job_id: str, event_type: str) -> list[dict[str, Any]]:
    """The ``details`` of every ``event_type`` the job wrote, in sequence order."""
    return [record["details"] for record in pipeline_events(run_root)
            if record["job_id"] == job_id and record["event_type"] == event_type]


def assert_job_lifecycle(run_root: Path, job_id: str, *, terminal: str, attempts: int = 1) -> dict[str, Any]:
    """Assert the job's lifecycle telemetry, status and the run metrics agree; return the summary.

    ``terminal`` is the status of the *latest* attempt (``SUCCEEDED``, ``COMPLETED_WITH_GAPS`` or
    ``FAILED``); earlier attempts of a resumed run may have failed.
    """
    run_root = Path(run_root)
    records = pipeline_events(run_root)
    mine = [record for record in records if record["job_id"] == job_id]
    started = [record for record in mine if record["event_type"] == "JOB_STARTED"]
    assert len(started) == attempts, f"{job_id}: expected {attempts} JOB_STARTED, saw {len(started)}"
    terminals = [record for record in mine if record["event_type"] in TERMINALS.values()]
    assert len(terminals) == attempts, f"{job_id}: expected {attempts} terminal job events, saw " \
                                       f"{[record['event_type'] for record in terminals]}"
    last = terminals[-1]
    assert last["event_type"] == TERMINALS[terminal], last["event_type"]
    assert last["level"] == ("ERROR" if terminal == "FAILED" else "INFO"), last
    attempt_ids = [record["attempt_id"] for record in started]
    assert len(set(attempt_ids)) == attempts, "each attempt starts once"
    assert last["attempt_id"] == attempt_ids[-1]
    if terminal == "FAILED":
        failed_tasks = [record for record in mine if record["event_type"] == "TASK_FAILED"
                        and record["attempt_id"] == last["attempt_id"]]
        assert failed_tasks, "a failed attempt names the task that failed"
        for record in failed_tasks:
            assert record["level"] == "ERROR"
            assert record["details"].get("error_type"), "TASK_FAILED names the error type"
            assert record["details"].get("unit_id"), "TASK_FAILED names the unit"
    # The attempt's own status record agrees with the event stream.
    status_path = run_root / "data" / "jobs" / job_id / "attempts" / last["attempt_id"] / "status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["status"] == terminal, status
    assert isinstance(status.get("duration_ms"), int) and status["duration_ms"] >= 0, status
    assert status.get("completed_at"), status
    # The run-wide summary was written when the run ended and counts what happened.
    summary_path = run_root / "data" / "telemetry" / "summary.json"
    assert summary_path.is_file(), "write_run_metrics did not run at the end of the run"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    counts = summary["event_counts"]
    assert counts.get("JOB_STARTED", 0) >= attempts
    assert counts.get(TERMINALS[terminal], 0) >= 1, counts
    assert isinstance(summary.get("wall_time_ms"), int) and summary["wall_time_ms"] >= 0
    assert summary["run_id"] == run_root.name
    return summary
