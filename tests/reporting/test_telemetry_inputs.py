"""Contract tests for the telemetry report inputs and document assembly."""
from __future__ import annotations

import json
from pathlib import Path

from appsec_review.reporting.latex import render_latex
from appsec_review.reporting.telemetry import RENDERER, load_inputs, telemetry_document

from .telemetry_fixture import JOBS, RUN_ID, T0, build_telemetry_run


def test_completed_run_inputs(tmp_path: Path) -> None:
    inputs = load_inputs(build_telemetry_run(tmp_path))
    assert inputs.run_id == RUN_ID
    assert inputs.summary_source == "summary.json" and len(inputs.summary_sha256 or "") == 64
    assert inputs.completion_status == "COMPLETED_WITH_GAPS"
    assert inputs.named_gaps == ()
    assert inputs.source_date_epoch == int(T0.timestamp()) + 1012  # the RUN_COMPLETED event
    assert [(job.job_id, job.attempt_id, job.status) for job in inputs.jobs] == [
        (JOBS[0], "a1", "SUCCEEDED"), (JOBS[1], "a1", "COMPLETED_WITH_GAPS"),
        (JOBS[2], "a1", "SUCCEEDED"), (JOBS[3], "a1", "FAILED"), (JOBS[3], "a2", "SUCCEEDED")]
    first = inputs.jobs[0]
    assert (first.start_ms, first.end_ms) == (1000, 61000)


def test_failed_and_running_runs(tmp_path: Path) -> None:
    failed = load_inputs(build_telemetry_run(tmp_path / "f", outcome="FAILED"))
    assert failed.completion_status == "FAILED"
    running = load_inputs(build_telemetry_run(tmp_path / "r", outcome="RUNNING"))
    assert running.completion_status == "UNKNOWN"
    review = next(job for job in running.jobs if job.job_id == JOBS[2])
    assert review.status == "RUNNING" and review.end_ms is None


def test_missing_summary_is_recomputed_in_memory_and_named(tmp_path: Path) -> None:
    run_dir = build_telemetry_run(tmp_path, write_summary=False)
    inputs = load_inputs(run_dir)
    assert inputs.summary_source == "recomputed" and inputs.summary_sha256 is None
    assert inputs.summary["run_id"] == RUN_ID
    assert "metrics_summary_missing" in inputs.named_gaps
    assert not (run_dir / "data" / "telemetry" / "summary.json").exists()


def test_mismatched_summary_and_missing_log_are_gaps(tmp_path: Path) -> None:
    run_dir = build_telemetry_run(tmp_path)
    summary = run_dir / "data" / "telemetry" / "summary.json"
    summary.write_text(json.dumps({"schema": "appsec-review/run-metrics/4", "run_id": RUN_ID}), encoding="utf-8")
    (run_dir / "data" / "logs" / "pipeline.jsonl").unlink()
    inputs = load_inputs(run_dir)
    assert inputs.summary == {} and inputs.summary_source == "unavailable"
    assert {"metrics_summary_schema_mismatch", "pipeline_event_log_missing"} <= set(inputs.named_gaps)
    assert inputs.events == () and inputs.jobs == () and inputs.completion_status == "UNKNOWN"


def test_document_is_deterministic_and_renders(tmp_path: Path) -> None:
    first = telemetry_document(build_telemetry_run(tmp_path / "a"))
    second = telemetry_document(build_telemetry_run(tmp_path / "b"))
    assert first == second
    assert first.renderer == RENDERER and first.head_label == "metrics summary sha256"
    assert render_latex(first) == render_latex(second)


def test_format_helpers() -> None:
    from appsec_review.reporting.telemetry import format as fmt
    assert [fmt.duration(v) for v in (850, 4200, 1012000, 7_500_000, None, -1)] == [
        "850 ms", "4.2 s", "16m 52s", "2h 05m", "unavailable", "unavailable"]
    assert (fmt.count(7810), fmt.compact(7810), fmt.compact(950), fmt.percent(0.825889), fmt.count(True)) == (
        "7,810", "7.8k", "950", "82.6%", "unavailable")
