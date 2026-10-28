from __future__ import annotations

from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.debug_symbols.contract import JOB_ID


def test_missing_symbol_metrics_are_unavailable_not_empty_success(tmp_path) -> None:
    metrics = aggregate_run_metrics(tmp_path)["debug_symbols"]
    assert metrics["index"]["available"] is False
    assert metrics["index"]["record_count"] is None
    assert metrics["index"]["unavailable_reason"] == "debug_symbol_index_metrics_not_emitted"


def test_symbol_metrics_use_latest_snapshot_and_count_bounded_query_work(tmp_path) -> None:
    log = PipelineLog(tmp_path)
    log.write("DEBUG_SYMBOL_TARGET_SELECTED", run_id="run", job_id=JOB_ID,
              attempt_id="attempt_0001", details={"compiler_target": "msvc"})
    for attempt, records in enumerate((12, 14), 1):
        log.write("DEBUG_SYMBOL_INDEX_COMPLETED", run_id="run", job_id=JOB_ID,
                  attempt_id=f"attempt_{attempt:04d}", details={
            "compiler_target": "msvc", "record_count": records, "artifact_count": 1,
            "gap_count": 2, "duration_ms": 8})
    log.write("DEBUG_SYMBOL_ARTIFACT_FAILED", run_id="run", job_id=JOB_ID,
              attempt_id="attempt_0001", details={"compiler_target": "msvc"})
    for mode in ("address", "type_layout"):
        log.write("DEBUG_SYMBOL_QUERY_COMPLETED", run_id="run", details={
            "compiler_target": "msvc", "mode": mode, "returned_count": 2,
            "duration_ms": 3, "gap_count": 1, "truncated_count": 0})
    metrics = aggregate_run_metrics(tmp_path)["debug_symbols"]
    assert metrics["compiler_target"] == "msvc"
    assert metrics["index_attempt_count"] == 2
    assert metrics["index"]["record_count"] == 14
    assert metrics["artifact_failure_count"] == 1
    assert metrics["queries"] == {
        "count": 2, "by_mode": {"address": 1, "type_layout": 1},
        "returned_count": 4, "duration_ms": 6, "gap_count": 2, "truncated_count": 0}
    assert metrics["metric_gaps"] == []


def test_invalid_or_missing_metric_values_never_become_zero(tmp_path) -> None:
    log = PipelineLog(tmp_path)
    log.write("DEBUG_SYMBOL_INDEX_COMPLETED", run_id="run", details={
        "compiler_target": "clang", "record_count": -1, "artifact_count": True})
    log.write("DEBUG_SYMBOL_QUERY_COMPLETED", run_id="run", details={
        "compiler_target": "clang", "mode": "address", "returned_count": 3})
    log.write("DEBUG_SYMBOL_QUERY_COMPLETED", run_id="run", details={
        "compiler_target": "private-symbol-name", "mode": "address"})
    metrics = aggregate_run_metrics(tmp_path)["debug_symbols"]
    assert metrics["index"]["record_count"] is None
    assert metrics["index"]["artifact_count"] is None
    assert metrics["queries"]["duration_ms"] is None
    assert "debug_symbol_metric_invalid_target" in metrics["metric_gaps"]


def test_failed_symbol_attempts_are_counted_without_a_completion_snapshot(tmp_path) -> None:
    log = PipelineLog(tmp_path)
    log.write("JOB_STARTED", run_id="run", job_id=JOB_ID, attempt_id="attempt_0001")
    log.write("JOB_FAILED", run_id="run", job_id=JOB_ID, attempt_id="attempt_0001")
    metrics = aggregate_run_metrics(tmp_path)["debug_symbols"]
    assert metrics["index_attempt_count"] == 1
    assert metrics["index"]["available"] is False
