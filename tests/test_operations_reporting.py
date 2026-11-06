from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
from subprocess import TimeoutExpired

import pytest

from appsec_review.observability.costs import account_calls
from appsec_review.observability.diagnostics import execution_category, execution_summary
from appsec_review.observability.events import EventCursor, PipelineLog
from appsec_review.observability.operator import OperatorFollower
from appsec_review.observability.otlp import BoundedOTLP
from appsec_review.observability.telemetry import aggregate_run_metrics, emit_model_event


def emit(log, kind, **details):
    return log.write(kind, run_id=log.path.parents[2].name, job_id="job", attempt_id="attempt-1",
                     details=details)


def dispatch(root, status="STARTED", identity="dispatch-1"):
    return {"runId": identity, "status": status, "startTime": 1,
            "tags": [{"key": "appsec/application_run_id", "value": root.name}], "stepStats": []}


def test_cursor_pages_restart_torn_tail_and_replacement(tmp_path, monkeypatch):
    log = PipelineLog(tmp_path)
    for number in range(10):
        emit(log, "TEST", number=number)
    monkeypatch.setattr(Path, "read_bytes", lambda *_: pytest.fail("full-log read is forbidden"))
    page = log.follow(max_records=3)
    assert len(page.records) == 3 and page.status == "backlog"
    cursor = EventCursor(**json.loads(json.dumps(asdict(page.cursor))))
    second = log.follow(cursor, max_records=10)
    assert [row["sequence"] for row in second.records] == list(range(4, 11))
    with log.path.open("ab") as stream:
        stream.write(b'{"sequence":11')
    torn = log.follow(second.cursor)
    assert torn.status == "torn_tail" and torn.cursor == second.cursor
    emit(log, "RECOVERED")
    assert log.follow(torn.cursor).records[0]["sequence"] == 11
    log.path.unlink()
    emit(log, "NEW")
    replaced = log.follow(second.cursor)
    assert replaced.reset_reason == "log_replaced_or_truncated"
    assert replaced.records[0]["sequence"] == 1


def test_complete_corruption_and_invalid_cursor_are_not_skipped(tmp_path):
    log = PipelineLog(tmp_path)
    emit(log, "OK")
    with log.path.open("ab") as stream:
        stream.write(b"broken\n")
    with pytest.raises(ValueError, match="malformed complete"):
        log.follow()
    with pytest.raises(ValueError, match="cursor"):
        log.follow(EventCursor(offset=10))


def test_unknown_schema_and_wrong_run_fail_explicitly(tmp_path):
    log = PipelineLog(tmp_path)
    event = emit(log, "OK")
    event["schema"] = "future/99"
    log.path.write_text(json.dumps(event) + "\n")
    with pytest.raises(ValueError, match="unsupported"):
        OperatorFollower(tmp_path).poll()
    event["schema"] = "appsec-review/telemetry-event/1"
    event["run_id"] = "another"
    log.path.write_text(json.dumps(event) + "\n")
    with pytest.raises(ValueError, match="provenance"):
        OperatorFollower(tmp_path).poll()


def test_live_long_operation_is_not_dead_without_heartbeat(tmp_path):
    log = PipelineLog(tmp_path)
    start = emit(log, "JOB_STARTED")
    now = datetime.fromisoformat(start["timestamp"]) + timedelta(days=2)
    follower = OperatorFollower(tmp_path)
    follower.poll()
    report = follower.snapshot(now=now, dispatches=[dispatch(tmp_path)])
    assert report["liveness"] == "active"
    assert report["alerts"][0]["category"] == "progress_unconfirmed"
    assert follower.snapshot(now=now, dispatches=[dispatch(tmp_path)])["alerts"] == []
    assert follower.snapshot(now=now)["liveness"] == "unknown"
    assert report["analysis_completeness"] == "unknown"


def test_coalescing_is_incremental_and_capacity_never_loses_critical_records(tmp_path):
    log = PipelineLog(tmp_path)
    follower = OperatorFollower(tmp_path, capacity=2)
    emit(log, "JOB_STARTED")
    for number in range(20):
        emit(log, "OPERATION_PROGRESS", span_id="span", progress_sequence=number)
    assert follower.poll() == "caught_up"
    assert len(follower.records) == 2
    assert follower.counts["OPERATION_PROGRESS"] == 20
    before = follower.cursor
    emit(log, "JOB_SUCCEEDED")
    assert follower.poll() == "capacity_reached"
    assert follower.cursor == before
    assert log.follow(before).records[0]["event_type"] == "JOB_SUCCEEDED"


def test_multiple_attempts_dispatches_reused_gaps_and_conflicting_completion(tmp_path):
    log = PipelineLog(tmp_path)
    emit(log, "RUN_STARTED")
    emit(log, "JOB_STARTED")
    emit(log, "JOB_FAILED", terminal_status="FAILED")
    log.write("JOB_STARTED", run_id=tmp_path.name, job_id="job", attempt_id="attempt-2")
    log.write("JOB_COMPLETED_WITH_GAPS", run_id=tmp_path.name, job_id="job", attempt_id="attempt-2")
    emit(log, "TASK_REUSED", completion_status="COMPLETED_WITH_GAPS", gap_count=1,
         metrics_receipt={"path": "do-not-print-secret-path", "sha256": "a" * 64})
    emit(log, "RUN_COMPLETED", completion_status="SUCCEEDED")
    follower = OperatorFollower(tmp_path)
    follower.poll()
    report = follower.snapshot(dispatches=[dispatch(tmp_path, "FAILURE"), dispatch(tmp_path, identity="dispatch-2")])
    assert report["liveness"] == "conflicting_evidence"
    assert len(report["dispatches"]) == 2
    assert report["jobs"][0]["retry_attempts_observed"] == 1
    assert report["analysis_completeness"] == "declared_gaps"
    assert any(gap["reused"] for gap in report["gaps"])
    assert "do-not-print" not in json.dumps(report)
    emit(log, "GRAPH_FAILED", completion_status="FAILED")
    follower.poll()
    assert follower.snapshot()["operational_status"] == "CONFLICT"


@pytest.mark.parametrize(("details", "category"), [
    ({"error_class": "TimeoutExpired", "terminal_status": "FAILED"}, "timeout"),
    ({"timed_out": True, "exit_code": -9}, "timeout"),
    ({"oom_killed": True, "exit_code": -9}, "oom"),
    ({"exit_code": -9}, "exit_failure"),
    ({"terminal_status": "CANCELED"}, "cancelled"),
    ({"exit_code": 0}, "success"), ({}, "unknown"),
])
def test_execution_classification_does_not_guess_oom(details, category):
    assert execution_category(details) == category
    summary = execution_summary({**details, "stderr": "private stderr", "prompt": "private prompt",
                                 "stderr_sha256": "b" * 64})
    assert "private" not in json.dumps(summary)
    assert summary["diagnostics"]["stderr"]["sha256"] == "b" * 64


def model_event(log, invocation, **details):
    return emit(log, "MODEL_CALL_COMPLETED", model_invocation_id=invocation, provider="p", model="m",
                input_tokens=100, output_tokens=20, cache_tokens=10, **details)


def test_cost_provenance_unknowns_replays_duplicates_and_shared_allocations(tmp_path):
    log = PipelineLog(tmp_path)
    events = [
        model_event(log, "actual", provider_charge={"source": "provider_reported", "amount": "0.25", "currency": "USD"}),
        model_event(log, "estimated"),
        model_event(log, "subscription", billing_mode="subscription"),
        model_event(log, "replay", execution_mode="replay"),
    ]
    events.append(events[0])
    prices = {"schema": "appsec-review/api-prices/1", "version": "fixture-v1", "rates": {
        "p/m": {"input_per_million": "1", "output_per_million": "2", "cache_per_million": "0.5",
                "currency": "USD", "cache_semantics": "included_in_input"}}}
    key = f"{tmp_path.name}/job/attempt-1/actual"
    report = account_calls(events, prices=prices, finding_links={key: ["f1", "f2", "f1"]})
    assert report["run"]["known_amounts"] == {"api_estimate/USD": "0.000135", "provider_reported/USD": "0.25"}
    assert report["run"]["status"] == "partial"
    assert report["duplicate_records"] == 1
    assert report["finding_allocations"][0]["share_denominator"] == 2
    assert report["finding_allocations"][0]["total_amount"] == "0.25"
    assert report["run"]["usage"]["input_tokens"] == 300
    assert account_calls(events)["calls"][1]["provenance"] == "unknown"


def test_missing_usage_legacy_identity_and_conflicts_are_not_zero(tmp_path):
    log = PipelineLog(tmp_path)
    events = [emit(log, "MODEL_CALL_STARTED", model_invocation_id="missing"),
              emit(log, "MODEL_CALL_COMPLETED", invocation_id="legacy", input_tokens=None,
                   output_tokens=3, cache_tokens=None),
              model_event(log, "conflict", provider_charge={"source": "provider_reported", "amount": 1, "currency": "USD"}),
              model_event(log, "conflict", provider_charge={"source": "provider_reported", "amount": 2, "currency": "USD"})]
    report = account_calls(events)
    assert report["run"]["usage"]["input_tokens"] is None
    assert len(report["calls"]) == 3 and len(report["conflicting_calls"]) == 1
    metrics = aggregate_run_metrics(tmp_path)
    assert any(row["invocation_id"] == "legacy" for row in metrics["model_invocations"])
    assert metrics["cost_provenance"]["run"]["status"] == "partial"


def test_timeout_expired_telemetry_is_reported_and_rethrown(tmp_path):
    from appsec_review.inference.request import ReviewModelRequest
    from appsec_review.observability.model_calls import call_model

    request = ReviewModelRequest(schema="fixture", role="role", persona="persona", stack_profile="stack",
                                 guidance_bundle_sha256="a" * 64, guidance_text="",
                                 task_input={}, transcript=(), provider="p", model="m", reasoning="high")
    def timeout(*args, **kwargs):
        raise TimeoutExpired("private command", 1, stderr=b"private diagnostic")
    with pytest.raises(TimeoutExpired):
        call_model(timeout, request, timeout_seconds=1, run_root=tmp_path, run_id=tmp_path.name,
                   job_id="job", attempt_id="a", step_id="step", task_id="task")
    events, _ = PipelineLog(tmp_path).read()
    assert events[-1]["details"]["terminal_status"] == "TIMED_OUT"
    assert "private" not in json.dumps(events)


def test_otlp_redacts_and_preserves_queue_on_failure_and_backpressure(tmp_path):
    event = emit(PipelineLog(tmp_path), "PROMPT_SECRET", prompt="private", stderr_text="private")
    failures = []
    def unavailable(batch):
        failures.append(batch)
        raise OSError("private collector details")
    exporter = BoundedOTLP(unavailable, capacity=1, batch_size=1)
    assert exporter.offer(event) == "disabled"
    exporter.enabled = True
    assert exporter.offer(event) == "queued"
    assert exporter.offer(event) == "backpressure_retry_same_event"
    result = exporter.flush()
    assert result["status"] == "export_failed" and result["pending"] == 1
    assert "private" not in json.dumps(result) + json.dumps(failures)
    exported = []
    exporter.exporter = exported.append
    assert exporter.flush()["pending"] == 0
    assert exported[0] == failures[0]


def test_legacy_run_report_preserves_keys_and_does_not_mark_age_as_dead(tmp_path):
    script = Path(__file__).parents[1] / "deploy/dagster/bin/run_report.py"
    spec = importlib.util.spec_from_file_location("ops_run_report", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = tmp_path / "runs/2026-11-06-0001"
    run.mkdir(parents=True)
    emit(PipelineLog(run), "JOB_STARTED")
    report = module.build_report(tmp_path, [dispatch(run)], now=datetime.now(timezone.utc))
    assert report["schema"] == "appsec-review/operator-performance-report/1"
    assert len(report["dagster"]["genuinelyRunning"]) == 1
    assert report["dagster"]["stale"] == []
    assert report["operator"]["runs"][0]["liveness"] == "active"
