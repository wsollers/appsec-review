from __future__ import annotations

import json
import os
from multiprocessing import get_context
from pathlib import Path

import hashlib

import pytest

from appsec_review.observability import (
    FindingLifecycle, PipelineLog, aggregate_run_metrics, emit_model_event, validate_event,
)
from appsec_review.cli import main


def _writer(root: str, worker: int, count: int) -> None:
    log = PipelineLog(Path(root))
    for index in range(count):
        log.write("STRESS", run_id="run", job_id=f"job_{worker}", attempt_id="attempt_0001",
                  details={"worker": worker, "index": index, "token": "must-redact"})


def test_process_safe_log_has_contiguous_order_and_redaction(tmp_path: Path) -> None:
    context = get_context("spawn")
    processes = [context.Process(target=_writer, args=(str(tmp_path), worker, 15)) for worker in range(4)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    records, torn = PipelineLog(tmp_path).read()
    assert not torn
    assert [item["sequence"] for item in records] == list(range(1, 61))
    assert all(item["details"]["token"] == "<redacted>" for item in records)


def test_torn_final_record_is_ignored_and_recovered(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    log.write("FIRST", run_id="run")
    with log.path.open("ab") as stream:
        stream.write(b'{"sequence":2')
    records, torn = log.read()
    assert len(records) == 1 and torn
    log.write("SECOND", run_id="run")
    records, torn = log.read()
    assert not torn
    assert [record["sequence"] for record in records] == [1, 2]
    assert all(json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines())


def test_append_does_not_read_complete_history(tmp_path: Path, monkeypatch) -> None:
    log = PipelineLog(tmp_path)
    for _ in range(40):
        log.write("FIRST", run_id="run", details={"padding": "x" * 8192})
    def denied(*args, **kwargs):
        raise AssertionError("append must not read full log history")
    monkeypatch.setattr(Path, "read_bytes", denied)
    assert log.write("LAST", run_id="run")["sequence"] == 41


def test_complete_corruption_is_not_discarded_as_torn_tail(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    log.write("FIRST", run_id="run")
    with log.path.open("ab") as stream:
        stream.write(b"malformed complete record\n")
    before = log.path.read_bytes()
    with pytest.raises(ValueError, match="malformed complete"):
        log.write("LAST", run_id="run")
    assert log.path.read_bytes() == before
    with pytest.raises(ValueError, match="malformed complete"):
        log.read()


def test_append_reuses_only_exact_bounded_record_decodes(tmp_path: Path, monkeypatch) -> None:
    from appsec_review.observability import events

    log = PipelineLog(tmp_path)
    for _ in range(40):
        log.write("FIRST", run_id="run")
    original = events.json.loads
    decoded = []

    def decode(payload, *args, **kwargs):
        decoded.append(payload)
        return original(payload, *args, **kwargs)

    monkeypatch.setattr(events.json, "loads", decode)
    assert log.write("NEXT", run_id="run")["sequence"] == 41
    assert log.write("LAST", run_id="run")["sequence"] == 42
    assert len(decoded) == 2
    assert events._tail_sequence.cache_info().maxsize == 256

    payload = log.path.read_bytes()
    assert b'"sequence":41,' in payload
    corrupted = payload.replace(b'"sequence":41,', b'"sequence":11,', 1)
    log.path.write_bytes(corrupted)
    with pytest.raises(ValueError, match="invalid pipeline log tail sequence"):
        log.write("REJECT", run_id="run")
    assert log.path.read_bytes() == corrupted


def test_writer_failure_releases_kernel_lock(tmp_path: Path, monkeypatch) -> None:
    log = PipelineLog(tmp_path)
    original = os.fsync
    calls = 0
    def fail_once(descriptor):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected writer failure")
        return original(descriptor)
    monkeypatch.setattr(os, "fsync", fail_once)
    try:
        try:
            log.write("FAILED_WRITE", run_id="run")
        except OSError:
            pass
        log.write("RECOVERED_WRITE", run_id="run")
    finally:
        monkeypatch.setattr(os, "fsync", original)
    records, torn = log.read()
    assert not torn
    assert records[-1]["event_type"] == "RECOVERED_WRITE"


def test_cli_filters_global_log_without_external_tools(tmp_path: Path, capsys) -> None:
    source = Path(__file__).parents[1] / "appsec-review.toml"
    config = tmp_path / "appsec-review.toml"
    config.write_bytes(source.read_bytes())
    run_root = tmp_path / "runs/2026-10-08-0001"
    log = PipelineLog(run_root)
    log.write("ONE", run_id=run_root.name, job_id="job_review_intake", attempt_id="attempt_0001")
    log.write("TWO", run_id=run_root.name, job_id="job_target_catalog", attempt_id="attempt_0001")
    assert main(["--config", str(config), "logs", "--run-id", run_root.name,
                 "--job", "job_target_catalog", "--raw"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event_type"] == "TWO"


def test_canonical_event_model_tool_and_gap_metrics_are_deterministic(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    log.write("TASK_STARTED", run_id="run", job_id="job", attempt_id="attempt_0001",
              details={"dagster_run_id": "dagster", "dagster_node": "node", "tool_id": "tool-x"})
    emit_model_event(log, event_type="MODEL_CALL_STARTED", run_id="run", invocation_id="model-1",
                     provider="provider", model="model", reasoning_level="high",
                     guidance_bundle_sha256="a" * 64, request_sha256="b" * 64)
    emit_model_event(log, event_type="MODEL_CALL_COMPLETED", run_id="run", invocation_id="model-1",
                     provider="provider", model="model", reasoning_level="high",
                     guidance_bundle_sha256="a" * 64, request_sha256="b" * 64,
                     terminal_status="SUCCEEDED", duration_ms=12, input_tokens=10,
                     output_tokens=5, cache_tokens=2)
    log.write("TASK_COMPLETED_WITH_GAPS", run_id="run", job_id="job", attempt_id="attempt_0001",
              details={"completion_status": "COMPLETED_WITH_GAPS", "duration_ms": 20,
                       "prompt": "must not appear", "raw_model_output": "must not appear"})
    records, _ = log.read()
    assert all(validate_event(record) is None for record in records)
    assert "must not appear" not in log.path.read_text(encoding="utf-8")
    first = aggregate_run_metrics(tmp_path)
    second = aggregate_run_metrics(tmp_path)
    assert first == second
    assert first["model_tokens"] == {"cache_tokens": 2, "input_tokens": 10, "output_tokens": 5}
    assert first["dispositions"]["COMPLETED_WITH_GAPS"] == 1


def test_parallel_tools_pair_by_invocation_job_and_attempt_not_fifo(tmp_path):
    log = PipelineLog(tmp_path)
    def emit(event, job, attempt, invocation, duration=None):
        details = {"tool_id": "fixture", "tool_invocation_id": invocation}
        if duration is not None:
            details["duration_ms"] = duration
        log.write(event, run_id="run", job_id=job, attempt_id=attempt, details=details)
    for job, attempt, invocation in [("one", "a", "first"), ("one", "a", "second"),
                                     ("two", "a", "first"), ("one", "b", "first")]:
        emit("TOOL_INVOCATION_STARTED", job, attempt, invocation)
    for job, attempt, invocation in [("one", "a", "second"), ("one", "b", "first"),
                                     ("two", "a", "first"), ("one", "a", "first")]:
        emit("TOOL_INVOCATION_COMPLETED", job, attempt, invocation, 10)
    emit("TOOL_INVOCATION_COMPLETED", "one", "a", "first", 10)
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["duplicate_lifecycle_records"] == 1
    assert metrics["event_count"] == sum(metrics["event_counts"].values()) == 8
    assert metrics["raw_event_count"] == sum(metrics["raw_event_counts"].values()) == 9
    assert metrics["event_counts"]["TOOL_INVOCATION_COMPLETED"] == 4
    assert metrics["raw_event_counts"]["TOOL_INVOCATION_COMPLETED"] == 5
    assert metrics["tool_calls"] == {"fixture": 4}
    assert metrics["lifecycle_gaps"] == metrics["lifecycle_conflicts"] == []
    assert metrics["lifecycle_accounting"] == "complete"
    assert metrics["duration_ms_by_event"]["TOOL_INVOCATION_COMPLETED"] == 40


def test_missing_and_conflicting_tool_terminals_are_explicit_metric_gaps(tmp_path):
    log = PipelineLog(tmp_path)
    values = dict(run_id="run", job_id="one", attempt_id="a")
    log.write("TOOL_INVOCATION_STARTED", **values, details={"tool_invocation_id": "lost"})
    log.write("TOOL_INVOCATION_STARTED", **values, details={"tool_invocation_id": "conflict"})
    log.write("TOOL_INVOCATION_COMPLETED", **values,
              details={"tool_invocation_id": "conflict", "duration_ms": 10})
    log.write("TOOL_INVOCATION_COMPLETED", **values,
              details={"tool_invocation_id": "conflict", "duration_ms": 99})
    log.write("JOB_SUCCEEDED", **values)
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["lifecycle_accounting"] == "partial"
    assert metrics["lifecycle_conflicts"][0]["invocation_id"] == "conflict"
    assert metrics["lifecycle_gaps"] == [{
        "family": "TOOL", "job_id": "one", "step_id": "-", "task_id": "-", "attempt_id": "a",
        "invocation_id": "lost", "started_at": log.read()[0][0]["timestamp"],
        "reason": "missing_terminal_after_job_finished"}]


def test_finding_transitions_are_valid_idempotent_and_distinct_from_observations(tmp_path: Path) -> None:
    lifecycle = FindingLifecycle(tmp_path)
    reason = hashlib.sha256(b"bounded reason").hexdigest()
    candidate = lifecycle.transition(run_id="run", finding_package_id="finding-1",
                                     new_state="CANDIDATE", evidence_identities=("observation-1",),
                                     actor_class="deterministic", reason_hash=reason)
    duplicate = lifecycle.transition(run_id="run", finding_package_id="finding-1",
                                     new_state="CANDIDATE", evidence_identities=("observation-1",),
                                     actor_class="deterministic", reason_hash=reason)
    assert duplicate["event_id"] == candidate["event_id"]
    lifecycle.transition(run_id="run", finding_package_id="finding-1", new_state="CONFIRMED",
                         evidence_identities=("observation-1",), actor_class="human", reason_hash=reason)
    with pytest.raises(ValueError, match="invalid finding transition"):
        lifecycle.transition(run_id="run", finding_package_id="finding-1", new_state="REFUTED",
                             evidence_identities=("observation-1",), actor_class="human", reason_hash=reason)
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["finding_states"] == {"CANDIDATE": 1, "CONFIRMED": 1}


def test_metrics_separate_wall_concurrency_percentiles_reuse_and_running(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    events = [
        ("RUN_STARTED", "2026-10-08T00:00:00+00:00", {}),
        ("TASK_STARTED", "2026-10-08T00:00:01+00:00", {}),
        ("TASK_SUCCEEDED", "2026-10-08T00:00:05+00:00", {"duration_ms": 4000,
            "file_count": 2, "processed_bytes": 100}),
        ("TASK_STARTED", "2026-10-08T00:00:02+00:00", {}),
        ("TASK_COMPLETED_WITH_GAPS", "2026-10-08T00:00:08+00:00", {"duration_ms": 6000,
            "completion_status": "COMPLETED_WITH_GAPS"}),
        ("TASK_REUSED", "2026-10-08T00:00:08.500000+00:00", {"checkpoint_reused": True,
            "fingerprint": "a" * 64}),
        ("TASK_STARTED", "2026-10-08T00:00:09+00:00", {}),
        ("DAGSTER_QUEUE_DELAY", "2026-10-08T00:00:10+00:00", {"queue_delay_ms": 250}),
        ("RUN_CANCELLED", "2026-10-08T00:00:11+00:00", {"completion_status": "CANCELLED"}),
    ]
    for event, _timestamp, details in events:
        log.write(event, run_id="run", job_id="job", attempt_id="attempt_0001",
                  step_id="step", task_id="task", details=details)
    records, _ = log.read()
    for record, (_event, timestamp, _details) in zip(records, events):
        record["timestamp"] = timestamp
    log.path.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in records), encoding="utf-8")
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["wall_time_ms"] == 11000
    assert metrics["summed_concurrent_task_ms"] == 10000
    assert metrics["queue_delay_ms"]["p95"] == 250
    assert metrics["reuse"]["hits"] == 1
    assert metrics["throughput_totals"] == {"file_count": 2, "processed_bytes": 100}
    assert metrics["operations"][0]["p95_ms"] == 6000
    assert metrics["genuinely_running"][0]["family"] == "TASK"
    assert metrics["dispositions"]["CANCELLED"] == 1
