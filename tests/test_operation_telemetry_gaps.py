"""Operation telemetry: thread resources, blocked time, progress heartbeats, phases and cardinality."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable

import pytest

from appsec_review.jobs.job_openvex_export.metrics import JOB_ID as OPENVEX_JOB_ID
from appsec_review.jobs.job_openvex_export.metrics import aggregate_openvex_metrics
from appsec_review.observability import aggregate_run_metrics, spans
from appsec_review.observability.events import EventLog, PipelineLog
from appsec_review.observability.telemetry import RUN_METRICS_SCHEMA

from tests.reporting.telemetry_fixture import _Log

POSIX = pytest.mark.skipif(os.name != "posix", reason="Linux /proc and RUSAGE_THREAD semantics")
THREAD_FIELDS = ("read_syscalls", "write_syscalls", "thread_cpu_seconds", "thread_off_cpu_seconds",
                 "voluntary_context_switches", "involuntary_context_switches", "block_input_ops",
                 "block_output_ops", "major_page_faults", "rusage_scope", "rusage_unavailable_reason")


@pytest.fixture(autouse=True)
def _default_sampling():
    yield
    _wait_for(lambda: not spans._SAMPLER.entries, timeout=5)
    spans.configure_operation_sampling()


def _wait_for(condition: Callable[[], bool], *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError("condition not reached before the deadline")
        time.sleep(0.005)


def _events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _one(records: list[dict[str, Any]], event: str) -> dict[str, Any]:
    matching = [record for record in records if record["event"] == event]
    assert len(matching) == 1, matching
    return matching[0]


# --- section 1: resources ------------------------------------------------------------------------

@POSIX
def test_completed_span_records_thread_resources_on_linux(tmp_path: Path) -> None:
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute", unit_id="index.catalogs"):
        (tmp_path / "payload").write_bytes(b"x" * 4096)
        time.sleep(0.02)
    resources = _one(_events(tmp_path / "events.jsonl"), "OPERATION_COMPLETED")["resources"]
    assert resources["measurement_source"] == spans.RESOURCE_SOURCE == (
        "os.times/proc-self-io/getrusage-thread/thread_time")
    assert set(THREAD_FIELDS) <= set(resources)
    assert resources["rusage_scope"] == "thread" and resources["rusage_unavailable_reason"] is None
    for name in ("read_syscalls", "write_syscalls", "voluntary_context_switches",
                 "involuntary_context_switches", "block_input_ops", "block_output_ops", "major_page_faults"):
        assert type(resources[name]) is int and resources[name] >= 0, name
    assert resources["write_syscalls"] >= 1
    assert resources["voluntary_context_switches"] >= 1        # the sleep yielded the CPU
    assert resources["thread_off_cpu_seconds"] >= 0.015
    assert 0 <= resources["thread_cpu_seconds"] < 0.5


def test_unavailable_resources_are_null_with_a_reason_never_zero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(spans, "_io", lambda: None)
    monkeypatch.setattr(spans, "_resource", None)
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute"):
        pass
    resources = _one(_events(tmp_path / "events.jsonl"), "OPERATION_COMPLETED")["resources"]
    assert resources["io_unavailable_reason"] == "proc_io_unavailable"
    assert resources["rusage_scope"] is None
    assert resources["rusage_unavailable_reason"] == "rusage_thread_unavailable"
    for name in ("read_syscalls", "write_syscalls", "physical_write_bytes", "voluntary_context_switches",
                 "involuntary_context_switches", "block_input_ops", "block_output_ops", "major_page_faults"):
        assert resources[name] is None, name
    assert resources["thread_cpu_seconds"] is not None       # thread_time stays portable


def test_span_exiting_on_another_thread_reports_no_thread_values() -> None:
    begin = spans._usage()
    holder: dict[str, Any] = {}
    worker = threading.Thread(target=lambda: holder.update(end=spans._usage()))
    worker.start()
    worker.join()
    resources = spans._resources(begin, holder["end"], spans.RESOURCE_SOURCE,
                                 thread_reason="span_exited_on_another_thread")
    assert resources["thread_cpu_seconds"] is None and resources["voluntary_context_switches"] is None
    assert resources["rusage_unavailable_reason"] == "span_exited_on_another_thread"


# --- section 2a: thread-state parsing from /proc --------------------------------------------------

def _fake_task(root: Path, tid: int, *, state: str = "D", wchan: str | None = "jbd2_log_wait_commit") -> None:
    task = root / "task" / str(tid)
    task.mkdir(parents=True)
    # The command name may itself contain ") "; parsing must anchor on the last parenthesis.
    after = [state, "1", "1", "1", "0", "-1", "0", "0", "0", "7", "0", "100", "50"]
    (task / "stat").write_text(f"{tid} (we) ird) {' '.join(after)}\n", encoding="ascii")
    if wchan is not None:
        (task / "wchan").write_text(wchan, encoding="ascii")
    (task / "status").write_text("Name:\tworker\nvoluntary_ctxt_switches:\t5\n"
                                 "nonvoluntary_ctxt_switches:\t2\n", encoding="ascii")
    (task / "io").write_text("read_bytes: 1024\nwrite_bytes: 8192\ncancelled_write_bytes: 4096\n",
                             encoding="ascii")


@POSIX
def test_thread_state_and_wait_channel_parse_from_proc(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(spans, "_PROC_ROOT", tmp_path)
    _fake_task(tmp_path, 11)
    _fake_task(tmp_path, 12, state="S", wchan="bad symbol!")
    _fake_task(tmp_path, 13, state="R", wchan="0")
    _fake_task(tmp_path, 14, state="S", wchan=None)
    _fake_task(tmp_path, 15, state="S", wchan="x" * 65)
    assert spans._thread_state(11) == ("D", "jbd2_log_wait_commit")
    assert spans._thread_state(12) == ("S", "other")
    assert spans._thread_state(13) == ("R", None)
    assert spans._thread_state(14) == ("S", None)
    assert spans._thread_state(15) == ("S", "other")
    assert spans._proc_tasks_available()

    usage = spans._proc_usage(11)
    assert usage.thread_cpu == pytest.approx(150 / os.sysconf("SC_CLK_TCK"))
    assert usage.rusage == {"voluntary_context_switches": 5, "involuntary_context_switches": 2,
                            "block_input_ops": 2, "block_output_ops": 8, "major_page_faults": 7}
    assert usage.io is None                                   # no fake /proc/self/io
    missing = spans._proc_usage(99)
    assert missing.rusage is None and missing.rusage_reason == "proc_thread_unavailable"


def test_thread_state_tally_is_bounded() -> None:
    span = spans.OperationSpan("unit.execute")
    for state, channel in (("D", "jbd2_log_wait_commit"), ("D", "jbd2_log_wait_commit"),
                           ("S", "do_epoll_wait"), ("R", None), ("Z", None), ("t", "ptrace_stop")):
        span.tally(state, channel)
    view = span.thread_state_view()
    assert {key: view[key] for key in ("samples", "R", "S", "D", "other")} == {
        "samples": 6, "R": 1, "S": 1, "D": 2, "other": 2}
    assert view["top_wait_channels"][0] == {"symbol": "jbd2_log_wait_commit", "samples": 2}
    for index in range(80):
        span.tally("S", f"symbol_{index:02d}")
    assert len(span.wait_channels) == spans._MAX_WAIT_SYMBOLS + 1    # overflow folds into "other"
    assert span.wait_channels["other"] == 80 - (spans._MAX_WAIT_SYMBOLS - 3)
    assert len(span.thread_state_view()["top_wait_channels"]) == 5


# --- section 3: progress heartbeats ---------------------------------------------------------------

def test_progress_heartbeats_are_cumulative_and_stop_on_exit(tmp_path: Path) -> None:
    spans.configure_operation_sampling(progress_interval_seconds=0.05, sample_interval_seconds=0.01)
    path = tmp_path / "events.jsonl"
    events = EventLog(path)
    with spans.operation_span(events, "unit.execute", unit_id="index.relationships") as span:
        spans.expect_work("artifacts_processed", 4)
        for _ in range(4):
            spans.count_work("artifacts_processed")
            with spans.operation_phase("index.prepare"):
                time.sleep(0.02)
        observed = span.progress_count
        _wait_for(lambda: span.progress_count >= observed + 2)
    exited = len(_events(path))
    time.sleep(0.2)
    records = _events(path)
    assert len(records) == exited                              # nothing after the span closed
    progress = [record for record in records if record["event"] == "OPERATION_PROGRESS"]
    completed = _one(records, "OPERATION_COMPLETED")
    assert completed["progress_count"] == len(progress) >= 2
    assert completed["progress_write_failures"] == 0 and completed["sampler_errors"] == 0
    assert completed["progress_unavailable_reason"] is None
    assert [record["progress_sequence"] for record in progress] == list(range(1, len(progress) + 1))
    elapsed = [record["elapsed_ms"] for record in progress]
    assert elapsed == sorted(elapsed) and elapsed[0] >= 40
    previous = 0
    for record in progress:
        assert not {"duration_ms", "terminal_status", "disposition", "completion_status"} & set(record)
        assert record["span_id"] == completed["span_id"] and record["unit_id"] == "index.relationships"
        assert record["operation_id"] == "unit.execute" and record["progress_interval_ms"] == 50
        assert set(record["resources"]) == set(completed["resources"])
        assert record["resources"]["measurement_source"] == spans.PROGRESS_RESOURCE_SOURCE
        assert record["work"].get("artifacts_processed", 0) >= previous
        previous = record["work"].get("artifacts_processed", 0)
    last = progress[-1]
    assert last["work"] == {"artifacts_processed": 4} and last["expected"] == {"artifacts_processed": 4}
    assert last["phases"]["index.prepare"]["count"] == 4
    assert completed["phases"]["index.prepare"]["count"] == 4
    if os.name == "posix":
        assert last["thread_states"]["samples"] >= 1 and last["thread_state_now"] is not None
        assert last["resources"]["rusage_scope"] == "thread"
        assert completed["thread_states"]["samples"] >= last["thread_states"]["samples"]
    _wait_for(lambda: spans._SAMPLER.thread is None)           # the idle sampler exits


def test_short_spans_report_no_samples_and_no_progress(tmp_path: Path) -> None:
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute"):
        pass
    completed = _one(_events(tmp_path / "events.jsonl"), "OPERATION_COMPLETED")
    assert completed["progress_count"] == 0
    assert completed["thread_states"] == {"samples": 0, "R": 0, "S": 0, "D": 0, "other": 0,
                                          "top_wait_channels": []}


def test_disabled_sampling_registers_nothing(tmp_path: Path) -> None:
    spans.configure_operation_sampling(progress_interval_seconds=0, sample_interval_seconds=0)
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute"):
        assert not spans._SAMPLER.entries
    completed = _one(_events(tmp_path / "events.jsonl"), "OPERATION_COMPLETED")
    assert completed["progress_unavailable_reason"] == "sampling_disabled"

    spans.configure_operation_sampling(progress_interval_seconds=0, sample_interval_seconds=0.01)
    with spans.operation_span(events, "unit.execute") as span:
        assert span.progress_unavailable_reason == "progress_disabled"
        time.sleep(0.05)
    assert not [record for record in _events(tmp_path / "events.jsonl")
                if record["event"] == "OPERATION_PROGRESS"]


def test_sampling_configuration_is_validated() -> None:
    for value in (-1, float("inf"), float("nan"), True, "1"):
        with pytest.raises(ValueError):
            spans.configure_operation_sampling(progress_interval_seconds=value)
        with pytest.raises(ValueError):
            spans.configure_operation_sampling(sample_interval_seconds=value)
    spans.configure_operation_sampling(progress_interval_seconds=2, sample_interval_seconds=0.5)
    assert spans.operation_sampling() == spans.SamplingSettings(2.0, 0.5)


def test_active_span_cap_marks_overflow_spans(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(spans, "MAX_SAMPLED_SPANS", 1)
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute"):
        with spans.operation_span(events, "attempt.prepare_inputs") as inner:
            assert inner.progress_unavailable_reason == "active_span_limit"
            assert len(spans._SAMPLER.entries) == 1
    completed = [record for record in _events(tmp_path / "events.jsonl")
                 if record["event"] == "OPERATION_COMPLETED"]
    assert [record["progress_unavailable_reason"] for record in completed] == ["active_span_limit", None]


@POSIX
def test_sampler_exceptions_are_swallowed_and_counted(tmp_path: Path, monkeypatch) -> None:
    def broken(_tid):
        raise RuntimeError("unreadable")

    monkeypatch.setattr(spans, "_thread_state", broken)
    spans.configure_operation_sampling(progress_interval_seconds=0, sample_interval_seconds=0.01)
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute") as span:
        _wait_for(lambda: span.sampler_errors >= 2)
    completed = _one(_events(tmp_path / "events.jsonl"), "OPERATION_COMPLETED")
    assert completed["terminal_status"] == "SUCCEEDED" and completed["sampler_errors"] >= 2


def test_progress_write_failures_are_counted_not_raised(tmp_path: Path) -> None:
    class FailingProgress(EventLog):
        def write(self, event: str, **fields: Any) -> None:
            if event == "OPERATION_PROGRESS":
                raise OSError("disk full")
            super().write(event, **fields)

    spans.configure_operation_sampling(progress_interval_seconds=0.02, sample_interval_seconds=0)
    events = FailingProgress(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute") as span:
        _wait_for(lambda: span.progress_write_failures >= 2)
    completed = _one(_events(tmp_path / "events.jsonl"), "OPERATION_COMPLETED")
    assert completed["progress_count"] == 0 and completed["progress_write_failures"] >= 2


def test_sampler_registry_resets_in_forked_child(tmp_path: Path) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    spans.configure_operation_sampling(progress_interval_seconds=60, sample_interval_seconds=60)
    events = EventLog(tmp_path / "events.jsonl")
    result = tmp_path / "child.json"
    with spans.operation_span(events, "unit.execute"):
        parent_sampler = spans._SAMPLER
        assert parent_sampler.entries
        pid = os.fork()
        if pid == 0:  # pragma: no cover - child process
            try:
                result.write_text(json.dumps({"fresh": spans._SAMPLER is not parent_sampler,
                                              "entries": len(spans._SAMPLER.entries)}))
            finally:
                os._exit(0)
        os.waitpid(pid, 0)
    assert json.loads(result.read_text()) == {"fresh": True, "entries": 0}


# --- section 4: phases -----------------------------------------------------------------------------

def test_operation_phase_accumulates_nested_inclusive_timings(tmp_path: Path) -> None:
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute") as span:
        for _ in range(2):
            with spans.operation_phase("index.publish"):
                with spans.operation_phase("storage.fsync"):
                    time.sleep(0.02)
        with spans.operation_phase("index.digest"):
            deadline = time.thread_time() + 0.03
            while time.thread_time() < deadline:
                pass
        phases = span.phase_view()
    assert list(phases) == sorted(phases) == ["index.digest", "index.publish", "storage.fsync"]
    assert phases["index.publish"]["count"] == phases["storage.fsync"]["count"] == 2
    assert phases["index.publish"]["wall_ms"] >= phases["storage.fsync"]["wall_ms"] >= 40
    assert phases["storage.fsync"]["off_cpu_ms"] >= 30            # sleeping is off-CPU
    assert phases["index.digest"]["thread_cpu_ms"] >= 25          # busy work is on-CPU
    for value in phases.values():
        assert value["off_cpu_ms"] == pytest.approx(max(0, value["wall_ms"] - value["thread_cpu_ms"]), abs=0.01)
    completed = _one(_events(tmp_path / "events.jsonl"), "OPERATION_COMPLETED")
    assert completed["phases"]["index.publish"]["count"] == 2


def test_operation_phase_vocabulary_cap_and_no_op_without_span(tmp_path: Path, monkeypatch) -> None:
    with pytest.raises(ValueError, match="unknown operation phase"):
        spans.operation_phase("index.anything")
    with spans.operation_phase("index.prepare") as phase:     # no active span: a no-op
        assert phase.span is None
    monkeypatch.setattr(spans, "MAX_SPAN_PHASES", 2)
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute") as span:
        for name in ("index.prepare", "index.digest", "index.link", "index.prepare"):
            with spans.operation_phase(name):
                pass
    assert {name: value["count"] for name, value in span.phase_view().items()} == {
        "index.digest": 1, "index.prepare": 2}


def test_phase_attributes_to_the_innermost_span(tmp_path: Path) -> None:
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute") as outer:
        with spans.operation_span(events, "attempt.prepare_inputs") as inner:
            with spans.operation_phase("index.link"):
                pass
    assert "index.link" in inner.phase_view() and not outer.phase_view()


# --- section 5: cardinality -----------------------------------------------------------------------

def test_expect_work_is_validated_and_last_value_wins(tmp_path: Path) -> None:
    for name, total in (("unknown_counter", 1), ("artifacts_processed", -1),
                        ("artifacts_processed", True), ("artifacts_processed", 1.5)):
        with pytest.raises(ValueError):
            spans.expect_work(name, total)
    spans.expect_work("artifacts_processed", 3)                 # no span: a no-op
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute"):
        spans.expect_work("artifacts_processed", 3)
        spans.expect_work("artifacts_processed", 5)
        for name in ("receipts_processed", "artifacts_processed", "shards_built", "shards_reused",
                     "entities_written", "relations_written", "invocations_scanned", "fsync_calls"):
            spans.count_work(name, 2)
    completed = _one(_events(tmp_path / "events.jsonl"), "OPERATION_COMPLETED")
    assert completed["expected"] == {"artifacts_processed": 5}
    assert completed["work"] == dict.fromkeys(sorted((
        "artifacts_processed", "entities_written", "fsync_calls", "invocations_scanned",
        "receipts_processed", "relations_written", "shards_built", "shards_reused")), 2)


def test_timed_fsync_counts_and_times_inside_a_span(tmp_path: Path) -> None:
    from appsec_review.storage.atomic import atomic_bytes, timed_fsync
    events = EventLog(tmp_path / "events.jsonl")
    with spans.operation_span(events, "unit.execute") as span:
        with (tmp_path / "f").open("wb") as stream:
            stream.write(b"x")
            timed_fsync(stream.fileno())
        atomic_bytes(tmp_path / "g", b"y")
    assert span.work_view()["fsync_calls"] >= 2
    assert span.phase_view()["storage.fsync"]["count"] == span.work_view()["fsync_calls"]
    with (tmp_path / "h").open("wb") as stream:
        timed_fsync(stream.fileno())                           # no span: plain fsync


# --- EventLog concurrency --------------------------------------------------------------------------

def test_concurrent_event_log_appends_are_whole_lines(tmp_path: Path) -> None:
    events = EventLog(tmp_path / "events.jsonl")
    payload = "p" * 16384

    def write(worker: int) -> None:
        for index in range(100):
            events.write("OPERATION_PROGRESS", worker=worker, index=index, payload=payload)

    threads = [threading.Thread(target=write, args=(worker,)) for worker in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    records = _events(tmp_path / "events.jsonl")
    assert len(records) == 800
    assert {(record["worker"], record["index"]) for record in records} == {
        (worker, index) for worker in range(8) for index in range(100)}


# --- section 6: aggregation -----------------------------------------------------------------------

JOB = "job_artifact_indexing"
SPAN = "a" * 32


def _write(run_dir: Path, log: _Log) -> Path:
    path = run_dir / "data" / "logs" / "pipeline.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join((json.dumps(record, sort_keys=True) + "\n").encode() for record in log.records))
    return run_dir


def _span_events(log: _Log, *, start: float, span_id: str = SPAN, heartbeats: tuple[float, ...] = (),
                 end: float | None = None, attempt: str = "a1", duration_ms: float | None = None,
                 completed: dict[str, Any] | None = None) -> None:
    correlation = {"span_id": span_id, "parent_span_id": None, "operation_id": "unit.execute",
                   "unit_id": "index.relationships", "scope_id": None, "query_profile": None,
                   "resource_lease_id": None, "tool_invocation_id": None}
    log(start, "OPERATION_STARTED", job=JOB, attempt=attempt, step="index", task="relationships",
        **correlation)
    for sequence, at in enumerate(heartbeats, 1):
        log(at, "OPERATION_PROGRESS", job=JOB, attempt=attempt, step="index", task="relationships",
            **correlation, progress_sequence=sequence, progress_interval_ms=60000,
            elapsed_ms=(at - start) * 1000, resources={"thread_off_cpu_seconds": 1.0},
            work={"artifacts_processed": 50 * sequence, "fsync_calls": 900 * sequence},
            expected={"artifacts_processed": 200}, phases={"index.sqlite_write": {
                "count": sequence, "wall_ms": 1000.0, "thread_cpu_ms": 10.0, "off_cpu_ms": 990.0}},
            thread_states={"samples": 60 * sequence, "R": 1, "S": 0, "D": 60 * sequence - 1, "other": 0,
                           "top_wait_channels": [{"symbol": "jbd2_log_wait_commit", "samples": 50}]},
            thread_state_now="D", wait_channel_now="jbd2_log_wait_commit")
    if end is not None:
        log(end, "OPERATION_COMPLETED", job=JOB, attempt=attempt, step="index", task="relationships",
            **correlation, terminal_status="SUCCEEDED",
            duration_ms=duration_ms if duration_ms is not None else (end - start) * 1000,
            progress_count=len(heartbeats), progress_write_failures=0, sampler_errors=0,
            progress_unavailable_reason=None, **(completed or {}))


def test_operation_progress_reports_running_spans_with_last_heartbeat(tmp_path: Path) -> None:
    log = _Log("run")
    log(0, "JOB_STARTED", job=JOB, attempt="a1")
    _span_events(log, start=1, heartbeats=(61, 121))
    _span_events(log, start=2, span_id="b" * 32)                # started, no heartbeat yet
    log(150, "TASK_STARTED", job=JOB, attempt="a1", step="other", task="other")
    metrics = aggregate_run_metrics(_write(tmp_path / "run", log))
    assert metrics["schema"] == RUN_METRICS_SCHEMA == "appsec-review/run-metrics/6"
    first, second = metrics["operation_progress"]
    assert first["span_id"] == SPAN and first["state"] == "running"
    assert first["stage"] == "unit.execute" and first["unit_id"] == "index.relationships"
    assert first["progress_sequence"] == 2 and first["elapsed_ms"] == 120000
    assert first["work"] == {"artifacts_processed": 100, "fsync_calls": 1800}
    assert first["expected"] == {"artifacts_processed": 200}
    assert first["completion_ratio"] == {"artifacts_processed": 0.5}
    assert first["thread_states"]["D"] == 119 and first["wait_channel_now"] == "jbd2_log_wait_commit"
    assert first["last_progress_at"].endswith("10:02:01+00:00")
    assert second["span_id"] == "b" * 32 and second["state"] == "running"
    assert second["last_progress_at"] is None and second["completion_ratio"] == {}
    assert metrics["duplicate_lifecycle_records"] == 0         # distinct heartbeats are not duplicates


def test_operation_progress_marks_stale_or_closed_spans_lost(tmp_path: Path) -> None:
    stale = _Log("run")
    _span_events(stale, start=1, heartbeats=(61,))
    stale(61 + 181, "TASK_STARTED", job=JOB, attempt="a1", step="other", task="other")
    assert aggregate_run_metrics(_write(tmp_path / "stale" / "run", stale))[
        "operation_progress"][0]["state"] == "lost"

    fresh = _Log("run")
    _span_events(fresh, start=1, heartbeats=(61,))
    fresh(61 + 179, "TASK_STARTED", job=JOB, attempt="a1", step="other", task="other")
    assert aggregate_run_metrics(_write(tmp_path / "fresh" / "run", fresh))[
        "operation_progress"][0]["state"] == "running"

    closed = _Log("run")
    _span_events(closed, start=1)
    closed(5, "JOB_FAILED", job=JOB, attempt="a1")
    row = aggregate_run_metrics(_write(tmp_path / "closed" / "run", closed))["operation_progress"][0]
    assert row["state"] == "lost" and row["last_progress_at"] is None


def test_out_of_order_and_repeated_heartbeats(tmp_path: Path) -> None:
    log = _Log("run")
    _span_events(log, start=1, heartbeats=(61, 121))
    second = log.records[-1]
    first = log.records[-2]
    log.records[-2], log.records[-1] = second, first            # newest first in the file
    log.records.append(dict(second))                             # a replayed heartbeat
    for sequence, record in enumerate(log.records, 1):
        record["sequence"] = sequence
    metrics = aggregate_run_metrics(_write(tmp_path / "run", log))
    assert metrics["operation_progress"][0]["progress_sequence"] == 2
    assert metrics["duplicate_lifecycle_records"] == 1 and not metrics["lifecycle_conflicts"]


def test_operation_progress_is_bounded(tmp_path: Path) -> None:
    log = _Log("run")
    for index in range(205):
        _span_events(log, start=1 + index * 0.001, span_id=f"{index:032x}")
    assert len(aggregate_run_metrics(_write(tmp_path / "run", log))["operation_progress"]) == 200


def test_progress_records_do_not_perturb_existing_aggregates(tmp_path: Path) -> None:
    def build(heartbeats: tuple[float, ...]) -> dict[str, Any]:
        log = _Log("run")
        log(0, "JOB_STARTED", job=JOB, attempt="a1")
        log(0.5, "TASK_STARTED", job=JOB, attempt="a1", step="index", task="relationships")
        _span_events(log, start=1, heartbeats=heartbeats, end=200, completed={
            "work": {"artifacts_processed": 200}, "phases": {}, "expected": {"artifacts_processed": 200},
            "thread_states": {"samples": 0, "R": 0, "S": 0, "D": 0, "other": 0, "top_wait_channels": []},
            "resources": {"thread_off_cpu_seconds": 1.0}})
        log(201, "TASK_SUCCEEDED", job=JOB, attempt="a1", step="index", task="relationships",
            duration_ms=200500, processed_count=200)
        log(202, "JOB_SUCCEEDED", job=JOB, attempt="a1", duration_ms=202000, artifact_count=200)
        return aggregate_run_metrics(_write(tmp_path / str(len(heartbeats)) / "run", log))

    with_progress, without = build((61, 121, 181)), build(())
    assert with_progress["raw_event_counts"]["OPERATION_PROGRESS"] == 3
    varying = {"event_count", "event_counts", "raw_event_count", "raw_event_counts", "resource_spans",
               "operation_hotspots"}
    assert {key: value for key, value in with_progress.items() if key not in varying} == {
        key: value for key, value in without.items() if key not in varying}
    for metrics in (with_progress, without):
        assert not metrics["lifecycle_gaps"] and metrics["lifecycle_accounting"] == "complete"
        assert "OPERATION_PROGRESS" not in metrics["duration_ms_by_event"]
        assert not metrics["operation_progress"]
    # The completion record alone carries the heartbeat count.
    assert with_progress["resource_spans"][0]["progress_count"] == 3
    assert without["resource_spans"][0]["progress_count"] == 0
    assert [{**row, "progress_count": None} for row in with_progress["resource_spans"]] == [
        {**row, "progress_count": None} for row in without["resource_spans"]]
    assert with_progress["operation_hotspots"] == without["operation_hotspots"]


def test_orphan_heartbeat_creates_no_lifecycle_gap(tmp_path: Path) -> None:
    log = _Log("run")
    _span_events(log, start=1, heartbeats=(61,))
    del log.records[0]                                           # no OPERATION_STARTED
    for sequence, record in enumerate(log.records, 1):
        record["sequence"] = sequence
    metrics = aggregate_run_metrics(_write(tmp_path / "run", log))
    assert not metrics["lifecycle_gaps"] and not metrics["operation_progress"]
    assert not metrics["dispositions"] and not metrics["throughput_totals"]


def test_openvex_metrics_ignore_progress_records(tmp_path: Path) -> None:
    def records(with_progress: bool) -> list[dict[str, Any]]:
        log = _Log("run")
        correlation = {"span_id": SPAN, "parent_span_id": None, "operation_id": "openvex.assemble"}
        log(1, "OPERATION_STARTED", job=OPENVEX_JOB_ID, attempt="a1", **correlation)
        if with_progress:
            log(61, "OPERATION_PROGRESS", job=OPENVEX_JOB_ID, attempt="a1", **correlation,
                progress_sequence=1, elapsed_ms=60000, work={})
        log(70, "OPERATION_COMPLETED", job=OPENVEX_JOB_ID, attempt="a1", **correlation,
            terminal_status="SUCCEEDED", duration_ms=69000, work={})
        return log.records

    assert aggregate_openvex_metrics(tmp_path, records(True)) == aggregate_openvex_metrics(
        tmp_path, records(False))


def test_operation_hotspots_explain_where_time_went(tmp_path: Path) -> None:
    log = _Log("run")
    _span_events(log, start=1, end=11, duration_ms=10000, completed={
        "resources": {"thread_off_cpu_seconds": 8.0},
        "thread_states": {"samples": 10, "R": 1, "S": 3, "D": 6, "other": 0,
                          "top_wait_channels": [{"symbol": "jbd2_log_wait_commit", "samples": 6}]},
        "phases": {"index.digest": {"count": 4, "wall_ms": 100.0},
                   "index.sqlite_write": {"count": 4, "wall_ms": 7000.0}},
        "work": {"artifacts_processed": 4, "shards_built": 3, "shards_reused": 1, "fsync_calls": 12}})
    _span_events(log, start=2, end=3, span_id="b" * 32, duration_ms=1000)
    for index in range(25):
        _span_events(log, start=20 + index, end=20.5 + index, span_id=f"{index:032x}", duration_ms=10)
    hotspots = aggregate_run_metrics(_write(tmp_path / "run", log))["operation_hotspots"]
    assert len(hotspots) == 20
    top = hotspots[0]
    assert top == {
        "job_id": JOB, "attempt_id": "a1", "span_id": SPAN, "stage": "unit.execute",
        "unit_id": "index.relationships", "terminal_status": "SUCCEEDED", "duration_ms": 10000,
        "thread_off_cpu_ratio": 0.8, "d_state_ratio": 0.6, "top_wait_channel": "jbd2_log_wait_commit",
        "dominant_phase": "index.sqlite_write", "dominant_phase_wall_ms": 7000.0,
        "ms_per_artifact": 2500.0, "fsync_calls_per_shard": 3.0,
    }
    bare = hotspots[1]
    assert bare["span_id"] == "b" * 32 and bare["duration_ms"] == 1000
    assert all(bare[key] is None for key in (
        "thread_off_cpu_ratio", "d_state_ratio", "top_wait_channel", "dominant_phase",
        "ms_per_artifact", "fsync_calls_per_shard"))


# --- section 6 D3: report -------------------------------------------------------------------------

def test_report_renders_progress_and_hotspot_sections(tmp_path: Path) -> None:
    from appsec_review.reporting.model import Box, Table
    from appsec_review.reporting.telemetry import load_inputs
    from appsec_review.reporting.telemetry.overview import overview_sections
    from appsec_review.reporting.tokens import BoxKind
    from tests.reporting.telemetry_fixture import build_telemetry_run

    def boxes(summary_update: dict[str, Any] | None, drop: tuple[str, ...] = ()) -> dict[str, Box]:
        run_dir = build_telemetry_run(tmp_path / str(len(list(tmp_path.iterdir()))))
        path = run_dir / "data" / "telemetry" / "summary.json"
        summary = json.loads(path.read_text(encoding="utf-8"))
        summary.update(summary_update or {})
        for key in drop:
            summary.pop(key)
        path.write_text(json.dumps(summary), encoding="utf-8")
        return {block.title: block for block in overview_sections(load_inputs(run_dir))
                if isinstance(block, Box)}

    def texts(box: Box) -> list[str]:
        table = next(item for item in box.items if isinstance(item, Table))
        return [" | ".join(cell.text for cell in row) for row in table.rows]

    running = {"span_id": "r", "stage": "unit.execute", "unit_id": "index.members", "state": "running",
               "started_at": "2026-10-21T10:00:01+00:00", "last_progress_at": "2026-10-21T10:01:01+00:00",
               "elapsed_ms": 60000, "work": {"artifacts_processed": 5}, "expected": {"artifacts_processed": 10},
               "completion_ratio": {"artifacts_processed": 0.5}, "thread_state_now": "S",
               "wait_channel_now": None}
    lost = {**running, "span_id": "l", "unit_id": "index.relationships", "state": "lost",
            "started_at": "2026-10-21T10:00:05+00:00", "thread_state_now": "D",
            "wait_channel_now": "jbd2_log_wait_commit"}
    hotspot = {"stage": "unit.execute", "unit_id": "index.relationships", "duration_ms": 2711000,
               "thread_off_cpu_ratio": 0.84, "d_state_ratio": 0.7, "top_wait_channel": "jbd2_log_wait_commit",
               "dominant_phase": "index.sqlite_write", "ms_per_artifact": 317.4, "fsync_calls_per_shard": 140.0}
    shown = boxes({"operation_progress": [running, lost], "operation_hotspots": [hotspot]})
    progress = shown["Operations in progress"]
    assert progress.kind is BoxKind.GAP and progress.meta == "1 lost"
    rows = texts(progress)
    assert rows[0].startswith("unit.execute [index.relationships] | lost")    # lost spans first
    assert "jbd2_log_wait_commit" in rows[0] and "artifacts_processed 5/10" in rows[1]
    hot = texts(shown["Operation hotspots"])
    assert len(hot) == 1 and "index.sqlite_write" in hot[0] and "jbd2_log_wait_commit" in hot[0]
    assert "fsync/shard" in hot[0] and "/artifact" in hot[0]

    empty = boxes({"operation_progress": [], "operation_hotspots": []})
    assert empty["Operations in progress"].kind is BoxKind.RESULT
    assert empty["Operation hotspots"].kind is BoxKind.RESULT
    legacy = boxes(None, drop=("operation_progress", "operation_hotspots"))
    assert legacy["Operations in progress"].kind is BoxKind.GAP
    assert legacy["Operation hotspots"].kind is BoxKind.GAP


# --- configuration ---------------------------------------------------------------------------------

def test_runtime_intervals_are_typed_and_applied_by_the_runner(tmp_path: Path) -> None:
    from appsec_review.runtime.runner import JobRunner
    from tests.test_config import _variant

    default = _variant(tmp_path / "default")
    assert default.runtime.operation_progress_interval_seconds == 60.0
    assert default.runtime.operation_sample_interval_seconds == 1.0
    configured = _variant(tmp_path / "configured", ("[runtime]\n", "[runtime]\n"
                          "operation_progress_interval_seconds = 5\noperation_sample_interval_seconds = 0.5\n"))
    assert configured.runtime.operation_progress_interval_seconds == 5.0
    assert configured.resolved_sha256 != default.resolved_sha256
    JobRunner(configured)
    assert spans.operation_sampling() == spans.SamplingSettings(5.0, 0.5)
    for bad, message in (("-1", "finite and non-negative"), ('"1"', "number of seconds"),
                         ("true", "number of seconds")):
        with pytest.raises(ValueError, match=message):
            _variant(tmp_path / f"bad-{len(message)}-{bad.strip('\"')}", (
                "[runtime]\n", f"[runtime]\noperation_progress_interval_seconds = {bad}\n"))


# --- sections 4/5 wiring and section 7 switch: artifact indexing --------------------------------------

def _indexing_run(tmp_path: Path, monkeypatch, *, disable_spans: bool = False):
    from appsec_review.jobs.job_artifact_indexing import build_job
    from appsec_review.runtime import GraphRunner
    from appsec_review.runtime import runner as runner_module
    from tests.test_artifact_indexing import RUN_ID, _publish_changed_language_receipts, _seed

    config, target, snapshot, run_root, receipts, accepted_path, handoff_path, latest = _seed(tmp_path)
    receipt = receipts[0]
    obj = receipt["artifacts"][0]
    receipt["tool_invocations"] = [{
        "tool": "cc", "tool_kind": "compiler", "parent_command_id": receipt["commands"][0]["command_id"],
        "origin": "execution-capture:command-001:event-7", "argv_sha256": "c" * 64,
        "mapping_confidence": 1.0, "inputs": [],
        "outputs": [{"workspace_path": obj["workspace_path"], "sha256": obj["sha256"]}],
    }]
    _publish_changed_language_receipts(run_root, receipts, accepted_path, handoff_path, latest)
    monkeypatch.setattr(runner_module, "configure_operation_sampling", lambda **_: None)
    spans.configure_operation_sampling(progress_interval_seconds=0.01, sample_interval_seconds=0.005)
    original = spans.operation_span

    @contextmanager
    def without_operation_measurement(*args, **kwargs):
        yield None

    with monkeypatch.context() as patch:
        if disable_spans:
            for name, module in tuple(sys.modules.items()):
                if name.startswith("appsec_review.") and module is not None:
                    if getattr(module, "operation_span", None) is original:
                        patch.setattr(module, "operation_span", without_operation_measurement)
        GraphRunner(config, [build_job()]).run(target_root=target, source_fingerprint=snapshot, run_id=RUN_ID)
        rerun = GraphRunner(config, [build_job()]).run(
            target_root=target, source_fingerprint=snapshot, run_id=RUN_ID, force_from="job_artifact_indexing")
    return run_root, receipts, rerun


def test_artifact_indexing_records_phases_counters_and_expected_totals(tmp_path: Path, monkeypatch) -> None:
    run_root, receipts, _rerun = _indexing_run(tmp_path, monkeypatch)
    records, torn = PipelineLog(run_root).read()
    assert not torn
    units: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        details = record["details"]
        if record["event_type"] == "OPERATION_COMPLETED" and details.get("operation_id") == "unit.execute":
            units.setdefault(details["unit_id"], []).append(details)
    for unit in ("index.catalogs", "index.members", "index.relationships"):
        built, reused = units[unit]
        for details in (built, reused):
            work, expected = details["work"], details["expected"]
            assert expected["artifacts_processed"] >= 1
            assert work["receipts_processed"] == len(receipts)
            assert "index.lock_wait" in details["phases"]
        assert built["work"].get("shards_built", 0) >= 1
        assert reused["work"].get("shards_reused", 0) >= 1 and not reused["work"].get("shards_built")
        assert "index.reuse_verify" in reused["phases"]
    relationships, reused_relationships = units["index.relationships"]
    artifacts = relationships["expected"]["artifacts_processed"]
    assert relationships["work"]["artifacts_processed"] == artifacts
    assert relationships["work"]["shards_built"] == artifacts             # one relation shard per artifact
    assert reused_relationships["work"]["shards_reused"] == artifacts
    assert relationships["work"]["invocations_scanned"] == sum(
        len(receipt["artifacts"]) * len(receipt.get("tool_invocations", ())) for receipt in receipts)
    assert relationships["work"]["relations_written"] >= 1
    assert {"index.prepare", "index.sqlite_write", "index.sqlite_vacuum", "index.digest",
            "index.link"} <= set(relationships["phases"])
    progress = [record for record in records if record["event_type"] == "OPERATION_PROGRESS"]
    metrics = aggregate_run_metrics(run_root)
    assert metrics["operation_hotspots"] and not metrics["operation_progress"]
    assert len(progress) == sum(span["progress_count"] or 0 for span in metrics["resource_spans"])
    assert any(span["phases"] for span in metrics["resource_spans"])


def test_disabling_operation_spans_disables_sampler_phases_and_counters(tmp_path: Path, monkeypatch) -> None:
    run_root, _receipts, rerun = _indexing_run(tmp_path, monkeypatch, disable_spans=True)
    assert rerun["jobs"]["job_artifact_indexing"]
    records, _torn = PipelineLog(run_root).read()
    assert not [record for record in records if record["event_type"].startswith("OPERATION_")]
    assert not spans._SAMPLER.entries
    metrics = aggregate_run_metrics(run_root)
    assert not metrics["resource_spans"] and not metrics["operation_progress"]
    assert not metrics["operation_hotspots"] and not metrics["work_counters"]
