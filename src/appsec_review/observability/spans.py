"""Bounded operation measurements in the existing run-owned event stream.

A span records process and thread resource deltas when it completes. While it is open, one lazily
started daemon sampler tallies the span thread's scheduler state and periodically writes an
``OPERATION_PROGRESS`` snapshot, so a long or killed span leaves its last known state. Per-item work
(counters, expected totals and sub-phase timings) is aggregated in memory and never emitted per item.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import math
import os
from pathlib import Path
import re
import threading
import time
from typing import Any, Iterator
from uuid import uuid4

from .events import EventLog

try:
    import resource as _resource
except ImportError:  # pragma: no cover - not available on Windows
    _resource = None  # type: ignore[assignment]


_ACTIVE: ContextVar[OperationSpan | None] = ContextVar("review_operation_span", default=None)
_COUNTERS = frozenset({
    "target_hash_bytes", "target_hash_objects", "copy_bytes", "copy_objects", "custody_alias_objects",
    "path_count", "receipt_references", "receipt_validations",
    "shard_references", "shard_validations", "manifest_validations",
    "scratch_paths", "assembly_count", "platform_scan_invocations",
    "platform_hash_bytes", "cache_hits", "cache_misses", "builder_launches", "preinstalled_runtimes",
    "handoff_validations", "native_output_references", "native_output_bytes",
    "observation_references", "provenance_gaps",
    "receipts_processed", "artifacts_processed", "shards_built", "shards_reused",
    "entities_written", "relations_written", "invocations_scanned", "fsync_calls",
})
_PHASES = frozenset({
    "index.prepare", "index.sqlite_write", "index.sqlite_vacuum", "index.digest", "index.publish",
    "index.link", "index.custody_bind", "index.lock_wait", "index.reuse_verify",
    "storage.fsync", "storage.copy", "build.output_classify",
})
MAX_SPAN_PHASES = 32
MAX_SAMPLED_SPANS = 32
_TOP_WAIT_CHANNELS = 5
_MAX_WAIT_SYMBOLS = 64
_WCHAN = re.compile(r"[A-Za-z0-9_.]{1,64}")
_SAMPLED_STATES = ("R", "S", "D")
_RUSAGE_FIELDS = ("voluntary_context_switches", "involuntary_context_switches",
                  "block_input_ops", "block_output_ops", "major_page_faults")
RESOURCE_SOURCE = "os.times/proc-self-io/getrusage-thread/thread_time"
PROGRESS_RESOURCE_SOURCE = "os.times/proc-self-io/proc-self-task"
_PROC_ROOT = Path("/proc/self")


@dataclass(frozen=True, slots=True)
class SamplingSettings:
    progress_interval_seconds: float = 60.0
    sample_interval_seconds: float = 1.0


_settings = SamplingSettings()


def configure_operation_sampling(*, progress_interval_seconds: float = 60.0,
                                 sample_interval_seconds: float = 1.0) -> None:
    """Set the process-wide progress and thread-state sampling cadence; 0 disables either."""
    global _settings
    for name, value in (("progress_interval_seconds", progress_interval_seconds),
                        ("sample_interval_seconds", sample_interval_seconds)):
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value < 0):
            raise ValueError(f"{name} must be a finite non-negative number")
    _settings = SamplingSettings(float(progress_interval_seconds), float(sample_interval_seconds))


def operation_sampling() -> SamplingSettings:
    return _settings


def _io() -> dict[str, int] | None:
    if os.name != "posix":
        return None
    try:
        lines = (_PROC_ROOT / "io").read_text(encoding="ascii").splitlines()
    except OSError:
        return None
    values = dict(line.split(": ", 1) for line in lines if ": " in line)
    try:
        result = {name: int(values[name]) for name in ("rchar", "wchar", "read_bytes", "write_bytes")}
        result.update({name: int(values[name]) for name in ("syscr", "syscw") if name in values})
    except (KeyError, ValueError):
        return None
    return result


def _rusage_thread() -> tuple[dict[str, int] | None, str | None]:
    if _resource is None or not hasattr(_resource, "RUSAGE_THREAD"):
        return None, "rusage_thread_unavailable"
    try:
        usage = _resource.getrusage(_resource.RUSAGE_THREAD)
    except (OSError, ValueError):
        return None, "rusage_thread_unavailable"
    return {"voluntary_context_switches": usage.ru_nvcsw, "involuntary_context_switches": usage.ru_nivcsw,
            "block_input_ops": usage.ru_inblock, "block_output_ops": usage.ru_oublock,
            "major_page_faults": usage.ru_majflt}, None


@dataclass(frozen=True, slots=True)
class _Usage:
    monotonic_ns: int
    cpu_user: float
    cpu_system: float
    io: dict[str, int] | None
    thread_id: int
    thread_cpu: float | None
    rusage: dict[str, int] | None
    rusage_reason: str | None


def _usage() -> _Usage:
    """Measure on the calling (span) thread."""
    cpu = os.times()
    rusage, reason = _rusage_thread()
    return _Usage(time.monotonic_ns(), cpu.user, cpu.system, _io(), threading.get_native_id(),
                  time.thread_time(), rusage, reason)


def _stat_fields(tid: int) -> list[str]:
    text = (_PROC_ROOT / "task" / str(tid) / "stat").read_text(encoding="ascii", errors="replace")
    return text[text.rindex(")") + 2:].split()


def _proc_usage(tid: int) -> _Usage:
    """Measure another thread from /proc, for progress snapshots taken on the sampler thread."""
    cpu = os.times()
    thread_cpu = rusage = None
    reason: str | None = "proc_thread_unavailable"
    if os.name == "posix":
        try:
            fields = _stat_fields(tid)
            ticks = os.sysconf("SC_CLK_TCK")
            thread_cpu = (int(fields[11]) + int(fields[12])) / ticks
            base = _PROC_ROOT / "task" / str(tid)
            status = dict(line.split(":", 1) for line in
                          (base / "status").read_text(encoding="ascii", errors="replace").splitlines()
                          if ":" in line)
            io = dict(line.split(": ", 1) for line in
                      (base / "io").read_text(encoding="ascii").splitlines() if ": " in line)
            written = max(0, int(io["write_bytes"]) - int(io.get("cancelled_write_bytes", 0)))
            rusage = {"voluntary_context_switches": int(status["voluntary_ctxt_switches"]),
                      "involuntary_context_switches": int(status["nonvoluntary_ctxt_switches"]),
                      "block_input_ops": int(io["read_bytes"]) >> 9, "block_output_ops": written >> 9,
                      "major_page_faults": int(fields[9])}
            reason = None
        except (OSError, ValueError, KeyError, IndexError):
            rusage = None
    return _Usage(time.monotonic_ns(), cpu.user, cpu.system, _io(), tid, thread_cpu, rusage, reason)


def _resources(start: _Usage, end: _Usage, source: str, *, thread_reason: str | None = None) -> dict[str, Any]:
    wall = max(0, end.monotonic_ns - start.monotonic_ns) / 1_000_000_000
    resources: dict[str, Any] = {
        "measurement_scope": "process_inclusive_not_additive",
        "measurement_source": source,
        "cpu_user_seconds": max(0, end.cpu_user - start.cpu_user),
        "cpu_system_seconds": max(0, end.cpu_system - start.cpu_system),
        "child_cpu_seconds": None,
        "child_cpu_unavailable_reason": "children_accounted_by_executor_not_parent_span",
        "peak_rss_bytes": None,
        "peak_rss_unavailable_reason": "process_high_water_mark_not_attributable_to_span",
        "logical_read_bytes": None, "logical_write_bytes": None,
        "physical_read_bytes": None, "physical_write_bytes": None,
        "io_unavailable_reason": None,
        "read_syscalls": None, "write_syscalls": None,
        "thread_cpu_seconds": None, "thread_off_cpu_seconds": None,
        **dict.fromkeys(_RUSAGE_FIELDS),
        "rusage_scope": None, "rusage_unavailable_reason": None,
    }
    if start.io is None or end.io is None:
        resources["io_unavailable_reason"] = "proc_io_unavailable"
    else:
        for field_name, proc_name in (
            ("logical_read_bytes", "rchar"), ("logical_write_bytes", "wchar"),
            ("physical_read_bytes", "read_bytes"), ("physical_write_bytes", "write_bytes"),
            ("read_syscalls", "syscr"), ("write_syscalls", "syscw"),
        ):
            if proc_name in start.io and proc_name in end.io:
                resources[field_name] = max(0, end.io[proc_name] - start.io[proc_name])
    if thread_reason is None and start.thread_cpu is not None and end.thread_cpu is not None:
        thread_cpu = max(0.0, end.thread_cpu - start.thread_cpu)
        resources["thread_cpu_seconds"] = round(thread_cpu, 6)
        resources["thread_off_cpu_seconds"] = round(max(0.0, wall - thread_cpu), 6)
    if thread_reason is None and start.rusage is not None and end.rusage is not None:
        for name in _RUSAGE_FIELDS:
            resources[name] = max(0, end.rusage[name] - start.rusage[name])
        resources["rusage_scope"] = "thread"
    else:
        resources["rusage_unavailable_reason"] = (
            thread_reason or end.rusage_reason or start.rusage_reason or "rusage_thread_unavailable")
    return resources


def _wait_symbol(value: str | None) -> str | None:
    if not value or value == "0":
        return None
    return value if _WCHAN.fullmatch(value) else "other"


def _thread_state(tid: int) -> tuple[str, str | None]:
    state = _stat_fields(tid)[0][:1]
    try:
        wchan = (_PROC_ROOT / "task" / str(tid) / "wchan").read_text(encoding="ascii", errors="replace").strip()
    except OSError:
        wchan = ""
    return state, _wait_symbol(wchan)


def _proc_tasks_available() -> bool:
    return os.name == "posix" and (_PROC_ROOT / "task").is_dir()


@dataclass
class OperationSpan:
    stage: str
    span_id: str = field(default_factory=lambda: uuid4().hex)
    unit_id: str | None = None
    scope_id: str | None = None
    query_profile: str | None = None
    resource_lease_id: str | None = None
    tool_invocation_id: str | None = None
    counters: dict[str, int] = field(default_factory=dict)
    status: str = "SUCCEEDED"
    lock: Any = field(default_factory=threading.Lock)
    expected: dict[str, int] = field(default_factory=dict)
    phases: dict[str, list[int]] = field(default_factory=dict)
    state_counts: Counter = field(default_factory=Counter)
    wait_channels: Counter = field(default_factory=Counter)
    progress_count: int = 0
    progress_write_failures: int = 0
    sampler_errors: int = 0
    progress_unavailable_reason: str | None = None

    def count(self, name: str, value: int = 1) -> None:
        if name not in _COUNTERS or type(value) is not int or value < 0:
            raise ValueError("invalid bounded operation counter")
        with self.lock:
            self.counters[name] = self.counters.get(name, 0) + value

    def expect(self, name: str, total: int) -> None:
        if name not in _COUNTERS or type(total) is not int or total < 0:
            raise ValueError("invalid expected operation work")
        with self.lock:
            self.expected[name] = total

    def add_phase(self, name: str, wall_ns: int, cpu_ns: int) -> None:
        with self.lock:
            entry = self.phases.get(name)
            if entry is None:
                if len(self.phases) >= MAX_SPAN_PHASES:
                    return
                entry = self.phases[name] = [0, 0, 0]
            entry[0] += 1
            entry[1] += max(0, wall_ns)
            entry[2] += max(0, cpu_ns)

    def tally(self, state: str, wait_channel: str | None) -> None:
        with self.lock:
            self.state_counts["samples"] += 1
            self.state_counts[state if state in _SAMPLED_STATES else "other"] += 1
            if wait_channel is not None:
                if wait_channel not in self.wait_channels and len(self.wait_channels) >= _MAX_WAIT_SYMBOLS:
                    wait_channel = "other"
                self.wait_channels[wait_channel] += 1

    def work_view(self) -> dict[str, int]:
        with self.lock:
            return dict(sorted(self.counters.items()))

    def expected_view(self) -> dict[str, int]:
        with self.lock:
            return dict(sorted(self.expected.items()))

    def phase_view(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            items = sorted((name, tuple(values)) for name, values in self.phases.items())
        return {name: {"count": count, "wall_ms": round(wall / 1_000_000, 3),
                       "thread_cpu_ms": round(cpu / 1_000_000, 3),
                       "off_cpu_ms": round(max(0, wall - cpu) / 1_000_000, 3)}
                for name, (count, wall, cpu) in items}

    def thread_state_view(self) -> dict[str, Any]:
        with self.lock:
            states = dict(self.state_counts)
            channels = list(self.wait_channels.items())
        top = sorted(channels, key=lambda item: (-item[1], item[0]))[:_TOP_WAIT_CHANNELS]
        return {"samples": states.get("samples", 0),
                **{name: states.get(name, 0) for name in (*_SAMPLED_STATES, "other")},
                "top_wait_channels": [{"symbol": symbol, "samples": samples} for symbol, samples in top]}


def count_work(name: str, value: int = 1) -> None:
    span = _ACTIVE.get()
    if span is not None:
        span.count(name, value)


def expect_work(name: str, total: int) -> None:
    """Declare the expected total of a counter on the innermost span; the last value wins."""
    if name not in _COUNTERS or type(total) is not int or total < 0:
        raise ValueError("invalid expected operation work")
    span = _ACTIVE.get()
    if span is not None:
        span.expect(name, total)


class _Phase:
    __slots__ = ("name", "span", "wall", "cpu")

    def __init__(self, name: str):
        self.name = name
        self.span: OperationSpan | None = None
        self.wall = self.cpu = 0

    def __enter__(self) -> _Phase:
        self.span = _ACTIVE.get()
        if self.span is not None:
            self.wall = time.monotonic_ns()
            self.cpu = time.thread_time_ns()
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.span is not None:
            self.span.add_phase(self.name, time.monotonic_ns() - self.wall, time.thread_time_ns() - self.cpu)
            self.span = None


def operation_phase(name: str) -> _Phase:
    """Time a named sub-phase into the innermost span (inclusive when nested; no-op without a span)."""
    if name not in _PHASES:
        raise ValueError(f"unknown operation phase: {name}")
    return _Phase(name)


class _Registration:
    __slots__ = ("owner", "span", "events", "correlation", "start", "sample_interval",
                 "progress_interval", "next_sample", "next_progress", "closed", "progress_lock")

    def __init__(self, owner: _Sampler, span: OperationSpan, events: EventLog,
                 correlation: dict[str, Any], start: _Usage, settings: SamplingSettings):
        self.owner = owner
        self.span = span
        self.events = events
        self.correlation = correlation
        self.start = start
        self.sample_interval = settings.sample_interval_seconds
        self.progress_interval = settings.progress_interval_seconds
        begun = start.monotonic_ns / 1_000_000_000
        self.next_sample = begun + self.sample_interval if self.sample_interval else math.inf
        self.next_progress = begun + self.progress_interval if self.progress_interval else math.inf
        self.closed = False
        self.progress_lock = threading.Lock()


class _Sampler:
    """One daemon thread per process sampling the registered, currently open spans."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.entries: dict[str, _Registration] = {}
        self.thread: threading.Thread | None = None
        # Registration wakes an idle tick so a new span's cadence starts on schedule.
        self.wake = threading.Event()

    def register(self, span: OperationSpan, events: EventLog, correlation: dict[str, Any],
                 start: _Usage) -> _Registration | None:
        settings = _settings
        if not settings.progress_interval_seconds and not settings.sample_interval_seconds:
            span.progress_unavailable_reason = "sampling_disabled"
            return None
        with self.lock:
            if len(self.entries) >= MAX_SAMPLED_SPANS:
                span.progress_unavailable_reason = "active_span_limit"
                return None
            entry = _Registration(self, span, events, correlation, start, settings)
            self.entries[span.span_id] = entry
            self.wake.set()
            if self.thread is None:
                thread = threading.Thread(target=self._run, name="operation-span-sampler", daemon=True)
                try:
                    thread.start()
                except RuntimeError:
                    self.entries.pop(span.span_id, None)
                    span.sampler_errors += 1
                    span.progress_unavailable_reason = "sampler_unavailable"
                    return None
                self.thread = thread
        if not settings.progress_interval_seconds:
            span.progress_unavailable_reason = "progress_disabled"
        return entry

    def unregister(self, entry: _Registration) -> None:
        with entry.progress_lock:
            entry.closed = True
        with self.lock:
            self.entries.pop(entry.span.span_id, None)

    def _run(self) -> None:
        idle = False
        try:
            while True:
                with self.lock:
                    entries = list(self.entries.values())
                    if not entries:
                        if idle:
                            self.thread = None
                            return
                        idle = True
                    else:
                        idle = False
                settings = _settings
                tick = min((value for value in (settings.sample_interval_seconds,
                                                settings.progress_interval_seconds) if value > 0), default=1.0)
                proc = bool(entries) and _proc_tasks_available()
                for entry in entries:
                    self._service(entry, proc)
                now = time.monotonic()
                earliest = min((min(entry.next_sample if proc else math.inf, entry.next_progress)
                                for entry in entries), default=math.inf)
                self.wake.wait(max(0.001, min(tick, earliest - now)))
                self.wake.clear()
        except BaseException:  # pragma: no cover - interpreter shutdown
            with self.lock:
                if self.thread is threading.current_thread():
                    self.thread = None

    def _service(self, entry: _Registration, proc: bool) -> None:
        span = entry.span
        try:
            now = time.monotonic()
            if proc and now >= entry.next_sample:
                entry.next_sample = now + entry.sample_interval
                span.tally(*_thread_state(entry.start.thread_id))
            if now >= entry.next_progress:
                entry.next_progress = now + entry.progress_interval
                self._progress(entry, proc)
        except Exception:
            with span.lock:
                span.sampler_errors += 1

    def _progress(self, entry: _Registration, proc: bool) -> None:
        span = entry.span
        with entry.progress_lock:
            if entry.closed:
                return
            now = _proc_usage(entry.start.thread_id)
            state_now = wait_now = None
            if proc:
                try:
                    state_now, wait_now = _thread_state(entry.start.thread_id)
                except (OSError, ValueError, IndexError):
                    with span.lock:
                        span.sampler_errors += 1
            sequence = span.progress_count + 1
            record = {
                **entry.correlation, "progress_sequence": sequence,
                "progress_interval_ms": round(entry.progress_interval * 1000),
                "elapsed_ms": round((now.monotonic_ns - entry.start.monotonic_ns) / 1_000_000, 3),
                "resources": _resources(entry.start, now, PROGRESS_RESOURCE_SOURCE),
                "work": span.work_view(), "expected": span.expected_view(), "phases": span.phase_view(),
                "thread_states": span.thread_state_view(),
                "thread_state_now": state_now, "wait_channel_now": wait_now,
            }
            try:
                entry.events.write("OPERATION_PROGRESS", **record)
            except Exception:
                with span.lock:
                    span.progress_write_failures += 1
                return
            with span.lock:
                span.progress_count = sequence


_SAMPLER = _Sampler()


def _close(entry: _Registration) -> None:
    if entry.owner is _SAMPLER:
        entry.owner.unregister(entry)
    else:
        entry.closed = True


def _reset_after_fork() -> None:
    """The sampler thread does not survive fork; inherited spans must not wait on its locks."""
    global _SAMPLER
    for entry in list(_SAMPLER.entries.values()):
        entry.closed = True
        entry.progress_lock = threading.Lock()
        entry.span.lock = threading.Lock()
    _SAMPLER = _Sampler()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


@contextmanager
def operation_span(events: EventLog, stage: str, *, unit_id: str | None = None,
                   scope_id: str | None = None, query_profile: str | None = None,
                   resource_lease_id: str | None = None,
                   tool_invocation_id: str | None = None) -> Iterator[OperationSpan]:
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", stage):
        raise ValueError("operation stage must be a bounded identifier")
    parent = _ACTIVE.get()
    context = {
        name: value if value is not None else getattr(parent, name, None)
        for name, value in (("unit_id", unit_id), ("scope_id", scope_id),
                            ("query_profile", query_profile), ("resource_lease_id", resource_lease_id),
                            ("tool_invocation_id", tool_invocation_id))
    }
    for name, value in context.items():
        if value is not None and (not isinstance(value, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", value)):
            raise ValueError(f"operation {name} must be a bounded identifier")
    span = OperationSpan(stage, **context)
    token = _ACTIVE.set(span)
    start = _usage()
    correlation = {"span_id": span.span_id, "parent_span_id": parent.span_id if parent else None,
                   "operation_id": stage, **context}
    try:
        events.write("OPERATION_STARTED", **correlation)
        entry = _SAMPLER.register(span, events, correlation, start)
        try:
            yield span
        except BaseException:
            span.status = "FAILED"
            raise
        finally:
            if entry is not None:
                _close(entry)
            end = _usage()
            moved = None if end.thread_id == start.thread_id else "span_exited_on_another_thread"
            with span.lock:
                progress = (span.progress_count, span.progress_write_failures, span.sampler_errors)
            events.write("OPERATION_COMPLETED", **correlation, terminal_status=span.status,
                         duration_ms=(end.monotonic_ns - start.monotonic_ns) / 1_000_000,
                         resources=_resources(start, end, RESOURCE_SOURCE, thread_reason=moved),
                         work=span.work_view(), expected=span.expected_view(), phases=span.phase_view(),
                         thread_states=span.thread_state_view(), progress_count=progress[0],
                         progress_write_failures=progress[1], sampler_errors=progress[2],
                         progress_unavailable_reason=span.progress_unavailable_reason)
    finally:
        _ACTIVE.reset(token)
