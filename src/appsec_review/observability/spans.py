"""Bounded operation measurements in the existing run-owned event stream."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import time
from threading import Lock
from typing import Any, Iterator
from uuid import uuid4

from .events import EventLog


_ACTIVE: ContextVar[OperationSpan | None] = ContextVar("review_operation_span", default=None)
_COUNTERS = frozenset({
    "target_hash_bytes", "target_hash_objects", "copy_bytes", "copy_objects", "custody_alias_objects",
    "path_count", "receipt_references", "receipt_validations",
    "shard_references", "shard_validations", "manifest_validations",
    "scratch_paths", "assembly_count", "platform_scan_invocations",
    "platform_hash_bytes", "cache_hits", "cache_misses", "builder_launches",
})


def _io() -> dict[str, int] | None:
    if os.name != "posix":
        return None
    path = Path("/proc/self/io")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (FileNotFoundError, PermissionError):
        return None
    values = dict(line.split(": ", 1) for line in lines)
    return {name: int(values[name]) for name in ("rchar", "wchar", "read_bytes", "write_bytes")}


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
    lock: Any = field(default_factory=Lock)

    def count(self, name: str, value: int = 1) -> None:
        if name not in _COUNTERS or type(value) is not int or value < 0:
            raise ValueError("invalid bounded operation counter")
        with self.lock:
            self.counters[name] = self.counters.get(name, 0) + value


def count_work(name: str, value: int = 1) -> None:
    span = _ACTIVE.get()
    if span is not None:
        span.count(name, value)


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
    start = time.monotonic_ns()
    cpu = os.times()
    io = _io()
    correlation = {"span_id": span.span_id, "parent_span_id": parent.span_id if parent else None,
                   "operation_id": stage, **context}
    try:
        events.write("OPERATION_STARTED", **correlation)
        try:
            yield span
        except BaseException:
            span.status = "FAILED"
            raise
        finally:
            end_cpu = os.times()
            end_io = _io()
            resources: dict[str, Any] = {
                "measurement_scope": "process_inclusive_not_additive",
                "measurement_source": "os.times/proc-self-io",
                "cpu_user_seconds": max(0, end_cpu.user - cpu.user),
                "cpu_system_seconds": max(0, end_cpu.system - cpu.system),
                "child_cpu_seconds": None,
                "child_cpu_unavailable_reason": "children_accounted_by_executor_not_parent_span",
                "peak_rss_bytes": None,
                "peak_rss_unavailable_reason": "process_high_water_mark_not_attributable_to_span",
                "logical_read_bytes": None, "logical_write_bytes": None,
                "physical_read_bytes": None, "physical_write_bytes": None,
                "io_unavailable_reason": None,
            }
            if io is None or end_io is None:
                resources["io_unavailable_reason"] = "proc_io_unavailable"
            else:
                for field_name, proc_name in (
                    ("logical_read_bytes", "rchar"), ("logical_write_bytes", "wchar"),
                    ("physical_read_bytes", "read_bytes"), ("physical_write_bytes", "write_bytes"),
                ):
                    resources[field_name] = max(0, end_io[proc_name] - io[proc_name])
            with span.lock:
                work = dict(sorted(span.counters.items()))
            events.write("OPERATION_COMPLETED", **correlation, terminal_status=span.status,
                         duration_ms=(time.monotonic_ns() - start) / 1_000_000,
                         resources=resources, work=work)
    finally:
        _ACTIVE.reset(token)
