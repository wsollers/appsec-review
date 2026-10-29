"""Read-only inputs of the run telemetry report.

``load_inputs`` reads ``data/logs/pipeline.jsonl`` (authoritative) and ``data/telemetry/summary.json``
(``appsec-review/run-metrics/6``). A missing, unreadable or mismatched summary is recomputed in
memory with :func:`aggregate_run_metrics` and never written back. Anything that cannot be read is a
named gap; it is never reported as zero work or as a clean run.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.observability.events import PipelineLog
from appsec_review.observability.telemetry import RUN_METRICS_SCHEMA, aggregate_run_metrics, validate_event

SUMMARY_PATH = Path("data") / "telemetry" / "summary.json"
EVENTS_PATH = Path("data") / "logs" / "pipeline.jsonl"
JOB_TERMINALS = {
    "JOB_SUCCEEDED": "SUCCEEDED", "JOB_COMPLETED_WITH_GAPS": "COMPLETED_WITH_GAPS",
    "JOB_FAILED": "FAILED", "JOB_CANCELLED": "CANCELLED", "JOB_CANCELED": "CANCELLED",
    "JOB_TIMED_OUT": "TIMED_OUT",
}
RUN_TERMINALS = {
    "GRAPH_SUCCEEDED": "SUCCEEDED", "GRAPH_COMPLETED_WITH_GAPS": "COMPLETED_WITH_GAPS",
    "GRAPH_FAILED": "FAILED", "GRAPH_CANCELED": "CANCELLED", "RUN_COMPLETED": None,
}
_STATUS_ALIASES = {"FAILURE": "FAILED", "CANCELED": "CANCELLED", "SUCCESS": "SUCCEEDED"}
# Run and job statuses reuse the verdict colours of tokens.py.
STATUS_TONE = {"SUCCEEDED": "confirmed", "COMPLETED_WITH_GAPS": "insufficient_evidence",
               "FAILED": "contradicted", "CANCELLED": "unresolved", "TIMED_OUT": "contradicted",
               "RUNNING": "proposed", "UNKNOWN": "unresolved"}


@dataclass(frozen=True, slots=True)
class JobSpan:
    """One job attempt on the run timeline; offsets are milliseconds from the run's first event."""

    job_id: str
    attempt_id: str
    status: str                       # a JOB_TERMINALS value, or RUNNING when no terminal was seen
    start_ms: int
    end_ms: int | None                # None while RUNNING
    started_at: str
    ended_at: str | None
    event_count: int


@dataclass(frozen=True, slots=True)
class TelemetryInputs:
    run_id: str
    summary: Mapping[str, Any]        # run-metrics/6 document, or {} when unavailable
    summary_source: str               # "summary.json" | "recomputed" | "unavailable"
    summary_sha256: str | None        # of the summary bytes on disk (summary.json source only)
    events: tuple[Mapping[str, Any], ...]
    events_sha256: str | None         # of the pipeline.jsonl bytes read
    torn_tail: bool
    run_started_at: str | None
    run_ended_at: str | None
    completion_status: str            # a STATUS_TONE key; the last run/graph terminal wins
    source_date_epoch: int
    jobs: tuple[JobSpan, ...]         # ordered by (start_ms, job_id, attempt_id)
    named_gaps: tuple[str, ...]


def _timestamp(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _offset(origin: datetime, value: datetime) -> int:
    return max(0, int((value - origin).total_seconds() * 1000))


def job_spans(events: tuple[Mapping[str, Any], ...]) -> tuple[JobSpan, ...]:
    """Job attempts from JOB_STARTED (else the attempt's first event) to its JOB_* terminal."""
    stamps = [stamp for stamp in (_timestamp(event.get("timestamp")) for event in events) if stamp]
    if not stamps:
        return ()
    origin = min(stamps)
    attempts: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        job = str(event.get("job_id") or "-")
        stamp = _timestamp(event.get("timestamp"))
        if job == "-" or stamp is None:
            continue
        key = (job, str(event.get("attempt_id") or "-"))
        state = attempts.setdefault(key, {"first": stamp, "started": None, "end": None,
                                          "status": "RUNNING", "count": 0})
        state["count"] += 1
        state["first"] = min(state["first"], stamp)
        kind = str(event.get("event_type"))
        if kind == "JOB_STARTED" and state["started"] is None:
            state["started"] = stamp
        elif kind in JOB_TERMINALS:
            state["end"], state["status"] = stamp, JOB_TERMINALS[kind]
    spans = []
    for (job, attempt), state in attempts.items():
        begun = state["started"] or state["first"]
        ended = state["end"]
        start_ms = _offset(origin, begun)
        spans.append(JobSpan(job_id=job, attempt_id=attempt, status=state["status"], start_ms=start_ms,
                             end_ms=None if ended is None else max(start_ms, _offset(origin, ended)),
                             started_at=begun.isoformat(), ended_at=None if ended is None else ended.isoformat(),
                             event_count=state["count"]))
    return tuple(sorted(spans, key=lambda span: (span.start_ms, span.job_id, span.attempt_id)))


def _completion(events: tuple[Mapping[str, Any], ...]) -> tuple[str, str | None]:
    status, ended = "UNKNOWN", None
    for event in events:
        kind = str(event.get("event_type"))
        if kind not in RUN_TERMINALS:
            continue
        details = event.get("details") if isinstance(event.get("details"), Mapping) else {}
        raw = details.get("completion_status") or RUN_TERMINALS[kind]
        if raw:
            raw = _STATUS_ALIASES.get(str(raw), str(raw))
            status = raw if raw in STATUS_TONE else "UNKNOWN"
            ended = str(event.get("timestamp"))
    return status, ended


def load_inputs(run_dir: Path) -> TelemetryInputs:
    run_dir = Path(run_dir)
    gaps: list[str] = []
    events: tuple[Mapping[str, Any], ...] = ()
    events_sha256 = None
    torn = False
    if not (run_dir / EVENTS_PATH).is_file():
        gaps.append("pipeline_event_log_missing")
    else:
        try:
            payload = (run_dir / EVENTS_PATH).read_bytes()
            records, torn = PipelineLog(run_dir).read()
            for record in records:
                validate_event(record)
            events, events_sha256 = tuple(records), hashlib.sha256(payload).hexdigest()
        except (OSError, ValueError):
            gaps.append("pipeline_event_log_unreadable")
    if torn:
        gaps.append("pipeline_event_log_torn_tail_ignored")

    summary: Mapping[str, Any] = {}
    summary_source, summary_sha256 = "unavailable", None
    try:
        payload = (run_dir / SUMMARY_PATH).read_bytes()
        candidate = json.loads(payload)
        if (isinstance(candidate, Mapping) and candidate.get("schema") == RUN_METRICS_SCHEMA
                and candidate.get("run_id") == run_dir.name):
            summary, summary_source = candidate, "summary.json"
            summary_sha256 = hashlib.sha256(payload).hexdigest()
        else:
            gaps.append("metrics_summary_schema_mismatch")
    except FileNotFoundError:
        gaps.append("metrics_summary_missing")
    except (OSError, ValueError):
        gaps.append("metrics_summary_unreadable")
    if not summary and events:
        try:
            summary, summary_source = aggregate_run_metrics(run_dir), "recomputed"
        except Exception:  # noqa: BLE001 - any derivation failure is a named gap, not a crash
            gaps.append("metrics_summary_recompute_failed")

    stamps = sorted(stamp for stamp in (_timestamp(event.get("timestamp")) for event in events) if stamp)
    status, ended = _completion(events)
    ended_stamp = (_timestamp(ended) if ended else None) or (stamps[-1] if stamps else None)
    return TelemetryInputs(
        run_id=run_dir.name, summary=summary, summary_source=summary_source,
        summary_sha256=summary_sha256, events=events, events_sha256=events_sha256, torn_tail=torn,
        run_started_at=stamps[0].isoformat() if stamps else None,
        run_ended_at=ended_stamp.isoformat() if ended_stamp else None,
        completion_status=status,
        source_date_epoch=int(ended_stamp.timestamp()) if ended_stamp else 0,
        jobs=job_spans(events), named_gaps=tuple(gaps))
