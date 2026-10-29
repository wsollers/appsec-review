"""Part I of the run telemetry report: the whole-run overview, and the closing appendix.

Pure, deterministic functions of :class:`TelemetryInputs` returning renderer-neutral blocks. Every
string taken from the run (job, tool, model and operation names, error classes, gap records) is
cleaned and bounded through ``reporting.text``. A value that was not recorded is shown as
``unavailable``, never as zero.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping

from ..model import (Bar, BarChart, Block, Box, Bullets, Cell, Field, Fields, Heading, Lane, Note, Para,
                     Segment, Stat, Stats, Table, Timeline, Truncation)
from ..text import anchor, bound, clean, sha256_value
from ..tokens import BoxKind
from . import format as fmt
from .inputs import STATUS_TONE, JobSpan, TelemetryInputs

LANE_LIMIT = 24
BAR_LIMIT = 16
OPERATION_LIMIT = 12
MODEL_LIMIT = 12
TOOL_LIMIT = 12
GAP_LIMIT = 16
LABEL_CHARS = 64
CELL_CHARS = 96
VALUE_CHARS = 220
FAILED = {"FAILED", "TIMED_OUT"}
_OK_TERMINALS = {"succeeded", "success", "completed", "accepted"}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _short(value: Any, limit: int = CELL_CHARS) -> str:
    """Cleaned and cut; a cut is marked with an ellipsis (cells and labels carry no truncation slot)."""
    text, cut = bound(value, limit)
    return f"{text}\u2026" if cut else text


def _operation_label(value: Any) -> str:
    """``job/step/task/tool`` with unset trailing parts dropped; run- and job-level operations are named."""
    parts = clean(value).split("/")
    while parts and parts[-1] in ("", "-"):
        parts.pop()
    if not parts:
        return "(run)"
    return f"{parts[0]} (job)" if len(parts) == 1 else "/".join(parts)


def _field(label: str, value: Any, *, mono: bool = False, badge: str | None = None) -> Field:
    text, cut = bound(value if value not in (None, "") else fmt.UNAVAILABLE, VALUE_CHARS)
    return Field(label, text, mono=mono, badge=badge, truncation=cut)


def _cap(items: list[Any], limit: int, unit: str = "rows") -> tuple[list[Any], Truncation | None]:
    if len(items) <= limit:
        return items, None
    rest = items[limit:]
    return items[:limit], Truncation(omitted=len(rest), unit=unit, sha256=sha256_value(rest))


def _mapping(summary: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = summary.get(key)
    return value if isinstance(value, Mapping) else {}


def _records(summary: Mapping[str, Any], key: str) -> list[Mapping[str, Any]] | None:
    value = summary.get(key)
    if not isinstance(value, list):
        return None
    return [item for item in value if isinstance(item, Mapping)]


def _status_tone(status: str) -> str:
    return STATUS_TONE.get(status, STATUS_TONE["UNKNOWN"])


def _total_ms(inputs: TelemetryInputs) -> int:
    wall = _number(inputs.summary.get("wall_time_ms"))
    ends = [max(span.start_ms, span.end_ms or 0) for span in inputs.jobs]
    return max(int(wall or 0), *ends, 0) if ends else int(wall or 0)


def _end(span: JobSpan, total_ms: int) -> int:
    return max(span.start_ms, total_ms if span.end_ms is None else span.end_ms)


def _attempt_counts(jobs: Iterable[JobSpan]) -> Counter[str]:
    return Counter(span.job_id for span in jobs)


def _job_counts(inputs: TelemetryInputs) -> dict[str, int]:
    statuses = Counter(span.status for span in inputs.jobs)
    return {"jobs": len({span.job_id for span in inputs.jobs}), "attempts": len(inputs.jobs),
            "succeeded": statuses["SUCCEEDED"], "gaps": statuses["COMPLETED_WITH_GAPS"],
            "failed": sum(statuses[status] for status in FAILED), "cancelled": statuses["CANCELLED"],
            "running": statuses["RUNNING"]}


def _model_calls(inputs: TelemetryInputs) -> list[Mapping[str, Any]] | None:
    return _records(inputs.summary, "model_invocations")


# --- executive summary -------------------------------------------------------------------------

def _summary_blocks(inputs: TelemetryInputs) -> tuple[Block, ...]:
    summary = inputs.summary
    counts = _job_counts(inputs)
    calls = _model_calls(inputs)
    tokens = _mapping(summary, "model_tokens")
    token_values = [_number(tokens.get(key)) for key in ("input_tokens", "output_tokens")]
    missing_usage = sum(1 for call in calls or () if _number(call.get("input_tokens")) is None)
    total_tokens = (fmt.compact(sum(token_values)) if tokens and all(v is not None for v in token_values)
                    else fmt.UNAVAILABLE)
    tool_calls = _mapping(summary, "tool_calls")
    tool_total = sum(int(v) for v in tool_calls.values() if _number(v) is not None)
    findings = _mapping(summary, "finding_states")
    finding_total = sum(int(v) for v in findings.values() if _number(v) is not None)
    if counts["failed"]:
        job_tone = "contradicted"
    elif counts["running"]:
        job_tone = "proposed"
    elif counts["gaps"]:
        job_tone = "insufficient_evidence"
    else:
        job_tone = "confirmed" if counts["attempts"] else "neutral"
    gap_count = len(inputs.named_gaps)
    stats = Stats((
        Stat("Completion", inputs.completion_status.replace("_", " ").lower(),
             _status_tone(inputs.completion_status)),
        Stat("Wall time", fmt.duration(summary.get("wall_time_ms"))),
        Stat("Jobs", fmt.count(counts["jobs"]) if counts["attempts"] else fmt.UNAVAILABLE, job_tone),
        Stat("Model calls", fmt.count(len(calls)) if calls is not None else fmt.UNAVAILABLE),
        Stat("Tokens (in + out)", total_tokens, "insufficient_evidence" if missing_usage else "neutral"),
        Stat("Tool calls", fmt.count(tool_total) if "tool_calls" in summary else fmt.UNAVAILABLE),
        Stat("Finding transitions", fmt.count(finding_total) if "finding_states" in summary else fmt.UNAVAILABLE),
        Stat("Named gaps", fmt.count(gap_count), "coverage_gap" if gap_count else "neutral"),
    ))
    if counts["attempts"]:
        jobs_line = (f"{fmt.plural(counts['attempts'], 'attempt')} of {fmt.plural(counts['jobs'], 'job')}: "
                     f"{fmt.count(counts['succeeded'])} succeeded, {fmt.count(counts['gaps'])} completed with gaps, "
                     f"{fmt.count(counts['failed'])} failed, {fmt.count(counts['cancelled'])} cancelled, "
                     f"{fmt.count(counts['running'])} still running.")
    else:
        jobs_line = "No job attempts were recorded; job counts are unavailable."
    notes: list[Block] = [stats, Note(jobs_line)]
    if missing_usage:
        notes.append(Note(f"{fmt.plural(missing_usage, 'model call')} recorded no token usage; the token total "
                          "covers only the calls that did and is a lower bound."))
    return tuple(notes)


# --- run timeline ------------------------------------------------------------------------------

def _timeline(inputs: TelemetryInputs) -> Block:
    if not inputs.jobs:
        return Note("No job spans were recorded; the run timeline is unavailable.")
    total = max(_total_ms(inputs), 1)
    attempts = _attempt_counts(inputs.jobs)
    lanes = []
    for span in inputs.jobs:
        name = _short(span.job_id, LABEL_CHARS)
        if attempts[span.job_id] > 1:
            name = f"{name} ({_short(span.attempt_id, 24)})"
        end = _end(span, total)
        state = span.status.replace("_", " ").lower()
        annotation = fmt.duration(end - span.start_ms)
        if span.end_ms is None:
            annotation += " (running)"
        lanes.append(Lane(name, (Segment(span.start_ms, end, _status_tone(span.status), state),), annotation))
    shown, omitted = _cap(lanes, LANE_LIMIT, "lanes")
    return Timeline(
        title="Job attempts over the run", total_ms=total, lanes=tuple(shown), omitted=omitted,
        caption=(f"One lane per job attempt on a 0 to {fmt.duration(total)} axis from the run's first event; "
                 "colour follows the attempt's terminal status. Running attempts extend to the last event."))


# --- where the time went ------------------------------------------------------------------------

def _job_bars(inputs: TelemetryInputs) -> Block:
    total = _total_ms(inputs)
    last_status: dict[str, str] = {}
    bounds: dict[str, tuple[int, int]] = {}
    for span in inputs.jobs:
        last_status[span.job_id] = span.status
        low, high = bounds.get(span.job_id, (span.start_ms, span.start_ms))
        bounds[span.job_id] = (min(low, span.start_ms), max(high, _end(span, total)))
    derived = {job: high - low for job, (low, high) in bounds.items()}
    family = {str(job): int(value) for job, value in _mapping(inputs.summary, "job_family_wall_span_ms").items()
              if job != "-" and _number(value) is not None and value >= 0}
    spans = family or derived
    if not spans:
        return Note("No job wall spans were recorded; per-job wall time is unavailable.")
    ordered = sorted(spans.items(), key=lambda item: (-item[1], item[0]))
    bars = [Bar(_short(job, LABEL_CHARS), float(value), fmt.duration(value),
                _status_tone(last_status[job]) if job in last_status else "neutral")
            for job, value in ordered]
    shown, omitted = _cap(bars, BAR_LIMIT, "bars")
    source = "the metrics summary" if family else "the job spans in the event log"
    return BarChart(title="Wall span per job", unit="longest first", bars=tuple(shown), omitted=omitted,
                    caption=(f"First to last event of each job across all attempts, from {source}; "
                             "colour follows the job's latest attempt."))


def _time_fields(inputs: TelemetryInputs) -> Box:
    summary = inputs.summary
    critical = _mapping(summary, "critical_path_candidate")
    queue = _mapping(summary, "queue_delay_ms")
    wall = _number(summary.get("wall_time_ms"))
    summed = _number(summary.get("summed_concurrent_task_ms"))
    ratio = f"{summed / wall:.2f}x" if wall and summed is not None else fmt.UNAVAILABLE
    critical_operation = critical.get("operation")
    rows = [
        _field("Critical path candidate", _operation_label(critical_operation) if critical_operation else None,
               mono=True),
        Field("Its duration", fmt.duration(critical.get("duration_ms"))),
        Field("Share of wall time", fmt.percent(critical.get("contribution_ratio"))),
        Field("Wall time", fmt.duration(wall)),
        Field("Summed task time", fmt.duration(summed)),
        Field("Parallelism", f"{ratio} (task time / wall time)" if ratio != fmt.UNAVAILABLE else ratio),
        Field("Queue delays observed", fmt.count(queue.get("count"))),
        Field("Queue delay p50 / p95 / max", " / ".join(fmt.duration(queue.get(key)) for key in ("p50", "p95", "max"))),
    ]
    return Box(BoxKind.RESULT, "Critical path and concurrency", chip="TIME", items=(
        Fields(tuple(rows)),
        Para("The critical path candidate is the longest single task interval; it bounds, not proves, "
             "what limited the run.", muted=True)))


def _operations(inputs: TelemetryInputs) -> Box:
    records = _records(inputs.summary, "operations")
    if not records:
        return Box(BoxKind.GAP, "Slowest operations", items=(
            Para("Operation timings are unavailable: the metrics summary recorded none."),))
    ordered = sorted(records, key=lambda item: (-(_number(item.get("p95_ms")) or 0), clean(item.get("operation"))))
    shown, omitted = _cap(ordered, OPERATION_LIMIT)
    rows = tuple((Cell(_short(_operation_label(item.get("operation"))), mono=True), Cell(fmt.count(item.get("count"))),
                  Cell(fmt.duration(item.get("p50_ms"))), Cell(fmt.duration(item.get("p95_ms"))),
                  Cell(fmt.duration(item.get("max_ms")))) for item in shown)
    return Box(BoxKind.RESULT, "Slowest operations", meta="by p95 duration", chip="TIME", items=(
        Table(("Operation (job/step/task/tool)", "Count", "p50", "p95", "Max"), rows,
              (0.52, 0.10, 0.12, 0.13, 0.13), omitted),))


def _span_label(item: Mapping[str, Any]) -> str:
    stage = clean(item.get("stage") or "-")
    unit = clean(item.get("unit_id") or "")
    return _short(f"{stage} [{unit}]" if unit else stage)


def _completion(item: Mapping[str, Any]) -> str:
    work = item.get("work") if isinstance(item.get("work"), Mapping) else {}
    expected = item.get("expected") if isinstance(item.get("expected"), Mapping) else {}
    ratios = item.get("completion_ratio") if isinstance(item.get("completion_ratio"), Mapping) else {}
    parts = [f"{clean(name)} {fmt.count(work.get(name, 0))}/{fmt.count(total)} ({fmt.percent(ratios.get(name))})"
             for name, total in sorted(expected.items(), key=lambda pair: clean(pair[0]))]
    return _short("; ".join(parts)) if parts else fmt.NA


def _progress(inputs: TelemetryInputs) -> Box:
    records = _records(inputs.summary, "operation_progress")
    title = "Operations in progress"
    if records is None:
        return Box(BoxKind.GAP, title, items=(
            Para("In-progress operation state is unavailable: the metrics summary predates heartbeats."),))
    if not records:
        return Box(BoxKind.RESULT, title, chip="TIME", items=(
            Para("Every started operation span recorded a completion."),))
    ordered = sorted(records, key=lambda item: (clean(item.get("state")) != "lost",
                                                clean(item.get("started_at")), clean(item.get("span_id"))))
    shown, omitted = _cap(ordered, OPERATION_LIMIT)
    rows = tuple((Cell(_span_label(item), mono=True), Cell(_short(item.get("state") or fmt.NA, 16)),
                  Cell(fmt.duration(item.get("elapsed_ms")) if item.get("elapsed_ms") is not None else fmt.NA),
                  Cell(_short(item.get("last_progress_at") or "none", 40)),
                  Cell(_completion(item)),
                  Cell(_short(" ".join(clean(value) for value in (item.get("thread_state_now"),
                                                                   item.get("wait_channel_now")) if value)
                              or fmt.NA, 48), mono=True)) for item in shown)
    lost = sum(1 for item in records if clean(item.get("state")) == "lost")
    return Box(BoxKind.GAP if lost else BoxKind.RESULT, title, meta=f"{fmt.count(lost)} lost",
               chip="TIME", items=(
        Table(("Operation [unit]", "State", "Elapsed", "Last heartbeat", "Progress vs expected",
               "Thread now"), rows, (0.26, 0.08, 0.10, 0.18, 0.26, 0.12), omitted),
        Para("A lost span started but never completed: its attempt closed or its heartbeats stopped. "
             "The last heartbeat is its last known state; n/a means not recorded.", muted=True)))


def _hotspots(inputs: TelemetryInputs) -> Box:
    records = _records(inputs.summary, "operation_hotspots")
    title = "Operation hotspots"
    if records is None:
        return Box(BoxKind.GAP, title, items=(
            Para("Operation hotspots are unavailable: the metrics summary predates them."),))
    if not records:
        return Box(BoxKind.RESULT, title, chip="TIME", items=(Para("No completed operation spans were timed."),))
    shown, omitted = _cap(list(records), OPERATION_LIMIT)
    rows = []
    for item in shown:
        rates = []
        if item.get("ms_per_artifact") is not None:
            rates.append(f"{fmt.duration(item.get('ms_per_artifact'))}/artifact")
        if item.get("fsync_calls_per_shard") is not None:
            rates.append(f"{_number(item.get('fsync_calls_per_shard')) or 0:.1f} fsync/shard")
        rows.append((Cell(_span_label(item), mono=True), Cell(fmt.duration(item.get("duration_ms"))),
                     Cell(fmt.percent(item.get("thread_off_cpu_ratio")) if item.get("thread_off_cpu_ratio")
                          is not None else fmt.NA),
                     Cell(fmt.percent(item.get("d_state_ratio")) if item.get("d_state_ratio") is not None
                          else fmt.NA),
                     Cell(_short(item.get("top_wait_channel") or fmt.NA, 40), mono=True),
                     Cell(_short(item.get("dominant_phase") or fmt.NA, 40), mono=True),
                     Cell(_short(", ".join(rates) or fmt.NA, 48))))
    return Box(BoxKind.RESULT, title, meta="longest completed spans", chip="TIME", items=(
        Table(("Operation [unit]", "Duration", "Off-CPU", "D state", "Top wait", "Dominant phase", "Per item"),
              tuple(rows), (0.24, 0.10, 0.09, 0.09, 0.16, 0.16, 0.16), omitted),
        Para("Off-CPU is span-thread wall time not spent on CPU; D state is the share of 1 s thread samples "
             "in uninterruptible (usually I/O) sleep. n/a means not recorded.", muted=True)))


# --- run-wide usage ----------------------------------------------------------------------------

def _token_cell(values: list[float | None]) -> str:
    present = [value for value in values if value is not None]
    if not present:
        return fmt.NA
    text = fmt.count(sum(present))
    return text if len(present) == len(values) else f"{text} (partial)"


def _models(inputs: TelemetryInputs) -> Box:
    calls = _model_calls(inputs)
    if calls is None:
        return Box(BoxKind.GAP, "Model usage", items=(Para("Model usage is unavailable: no metrics summary."),))
    if not calls:
        return Box(BoxKind.RESULT, "Model usage", chip="USAGE", items=(Para("No model calls were recorded."),))
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for call in calls:
        groups.setdefault((_short(call.get("model") or "unknown", 64),
                           _short(call.get("role") or "-", 32)), []).append(call)
    rows = []
    for (model, role), members in sorted(groups.items()):
        failed = sum(1 for call in members if clean(call.get("terminal_status")).lower() not in _OK_TERMINALS)
        durations = [_number(call.get("duration_ms")) for call in members]
        rows.append((Cell(model, mono=True), Cell(role), Cell(fmt.count(len(members))), Cell(fmt.count(failed)),
                     *(Cell(_token_cell([_number(call.get(key)) for call in members]))
                       for key in ("input_tokens", "output_tokens", "cache_tokens")),
                     Cell(_token_cell(durations) if None in durations else fmt.duration(sum(durations)))))
    shown, omitted = _cap(rows, MODEL_LIMIT)
    errors = sorted({_short(call.get("error_class"), CELL_CHARS) for call in calls if call.get("error_class")})
    errors_shown, errors_omitted = _cap(errors, 6, "error classes")
    items: list[Any] = [Table(("Model", "Role", "Calls", "Failed", "Input", "Output", "Cache", "Time"),
                              tuple(shown), (0.26, 0.10, 0.08, 0.08, 0.13, 0.12, 0.11, 0.12), omitted),
                        Para("Token counts a provider did not report are shown as n/a, never as zero; "
                             "'partial' sums only the calls that reported usage.", muted=True)]
    if errors_shown:
        items.append(Bullets(tuple(f"Error class: {error}" for error in errors_shown), errors_omitted))
    return Box(BoxKind.RESULT, "Model usage", meta="by model and role", chip="USAGE", items=tuple(items))


def _tools(inputs: TelemetryInputs) -> Box:
    counts = _mapping(inputs.summary, "tool_calls")
    stats: dict[str, dict[str, Any]] = {}
    for event in inputs.events:
        if event.get("event_type") != "TOOL_INVOCATION_COMPLETED":
            continue
        details = event.get("details") if isinstance(event.get("details"), Mapping) else {}
        tool = clean(details.get("tool_id") or details.get("mcp_tool") or "unknown")
        entry = stats.setdefault(tool, {"failed": 0, "ms": 0, "timed": 0})
        if clean(details.get("terminal_status") or details.get("disposition")).lower() not in _OK_TERMINALS:
            entry["failed"] += 1
        if _number(details.get("duration_ms")) is not None:
            entry["ms"] += int(details["duration_ms"])
            entry["timed"] += 1
    names = {clean(name): value for name, value in counts.items()}
    if not names and not stats:
        reason = "No tool calls were recorded." if "tool_calls" in inputs.summary else (
            "Tool usage is unavailable: no metrics summary or tool events.")
        return Box(BoxKind.RESULT, "Tool calls", chip="USAGE", items=(Para(reason),))
    rows = []
    for name in sorted(set(names) | set(stats)):
        entry = stats.get(name)
        rows.append((Cell(_short(name), mono=True), Cell(fmt.count(names.get(name))),
                     Cell(fmt.count(entry["failed"]) if entry else fmt.UNAVAILABLE),
                     Cell(fmt.duration(entry["ms"]) if entry and entry["timed"] else fmt.UNAVAILABLE)))
    shown, omitted = _cap(rows, TOOL_LIMIT)
    return Box(BoxKind.RESULT, "Tool calls", meta="by tool", chip="USAGE", items=(
        Table(("Tool", "Calls", "Failed", "Total time"), tuple(shown), (0.55, 0.15, 0.15, 0.15), omitted),))


def _builds_and_findings(inputs: TelemetryInputs) -> Box:
    builds = _mapping(inputs.summary, "project_image_builds")
    rows = [Field(label, fmt.count(builds.get(key)) if builds else fmt.UNAVAILABLE)
            for label, key in (("Image builds started", "started"), ("Built", "built"),
                               ("Reused", "reused"), ("Failed", "failed"))]
    by_family = _mapping(builds, "failed_by_family")
    if by_family:
        rows.append(_field("Failed by family", ", ".join(
            f"{clean(family)}: {fmt.count(value)}" for family, value in sorted(by_family.items()))))
    findings = _mapping(inputs.summary, "finding_states")
    if findings:
        finding_rows = tuple((Cell(_short(state)), Cell(fmt.count(value)))
                             for state, value in sorted(findings.items(), key=lambda item: clean(item[0])))
        finding_item: Any = Table(("Finding state reached", "Transitions"), finding_rows, (0.6, 0.4))
    else:
        finding_item = Para("Finding state transitions: unavailable." if "finding_states" not in inputs.summary
                            else "No finding state transitions were recorded.")
    return Box(BoxKind.RESULT, "Project images and finding lifecycle", chip="USAGE", items=(
        Fields(tuple(rows)), finding_item,
        Para("Finding transitions count lifecycle events, not security conclusions; see the review report.",
             muted=True)))


# --- data quality ------------------------------------------------------------------------------

def _gap_line(record: Mapping[str, Any]) -> str:
    where = "/".join(clean(record.get(key) or "-") for key in ("job_id", "attempt_id"))
    parts = [clean(record.get("family") or "-"), where]
    if record.get("invocation_id"):
        parts.append(clean(record.get("invocation_id")))
    return _short(f"{' '.join(parts)}: {clean(record.get('reason') or 'unspecified')}", VALUE_CHARS)


def _quality(inputs: TelemetryInputs) -> Box:
    summary = inputs.summary
    named = [_short(gap, VALUE_CHARS) for gap in inputs.named_gaps]
    lifecycle = [_gap_line(item) for item in _records(summary, "lifecycle_gaps") or ()]
    running = [_gap_line({**item, "reason": f"started {clean(item.get('started_at'))}, no terminal yet"})
               for item in _records(summary, "genuinely_running") or ()]
    source = {"summary.json": "read from data/telemetry/summary.json",
              "recomputed": "recomputed in memory from the event log (summary.json was not usable)",
              }.get(inputs.summary_source, "unavailable")
    rows = (Field("Metrics summary", source),
            Field("Lifecycle accounting", _short(summary.get("lifecycle_accounting") or fmt.UNAVAILABLE)),
            Field("Event log", "present" if inputs.events_sha256 else fmt.UNAVAILABLE),
            Field("Torn final record", "ignored" if inputs.torn_tail or summary.get("torn_tail_ignored") else "none"),
            Field("Named gaps", fmt.count(len(named))),
            Field("Lifecycle gaps", fmt.count(len(lifecycle)) if "lifecycle_gaps" in summary else fmt.UNAVAILABLE),
            Field("Still running", fmt.count(len(running)) if "genuinely_running" in summary else fmt.UNAVAILABLE))
    items: list[Any] = [Fields(rows), Para(
        "Missing, unreadable or incomplete telemetry is a named gap, not zero work and not a clean run. "
        "Values shown as unavailable were not recorded.")]
    for label, entries in (("Named gap", named), ("Lifecycle gap", lifecycle), ("Running", running)):
        shown, omitted = _cap(entries, GAP_LIMIT, "entries")
        if shown:
            items.append(Bullets(tuple(f"{label}: {entry}" for entry in shown), omitted))
    gap_total = len(named) + len(lifecycle)
    # Only an observed gap gets gap styling; a clean data-quality record reads as provenance.
    return Box(BoxKind.GAP if gap_total or running else BoxKind.PROVENANCE, "Data quality",
               meta=fmt.plural(gap_total, "gap"), items=tuple(items))


def overview_sections(inputs: TelemetryInputs) -> tuple[Block, ...]:
    """Executive summary, run timeline, where the time went, run-wide usage, data quality."""
    return (
        Heading(1, "Run overview", anchor("telemetry", "overview"),
                subtitle=f"Whole-run rollup for {_short(inputs.run_id, LABEL_CHARS)}; per-job detail follows in Part II"),
        *_summary_blocks(inputs),
        Heading(2, "Run timeline", anchor("telemetry", "timeline")),
        _timeline(inputs),
        Heading(2, "Where the time went", anchor("telemetry", "time")),
        _time_fields(inputs),
        _job_bars(inputs),
        _operations(inputs),
        _progress(inputs),
        _hotspots(inputs),
        Heading(2, "Run-wide usage", anchor("telemetry", "usage")),
        _models(inputs),
        _tools(inputs),
        _builds_and_findings(inputs),
        Heading(2, "Data quality", anchor("telemetry", "quality")),
        _quality(inputs),
    )


def appendix_sections(inputs: TelemetryInputs) -> tuple[Block, ...]:
    """Provenance (summary / event-log hashes and sources) and how to read the report."""
    from . import RENDERER  # deferred: the package imports this module

    rows = (_field("Run id", inputs.run_id, mono=True),
            _field("Metrics summary source", inputs.summary_source),
            _field("Metrics summary sha256", inputs.summary_sha256, mono=True),
            _field("Event log sha256", inputs.events_sha256, mono=True),
            Field("Events read", fmt.count(len(inputs.events)) if inputs.events_sha256 else fmt.UNAVAILABLE),
            _field("Run started", inputs.run_started_at, mono=True),
            _field("Run ended", inputs.run_ended_at, mono=True),
            _field("Report renderer", RENDERER, mono=True))
    return (
        Heading(1, "Provenance", anchor("telemetry", "provenance"), new_page=True,
                subtitle="Where every number in this report came from"),
        Box(BoxKind.PROVENANCE, "Sources", items=(Fields(rows),)),
        Box(BoxKind.PROVENANCE, "Reading this report", items=(Bullets((
            "Telemetry is observational process data about how the review ran; it is never security evidence.",
            "The event log (data/logs/pipeline.jsonl) is authoritative; the metrics summary is derived from it.",
            "'unavailable' (or 'n/a' in narrow table columns) means the value was not recorded, "
            "not that it was zero.",
            "Durations are wall-clock offsets from the run's first event; concurrent work overlaps.",
        )),)),
    )
