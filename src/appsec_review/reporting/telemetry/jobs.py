"""Part II of the run telemetry report: one supporting-detail section per job attempt.

Owned by chunk A2. Contract: pure, deterministic functions of :class:`TelemetryInputs`, returning
renderer-neutral blocks; every string passes through ``reporting.text`` cleaning/bounding.

Only data that carries the job's own identity is attributed to it: events with its ``job_id`` and
``attempt_id``, and summary ``model_invocations``, ``lifecycle_gaps`` and ``genuinely_running``
entries with the same identity. Run-wide summary sections (CodeQL, Tree-sitter, SBOM, ...) carry no
job identity and stay in the overview.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from ..model import Block, Box, Bullets, Cell, Field, Fields, Heading, Note, Stat, Stats, Table, Truncation
from ..text import anchor, bound, sha256_value, token
from ..tokens import BoxKind
from .format import NA, UNAVAILABLE, compact, count, duration, plural
from .inputs import STATUS_TONE, JobSpan, TelemetryInputs

MAX_JOBS = 40
MAX_ROWS = 12
MAX_GAPS = 12
LABEL_CHARS = 96
ERROR_CHARS = 120
STILL_RUNNING = "still running"
_SUCCESS = {"SUCCEEDED", "SUCCESS", "COMPLETED", "REUSED", "BUILT", "ACCEPTED"}
_TERMINAL_SUFFIXES = ("SUCCEEDED", "FAILED", "COMPLETED_WITH_GAPS", "COMPLETED", "CANCELED", "CANCELLED",
                      "TIMED_OUT", "REUSED", "SKIPPED")
_ALIASES = {"CANCELED": "CANCELLED", "SUCCESS": "SUCCEEDED", "FAILURE": "FAILED"}

Event = Mapping[str, Any]


def _label(value: Any, limit: int = LABEL_CHARS) -> str:
    text, _ = bound(value, limit)
    return text or "-"


def _details(event: Event) -> Mapping[str, Any]:
    details = event.get("details")
    return details if isinstance(details, Mapping) else {}


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _status(value: Any) -> str:
    raw = token(value, "UNKNOWN").upper()
    return _ALIASES.get(raw, raw)


def _status_cell(status: str) -> Cell:
    if status in _SUCCESS:
        return Cell(_status_words(status).capitalize())
    return Cell(status, badge=STATUS_TONE.get(status, "unresolved"), badge_label=_status_words(status))


def _status_words(status: str) -> str:
    return _label(status.replace("_", " "), 40)


def _rows_table(headers: tuple[str, ...], widths: tuple[float, ...], rows: list[tuple[Cell, ...]]) -> Table:
    omitted = None
    if len(rows) > MAX_ROWS:
        omitted = Truncation(omitted=len(rows) - MAX_ROWS, unit="rows",
                             sha256=sha256_value([[cell.text for cell in row] for row in rows]))
    return Table(headers=headers, rows=tuple(rows[:MAX_ROWS]), widths=widths, omitted=omitted)


def _terminal(event_type: str, prefix: str) -> str | None:
    if not event_type.startswith(prefix):
        return None
    suffix = event_type[len(prefix):]
    return _ALIASES.get(suffix, suffix) if suffix.endswith(_TERMINAL_SUFFIXES) else None


def _steps(events: list[Event]) -> list[tuple[Cell, ...]]:
    order: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        kind = str(event.get("event_type"))
        family = "TASK_" if kind.startswith("TASK_") else "STEP_" if kind.startswith("STEP_") else None
        if family is None:
            continue
        task = str(event.get("task_id") or "-") if family == "TASK_" else "-"
        state = order.setdefault((str(event.get("step_id") or "-"), task), {"status": "RUNNING", "duration": None})
        terminal = _terminal(kind, family)
        if terminal:
            state["status"] = terminal
            state["duration"] = _int(_details(event).get("duration_ms"))
        elif kind.endswith("STARTED"):
            state["status"] = "RUNNING"
    return [(Cell(_label(task), mono=True), Cell(_label(step), mono=True), _status_cell(state["status"]),
             Cell(duration(state["duration"]) if state["status"] != "RUNNING" else STILL_RUNNING))
            for (step, task), state in order.items()]


def _model_calls(inputs: TelemetryInputs, span: JobSpan, events: list[Event]) -> list[Mapping[str, Any]]:
    listed = inputs.summary.get("model_invocations") if inputs.summary else None
    if isinstance(listed, list):
        return [item for item in listed if isinstance(item, Mapping)
                and str(item.get("job_id")) == span.job_id and str(item.get("attempt_id") or "-") == span.attempt_id]
    calls = []
    for event in events:
        if event.get("event_type") == "MODEL_CALL_COMPLETED":
            details = _details(event)
            calls.append({**details, "invocation_id": details.get("model_invocation_id") or event.get("task_id")})
    return calls


def _model_rows(calls: list[Mapping[str, Any]]) -> list[tuple[Cell, ...]]:
    rows = []
    for call in calls:
        error = call.get("error_class")
        tokens = [count(call.get(key)) for key in ("input_tokens", "output_tokens", "cache_tokens")]
        rows.append((Cell(_label(call.get("invocation_id")), mono=True), Cell(_label(call.get("role"), 40)),
                     Cell(_label(call.get("model"), 60), mono=True), Cell(duration(call.get("duration_ms"))),
                     *(Cell(NA if value == UNAVAILABLE else value) for value in tokens),
                     _status_cell(_status(call.get("terminal_status") or "UNKNOWN")),
                     Cell(_label(error, ERROR_CHARS) if error else "-", mono=bool(error))))
    return rows


def _tools(events: list[Event]) -> list[dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {}
    for event in events:
        kind = str(event.get("event_type"))
        if not kind.startswith("TOOL_INVOCATION_"):
            continue
        details = _details(event)
        key = str(details.get("tool_invocation_id") or event.get("task_id") or f"#{event.get('sequence')}")
        state = tools.setdefault(key, {"id": key, "tool": None, "status": "RUNNING", "duration": None,
                                       "results": None})
        state["tool"] = state["tool"] or details.get("tool_id")
        terminal = _terminal(kind, "TOOL_INVOCATION_")
        if terminal:
            state["status"] = _status(details.get("terminal_status") or details.get("disposition") or terminal)
            state["duration"] = _int(details.get("duration_ms"))
            state["results"] = _int(details.get("result_count"))
    return list(tools.values())


def _tool_rows(tools: list[dict[str, Any]]) -> list[tuple[Cell, ...]]:
    return [(Cell(_label(tool["tool"]), mono=True), Cell(_label(tool["id"]), mono=True),
             Cell(duration(tool["duration"]) if tool["status"] != "RUNNING" else STILL_RUNNING),
             _status_cell(tool["status"]), Cell(count(tool["results"])))
            for tool in tools]


def _image_outcome(kind: str) -> str:
    if kind == "PROJECT_IMAGE_BUILT":
        return "BUILT"
    if kind.endswith("REUSED"):
        return "REUSED"
    return "FAILED" if kind.endswith("FAILED") else _status(kind.removeprefix("PROJECT_IMAGE_"))


def _subsystems(events: list[Event]) -> list[Box]:
    builds: dict[str, dict[str, Any]] = {}
    transitions: list[tuple[Cell, ...]] = []
    for event in events:
        kind = str(event.get("event_type"))
        details = _details(event)
        if kind.startswith("PROJECT_IMAGE_"):
            state = builds.setdefault(str(details.get("build_unit_id") or "-"),
                                      {"family": None, "status": "RUNNING", "duration": None})
            state["family"] = state["family"] or details.get("family")
            if kind != "PROJECT_IMAGE_BUILD_STARTED":
                state["status"] = _image_outcome(kind)
                state["duration"] = _int(details.get("duration_ms"))
        elif kind == "FINDING_TRANSITION":
            transitions.append((Cell(_label(details.get("finding_package_id")), mono=True),
                                Cell(_label(details.get("prior_state"), 40)),
                                Cell(_label(details.get("new_state"), 40)),
                                Cell(_label(event.get("timestamp"), 40), mono=True)))
    boxes = []
    if builds:
        rows = [(Cell(_label(unit), mono=True), Cell(_label(state["family"], 40)), _status_cell(state["status"]),
                 Cell(duration(state["duration"]) if state["status"] != "RUNNING" else STILL_RUNNING))
                for unit, state in builds.items()]
        boxes.append(Box(kind=BoxKind.RESULT, chip="BUILDS", title="Project image builds",
                         meta=plural(len(rows), "build unit"),
                         items=(_rows_table(("Build unit", "Family", "Outcome", "Duration"), (.4, .2, .2, .2), rows),)))
    if transitions:
        boxes.append(Box(kind=BoxKind.RESULT, chip="LIFECYCLE", title="Finding transitions",
                         meta=f"{plural(len(transitions), 'transition')}; process state, not security evidence",
                         items=(_rows_table(("Package", "From", "To", "At"), (.4, .17, .17, .26), transitions),)))
    return boxes


def _gaps(inputs: TelemetryInputs, span: JobSpan) -> list[str]:
    gaps = []
    if span.status == "RUNNING":
        gaps.append("Attempt has no terminal job event: it is still running or its end was not recorded.")
    elif span.status in {"FAILED", "TIMED_OUT", "CANCELLED"}:
        gaps.append(f"Attempt ended {span.status}; its work is incomplete.")
    for section, prefix in (("lifecycle_gaps", "Lifecycle gap"), ("genuinely_running", "Still running")):
        entries = inputs.summary.get(section) if inputs.summary else None
        for entry in entries if isinstance(entries, list) else ():
            if (not isinstance(entry, Mapping) or str(entry.get("job_id")) != span.job_id
                    or str(entry.get("attempt_id") or "-") != span.attempt_id):
                continue
            what = "/".join(_label(entry.get(key), 48) for key in ("family", "step_id", "task_id", "invocation_id")
                            if entry.get(key) not in (None, "-"))
            reason = f": {_label(entry.get('reason'), 60)}" if entry.get("reason") else ""
            gaps.append(f"{prefix} {what or '-'}{reason}")
    return gaps


def _tokens(calls: list[Mapping[str, Any]]) -> str:
    values = [(_int(call.get("input_tokens")), _int(call.get("output_tokens"))) for call in calls]
    known = [a + b for a, b in values if a is not None and b is not None]
    if not known:
        return UNAVAILABLE
    return compact(sum(known)) + ("" if len(known) == len(values) else " (partial)")


def _attempt(inputs: TelemetryInputs, span: JobSpan, events: list[Event], level: int) -> list[Block]:
    calls = _model_calls(inputs, span, events)
    tools = _tools(events)
    delays = [delay for delay in (_int(_details(event).get("queue_delay_ms")) for event in events
                                  if event.get("event_type") == "DAGSTER_QUEUE_DELAY") if delay is not None]
    wall = STILL_RUNNING if span.end_ms is None else duration(span.end_ms - span.start_ms)
    tone = STATUS_TONE.get(span.status, "unresolved")
    gaps = _gaps(inputs, span)
    blocks: list[Block] = []
    if level:
        blocks.append(Heading(level=level, text=f"Attempt {_label(span.attempt_id, 48)}",
                              anchor=anchor("job", span.job_id, span.attempt_id),
                              subtitle=f"{span.status.lower().replace('_', ' ')}, {wall}"))
    blocks.append(Stats(items=(
        Stat("Status", span.status.replace("_", " "), tone),
        Stat("Wall time", wall),
        Stat("Queue delay", duration(sum(delays)) if delays else UNAVAILABLE),
        Stat("Events", count(span.event_count)),
        Stat("Model calls", count(len(calls))),
        Stat("Tokens in+out", _tokens(calls)),
        Stat("Tool calls", count(len(tools))),
        Stat("Gaps", count(len(gaps)), "coverage_gap" if gaps else "neutral"))))
    blocks.append(Box(kind=BoxKind.PROVENANCE, chip="ATTEMPT", title="Attempt", items=(Fields(rows=(
        Field("Attempt id", _label(span.attempt_id), mono=True),
        Field("Status", span.status, badge=tone, badge_label=_status_words(span.status)),
        Field("Started at", _label(span.started_at, 40), mono=True),
        Field("Ended at", _label(span.ended_at, 40) if span.ended_at else STILL_RUNNING,
              mono=span.ended_at is not None),
        Field("Events", count(span.event_count)))),)))
    steps = _steps(events)
    if steps:
        blocks.append(Box(kind=BoxKind.PROVENANCE, chip="TASKS", title="Steps and tasks",
                          meta=plural(len(steps), "step or task", "steps and tasks"),
                          items=(_rows_table(("Task", "Step", "Status", "Duration"), (.36, .18, .28, .18), steps),)))
    if calls:
        failed = sum(1 for call in calls if _status(call.get("terminal_status") or "UNKNOWN") not in _SUCCESS)
        blocks.append(Box(kind=BoxKind.RESPONSE, chip="MODEL", title="Model calls",
                          meta=f"{plural(len(calls), 'call')}, {count(failed)} not succeeded; n/a: not recorded",
                          items=(_rows_table(
                              ("Invocation", "Role", "Model", "Duration", "In", "Out", "Cache", "Status", "Error"),
                              (.15, .09, .13, .09, .08, .08, .08, .13, .17), _model_rows(calls)),)))
    if tools:
        blocks.append(Box(kind=BoxKind.RESULT, chip="TOOLS", title="Tool invocations",
                          meta=plural(len(tools), "invocation"),
                          items=(_rows_table(("Tool", "Invocation", "Duration", "Status", "Results"),
                                             (.32, .24, .15, .15, .14), _tool_rows(tools)),)))
    blocks.extend(_subsystems(events))
    if gaps:
        omitted = None
        if len(gaps) > MAX_GAPS:
            omitted = Truncation(omitted=len(gaps) - MAX_GAPS, unit="gaps", sha256=sha256_value(gaps))
        blocks.append(Box(kind=BoxKind.GAP, title="Job gaps", meta=plural(len(gaps), "gap"),
                          items=(Bullets(items=tuple(gaps[:MAX_GAPS]), omitted=omitted),)))
    return blocks


def _by_attempt(events: Iterable[Event]) -> dict[tuple[str, str], list[Event]]:
    grouped: dict[tuple[str, str], list[Event]] = {}
    for event in events:
        grouped.setdefault((str(event.get("job_id") or "-"), str(event.get("attempt_id") or "-")), []).append(event)
    return grouped


def job_sections(inputs: TelemetryInputs) -> tuple[Block, ...]:
    """Per job, in ``inputs.jobs`` order: status, timings, model/tool use, subsystem metrics, gaps."""
    if not inputs.jobs:
        return ()
    order: dict[str, list[JobSpan]] = {}
    for span in inputs.jobs:
        order.setdefault(span.job_id, []).append(span)
    grouped = _by_attempt(inputs.events)
    blocks: list[Block] = [Heading(
        level=1, text="Job details", anchor=anchor("job-details"), new_page=True,
        subtitle="Supporting detail per job in timeline order: attempts, tasks, model and tool use, gaps")]
    for job_id, spans in list(order.items())[:MAX_JOBS]:
        statuses = ", ".join(f"{_label(span.attempt_id, 24)} {span.status.lower().replace('_', ' ')}"
                             for span in spans)
        blocks.append(Heading(level=2, text=_label(job_id), anchor=anchor("job", job_id),
                              subtitle=f"{count(len(spans))} attempt{'s' if len(spans) != 1 else ''}: {statuses}"))
        for span in spans:
            blocks.extend(_attempt(inputs, span, grouped.get((span.job_id, span.attempt_id), []),
                                   3 if len(spans) > 1 else 0))
    if len(order) > MAX_JOBS:
        blocks.append(Note(f"{count(len(order) - MAX_JOBS)} more jobs are not shown; "
                           f"only the first {MAX_JOBS} by start time are detailed."))
    return tuple(blocks)
