"""One-line, model-facing summaries of accepted graph facts (``fact-summary/1``).

A summary states what the fact records and nothing more. In particular a ``guard_fact`` summary reports only the
guard state, polarity, condition text, operator, the compared operand texts and, as a plain fact, the destination
object size when the export knows it; it never says that a guard is adequate, effective or sufficient, and never
summarises whether it bounds the destination of a write. Whether a guard bounds the destination of a particular write
is decided by the application's evidence rules (``graph.bounds``, ``evidence-admissibility/3``), not by the summary.

The same function summarizes a fact at package assembly (``review.packages``) and a row returned by a
retrieval tool (``review.cells``), so a package label and a retrieved row describe one fact identically.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SUMMARY_RULE = "appsec-review/fact-summary/1"
MAX_SUMMARY_CHARS = 240


def _text(value: Any, default: str = "?") -> str:
    return " ".join(str(value).split()) if isinstance(value, (str, int, float)) and str(value).strip() else default


def _display(value: Any) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("display")
    return _text(value, "") or None


def _bound(value: Any) -> str:
    return "?" if value is None else str(value)


def _operand(item: Any) -> str:
    if not isinstance(item, Mapping):
        return "?"
    shown = item.get("text") if item.get("text") is not None else item.get("value")
    return _text(shown, _text(item.get("kind"), "?"))


def _operands(comparison: Mapping[str, Any]) -> str:
    """The compared operand texts by role; the older single ``bound_display`` when operands were not recorded."""
    found = {item.get("role"): item for item in comparison.get("operands", ()) if isinstance(item, Mapping)}         if isinstance(comparison.get("operands"), list) else {}
    if found:
        return f", lhs {_operand(found.get('lhs'))}, rhs {_operand(found.get('rhs'))}"
    return f", operand {_text(comparison.get('bound_display'))}"


def summarize_fact(kind: str, payload: Mapping[str, Any] | None, *, line: int | None = None) -> str:
    """The summary of one graph fact of ``kind`` from its accepted ``graph-fact/1`` payload."""
    payload = payload if isinstance(payload, Mapping) else {}
    result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
    where = f", L{line}" if line else ""
    if kind == "sink_site":
        api = _display(result.get("api")) or _display(result.get("display")) or "sink"
        text = f"{api} [{_text(result.get('sink_class'), 'unclassified')}], argument {_text(result.get('argument_index'))}"
    elif kind == "range_fact":
        type_block = result.get("type") if isinstance(result.get("type"), Mapping) else {}
        interval = result.get("interval") if isinstance(result.get("interval"), Mapping) else None
        sign = {True: "signed", False: "unsigned"}.get(type_block.get("signed"), "sign unknown")
        bits = type_block.get("bits")
        shape = f"{_text(type_block.get('display'), 'operand type unknown')}" + (
            f" ({bits}-bit, {sign})" if bits else f" ({sign})")
        span = (f"interval {_bound(interval.get('lower'))}..{_bound(interval.get('upper'))}"
                if interval else "no interval computed")
        text = f"operand {_text(result.get('operand_index'))} type {shape}, {span}"
        if result.get("sign_change"):
            text += ", includes a sign change"
    elif kind == "guard_fact":
        condition = _display(result.get("condition"))
        comparison = result.get("comparison") if isinstance(result.get("comparison"), Mapping) else None
        text = (f"{_text(result.get('guard_state'), 'unknown')} guard, polarity {_text(result.get('polarity'), 'unknown')}: "
                f"{condition or 'no controlling condition recorded'}")
        if comparison:
            text += f" (operator {_text(comparison.get('operator'))}{_operands(comparison)})"
        destination = result.get("destination") if isinstance(result.get("destination"), Mapping) else {}
        size = destination.get("object_bytes")
        if isinstance(size, int) and not isinstance(size, bool) and size > 0:
            text += f"; destination object {size} bytes"
    elif kind == "call_site":
        caller = _display(result.get("caller")) or "?"
        callee_block = result.get("callee") if isinstance(result.get("callee"), Mapping) else {}
        callee = _display(callee_block) or "?"
        text = f"{caller} -> {callee} ({_text(callee_block.get('dispatch'), 'dispatch unknown')})"
    elif kind == "entry_point":
        text = f"{_display(result.get('api_or_parameter')) or 'entry'} [{_text(result.get('source_class'), 'unclassified')}]"
    elif kind == "dataflow_path":
        source = result.get("source") if isinstance(result.get("source"), Mapping) else {}
        sink = result.get("sink") if isinstance(result.get("sink"), Mapping) else {}
        text = (f"{_text(source.get('source_class'), 'unclassified')} source to {_text(sink.get('sink_class'), 'unclassified')} "
                f"sink, {_text(result.get('hop_count'), '?')} hop(s)" + (", steps truncated" if result.get("truncated_steps") else ""))
    elif kind == "flow_summary":
        pairs = result.get("pairs") if isinstance(result.get("pairs"), list) else []
        text = f"function flow summary, {len(pairs)} pair(s)" + (", k-limited" if result.get("k_limited") else "")
    elif kind == "symbol":
        text = _text(payload.get("qualified_name") or payload.get("kind"), "function")
    else:
        text = kind
    return (text + where)[:MAX_SUMMARY_CHARS]


__all__ = ["MAX_SUMMARY_CHARS", "SUMMARY_RULE", "summarize_fact"]
