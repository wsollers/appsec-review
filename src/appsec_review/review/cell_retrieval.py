"""Pure helpers of a cell's retrieval turns (review-protocol-v2.md section 5).

* :func:`adapt_graph_request` makes ``query_code_graph`` forgiving only where the application can decide
  deterministically: a ``depth`` or class filter that the mode ignores is dropped, and a subject of a kind the
  mode does not take is replaced by the one identity it unambiguously stands for (a call site by the symbol it
  calls or is in, a guard or range by its sink, a sink or entry point by its enclosing function, a tool
  observation by the single sink at its location). The response says what was changed.
* :func:`corrected_shape` is the one-line answer to a denied request: a well-formed request for the same intent.
* :func:`expand_plan` lists the typed requests ``expand`` runs for one identity. ``expand`` has no query logic of
  its own: every request goes through ``CellCapability.authorize`` and ``RetrievalCore`` like a model request.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from appsec_review.graph.contract import (
    DEPTH_MODES, MODE_SUBJECT_KINDS, QUERY_CODE_GRAPH, SINK_CLASS_MODES, SOURCE_CLASS_MODES, Mode,
)
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review.capability import EXPAND_TOOL, LOCATOR_TOOLS, TOOL_SCHEMAS, normalize_request

EXPAND_DEPTH = 3


def _result(entity: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = entity.get("payload") if isinstance(entity.get("payload"), Mapping) else {}
    return payload.get("result") if isinstance(payload.get("result"), Mapping) else {}


def _identity(value: Any) -> str | None:
    try:
        return LogicalIdentity.parse(value).value
    except (ValueError, TypeError, AttributeError):
        return None


def related_identities(entity: Mapping[str, Any]) -> list[str]:
    """Identities a fact names that a reviewer asking "more about this" needs next (sink, function, endpoints)."""
    result = _result(entity)
    kind = entity.get("kind")
    found: list[str | None] = []
    if kind in {"guard_fact", "range_fact"}:
        found.append(_identity((result.get("sink") or {}).get("sink_site")))
    elif kind == "call_site":
        found += [_identity((result.get("caller") or {}).get("symbol")), _identity((result.get("callee") or {}).get("symbol"))]
    elif kind == "dataflow_path":
        found += [_identity((result.get("sink") or {}).get("sink_site")),
                  _identity((result.get("source") or {}).get("entry_point"))]
    elif kind in {"sink_site", "entry_point"}:
        found.append(_identity((result.get("enclosing_function") or {}).get("symbol")))
    return [item for item in dict.fromkeys(found) if item]


def expand_plan(ref: str, *, max_depth: int) -> list[tuple[str, dict[str, Any]]]:
    """The typed requests ``expand`` runs for ``ref`` before following the identities its fact names."""
    kind = LogicalIdentity.parse(ref).kind.value
    plan: list[tuple[str, dict[str, Any]]] = [("find", {"identity": ref})]
    depth = max(1, min(EXPAND_DEPTH, max_depth))
    if kind == "sink_site":
        plan += [(QUERY_CODE_GRAPH, {"mode": mode, "subject": ref}) for mode in ("guards", "ranges", "paths")]
    elif kind == "entry_point":
        plan.append((QUERY_CODE_GRAPH, {"mode": "paths", "subject": ref}))
    elif kind == "symbol":
        plan += [(QUERY_CODE_GRAPH, {"mode": "callers", "subject": ref, "depth": depth}),
                 (QUERY_CODE_GRAPH, {"mode": "callees", "subject": ref, "depth": depth}),
                 (QUERY_CODE_GRAPH, {"mode": "sinks", "subject": ref})]
    elif kind in {"tool_observation", "source_file", "component", "build_unit"}:
        plan.append(("trace", {"identity": ref, "depth": 1}))
    return plan


def corrected_shape(request: Any, code: str, granted: Any) -> dict[str, Any]:
    """A well-formed request for the intent of a denied one (never executed; shown to the model)."""
    normalized = normalize_request(request)
    tool = normalized.get("tool") if isinstance(normalized, Mapping) else None
    parameters = normalized.get("parameters") if isinstance(normalized, Mapping) else None
    parameters = parameters if isinstance(parameters, Mapping) else {}
    if code in {"unknown_tool", "tool_not_granted"} or tool not in TOOL_SCHEMAS:
        return {"use_one_of": sorted(granted),
                "shape": {"tool": "<one of use_one_of>", "parameters": {"<name from tool_catalog>": "<value>"}}}
    if code in {"entity_out_of_scope", "unknown_label"}:
        return {"tool": EXPAND_TOOL, "parameters": {"label": "<a label shown in the package or a Q label>"}}
    path = parameters.get("path") if isinstance(parameters.get("path"), str) else None
    if tool in LOCATOR_TOOLS and (path is not None or code == "invalid_locator"):
        return {"tool": tool, "parameters": {"locator": {"path": path or "<a file path shown in the package>",
                                                         "line": "<line number>"}}}
    schema = TOOL_SCHEMAS[tool]
    properties = schema.get("properties", {})
    names = list(schema.get("required", ())) or sorted(properties)[:1]
    shape: dict[str, Any] = {"tool": tool, "parameters": {name: f"<{name}>" for name in names}}
    if tool == QUERY_CODE_GRAPH:
        mode = _mode(parameters.get("mode"))
        if mode is not None:
            shape["parameters"]["mode"] = mode.value
            shape["parameters"]["subject"] = "<one of: " + ", ".join(sorted(
                kind.value for kind in MODE_SUBJECT_KINDS[mode])) + ">"
            shape["note"] = ("depth applies only to callers and callees" if mode not in DEPTH_MODES else
                             "depth is 1 to the cell depth cap")
    if code in {"page_cap_exceeded", "depth_cap_exceeded"}:
        shape["note"] = "lower limit or depth; the cell caps are in capability"
    return shape


def _mode(value: Any) -> Mode | None:
    try:
        return Mode(value)
    except ValueError:
        return None


def adapt_graph_request(core: Any, request: Any) -> tuple[Any, list[str]]:
    """``(request, notes)``: the request with deterministic mode/subject repairs applied, and what changed."""
    normalized = normalize_request(request)
    if not isinstance(normalized, Mapping) or normalized.get("tool") != QUERY_CODE_GRAPH:
        return request, []
    parameters = normalized.get("parameters")
    if not isinstance(parameters, Mapping):
        return request, []
    params, notes = dict(parameters), []
    mode = _mode(params.get("mode"))
    subject = _identity(params.get("subject"))
    if mode is None or subject is None:
        return request, []
    if params.get("depth") is not None and mode not in DEPTH_MODES:
        params.pop("depth")
        notes.append("depth applies only to callers and callees; it was dropped")
    for name, modes in (("sink_class", SINK_CLASS_MODES), ("source_class", SOURCE_CLASS_MODES)):
        if params.get(name) is not None and mode not in modes:
            params.pop(name)
            notes.append(f"{name} does not apply to mode {mode.value}; it was dropped")
    kind = LogicalIdentity.parse(subject).kind
    if kind not in MODE_SUBJECT_KINDS[mode]:
        mapped = _map_subject(core, mode, subject, kind)
        if mapped is not None:
            params["subject"] = mapped[0]
            notes.append(mapped[1])
    return ({"tool": QUERY_CODE_GRAPH, "parameters": params}, notes) if notes else (request, [])


def _map_subject(core: Any, mode: Mode, subject: str, kind: EntityKind) -> tuple[str, str] | None:
    try:
        found = core.find(identity=subject, limit=1)["results"]
    except (ValueError, LookupError):
        return None
    if not found:
        return None
    entity = found[0]
    result = _result(entity)
    accepted = MODE_SUBJECT_KINDS[mode]
    target: str | None = None
    if kind is EntityKind.CALL_SITE and mode in {Mode.CALLERS, Mode.CALLEES}:
        side = "callee" if mode is Mode.CALLERS else "caller"
        target = _identity((result.get(side) or {}).get("symbol"))
    elif kind in {EntityKind.SINK_SITE, EntityKind.ENTRY_POINT} and EntityKind.SYMBOL in accepted:
        target = _identity((result.get("enclosing_function") or {}).get("symbol"))
    elif kind in {EntityKind.GUARD_FACT, EntityKind.RANGE_FACT, EntityKind.DATAFLOW_PATH} and EntityKind.SINK_SITE in accepted:
        target = _identity((result.get("sink") or {}).get("sink_site"))
    elif kind is EntityKind.TOOL_OBSERVATION and EntityKind.SINK_SITE in accepted:
        location = entity.get("location") or {}
        if location.get("path") and location.get("start_line"):
            try:
                sinks = core.find(kind="sink_site", path=location["path"], limit=100)["results"]
            except (ValueError, LookupError):
                sinks = []
            same = sorted({item["identity"] for item in sinks
                           if (item.get("location") or {}).get("start_line") == location["start_line"]})
            target = same[0] if len(same) == 1 else None
    if target is None or LogicalIdentity.parse(target).kind not in accepted:
        return None
    return target, (f"mode {mode.value} does not take a {kind.value} subject; the {LogicalIdentity.parse(target).kind.value} "
                    f"it names was used instead ({target[-12:]})")


__all__ = ["EXPAND_DEPTH", "adapt_graph_request", "corrected_shape", "expand_plan", "related_identities"]
