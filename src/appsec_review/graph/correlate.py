"""SARIF code-flow ↔ ``dataflow_path`` correlation (rule ``graph-sarif-correlation/1``).

docs/architecture/code-graph-precomputation.md, section 4.8. Pure functions over one scope's graph
facts and accepted CodeQL ``tool_observation`` rows (``observations`` shards, payload ``flows`` from
``jobs/job_codeql_analysis/sarif.py``), plus, when the prioritization shard is accepted, its
``review_signal``/``review_flow_step`` rows.

For each path-problem observation and each ``(code_flow, thread_flow)``:

* the sink step must match a ``sink_site`` and the source step an ``entry_point`` by exact byte span
  (SARIF line/column mapped to bytes through the accepted source, end column exclusive);
* candidate paths are the ``dataflow_path`` facts joining a matched entry point to a matched sink;
* each intermediate step matches a path step by exact byte span, else by start line (ambiguous), else
  it is unmatched. All exact → ``bridged``; otherwise ``partial``; no candidate path → ``broken``.

The best candidate per code flow is ``(state, unmatched, ambiguous, hop_count, identity)``-minimal. One
``DERIVED_FROM`` relation per (path, observation) carries every correlated code flow in order. A
``broken`` code flow whose sink matched is published as ``DERIVED_FROM`` from the ``sink_site`` with
state ``broken``; every broken flow is also returned in ``correlations`` so the job can publish it as a
gap. ``SAME_AS`` relates ``review_flow_step`` entities to the path they were mapped onto. Correlation is
not evidence by itself.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from appsec_review.graph.contract import Family, GraphFact
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.retrieval.model import EntityKind, RelationKind, RelationRecord, canonical_json

CORRELATION_RULE = "graph-sarif-correlation/1"
METHOD_SPAN = "sarif-step-byte-span"
METHOD_LINE = "sarif-step-line-only"


class CorrelationState(StrEnum):
    BRIDGED = "bridged"
    PARTIAL = "partial"
    BROKEN = "broken"


_RANK = {CorrelationState.BRIDGED: 0, CorrelationState.PARTIAL: 1, CorrelationState.BROKEN: 2}


@dataclass(frozen=True, slots=True)
class FlowCorrelation:
    observation: str
    code_flow: int
    thread_flow: int
    state: CorrelationState
    path: str | None
    sink_sites: tuple[str, ...]
    matched_steps: tuple[Mapping[str, Any], ...] = ()
    ambiguous_steps: tuple[Mapping[str, Any], ...] = ()
    unmatched_steps: tuple[int, ...] = ()
    reason: str | None = None

    def as_payload(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "code_flow": self.code_flow, "thread_flow": self.thread_flow, "state": self.state.value,
            "matched_steps": [dict(item) for item in self.matched_steps],
            "ambiguous_steps": [dict(item) for item in self.ambiguous_steps],
            "unmatched_steps": list(self.unmatched_steps),
        }
        if self.reason:
            value["reason"] = self.reason
        return value


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    correlations: tuple[FlowCorrelation, ...]
    relations: tuple[RelationRecord, ...]
    summary: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _Span:
    path: str
    sha256: str | None
    start_byte: int | None
    end_byte: int | None
    start_line: int


def _sarif_span(location: Mapping[str, Any], sources: Mapping[str, SourceFile]) -> _Span | None:
    path = location.get("path")
    if not path:
        return None
    try:
        start_line = int(location.get("start_line") or 0)
        end_line = int(location.get("end_line") or start_line)
        start_column = int(location.get("start_column") or 0)
        end_column = int(location.get("end_column") or start_column)
    except (TypeError, ValueError):
        return None
    if start_line < 1:
        return None
    source = sources.get(str(path))
    sha = location.get("file_sha256")
    if source is None or (sha and sha != source.sha256):
        return _Span(str(path), sha, None, None, start_line)
    return _Span(str(path), source.sha256, source.offset(start_line, start_column), source.offset(end_line, end_column),
                 start_line)


def _fact_span(location: Mapping[str, Any] | Any) -> _Span | None:
    if location is None:
        return None
    get = location.get if isinstance(location, Mapping) else (lambda name, default=None: getattr(location, name, default))
    if not get("path"):
        return None
    return _Span(str(get("path")), get("file_sha256"), get("start_byte"), get("end_byte"), int(get("start_line") or 0))


def _match(step: _Span | None, candidate: _Span | None) -> str | None:
    if step is None or candidate is None or step.path != candidate.path:
        return None
    if step.sha256 and candidate.sha256 and step.sha256 != candidate.sha256:
        return None
    if (step.start_byte is not None and step.end_byte is not None
            and (step.start_byte, step.end_byte) == (candidate.start_byte, candidate.end_byte)):
        return "span"
    return "line" if step.start_line == candidate.start_line else None


def _flow_groups(payload: Mapping[str, Any]) -> tuple[dict[tuple[int, int], list[Mapping[str, Any]]], int]:
    groups: dict[tuple[int, int], list[Mapping[str, Any]]] = {}
    unindexed = 0
    for step in payload.get("flows", ()) if isinstance(payload.get("flows"), list) else ():
        if not isinstance(step, Mapping):
            continue
        code_flow, thread_flow = step.get("code_flow"), step.get("thread_flow", 0)
        if not isinstance(code_flow, int) or not isinstance(thread_flow, int):
            unindexed += 1
            continue
        groups.setdefault((code_flow, thread_flow), []).append(step)
    for key in groups:
        groups[key].sort(key=lambda item: int(item.get("ordinal", 0) or 0))
    return groups, unindexed


def _ordered_match(step: _Span | None, path_steps: Sequence[tuple[int, _Span | None]], previous: int) -> tuple[
        str | None, list[int]]:
    exact = [n for n, span in path_steps if _match(step, span) == "span"]
    if exact:
        later = [n for n in exact if n > previous]
        return "span", [later[0] if later else exact[0]]
    lines = [n for n, span in path_steps if _match(step, span) == "line"]
    return ("line", lines) if lines else (None, [])


def _correlate_flow(steps: Sequence[Mapping[str, Any]], path: GraphFact,
                    sources: Mapping[str, SourceFile]) -> tuple[CorrelationState, list, list, list, list]:
    result = path.payload.get("result") or {}
    path_steps = [(int(item.get("n", index)), _fact_span(item.get("location")))
                  for index, item in enumerate(result.get("steps", ())) if isinstance(item, Mapping)]
    matched: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    unmatched: list[int] = []
    per_step: list[tuple[str | None, list[int]]] = []
    last = len(steps) - 1
    previous = -1
    for index, step in enumerate(steps):
        ordinal = int(step.get("ordinal", index) or index)
        location = step.get("location") if isinstance(step.get("location"), Mapping) else {}
        span = _sarif_span(location, sources)
        if index in (0, last):
            # Endpoints already matched the entry point / sink by exact span; bind them to the path ends.
            n = path_steps[0][0] if index == 0 and path_steps else path_steps[-1][0] if path_steps else index
            matched.append({"ordinal": ordinal, "path_step": n, "method": METHOD_SPAN,
                            "role": "source" if index == 0 else "sink"})
            per_step.append(("span", [n]))
            continue
        method, found = _ordered_match(span, path_steps, previous)
        per_step.append((method, found))
        if method == "span":
            previous = found[0]
            matched.append({"ordinal": ordinal, "path_step": found[0], "method": METHOD_SPAN})
        elif method == "line":
            ambiguous.append({"ordinal": ordinal, "path_steps": found, "method": METHOD_LINE})
        else:
            unmatched.append(ordinal)
    state = CorrelationState.BRIDGED if not ambiguous and not unmatched else CorrelationState.PARTIAL
    return state, matched, ambiguous, unmatched, per_step


def correlate(facts: Sequence[GraphFact], observations: Sequence[Mapping[str, Any]], *,
              sources: Mapping[str, SourceFile],
              priority: Sequence[Mapping[str, Any]] | None = None) -> CorrelationResult:
    """Apply ``graph-sarif-correlation/1`` to one CodeQL scope.

    ``facts``: the scope's graph facts (``sink_site``, ``entry_point`` and ``dataflow_path`` are read).
    ``observations``: accepted CodeQL ``tool_observation`` rows (``ShardSet.entities`` shape) of that
    scope; rows without ``flows`` are not path problems and are skipped. ``sources``: accepted source
    bytes by target-relative path. ``priority``: accepted ``review_signal`` and ``review_flow_step``
    rows, or ``None`` when the prioritization shard is not accepted (then no ``SAME_AS`` is emitted).
    """
    sinks = sorted(((fact.identity.value, _fact_span(fact.location)) for fact in facts
                    if fact.family is Family.SINK_SITE), key=lambda item: item[0])
    entries = sorted(((fact.identity.value, _fact_span(fact.location)) for fact in facts
                      if fact.family is Family.ENTRY_POINT), key=lambda item: item[0])
    paths = sorted((fact for fact in facts if fact.family is Family.DATAFLOW_PATH), key=lambda item: item.identity.value)
    by_endpoints: dict[tuple[str, str], list[GraphFact]] = {}
    for path in paths:
        result = path.payload.get("result") or {}
        source = result.get("source") if isinstance(result.get("source"), Mapping) else {}
        sink = result.get("sink") if isinstance(result.get("sink"), Mapping) else {}
        by_endpoints.setdefault((str(source.get("entry_point")), str(sink.get("sink_site"))), []).append(path)
    path_by_id = {path.identity.value: path for path in paths}

    correlations: list[FlowCorrelation] = []
    step_maps: dict[tuple[str, int, int], tuple[str, list[Mapping[str, Any]], list]] = {}
    gaps: list[str] = []
    for row in sorted(observations, key=lambda item: str(item.get("identity"))):
        if row.get("kind", EntityKind.TOOL_OBSERVATION.value) != EntityKind.TOOL_OBSERVATION.value:
            continue
        payload = row.get("payload") or {}
        if payload.get("producer", "codeql") != "codeql":
            continue
        observation = str(row["identity"])
        groups, unindexed = _flow_groups(payload)
        if unindexed:
            gaps.append(f"{observation}: {unindexed} flow steps lack code_flow indices and were not correlated")
        for (code_flow, thread_flow), steps in sorted(groups.items()):
            first = _sarif_span(steps[0].get("location") or {}, sources)
            final = _sarif_span(steps[-1].get("location") or {}, sources)
            matched_sinks = tuple(identity for identity, span in sinks if _match(final, span) == "span")
            matched_entries = tuple(identity for identity, span in entries if _match(first, span) == "span")
            reason = None
            if final is None or final.start_byte is None or first is None or first.start_byte is None:
                reason = "endpoint_unmapped"
            elif not matched_sinks:
                reason = "sink_unmatched"
            elif not matched_entries:
                reason = "source_unmatched"
            candidates = [path for entry in matched_entries for sink in matched_sinks
                          for path in by_endpoints.get((entry, sink), ())]
            if reason is None and not candidates:
                reason = "no_path"
            if reason is not None:
                correlations.append(FlowCorrelation(
                    observation, code_flow, thread_flow, CorrelationState.BROKEN, None, matched_sinks,
                    unmatched_steps=tuple(int(step.get("ordinal", index) or index) for index, step in enumerate(steps)),
                    reason=reason))
                continue
            scored = []
            for path in candidates:
                state, matched, ambiguous, unmatched, per_step = _correlate_flow(steps, path, sources)
                result = path.payload.get("result") or {}
                scored.append(((_RANK[state], len(unmatched), len(ambiguous), int(result.get("hop_count") or 0),
                                path.identity.value), state, path, matched, ambiguous, unmatched, per_step))
            _, state, path, matched, ambiguous, unmatched, per_step = min(scored, key=lambda item: item[0])
            correlations.append(FlowCorrelation(
                observation, code_flow, thread_flow, state, path.identity.value, matched_sinks, tuple(matched),
                tuple(ambiguous), tuple(unmatched)))
            step_maps[(observation, code_flow, thread_flow)] = (path.identity.value, steps, per_step)

    relations: list[RelationRecord] = []
    pairs: dict[tuple[str, str], list[FlowCorrelation]] = {}
    for item in correlations:
        if item.path is not None:
            pairs.setdefault((item.path, item.observation), []).append(item)
        else:
            for sink in item.sink_sites:
                pairs.setdefault((sink, item.observation), []).append(item)
    for (source_id, observation), items in sorted(pairs.items()):
        items = sorted(items, key=lambda value: (value.code_flow, value.thread_flow))
        overall = max((value.state for value in items), key=lambda state: _RANK[state])
        exact = overall is CorrelationState.BRIDGED
        ambiguity = None
        if not exact:
            ambiguity = "; ".join(
                f"code_flow {value.code_flow}.{value.thread_flow} {value.state.value}"
                + (f" ({value.reason})" if value.reason else
                   f" ({len(value.ambiguous_steps)} ambiguous, {len(value.unmatched_steps)} unmatched steps)")
                for value in items if value.state is not CorrelationState.BRIDGED)[:1024]
        confidence = {CorrelationState.BRIDGED: 1.0, CorrelationState.PARTIAL: 0.5, CorrelationState.BROKEN: 0.0}[overall]
        relations.append(RelationRecord(
            RelationKind.DERIVED_FROM, source_id, observation, exact, confidence, ambiguity,
            {"rule": CORRELATION_RULE, "state": overall.value, "code_flows": [value.as_payload() for value in items]}))

    same_as = 0
    if priority is not None:
        signals = {}
        for row in priority:
            payload = row.get("payload") or {}
            if row.get("kind") == EntityKind.REVIEW_SIGNAL.value and payload.get("category") == "semantic_path":
                signals[str(payload.get("path_id") or row.get("native_id"))] = payload
        flow_steps = sorted((row for row in priority if row.get("kind") == EntityKind.REVIEW_FLOW_STEP.value),
                            key=lambda item: str(item.get("identity")))
        for row in flow_steps:
            payload = row.get("payload") or {}
            signal = signals.get(str(payload.get("path_id")))
            if signal is None:
                continue
            key = (str(signal.get("observation")), signal.get("code_flow"), signal.get("thread_flow", 0))
            if key not in step_maps:
                continue
            path_id, steps, per_step = step_maps[key]
            ordinal = payload.get("ordinal")
            if not isinstance(ordinal, int) or not 0 <= ordinal < len(steps):
                continue
            sarif_location = steps[ordinal].get("location") or {}
            location = row.get("location") or {}
            if (location.get("path"), location.get("start_line")) != (sarif_location.get("path"),
                                                                      sarif_location.get("start_line")):
                continue
            method, found = per_step[ordinal]
            if method is None:
                continue
            result = path_by_id[path_id].payload.get("result") or {}
            spans = {int(item.get("n", index)): _fact_span(item.get("location"))
                     for index, item in enumerate(result.get("steps", ())) if isinstance(item, Mapping)}
            review_span = _fact_span(location)
            exact = (method == "span" and len(found) == 1 and review_span is not None and spans.get(found[0]) is not None
                     and _match(review_span, spans[found[0]]) == "span")
            relations.append(RelationRecord(
                RelationKind.SAME_AS, str(row["identity"]), path_id, exact, 1.0 if exact else 0.5,
                None if exact else (f"review flow step is mapped through SARIF step {ordinal} by "
                                    f"{METHOD_SPAN if method == 'span' else METHOD_LINE}; its own location is "
                                    "line-granular"),
                {"rule": CORRELATION_RULE, "method": METHOD_SPAN if method == "span" else METHOD_LINE,
                 "review_flow_ordinal": ordinal, "path_steps": list(found)}))
            same_as += 1

    unique: dict[str, RelationRecord] = {}
    for relation in sorted(relations, key=lambda item: (item.relation_id, canonical_json(item.payload or {}))):
        unique.setdefault(relation.relation_id, relation)
    states = {state.value: sum(1 for item in correlations if item.state is state) for state in CorrelationState}
    summary = {"rule": CORRELATION_RULE, "code_flows": len(correlations), "states": states,
               "same_as": same_as, "priority_available": priority is not None,
               "broken": [{"observation": item.observation, "code_flow": item.code_flow,
                           "thread_flow": item.thread_flow, "reason": item.reason}
                          for item in correlations if item.state is CorrelationState.BROKEN],
               "gaps": list(dict.fromkeys(gaps))}
    return CorrelationResult(tuple(correlations), tuple(unique[key] for key in sorted(unique)), summary)
