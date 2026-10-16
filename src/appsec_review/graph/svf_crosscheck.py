"""SVF points-to cross-check of CodeQL graph facts (docs/architecture/svf-alias-producer.md, section 7).

Pure functions over already cross-checked :class:`GraphFact` values and accepted SVF rows
(``points_to_set`` and ``indirect_call_targets`` from ``job_svf_alias_analysis``). Nothing here runs
an analyzer or reads a target tree.

Andersen's analysis over-approximates the modeled program, which fixes what an SVF answer may do:

* membership or may-alias can only confirm (``agree``) or add doubt (``partial``, which removes direct
  eligibility under ``graph-fact-admissibility/1``);
* a missing target or no-alias can contradict (``disagree``) only when every consulted SVF record is
  complete and comes from a closed-world module; weaker SVF evidence is recorded as a ``not_covered``
  producer entry with its detail, which never changes the fact's state or eligibility;
* SVF never makes a fact eligible and never changes a CodeQL result field. An indirect call CodeQL
  leaves unresolved gains ``secondary_only`` facts for SVF's targets, which are never direct-eligible.

Each SVF verdict is recorded as its own producer entry (``rule: svf-cross-check/1``) inside the
fact's ``graph-cross-check/1`` block; the block's state is the most doubtful of all producer states.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from appsec_review.graph.contract import (
    AUTHORITY, CROSS_CHECK_RULE, GRAPH_FACT_SCHEMA, Coverage, CrossCheckState, Dispatch, Family, GraphFact,
    Producer, admissibility, fact_identity,
)
from appsec_review.graph.crosscheck import CrossCheckResult, _relations_unique
from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval.model import EntityKind, RelationKind, RelationRecord, SourceLocation


SVF_RULE = "svf-cross-check/1"
METHOD_CALL = "svf-indirect-call-in-span"
METHOD_ALIAS = "svf-points-to-intersection"
SVF_KINDS = (EntityKind.POINTS_TO_SET.value, EntityKind.INDIRECT_CALL_TARGETS.value)
_DYNAMIC = frozenset({Dispatch.FUNCTION_POINTER_RESOLVED.value, Dispatch.VIRTUAL_RESOLVED.value})
_RANK = {CrossCheckState.DISAGREE: 0, CrossCheckState.PARTIAL: 1, CrossCheckState.AGREE: 2,
         CrossCheckState.NOT_COVERED: 3}
_SINK_ROLES = {"memory_write": ("store", "call_arg"), "memory_read": ("load", "call_arg"),
               "allocation_size": ("call_arg",)}
MAY_ALIAS, NO_ALIAS, UNKNOWN = "may_alias", "no_alias", "unknown"


def function_tail(name: object) -> str:
    """Unqualified function name of a demangled or source display name.

    Drops a trailing parameter list (and cv/ref qualifiers after it) by matching parentheses from the
    end, so ``ns::(anonymous namespace)::f(unsigned long) const`` yields ``f``; the first ``(`` is not a
    safe cut because qualifiers such as ``(anonymous namespace)`` contain parentheses.
    """
    text = str(name or "").strip()
    for suffix in (" const", " volatile", " &&", " &", " noexcept"):
        while text.endswith(suffix):
            text = text[: -len(suffix)].rstrip()
    for close, open_ in ((")", "("), (">", "<")):
        if not text.endswith(close):
            continue
        depth = 0
        for index in range(len(text) - 1, -1, -1):
            depth += {close: 1, open_: -1}.get(text[index], 0)
            if depth == 0:
                text = text[:index].rstrip()
                break
    return text.rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()


@dataclass(frozen=True, slots=True)
class SvfShard:
    """Accepted rows of one ``job_svf_alias_analysis`` shard."""

    index: str
    shard_id: str
    sha256: str
    entities: tuple[Mapping[str, Any], ...] = ()

    @property
    def upstream(self) -> dict[str, str]:
        return {"index": self.index, "shard_id": self.shard_id, "sha256": self.sha256}


def read_svf(shard_set: ShardSet, shard: Mapping[str, Any]) -> SvfShard:
    return SvfShard(str(shard["name"]), str(shard.get("shard_id", "default")), str(shard["sha256"]),
                    tuple(shard_set.entities([shard], kinds=SVF_KINDS)))


@dataclass(frozen=True, slots=True)
class _Row:
    identity: str
    kind: str
    payload: Mapping[str, Any]
    path: str
    line: int
    column: int
    shard: SvfShard

    @property
    def module(self) -> str:
        return str(self.payload.get("module_id", ""))

    @property
    def complete(self) -> bool:
        return bool(self.payload.get("complete")) and bool(self.payload.get("module_closed_world"))


def _rows(shards: Sequence[SvfShard]) -> list[_Row]:
    rows = []
    for shard in shards:
        for entity in shard.entities:
            location = entity.get("location") or {}
            if not location or location.get("ambiguous") or not location.get("path"):
                continue
            rows.append(_Row(str(entity["identity"]), str(entity["kind"]), entity.get("payload") or {},
                             str(location["path"]), int(location["start_line"]), int(location["start_column"]), shard))
    return sorted(rows, key=lambda row: row.identity)


def _span(location: SourceLocation | Mapping[str, Any] | None) -> tuple[str, int, int, int, int] | None:
    if location is None:
        return None
    if isinstance(location, SourceLocation):
        if location.ambiguous:
            return None
        return (location.path, location.start_line, location.start_column, location.end_line, location.end_column)
    if location.get("ambiguous") or not location.get("path"):
        return None
    return (str(location["path"]), int(location["start_line"]), int(location["start_column"]),
            int(location["end_line"]), int(location["end_column"]))


def _inside(row: _Row, span: tuple[str, int, int, int, int]) -> bool:
    path, start_line, start_column, end_line, end_column = span
    if row.path != path or not start_line <= row.line <= end_line:
        return False
    if row.line == start_line and row.column < start_column:
        return False
    return not (row.line == end_line and row.column > end_column)


def _by_module(rows: Sequence[_Row]) -> dict[str, list[_Row]]:
    grouped: dict[str, list[_Row]] = {}
    for row in rows:
        grouped.setdefault(row.module, []).append(row)
    return grouped


@dataclass(frozen=True, slots=True)
class _Verdict:
    state: CrossCheckState
    method: str
    detail: str
    rows: tuple[_Row, ...]
    contradicting: tuple[_Row, ...] = ()


def _call_verdict(fact: GraphFact, rows: Sequence[_Row]) -> tuple[_Verdict | None, list[dict[str, str]]]:
    """Returns the verdict and, for an unresolved CodeQL call, SVF's target names."""
    span = _span(fact.location)
    callee = fact.payload["result"]["callee"]
    if span is None:
        return None, []
    matched = [row for row in rows if row.kind == EntityKind.INDIRECT_CALL_TARGETS.value and _inside(row, span)]
    if not matched:
        return None, []
    targets: dict[str, dict[str, str]] = {}
    for row in matched:
        for target in row.payload.get("targets", ()):
            name = str(target.get("demangled") or target.get("name") or "")
            if name:
                targets.setdefault(function_tail(name), {"name": str(target.get("name", name)), "demangled": name})
    complete = all(row.complete for row in matched)
    if callee["dispatch"] == Dispatch.UNRESOLVED_INDIRECT.value:
        if not targets:
            return None, []
        names = sorted(targets)
        return (_Verdict(CrossCheckState.NOT_COVERED, METHOD_CALL,
                         f"CodeQL resolves no target; SVF resolves {len(names)}: {', '.join(names[:8])}",
                         tuple(matched)), [targets[name] for name in names])
    wanted = function_tail(callee.get("display"))
    if wanted in targets:
        return _Verdict(CrossCheckState.AGREE, METHOD_CALL, f"SVF target set contains {wanted}", tuple(matched)), []
    if complete:
        return _Verdict(CrossCheckState.DISAGREE, METHOD_CALL,
                        f"closed-world SVF target set ({', '.join(sorted(targets)[:8]) or 'empty'}) excludes {wanted}",
                        tuple(matched), tuple(matched)), []
    return _Verdict(CrossCheckState.NOT_COVERED, METHOD_CALL,
                    f"SVF target set excludes {wanted} but is incomplete or open-world; no verdict", tuple(matched)), []


def _alias(compare: Sequence[_Row], sink: Sequence[_Row]) -> str:
    """Alias answer within one module: may when any set intersects; no only when all are complete."""
    compare = [row for row in compare if row.payload.get("points_to")]
    sink = [row for row in sink if row.payload.get("points_to")]
    if not compare or not sink:
        return UNKNOWN
    for left in compare:
        for right in sink:
            if set(left.payload["points_to"]) & set(right.payload["points_to"]):
                return MAY_ALIAS
    return NO_ALIAS if all(row.complete for row in [*compare, *sink]) else UNKNOWN


def _guard_verdict(fact: GraphFact, sink: GraphFact | None, rows: Sequence[_Row]) -> _Verdict | None:
    result = fact.payload["result"]
    condition = _span(fact.location) if result.get("condition") else None
    if sink is None or condition is None or sink.location is None:
        return None
    sink_span = _span(sink.location)
    if sink_span is None:
        return None
    sink_result = sink.payload["result"]
    roles = _SINK_ROLES.get(str(sink_result.get("sink_class")))
    if roles is None:
        return None
    argument = sink_result.get("argument_index")
    compares = [row for row in rows if row.kind == EntityKind.POINTS_TO_SET.value
                and row.payload.get("role") == "compare" and _inside(row, condition)]
    operands = [row for row in rows if row.kind == EntityKind.POINTS_TO_SET.value and _inside(row, sink_span)
                and row.payload.get("role") in roles
                and (row.payload.get("role") != "call_arg" or row.payload.get("operand") == argument)]
    if not compares or not operands:
        return None
    by_compare, by_operand = _by_module(compares), _by_module(operands)
    answers = [_alias(by_compare[module], by_operand[module]) for module in sorted(set(by_compare) & set(by_operand))]
    if not answers:
        return None
    answer = MAY_ALIAS if MAY_ALIAS in answers else NO_ALIAS if all(item == NO_ALIAS for item in answers) else UNKNOWN
    consulted = tuple(sorted({row.identity: row for row in [*compares, *operands]}.values(),
                             key=lambda row: row.identity))
    constrains = result.get("constrains_sink_operand")
    if answer == UNKNOWN:
        return None
    if constrains is True:
        if answer == MAY_ALIAS:
            return _Verdict(CrossCheckState.AGREE, METHOD_ALIAS, "guard operand may alias the sink operand", consulted)
        return _Verdict(CrossCheckState.DISAGREE, METHOD_ALIAS,
                        "closed-world SVF points-to sets of the guard operand and the sink operand are disjoint",
                        consulted, consulted)
    if constrains is False:
        if answer == NO_ALIAS:
            return _Verdict(CrossCheckState.AGREE, METHOD_ALIAS, "guard operand does not alias the sink operand",
                            consulted)
        return _Verdict(CrossCheckState.PARTIAL, METHOD_ALIAS,
                        "CodeQL finds no constraint but the guard operand may alias the sink operand", consulted)
    return _Verdict(CrossCheckState.NOT_COVERED, METHOD_ALIAS,
                    f"CodeQL cannot connect the guard to the sink operand; SVF answers {answer} (annotation only)",
                    consulted)


def _merge(fact: GraphFact, verdict: _Verdict) -> GraphFact:
    payload = dict(fact.payload)
    block = dict(payload["cross_check"])
    producers = [dict(item) for item in block.get("producers", ()) if item.get("name") != Producer.SVF.value]
    producers.append({"name": Producer.SVF.value, "state": verdict.state.value, "method": verdict.method,
                      "rule": SVF_RULE, "detail": verdict.detail})
    states = [CrossCheckState(item["state"]) for item in producers]
    state = min(states, key=lambda item: _RANK[item]) if states else CrossCheckState.NOT_COVERED
    upstream = {tuple(sorted(item.items())): dict(item) for item in payload.get("upstream", ())}
    for row in verdict.rows:
        upstream[tuple(sorted(row.shard.upstream.items()))] = row.shard.upstream
    payload["upstream"] = [upstream[key] for key in sorted(upstream)]
    payload["cross_check"] = {"rule": CROSS_CHECK_RULE, "state": state.value,
                              "producers": sorted(producers, key=lambda item: item["name"])}
    payload["admissibility"] = admissibility(payload)
    return replace(fact, payload=payload)


def _secondary_fact(fact: GraphFact, target: Mapping[str, str], verdict: _Verdict, *, target_snapshot: str,
                    scope: Mapping[str, Any]) -> GraphFact:
    result = fact.payload["result"]
    location = fact.location
    assert location is not None
    identity = fact_identity(Family.CALL_SITE, target_snapshot, {
        "scope_id": scope["scope_id"], "caller_symbol": result["caller"]["symbol"], "path": location.path,
        "start_byte": location.start_byte, "end_byte": location.end_byte, "callee_name": target["demangled"]})
    upstream = sorted({row.shard.shard_id: row.shard.upstream for row in verdict.rows}.values(),
                      key=lambda item: item["shard_id"])
    payload: dict[str, Any] = {
        "schema": GRAPH_FACT_SCHEMA, "family": Family.CALL_SITE.value,
        "producer": {"name": Producer.SVF.value,
                     "tool_version": str(verdict.rows[0].payload.get("tool_version", "unknown")),
                     "export_pack_sha256": None, "catalog_version": None, "rule_version": SVF_RULE},
        "scope": {key: scope.get(key) for key in ("scope_id", "language", "build_unit_id", "component_id")},
        "exact": False, "coverage_status": Coverage.PARTIAL.value,
        "gaps": ["secondary_only: CodeQL resolves no target for this indirect call; SVF's Andersen analysis resolves "
                 "this one. It is missing CodeQL coverage, not a CodeQL negative, and SVF may over-approximate"],
        "cross_check": {"rule": CROSS_CHECK_RULE, "state": CrossCheckState.PARTIAL.value,
                        "producers": [{"name": Producer.SVF.value, "state": CrossCheckState.AGREE.value,
                                       "method": METHOD_CALL, "rule": SVF_RULE}]},
        "result": {"caller": dict(result["caller"]),
                   "callee": {"symbol": None, "display": target["demangled"],
                              "dispatch": Dispatch.SECONDARY_ONLY.value, "candidate_count": 1},
                   "argument_count": result.get("argument_count"), "in_loop": result.get("in_loop", "unknown"),
                   "secondary": {"producer": Producer.SVF.value, "resolution": "andersen-points-to",
                                 "linkage_name": target["name"], "unresolved_codeql_fact": fact.identity.value}},
        "upstream": upstream, "authority": AUTHORITY,
    }
    payload["admissibility"] = admissibility(payload)
    return GraphFact(identity, f"{result['caller']['display']} -> {target['demangled']}"[:256], payload, location)


def svf_cross_check(facts: Sequence[GraphFact], shards: Sequence[SvfShard], *, target_snapshot: str,
                    scope: Mapping[str, Any]) -> CrossCheckResult:
    """Apply the SVF verdicts of section 7 to one scope's already cross-checked facts.

    Without SVF shards the facts are returned unchanged. Returns every input fact (updated where SVF
    covered it), new ``secondary_only`` call-site facts, the ``CONTRADICTS``/``DERIVED_FROM``/
    ``CONTAINS`` relations and a deterministic summary.
    """
    if not shards:
        return CrossCheckResult(tuple(facts), (), {"rule": SVF_RULE, "states": {}, "secondary_only": 0,
                                                   "shards": []})
    rows = _rows(shards)
    by_id = {fact.identity.value: fact for fact in facts}
    updated: list[GraphFact] = []
    new_facts: dict[str, GraphFact] = {}
    relations: list[RelationRecord] = []
    states: dict[str, int] = {}
    for fact in sorted(facts, key=lambda item: item.identity.value):
        verdict: _Verdict | None = None
        targets: list[dict[str, str]] = []
        if fact.family is Family.CALL_SITE and fact.payload["result"]["callee"]["dispatch"] in (
                _DYNAMIC | {Dispatch.UNRESOLVED_INDIRECT.value}):
            verdict, targets = _call_verdict(fact, rows)
        elif fact.family is Family.GUARD_FACT:
            verdict = _guard_verdict(fact, by_id.get(str(fact.payload["result"]["sink"]["sink_site"])), rows)
        if verdict is None:
            updated.append(fact)
            continue
        states[verdict.state.value] = states.get(verdict.state.value, 0) + 1
        updated.append(_merge(fact, verdict))
        for row in verdict.contradicting:
            relations.append(RelationRecord(RelationKind.CONTRADICTS, fact.identity.value, row.identity, False, 1.0,
                                            verdict.detail[:512], {"rule": SVF_RULE, "producer": Producer.SVF.value}))
        for target in targets:
            secondary = _secondary_fact(fact, target, verdict, target_snapshot=target_snapshot, scope=scope)
            if secondary.identity.value in by_id or secondary.identity.value in new_facts:
                continue
            new_facts[secondary.identity.value] = secondary
            for row in verdict.rows:
                relations.append(RelationRecord(RelationKind.DERIVED_FROM, secondary.identity.value, row.identity,
                                                False, 1.0, "SVF Andersen target of an indirect call",
                                                {"rule": SVF_RULE, "producer": Producer.SVF.value}))
            caller = fact.payload["result"]["caller"].get("symbol")
            if caller:
                relations.append(RelationRecord(RelationKind.CONTAINS, str(caller), secondary.identity.value, False,
                                                1.0, "SVF-resolved indirect call target",
                                                {"rule": SVF_RULE, "producer": Producer.SVF.value}))
    all_facts = sorted([*updated, *new_facts.values()], key=lambda item: item.identity.value)
    summary = {"rule": SVF_RULE, "states": dict(sorted(states.items())), "secondary_only": len(new_facts),
               "shards": [shard.upstream for shard in shards]}
    return CrossCheckResult(tuple(all_facts), _relations_unique(relations), summary)
