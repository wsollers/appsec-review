"""The interaction lane of the generated threat model (T-107, step ``facts.interactions``).

Turns accepted code-graph facts, tree-sitter call sites and review-prioritization signals into
``Fact`` records of kind ``interaction``. It is a pure function over an ``EvidenceView``: it never
opens a file, a shard or the target. Callee names, paths and symbols come from the target and are
carried as data only; nothing here interprets them.

Producer payload keys this lane relies on (a missing or mistyped key is read as ``None``; a record
whose class or category then maps to no interaction yields no fact):

``job_code_graph_index`` / ``code_graph_facts``, payload built by ``Normalizer.fact``
(``src/appsec_review/graph/normalize.py:476``), closed keys in ``graph/contract.py:207-210``:

- entity kind ``entry_point`` (``build_entries``, ``normalize.py:600``): ``scope.build_unit_id``,
  ``scope.component_id``, ``result.source_class`` (``normalize.py:624``, vocabulary
  ``contract.SourceClass``), ``result.api_or_parameter.api`` (``normalize.py:625-626``, may be
  null), ``result.enclosing_function.display`` and ``.symbol`` (``normalize.py:627``).
- entity kind ``sink_site`` (``build_sinks``, ``normalize.py:552``): the same ``scope`` keys,
  ``result.sink_class`` (``normalize.py:581``, vocabulary ``contract.SinkClass``),
  ``result.api.display`` (``normalize.py:582``), ``result.enclosing_function`` (``normalize.py:585``).

``job_tree_sitter_ast`` / ``tree_sitter_ast``, entity payload built in
``src/appsec_review/jobs/job_tree_sitter_ast/normalize.py:120-129``, ``syntax`` block built by
``project`` (``projection.py:122-128``): ``syntax.category`` (``"call_expression"``),
``syntax.written_name``, ``syntax.enclosing_definition`` (the entity identity of the enclosing
definition node, or null), ``syntax.syntactic_qualifiers`` (written names of the enclosing
definitions, innermost last, ``projection.py:135``), ``build_unit_id`` (``normalize.py:126``).
The payload has no ``component_id``; it is read if present and is otherwise ``None``.

``job_review_prioritization`` / ``priority_items``, entity kind ``review_signal``, payload
``{**record, "authority": ...}`` (``jobs/job_review_prioritization/job.py:752``) over the record of
``Extractor.signal`` (``heuristics.py:203-207``): ``rule_id``, ``basis`` (``observed_syntax``,
``heuristic_inference`` or ``verified_semantic_path``, ``rules.py:17-19``), ``category``,
``surface`` (absent on suppression records, ``heuristics.py:516-519``), ``path``, ``function_id``
(``<path>#<qualified name>@<line>:<column>``, ``complexity.py:357``, or null). Semgrep and CodeQL
records (``semantic.py:72-80`` and ``semantic.py:127-139``) carry the same ``rule_id``, ``basis``,
``category`` and ``surface``. The payload has no build unit or component.

Enclosing symbols are names, so facts from different producers compare: the graph's
``enclosing_function.display`` (else its ``symbol`` identity), tree-sitter's innermost syntactic
qualifier when an enclosing definition exists (else that definition's identity), and the qualified
name inside a signal's ``function_id`` (else the whole ``function_id``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.threat_model import view as views
from appsec_review.threat_model.contract import (
    BASIS_PRECEDENCE, Basis, EvidenceRecord, EvidenceRef, Fact, FactKind, InputLedgerRow, Interaction, LaneResult,
    Limits, canonical, cite, merge_evidence, strongest,
)
from appsec_review.threat_model.view import EvidenceView

GRAPH_INPUT = ("job_code_graph_index", "code_graph_facts")
SYNTAX_INPUT = ("job_tree_sitter_ast", "tree_sitter_ast")
SIGNAL_INPUT = ("job_review_prioritization", "priority_items")
SEMANTIC_SIGNAL_BASIS = "verified_semantic_path"
LANE = "interactions"
ENTRY_POINT_BOUND = "interactions.max_entry_points"


class InteractionRules(Protocol):
    """The part of the reference data this lane needs (the interaction catalog, design section 5.1)."""

    def interaction_for_source_class(self, source_class: str) -> Interaction | None: ...

    def interaction_for_sink_class(self, sink_class: str) -> Interaction | None: ...

    def interaction_for_signal(self, category: str, surface: str | None) -> Interaction | None: ...

    def callee_names(self) -> tuple[str, ...]: ...  # sorted

    def interaction_for_callee(self, name: str) -> Interaction | None: ...


@dataclass(frozen=True, slots=True)
class _Candidate:
    """One record's reading: where it is, what it says and the citation that says it."""
    interaction: Interaction
    path: str
    start_line: int
    reference: EvidenceRef
    attributes: Mapping[str, Any]

    @property
    def rank(self) -> tuple[int, str, str]:
        return (BASIS_PRECEDENCE.index(self.reference.basis), self.reference.rule, self.reference.ref)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _mapping(value: Any, key: str) -> Mapping[str, Any]:
    found = value.get(key) if isinstance(value, Mapping) else None
    return found if isinstance(found, Mapping) else {}


def _candidate(record: EvidenceRecord, interaction: Interaction, basis: Basis, rule: str, *,
               source_class: str | None = None, sink_class: str | None = None, callee: str | None = None,
               enclosing_symbol: str | None = None, build_unit_id: str | None = None,
               component_id: str | None = None) -> _Candidate:
    assert record.span is not None
    return _Candidate(interaction, record.span.path, record.span.start_line, cite(record, basis, rule), {
        "interaction": interaction.value, "path": record.span.path, "source_class": source_class,
        "sink_class": sink_class, "callee": callee, "enclosing_symbol": enclosing_symbol,
        "build_unit_id": build_unit_id, "component_id": component_id})


def _graph_candidate(record: EvidenceRecord, kind: str, rules: InteractionRules) -> _Candidate | None:
    result, scope = _mapping(record.payload, "result"), _mapping(record.payload, "scope")
    function = _mapping(result, "enclosing_function")
    common = {"enclosing_symbol": _text(function.get("display")) or _text(function.get("symbol")),
              "build_unit_id": _text(scope.get("build_unit_id")), "component_id": _text(scope.get("component_id"))}
    if kind == "entry_point":
        klass = _text(result.get("source_class"))
        interaction = rules.interaction_for_source_class(klass) if klass else None
        if interaction is None:
            return None
        return _candidate(record, Interaction(interaction), Basis.VERIFIED_SEMANTIC, f"graph.entry_point.{klass}",
                          source_class=klass, callee=_text(_mapping(result, "api_or_parameter").get("api")), **common)
    klass = _text(result.get("sink_class"))
    interaction = rules.interaction_for_sink_class(klass) if klass else None
    if interaction is None:
        return None
    return _candidate(record, Interaction(interaction), Basis.VERIFIED_SEMANTIC, f"graph.sink_site.{klass}",
                      sink_class=klass, callee=_text(_mapping(result, "api").get("display")), **common)


def _syntax_candidate(record: EvidenceRecord, name: str, interaction: Interaction) -> _Candidate | None:
    syntax = _mapping(record.payload, "syntax")
    if syntax.get("category") != "call_expression" or syntax.get("written_name") != name:
        return None  # not exactly a catalogued callee: nothing is claimed
    enclosing = _text(syntax.get("enclosing_definition"))
    qualifiers = syntax.get("syntactic_qualifiers")
    written = _text(qualifiers[-1]) if enclosing and isinstance(qualifiers, (list, tuple)) and qualifiers else None
    return _candidate(record, interaction, Basis.OBSERVED_SYNTAX, f"syntax.call.{name}", callee=name,
                      enclosing_symbol=written or enclosing, build_unit_id=_text(record.payload.get("build_unit_id")),
                      component_id=_text(record.payload.get("component_id")))


def _signal_symbol(payload: Mapping[str, Any]) -> str | None:
    function_id, path = _text(payload.get("function_id")), _text(payload.get("path"))
    if function_id is None:
        return None
    if path and function_id.startswith(f"{path}#"):
        return _text(function_id[len(path) + 1:].rpartition("@")[0]) or function_id
    return function_id


def _signal_candidate(record: EvidenceRecord, rules: InteractionRules) -> _Candidate | None:
    payload = record.payload
    category, rule_id = _text(payload.get("category")), _text(payload.get("rule_id"))
    interaction = rules.interaction_for_signal(category, _text(payload.get("surface"))) if category else None
    if interaction is None or rule_id is None:
        return None
    basis = Basis.VERIFIED_SEMANTIC if payload.get("basis") == SEMANTIC_SIGNAL_BASIS else Basis.OBSERVED_SYNTAX
    return _candidate(record, Interaction(interaction), basis, f"signal.{rule_id}",
                      enclosing_symbol=_signal_symbol(payload))


def _fact(group: list[_Candidate], limits: Limits) -> Fact:
    """One fact per interaction, path and start line; the strongest-basis record supplies the attributes."""
    lead = min(group, key=lambda item: item.rank)
    evidence = merge_evidence(tuple(item.reference for item in group), limit=limits.max_evidence_refs_per_element)
    identity = {"interaction": lead.interaction.value, "path": lead.path, "start_line": lead.start_line,
                "enclosing_symbol": lead.attributes["enclosing_symbol"]}
    return Fact(FactKind.INTERACTION, identity, f"{lead.interaction.value} {lead.path}:{lead.start_line}",
                strongest(*(item.reference.basis for item in group)), evidence, lead.attributes)


def interactions(view: EvidenceView, rules: InteractionRules, limits: Limits, *,
                 unit_id: str = "facts.interactions") -> LaneResult:
    """Interaction facts with their gaps and ledger rows, independent of the order records arrive in."""
    candidates: list[_Candidate] = []
    gaps: list[Mapping[str, Any]] = []
    ledger: list[InputLedgerRow] = []
    read_any = False

    def take(query: str, page: views.Page, reading: Any) -> tuple[int, int]:
        if page.truncated:
            gaps.append(views.truncated_gap(query, limits.max_query_rows, unit_id=unit_id))
        unlocated = 0
        for record in page.records:
            if record.span is None:
                unlocated += 1
                continue
            found = reading(record)
            if found is not None:
                candidates.append(found)
        return len(page.records), unlocated

    def unlocated_gap(scope: str, count: int) -> None:
        if count:
            gaps.append(producer_gap(
                GapCode.LOCATION_UNRESOLVED,
                f"{scope} returned {count} records without a source span; they were not used",
                unit_id=unit_id, scope_id=scope))

    opened = views.open_input(view, *GRAPH_INPUT, unit_id=unit_id)
    gaps.extend(opened.gaps)
    read = 0
    if opened.readable:
        read_any = True
        for kind in ("entry_point", "sink_site"):
            page = view.entities(*GRAPH_INPUT, kind, limit=limits.max_query_rows)
            count, unlocated = take(f"graph.{kind}", page,
                                    lambda record, kind=kind: _graph_candidate(record, kind, rules))
            read += count
            unlocated_gap(f"graph.{kind}", unlocated)
    ledger.append(views.with_count(opened.row, read))

    opened = views.open_input(view, *SYNTAX_INPUT, unit_id=unit_id)
    gaps.extend(opened.gaps)
    read = 0
    if opened.readable:
        read_any = True
        unlocated = 0
        for name in sorted(set(rules.callee_names())):
            interaction = rules.interaction_for_callee(name)
            if interaction is None:
                continue
            page = view.search_calls(name, limit=limits.max_query_rows)
            count, missing = take(f"syntax.call.{name}", page,
                                  lambda record, name=name, interaction=Interaction(interaction):
                                  _syntax_candidate(record, name, interaction))
            read += count
            unlocated += missing
        unlocated_gap("syntax.call", unlocated)
    ledger.append(views.with_count(opened.row, read))

    opened = views.open_input(view, *SIGNAL_INPUT, unit_id=unit_id)
    gaps.extend(opened.gaps)
    read = 0
    if opened.readable:
        read_any = True
        page = view.entities(*SIGNAL_INPUT, "review_signal", limit=limits.max_query_rows)
        read, unlocated = take("signal.review_signal", page, lambda record: _signal_candidate(record, rules))
        unlocated_gap("signal.review_signal", unlocated)
    ledger.append(views.with_count(opened.row, read))

    groups: dict[tuple[str, str, int], list[_Candidate]] = {}
    for item in candidates:
        groups.setdefault((item.interaction.value, item.path, item.start_line), []).append(item)
    facts = [_fact(group, limits) for group in groups.values()]
    if len(facts) > limits.max_entry_points:
        facts.sort(key=lambda fact: (BASIS_PRECEDENCE.index(fact.basis), canonical(fact.native_identity)))
        facts = facts[:limits.max_entry_points]
        gaps.append(views.truncated_gap(ENTRY_POINT_BOUND, limits.max_entry_points, unit_id=unit_id))
    facts.sort(key=lambda fact: canonical(fact.native_identity))
    if read_any and not facts:
        gaps.append(views.empty_gap(LANE, unit_id=unit_id))
    return LaneResult(tuple(facts), tuple(gaps), tuple(ledger))
