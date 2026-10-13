"""Cross-check of CodeQL call-site facts against accepted C/C++ secondary producers.

Rule ``graph-cross-check/1`` (docs/architecture/code-graph-precomputation.md, D1 and 4.1). Pure
functions over already-built :class:`GraphFact` values and accepted secondary shard rows read through
``indexing.store.ShardSet``; nothing here runs an analyzer or reads a target tree.

Producers and what each may conclude:

* ``clangd`` ``CALLS`` edges. Every located reference is assigned to the innermost exact CodeQL
  ``call_site`` span (by byte offset) that contains it. Same callee and caller symbol → ``agree``;
  a different callee for a direct call → ``disagree`` with a ``CONTRADICTS`` relation; a symbol
  identity only linked by name, a dynamic-dispatch candidate clangd cannot confirm, or a caller that
  differs → ``partial``. A reference no CodeQL span contains becomes a ``secondary_only`` fact.
* ``llvm-ir`` unique direct ``CALLS`` and ``clang-ast`` ``CallExpr`` nodes. They carry no call-site
  location, so they match by caller/callee name within the same translation unit and can only
  confirm (``agree``) or not cover a fact; their absence is never a contradiction. An IR edge whose
  caller CodeQL covers but whose callee CodeQL never reports becomes a ``secondary_only`` fact.

Missing secondary shards leave every fact ``not_covered``; cross-check is a second opinion, never a
prerequisite. Disagreement is published, never merged or dropped.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
import hashlib
from typing import Any

from appsec_review.graph.contract import (
    AUTHORITY, CROSS_CHECK_RULE, GRAPH_FACT_SCHEMA, Coverage, CrossCheckState, Dispatch, Family, GraphFact,
    Producer, admissibility, fact_identity,
)
from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval.model import (
    EntityKind, EntityRecord, RelationKind, RelationRecord, SourceLocation, canonical_json,
)

METHOD_CLANGD_SPAN = "clangd-reference-in-span"
METHOD_IR_NAME = "ir-name-same-tu"
METHOD_AST_NAME = "ast-name-same-tu"
METHOD_SYMBOL_SPAN = "definition-span-equal"
METHOD_SYMBOL_NAME = "name-and-file"

SECONDARY_KINDS: Mapping[Producer, str] = {
    Producer.CLANGD: EntityKind.SYMBOL.value,
    Producer.LLVM_IR: EntityKind.IR_ENTITY.value,
    Producer.CLANG_AST: EntityKind.AST_NODE.value,
}
_DYNAMIC = frozenset({Dispatch.VIRTUAL_RESOLVED.value, Dispatch.FUNCTION_POINTER_RESOLVED.value,
                      Dispatch.TEMPLATE_INSTANTIATION.value})
_STATE_RANK = {CrossCheckState.DISAGREE: 0, CrossCheckState.PARTIAL: 1, CrossCheckState.AGREE: 2,
               CrossCheckState.NOT_COVERED: 3}


@dataclass(frozen=True, slots=True)
class SourceFile:
    """An accepted source file's hash and bytes, for line/column to byte-offset mapping."""

    sha256: str
    data: bytes
    line_starts: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if hashlib.sha256(self.data).hexdigest() != self.sha256:
            raise ValueError("source bytes differ from their accepted sha256")
        starts = [0]
        position = self.data.find(b"\n")
        while position != -1:
            starts.append(position + 1)
            position = self.data.find(b"\n", position + 1)
        object.__setattr__(self, "line_starts", tuple(starts))

    @classmethod
    def from_bytes(cls, data: bytes) -> "SourceFile":
        return cls(hashlib.sha256(data).hexdigest(), bytes(data))

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def line_count(self) -> int:
        return len(self.line_starts)

    def offset(self, line: int, column: int) -> int | None:
        """Byte offset of a 1-based line and 1-based UTF-16 column (SARIF/LSP convention).

        A column one past the last character is the line's end offset (an exclusive end).
        """
        starts = self.line_starts
        if not isinstance(line, int) or not isinstance(column, int) or not 1 <= line <= len(starts) or column < 1:
            return None
        start = starts[line - 1]
        end = starts[line] - 1 if line < len(starts) else len(self.data)
        units = column - 1
        consumed = 0
        for character in self.data[start:end].decode("utf-8", errors="surrogateescape"):
            if units <= 0:
                break
            units -= 2 if ord(character) > 0xFFFF else 1
            consumed += len(character.encode("utf-8", errors="surrogateescape"))
        return None if units > 0 else start + consumed


@dataclass(frozen=True, slots=True)
class SecondaryShard:
    """Accepted rows of one secondary shard (``ShardSet.entities``/``relations`` row shapes)."""

    producer: Producer
    index: str
    shard_id: str
    sha256: str
    entities: tuple[Mapping[str, Any], ...] = ()
    relations: tuple[Mapping[str, Any], ...] = ()
    tool_version: str = "unknown"

    @property
    def upstream(self) -> dict[str, str]:
        return {"index": self.index, "shard_id": self.shard_id, "sha256": self.sha256}


def read_secondary(shard_set: ShardSet, shard: Mapping[str, Any], producer: Producer | str, *,
                   tool_version: str = "unknown") -> SecondaryShard:
    """Read one accepted secondary shard's producer entities and ``CALLS`` relations."""
    producer = Producer(producer)
    if producer is Producer.CODEQL_EXPORT:
        raise ValueError("codeql-export is the primary producer, not a cross-check input")
    entities = tuple(shard_set.entities([shard], kinds=(SECONDARY_KINDS[producer],)))
    relations = tuple(shard_set.relations([shard], kinds=(RelationKind.CALLS.value,)))
    return SecondaryShard(producer, str(shard["name"]), str(shard.get("shard_id", "default")), str(shard["sha256"]),
                          entities, relations, tool_version)


@dataclass(frozen=True, slots=True)
class CrossCheckInputs:
    clangd: tuple[SecondaryShard, ...] = ()
    llvm_ir: tuple[SecondaryShard, ...] = ()
    clang_ast: tuple[SecondaryShard, ...] = ()

    def __post_init__(self) -> None:
        for producer, shards in ((Producer.CLANGD, self.clangd), (Producer.LLVM_IR, self.llvm_ir),
                                 (Producer.CLANG_AST, self.clang_ast)):
            if any(shard.producer is not producer for shard in shards):
                raise ValueError(f"{producer.value} inputs must hold only {producer.value} shards")


@dataclass(frozen=True, slots=True)
class CrossCheckResult:
    facts: tuple[GraphFact, ...]
    relations: tuple[RelationRecord, ...]
    summary: Mapping[str, Any] = field(default_factory=dict)


def _tail(name: Any) -> str:
    text = str(name or "")
    if "(" in text:
        text = text[:text.index("(")]
    return text.rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()


def _names(name: Any) -> frozenset[str]:
    text = str(name or "").strip()
    return frozenset(value for value in (text, _tail(text)) if value)


def _exact_location(fact: GraphFact) -> SourceLocation | None:
    location = fact.location
    if location is None or location.ambiguous or location.confidence != 1.0:
        return None
    return location


def _relations_unique(relations: Iterable[RelationRecord]) -> tuple[RelationRecord, ...]:
    found: dict[str, RelationRecord] = {}
    for relation in sorted(relations, key=lambda item: (item.relation_id, canonical_json(item.payload or {}))):
        found.setdefault(relation.relation_id, relation)
    return tuple(found[key] for key in sorted(found))


def link_symbols(graph_symbols: Sequence[EntityRecord], clangd: Sequence[SecondaryShard], *,
                 sources: Mapping[str, SourceFile]) -> tuple[dict[tuple[str, str], bool], tuple[RelationRecord, ...]]:
    """``SAME_AS`` between graph-published (CodeQL) symbols and clangd symbols (section 3.1).

    ``exact=True`` only when the clangd definition byte span (from its line/column definition and the
    accepted source bytes) equals the graph symbol's byte span; same file and same name otherwise give
    an ambiguous ``name-and-file`` link. Returns the link map ``{(graph_id, clangd_id): exact}`` with
    both orientations, and the relations.
    """
    by_file: dict[str, list[tuple[Mapping[str, Any], tuple[int, int] | None]]] = {}
    for shard in clangd:
        for row in shard.entities:
            definition = (row.get("payload") or {}).get("definition")
            if row.get("kind") != EntityKind.SYMBOL.value or not isinstance(definition, Mapping):
                continue
            path = str(definition.get("path", ""))
            source = sources.get(path)
            span = None
            if source is not None:
                start = source.offset(int(definition.get("line", 0) or 0), int(definition.get("column", 0) or 0))
                end = source.offset(int(definition.get("end_line", 0) or 0), int(definition.get("end_column", 0) or 0))
                span = (start, end) if start is not None and end is not None else None
            by_file.setdefault(path, []).append((row, span))
    links: dict[tuple[str, str], bool] = {}
    relations: list[RelationRecord] = []
    for symbol in sorted(graph_symbols, key=lambda item: item.identity.value):
        location = symbol.location
        if symbol.identity.kind is not EntityKind.SYMBOL or location is None:
            continue
        for row, span in sorted(by_file.get(location.path, ()), key=lambda item: str(item[0]["identity"])):
            if not (_names(symbol.name) & _names(row.get("name"))):
                continue
            exact = (span == (location.start_byte, location.end_byte) and not location.ambiguous
                     and (sources.get(location.path) is None or sources[location.path].sha256 == location.file_sha256))
            method = METHOD_SYMBOL_SPAN if exact else METHOD_SYMBOL_NAME
            links[(symbol.identity.value, str(row["identity"]))] = exact
            links[(str(row["identity"]), symbol.identity.value)] = exact
            relations.append(RelationRecord(
                RelationKind.SAME_AS, symbol.identity.value, str(row["identity"]), exact, 1.0 if exact else 0.5,
                None if exact else "CodeQL and clangd symbols share a file and name but not a definition byte span",
                {"rule": CROSS_CHECK_RULE, "method": method, "producer": Producer.CLANGD.value}))
    return links, _relations_unique(relations)


class _Symbols:
    """Symbol equivalence for one cross-check: identity, exact SAME_AS, or name-only."""

    def __init__(self, links: Mapping[tuple[str, str], bool], names: Mapping[str, str]):
        self.links = links
        self.names = names

    def match(self, left: str | None, left_display: Any, right: str | None) -> str:
        if left and right and left == right:
            return "exact"
        if left and right and (left, right) in self.links:
            return "exact" if self.links[(left, right)] else "ambiguous"
        if right and _names(left_display) & _names(self.names.get(right)):
            return "ambiguous"
        return "different"


@dataclass(slots=True)
class _Verdict:
    state: CrossCheckState
    method: str
    detail: str | None = None


def _combine(verdicts: Mapping[Producer, _Verdict]) -> CrossCheckState:
    if not verdicts:
        return CrossCheckState.NOT_COVERED
    return min((verdict.state for verdict in verdicts.values()), key=lambda state: _STATE_RANK[state])


def _call_parts(fact: GraphFact) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    result = fact.payload.get("result") or {}
    caller = result.get("caller") if isinstance(result.get("caller"), Mapping) else {}
    callee = result.get("callee") if isinstance(result.get("callee"), Mapping) else {}
    return caller, callee


def _secondary_payload(*, family: Family, producer: SecondaryShard, scope: Mapping[str, Any], result: Mapping[str, Any],
                       gaps: list[str], producers: list[dict[str, Any]]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": GRAPH_FACT_SCHEMA, "family": family.value,
        "producer": {"name": producer.producer.value, "tool_version": producer.tool_version,
                     "export_pack_sha256": None, "catalog_version": None, "rule_version": CROSS_CHECK_RULE},
        "scope": {key: scope.get(key) for key in ("scope_id", "language", "build_unit_id", "component_id")},
        "exact": False, "coverage_status": Coverage.PARTIAL.value, "gaps": gaps,
        "cross_check": {"rule": CROSS_CHECK_RULE, "state": CrossCheckState.PARTIAL.value, "producers": producers},
        "result": dict(result), "upstream": [producer.upstream], "authority": AUTHORITY,
    }
    payload["admissibility"] = admissibility(payload)
    return payload


def cross_check(facts: Sequence[GraphFact], inputs: CrossCheckInputs, *, target_snapshot: str,
                scope: Mapping[str, Any], sources: Mapping[str, SourceFile],
                graph_symbols: Sequence[EntityRecord] = ()) -> CrossCheckResult:
    """Apply ``graph-cross-check/1`` to one CodeQL scope's facts.

    ``facts`` are the scope's normalized facts (any family; only ``call_site`` is cross-checked, every
    other family is set ``not_covered``). ``sources`` maps accepted target-relative paths of the scope
    to their bytes; secondary references outside it are ignored. ``scope`` is the graph-fact scope block
    for published ``secondary_only`` facts. ``graph_symbols`` are the CodeQL-exported ``symbol``
    entities, linked to clangd symbols with ``SAME_AS``.

    Returns every input fact with a recomputed ``cross_check`` and ``admissibility`` block plus new
    ``secondary_only`` facts (sorted by identity), the ``CONTRADICTS``, ``DERIVED_FROM``, ``SAME_AS``,
    ``CONTAINS`` and ``CALLS`` relations (sorted by relation id) and a deterministic summary.
    """
    if not str(scope.get("scope_id") or ""):
        raise ValueError("cross-check scope requires a scope_id")
    links, relations = link_symbols(graph_symbols, inputs.clangd, sources=sources)
    out_relations: list[RelationRecord] = list(relations)
    clangd_names: dict[str, str] = {}
    for shard in inputs.clangd:
        for row in shard.entities:
            clangd_names[str(row["identity"])] = str(row.get("name") or "")
    symbols = _Symbols(links, clangd_names)
    calls = sorted((fact for fact in facts if fact.family is Family.CALL_SITE), key=lambda item: item.identity.value)
    verdicts: dict[str, dict[Producer, _Verdict]] = {fact.identity.value: {} for fact in calls}
    consulted: dict[str, list[dict[str, str]]] = {fact.identity.value: [] for fact in calls}
    new_facts: list[GraphFact] = []
    seen: set[str] = set()
    summary_gaps: list[str] = []

    # clangd: assign each located CALLS reference to the innermost exact CodeQL call span.
    if inputs.clangd:
        spans: dict[str, list[tuple[int, int, list[GraphFact]]]] = {}
        grouped: dict[tuple[str, int, int], list[GraphFact]] = {}
        for fact in calls:
            location = _exact_location(fact)
            if location is not None:
                grouped.setdefault((location.path, location.start_byte, location.end_byte), []).append(fact)
        for (path, start, end), members in sorted(grouped.items(), key=lambda item: item[0]):
            spans.setdefault(path, []).append((start, end, members))
        assigned: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
        orphans: list[tuple[SecondaryShard, dict[str, Any]]] = []
        unlocated = 0
        for shard in inputs.clangd:
            for relation in shard.relations:
                if relation.get("kind") != RelationKind.CALLS.value:
                    continue
                payload = relation.get("payload") or {}
                locations = [item for item in payload.get("locations", ()) if isinstance(item, Mapping)]
                unlocated += max(0, int(payload.get("occurrences", 0) or 0) - len(locations))
                for item in locations:
                    path = str(item.get("path", ""))
                    source = sources.get(path)
                    if source is None:
                        continue  # outside this scope's accepted sources
                    line, column = int(item.get("line", 0) or 0), int(item.get("column", 0) or 0)
                    offset = source.offset(line, column)
                    if offset is None:
                        summary_gaps.append(f"clangd reference {path}:{line}:{column} does not resolve in the source")
                        continue
                    reference = {"caller": str(relation["source_id"]), "callee": str(relation["target_id"]),
                                 "path": path, "line": line, "column": column, "offset": offset,
                                 "shard": shard.upstream}
                    containing = [(end - start, start, end) for start, end, _ in spans.get(path, ())
                                  if start <= offset < end]
                    if containing:
                        _, start, end = min(containing)
                        assigned.setdefault((path, start, end), []).append(reference)
                    else:
                        orphans.append((shard, reference))
        if unlocated:
            summary_gaps.append(f"{unlocated} clangd call references beyond the per-edge location bound were not checked")
        for key, members in grouped.items():
            references = sorted(assigned.get(key, ()), key=lambda item: (item["offset"], item["callee"], item["caller"]))
            for fact in members:
                caller, callee = _call_parts(fact)
                upstreams = {canonical_json(item["shard"]): item["shard"] for item in references}
                consulted[fact.identity.value].extend(upstreams[name] for name in sorted(upstreams))
                if not references:
                    verdicts[fact.identity.value][Producer.CLANGD] = _Verdict(
                        CrossCheckState.NOT_COVERED, METHOD_CLANGD_SPAN, "no clangd CALLS reference in the call span")
                    continue
                rank = {"exact": 0, "ambiguous": 1, "different": 2}
                scored = []
                for reference in references:
                    callee_match = symbols.match(callee.get("symbol"), callee.get("display"), reference["callee"])
                    caller_match = symbols.match(caller.get("symbol"), caller.get("display"), reference["caller"])
                    scored.append(((rank[callee_match], rank[caller_match]), callee_match, caller_match, reference))
                _, callee_match, caller_match, reference = min(scored, key=lambda item: item[0])
                dispatch = str(callee.get("dispatch", ""))
                if callee_match == "exact" and caller_match == "exact":
                    verdict = _Verdict(CrossCheckState.AGREE, METHOD_CLANGD_SPAN)
                    out_relations.append(RelationRecord(
                        RelationKind.DERIVED_FROM, fact.identity.value, reference["callee"], True, 1.0, None,
                        {"rule": CROSS_CHECK_RULE, "producer": Producer.CLANGD.value, "method": METHOD_CLANGD_SPAN,
                         "reference": {name: reference[name] for name in ("path", "line", "column")}}))
                elif callee_match != "different":
                    verdict = _Verdict(CrossCheckState.PARTIAL, METHOD_CLANGD_SPAN,
                                       f"clangd callee matches by {callee_match} identity, caller by {caller_match}")
                    out_relations.append(RelationRecord(
                        RelationKind.DERIVED_FROM, fact.identity.value, reference["callee"], False, 0.5,
                        f"clangd reference matched with {callee_match} callee and {caller_match} caller identity",
                        {"rule": CROSS_CHECK_RULE, "producer": Producer.CLANGD.value, "method": METHOD_CLANGD_SPAN,
                         "reference": {name: reference[name] for name in ("path", "line", "column")}}))
                elif dispatch in _DYNAMIC or dispatch == Dispatch.UNRESOLVED_INDIRECT.value:
                    verdict = _Verdict(CrossCheckState.PARTIAL, METHOD_CLANGD_SPAN,
                                       f"clangd reports one static callee for a {dispatch} call")
                    out_relations.append(RelationRecord(
                        RelationKind.DERIVED_FROM, fact.identity.value, reference["callee"], False, 0.5,
                        f"clangd names a static callee for a {dispatch} call; it cannot confirm this candidate",
                        {"rule": CROSS_CHECK_RULE, "producer": Producer.CLANGD.value, "method": METHOD_CLANGD_SPAN,
                         "reference": {name: reference[name] for name in ("path", "line", "column")}}))
                else:
                    verdict = _Verdict(CrossCheckState.DISAGREE, METHOD_CLANGD_SPAN,
                                       "clangd resolves this call span to a different callee")
                    contradicting = sorted({item["callee"] for item in references})
                    for target in contradicting:
                        where = [item for item in references if item["callee"] == target]
                        first = where[0]
                        out_relations.append(RelationRecord(
                            RelationKind.CONTRADICTS, fact.identity.value, target, False, 0.5,
                            (f"clangd resolves the call at {first['path']}:{first['line']}:{first['column']} to "
                             f"{clangd_names.get(target) or target}; CodeQL resolves it to "
                             f"{callee.get('display') or 'an unresolved callee'}")[:1024],
                            {"rule": CROSS_CHECK_RULE, "producer": Producer.CLANGD.value,
                             "method": METHOD_CLANGD_SPAN, "codeql_callee": callee.get("symbol"),
                             "clangd_callee": target,
                             "references": [{name: item[name] for name in ("path", "line", "column")}
                                            for item in where]}))
                verdicts[fact.identity.value][Producer.CLANGD] = verdict
        for fact in calls:
            if _exact_location(fact) is None:
                verdicts[fact.identity.value][Producer.CLANGD] = _Verdict(
                    CrossCheckState.NOT_COVERED, METHOD_CLANGD_SPAN, "the fact has no exact call span")
        # clangd references no CodeQL span contains become secondary_only facts.
        for shard, reference in sorted(orphans, key=lambda item: (item[1]["path"], item[1]["offset"],
                                                                    item[1]["caller"], item[1]["callee"])):
            source = sources[reference["path"]]
            caller_name = clangd_names.get(reference["caller"]) or reference["caller"]
            callee_name = clangd_names.get(reference["callee"]) or reference["callee"]
            identity = fact_identity(Family.CALL_SITE, target_snapshot, {
                "scope_id": scope["scope_id"], "caller_symbol": reference["caller"], "path": reference["path"],
                "start_byte": reference["offset"], "end_byte": reference["offset"], "callee_name": callee_name})
            if identity.value in seen:
                continue
            seen.add(identity.value)
            location = SourceLocation(
                target_snapshot, reference["path"], source.sha256, reference["offset"], reference["offset"],
                reference["line"], reference["line"], reference["column"], reference["column"],
                {"producer": Producer.CLANGD.value, "line": reference["line"], "column": reference["column"]},
                "clangd-reference-point", 0.5, True)
            payload = _secondary_payload(
                family=Family.CALL_SITE, producer=shard, scope=scope,
                result={"caller": {"symbol": reference["caller"], "display": caller_name},
                        "callee": {"symbol": reference["callee"], "display": callee_name,
                                   "dispatch": Dispatch.SECONDARY_ONLY.value, "candidate_count": 1},
                        "argument_count": None, "in_loop": "unknown",
                        "secondary": {"producer": Producer.CLANGD.value,
                                      "reference": {name: reference[name] for name in ("path", "line", "column")}}},
                gaps=["secondary_only: no CodeQL call_site covers this clangd reference; this is missing CodeQL "
                      "coverage, not a CodeQL negative",
                      "location is the clangd reference point, not the call expression span"],
                producers=[{"name": Producer.CLANGD.value, "state": CrossCheckState.AGREE.value,
                            "method": METHOD_CLANGD_SPAN}])
            new_facts.append(GraphFact(identity, f"{caller_name} -> {callee_name}"[:256], payload, location))
            out_relations.append(RelationRecord(RelationKind.CONTAINS, reference["caller"], identity.value, True, 1.0,
                                                None, {"rule": CROSS_CHECK_RULE, "producer": Producer.CLANGD.value}))
            out_relations.append(RelationRecord(RelationKind.CALLS, identity.value, reference["callee"], True, 1.0,
                                                None, {"rule": CROSS_CHECK_RULE, "producer": Producer.CLANGD.value}))

    # LLVM IR: callee and caller name within the same translation unit; confirm or not cover only.
    if inputs.llvm_ir:
        ir_entities: dict[str, tuple[str, str, SecondaryShard, Mapping[str, Any]]] = {}
        for shard in inputs.llvm_ir:
            for row in shard.entities:
                location = row.get("location") or {}
                if location.get("path"):
                    ir_entities[str(row["identity"])] = (str(row.get("name") or ""), str(location["path"]), shard, row)
        ir_paths = {value[1] for value in ir_entities.values()}
        edges: dict[str, list[tuple[str, str, str, str, SecondaryShard]]] = {}
        for shard in inputs.llvm_ir:
            for relation in shard.relations:
                caller_row, callee_row = ir_entities.get(str(relation["source_id"])), ir_entities.get(
                    str(relation["target_id"]))
                if relation.get("kind") != RelationKind.CALLS.value or caller_row is None or callee_row is None:
                    continue
                edges.setdefault(caller_row[1], []).append(
                    (caller_row[0], callee_row[0], str(relation["source_id"]), str(relation["target_id"]), shard))
        for path in edges:
            edges[path].sort(key=lambda item: item[:4])
        covered_pairs: set[tuple[str, str, str]] = set()
        codeql_callers: dict[str, set[str]] = {}
        for fact in calls:
            caller, callee = _call_parts(fact)
            location = fact.location
            path = location.path if location is not None else ""
            if path:
                codeql_callers.setdefault(path, set()).update(_names(caller.get("display")))
            if path not in ir_paths:
                verdicts[fact.identity.value][Producer.LLVM_IR] = _Verdict(
                    CrossCheckState.NOT_COVERED, METHOD_IR_NAME, "no LLVM IR translation unit for this path")
                continue
            match = next((edge for edge in edges.get(path, ())
                          if edge[0] in _names(caller.get("display")) and edge[1] in _names(callee.get("display"))),
                         None)
            if match is None:
                verdicts[fact.identity.value][Producer.LLVM_IR] = _Verdict(
                    CrossCheckState.NOT_COVERED, METHOD_IR_NAME, "no IR call with this caller and callee name")
                continue
            covered_pairs.add((path, match[0], match[1]))
            verdicts[fact.identity.value][Producer.LLVM_IR] = _Verdict(CrossCheckState.AGREE, METHOD_IR_NAME)
            consulted[fact.identity.value].append(match[4].upstream)
            out_relations.append(RelationRecord(
                RelationKind.DERIVED_FROM, fact.identity.value, match[3], False, 0.5,
                "LLVM IR call matched by caller and callee name within the same translation unit; IR has no "
                "call-site location", {"rule": CROSS_CHECK_RULE, "producer": Producer.LLVM_IR.value,
                                       "method": METHOD_IR_NAME}))
        # IR edges whose caller CodeQL covers but whose callee it never reports in that TU.
        reported = {(fact.location.path, name_caller, name_callee)
                    for fact in calls if fact.location is not None
                    for name_caller in _names(_call_parts(fact)[0].get("display"))
                    for name_callee in _names(_call_parts(fact)[1].get("display"))}
        for path in sorted(edges):
            source = sources.get(path)
            if source is None:
                continue
            for caller_name, callee_name, caller_id, callee_id, shard in edges[path]:
                if caller_name not in codeql_callers.get(path, set()) or (path, caller_name, callee_name) in reported:
                    continue
                identity = fact_identity(Family.CALL_SITE, target_snapshot, {
                    "scope_id": scope["scope_id"], "caller_symbol": caller_id, "path": path, "start_byte": 0,
                    "end_byte": source.size, "callee_name": callee_name})
                if identity.value in seen:
                    continue
                seen.add(identity.value)
                location = SourceLocation(target_snapshot, path, source.sha256, 0, source.size, 1,
                                          source.line_count, 1, 1,
                                          {"producer": Producer.LLVM_IR.value, "translation_unit": path},
                                          "ir-translation-unit", 0.5, True)
                payload = _secondary_payload(
                    family=Family.CALL_SITE, producer=shard, scope=scope,
                    result={"caller": {"symbol": caller_id, "display": caller_name},
                            "callee": {"symbol": callee_id, "display": callee_name,
                                       "dispatch": Dispatch.SECONDARY_ONLY.value, "candidate_count": 1},
                            "argument_count": None, "in_loop": "unknown",
                            "secondary": {"producer": Producer.LLVM_IR.value, "translation_unit": path}},
                    gaps=["secondary_only: no CodeQL call_site reports this LLVM IR call; this is missing CodeQL "
                          "coverage, not a CodeQL negative",
                          "location is the whole translation unit; IR carries no call-site location"],
                    producers=[{"name": Producer.LLVM_IR.value, "state": CrossCheckState.AGREE.value,
                                "method": METHOD_IR_NAME}])
                new_facts.append(GraphFact(identity, f"{caller_name} -> {callee_name}"[:256], payload, location))
                ambiguity = "LLVM IR call matched by name; IR carries no call-site location"
                out_relations.append(RelationRecord(RelationKind.CONTAINS, caller_id, identity.value, False, 0.5,
                                                    ambiguity, {"rule": CROSS_CHECK_RULE,
                                                                "producer": Producer.LLVM_IR.value}))
                out_relations.append(RelationRecord(RelationKind.CALLS, identity.value, callee_id, False, 0.5,
                                                    ambiguity, {"rule": CROSS_CHECK_RULE,
                                                                "producer": Producer.LLVM_IR.value}))

    # Clang AST: CallExpr nodes with a referencedDecl name, within the same translation unit.
    if inputs.clang_ast:
        nodes: dict[str, list[tuple[str, str, SecondaryShard]]] = {}
        tu_paths: set[str] = set()
        for shard in inputs.clang_ast:
            for row in shard.entities:
                payload = row.get("payload") or {}
                location = row.get("location") or {}
                if payload.get("kind") != "CallExpr" or not location.get("path"):
                    continue
                tu_paths.add(str(location["path"]))
                referenced = payload.get("referenced_decl")
                name = referenced.get("name") if isinstance(referenced, Mapping) else None
                if name:
                    nodes.setdefault(str(location["path"]), []).append((str(name), str(row["identity"]), shard))
        for path in nodes:
            nodes[path].sort(key=lambda item: item[:2])
        for fact in calls:
            _, callee = _call_parts(fact)
            path = fact.location.path if fact.location is not None else ""
            if path not in nodes:
                reason = ("Clang AST CallExpr nodes carry no referencedDecl" if path in tu_paths
                          else "no Clang AST translation unit for this path")
                verdicts[fact.identity.value][Producer.CLANG_AST] = _Verdict(
                    CrossCheckState.NOT_COVERED, METHOD_AST_NAME, reason)
                continue
            match = next((node for node in nodes[path] if node[0] in _names(callee.get("display"))), None)
            if match is None:
                verdicts[fact.identity.value][Producer.CLANG_AST] = _Verdict(
                    CrossCheckState.NOT_COVERED, METHOD_AST_NAME, "no CallExpr names this callee")
                continue
            verdicts[fact.identity.value][Producer.CLANG_AST] = _Verdict(CrossCheckState.AGREE, METHOD_AST_NAME)
            consulted[fact.identity.value].append(match[2].upstream)
            out_relations.append(RelationRecord(
                RelationKind.DERIVED_FROM, fact.identity.value, match[1], False, 0.5,
                "Clang AST CallExpr matched by referenced callee name within the same translation unit",
                {"rule": CROSS_CHECK_RULE, "producer": Producer.CLANG_AST.value, "method": METHOD_AST_NAME}))

    updated: list[GraphFact] = []
    states: dict[str, int] = {state.value: 0 for state in CrossCheckState}
    for fact in facts:
        payload = dict(fact.payload)
        producers: list[dict[str, Any]] = []
        state = CrossCheckState.NOT_COVERED
        if fact.family is Family.CALL_SITE:
            fact_verdicts = verdicts[fact.identity.value]
            state = _combine(fact_verdicts)
            for producer in sorted(fact_verdicts, key=lambda item: item.value):
                verdict = fact_verdicts[producer]
                entry: dict[str, Any] = {"name": producer.value, "state": verdict.state.value, "method": verdict.method}
                if verdict.detail:
                    entry["detail"] = verdict.detail
                producers.append(entry)
            if state is not CrossCheckState.NOT_COVERED:
                upstream = {canonical_json(item): dict(item) for item in payload.get("upstream", ())}
                upstream.update({canonical_json(item): dict(item) for item in consulted[fact.identity.value]})
                payload["upstream"] = [upstream[key] for key in sorted(upstream)]
        payload["cross_check"] = {"rule": CROSS_CHECK_RULE, "state": state.value, "producers": producers}
        payload["admissibility"] = admissibility(payload)
        states[state.value] += 1
        updated.append(replace(fact, payload=payload))
    all_facts = sorted([*updated, *new_facts], key=lambda item: item.identity.value)
    if len({item.identity.value for item in all_facts}) != len(all_facts):
        raise ValueError("cross-check produced duplicate fact identities")
    secondary_counts: dict[str, int] = {}
    for fact in new_facts:
        name = fact.payload["producer"]["name"]
        secondary_counts[name] = secondary_counts.get(name, 0) + 1
    summary = {
        "rule": CROSS_CHECK_RULE, "scope_id": scope["scope_id"], "states": states,
        "secondary_only": dict(sorted(secondary_counts.items())),
        "producers": {producer.value: [shard.upstream for shard in shards]
                      for producer, shards in ((Producer.CLANGD, inputs.clangd), (Producer.LLVM_IR, inputs.llvm_ir),
                                               (Producer.CLANG_AST, inputs.clang_ast)) if shards},
        "symbol_links": sum(1 for relation in relations if relation.kind is RelationKind.SAME_AS),
        "gaps": list(dict.fromkeys(summary_gaps)),
    }
    return CrossCheckResult(tuple(all_facts), _relations_unique(out_relations), summary)
