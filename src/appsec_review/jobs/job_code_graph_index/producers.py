"""The ``producer_neighborhood`` shard: flow graphs, analyzer diagnostics and clangd symbols of one scope.

docs/architecture/seeded-neighborhoods.md section 9 is normative. The seeded Clang AST/LLVM IR run,
the seeded Clang Static Analyzer run and the clangd symbol index each publish their own shards. This
module copies the slices a model or workflow can read through ``query_codeql_neighborhood`` into one
bounded ``graph`` shard per CodeQL scope, so a review role that is granted the scope can reach them
without being granted the producers' own indexes:

* ``flow``        one ``ir_entity`` row per LLVM IR function: blocks, edges, dominators, post-dominators, def-use,
                 and ``source_cfg`` (Clang's source-level CFG: conditions, terminators, calls) when it was replayed;
* ``diagnostics`` one ``tool_observation`` row per Clang-Tidy / Clang Static Analyzer diagnostic with its trace;
* ``symbols``     one ``symbol`` row per clangd symbol linked to a CodeQL symbol, with callers and callees;
* ``cpg``         one ``tool_observation`` row per function of the seeded Joern CPG export (calls, branches,
                 reaching-definition count). Joern is opt-in, so its absence is a named gap, never a clean result.

This is not a new fact family: every row keeps its producer's own identity and entity kind, carries
``payload.scope`` like a family fact, and the shard is published beside the ``codeql_database`` card.
Rows are bounded; every cut is a named gap. Clangd symbols never carry the raw clangd id (a hashed
USR): the native id is ``clangd:<qualified name>``, a separate identity space from CodeQL symbols, and
the link to the CodeQL symbol is an explicit ``cross_reference``.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from appsec_review.graph.contract import Producer
from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval import EntityKind, EntityRecord, LogicalIdentity, RelationKind, RelationRecord, SourceLocation

PRODUCERS_KIND = "producer_neighborhood"
PRODUCERS_SCHEMA = "appsec-review/producer-neighborhood/1"
FACTS = ("flow", "diagnostics", "symbols", "cpg")
MAX_FLOW_FUNCTIONS = 200
MAX_DIAGNOSTICS = 1000
MAX_SYMBOLS = 500
MAX_CPG_FUNCTIONS = 200
MAX_RELATED = 20            # callers or callees listed on one clangd symbol row
MAX_TRACE_STEPS = 50
MAX_ROW_GAPS = 8
_LABEL_RANK = {"at_seed": 0, "in_seed_function": 1, "in_neighborhood": 2, "unclassified": 3, "outside_neighborhood": 4}


@dataclass(slots=True)
class ProducerRows:
    entities: list[EntityRecord] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def status(self) -> str:
        """``unavailable`` without a row; otherwise ``partial`` (a neighborhood is never the whole program)."""
        return "partial" if self.entities else "unavailable"


def _tail(name: Any) -> str:
    text = str(name or "")
    if "(" in text:
        text = text[:text.index("(")]
    return text.rsplit("::", 1)[-1].rsplit(".", 1)[-1].strip()


def _names(*values: Any) -> list[str]:
    found = {str(value).strip() for value in values if str(value or "").strip()}
    found.update(_tail(value) for value in list(found))
    return sorted(name for name in found if name)


def _location(snapshot: str, value: Mapping[str, Any] | None) -> SourceLocation | None:
    if not value or value.get("path") is None:
        return None
    return SourceLocation(snapshot, str(value["path"]), str(value["file_sha256"]), int(value["start_byte"]),
                          int(value["end_byte"]), int(value["start_line"]), int(value["end_line"]),
                          int(value["start_column"]), int(value["end_column"]), {},
                          str(value["mapping_method"]), float(value["confidence"]), bool(value["ambiguous"]))


def _record(row: Mapping[str, Any], snapshot: str, payload: Mapping[str, Any], *, native_id: str | None = None,
            name: str | None = None, text: str | None = None) -> EntityRecord:
    return EntityRecord(LogicalIdentity.parse(row["identity"]), native_id if native_id is not None else row["native_id"],
                        name if name is not None else row["name"], text if text is not None else row["text"],
                        payload, _location(snapshot, row.get("location")))


def _base(scope: Mapping[str, Any], producer: Producer, fact: str) -> dict[str, Any]:
    block = {"scope_id": scope["scope_id"], "language": scope["language"], "build_unit_id": scope["build_unit_id"],
             "component_id": None}
    return {"schema": PRODUCERS_SCHEMA, "scope": block, "scope_id": scope["scope_id"], "producer": producer.value,
            "fact": fact}


def _flow_rows(shard_set: ShardSet, shards: Sequence[Mapping[str, Any]], scope: Mapping[str, Any], snapshot: str,
               out: ProducerRows) -> None:
    if not shards:
        out.gaps.append("producer_not_run: no accepted llvm-ir output covers this database; flow graphs are absent")
        return
    rows = [row for row in shard_set.entities(shards, kinds=(EntityKind.IR_ENTITY.value,))
            if isinstance(row["payload"].get("flow"), Mapping)]
    rows.sort(key=lambda row: (int(row["payload"].get("distance", 0) or 0), row["identity"]))
    if len(rows) > MAX_FLOW_FUNCTIONS:
        out.gaps.append(f"limit_reached: flow graphs are published for the {MAX_FLOW_FUNCTIONS} nearest of "
                        f"{len(rows)} LLVM IR functions")
    for row in rows[:MAX_FLOW_FUNCTIONS]:
        source = row["payload"]
        payload = {**_base(scope, Producer.LLVM_IR, "flow"), "function": row["name"],
                   "names": _names(row["name"], source.get("qualified_name")),
                   "linkage_name": source.get("linkage_name"), "compile_unit_id": source.get("compile_unit_id"),
                   "distance": source.get("distance"), "seeded": bool(source.get("seeded")),
                   "flow": source["flow"],
                   "source_cfg": source["source_cfg"] if isinstance(source.get("source_cfg"), Mapping) else None}
        out.entities.append(_record(row, snapshot, payload, text=f"flow {row['name']}"))
    out.counts["flow"] = min(len(rows), MAX_FLOW_FUNCTIONS)
    without = sum(1 for row in rows[:MAX_FLOW_FUNCTIONS] if not isinstance(row["payload"].get("source_cfg"), Mapping))
    if without:
        out.gaps.append(f"source_cfg_unavailable: {without} of {min(len(rows), MAX_FLOW_FUNCTIONS)} flow function(s) "
                        "carry no source-level CFG (not replayed, failed or overloaded); the LLVM IR flow is complete for them")
    if without < min(len(rows), MAX_FLOW_FUNCTIONS):
        out.gaps.append("source_cfg_no_block_lines: source CFG blocks are not mapped to source lines")


def _diagnostic_rows(shard_set: ShardSet, shards: Sequence[Mapping[str, Any]], scope: Mapping[str, Any],
                     snapshot: str, out: ProducerRows) -> None:
    if not shards:
        out.gaps.append("producer_not_run: no accepted clang-static output covers this database; diagnostics are absent")
        return
    rows = list(shard_set.entities(shards, kinds=(EntityKind.TOOL_OBSERVATION.value,)))
    rows = [row for row in rows if row["payload"].get("scanner") in ("clang-tidy", "clang-static-analyzer")]
    rows.sort(key=lambda row: (_LABEL_RANK.get(str((row["payload"].get("seeded") or {}).get("label")), 3),
                               row["identity"]))
    if len(rows) > MAX_DIAGNOSTICS:
        out.gaps.append(f"limit_reached: diagnostics are published for the first {MAX_DIAGNOSTICS} of {len(rows)}; "
                        "those at a seed come first")
    for row in rows[:MAX_DIAGNOSTICS]:
        source = row["payload"]
        trace = [step for step in source.get("trace") or () if isinstance(step, Mapping)]
        seeded = source.get("seeded") if isinstance(source.get("seeded"), Mapping) else {}
        payload = {**_base(scope, Producer.CLANG_STATIC, "diagnostics"), "scanner": source.get("scanner"),
                   "check": source.get("native_rule_id") or row["name"],
                   "severity": source.get("reported_severity"), "message": str(source.get("message", ""))[:1024],
                   "fix_it": bool(source.get("fix_it")),
                   "trace_length": int(source.get("trace_length", len(trace)) or 0),
                   "trace": trace[:MAX_TRACE_STEPS], "trace_truncated": len(trace) > MAX_TRACE_STEPS,
                   "function": seeded.get("function"), "label": seeded.get("label"),
                   "seeds": list(seeded.get("seeds") or ()), "outside_neighborhood": bool(seeded.get("outside_neighborhood")),
                   "evidence_id": source.get("evidence_id")}
        out.entities.append(_record(row, snapshot, payload))
    out.counts["diagnostics"] = min(len(rows), MAX_DIAGNOSTICS)


def _cpg_rows(shard_set: ShardSet, shards: Sequence[Mapping[str, Any]], scope: Mapping[str, Any], snapshot: str,
              out: ProducerRows) -> None:
    if not shards:
        out.gaps.append("producer_not_run: no accepted joern-cpg output covers this database (Joern is opt-in); "
                        "CPG facts are absent")
        return
    rows = [row for row in shard_set.entities(shards, kinds=(EntityKind.AST_NODE.value,))
            if row["payload"].get("fact") == "cpg"]
    rows.sort(key=lambda row: (str(row["payload"].get("path")), int(row["payload"].get("line") or 0), row["identity"]))
    if not rows:
        out.gaps.append("cpg_export_unavailable: the Joern CPG export published no function row for this database")
    if len(rows) > MAX_CPG_FUNCTIONS:
        out.gaps.append(f"limit_reached: CPG rows are published for {MAX_CPG_FUNCTIONS} of {len(rows)} functions")
    for row in rows[:MAX_CPG_FUNCTIONS]:
        source = row["payload"]
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {
            "producer": Producer.JOERN_CPG.value, "scope_id": scope["scope_id"], "function": source.get("full_name"),
            "path": source.get("path"), "line": source.get("line")})
        payload = {**_base(scope, Producer.JOERN_CPG, "cpg"), "function": row["name"],
                   "names": _names(row["name"], source.get("full_name")), "full_name": source.get("full_name"),
                   "signature": source.get("signature"), "path": source.get("path"), "line": source.get("line"),
                   "line_end": source.get("line_end"), "has_body": bool(source.get("has_body")),
                   "calls": list(source.get("calls") or ()), "branches": list(source.get("branches") or ()),
                   "operator_calls": source.get("operator_calls", 0),
                   "reaching_def_edges": source.get("reaching_def_edges", 0), "cut": list(source.get("cut") or ()),
                   "callee_matching": "name_only", "block_lines": "none"}
        out.entities.append(EntityRecord(identity, f"joern-cpg:{source.get('full_name')}", row["name"],
                                         f"cpg {row['name']}", payload, None))
    out.counts["cpg"] = min(len(rows), MAX_CPG_FUNCTIONS)


def _symbol_rows(shard_set: ShardSet, shards: Sequence[Mapping[str, Any]], links: Mapping[str, list[dict[str, Any]]],
                 scope: Mapping[str, Any], snapshot: str, out: ProducerRows) -> None:
    if not shards:
        out.gaps.append("producer_not_run: no accepted clangd output covers this database; clangd symbols are absent")
        return
    symbols = {row["identity"]: row for row in shard_set.entities(shards, kinds=(EntityKind.SYMBOL.value,))}
    calls: dict[str, set[str]] = {}
    callers: dict[str, set[str]] = {}
    for relation in shard_set.relations(shards, kinds=(RelationKind.CALLS.value,)):
        calls.setdefault(relation["source_id"], set()).add(relation["target_id"])
        callers.setdefault(relation["target_id"], set()).add(relation["source_id"])
    linked = sorted(identity for identity in symbols if identity in links)
    if not linked:
        out.gaps.append("symbols_unlinked: no clangd symbol is linked to a CodeQL symbol of this database")
    if len(linked) > MAX_SYMBOLS:
        out.gaps.append(f"limit_reached: clangd symbols are published for {MAX_SYMBOLS} of {len(linked)} linked symbols")

    def related(identities: set[str], which: str) -> list[dict[str, Any]]:
        items = []
        for identity in sorted(identities):
            row = symbols.get(identity)
            if row is None:
                continue
            items.append({"identity": identity, "name": str(row["name"])[:256],
                          "codeql_symbol": [link["codeql_symbol"] for link in links.get(identity, ())][:3]})
        if len(items) > MAX_RELATED:
            out.gaps.append(f"limit_reached: a clangd symbol lists {len(items)} {which}; the first {MAX_RELATED} are kept")
        return items[:MAX_RELATED]

    for identity in linked[:MAX_SYMBOLS]:
        row, source = symbols[identity], symbols[identity]["payload"]
        qualified = str(row["name"])
        payload = {**_base(scope, Producer.CLANGD, "symbols"), "identity_space": "clangd", "qualified_name": qualified,
                   "names": _names(qualified), "kind": source.get("kind"), "lang": source.get("lang"),
                   "namespace": source.get("scope"), "signature": source.get("signature"),
                   "return_type": source.get("return_type"), "reference_count": source.get("reference_count", 0),
                   "definition": source.get("definition"), "declaration": source.get("declaration"),
                   "cross_reference": links[identity][:3],
                   "callers": related(callers.get(identity, set()), "callers"),
                   "callees": related(calls.get(identity, set()), "callees")}
        out.entities.append(_record(row, snapshot, payload, native_id=f"clangd:{qualified}", name=qualified,
                                    text=f"clangd symbol {qualified}"))
    out.counts["symbols"] = min(len(linked), MAX_SYMBOLS)


def symbol_links(relations: Sequence[RelationRecord]) -> dict[str, list[dict[str, Any]]]:
    """clangd symbol identity -> its ``SAME_AS`` links to CodeQL symbols (the cross-reference between identity spaces)."""
    found: dict[str, list[dict[str, Any]]] = {}
    for relation in sorted(relations, key=lambda item: item.relation_id):
        if relation.kind is RelationKind.SAME_AS:
            found.setdefault(relation.target_id, []).append({
                "codeql_symbol": relation.source_id, "exact": bool(relation.exact),
                "method": (relation.payload or {}).get("method")})
    return found


def build(run_root: Path, *, scope: Mapping[str, Any], snapshot: str,
          relations: Sequence[RelationRecord]) -> ProducerRows:
    """The bounded producer rows of one scope, read from its accepted secondary and analyzer shards only."""
    inputs = scope.get("inputs") or {}
    secondary, analyzers = inputs.get("secondary") or {}, inputs.get("analyzers") or {}
    out = ProducerRows()
    shards = [*secondary.get(Producer.LLVM_IR.value, ()), *secondary.get(Producer.CLANGD.value, ()),
              *analyzers.get(Producer.CLANG_STATIC.value, ()), *analyzers.get(Producer.JOERN_CPG.value, ())]
    shard_set = ShardSet(run_root, shards)
    _flow_rows(shard_set, secondary.get(Producer.LLVM_IR.value, ()), scope, snapshot, out)
    _diagnostic_rows(shard_set, analyzers.get(Producer.CLANG_STATIC.value, ()), scope, snapshot, out)
    _symbol_rows(shard_set, secondary.get(Producer.CLANGD.value, ()), symbol_links(relations), scope, snapshot, out)
    _cpg_rows(shard_set, analyzers.get(Producer.JOERN_CPG.value, ()), scope, snapshot, out)
    for name in ("llvm-ir", "clang-static", "joern-cpg"):
        out.gaps.extend(f"{name}: {gap}" for table in (secondary, analyzers) for shard in table.get(name, ())
                        for gap in ((shard.get("producer") or {}).get("seeded") or {}).get("gaps", ())[:3])
    out.gaps = list(dict.fromkeys(gap[:300] for gap in out.gaps))[:MAX_ROW_GAPS * 3]
    return out
