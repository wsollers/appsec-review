"""CodeQL graph-export normalizer, rule ``graph-normalize/2`` (code-graph chunk C3).

docs/architecture/code-graph-precomputation.md sections 3, 4 and 10 (C3) are normative. Pure
functions: one CodeQL scope's verified raw exports (``appsec-review/codeql-graph-export/1`` objects,
as ``codeql.runtime.load_graph_exports`` returns them), the scope block, the accepted source bytes and
the catalog become contract :class:`GraphFact` values, CodeQL-export ``symbol`` entities, relations
and one coverage row per family. Nothing here runs an analyzer or reads a target tree.

Public API (``job_code_graph_index`` calls it once per scope)::

    normalize_scope(exports, *, scope, target_snapshot, sources, catalog, settings,
                    tool_version, export_pack_sha256, upstream=()) -> NormalizedScope

* ``exports``: ``{query_id: export object}`` for the scope (missing query ids make the families that
  need them ``unavailable``; an empty mapping is a scope whose export failed).
* ``scope``: ``scope_id``, ``language``, ``build_unit_id``, optional ``component_id``, ``root`` (the
  CodeQL scope root, default ``"."``) and ``files`` (``[{path, sha256}]``, the files the database was
  built from; defaults to ``sources``). Export paths are resolved with the same prefix rules as
  ``jobs/job_codeql_analysis/sarif.py::map_location`` (reused, not copied); only a unique
  confidence-1.0 mapping onto an accepted source is exact.
* ``sources``: ``{target-relative path: crosscheck.SourceFile}`` of the accepted snapshot. A scope file
  whose hash differs from the accepted bytes raises :class:`appsec_review.review.models.IntegrityError`.
* ``catalog``: :func:`appsec_review.graph.catalog.load_catalog`; ``settings``: ``GraphSettings``.
* ``tool_version``/``export_pack_sha256`` fill the payload ``producer`` block; ``upstream`` entries
  (``{index, shard_id, sha256}``) are added to every fact's ``upstream`` next to the per-query export
  entries ``{"index": "codeql-graph-export", "shard_id": "<scope_id>:<query_id>", "sha256": bqrs_sha256}``.

Locations: exports carry 1-based lines and columns with an inclusive end column and no byte
offsets. Offsets are derived from the accepted bytes through ``crosscheck.SourceFile.offset`` (UTF-16
columns, the SARIF/LSP convention correlation uses) and published as ``SourceLocation`` with an
exclusive ``end_byte`` and exclusive ``end_column``. A location that cannot be mapped exactly is
published ``ambiguous`` with a named reason (``line_only_location``, ``macro_expansion_site``,
``symbol_name_mismatch``); a fact with any inexact embedded location is ``exact=false`` (for paths
the gap is ``ambiguous_step_location``). Rows whose own location does not resolve to an accepted file
are not published and are counted as the family gap ``unmapped_location``.

Guard operands: a comparison guard publishes ``comparison.operands`` (role, closed syntactic kind, integer value,
text, location) and ``destination.object_bytes``. The operand text is sliced here from the accepted source bytes at
the exported operand location (bounded to 200 characters), never taken from the export; both are facts, and no
guard-to-sink relation is classified.

Symbols: one ``symbol`` entity per exported function (producer ``codeql-export``) located at the
defining-name span (``Function.getLocation()`` start plus the unqualified name), the span clangd's
``SAME_AS`` link compares. Payload ``result`` fields that name functions carry these identities.

Relations: ``CONTAINS`` (function symbol → call_site/sink_site/entry_point), ``CALLS`` (call_site →
callee symbol), ``GUARDS`` (guard_fact → sink_site), ``DERIVED_FROM`` (range_fact → sink_site,
flow_summary → symbol), ``FLOWS_TO`` (entry_point → sink_site, payload ``path_id`` = the shortest
kept path and ``path_ids``). Every ``cross_check`` starts ``not_covered`` (C4 updates it).
:meth:`NormalizedScope.shards` partitions the output into one ``(scope, family)`` shard each, with the
symbols in the ``call_site`` shard.

Output is sorted by identity and byte-identical across runs and shuffled input rows.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from appsec_review.graph.catalog import (
    RULES_ROOT,
    Catalog,
    Classification,
    LanguageCatalog,
)
from appsec_review.graph.contract import (
    AUTHORITY,
    CROSS_CHECK_RULE,
    GRAPH_FACT_SCHEMA,
    GUARD_OPERAND_ROLES,
    GUARD_OPERAND_TEXT_LIMIT,
    NORMALIZE_RULE,
    Coverage,
    CrossCheckState,
    Dispatch,
    Family,
    GraphFact,
    GraphSettings,
    GuardOperandKind,
    GuardPolarity,
    GuardState,
    Producer,
    SinkClass,
    SourceClass,
    admissibility,
    fact_identity,
    none_guard_native,
    validate_payload,
)
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.jobs.job_codeql_analysis.sarif import map_location
from appsec_review.retrieval.model import (
    EntityKind,
    EntityRecord,
    LogicalIdentity,
    RelationKind,
    RelationRecord,
    SourceLocation,
    canonical_json,
)
from appsec_review.review.models import IntegrityError

COLUMNS_PATH = RULES_ROOT / "columns.json"
EXPORT_UPSTREAM_INDEX = "codeql-graph-export"
METHOD_EXACT = "codeql-location-exact"
METHOD_LINE_ONLY = "codeql-line-only"
METHOD_MACRO = "codeql-macro-expansion-site"
METHOD_NAME_SCAN = "codeql-name-scan"
ANALYSIS_RANGES = "codeql-simple-range-analysis"
SELECTION = "shortest-k"
MAX_ENUMERATED_PATHS_PER_FLOW = 4096

FAMILY_QUERIES: Mapping[Family, tuple[str, ...]] = {
    Family.CALL_SITE: ("call_sites",),
    Family.SINK_SITE: ("sink_sites",),
    Family.ENTRY_POINT: ("source_sites",),
    Family.FLOW_SUMMARY: ("flow_summaries", "call_sites"),
    Family.DATAFLOW_PATH: ("path_flows", "path_edges", "path_sanitizers", "sink_sites", "source_sites", "guards"),
    Family.GUARD_FACT: ("guards", "sink_sites"),
    Family.RANGE_FACT: ("ranges", "range_conversions", "sink_sites"),
}
# Queries without which the family cannot be built at all (the rest only lose a detail, as a gap).
FAMILY_REQUIRED: Mapping[Family, tuple[str, ...]] = {
    Family.CALL_SITE: ("call_sites",),
    Family.SINK_SITE: ("sink_sites",),
    Family.ENTRY_POINT: ("source_sites",),
    Family.FLOW_SUMMARY: ("flow_summaries",),
    Family.DATAFLOW_PATH: ("path_flows", "path_edges", "sink_sites", "source_sites"),
    Family.GUARD_FACT: ("guards", "sink_sites"),
    Family.RANGE_FACT: ("ranges", "sink_sites"),
}
_GUARD_RANK = {state.value: rank for rank, state in enumerate(GuardState)}
# Least protective first: a collision between two states for one condition keeps the weaker claim.
_GUARD_CONSERVATIVE = {GuardState.NONE.value: 0, GuardState.NON_DOMINATING.value: 1,
                       GuardState.POST_DOMINATING_ONLY.value: 2, GuardState.DOMINATING.value: 3}

_INTEGER = re.compile(r"-?[0-9]+")
Key5 = tuple[str, int, int, int, int]
Key6 = tuple[str, int, int, int, int, int]


def _load_columns(path: Path = COLUMNS_PATH) -> dict[str, dict[str, tuple[str, ...]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return {language: {query["query_id"]: tuple(column["name"] for column in query["columns"])
                       for query in section["queries"]}
            for language, section in document["languages"].items()}


_COLUMNS: dict[str, dict[str, tuple[str, ...]]] | None = None


def export_columns(language: str) -> Mapping[str, tuple[str, ...]]:
    """The ordered column contract per ``query_id`` from ``rules/codeql-graph-export/columns.json``."""
    global _COLUMNS
    if _COLUMNS is None:
        _COLUMNS = _load_columns()
    return _COLUMNS[language]


@dataclass(frozen=True, slots=True)
class CoverageRow:
    """One ``graph:<scope_id>:<family>`` coverage row (section 7.4)."""

    scope_id: str
    family: Family
    status: Coverage
    gaps: tuple[str, ...] = ()
    facts: int = 0
    counts: Mapping[str, int] = field(default_factory=dict)

    @property
    def area(self) -> str:
        return f"graph:{self.scope_id}:{self.family.value}"

    @property
    def gap(self) -> str | None:
        return "; ".join(self.gaps)[:4096] or None

    def as_dict(self) -> dict[str, Any]:
        return {"area": self.area, "family": self.family.value, "status": self.status.value,
                "gaps": list(self.gaps), "facts": self.facts, "counts": dict(sorted(self.counts.items()))}


@dataclass(frozen=True, slots=True)
class FamilyShard:
    family: Family
    entities: tuple[EntityRecord, ...]
    relations: tuple[RelationRecord, ...]
    coverage: CoverageRow


@dataclass(frozen=True, slots=True)
class NormalizedScope:
    scope_id: str
    facts: tuple[GraphFact, ...]
    symbols: tuple[EntityRecord, ...]
    relations: tuple[RelationRecord, ...]
    coverage: tuple[CoverageRow, ...]

    def coverage_for(self, family: Family | str) -> CoverageRow:
        family = Family(family)
        return next(row for row in self.coverage if row.family is family)

    def shards(self) -> tuple[FamilyShard, ...]:
        """One shard per family; symbols ride in ``call_site``, each relation with its fact endpoint."""
        family_of = {fact.identity.value: fact.family for fact in self.facts}
        relations: dict[Family, list[RelationRecord]] = defaultdict(list)
        for relation in self.relations:
            family = family_of.get(relation.source_id) or family_of.get(relation.target_id)
            if family is not None:
                relations[family].append(relation)
        out = []
        for family in Family:
            entities = [fact.to_entity() for fact in self.facts if fact.family is family]
            if family is Family.CALL_SITE:
                entities.extend(self.symbols)
            out.append(FamilyShard(family, tuple(sorted(entities, key=lambda item: item.identity.value)),
                                   tuple(sorted(relations[family], key=lambda item: item.relation_id)),
                                   self.coverage_for(family)))
        return tuple(out)

    def to_document(self) -> dict[str, Any]:
        """Canonical JSON-ready view (golden fixtures, determinism checks)."""
        def location(value: SourceLocation | None) -> dict[str, Any] | None:
            return asdict(value) if value is not None else None
        return {
            "rule": NORMALIZE_RULE, "scope_id": self.scope_id,
            "facts": [{"identity": fact.identity.value, "name": fact.name, "payload": fact.payload,
                       "location": location(fact.location)} for fact in self.facts],
            "symbols": [{"identity": item.identity.value, "native_id": item.native_id, "name": item.name,
                         "text": item.text, "payload": item.payload, "location": location(item.location)}
                        for item in self.symbols],
            "relations": [{"relation_id": item.relation_id, "kind": item.kind.value, "source_id": item.source_id,
                           "target_id": item.target_id, "exact": item.exact, "confidence": item.confidence,
                           "ambiguity": item.ambiguity, "payload": item.payload} for item in self.relations],
            "coverage": [row.as_dict() for row in self.coverage],
        }

    def to_json(self) -> bytes:
        return json.dumps(self.to_document(), sort_keys=True, indent=1, ensure_ascii=False).encode() + b"\n"


# --------------------------------------------------------------------------- locations


@dataclass(frozen=True, slots=True)
class _Mapped:
    location: SourceLocation | None
    reason: str | None = None

    @property
    def exact(self) -> bool:
        return self.location is not None and self.reason is None and not self.location.ambiguous


def _api_tail(name: str) -> str:
    """The last `::` segment of a qualified callee name (`std::fs::canonicalize` -> `canonicalize`)."""
    return name.split("(", 1)[0].rsplit("::", 1)[-1].strip()


def _location_dict(mapped: _Mapped | None) -> dict[str, Any] | None:
    """An embedded ``SourceLocation`` (steps, conditions, operands); export coordinates stay on the fact."""
    if mapped is None or mapped.location is None:
        return None
    value = asdict(mapped.location)
    value["producer_location"] = {}
    return value


class _Locator:
    """Export path/line/column → accepted ``SourceLocation`` with exclusive ends."""

    def __init__(self, snapshot: str, scope: Mapping[str, Any], sources: Mapping[str, SourceFile]):
        self.snapshot, self.sources = snapshot, sources
        self.root = str(scope.get("root") or ".")
        files = scope.get("files")
        if files is None:
            files = [{"path": path, "sha256": source.sha256} for path, source in sorted(sources.items())]
        self.files = [{"path": str(item["path"]), "sha256": str(item["sha256"])} for item in files]
        for item in self.files:
            source = sources.get(item["path"])
            if source is not None and source.sha256 != item["sha256"]:
                raise IntegrityError(f"CodeQL scope file {item['path']} hash differs from the accepted snapshot")
        self._paths: dict[str, str | None] = {}
        self._spans: dict[tuple[Any, ...], _Mapped] = {}

    def path(self, raw: str) -> str | None:
        if raw not in self._paths:
            resolved = None
            if raw:
                mapped = map_location({"artifactLocation": {"uri": raw}, "region": {"startLine": 1}},
                                      files=self.files, root=self.root)
                if mapped.path is not None and mapped.confidence == 1.0 and not mapped.ambiguous:
                    resolved = mapped.path if mapped.path in self.sources else None
            self._paths[raw] = resolved
        return self._paths[raw]

    def _producer(self, raw: str, start_line: int, start_column: int, end_line: int, end_column: int) -> dict[str, Any]:
        return {"producer": Producer.CODEQL_EXPORT.value, "export_path": raw, "start_line": start_line,
                "start_column": start_column, "end_line": end_line, "end_column_inclusive": end_column}

    def _line_span(self, path: str, raw: str, start_line: int, end_line: int, start_column: int,
                   end_column: int, reason: str) -> _Mapped:
        source = self.sources[path]
        starts = source.line_starts
        end_line = end_line if start_line <= end_line <= len(starts) else start_line
        start = starts[start_line - 1]
        end = starts[end_line] - 1 if end_line < len(starts) else source.size
        return _Mapped(SourceLocation(self.snapshot, path, source.sha256, start, max(start, end), start_line, end_line,
                                      1, 1, self._producer(raw, start_line, start_column, end_line, end_column),
                                      METHOD_LINE_ONLY, 0.5, True), reason)

    def span(self, key: Key5) -> _Mapped:
        if key not in self._spans:
            self._spans[key] = self._span(*key)
        return self._spans[key]

    def _span(self, raw: str, start_line: int, start_column: int, end_line: int, end_column: int) -> _Mapped:
        path = self.path(raw)
        if path is None:
            return _Mapped(None, "unmapped_location")
        source = self.sources[path]
        if not isinstance(start_line, int) or not 1 <= start_line <= source.line_count:
            return _Mapped(None, "unmapped_location")
        start = source.offset(start_line, start_column) if start_column >= 1 else None
        end = (source.offset(end_line, end_column + 1)
               if end_column >= 1 and end_line >= start_line else None)
        if start is None or end is None or end < start:
            return self._line_span(path, raw, start_line, end_line, start_column, end_column, "line_only_location")
        return _Mapped(SourceLocation(self.snapshot, path, source.sha256, start, end, start_line, end_line,
                                      start_column, end_column + 1,
                                      self._producer(raw, start_line, start_column, end_line, end_column),
                                      METHOD_EXACT, 1.0, False))

    def name_span(self, raw: str, line: int, column: int, name: str) -> _Mapped:
        """The defining-name span of a function whose ``getLocation()`` starts at ``line``/``column``."""
        key = ("name", raw, line, column, name)
        if key in self._spans:
            return self._spans[key]
        path = self.path(raw)
        if path is None or not isinstance(line, int) or line < 1 or line > self.sources[path].line_count:
            mapped = _Mapped(None, "unmapped_location")
        else:
            source = self.sources[path]
            start = source.offset(line, column) if column >= 1 else None
            if start is None:
                mapped = self._line_span(path, raw, line, line, column, column, "line_only_location")
            else:
                tail = name.split("(", 1)[0].rsplit("::", 1)[-1].strip()
                found = next((candidate for candidate in (tail, name, tail.rsplit(".", 1)[-1]) if candidate
                              and source.data.startswith(candidate.encode("utf-8"), start)), None)
                reason = None if found else "symbol_name_mismatch"
                if found is None:
                    end = start
                    while end < source.size and (chr(source.data[end]).isalnum() or source.data[end] in b"_~"):
                        end += 1
                    found = source.data[start:end].decode("utf-8", errors="replace")
                width = len(found.encode("utf-16-le")) // 2
                end_byte = start + len(found.encode("utf-8"))
                mapped = _Mapped(SourceLocation(
                    self.snapshot, path, source.sha256, start, end_byte, line, line, column, column + max(width, 0),
                    {"producer": Producer.CODEQL_EXPORT.value, "export_path": raw, "start_line": line,
                     "start_column": column, "name": name},
                    METHOD_EXACT if reason is None else METHOD_NAME_SCAN, 1.0 if reason is None else 0.5,
                    reason is not None), reason)
        self._spans[key] = mapped
        return mapped


def _macro(mapped: _Mapped) -> _Mapped:
    """A condition inside a macro expansion maps to the expansion site, never exactly."""
    if mapped.location is None:
        return mapped
    return _Mapped(replace(mapped.location, mapping_method=METHOD_MACRO, confidence=0.5, ambiguous=True),
                   "macro_expansion_site")


def _bool(value: Any) -> bool | str:
    return True if value == "true" else False if value == "false" else "unknown"


def _bound(value: Any) -> int | float | str:
    text = str(value or "").strip()
    if not text or text == "unknown":
        return "unknown"
    try:
        number = float(text)
    except ValueError:
        return text
    return int(number) if number.is_integer() else number


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


# --------------------------------------------------------------------------- normalizer


class _Normalizer:
    def __init__(self, exports: Mapping[str, Mapping[str, Any]], *, scope: Mapping[str, Any], target_snapshot: str,
                 sources: Mapping[str, SourceFile], catalog: Catalog, settings: GraphSettings, tool_version: str,
                 export_pack_sha256: str, upstream: Sequence[Mapping[str, Any]]):
        self.scope_id = str(scope.get("scope_id") or "")
        if not self.scope_id:
            raise ValueError("graph normalization requires a scope_id")
        self.snapshot, self.settings = target_snapshot, settings
        self.language: LanguageCatalog = catalog.language(str(scope.get("language") or ""))
        self.catalog = catalog
        self.scope_block = {"scope_id": self.scope_id, "language": scope.get("language"),
                            "build_unit_id": scope.get("build_unit_id"), "component_id": scope.get("component_id")}
        self.producer = {"name": Producer.CODEQL_EXPORT.value, "tool_version": str(tool_version),
                         "export_pack_sha256": str(export_pack_sha256), "catalog_version": catalog.version,
                         "rule_version": NORMALIZE_RULE}
        self.extra_upstream = [{"index": str(item["index"]), "shard_id": str(item["shard_id"]),
                                "sha256": str(item["sha256"])} for item in upstream]
        self.locator = _Locator(target_snapshot, scope, sources)
        columns = export_columns(self.language.language)
        self.exports: dict[str, Mapping[str, Any]] = {}
        self.rows: dict[str, list[dict[str, Any]]] = {}
        for query_id, document in exports.items():
            expected = columns.get(query_id)
            if expected is None or tuple(document.get("columns") or ()) != expected:
                raise IntegrityError(f"graph export {query_id} columns differ from columns.json")
            self.exports[query_id] = document
            rows = sorted((list(row) for row in document["rows"]), key=lambda row: tuple(str(value) for value in row))
            self.rows[query_id] = [dict(zip(expected, row)) for row in rows]
        self.gaps: dict[Family, list[str]] = defaultdict(list)
        self.partial: dict[Family, bool] = defaultdict(bool)
        self.counts: dict[Family, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.facts: dict[Family, dict[str, GraphFact]] = {family: {} for family in Family}
        self.relations: list[RelationRecord] = []
        self.symbols: dict[tuple[str, str, int, int], EntityRecord] = {}
        self.symbol_names: dict[str, set[str]] = defaultdict(set)
        self.sinks: dict[Key6, GraphFact] = {}
        self.entries: dict[Key5, GraphFact] = {}
        self.guards_by_sink: dict[str, list[str]] = defaultdict(list)

    # -- helpers ------------------------------------------------------------------------------
    def available(self, family: Family) -> bool:
        return all(query in self.exports for query in FAMILY_REQUIRED[family])

    def family_gap(self, family: Family, gap: str, *, partial: bool = True) -> None:
        self.gaps[family].append(gap)
        if partial:
            self.partial[family] = True

    def upstream(self, family: Family) -> list[dict[str, str]]:
        values = {canonical_json(item): item for item in self.extra_upstream}
        for query_id in FAMILY_QUERIES[family]:
            document = self.exports.get(query_id)
            if document is not None:
                item = {"index": EXPORT_UPSTREAM_INDEX, "shard_id": f"{self.scope_id}:{query_id}",
                        "sha256": str(document["bqrs_sha256"])}
                values[canonical_json(item)] = item
        return [values[key] for key in sorted(values)]

    def fact(self, family: Family, native: Mapping[str, Any], name: str, result: Mapping[str, Any],
             mapped: _Mapped, *, exact: bool, gaps: Sequence[str] = (), complete: bool = True) -> GraphFact:
        identity = fact_identity(family, self.snapshot, native)
        exact = bool(exact and mapped.exact)
        payload: dict[str, Any] = {
            "schema": GRAPH_FACT_SCHEMA, "family": family.value, "producer": dict(self.producer),
            "scope": dict(self.scope_block), "exact": exact,
            "coverage_status": Coverage.COMPLETE.value if complete else Coverage.PARTIAL.value,
            "gaps": list(dict.fromkeys(gaps)),
            "cross_check": {"rule": CROSS_CHECK_RULE, "state": CrossCheckState.NOT_COVERED.value, "producers": []},
            "result": dict(result), "upstream": self.upstream(family), "authority": AUTHORITY,
        }
        payload["admissibility"] = admissibility(payload)
        validate_payload(payload)
        return GraphFact(identity, name[:256], payload, mapped.location)

    def add(self, fact: GraphFact) -> bool:
        bucket = self.facts[fact.family]
        if fact.identity.value in bucket:
            self.family_gap(fact.family, f"duplicate_identity: {fact.name} collides with an earlier "
                                         f"{fact.family.value} fact and was not published")
            return False
        bucket[fact.identity.value] = fact
        return True

    def relation(self, kind: RelationKind, source: str, target: str, **payload: Any) -> None:
        self.relations.append(RelationRecord(kind, source, target, True, 1.0, None,
                                             {"rule": NORMALIZE_RULE, **payload}))

    def symbol(self, name: str, raw_path: str, line: int, column: int) -> str | None:
        """The CodeQL-export ``symbol`` identity of a function, created on first use."""
        if not name or not raw_path or not isinstance(line, int) or line < 1:
            return None
        key = (name, raw_path, line, column)
        record = self.symbols.get(key)
        if record is None:
            identity = LogicalIdentity.derive(EntityKind.SYMBOL, self.snapshot, {
                "producer": Producer.CODEQL_EXPORT.value, "scope_id": self.scope_id, "qualified_name": name,
                "export_path": raw_path, "line": line, "column": column})
            mapped = self.locator.name_span(raw_path, line, column, name)
            gaps = [f"{mapped.reason}: the function name does not resolve exactly at {raw_path}:{line}:{column}"] \
                if mapped.reason else []
            record = EntityRecord(identity, name, name, f"function {name}", {
                "producer": Producer.CODEQL_EXPORT.value, "rule_version": NORMALIZE_RULE,
                "scope": dict(self.scope_block), "kind": "function", "qualified_name": name, "exact": mapped.exact,
                "mapping_method": mapped.location.mapping_method if mapped.location else None, "gaps": gaps,
            }, mapped.location)
            self.symbols[key] = record
            self.symbol_names[name].add(identity.value)
        return record.identity.value

    def symbol_by_name(self, name: str) -> str | None:
        found = self.symbol_names.get(name, set())
        return next(iter(found)) if len(found) == 1 else None

    @staticmethod
    def key5(row: Mapping[str, Any], prefix: str) -> Key5:
        return (str(row[f"{prefix}_path"]), int(row[f"{prefix}_start_line"]), int(row[f"{prefix}_start_column"]),
                int(row[f"{prefix}_end_line"]), int(row[f"{prefix}_end_column"]))

    def key6(self, row: Mapping[str, Any]) -> Key6:
        return (*self.key5(row, "sink"), int(row["argument_index"]))

    def unmapped(self, family: Family, what: str, key: Key5) -> None:
        self.counts[family]["unmapped_rows"] += 1
        self.family_gap(family, f"unmapped_location: {what} at {key[0] or '<outside source root>'}:{key[1]} does "
                                "not resolve to an accepted source and was not published")

    def truncated_exports(self, family: Family) -> None:
        for query_id in FAMILY_QUERIES[family]:
            document = self.exports.get(query_id)
            if document is not None and document["truncated"]:
                self.family_gap(family, f"export_truncated: {query_id} exported {len(document['rows'])} of "
                                        f"{document['row_count']} rows")

    # -- families -----------------------------------------------------------------------------
    def build_sinks(self) -> None:
        family = Family.SINK_SITE
        groups: dict[Key6, list[tuple[Classification, dict[str, Any]]]] = defaultdict(list)
        for row in self.rows["sink_sites"]:
            groups[self.key6(row)].append((self.language.classify_sink(row), row))
        for key in sorted(groups):
            items = groups[key]
            classification, row = min(items, key=lambda item: (item[0].rank, tuple(str(v) for v in item[1].values())))
            mapped = self.locator.span(key[:5])
            if mapped.location is None:
                self.unmapped(family, "sink", key[:5])
                continue
            operand = self.locator.span(self.key5(row, "operand"))
            function = self.symbol(row["function_name"], row["function_path"], row["function_start_line"],
                                   row["function_start_column"])
            gaps = []
            if mapped.reason:
                gaps.append(f"{mapped.reason}: sink expression location is not exact")
            if not operand.exact:
                gaps.append(f"{operand.reason or 'unmapped_location'}: sink operand location is not exact")
            if not classification.classified:
                self.counts[family]["unclassified"] += 1
                gaps.append(f"unclassified_sink: no catalog rule classifies model {row['model']!r}"
                            + (f" api {row['api']!r}" if row["api"] else ""))
            location = mapped.location
            native = {"scope_id": self.scope_id, "path": location.path, "start_byte": location.start_byte,
                      "end_byte": location.end_byte, "sink_class": classification.klass,
                      "argument_index": key[5]}
            result = {
                "sink_class": classification.klass, "cwe_family": classification.cwe_family,
                "api": {"display": row["api"] or row["sink_display"], "declared_in": row["declared_in"] or None},
                "argument_index": key[5], "display": row["sink_display"],
                "operand": {"location": _location_dict(operand), "exact": operand.exact},
                "enclosing_function": {"symbol": function, "display": row["function_name"]},
                "dominating_sanitizer_count": int(row["dominating_sanitizer_count"]),
                "catalog_rule": classification.rule_id, "model": row["model"],
                "models": sorted({str(item[1]["model"]) for item in items}),
            }
            name = f"{row['api'] or row['sink_display']} [{classification.klass}]"
            fact = self.fact(family, native, name, result, mapped, exact=operand.exact, gaps=gaps)
            if self.add(fact):
                self.sinks[key] = fact
                if function:
                    self.relation(RelationKind.CONTAINS, function, fact.identity.value)
        if self.counts[family]["unclassified"]:
            self.family_gap(family, f"unclassified_sink: {self.counts[family]['unclassified']} sinks the catalog "
                                    f"{self.catalog.version} does not classify are published ineligible")

    def build_entries(self) -> None:
        family = Family.ENTRY_POINT
        groups: dict[Key5, list[tuple[Classification, dict[str, Any]]]] = defaultdict(list)
        for row in self.rows["source_sites"]:
            groups[self.key5(row, "source")].append((self.language.classify_source(row), row))
        for key in sorted(groups):
            items = groups[key]
            classification, row = min(items, key=lambda item: (item[0].rank, tuple(str(v) for v in item[1].values())))
            mapped = self.locator.span(key)
            if mapped.location is None:
                self.unmapped(family, "source", key)
                continue
            function = self.symbol(row["function_name"], row["function_path"], row["function_start_line"],
                                   row["function_start_column"])
            gaps = [f"{mapped.reason}: source location is not exact"] if mapped.reason else []
            if not classification.classified:
                self.counts[family]["unclassified"] += 1
                gaps.append(f"unclassified_source: no catalog rule classifies model {row['model']!r}"
                            + (f" source_type {row['source_type']!r}" if row["source_type"] else "")
                            + (f" api {row['api']!r}" if row["api"] else ""))
            location = mapped.location
            native = {"scope_id": self.scope_id, "path": location.path, "start_byte": location.start_byte,
                      "end_byte": location.end_byte, "source_class": classification.klass}
            result = {
                "source_class": classification.klass,
                "api_or_parameter": {"display": row["source_display"], "node_kind": row["node_kind"],
                                     "api": row["api"] or None, "index": int(row["index"])},
                "enclosing_function": {"symbol": function, "display": row["function_name"]},
                "exposure": {"basis": classification.basis, "contract_id": None},
                "catalog_rule": classification.rule_id, "model": row["model"],
                "source_type": row["source_type"] or None,
            }
            fact = self.fact(family, native, f"{row['source_display']} [{classification.klass}]", result, mapped,
                             exact=True, gaps=gaps)
            if self.add(fact):
                self.entries[key] = fact
                if function:
                    self.relation(RelationKind.CONTAINS, function, fact.identity.value)
        if self.counts[family]["unclassified"]:
            self.family_gap(family, f"unclassified_source: {self.counts[family]['unclassified']} sources the "
                                    f"catalog {self.catalog.version} does not classify are published ineligible")
        self.family_gap(family, f"source_model_coverage: {self.language.model_library} as bundled with CodeQL "
                                f"{self.producer['tool_version']}; frameworks without models yield no entry points",
                        partial=False)

    @staticmethod
    def guard_vocabulary_error(row: Mapping[str, Any]) -> str | None:
        """The first closed-vocabulary or integer violation of a guard row's operand and object-size columns."""
        for role in GUARD_OPERAND_ROLES:
            if row[f"{role}_kind"] not in {kind.value for kind in GuardOperandKind}:
                return f"{role}_kind {row[f'{role}_kind']!r}"
            if not _INTEGER.fullmatch(str(row[f"{role}_value"])) and row[f"{role}_value"] != "":
                return f"{role}_value {row[f'{role}_value']!r}"
        if not isinstance(row["destination_object_bytes"], int) or row["destination_object_bytes"] < -1:
            return f"destination_object_bytes {row['destination_object_bytes']!r}"
        return None

    def guard_operands(self, row: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
        """The ``lhs`` and ``rhs`` operands of a comparison row and the gaps of their text.

        The text is sliced from the accepted source bytes at the operand location, so it is exact and
        bound to the accepted file hash; it is never taken from the export. It is ``None`` (with a named
        gap) when the location does not resolve exactly, or when a macro operand is reported at the whole
        expansion site, where the bytes are the macro call and not the operand.
        """
        operands: list[dict[str, Any]] = []
        gaps: list[str] = []
        condition = self.key5(row, "condition")
        for role in GUARD_OPERAND_ROLES:
            key = self.key5(row, role)
            mapped = self.locator.span(key) if key[0] else _Mapped(None, "unmapped_location")
            text: str | None = None
            if mapped.location is None:
                gaps.append(f"operand_text_unavailable: {role} operand location does not resolve to an accepted "
                            "source")
            elif not mapped.exact:
                gaps.append(f"operand_text_unavailable: {role} operand location is not exact ({mapped.reason})")
            elif row["in_macro"] == "true" and key == condition:
                gaps.append(f"operand_text_unavailable: {role} operand is reported at the macro expansion site")
            else:
                data = self.locator.sources[mapped.location.path].data
                text = data[mapped.location.start_byte:mapped.location.end_byte].decode("utf-8", errors="replace")
                if len(text) > GUARD_OPERAND_TEXT_LIMIT:
                    text = text[:GUARD_OPERAND_TEXT_LIMIT]
                    gaps.append(f"operand_text_truncated: {role} operand text is cut at "
                                f"{GUARD_OPERAND_TEXT_LIMIT} characters")
            value = row[f"{role}_value"]
            operands.append({"role": role, "kind": row[f"{role}_kind"], "value": int(value) if value != "" else None,
                             "text": text, "location": _location_dict(mapped)})
        return operands, gaps

    def build_guards(self) -> None:
        family = Family.GUARD_FACT
        per_sink: dict[str, list[GraphFact]] = defaultdict(list)
        for row in self.rows["guards"]:
            key = self.key6(row)
            sink = self.sinks.get(key)
            if sink is None:
                self.counts[family]["unattached_rows"] += 1
                self.family_gap(family, f"unattached_guard: guard row for sink {key[0]}:{key[1]} has no published "
                                        "sink_site")
                continue
            state = str(row["guard_state"])
            if state not in _GUARD_RANK:
                self.family_gap(family, f"unknown_guard_state: {state!r} at {key[0]}:{key[1]} was not published")
                continue
            vocabulary = self.guard_vocabulary_error(row)
            if vocabulary:
                self.family_gap(family, f"unknown_guard_vocabulary: {vocabulary} at {key[0]}:{key[1]} was not "
                                        "published")
                continue
            polarity = str(row["polarity"]) if row["polarity"] in {item.value for item in GuardPolarity} \
                else GuardPolarity.UNKNOWN.value
            sink_location = sink.location
            assert sink_location is not None
            gaps: list[str] = []
            if state == GuardState.NONE.value:
                native = none_guard_native(self.scope_id, sink.identity.value, sink_location.path,
                                           sink_location.start_byte, sink_location.end_byte)
                mapped = _Mapped(sink_location, None if sink.payload["exact"] else "inexact_sink_location")
                condition = None
                exact = sink.payload["exact"]
            else:
                mapped = self.locator.span(self.key5(row, "condition"))
                if mapped.location is None:
                    self.unmapped(family, "guard condition", self.key5(row, "condition"))
                    continue
                if row["in_macro"] == "true":
                    mapped = _macro(mapped)
                if mapped.reason:
                    gaps.append(f"{mapped.reason}: condition location is not exact")
                location = mapped.location
                native = {"scope_id": self.scope_id, "sink_identity": sink.identity.value,
                          "condition_path": location.path, "condition_start_byte": location.start_byte,
                          "condition_end_byte": location.end_byte}
                condition = {"display": row["condition_display"], "location": _location_dict(mapped),
                             "in_macro": row["in_macro"] == "true"}
                exact = True
            if state == GuardState.POST_DOMINATING_ONLY.value:
                gaps.append("post_dominating_only: the check follows the sink; it is never a present dominating guard")
            constrains = _bool(row["constrains_sink_operand"])
            if constrains == "unknown":
                gaps.append("constrains_sink_operand_unknown: CodeQL local flow cannot connect the condition to the "
                            "sink operand")
            comparison = None
            if row["comparison_operator"]:
                operands, operand_gaps = self.guard_operands(row)
                gaps.extend(operand_gaps)
                comparison = {"operator": row["comparison_operator"], "bound_display": row["bound_display"],
                              "operands": operands}
            object_bytes = int(row["destination_object_bytes"])
            result = {
                "sink": {"sink_site": sink.identity.value, "sink_class": sink.payload["result"]["sink_class"]},
                "guard_state": state, "polarity": polarity, "condition": condition,
                "constrains_sink_operand": constrains,
                "comparison": comparison,
                "destination": {"object_bytes": object_bytes if object_bytes > 0 else None},
            }
            name = f"{state}: {row['condition_display'] or 'no controlling guard'} -> {sink.name}"
            fact = self.fact(family, native, name, result, mapped, exact=exact, gaps=gaps)
            per_sink[sink.identity.value].append(fact)
        bound = self.settings.max_guards_per_sink
        for sink_id in sorted(per_sink):
            unique: dict[str, GraphFact] = {}
            for fact in sorted(per_sink[sink_id], key=lambda item: (
                    _GUARD_CONSERVATIVE[item.payload["result"]["guard_state"]], item.identity.value)):
                if fact.identity.value in unique:
                    self.family_gap(family, f"guard_state_collision: one condition of sink {sink_id} has several "
                                            "states; the least protective one is published")
                    continue
                unique[fact.identity.value] = fact
            ordered = sorted(unique.values(), key=lambda item: (_GUARD_RANK[item.payload["result"]["guard_state"]],
                                                                 item.identity.value))
            kept, omitted = ordered[:bound], ordered[bound:]
            if omitted:
                gap = f"truncated_guards: {len(omitted)} guards of this sink exceed max_guards_per_sink={bound}"
                self.family_gap(family, f"truncated_guards: sink {sink_id}: {len(omitted)} guards omitted")
                kept = [self.with_gap(fact, gap) for fact in kept]
            for fact in kept:
                if self.add(fact):
                    self.guards_by_sink[sink_id].append(fact.identity.value)
                    self.relation(RelationKind.GUARDS, fact.identity.value, sink_id)

    def with_gap(self, fact: GraphFact, gap: str) -> GraphFact:
        """``fact`` with an additional gap and ``partial`` coverage (a bound hit for this fact)."""
        payload = dict(fact.payload)
        payload["gaps"] = list(dict.fromkeys([*payload["gaps"], gap]))
        payload["coverage_status"] = Coverage.PARTIAL.value
        payload["admissibility"] = admissibility(payload)
        validate_payload(payload)
        return replace(fact, payload=payload)

    def build_ranges(self) -> None:
        family = Family.RANGE_FACT
        conversions: dict[Key6, list[dict[str, Any]]] = defaultdict(list)
        for row in self.rows.get("range_conversions", ()):
            conversions[self.key6(row)].append(row)
        if "range_conversions" not in self.exports:
            self.family_gap(family, "export_unavailable: range_conversions; conversion chains are unknown")
        for row in self.rows["ranges"]:
            key = self.key6(row)
            sink = self.sinks.get(key)
            if sink is None:
                self.counts[family]["unattached_rows"] += 1
                self.family_gap(family, f"unattached_range: range row for sink {key[0]}:{key[1]} has no published "
                                        "sink_site")
                continue
            mapped = self.locator.span(self.key5(row, "operand"))
            gaps: list[str] = []
            if mapped.location is None:
                mapped = _Mapped(sink.location, "operand_unmapped")
                gaps.append("operand_unmapped: the operand location does not resolve; the sink span is used")
            elif mapped.reason:
                gaps.append(f"{mapped.reason}: operand location is not exact")
            chain = []
            exact = True
            for item in sorted(conversions.get(key, ()), key=lambda value: (int(value["step"]),
                                                                            tuple(str(v) for v in value.values()))):
                location = self.locator.span(self.key5(item, "conversion"))
                if not location.exact:
                    exact = False
                    gaps.append(f"{location.reason or 'unmapped_location'}: conversion {item['step']} location is "
                                "not exact")
                chain.append({"step": int(item["step"]), "kind": item["kind"], "from_type": item["from_type"],
                              "to_type": item["to_type"], "location": _location_dict(location)})
            integral = row["applicability"] == "integral"
            if not integral:
                gaps.append("not_applicable: the operand is not integral; no interval is computed")
            interval = {"lower": _bound(row["lower"]), "upper": _bound(row["upper"])} if integral else None
            result = {
                "sink": {"sink_site": sink.identity.value, "sink_class": sink.payload["result"]["sink_class"]},
                "operand_index": key[5], "applicability": row["applicability"],
                "type": {"display": row["type_display"],
                         "signed": True if row["signed"] == "true" else False if row["signed"] == "false" else None,
                         "bits": int(row["bits"])},
                "interval": interval, "conversions": chain,
                "sign_change": any(item["kind"] == "sign_change" for item in chain),
                "analysis": ANALYSIS_RANGES, "precision": "may_over_approximate",
            }
            native = {"scope_id": self.scope_id, "sink_identity": sink.identity.value, "operand_index": key[5]}
            fact = self.fact(family, native, f"{row['type_display']} operand {key[5]} of {sink.name}", result, mapped,
                             exact=exact, gaps=gaps)
            if self.add(fact):
                self.relation(RelationKind.DERIVED_FROM, fact.identity.value, sink.identity.value)

    def build_calls(self) -> None:
        family = Family.CALL_SITE
        by_caller: dict[str, list[GraphFact]] = defaultdict(list)
        for row in self.rows["call_sites"]:
            key = self.key5(row, "call")
            mapped = self.locator.span(key)
            caller = self.symbol(row["caller_name"], row["caller_path"], row["caller_start_line"],
                                 row["caller_start_column"])
            if mapped.location is None or caller is None:
                self.unmapped(family, "call", key)
                continue
            callee = self.symbol(row["callee_name"], row["callee_path"], row["callee_start_line"],
                                 row["callee_start_column"]) if row["callee_path"] else None
            dispatch = str(row["dispatch"])
            if dispatch not in {item.value for item in Dispatch} or dispatch == Dispatch.SECONDARY_ONLY.value:
                self.family_gap(family, f"unknown_dispatch: {dispatch!r} at {key[0]}:{key[1]} was not published")
                continue
            gaps = [f"{mapped.reason}: call location is not exact"] if mapped.reason else []
            if dispatch == Dispatch.UNRESOLVED_INDIRECT.value:
                self.counts[family]["unresolved_indirect"] += 1
                gaps.append("unresolved_indirect: CodeQL resolves no target for this call; callers closures through "
                            "it are unsound")
            location = mapped.location
            native = {"scope_id": self.scope_id, "caller_symbol": caller, "path": location.path,
                      "start_byte": location.start_byte, "end_byte": location.end_byte,
                      "callee_name": row["callee_name"]}
            result = {
                "caller": {"symbol": caller, "display": row["caller_name"]},
                "callee": {"symbol": callee, "display": row["callee_name"], "dispatch": dispatch,
                           "candidate_count": int(row["candidate_count"]),
                           "declared_in": row["callee_declared_in"] or None},
                "argument_count": int(row["argument_count"]), "in_loop": _bool(row["in_loop"]),
            }
            fact = self.fact(family, native, f"{row['caller_name']} -> {row['callee_name']}", result, mapped,
                             exact=True, gaps=gaps)
            by_caller[caller].append(fact)
        if self.counts[family]["unresolved_indirect"]:
            self.family_gap(family, f"unresolved_indirect: {self.counts[family]['unresolved_indirect']} call sites "
                                    "have no resolved target")
        bound = self.settings.max_neighbors_per_function
        for caller in sorted(by_caller):
            facts = sorted(by_caller[caller], key=lambda item: item.identity.value)
            kept, omitted = facts[:bound], facts[bound:]
            if omitted:
                self.counts[family]["truncated_neighbors"] += len(omitted)
                self.family_gap(family, f"truncated_neighbors: function {caller}: {len(omitted)} call sites beyond "
                                        f"max_neighbors_per_function={bound}")
                gap = (f"truncated_neighbors: the caller has {len(facts)} call sites; "
                       f"max_neighbors_per_function={bound} kept the first by identity")
                kept = [self.with_gap(fact, gap) for fact in kept]
            for fact in kept:
                if self.add(fact):
                    self.relation(RelationKind.CONTAINS, caller, fact.identity.value)
                    callee = fact.payload["result"]["callee"]["symbol"]
                    if callee:
                        self.relation(RelationKind.CALLS, fact.identity.value, callee)

    def build_summaries(self) -> None:
        family = Family.FLOW_SUMMARY
        calls: dict[tuple[str, str, int, int], list[dict[str, Any]]] = defaultdict(list)
        for row in self.rows.get("call_sites", ()):
            calls[(row["caller_name"], row["caller_path"], row["caller_start_line"],
                   row["caller_start_column"])].append(row)
        if "call_sites" not in self.exports:
            self.family_gap(family, "export_unavailable: call_sites; sanitizer and opaque calls are unknown")
        groups: dict[tuple[str, str, int, int], list[dict[str, Any]]] = defaultdict(list)
        for row in self.rows["flow_summaries"]:
            groups[(row["function_name"], row["function_path"], row["function_start_line"],
                    row["function_start_column"])].append(row)
        k_limited = bool(self.exports["flow_summaries"]["truncated"])
        sanitizers = self.language.sanitizer_apis
        for key in sorted(groups):
            symbol = self.symbol(*key)
            record = self.symbols.get(key)
            if symbol is None or record is None or record.location is None:
                self.unmapped(family, "function", (key[1], key[2], key[3], key[2], key[3]))
                continue
            mapped = self.locator.name_span(key[1], key[2], key[3], key[0])
            pairs = sorted(({"from": {"kind": row["from_kind"], "index": int(row["from_index"]),
                                      "name": row["from_name"]},
                             "to": {"kind": row["to_kind"], "index": int(row["to_index"]), "name": row["to_name"],
                                    "model": row["to_model"] or None},
                             "kind": row["flow_kind"]} for row in groups[key]), key=canonical_json)
            called = calls.get(key, [])
            gaps = [f"{mapped.reason}: function name location is not exact"] if mapped.reason else []
            if k_limited:
                gaps.append("k_limited: the flow_summaries export was truncated; pairs may be missing")
            result = {
                "function": {"symbol": symbol, "display": key[0]}, "pairs": pairs,
                "sanitizes": sorted({row["callee_name"] for row in called if row["callee_name"] in sanitizers
                                     or _api_tail(row["callee_name"]) in sanitizers}),
                "opaque_calls": sorted({row["callee_name"] for row in called
                                        if row["dispatch"] == Dispatch.EXTERNAL_UNDEFINED.value}),
                "k_limited": k_limited, "recursion_collapsed": True, "field_depth": 1,
            }
            native = {"scope_id": self.scope_id, "function_symbol": symbol, "rule_version": NORMALIZE_RULE}
            fact = self.fact(family, native, f"{key[0]} summary", result, mapped, exact=True, gaps=gaps,
                             complete=not k_limited)
            if self.add(fact):
                self.relation(RelationKind.DERIVED_FROM, fact.identity.value, symbol)

    def build_paths(self) -> None:
        family = Family.DATAFLOW_PATH
        flow_key = lambda row: (*self.key5(row, "source"), *self.key6(row))
        edges: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
        for row in self.rows["path_edges"]:
            edges[flow_key(row)].append(row)
        sanitizer_rows: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
        for row in self.rows.get("path_sanitizers", ()):
            sanitizer_rows[flow_key(row)].append(row)
        if "path_sanitizers" not in self.exports:
            self.family_gap(family, "export_unavailable: path_sanitizers; sanitizers on paths are unknown")
        candidates: dict[str, list[tuple[tuple[int, str], dict[str, Any]]]] = defaultdict(list)
        for row in self.rows["path_flows"]:
            key = flow_key(row)
            sink = self.sinks.get(self.key6(row))
            if sink is None:
                self.counts[family]["unattached_flows"] += 1
                self.family_gap(family, f"unattached_flow: flow to {key[5]}:{key[6]} has no published sink_site")
                continue
            for candidate in self.enumerate(key, edges.get(key, ()), sink):
                candidates[sink.identity.value].append(((candidate["hop_count"], candidate["step_hash"]), candidate))
        bound = self.settings.max_paths_per_sink
        for sink_id in sorted(candidates):
            ordered = [item[1] for item in sorted(candidates[sink_id], key=lambda item: (
                item[0], item[1]["source_key"]))]
            kept, omitted = ordered[:bound], ordered[bound:]
            if omitted:
                self.counts[family]["omitted_paths"] += len(omitted)
                self.family_gap(family, f"omitted_paths: sink {sink_id}: {len(omitted)} paths beyond "
                                        f"max_paths_per_sink={bound}")
            flows_to: dict[str, list[str]] = defaultdict(list)
            for rank, candidate in enumerate(kept):
                fact = self.path_fact(candidate, rank, len(omitted), sanitizer_rows)
                if self.add(fact):
                    source = fact.payload["result"]["source"]["entry_point"]
                    if source:
                        flows_to[source].append(fact.identity.value)
            for source in sorted(flows_to):
                self.relation(RelationKind.FLOWS_TO, source, sink_id, path_id=flows_to[source][0],
                              path_ids=flows_to[source])

    def enumerate(self, key: tuple, rows: Sequence[Mapping[str, Any]], sink: GraphFact) -> list[dict[str, Any]]:
        """Every simple source→terminal node sequence of one flow, bounded."""
        family = Family.DATAFLOW_PATH
        graph: dict[Key5, list[tuple[Key5, str]]] = defaultdict(list)
        nodes: dict[Key5, tuple[str, str]] = {}
        for row in rows:
            start, end = self.key5(row, "from"), self.key5(row, "to")
            graph[start].append((end, str(row["edge_kind"])))
            nodes.setdefault(start, (str(row["from_display"]), str(row["from_function"])))
            nodes.setdefault(end, (str(row["to_display"]), str(row["to_function"])))
        source: Key5 = tuple(key[:5])  # type: ignore[assignment]
        for start, successors in list(graph.items()):
            graph[start] = sorted(set(successors))
        if source not in graph:
            self.family_gap(family, f"flow_without_edges: flow from {source[0]}:{source[1]} to sink {sink.name} "
                                    "has no path edges and was not published")
            return []
        found: list[list[tuple[Key5, str]]] = []
        stack: list[tuple[Key5, list[tuple[Key5, str]]]] = [(source, [(source, "source")])]
        exhausted = False
        while stack:
            node, trail = stack.pop()
            successors = [item for item in graph.get(node, ()) if all(item[0] != step[0] for step in trail)]
            if not graph.get(node):
                found.append(trail)
                if len(found) >= MAX_ENUMERATED_PATHS_PER_FLOW:
                    exhausted = bool(stack)
                    break
                continue
            for successor in reversed(successors):
                stack.append((successor[0], [*trail, successor]))
        if exhausted:
            self.family_gap(family, f"path_enumeration_bound: flow to sink {sink.name} has more than "
                                    f"{MAX_ENUMERATED_PATHS_PER_FLOW} simple paths; the rest were not considered")
        out = []
        for trail in found:
            steps = []
            for index, (node, edge_kind) in enumerate(trail):
                display, function = nodes.get(node, ("", ""))
                role = ("source" if index == 0 else "sink" if index == len(trail) - 1 else
                        "call" if edge_kind == "call" else "return" if edge_kind == "return" else "step")
                steps.append({"node": node, "role": role, "display": display, "function": function,
                              "edge": edge_kind})
            step_hash = _sha([list(step["node"]) for step in steps])
            out.append({"source_key": source, "sink": sink, "steps": steps, "hop_count": len(steps) - 1,
                        "step_hash": step_hash, "flow_key": key})
        return out

    def path_fact(self, candidate: Mapping[str, Any], rank: int, omitted: int,
                  sanitizer_rows: Mapping[tuple, Sequence[Mapping[str, Any]]]) -> GraphFact:
        family = Family.DATAFLOW_PATH
        sink: GraphFact = candidate["sink"]
        steps = candidate["steps"]
        gaps: list[str] = []
        complete = True
        limit = self.settings.max_path_steps
        truncated = len(steps) > limit
        if truncated:
            steps = [*steps[:limit - 1], steps[-1]] if limit > 1 else [steps[-1]]
            complete = False
            self.counts[family]["truncated_steps"] += 1
            self.family_gap(family, f"truncated_steps: a path to sink {sink.identity.value} has "
                                    f"{candidate['hop_count'] + 1} steps; max_path_steps={limit}")
            gaps.append(f"truncated_steps: {candidate['hop_count'] + 1} steps exceed max_path_steps={limit}; "
                        "middle steps were dropped")
        exact = True
        rendered = []
        depth = max_depth = 0
        for n, step in enumerate(steps):
            mapped = self.locator.span(step["node"])
            if not mapped.exact:
                exact = False
                where = f"{step['node'][0]}:{step['node'][1]}"
                gaps.append(f"ambiguous_step_location: step {n} at {where} "
                            f"({mapped.reason or 'unmapped_location'})")
            if step["edge"] == "call":
                depth += 1
                max_depth = max(max_depth, depth)
            elif step["edge"] == "return":
                depth = max(0, depth - 1)
            rendered.append({"n": n, "location": _location_dict(mapped), "role": step["role"],
                             "symbol": self.symbol_by_name(step["function"]) if step["function"] else None,
                             "display": step["display"]})
        entry = self.entries.get(candidate["source_key"])
        source_class = entry.payload["result"]["source_class"] if entry else SourceClass.UNCLASSIFIED.value
        if entry is None:
            gaps.append("unmatched_source: the flow source is not a published entry_point")
        sanitizers = []
        for row in sorted(sanitizer_rows.get(candidate["flow_key"], ()), key=lambda value: tuple(
                str(v) for v in value.values())):
            mapped = self.locator.span(self.key5(row, "sanitizer"))
            if not mapped.exact:
                exact = False
                gaps.append(f"{mapped.reason or 'unmapped_location'}: sanitizer {row['api']} location is not exact")
            sanitizers.append({"api": row["api"], "location": _location_dict(mapped)})
        if omitted:
            gaps.append(f"omitted_paths: {omitted} other paths to this sink exceed max_paths_per_sink="
                        f"{self.settings.max_paths_per_sink}")
        sink_result = sink.payload["result"]
        if sink_result["sink_class"] == SinkClass.UNCLASSIFIED.value:
            gaps.append("unclassified_sink: the path's sink is not classified by the catalog")
        result = {
            "source": {"entry_point": entry.identity.value if entry else None, "source_class": source_class},
            "sink": {"sink_site": sink.identity.value, "sink_class": sink_result["sink_class"],
                     "cwe_family": sink_result["cwe_family"]},
            "steps": rendered, "hop_count": candidate["hop_count"], "call_depth": max_depth,
            "guards": sorted(self.guards_by_sink.get(sink.identity.value, ())), "sanitizers": sanitizers,
            "truncated_steps": truncated, "selection": SELECTION, "rank": rank,
        }
        source_identity = entry.identity.value if entry else "unmatched-source:" + _sha(list(candidate["source_key"]))
        native = {"scope_id": self.scope_id, "source_identity": source_identity, "sink_identity": sink.identity.value,
                  "step_locations_sha256": candidate["step_hash"]}
        source_display = steps[0]["display"] or "source"
        mapped = _Mapped(sink.location, None if sink.payload["exact"] else "inexact_sink_location")
        return self.fact(family, native, f"{source_display} -> {sink.name}", result, mapped,
                         exact=exact and (entry is None or entry.payload["exact"]), gaps=gaps, complete=complete)

    # -- run ----------------------------------------------------------------------------------
    def run(self) -> NormalizedScope:
        builders = (
            (Family.SINK_SITE, self.build_sinks), (Family.ENTRY_POINT, self.build_entries),
            (Family.GUARD_FACT, self.build_guards), (Family.RANGE_FACT, self.build_ranges),
            (Family.CALL_SITE, self.build_calls), (Family.FLOW_SUMMARY, self.build_summaries),
            (Family.DATAFLOW_PATH, self.build_paths),
        )
        unavailable: set[Family] = set()
        for family, build in builders:
            if not self.available(family):
                unavailable.add(family)
                missing = [query for query in FAMILY_REQUIRED[family] if query not in self.exports]
                self.gaps[family].append(f"export_unavailable: {', '.join(missing)} not exported for this scope")
                continue
            self.truncated_exports(family)
            build()
        # Bound each family deterministically by identity.
        cap = self.settings.max_facts_per_family_per_scope
        for family in Family:
            bucket = self.facts[family]
            if len(bucket) > cap:
                dropped = sorted(bucket)[cap:]
                for identity in dropped:
                    del bucket[identity]
                self.family_gap(family, f"max_facts_per_family_per_scope: {len(dropped)} {family.value} facts beyond "
                                        f"{cap} were not published")
        facts = sorted((fact for bucket in self.facts.values() for fact in bucket.values()),
                       key=lambda item: item.identity.value)
        symbols = sorted(self.symbols.values(), key=lambda item: item.identity.value)
        known = {fact.identity.value for fact in facts} | {item.identity.value for item in symbols}
        unique: dict[str, RelationRecord] = {}
        for relation in sorted(self.relations, key=lambda item: (item.relation_id, canonical_json(item.payload or {}))):
            if relation.source_id in known and relation.target_id in known:
                unique.setdefault(relation.relation_id, relation)
        coverage = []
        for family in Family:
            members = [fact for fact in facts if fact.family is family]
            inexact = sum(1 for fact in members if not fact.payload["exact"])
            if inexact:
                self.family_gap(family, f"inexact_locations: {inexact} {family.value} facts have an inexact location")
            incomplete = sum(1 for fact in members if fact.payload["coverage_status"] != Coverage.COMPLETE.value)
            if incomplete:
                self.family_gap(family, f"incomplete_facts: {incomplete} {family.value} facts are partial")
            if family in unavailable:
                status = Coverage.UNAVAILABLE
            else:
                status = Coverage.PARTIAL if self.partial[family] else Coverage.COMPLETE
            counts = {name: value for name, value in self.counts[family].items() if value}
            coverage.append(CoverageRow(self.scope_id, family, status, tuple(dict.fromkeys(self.gaps[family])),
                                        len(members), counts))
        return NormalizedScope(self.scope_id, tuple(facts), tuple(symbols),
                               tuple(unique[key] for key in sorted(unique)), tuple(coverage))


def normalize_scope(exports: Mapping[str, Mapping[str, Any]], *, scope: Mapping[str, Any], target_snapshot: str,
                    sources: Mapping[str, SourceFile], catalog: Catalog, settings: GraphSettings | None = None,
                    tool_version: str, export_pack_sha256: str,
                    upstream: Sequence[Mapping[str, Any]] = ()) -> NormalizedScope:
    """Normalize one CodeQL scope's verified graph exports (see the module docstring)."""
    return _Normalizer(exports, scope=scope, target_snapshot=target_snapshot, sources=sources, catalog=catalog,
                       settings=settings or GraphSettings(), tool_version=tool_version,
                       export_pack_sha256=export_pack_sha256, upstream=upstream).run()


__all__ = [
    "COLUMNS_PATH",
    "EXPORT_UPSTREAM_INDEX",
    "FAMILY_QUERIES",
    "FAMILY_REQUIRED",
    "CoverageRow",
    "FamilyShard",
    "NormalizedScope",
    "export_columns",
    "normalize_scope",
]
