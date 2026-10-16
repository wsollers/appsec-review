"""Shared code-graph contract (docs/architecture/code-graph-precomputation.md, sections 3, 5 and 6).

Names and values here are data contracts shared by the CodeQL export, the graph normalizer and
cross-checker, ``job_code_graph_index``, the ``query_code_graph`` retrieval tool and the review
validator. Chunks import them and never edit them; a change is a versioned contract change.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum
import re
from typing import Any, Mapping

from appsec_review.retrieval.model import EntityKind, EntityRecord, LogicalIdentity, SourceLocation
from appsec_review.review.models import Predicate

GRAPH_INDEX = "graph"
QUERY_CODE_GRAPH = "query_code_graph"
GRAPH_FACT_SCHEMA = "appsec-review/graph-fact/1"
EXPORT_SCHEMA = "appsec-review/codeql-graph-export/1"
CATALOG_SCHEMA = "appsec-review/graph-catalog/1"
NORMALIZE_RULE = "graph-normalize/1"
CROSS_CHECK_RULE = "graph-cross-check/1"
ADMISSIBILITY_RULE = "graph-fact-admissibility/1"
FACT_PREDICATES_RULE = "graph-fact-predicates/1"
AUTHORITY = "computed from accepted run-owned evidence; a graph fact is not a tool finding"


class Family(StrEnum):
    CALL_SITE = "call_site"
    SINK_SITE = "sink_site"
    ENTRY_POINT = "entry_point"
    FLOW_SUMMARY = "flow_summary"
    DATAFLOW_PATH = "dataflow_path"
    GUARD_FACT = "guard_fact"
    RANGE_FACT = "range_fact"


class Mode(StrEnum):
    CALLERS = "callers"
    CALLEES = "callees"
    SINKS = "sinks"
    ENTRY_POINTS = "entry_points"
    PATHS = "paths"
    GUARDS = "guards"
    RANGES = "ranges"
    SUMMARY = "summary"
    SARIF_PATH = "sarif_path"


class Dispatch(StrEnum):
    DIRECT = "direct"
    VIRTUAL_RESOLVED = "virtual_resolved"
    FUNCTION_POINTER_RESOLVED = "function_pointer_resolved"
    TEMPLATE_INSTANTIATION = "template_instantiation"
    UNRESOLVED_INDIRECT = "unresolved_indirect"
    EXTERNAL_UNDEFINED = "external_undefined"
    SECONDARY_ONLY = "secondary_only"


class SinkClass(StrEnum):
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    ALLOCATION_SIZE = "allocation_size"
    FORMAT_STRING = "format_string"
    COMMAND_EXECUTION = "command_execution"
    PATH_ACCESS = "path_access"
    SQL_QUERY = "sql_query"
    CODE_INJECTION = "code_injection"
    DESERIALIZATION = "deserialization"
    INTEGER_CONVERSION = "integer_conversion"
    CRYPTO_MISUSE = "crypto_misuse"
    LOG_OUTPUT = "log_output"
    UNCLASSIFIED = "unclassified"


class SourceClass(StrEnum):
    REMOTE = "remote"
    LOCAL_USER = "local_user"
    ARGV = "argv"
    ENVIRONMENT = "environment"
    FILE = "file"
    IPC = "ipc"
    DATABASE = "database"
    INTERNAL = "internal"
    UNCLASSIFIED = "unclassified"


class GuardState(StrEnum):
    DOMINATING = "dominating"
    NON_DOMINATING = "non_dominating"
    POST_DOMINATING_ONLY = "post_dominating_only"
    NONE = "none"


class GuardPolarity(StrEnum):
    TRUE_BRANCH = "true_branch"
    FALSE_BRANCH = "false_branch"
    UNKNOWN = "unknown"


class CrossCheckState(StrEnum):
    AGREE = "agree"
    DISAGREE = "disagree"
    NOT_COVERED = "not_covered"
    PARTIAL = "partial"


class Coverage(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


class Producer(StrEnum):
    CODEQL_EXPORT = "codeql-export"
    CLANGD = "clangd"
    LLVM_IR = "llvm-ir"
    CLANG_AST = "clang-ast"
    CLANG_STATIC = "clang-static"
    JOERN_CPG = "joern-cpg"


FAMILY_KINDS: Mapping[Family, EntityKind] = {family: EntityKind(family.value) for family in Family}

# User decision A2: these source classes are attacker-reachable for attacker_input_control.
ATTACKER_REACHABLE_SOURCES = frozenset({
    SourceClass.REMOTE, SourceClass.LOCAL_USER, SourceClass.ARGV, SourceClass.ENVIRONMENT, SourceClass.FILE,
    SourceClass.IPC,
})

# Section 5.2: subject kinds each mode accepts, the family it returns, and its optional filters.
MODE_SUBJECT_KINDS: Mapping[Mode, frozenset[EntityKind]] = {
    Mode.CALLERS: frozenset({EntityKind.SYMBOL}),
    Mode.CALLEES: frozenset({EntityKind.SYMBOL}),
    Mode.SINKS: frozenset({EntityKind.SYMBOL, EntityKind.SOURCE_FILE, EntityKind.COMPONENT, EntityKind.REVIEW_UNIT}),
    Mode.ENTRY_POINTS: frozenset({EntityKind.SYMBOL, EntityKind.SOURCE_FILE, EntityKind.COMPONENT,
                                  EntityKind.REVIEW_UNIT}),
    Mode.PATHS: frozenset({EntityKind.SINK_SITE, EntityKind.ENTRY_POINT, EntityKind.SYMBOL, EntityKind.SOURCE_FILE}),
    Mode.GUARDS: frozenset({EntityKind.SINK_SITE}),
    Mode.RANGES: frozenset({EntityKind.SINK_SITE}),
    Mode.SUMMARY: frozenset({EntityKind.SYMBOL}),
    Mode.SARIF_PATH: frozenset({EntityKind.TOOL_OBSERVATION}),
}
MODE_FAMILY: Mapping[Mode, Family] = {
    Mode.CALLERS: Family.CALL_SITE, Mode.CALLEES: Family.CALL_SITE, Mode.SINKS: Family.SINK_SITE,
    Mode.ENTRY_POINTS: Family.ENTRY_POINT, Mode.PATHS: Family.DATAFLOW_PATH, Mode.GUARDS: Family.GUARD_FACT,
    Mode.RANGES: Family.RANGE_FACT, Mode.SUMMARY: Family.FLOW_SUMMARY, Mode.SARIF_PATH: Family.DATAFLOW_PATH,
}
DEPTH_MODES = frozenset({Mode.CALLERS, Mode.CALLEES})
SINK_CLASS_MODES = frozenset({Mode.SINKS, Mode.PATHS})
SOURCE_CLASS_MODES = frozenset({Mode.ENTRY_POINTS, Mode.PATHS})
MAX_TOOL_DEPTH = 4
MAX_TOOL_LIMIT = 100

# Section 6, graph-fact-predicates/1: the predicates a direct-eligible fact may satisfy directly.
# flow_summary is deliberately absent: it is indirect for every predicate.
GRAPH_FACT_PREDICATES: Mapping[Family, frozenset[Predicate]] = {
    Family.CALL_SITE: frozenset({Predicate.AFFECTED_CONSTRUCT}),
    Family.SINK_SITE: frozenset({Predicate.AFFECTED_CONSTRUCT}),
    Family.ENTRY_POINT: frozenset({Predicate.ATTACKER_INPUT_CONTROL}),
    Family.DATAFLOW_PATH: frozenset({Predicate.SOURCE_TO_SINK_REACHABILITY, Predicate.ATTACKER_INPUT_CONTROL}),
    Family.GUARD_FACT: frozenset({Predicate.MISSING_OR_INEFFECTIVE_GUARD}),
    Family.RANGE_FACT: frozenset({Predicate.MISSING_OR_INEFFECTIVE_GUARD}),
}

# Section 3.3: the exact native identity fields per family.
NATIVE_IDENTITY_FIELDS: Mapping[Family, tuple[str, ...]] = {
    Family.CALL_SITE: ("scope_id", "caller_symbol", "path", "start_byte", "end_byte", "callee_name"),
    Family.SINK_SITE: ("scope_id", "path", "start_byte", "end_byte", "sink_class", "argument_index"),
    Family.ENTRY_POINT: ("scope_id", "path", "start_byte", "end_byte", "source_class"),
    Family.FLOW_SUMMARY: ("scope_id", "function_symbol", "rule_version"),
    Family.DATAFLOW_PATH: ("scope_id", "source_identity", "sink_identity", "step_locations_sha256"),
    Family.GUARD_FACT: ("scope_id", "sink_identity", "condition_path", "condition_start_byte", "condition_end_byte"),
    Family.RANGE_FACT: ("scope_id", "sink_identity", "operand_index"),
}

PAYLOAD_KEYS = frozenset({"schema", "family", "producer", "scope", "exact", "coverage_status", "gaps", "cross_check",
                          "admissibility", "result", "upstream", "authority"})
_PRODUCER_KEYS = frozenset({"name", "tool_version", "export_pack_sha256", "catalog_version", "rule_version"})
_SCOPE_KEYS = frozenset({"scope_id", "language", "build_unit_id", "component_id"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class GraphContractError(ValueError):
    """A graph fact, export or setting violates the shared contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise GraphContractError(message)


def fact_identity(family: Family | str, target_snapshot: str, native: Mapping[str, Any]) -> LogicalIdentity:
    """Derive a fact's logical identity from exactly its family's native identity fields."""
    family = Family(family)
    expected = NATIVE_IDENTITY_FIELDS[family]
    _require(set(native) == set(expected), f"{family.value} native identity must have exactly {list(expected)}")
    _require(all(native[name] is not None and native[name] != "" for name in expected),
             f"{family.value} native identity fields must be non-empty")
    return LogicalIdentity.derive(FAMILY_KINDS[family], target_snapshot, {name: native[name] for name in expected})


def none_guard_native(scope_id: str, sink_identity: str, sink_path: str, sink_start_byte: int,
                      sink_end_byte: int) -> dict[str, Any]:
    """Native identity of the explicit ``guard_state = none`` fact for one sink.

    A ``none`` fact has no condition, so its condition fields are the sink's own path and byte span.
    This keeps exactly one ``none`` fact per sink and never collides with a real condition, which
    cannot share the sink expression's exact span.
    """
    return {"scope_id": scope_id, "sink_identity": sink_identity, "condition_path": sink_path,
            "condition_start_byte": sink_start_byte, "condition_end_byte": sink_end_byte}


def mapped_predicates(family: Family | str, result: Mapping[str, Any]) -> frozenset[Predicate]:
    """Predicates a direct-eligible fact of ``family`` may satisfy, after the family's condition."""
    family = Family(family)
    mapped = GRAPH_FACT_PREDICATES.get(family, frozenset())
    if family is Family.ENTRY_POINT and result.get("source_class") not in ATTACKER_REACHABLE_SOURCES:
        return frozenset()
    if family is Family.DATAFLOW_PATH:
        source = result.get("source") if isinstance(result.get("source"), Mapping) else {}
        if source.get("source_class") not in ATTACKER_REACHABLE_SOURCES:
            return mapped - {Predicate.ATTACKER_INPUT_CONTROL}
    return mapped


def ineligibility_reasons(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Every graph-fact-admissibility/1 condition the payload fails (section 3.4), in fixed order."""
    reasons: list[str] = []
    if payload.get("exact") is not True:
        reasons.append("inexact_location")
    if payload.get("coverage_status") != Coverage.COMPLETE.value:
        reasons.append("incomplete_coverage")
    state = (payload.get("cross_check") or {}).get("state")
    if state not in {CrossCheckState.AGREE.value, CrossCheckState.NOT_COVERED.value}:
        reasons.append(f"cross_check_{state or 'missing'}")
    family = payload.get("family")
    result = payload.get("result") if isinstance(payload.get("result"), Mapping) else {}
    unclassified = SinkClass.UNCLASSIFIED.value
    if family == Family.SINK_SITE.value and result.get("sink_class", unclassified) == unclassified:
        reasons.append("unclassified_sink")
    if family == Family.ENTRY_POINT.value and result.get("source_class", unclassified) == unclassified:
        reasons.append("unclassified_source")
    if family == Family.RANGE_FACT.value and (result.get("applicability") == "not_applicable"
                                              or result.get("interval", {}) is None):
        reasons.append("range_not_applicable")
    if family == Family.DATAFLOW_PATH.value:
        source = result.get("source") if isinstance(result.get("source"), Mapping) else {}
        sink = result.get("sink") if isinstance(result.get("sink"), Mapping) else {}
        if source.get("source_class", unclassified) == unclassified:
            reasons.append("unclassified_source")
        if sink.get("sink_class", unclassified) == unclassified:
            reasons.append("unclassified_sink")
    return tuple(reasons)


def admissibility(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The admissibility block a producer must publish for ``payload``."""
    reasons = ineligibility_reasons(payload)
    return {"rule": ADMISSIBILITY_RULE, "direct_eligible": not reasons, "ineligibility_reasons": list(reasons)}


def validate_payload(payload: Mapping[str, Any]) -> None:
    """Check the closed graph-fact/1 shape and that the published admissibility is the computed one."""
    _require(set(payload) == PAYLOAD_KEYS, f"graph fact payload keys must be exactly {sorted(PAYLOAD_KEYS)}")
    _require(payload["schema"] == GRAPH_FACT_SCHEMA and payload["authority"] == AUTHORITY,
             "graph fact schema or authority is invalid")
    Family(payload["family"])
    producer, scope = payload["producer"], payload["scope"]
    _require(isinstance(producer, Mapping) and set(producer) == _PRODUCER_KEYS, "graph fact producer is invalid")
    Producer(producer["name"])
    _require(isinstance(scope, Mapping) and set(scope) == _SCOPE_KEYS and bool(scope["scope_id"]),
             "graph fact scope is invalid")
    _require(isinstance(payload["exact"], bool), "graph fact exact must be a boolean")
    Coverage(payload["coverage_status"])
    _require(isinstance(payload["gaps"], list) and all(isinstance(gap, str) and gap for gap in payload["gaps"]),
             "graph fact gaps must be strings")
    _require(payload["coverage_status"] == Coverage.COMPLETE.value or bool(payload["gaps"]),
             "an incomplete graph fact must name its gaps")
    cross_check = payload["cross_check"]
    _require(isinstance(cross_check, Mapping) and set(cross_check) == {"rule", "state", "producers"}
             and cross_check["rule"] == CROSS_CHECK_RULE, "graph fact cross_check is invalid")
    CrossCheckState(cross_check["state"])
    _require(isinstance(payload["result"], Mapping), "graph fact result must be an object")
    _require(isinstance(payload["upstream"], list) and all(
        isinstance(item, Mapping) and set(item) == {"index", "shard_id", "sha256"} and _SHA256.fullmatch(
            str(item["sha256"])) for item in payload["upstream"]), "graph fact upstream entries are invalid")
    _require(dict(payload["admissibility"]) == admissibility(payload),
             "published admissibility differs from graph-fact-admissibility/1")


@dataclass(frozen=True, slots=True)
class GraphFact:
    identity: LogicalIdentity
    name: str
    payload: Mapping[str, Any]
    location: SourceLocation | None

    @property
    def family(self) -> Family:
        return Family(self.payload["family"])

    def to_entity(self) -> EntityRecord:
        validate_payload(self.payload)
        _require(self.identity.kind is FAMILY_KINDS[self.family], "fact identity kind differs from its family")
        if self.payload["exact"]:
            _require(self.location is not None and not self.location.ambiguous and self.location.confidence == 1.0,
                     "an exact graph fact needs an exact, unambiguous source location")
        return EntityRecord(self.identity, self.identity.value, self.name[:256], "", dict(self.payload), self.location)


EXPORT_KEYS = frozenset({"schema", "query_id", "columns", "rows", "row_count", "truncated", "bqrs_sha256"})


def validate_export(document: Mapping[str, Any]) -> None:
    """Check one raw CodeQL graph export (the C1 → C3 contract)."""
    _require(set(document) == EXPORT_KEYS and document["schema"] == EXPORT_SCHEMA, "graph export shape is invalid")
    _require(isinstance(document["query_id"], str) and bool(document["query_id"]), "graph export query_id is required")
    columns, rows = document["columns"], document["rows"]
    _require(isinstance(columns, list) and columns and all(isinstance(column, str) and column for column in columns)
             and len(set(columns)) == len(columns), "graph export columns must be unique names")
    _require(isinstance(rows, list) and all(isinstance(row, list) and len(row) == len(columns) for row in rows),
             "graph export rows must match the columns")
    keys = [tuple(str(value) for value in row) for row in rows]
    _require(keys == sorted(keys), "graph export rows must be sorted")
    _require(isinstance(document["truncated"], bool) and isinstance(document["row_count"], int),
             "graph export counts are invalid")
    if document["truncated"]:
        _require(document["row_count"] >= len(rows), "truncated export row_count must cover the omitted rows")
    else:
        _require(document["row_count"] == len(rows), "graph export row_count differs from its rows")
    _require(bool(_SHA256.fullmatch(str(document["bqrs_sha256"]))), "graph export bqrs_sha256 is invalid")


@dataclass(frozen=True, slots=True)
class GraphSettings:
    max_call_depth: int = 3
    max_neighbors_per_function: int = 200
    max_paths_per_sink: int = 8
    max_path_steps: int = 40
    max_guards_per_sink: int = 16
    max_facts_per_family_per_scope: int = 200000
    max_export_bytes: int = 268435456
    export_timeout_seconds: int = 1800

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            _require(isinstance(value, int) and not isinstance(value, bool) and value > 0,
                     f"graph setting {item.name} must be a positive integer")
        _require(self.max_call_depth <= MAX_TOOL_DEPTH, f"max_call_depth may not exceed {MAX_TOOL_DEPTH}")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "GraphSettings":
        value = dict(value or {})
        unknown = set(value) - {item.name for item in fields(cls)}
        _require(not unknown, f"unknown graph settings: {', '.join(sorted(unknown))}")
        return cls(**value)
