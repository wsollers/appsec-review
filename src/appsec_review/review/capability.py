"""In-process review-cell capability (design R2).

A capability is a frozen record bound by SHA-256 to one run, accepted manifest, package, role,
round, closed tool and index allowlists, entity scope, and caps. `authorize` decides one
model-proposed retrieval request. A model asking for something outside the capability is
expected adversarial input: the answer is an `AuthorityDenied` value, which the cell records as an
`authority_error` gap and security event. Only a capability that fails its own hash check raises,
because that means the application, not the model, is wrong.

The tool catalog is `appsec_review.mcp.schema.TOOLS`, the runtime source that
`docs/schemas/retrieval-mcp-tools.json` is tested to match.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
import hmac
import math
import re
from typing import Any, Mapping

from appsec_review.graph.contract import FAMILY_KINDS, GRAPH_INDEX, QUERY_CODE_GRAPH
from appsec_review.mcp.schema import TOOLS
from appsec_review.retrieval.graph import request_error as graph_request_error
from appsec_review.retrieval.index import INDEX_NAMES
from appsec_review.retrieval.neighborhood import LIST_CODEQL_DATABASES, QUERY_CODEQL_NEIGHBORHOOD
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError, Role

CAPABILITY_SCHEMA = "appsec-review/cell-capability/1"

# Tools a cell may run in-process on `RetrievalCore`. The OWASP workbench query reads a separate
# store through the MCP adapter, so it is not grantable to a review cell.
IN_PROCESS_TOOLS = frozenset(tool["name"] for tool in TOOLS) - {"query_owasp_workbench"}
TOOL_SCHEMAS: Mapping[str, Mapping[str, Any]] = {
    tool["name"]: tool["inputSchema"] for tool in TOOLS if tool["name"] in IN_PROCESS_TOOLS}

# Indexes each tool reads when it takes no `indexes` parameter. Identity-addressed tools
# (`read_excerpt`, `trace`, `resolve_evidence`) are bounded by entity scope instead.
TOOL_INDEXES: Mapping[str, frozenset[str]] = {
    "query_artifacts": frozenset({"artifacts", "observations", "evidence"}),
    "query_build_security": frozenset({"build_security"}),
    "query_ci_configuration": frozenset({"observations", "evidence"}),
    "query_codeql": frozenset({"observations"}),
    "query_change_context": frozenset({"history"}),
    "query_hotspots": frozenset({"priority"}),
    "query_precomputed": frozenset({"precomputed"}),
    "query_observations": frozenset({"observations", "precomputed"}),
    "query_dataset_inventory": frozenset({"inventory"}),
    QUERY_CODE_GRAPH: frozenset({GRAPH_INDEX}),
    LIST_CODEQL_DATABASES: frozenset({GRAPH_INDEX}),
    QUERY_CODEQL_NEIGHBORHOOD: frozenset({GRAPH_INDEX}),
}
INDEX_PARAMETER_TOOLS = frozenset({"search", "find", "coverage"})
IDENTITY_TOOLS = frozenset({"read_excerpt", "trace", "resolve_evidence"})
IDENTITY_PARAMETERS = frozenset({"identity", "subject", "source", "artifact", "artifact_identity",
                                 "producing_build_action", "database", "observation"})
# Parameter names that address the filesystem or a query language are never grantable.
FORBIDDEN_PARAMETERS = frozenset({"path", "paths", "glob", "regex", "pattern", "sql", "query_sql",
                                  "expression", "file", "directory", "url"})
_LOGICAL_ID = re.compile(r"^asr:[a-z][a-z0-9_]*:[0-9a-f]{64}$")
# Entity kinds a ``graph`` shard publishes: the seven fact families plus the CodeQL-export function
# symbols that contain them. Each carries ``payload.scope.scope_id`` (graph-fact/1 and the graph job's
# symbol payload), which is what a scope-bound graph grant is checked against.
GRAPH_ROW_KINDS = frozenset({*(kind.value for kind in FAMILY_KINDS.values()), "symbol", "codeql_database",
                             "ir_entity", "tool_observation"})
_SCOPE_ID = re.compile(r"^[!-~]{1,256}$")   # printable, no whitespace; compared by equality only
_PATH_LIKE = re.compile(r"(^[/~]|^[A-Za-z]:[\\/]|\.\.|\\|\x00|^file:|://)")
_REGEX_LIKE = re.compile(r"(\.\*|\.\+|\(\?|\[\^|\[[^\]]*-[^\]]*\]|\{\d+(,\d*)?\}|\||(?<!\w)\^|\$$)")
# Statement syntax only: searching for SQL *words* in target code stays possible because the core
# quotes every search term, but statement separators, comments, and set/schema operators do not.
_SQL_LIKE = re.compile(r"(?i)(;|--|/\*|\*/|\bunion\s+(all\s+)?select\b|\b(drop|attach|detach|pragma)\s+\w)")
_PARAMETER_EXEMPT_FROM_TEXT_CHECK = frozenset({"cursor"})   # HMAC-verified by the core


@dataclass(frozen=True, slots=True)
class Authorized:
    tool: str
    parameters: Mapping[str, Any]        # normalized: allowlisted indexes and page size applied
    filter_sha256: str


@dataclass(frozen=True, slots=True)
class AuthorityDenied:
    code: str                            # closed machine code; reason is bounded commentary
    reason: str
    filter_sha256: str


_DENIAL_CODES = frozenset({"malformed_request", "unknown_tool", "tool_not_granted", "schema_violation",
                           "forbidden_parameter", "path_like_value", "regex_like_value", "sql_like_value",
                           "entity_out_of_scope", "index_not_granted", "query_cap_exceeded",
                           "page_cap_exceeded", "depth_cap_exceeded"})


@dataclass(frozen=True, slots=True)
class CellCapability:
    run_id: str
    manifest_sha256: str
    package_id: str
    package_sha256: str
    role: Role
    round: int
    tools: tuple[str, ...]
    indexes: tuple[str, ...]
    entities: tuple[str, ...]            # exact accepted logical identities
    entity_prefixes: tuple[str, ...]     # e.g. "asr:source_span:"; never the empty prefix
    # CodeQL scope ids whose accepted graph facts belong to this package's scope (its build unit or
    # paths; ``retrieval.graph_scopes``). A graph row is in scope only when its own
    # ``payload.scope.scope_id`` is listed; this is never a kind-wide grant across scopes.
    graph_scopes: tuple[str, ...]
    max_queries: int
    max_turns: int
    page_size: int
    max_depth: int
    max_result_bytes: int
    capability_sha256: str = field(default="")

    @classmethod
    def issue(cls, *, run_id: str, manifest_sha256: str, package_id: str, package_sha256: str,
              role: Role | str, round: int, tools, indexes, entities=(), entity_prefixes=(),
              graph_scopes=(), max_queries: int, max_turns: int, page_size: int, max_depth: int,
              max_result_bytes: int) -> "CellCapability":
        """Issue a capability; an unknown tool, index, or cap is an application error."""
        values = {
            "run_id": str(run_id), "manifest_sha256": str(manifest_sha256),
            "package_id": str(package_id), "package_sha256": str(package_sha256),
            "role": Role(role), "round": int(round),
            "tools": tuple(sorted(set(tools))), "indexes": tuple(sorted(set(indexes))),
            "entities": tuple(sorted(set(entities))),
            "entity_prefixes": tuple(sorted(set(entity_prefixes))),
            "graph_scopes": tuple(sorted(set(graph_scopes))),
            "max_queries": int(max_queries), "max_turns": int(max_turns),
            "page_size": int(page_size), "max_depth": int(max_depth),
            "max_result_bytes": int(max_result_bytes),
        }
        if unknown := set(values["tools"]) - IN_PROCESS_TOOLS:
            raise ValueError(f"capability names tools outside the in-process catalog: {sorted(unknown)}")
        if unknown := set(values["indexes"]) - set(INDEX_NAMES):
            raise ValueError(f"capability names unknown indexes: {sorted(unknown)}")
        if any(not _LOGICAL_ID.fullmatch(item) for item in values["entities"]):
            raise ValueError("capability entity scope holds a non-logical identity")
        if any(not re.fullmatch(r"asr:([a-z][a-z0-9_]*:([0-9a-f]{0,64})?)?", item) or item == ""
               for item in values["entity_prefixes"]):
            raise ValueError("capability entity prefix is not a logical-identity prefix")
        if any(not isinstance(item, str) or not _SCOPE_ID.fullmatch(item) for item in values["graph_scopes"]):
            raise ValueError("capability graph scope is not a CodeQL scope id")
        if values["graph_scopes"] and GRAPH_INDEX not in values["indexes"]:
            raise ValueError("a graph scope grant requires the graph index")
        if values["round"] < 0 or min(values["max_queries"], values["max_turns"], values["page_size"],
                                      values["max_depth"], values["max_result_bytes"]) < 1:
            raise ValueError("capability caps must be positive")
        if values["page_size"] > 100 or values["max_depth"] > 8:
            raise ValueError("capability caps exceed the retrieval tool bounds")
        unsigned = cls(**values)
        return cls(**values, capability_sha256=unsigned.compute_sha256())

    def body(self) -> dict[str, Any]:
        return {"schema": CAPABILITY_SCHEMA, **{
            item.name: (getattr(self, item.name).value if item.name == "role" else
                        list(getattr(self, item.name)) if isinstance(getattr(self, item.name), tuple)
                        else getattr(self, item.name))
            for item in fields(self) if item.name != "capability_sha256"}}

    def compute_sha256(self) -> str:
        return sha256_hex(self.body())

    def semantic_body(self) -> dict[str, Any]:
        """The capability inputs to a cell fingerprint: tools, indexes, scope, and caps."""
        body = self.body()
        return {key: body[key] for key in ("tools", "indexes", "entities", "entity_prefixes", "graph_scopes",
                                            "max_queries", "max_turns", "page_size", "max_depth",
                                            "max_result_bytes")}

    def public_view(self) -> dict[str, Any]:
        """The trusted capability/budget receipt shown to the worker."""
        return {"capability_sha256": self.capability_sha256, **self.semantic_body()}

    def verify(self) -> None:
        if not self.capability_sha256 or not hmac.compare_digest(self.capability_sha256,
                                                                   self.compute_sha256()):
            raise IntegrityError("cell capability failed its hash check")

    def entity_in_scope(self, identity: str) -> bool:
        return isinstance(identity, str) and bool(_LOGICAL_ID.fullmatch(identity)) and (
            identity in self.entities or any(identity.startswith(prefix) for prefix in self.entity_prefixes))

    def graph_row_in_scope(self, row: Mapping[str, Any]) -> bool:
        """Whether one returned graph entity row belongs to a granted CodeQL scope.

        The row must be a ``graph``-index entity of a graph kind whose own identity is a logical
        identity of that kind, and its accepted payload must name a ``scope.scope_id`` this capability
        lists. The payload comes from the retrieval core's accepted shard, never from the model.
        """
        if not self.graph_scopes or not isinstance(row, Mapping) or row.get("index") != GRAPH_INDEX:
            return False
        identity, kind = row.get("identity"), row.get("kind")
        if kind not in GRAPH_ROW_KINDS or not isinstance(identity, str) or not _LOGICAL_ID.fullmatch(identity) \
                or not identity.startswith(f"asr:{kind}:"):
            return False
        payload = row.get("payload")
        scope = payload.get("scope") if isinstance(payload, Mapping) else None
        return isinstance(scope, Mapping) and scope.get("scope_id") in self.graph_scopes

    def authorize(self, request: Any, *, queries_used: int = 0,
                  granted: frozenset[str] | set[str] = frozenset()) -> Authorized | AuthorityDenied:
        """Authorize one `{"tool", "parameters"}` request; never raises for model input.

        ``granted`` holds identities this cell already received in scope-checked graph rows (see
        :meth:`graph_row_in_scope`); they may be addressed like package entities.
        """
        self.verify()
        try:
            filter_sha = sha256_hex(request)
        except (TypeError, ValueError):
            filter_sha = sha256_hex(repr(request)[:4096])

        def deny(code: str, reason: str) -> AuthorityDenied:
            assert code in _DENIAL_CODES
            return AuthorityDenied(code, reason[:256], filter_sha)

        if not isinstance(request, Mapping) or set(request) - {"tool", "parameters"} or \
                not isinstance(request.get("tool"), str):
            return deny("malformed_request", "a request is exactly {tool, parameters}")
        tool = request["tool"]
        parameters = request.get("parameters", {})
        if not isinstance(parameters, Mapping) or any(not isinstance(key, str) for key in parameters):
            return deny("malformed_request", "parameters must be an object")
        if tool not in TOOL_SCHEMAS:
            return deny("unknown_tool", "tool is not in the retrieval catalog")
        if tool not in self.tools:
            return deny("tool_not_granted", f"{tool} is not granted to this cell")
        if forbidden := sorted(set(parameters) & FORBIDDEN_PARAMETERS):
            return deny("forbidden_parameter", f"parameter is never grantable: {forbidden[0]}")
        schema = TOOL_SCHEMAS[tool]
        error = _schema_error(parameters, schema)
        if error:
            return deny("schema_violation", error)
        if tool == QUERY_CODE_GRAPH and (error := graph_request_error(parameters)):
            return deny("schema_violation", error)
        for key, value in parameters.items():
            for text in _strings(value):
                if key in _PARAMETER_EXEMPT_FROM_TEXT_CHECK or (key in IDENTITY_PARAMETERS and
                                                                 _LOGICAL_ID.fullmatch(text)):
                    continue
                if _PATH_LIKE.search(text):
                    return deny("path_like_value", f"{key} looks like a filesystem path")
                if _REGEX_LIKE.search(text):
                    return deny("regex_like_value", f"{key} looks like a regular expression")
                if _SQL_LIKE.search(text):
                    return deny("sql_like_value", f"{key} looks like a query language")
        for key in sorted(set(parameters) & IDENTITY_PARAMETERS):
            if not (self.entity_in_scope(parameters[key]) or parameters[key] in granted):
                return deny("entity_out_of_scope", f"{key} is outside the package entity scope")
        if tool in IDENTITY_TOOLS and "identity" not in parameters:
            return deny("schema_violation", f"{tool} requires an identity")
        normalized = dict(parameters)
        if tool in INDEX_PARAMETER_TOOLS:
            requested = parameters.get("indexes")
            if requested is None:
                if not self.indexes:
                    return deny("index_not_granted", "no index is granted to this cell")
                normalized["indexes"] = list(self.indexes)
            elif not requested or set(requested) - set(self.indexes):
                return deny("index_not_granted", "requested index is not granted")
        elif tool in TOOL_INDEXES and not TOOL_INDEXES[tool] <= set(self.indexes):
            return deny("index_not_granted", f"{tool} reads indexes not granted to this cell")
        if "limit" in schema["properties"]:
            if int(parameters.get("limit", self.page_size)) > self.page_size:
                return deny("page_cap_exceeded", "limit exceeds the cell page size")
            normalized.setdefault("limit", self.page_size)
        if tool == "trace":
            if int(parameters.get("depth", 2)) > self.max_depth:
                return deny("depth_cap_exceeded", "trace depth exceeds the cell depth cap")
            normalized.setdefault("depth", min(2, self.max_depth))
        if tool == QUERY_CODE_GRAPH and int(parameters.get("depth", 1)) > self.max_depth:
            return deny("depth_cap_exceeded", "graph closure depth exceeds the cell depth cap")
        if tool == QUERY_CODEQL_NEIGHBORHOOD and int(parameters.get("depth", 0)) > self.max_depth:
            return deny("depth_cap_exceeded", "neighborhood depth exceeds the cell depth cap")
        if queries_used >= self.max_queries:
            return deny("query_cap_exceeded", "the cell query budget is exhausted")
        return Authorized(tool, normalized, sha256_hex({"tool": tool, "parameters": normalized}))


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _schema_error(value: Mapping[str, Any], schema: Mapping[str, Any]) -> str | None:
    """The closed JSON-schema subset the retrieval catalog uses."""
    properties = schema.get("properties", {})
    if unknown := sorted(set(value) - set(properties)):
        return f"unknown parameter: {unknown[0][:64]}"
    if missing := sorted(set(schema.get("required", ())) - set(value)):
        return f"missing parameter: {missing[0]}"
    for key, child in value.items():
        if error := _value_error(child, properties[key]):
            return f"{key}: {error}"
    return None


def _value_error(value: Any, schema: Mapping[str, Any]) -> str | None:
    kind = schema.get("type")
    if kind == "string" or (kind is None and "enum" in schema):
        if not isinstance(value, str):
            return "must be a string"
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 4096):
            return "string length out of bounds"
        if "pattern" in schema and not re.fullmatch(schema["pattern"].strip("^$"), value):
            return "does not match the declared format"
    elif kind == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            return "must be an integer"
    elif kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return "must be a finite number"
    elif kind == "boolean":
        if not isinstance(value, bool):
            return "must be a boolean"
    elif kind == "array":
        if not isinstance(value, list) or len(value) > 64:
            return "must be a bounded array"
        if schema.get("uniqueItems") and len({repr(item) for item in value}) != len(value):
            return "items must be unique"
        for item in value:
            if error := _value_error(item, schema.get("items", {})):
                return error
        return None
    else:
        return "unsupported parameter type"
    if "enum" in schema and value not in schema["enum"]:
        return "value is not in the closed set"
    if "minimum" in schema and value < schema["minimum"]:
        return "below minimum"
    if "maximum" in schema and value > schema["maximum"]:
        return "above maximum"
    return None


__all__ = ["AuthorityDenied", "Authorized", "CAPABILITY_SCHEMA", "CellCapability", "GRAPH_ROW_KINDS",
           "IN_PROCESS_TOOLS", "TOOL_INDEXES", "TOOL_SCHEMAS"]
