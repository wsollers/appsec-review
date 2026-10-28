"""One bounded, hash-pinned query surface for DWARF and PDB normalized evidence."""
from __future__ import annotations

from contextlib import ExitStack, closing
import json
import time
from typing import Any, Mapping

from appsec_review.debug_symbols.contract import INDEX_NAME, MAX_LIMIT, QUERY_TOOL, QueryMode, RecordKind
from appsec_review.graph.contract import FAMILY_KINDS
from appsec_review.retrieval.debug_symbol_index import ARTIFACT_KINDS, address_prefixes
from appsec_review.retrieval.model import EntityKind, LogicalIdentity

ARGUMENTS = frozenset({"mode", "artifact_identity", "subject", "address", "limit", "cursor"})
_MODE_KIND = {
    QueryMode.SYMBOL: RecordKind.SYMBOL, QueryMode.SOURCE_RANGES: RecordKind.SOURCE_RANGE,
    QueryMode.TYPE_LAYOUT: RecordKind.TYPE_LAYOUT, QueryMode.INLINE_FRAMES: RecordKind.INLINE_FRAME,
    QueryMode.COMPILATION_UNITS: RecordKind.COMPILATION_UNIT,
}
_SUBJECT_KINDS = {
    QueryMode.SYMBOL: {EntityKind.SYMBOL},
    QueryMode.ADDRESS: {EntityKind.SYMBOL, EntityKind.SOURCE_SPAN, EntityKind.IR_ENTITY, EntityKind.COMPILE_UNIT},
    QueryMode.SOURCE_RANGES: {EntityKind.SOURCE_FILE, EntityKind.SOURCE_SPAN, EntityKind.SYMBOL, EntityKind.COMPILE_UNIT},
    QueryMode.TYPE_LAYOUT: {EntityKind.SYMBOL, EntityKind.IR_ENTITY},
    QueryMode.INLINE_FRAMES: {EntityKind.SYMBOL, EntityKind.IR_ENTITY},
    QueryMode.COMPILATION_UNITS: {EntityKind.COMPILE_UNIT},
    QueryMode.GRAPH_LINKS: {EntityKind.SYMBOL, EntityKind.SOURCE_SPAN, EntityKind.IR_ENTITY, EntityKind.COMPILE_UNIT},
    QueryMode.COVERAGE: set(),
}
MAX_OFFSET = 100_000


def request_error(parameters: Mapping[str, Any]) -> str | None:
    if set(parameters) - ARGUMENTS:
        return "unknown debug-symbol query parameters"
    try:
        mode = QueryMode(parameters.get("mode"))
    except (ValueError, TypeError):
        return "mode is not in the closed debug-symbol set"
    for key in ("subject", "artifact_identity"):
        if parameters.get(key) is None:
            continue
        try:
            kind = LogicalIdentity.parse(parameters[key]).kind
        except (ValueError, TypeError):
            return f"{key} must be an exact accepted logical identity"
        if kind not in (ARTIFACT_KINDS if key == "artifact_identity" else _SUBJECT_KINDS[mode]):
            return f"mode {mode.value} does not accept this {key} kind"
    if mode in {QueryMode.ADDRESS, QueryMode.COVERAGE} and not parameters.get("artifact_identity"):
        return f"mode {mode.value} requires artifact_identity"
    if mode is QueryMode.GRAPH_LINKS and not parameters.get("subject"):
        return "graph_links requires an exact subject; artifact-wide inferred graph joins are not supported"
    if not parameters.get("subject") and not parameters.get("artifact_identity"):
        return f"mode {mode.value} requires an exact subject or artifact_identity"
    address = parameters.get("address")
    if mode is QueryMode.ADDRESS:
        if type(address) is not int or not 0 <= address < 2**64:
            return "address must be an unsigned 64-bit build-relative integer"
    elif address is not None:
        return "address applies only to address mode"
    limit = parameters.get("limit", 20)
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        return f"limit must be an integer between 1 and {MAX_LIMIT}"
    cursor = parameters.get("cursor")
    if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 4096):
        return "cursor must be a bounded query-bound token"
    return None


def row_in_scope(row: Mapping[str, Any], in_scope, graph_scopes=()) -> bool:
    """Closure over an accepted artifact, verified source or exact native parent; never kind-wide."""
    if not isinstance(row, Mapping) or row.get("index") != INDEX_NAME:
        return False
    try:
        identity = LogicalIdentity.parse(row.get("identity"))
    except (ValueError, TypeError):
        return False
    data = row.get("payload")
    if not isinstance(data, Mapping) or row.get("kind") != identity.kind.value:
        return False
    artifact = data.get("artifact_identity")
    try:
        artifact_kind = LogicalIdentity.parse(artifact).kind
    except (ValueError, TypeError):
        return False
    if artifact_kind not in ARTIFACT_KINDS:
        return False
    if not any(isinstance(value, str) and in_scope(value) for value in (
        row["identity"], artifact, data.get("source_identity"), data.get("parent_identity"))):
        return False
    return all(isinstance(link, Mapping) and link.get("exact") is True and
               (in_scope(link.get("graph_identity")) or link.get("graph_scope") in graph_scopes)
               for link in row.get("graph_links", ()))


def _graph_links(core, databases, subject, deadline, limit):
    links: dict[str, dict[str, Any]] = {}
    truncated = False
    graph_databases = [(shard, database) for shard, database in databases if shard["name"] == "graph"]
    allowed = {kind.value for kind in FAMILY_KINDS.values()}
    for _shard, database in databases:
        core._check_deadline(deadline)
        rows = database.execute(
            "SELECT * FROM relations WHERE exact=1 AND ambiguity IS NULL AND "
            "(source_id=? OR target_id=?) ORDER BY relation_id LIMIT ?",
            (subject, subject, limit + 1)).fetchall()
        truncated |= len(rows) > limit
        for relation in rows:
            endpoint = relation["target_id"] if relation["source_id"] == subject else relation["source_id"]
            if LogicalIdentity.parse(endpoint).kind.value not in allowed:
                continue
            for shard, graph_db in graph_databases:
                fact = graph_db.execute("SELECT identity,payload_json FROM entities WHERE identity=?", (endpoint,)).fetchone()
                if fact:
                    scope = json.loads(fact["payload_json"]).get("scope", {})
                    links[relation["relation_id"]] = {
                        "relation_id": relation["relation_id"], "kind": relation["kind"],
                        "source_id": relation["source_id"], "target_id": relation["target_id"],
                        "exact": True, "confidence": relation["confidence"],
                        "graph_identity": endpoint, "graph_shard_sha256": shard["sha256"],
                        "graph_scope": scope.get("scope_id") if isinstance(scope, Mapping) else None,
                    }
                    break
    return [links[key] for key in sorted(links)][:limit], truncated or len(links) > limit


def query_debug_symbols(core, *, mode: str, artifact_identity: str | None = None,
                        subject: str | None = None, address: int | None = None,
                        limit: int = 20, cursor: str | None = None) -> dict[str, Any]:
    parameters = dict(mode=mode, artifact_identity=artifact_identity, subject=subject,
                      address=address, limit=limit, cursor=cursor)
    if error := request_error(parameters):
        raise ValueError(error)
    if limit > core.limits.max_results:
        raise ValueError("limit exceeds retrieval result bound")
    query_mode = QueryMode(mode)
    request_hash = core._request_hash(QUERY_TOOL, parameters)
    offset = core._offset(cursor, request_hash)
    if offset > MAX_OFFSET:
        raise ValueError("debug-symbol cursor exceeds maximum page traversal")
    targets = {(shard.get("producer") or {}).get("compiler_target")
               for shard in core.indexes.get(INDEX_NAME, ())
               if (shard.get("producer") or {}).get("compiler_target") in {"clang", "msvc"}}

    def completed(response=None, *, failed=False, duration_ms=0):
        core.log.write("DEBUG_SYMBOL_QUERY_COMPLETED", run_id=core.run_id, job_id="retrieval",
                       trigger="mcp", orchestrator="retrieval", details={
                           "mode": query_mode.value,
                           "compiler_target": next(iter(targets)) if len(targets) == 1 else "mixed" if targets else "unknown",
                           "returned_count": len(response["results"]) if response else 0,
                           "gap_count": len(response["coverage_gaps"]) if response else 1,
                           "duration_ms": response["duration_ms"] if response else duration_ms,
                           "truncated_count": int(response["truncated"]) if response else 0,
                           "terminal_status": ("FAILED" if failed else "COMPLETED_WITH_GAPS"
                                               if response and response["coverage_gaps"] else "SUCCEEDED"),
                       })

    def operation(deadline):
        gaps: list[str] = []
        rows: dict[str, dict[str, Any]] = {}
        shards = core.indexes.get(INDEX_NAME, ())
        if not shards:
            return [], ["accepted debug_symbols index is unavailable"], False, offset
        bound = offset + limit + 1
        covered = False
        link_truncated = False
        with ExitStack() as stack:
            opened = [(shard, stack.enter_context(closing(core._database(shard, deadline)))) for shard in shards]
            graph = []
            if query_mode is QueryMode.GRAPH_LINKS:
                graph = [(shard, stack.enter_context(closing(core._database(shard, deadline))))
                         for shard in core.indexes.get("graph", ())]
                if not graph:
                    gaps.append("accepted graph index is unavailable; debug data does not establish graph edges")
            for shard, database in opened:
                core._check_deadline(deadline)
                if artifact_identity:
                    scoped_artifacts = [artifact_identity]
                    if not database.execute(
                        "SELECT 1 FROM debug_symbol_records WHERE artifact_identity=? UNION ALL "
                        "SELECT 1 FROM coverage WHERE area=? LIMIT 1",
                        (artifact_identity, artifact_identity)).fetchone():
                        continue
                else:
                    scoped_artifacts = [row[0] for row in database.execute(
                        "SELECT artifact_identity FROM debug_symbol_records WHERE identity=? UNION "
                        "SELECT artifact_identity FROM debug_symbol_records WHERE source_identity=? LIMIT 101",
                        (subject, subject))]
                    if not scoped_artifacts:
                        continue
                    if len(scoped_artifacts) > 100:
                        gaps.append("source-to-artifact coverage inventory bound reached")
                covered = True
                target = (shard.get("producer") or {}).get("compiler_target")
                if target in {"clang", "msvc"}:
                    targets.add(target)
                if shard.get("gaps"):
                    gaps.append(f"debug_symbols shard reports {len(shard['gaps'])} unscoped gaps; "
                                "only exact artifact coverage is published")
                coverage = [dict(row) for row in database.execute(
                    "SELECT area,status,gap FROM coverage WHERE area IN (" +
                    ",".join("?" for _ in scoped_artifacts) +
                    ") ORDER BY area,status,gap LIMIT 201", scoped_artifacts)]
                if not coverage:
                    gaps.append("exact artifact debug-symbol coverage inventory is unavailable")
                gaps.extend(f"debug_symbols: {row['area']}: {row['status']}" +
                            (f": {row['gap']}" if row["gap"] else "")
                            for row in coverage if row["status"] != "complete" or row["gap"])
                if len(coverage) > 200:
                    gaps.append("debug-symbol coverage row bound reached")
                if query_mode is QueryMode.COVERAGE:
                    rows[str(shard.get("shard_id", "default"))] = {
                        "identity": artifact_identity, "kind": LogicalIdentity.parse(artifact_identity).kind.value,
                        "index": INDEX_NAME, "shard_id": str(shard.get("shard_id", "default")),
                        "artifact_reference": {"index": INDEX_NAME, "identity": artifact_identity,
                                               "shard_sha256": shard["sha256"]},
                        "payload": {"artifact_identity": artifact_identity, "coverage": coverage[:200]},
                    }
                    continue
                clauses, args = [], []
                if artifact_identity:
                    clauses.append("d.artifact_identity=?")
                    args.append(artifact_identity)
                if query_mode in _MODE_KIND:
                    clauses.append("d.record_kind=?")
                    args.append(_MODE_KIND[query_mode].value)
                if subject:
                    source_kind = LogicalIdentity.parse(subject).kind
                    if query_mode is QueryMode.SOURCE_RANGES and source_kind in {
                        EntityKind.SOURCE_FILE, EntityKind.SOURCE_SPAN,
                    }:
                        clauses.append("d.identity IN (SELECT identity FROM debug_symbol_records "
                                       "WHERE source_identity=? UNION SELECT identity FROM debug_symbol_records "
                                       "WHERE identity=?)")
                        args.extend([subject, subject])
                    elif query_mode in {QueryMode.INLINE_FRAMES, QueryMode.SOURCE_RANGES}:
                        clauses.append("d.identity IN (SELECT identity FROM debug_symbol_records WHERE identity=? "
                                       "UNION SELECT child.identity FROM debug_symbol_records parent "
                                       "JOIN debug_symbol_records child ON child.artifact_identity=parent.artifact_identity "
                                       "AND child.parent_key=parent.native_key WHERE parent.identity=?)")
                        args.extend([subject, subject])
                    else:
                        clauses.append("d.identity=?")
                        args.append(subject)
                if query_mode is QueryMode.ADDRESS:
                    prefixes = address_prefixes(address)
                    clauses.append("d.identity IN (SELECT identity FROM debug_symbol_addresses "
                                   "WHERE artifact_identity=? AND prefix IN (" +
                                   ",".join("?" for _ in prefixes) + "))")
                    args.extend([artifact_identity, *prefixes])
                query = (
                    "SELECT e.*,l.*,p.identity AS parent_identity FROM debug_symbol_records d "
                    "JOIN entities e ON e.identity=d.identity "
                    "LEFT JOIN locations l ON l.entity_id=e.identity "
                    "LEFT JOIN debug_symbol_records p ON p.artifact_identity=d.artifact_identity "
                    "AND p.native_key=d.parent_key WHERE " + (" AND ".join(clauses) or "1") +
                    " ORDER BY d.identity LIMIT ?")
                for row in database.execute(query, [*args, bound]):
                    core._check_deadline(deadline)
                    item = core._entity(row, INDEX_NAME)
                    item["shard_id"] = str(shard.get("shard_id", "default"))
                    item["artifact_reference"] = {"index": INDEX_NAME, "identity": row["identity"],
                                                  "shard_sha256": shard["sha256"]}
                    item["payload"].pop("parent_identity", None)
                    if row["parent_identity"]:
                        item["payload"]["parent_identity"] = row["parent_identity"]
                    target = item["payload"].get("compiler_target")
                    if target in {"clang", "msvc"}:
                        targets.add(target)
                    if query_mode is QueryMode.GRAPH_LINKS:
                        item["graph_links"], clipped = _graph_links(
                            core, opened + graph, row["identity"], deadline, limit)
                        link_truncated |= clipped
                        if not item["graph_links"]:
                            continue
                    rows.setdefault(item["identity"], item)
        ordered = [rows[key] for key in sorted(rows)]
        if not covered:
            gaps.append("accepted debug-symbol coverage is unavailable for the requested artifact or subject")
        elif not ordered:
            gaps.append("no matching debug-symbol records within accepted coverage; not evidence of absence")
        more = len(ordered) > offset + limit
        traversal_limited = more and offset + limit > MAX_OFFSET
        if traversal_limited:
            more = False
            gaps.append("debug-symbol page traversal bound reached; additional rows were withheld")
        if more:
            gaps.append("debug-symbol row limit reached; continue with the query-bound cursor")
        if link_truncated:
            gaps.append("exact graph relationship bound reached; additional relationships were not inspected")
        return ordered[offset:offset + limit], gaps, more, offset, more or link_truncated or traversal_limited

    started = time.monotonic()
    try:
        response = core._execute(QUERY_TOOL, parameters, operation)
    except BaseException:
        completed(failed=True, duration_ms=max(0, int((time.monotonic() - started) * 1000)))
        raise
    if response["truncated"] and not response["results"] and response["pagination"]["next_cursor"]:
        response["pagination"]["next_cursor"] = None
        response["coverage_gaps"] = [
            "single debug-symbol record exceeds response byte budget; no continuation can make progress"
            if gap.startswith("response byte budget") else gap for gap in response["coverage_gaps"]]
    completed(response)
    return response
