"""Bounded syntax-only navigation and intra-procedural CFG queries; reads accepted indices only."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from typing import TYPE_CHECKING, Any, Callable, Mapping

from .model import EntityKind, LogicalIdentity, canonical_json, normalize_relative_path
from .syntax_contract import (
    CFG_SCHEMA,
    GUARD_POLARITIES,
    MAX_NAME_BYTES,
    MODES,
    QUERY_CFG_FUNCTION,
    QUERY_GUARD_DOMINATORS,
    SCHEMA,
)

if TYPE_CHECKING:
    from .core import RetrievalCore

QUERY_SYNTAX = "query_syntax"


def _match_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project just the syntax match; CFG tables and raw captures are not part of this route."""
    syntax = payload["syntax"]
    fields = ("schema", "source_identity", "category", "enclosing_definition", "resolution", "syntax_only",
              "import_expression", "import_form", "name_span")
    match = {key: syntax[key] for key in fields if key in syntax}
    omitted = 0

    def bounded(value: str) -> str:
        nonlocal omitted
        encoded = value.encode("utf-8")
        prefix = encoded[:MAX_NAME_BYTES].decode("utf-8", errors="ignore")
        omitted += len(encoded) - len(prefix.encode("utf-8"))
        return prefix

    match["written_name"] = bounded(syntax["written_name"])
    qualifiers = syntax.get("syntactic_qualifiers", ())
    match["syntactic_qualifiers"] = [bounded(name) for name in qualifiers[:8]]
    if omitted or len(qualifiers) > 8:
        match["capture_bytes_omitted"] = omitted
        match["qualifiers_omitted"] = max(0, len(qualifiers) - 8)
    return {"syntax_only": True, "syntax": match}


def row_in_scope(row: Mapping[str, Any], sources: tuple[str, ...] | list[str]) -> bool:
    """Only an exact, signed source-file identity grants syntax rows; prefixes never do."""
    payload = row.get("payload")
    syntax = payload.get("syntax") if isinstance(payload, Mapping) else None
    identity = row.get("identity")
    return (row.get("index") == "analysis" and row.get("kind") == "ast_node"
            and isinstance(identity, str) and identity.startswith("asr:ast_node:")
            and isinstance(syntax, Mapping) and syntax.get("schema") == SCHEMA
            and syntax.get("syntax_only") is True and syntax.get("source_identity") in sources
            and row.get("location") is not None)


def query_syntax(core: "RetrievalCore", *, mode: str, subject: str, name: str | None = None,
                 limit: int = 20, cursor: str | None = None) -> dict[str, Any]:
    identity = LogicalIdentity.parse(subject)
    if mode not in MODES or identity.kind not in {EntityKind.SOURCE_FILE, EntityKind.AST_NODE}:
        raise ValueError("syntax queries require a supported mode and source_file or ast_node subject")
    if name is not None and (not isinstance(name, str) or not name or len(name.encode("utf-8")) > MAX_NAME_BYTES):
        raise ValueError("syntax written name exceeds bound")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= min(100, core.limits.max_results):
        raise ValueError("syntax result limit exceeds bound")
    parameters = {"mode": mode, "subject": subject, "name": name, "limit": limit, "cursor": cursor}
    offset = core._offset(cursor, core._request_hash(QUERY_SYNTAX, parameters))

    def operation(deadline: float):
        # Source subjects already carry their immutable content identity. AST subjects also restrict
        # the answer to their own byte span, not siblings elsewhere in the source file.
        source_id = subject
        span: tuple[int, int] | None = None
        if identity.kind == EntityKind.AST_NODE:
            subject_row = None
            for shard in core.indexes.get("analysis", ()):
                if shard.get("producer", {}).get("job") != "job_tree_sitter_ast":
                    continue
                with closing(core._database(shard, deadline)) as database:
                    row = database.execute("SELECT e.*, l.* FROM entities e JOIN locations l ON l.entity_id=e.identity "
                                           "WHERE e.identity=?", (subject,)).fetchone()
                    if row is not None:
                        subject_row = core._entity(row, "analysis")
                        break
            if subject_row is None:
                return [], ["syntax subject has no accepted AST location"], False, offset
            location = subject_row["location"]
            source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, core.manifest["target_snapshot"],
                                               {"path": location["path"], "sha256": location["file_sha256"]}).value
            span = (location["start_byte"], location["end_byte"])
        found: dict[str, dict[str, Any]] = {}
        gaps = []
        available = False
        for shard in core.indexes.get("analysis", ()):
            if shard.get("producer", {}).get("job") != "job_tree_sitter_ast":
                continue
            with closing(core._database(shard, deadline)) as database:
                # This expression is backed by syntax_lookup, not a scan of source trees.
                base = ["e.kind='ast_node'", "json_extract(e.payload_json, '$.syntax.source_identity')=?",
                        "json_extract(e.payload_json, '$.syntax.schema')=?"]
                values: list[Any] = [source_id, SCHEMA]
                projection_coverage = database.execute("SELECT status, gap FROM coverage WHERE area=?",
                                                       ("syntax-projection:" + source_id,)).fetchone()
                probe = database.execute("SELECT 1 FROM entities e WHERE " + " AND ".join(base) + " LIMIT 1", values).fetchone()
                if projection_coverage is not None:
                    gaps.append(f"syntax projection {projection_coverage['status']}: {projection_coverage['gap']}")
                if probe is None:
                    available = available or (projection_coverage is not None
                                              and projection_coverage["status"] != "unavailable")
                    continue
                available = True
                if mode == "imports":
                    base.append("json_extract(e.payload_json, '$.syntax.import_expression')=1")
                else:
                    base.append("json_extract(e.payload_json, '$.syntax.category')=?")
                    values.append(MODES[mode])
                if name is not None:
                    base.append("json_extract(e.payload_json, '$.syntax.written_name')=?")
                    values.append(name)
                if span is not None:
                    base.extend(("l.start_byte>=?", "l.end_byte<=?"))
                    values.extend(span)
                sql = ("SELECT e.*, l.* FROM entities e JOIN locations l ON l.entity_id=e.identity WHERE " +
                       " AND ".join(base) + " ORDER BY e.identity LIMIT ?")
                for row in database.execute(sql, [*values, offset + limit + 1]):
                    item = core._entity(row, "analysis")
                    item["payload"] = _match_payload(item["payload"])
                    item["shard_id"] = shard.get("shard_id", "default")
                    found.setdefault(item["identity"], item)
                source = database.execute("SELECT l.path FROM locations l WHERE l.entity_id=?", (source_id,)).fetchone()
                if source is not None:
                    for row in database.execute("SELECT status, gap FROM coverage WHERE area=?", (source["path"],)):
                        if row["status"] != "complete":
                            gaps.append(f"syntax coverage {row['status']}: {row['gap']}")
        if not available:
            gaps.append("accepted syntax projection is unavailable for this source; absence is not evidence")
        # All mappings are intentionally a subset of a language's syntax; no name or call target resolves.
        gaps.append("syntax-only navigation: unresolved names and imports; not semantic references, calls or dataflow")
        ordered = [found[key] for key in sorted(found)]
        return ordered[offset:offset + limit], gaps, len(ordered) > offset + limit, offset

    return core._execute(QUERY_SYNTAX, parameters, operation)


def _cfg_coverage(
    database: sqlite3.Connection, payload: Mapping[str, Any], path: str,
) -> tuple[list[str], bool]:
    cfg = payload.get("cfg") or {}
    label = f"{path}: {cfg.get('function_id', '')}"
    reasons = list(cfg.get("gaps") or ())
    for count, records in (("node_count", "cfg_nodes"), ("edge_count", "cfg_edges")):
        if cfg.get(count) != len(payload.get(records) or ()):
            reasons.append(f"cfg_payload_incomplete:{records}")
    if cfg.get("truncated"):
        reasons.append("cfg_node_limit_reached")
    reasons.extend(f"cfg_unmodeled_construct:{kind}" for kind in cfg.get("unmodeled_constructs") or ())
    complete = cfg.get("coverage_status") == "complete" and not reasons
    status = cfg.get("coverage_status")
    if status not in {"complete", "partial"}:
        reasons.append("CFG coverage unknown: missing completeness metadata")
    elif not complete and not reasons:
        reasons.append("CFG coverage partial")
    gaps = [f"{label}: {reason}" for reason in dict.fromkeys(reasons)]
    areas = (path, "cfg:" + str(cfg.get("source_identity", "")),
             "cfg-ast-projection:" + str(cfg.get("function_id", "")))
    for row in database.execute("SELECT area,status,gap FROM coverage WHERE area IN (?,?,?) ORDER BY area,status,gap", areas):
        if row["status"] != "complete":
            gaps.append(f"{row['area']}: coverage {row['status']}: {row['gap'] or 'coverage incomplete'}")
            if row["area"] == path:
                complete = False
    return gaps, complete


def _cfg_occurrence(node: Mapping[str, Any]) -> tuple:
    if node.get("ast_identity"):
        return ("ast", node["ast_identity"])
    if node.get("ordinal_path"):
        return ("ordinal", tuple(node["ordinal_path"]))
    return ("node", node["node_id"])


def _common_occurrence_guards(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(guard: Mapping[str, Any]) -> str:
        # Cloned branch nodes differ by CFG id, but a common guard must still
        # resolve to the same source branch, arm and predicate in every context.
        return json.dumps({**guard, "branch_node_id": guard.get("branch_ast_identity") or guard["branch_node_id"]},
                          sort_keys=True, separators=(",", ":"))

    common = {key(g) for g in nodes[0].get("guard_dominators") or ()}
    for node in nodes[1:]:
        common.intersection_update(key(g) for g in node.get("guard_dominators") or ())
    return [g for g in nodes[0].get("guard_dominators") or () if key(g) in common]


def _sanitize_cfg_function_record(
    raw_payload: Mapping[str, Any],
    *,
    ast_identity: str,
    rel_path: str,
    file_sha256: str,
    shard_id: str,
    guards_complete: bool,
) -> dict[str, Any]:
    cfg = dict(raw_payload.get("cfg") or {})
    nodes = [dict(n) for n in (raw_payload.get("cfg_nodes") or ())]
    edges = [dict(e) for e in (raw_payload.get("cfg_edges") or ())]
    for node in nodes:
        node["path"] = rel_path
        node["file_sha256"] = file_sha256
        if not guards_complete:
            node["guard_dominators"] = []
    for edge in edges:
        edge["path"] = rel_path
    nodes.sort(key=lambda n: (int(n.get("start_line", 0)), int(n.get("start_byte", 0)), str(n.get("node_id", ""))))
    edges.sort(key=lambda e: str(e.get("edge_id", "")))
    return {
        "schema": CFG_SCHEMA,
        "ast_identity": ast_identity,
        "function_id": str(cfg.get("function_id", "")),
        "function_name": str(cfg.get("function_name", "")),
        "qualified_name": str(cfg.get("qualified_name", cfg.get("function_name", ""))),
        "language": str(cfg.get("language", "")),
        "source_identity": str(cfg.get("source_identity", "")),
        "path": rel_path,
        "file_sha256": file_sha256,
        "start_line": int(cfg.get("start_line", 1)),
        "end_line": int(cfg.get("end_line", 1)),
        "start_byte": int(cfg.get("start_byte", 0)),
        "end_byte": int(cfg.get("end_byte", 0)),
        "entry_node_id": str(cfg.get("entry_node_id", "")),
        "exit_node_id": str(cfg.get("exit_node_id", "")),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "guard_count": int(cfg.get("guard_count", 0)),
        "parameters": list(cfg.get("parameters") or ()),
        "decorators": list(cfg.get("decorators") or ()),
        "is_entrypoint_candidate": bool(cfg.get("is_entrypoint_candidate", False)),
        "entrypoint_route": cfg.get("entrypoint_route"),
        "shard_id": shard_id,
        "nodes": nodes,
        "edges": edges,
    }


_CFG_ORDER = (
    "l.path", "json_extract(e.payload_json, '$.cfg.start_line')",
    "json_extract(e.payload_json, '$.cfg.end_line')",
    "json_extract(e.payload_json, '$.cfg.function_id')",
)


def _cfg_page_state(core: "RetrievalCore", cursor: str | None, request_hash: str, *, compact: bool = False):
    state = core._cursor_state(cursor, request_hash)
    position = state.get("position", {"function": None, "block": None})
    if not isinstance(position, dict) or set(position) != {"function", "block"}:
        raise ValueError("invalid CFG cursor position")
    block_types = (int, int) if compact else (int, int, str)
    for field, types in (("function", (str, int, int, str)), ("block", block_types)):
        key = position[field]
        if key is not None and (not isinstance(key, list) or len(key) != len(types)
                                or any(type(value) is not kind for value, kind in zip(key, types))):
            raise ValueError("invalid CFG cursor position")
    if (state["offset"] and position["function"] is None
            or position["block"] is not None and position["function"] is None):
        raise ValueError("invalid CFG cursor position")
    if compact and position["block"] is not None and min(position["block"]) < 0:
        raise ValueError("invalid CFG cursor offsets")
    return state["offset"], position


def _cfg_candidates(core: "RetrievalCore", deadline: float, filters, position, bound: int):
    """Merge a bounded metadata page; do not bring CFG payloads across the SQLite boundary."""
    found = {}
    for shard in core.indexes.get("analysis", ()):
        if shard.get("producer", {}).get("job") != "job_tree_sitter_ast":
            continue
        core._check_deadline(deadline)
        with closing(core._database(shard, deadline)) as database:
            selected = filters(database)
            if selected is None:
                continue
            clauses, values, context = selected
            clauses = ["e.kind='ast_node'", "json_extract(e.payload_json, '$.cfg.schema')=?", *clauses]
            values = [CFG_SCHEMA, *values]
            if position["function"] is not None:
                comparison = ">=" if position["block"] is not None else ">"
                clauses.append(f"({','.join(_CFG_ORDER)}) {comparison} (?,?,?,?)")
                values.extend(position["function"])
            sql = ("SELECT e.identity, " + ", ".join(
                f"{expression} AS k{index}" for index, expression in enumerate(_CFG_ORDER)
            ) + " FROM entities e JOIN locations l ON l.entity_id=e.identity WHERE " +
                " AND ".join(clauses) + " ORDER BY " + ",".join(_CFG_ORDER) + ",e.identity LIMIT ?")
            for row in database.execute(sql, [*values, bound + 1]):
                core._check_deadline(deadline)
                key = tuple(row[f"k{index}"] for index in range(4))
                found.setdefault(key, (shard, row["identity"], context))
            found = {key: found[key] for key in sorted(found)[:bound + 1]}
    return [(key, *found[key]) for key in sorted(found)]


def _load_cfg(core: "RetrievalCore", deadline: float, shard, identity, *, compact=False):
    core._check_deadline(deadline)
    with closing(core._database(shard, deadline)) as database:
        row = database.execute(
            "SELECT e.identity,e.payload_json,l.path,l.file_sha256 FROM entities e "
            "JOIN locations l ON l.entity_id=e.identity WHERE e.identity=?", (identity,),
        ).fetchone()
        rel_path = normalize_relative_path(row["path"])
        payload = json.loads(row["payload_json"])
        gaps, complete = _cfg_coverage(database, payload, rel_path)
        record = _sanitize_cfg_function_record(
            payload, ast_identity=identity, rel_path=rel_path, file_sha256=row["file_sha256"],
            shard_id=str(shard.get("shard_id", "default")), guards_complete=complete)
        if compact:
            for count in ("node_count", "edge_count"):
                record[count] = payload["cfg"].get(count, record[count])
        return record, gaps


_CFG_SUMMARY = ("schema", "ast_identity", "function_id", "function_name", "qualified_name", "source_identity",
                "path", "file_sha256", "language", "start_line", "end_line", "entry_node_id", "exit_node_id",
                "node_count", "edge_count", "guard_count")
_CFG_NODE = ("node_id", "ast_identity", "kind", "start_line", "end_line", "start_byte", "end_byte",
             "guard_expression", "guard_polarity", "calls")
_CFG_EDGE = ("edge_id", "source_node_id", "target_node_id", "edge_kind", "guard_polarity")


def _compact_cfg_node(node: Mapping[str, Any]) -> dict[str, Any]:
    item = {key: node[key] for key in _CFG_NODE if node.get(key) not in (None, "", [])}
    omitted_bytes = 0

    def excerpt(text: str) -> str:
        nonlocal omitted_bytes
        data = text.encode("utf-8")
        value = data[:MAX_NAME_BYTES].decode("utf-8", errors="ignore")
        omitted_bytes += len(data) - len(value.encode("utf-8"))
        return value
    highlights = []
    if node["kind"] in {"branch", "loop", "switch"} or node.get("guard_expression"):
        highlights.append("branch")
    if node.get("guard_expression"):
        item["guard_expression"] = excerpt(node["guard_expression"])
    if calls := node.get("calls"):
        highlights.append("call")
        item["calls"] = [excerpt(name) for name in calls[:8]]
        if len(calls) > 8:
            item["calls_omitted"] = len(calls) - 8
    if omitted_bytes:
        item["capture_bytes_omitted"] = omitted_bytes
    if node["kind"] in {"exit", "return", "throw"} or node.get("early_exit"):
        highlights.append("exit")
    if highlights:
        item["highlights"] = highlights
    return item


def _compact_cfg_page(core, candidate, later_functions, position, offset, request_hash, block_limit,
                      edge_limit, deadline, cell_fits):
    key, shard, identity, _ = candidate
    rec, gaps = _load_cfg(core, deadline, shard, identity, compact=True)
    nodes, edges = rec["nodes"], rec["edges"]
    n, e = position["block"] or (0, 0)
    if position["block"] is not None and (tuple(position["function"]) != key or n > len(nodes) or e > len(edges)
                                           or (n, e) == (len(nodes), len(edges))):
        raise ValueError("invalid CFG cursor offsets")
    summary = {k: rec[k] for k in _CFG_SUMMARY}
    summary.update(block_offset=n, edge_offset=e)
    blocks = [_compact_cfg_node(node) for node in nodes[n:n + block_limit]]
    links = [{k: edge[k] for k in _CFG_EDGE if edge.get(k) is not None} for edge in edges[e:e + edge_limit]]

    def fit(row, page_gaps, next_n, next_e, *, omitted=False):
        core._check_deadline(deadline)
        remainder = (next_n, next_e) != (len(nodes), len(edges))
        more = remainder or later_functions
        next_cursor = core._cursor(offset + int(not remainder), request_hash, position={
            "function": key, "block": (next_n, next_e) if remainder else None}) if more else None
        if next_cursor and len(next_cursor) > 4096:
            return None
        rows = [] if row is None else [row]
        # A gap-only page has legitimately advanced; its zero-row prefix owns the cursor.
        cursors = [next_cursor] if row is None else [None, next_cursor]
        truncated = more or omitted
        preview = core._envelope(tool=QUERY_CFG_FUNCTION, results=rows.copy(), gaps=page_gaps,
                                 started=core.clock(), request_hash=request_hash, has_more=more,
                                 truncated=truncated, page_cursors=cursors)
        # Reserve the configured duration width, not an arbitrary payload margin.
        preview["duration_ms"] = max(preview["duration_ms"], core.limits.timeout_ms)
        if (len(preview["results"]) != len(rows) or (row is None and page_gaps[0] not in preview["coverage_gaps"])
                or len(canonical_json(preview)) > core.limits.max_response_bytes
                or (cell_fits and not cell_fits(preview))):
            return None
        core._check_deadline(deadline)
        return rows, page_gaps, more, offset, truncated, cursors

    def largest_prefix(header, page_gaps):
        def prefix(length):
            nb = min(length, len(blocks))
            ne = length - nb
            return fit({**header, "nodes": blocks[:nb], "edges": links[:ne]}, page_gaps, n + nb, e + ne)

        # The final page (no cursor) can be smaller than a shorter prefix. Try it first.
        count = len(blocks) + len(links)
        result = prefix(count)
        if result is not None:
            return result
        lo, hi, best = 1, count - 1, None
        while lo <= hi:
            mid = (lo + hi) // 2
            result = prefix(mid)
            if result is None:
                hi = mid - 1
            else:
                best, lo = result, mid + 1
        return best

    # Keep scope and citation fields, offsets and producer totals even on a minimal row.
    minimal = {k: summary[k] for k in ("ast_identity", "source_identity", "path", "start_line", "end_line",
                                        "node_count", "edge_count", "guard_count", "block_offset", "edge_offset")}
    minimal["summary_fields_omitted"] = True
    gap_options = [gaps]
    if gaps:
        gap_options.append([f"{len(gaps)} CFG coverage gap(s) omitted: byte limit"])
    for page_gaps in gap_options:
        for header in (summary, minimal):
            result = largest_prefix(header, page_gaps)
            if result is not None:
                return result

    if blocks or links:
        kind, index, item_id = (("block", n, blocks[0]["node_id"]) if blocks else
                                ("edge", e, links[0]["edge_id"]))
        next_n, next_e = (n + 1, e) if blocks else (n, e + 1)
        marker = {"kind": kind, "position": index, "reason": "byte_limit"}
        for omission in ({**marker, "id": item_id}, marker):
            for page_gaps in gap_options:
                for header in (summary, minimal):
                    row = {**header, "nodes": [], "edges": [], "omitted_item": omission}
                    result = fit(row, page_gaps, next_n, next_e, omitted=True)
                    if result is not None:
                        return result

        # At a tight boundary the summary alone may fit but not its marker. Keep
        # later items reachable with a gap-only page rather than skipping the function.
        if fit({**minimal, "nodes": [], "edges": []}, [], next_n, next_e, omitted=True) is not None:
            item_gap = (f"CFG function {offset}: {kind} {index} omitted: byte limit; "
                        f"totals {rec['node_count']} blocks, {rec['edge_count']} edges, {rec['guard_count']} guards")
            for page_gaps in gap_options:
                result = fit(None, [item_gap, *page_gaps], next_n, next_e, omitted=True)
                if result is not None:
                    return result

    # No scoped summary fits. Name the skipped remainder, without exposing source
    # identifiers outside a scoped result row. Try the shortest diagnostic last.
    short_gap = f"CFG function {offset} omitted"
    detail = (f"{short_gap} from block {n}/{rec['node_count']}, edge {e}/{rec['edge_count']}: "
              "cannot fit minimal summary and continuation")
    for page_gaps in ([detail, *gaps], [detail], [short_gap]):
        result = fit(None, page_gaps, len(nodes), len(edges), omitted=True)
        if result is not None:
            return result
    return [], [f"CFG function {offset}: omission and continuation cannot fit; nothing advanced"], False, offset, True, None


def query_cfg_function(
    core: "RetrievalCore",
    *,
    subject: str | None = None,
    function_name: str | None = None,
    path: str | None = None,
    limit: int = 20,
    cursor: str | None = None,
    block_limit: int | None = None,
    edge_limit: int | None = None,
    _cell_fits: Callable[[dict], bool] | None = None,
    _cell_line: int | None = None,
) -> dict[str, Any]:
    """Return bounded intra-procedural CFGs (nodes, edges, guard polarities) from accepted analysis shards."""
    if subject is None and function_name is None and path is None:
        raise ValueError("query_cfg_function requires at least one of subject, function_name, or path")
    norm_path = normalize_relative_path(path) if path is not None else None
    if function_name is not None and (
        not isinstance(function_name, str) or not function_name or len(function_name.encode("utf-8")) > MAX_NAME_BYTES
    ):
        raise ValueError("function_name exceeds bound")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= min(100, core.limits.max_results):
        raise ValueError("CFG result limit exceeds bound")

    compact = block_limit is not None or edge_limit is not None or _cell_fits is not None
    for bound in (block_limit, edge_limit):
        if bound is not None and (type(bound) is not int or not 1 <= bound <= 100):
            raise ValueError("CFG block_limit and edge_limit must be integers between 1 and 100")

    subject_kind: str | None = None
    if subject is not None:
        if not isinstance(subject, str) or not subject:
            raise ValueError("CFG subject must be a non-empty string")
        if subject.startswith("cfgfn:"):
            subject_kind = "cfgfn"
        else:
            parsed = LogicalIdentity.parse(subject)
            if parsed.kind not in {EntityKind.SOURCE_FILE, EntityKind.AST_NODE}:
                raise ValueError("CFG subject must be source_file, ast_node, or cfgfn:<id>")
            subject_kind = parsed.kind.value

    parameters = {
        "subject": subject,
        "function_name": function_name,
        "path": norm_path,
        "limit": limit,
        "cursor": cursor,
    }
    if compact:
        block_limit = block_limit or limit
        edge_limit = edge_limit or limit
        parameters.update(block_limit=block_limit, edge_limit=edge_limit, line=_cell_line)
    request_hash = core._request_hash(QUERY_CFG_FUNCTION, parameters)
    offset, position = _cfg_page_state(core, cursor, request_hash, compact=compact)

    def operation(deadline: float):
        gaps: list[str] = []
        def filters(_database):
            clauses, values = [], []
            if subject_kind == "source_file":
                clauses.append("json_extract(e.payload_json, '$.cfg.source_identity')=?")
                values.append(subject)
            elif subject_kind == "ast_node":
                clauses.append("e.identity=?")
                values.append(subject)
            elif subject_kind == "cfgfn":
                clauses.append("json_extract(e.payload_json, '$.cfg.function_id')=?")
                values.append(subject)
            if _cell_line is not None:
                clauses.append("l.start_line<=? AND l.end_line>=?")
                values.extend([_cell_line, _cell_line])
            if norm_path is not None:
                clauses.append("l.path=?")
                values.append(norm_path)
            if function_name is not None:
                clauses.append("(json_extract(e.payload_json, '$.cfg.function_name')=? "
                               "OR json_extract(e.payload_json, '$.cfg.qualified_name')=?)")
                values.extend([function_name, function_name])
            return clauses, values, None

        candidates = _cfg_candidates(core, deadline, filters, position, 1 if compact else limit)
        if compact and candidates:
            return _compact_cfg_page(core, candidates[0], len(candidates) > 1, position, offset, request_hash,
                                     block_limit, edge_limit, deadline, _cell_fits)
        results = []
        # There is no continuation for a withheld first full record: replaying
        # the same request/position under the same budget could never progress.
        cursors = [None]
        for key, shard, identity, _ in candidates[:limit]:
            record, coverage_gaps = _load_cfg(core, deadline, shard, identity)
            results.append(record)
            gaps.extend(coverage_gaps)
            cursors.append(core._cursor(offset + len(results), request_hash,
                                        position={"function": key, "block": None}))
        more = len(candidates) > limit
        if more:
            gaps.append("CFG coverage is page-local; continue with the cursor for remaining functions")
        if not any(s.get("producer", {}).get("job") == "job_tree_sitter_ast"
                   for s in core.indexes.get("analysis", ())):
            gaps.append("no accepted job_tree_sitter_ast analysis shards available")
        elif not candidates:
            gaps.append("no matching intra-procedural CFG function in accepted analysis shards; absence is not evidence")
        if results:
            preview = core._envelope(tool=QUERY_CFG_FUNCTION, results=results.copy(), gaps=gaps,
                                     started=core.clock(), request_hash=request_hash, has_more=more,
                                     page_cursors=cursors)
            if not preview["results"]:
                return ([], ["full CFG exceeds byte budget; retry with block_limit or edge_limit", *gaps],
                        False, offset, True, None)
        return results, gaps, more, offset, False, cursors

    return core._execute(QUERY_CFG_FUNCTION, parameters, operation)


def query_guard_dominators(
    core: "RetrievalCore",
    *,
    subject: str | None = None,
    path: str | None = None,
    line: int | None = None,
    node_id: str | None = None,
    polarity: str | None = None,
    limit: int = 20,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Return ordered branch guard dominators controlling a statement, line, AST node, or CFG block."""
    if subject is None and path is None and node_id is None:
        raise ValueError("query_guard_dominators requires subject, path, or node_id")
    norm_path = normalize_relative_path(path) if path is not None else None
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        raise ValueError("line must be a positive 1-based integer")
    if polarity is not None and polarity not in GUARD_POLARITIES:
        raise ValueError("guard polarity is not in the closed set")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= min(100, core.limits.max_results):
        raise ValueError("guard dominator result limit exceeds bound")

    subject_kind: str | None = None
    if subject is not None:
        parsed = LogicalIdentity.parse(subject)
        if parsed.kind not in {EntityKind.SOURCE_FILE, EntityKind.AST_NODE}:
            raise ValueError("subject must be source_file or ast_node")
        subject_kind = parsed.kind.value

    parameters = {
        "subject": subject,
        "path": norm_path,
        "line": line,
        "node_id": node_id,
        "polarity": polarity,
        "limit": limit,
        "cursor": cursor,
    }
    request_hash = core._request_hash(QUERY_GUARD_DOMINATORS, parameters)
    offset, position = _cfg_page_state(core, cursor, request_hash)

    def operation(deadline: float):
        results = []
        gaps: list[str] = []
        cursors = [core._cursor(offset, request_hash, position=position)]

        def filters(database):
            occurrence_block_id = None
            target_span = None
            target_source_id = subject if subject_kind == "source_file" else None
            target_line = line
            if subject_kind == "ast_node":
                ast_row = database.execute(
                    "SELECT json_extract(e.payload_json, '$.cfg_block_id') AS block_id, "
                    "l.path,l.file_sha256,l.start_line,l.start_byte,l.end_byte "
                    "FROM entities e JOIN locations l ON l.entity_id=e.identity WHERE e.identity=?",
                    (subject,),
                ).fetchone()
                if ast_row is None:
                    return None
                occurrence_block_id = ast_row["block_id"]
                target_span = (int(ast_row["start_byte"]), int(ast_row["end_byte"]))
                if target_line is None:
                    target_line = int(ast_row["start_line"])
                target_source_id = LogicalIdentity.derive(
                    EntityKind.SOURCE_FILE, core.manifest["target_snapshot"],
                    {"path": normalize_relative_path(str(ast_row["path"])), "sha256": str(ast_row["file_sha256"])},
                ).value

            clauses, values = [], []
            if target_source_id is not None:
                clauses.append("json_extract(e.payload_json, '$.cfg.source_identity')=?")
                values.append(target_source_id)
            if norm_path is not None:
                clauses.append("l.path=?")
                values.append(norm_path)
            if target_line is not None:
                clauses.append("l.start_line<=? AND l.end_line>=?")
                values.extend([target_line, target_line])
            if node_id is not None:
                clauses.append("EXISTS (SELECT 1 FROM json_each(e.payload_json, '$.cfg_nodes') n "
                               "WHERE json_extract(n.value, '$.node_id')=?)")
                values.append(node_id)
            return clauses, values, (occurrence_block_id, target_span, target_line)

        bound = core.limits.max_results
        candidates = _cfg_candidates(core, deadline, filters, position, bound)
        more = len(candidates) > bound
        for index, (key, shard, identity, context) in enumerate(candidates[:bound]):
            rec, coverage_gaps = _load_cfg(core, deadline, shard, identity)
            gaps.extend(coverage_gaps)
            rows = _guard_rows(rec, *context, node_id=node_id, polarity=polarity)
            if position["block"] is not None and tuple(position["function"]) == key:
                rows = [row for row in rows if _guard_key(row) > tuple(position["block"])]
            for row_index, row in enumerate(rows):
                core._check_deadline(deadline)
                results.append(row)
                cursors.append(core._cursor(offset + len(results), request_hash,
                                            position={"function": key, "block": _guard_key(row)}))
                if len(results) == limit:
                    more = row_index + 1 < len(rows) or index + 1 < len(candidates)
                    break
            if len(results) == limit:
                # When this function is exhausted, the next page must not reload it.
                if row_index + 1 == len(rows):
                    cursors[-1] = core._cursor(offset + len(results), request_hash,
                                               position={"function": key, "block": None})
                break
            cursors[-1] = core._cursor(offset + len(results), request_hash,
                                       position={"function": key, "block": None})

        if more:
            gaps.append("CFG coverage is page-local; candidate/result bound reached, continue with the cursor "
                        "(an empty page is not evidence of absence)")
        if not any(s.get("producer", {}).get("job") == "job_tree_sitter_ast"
                   for s in core.indexes.get("analysis", ())):
            gaps.append("no accepted job_tree_sitter_ast analysis shards available")
        elif not results and not more:
            gaps.append("no matching CFG guard-dominated block found; consult coverage gaps before interpreting absence")
        return results, gaps, more, offset, more and len(results) < limit, cursors

    return core._execute(QUERY_GUARD_DOMINATORS, parameters, operation)


def _guard_key(row):
    return row["start_line"], row["end_line"], row["node_id"]


def _guard_rows(rec, occurrence_block_id, target_span, target_line, *, node_id, polarity):
    candidates = rec["nodes"]
    if node_id is not None:
        candidates = [n for n in candidates if n.get("node_id") == node_id]
        if target_span is not None:
            candidates = [n for n in candidates
                          if (n["start_byte"] <= target_span[0] and n["end_byte"] >= target_span[1])
                          or (target_span[0] <= n["start_byte"] and target_span[1] >= n["end_byte"])]
        groups = [[n] for n in candidates]
    elif target_span is not None:
        anchors = [n for n in candidates if n["node_id"] == occurrence_block_id]
        if not anchors:
            anchors = [n for n in candidates if n["kind"] not in {"entry", "exit"}
                       and n["start_byte"] <= target_span[0] and n["end_byte"] >= target_span[1]]
        anchors.sort(key=lambda n: (n["end_byte"] - n["start_byte"], n["node_id"]))
        groups = ([[n for n in candidates if _cfg_occurrence(n) == _cfg_occurrence(anchors[0])]]
                  if anchors else [])
    elif target_line is not None:
        spanning = [n for n in candidates if n.get("kind") not in {"entry", "exit"}
                    and int(n.get("start_line", 0)) <= target_line <= int(n.get("end_line", 0))]
        spanning.sort(key=lambda n: (int(n["end_line"]) - int(n["start_line"]),
                                    int(n["end_byte"]) - int(n["start_byte"]), str(n["node_id"])))
        groups = ([[n for n in candidates if _cfg_occurrence(n) == _cfg_occurrence(spanning[0])]]
                  if spanning else [])
    else:
        by_occurrence: dict[tuple, list[dict[str, Any]]] = {}
        for node in candidates:
            by_occurrence.setdefault(_cfg_occurrence(node), []).append(node)
        groups = list(by_occurrence.values())

    matches = {}
    for contexts in groups:
        cnode = contexts[0]
        gdoms = _common_occurrence_guards(contexts)
        if node_id is None and target_span is None and target_line is None and not gdoms:
            continue
        if polarity is not None:
            gdoms = [g for g in gdoms if g.get("guard_polarity") == polarity]
            if not gdoms:
                continue
        nid = str(cnode["node_id"])
        matches.setdefault(nid, {
            "schema": CFG_SCHEMA,
            "function_id": rec["function_id"],
            "function_name": rec["function_name"],
            "node_id": nid,
            "ast_identity": cnode.get("ast_identity"),
            "kind": cnode.get("kind"),
            "language": rec["language"],
            "source_identity": rec["source_identity"],
            "path": rec["path"],
            "file_sha256": rec["file_sha256"],
            "start_line": int(cnode.get("start_line", 1)),
            "end_line": int(cnode.get("end_line", 1)),
            "statement_text": str(cnode.get("statement_text", "")),
            "guard_dominators": gdoms,
        })
    return sorted(matches.values(), key=_guard_key)
