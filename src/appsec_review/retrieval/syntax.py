"""Bounded syntax-only navigation and intra-procedural CFG queries; reads accepted indices only."""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING, Any, Mapping

from .model import EntityKind, LogicalIdentity, normalize_relative_path
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
                with core._database(shard, deadline) as database:
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
            with core._database(shard, deadline) as database:
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


def query_cfg_function(
    core: "RetrievalCore",
    *,
    subject: str | None = None,
    function_name: str | None = None,
    path: str | None = None,
    limit: int = 20,
    cursor: str | None = None,
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
    offset = core._offset(cursor, core._request_hash(QUERY_CFG_FUNCTION, parameters))

    def operation(deadline: float):
        found: dict[str, dict[str, Any]] = {}
        gaps: list[str] = []
        any_ts_shard = False
        for shard in core.indexes.get("analysis", ()):
            if shard.get("producer", {}).get("job") != "job_tree_sitter_ast":
                continue
            any_ts_shard = True
            with core._database(shard, deadline) as database:
                clauses = ["e.kind='ast_node'", "json_extract(e.payload_json, '$.cfg.schema')=?"]
                values: list[Any] = [CFG_SCHEMA]
                if subject_kind == "source_file":
                    clauses.append("json_extract(e.payload_json, '$.cfg.source_identity')=?")
                    values.append(subject)
                elif subject_kind == "ast_node":
                    clauses.append("e.identity=?")
                    values.append(subject)
                elif subject_kind == "cfgfn":
                    clauses.append("json_extract(e.payload_json, '$.cfg.function_id')=?")
                    values.append(subject)
                if norm_path is not None:
                    clauses.append("l.path=?")
                    values.append(norm_path)
                if function_name is not None:
                    clauses.append(
                        "(json_extract(e.payload_json, '$.cfg.function_name')=? "
                        "OR json_extract(e.payload_json, '$.cfg.qualified_name')=?)"
                    )
                    values.extend([function_name, function_name])
                sql = (
                    "SELECT e.identity, e.payload_json, l.path, l.file_sha256 "
                    "FROM entities e JOIN locations l ON l.entity_id=e.identity "
                    "WHERE " + " AND ".join(clauses) + " ORDER BY l.path, l.start_byte, e.identity"
                )
                for row in database.execute(sql, values):
                    rel_p = normalize_relative_path(str(row["path"]))
                    raw_payload = json.loads(row["payload_json"])
                    coverage_gaps, guards_complete = _cfg_coverage(database, raw_payload, rel_p)
                    gaps.extend(coverage_gaps)
                    rec = _sanitize_cfg_function_record(
                        raw_payload,
                        ast_identity=str(row["identity"]),
                        rel_path=rel_p,
                        file_sha256=str(row["file_sha256"]),
                        shard_id=str(shard.get("shard_id", "default")),
                        guards_complete=guards_complete,
                    )
                    found.setdefault(rec["function_id"], rec)
        if not any_ts_shard:
            gaps.append("no accepted job_tree_sitter_ast analysis shards available")
        elif not found:
            gaps.append("no matching intra-procedural CFG function in accepted analysis shards; absence is not evidence")
        ordered = sorted(
            found.values(),
            key=lambda r: (r["path"], r["start_line"], r["end_line"], r["function_id"]),
        )
        return ordered[offset:offset + limit], gaps, len(ordered) > offset + limit, offset

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
    offset = core._offset(cursor, core._request_hash(QUERY_GUARD_DOMINATORS, parameters))

    def operation(deadline: float):
        matches: dict[str, dict[str, Any]] = {}
        gaps: list[str] = []
        any_ts_shard = False
        for shard in core.indexes.get("analysis", ()):
            if shard.get("producer", {}).get("job") != "job_tree_sitter_ast":
                continue
            any_ts_shard = True
            with core._database(shard, deadline) as database:
                occurrence_block_id = None
                target_span = None
                target_source_id = subject if subject_kind == "source_file" else None
                target_line = line
                if subject_kind == "ast_node":
                    ast_row = database.execute(
                        "SELECT e.payload_json, l.path, l.file_sha256, l.start_line, l.start_byte, l.end_byte "
                        "FROM entities e JOIN locations l ON l.entity_id=e.identity WHERE e.identity=?",
                        (subject,),
                    ).fetchone()
                    if ast_row is None:
                        continue
                    ast_payload = json.loads(ast_row["payload_json"])
                    occurrence_block_id = ast_payload.get("cfg_block_id")
                    target_span = (int(ast_row["start_byte"]), int(ast_row["end_byte"]))
                    if target_line is None:
                        target_line = int(ast_row["start_line"])
                    target_source_id = LogicalIdentity.derive(
                        EntityKind.SOURCE_FILE,
                        core.manifest["target_snapshot"],
                        {"path": normalize_relative_path(str(ast_row["path"])), "sha256": str(ast_row["file_sha256"])},
                    ).value

                clauses = ["e.kind='ast_node'", "json_extract(e.payload_json, '$.cfg.schema')=?"]
                values: list[Any] = [CFG_SCHEMA]
                if target_source_id is not None:
                    clauses.append("json_extract(e.payload_json, '$.cfg.source_identity')=?")
                    values.append(target_source_id)
                if norm_path is not None:
                    clauses.append("l.path=?")
                    values.append(norm_path)
                if target_line is not None:
                    clauses.append("l.start_line<=? AND l.end_line>=?")
                    values.extend([target_line, target_line])

                sql = (
                    "SELECT e.identity, e.payload_json, l.path, l.file_sha256 "
                    "FROM entities e JOIN locations l ON l.entity_id=e.identity "
                    "WHERE " + " AND ".join(clauses) + " ORDER BY l.path, l.start_byte, e.identity"
                )
                for row in database.execute(sql, values):
                    rel_p = normalize_relative_path(str(row["path"]))
                    raw_payload = json.loads(row["payload_json"])
                    coverage_gaps, guards_complete = _cfg_coverage(database, raw_payload, rel_p)
                    rec = _sanitize_cfg_function_record(
                        raw_payload,
                        ast_identity=str(row["identity"]),
                        rel_path=rel_p,
                        file_sha256=str(row["file_sha256"]),
                        shard_id=str(shard.get("shard_id", "default")),
                        guards_complete=guards_complete,
                    )
                    candidates = rec["nodes"]
                    if node_id is not None:
                        candidates = [n for n in candidates if n.get("node_id") == node_id]
                        if target_span is not None:
                            candidates = [n for n in candidates
                                          if (n["start_byte"] <= target_span[0] and n["end_byte"] >= target_span[1])
                                          or (target_span[0] <= n["start_byte"] and target_span[1] >= n["end_byte"])]
                        if not candidates:
                            continue
                        groups = [[n] for n in candidates]
                    elif target_span is not None:
                        anchors = [n for n in candidates if n["node_id"] == occurrence_block_id]
                        if not anchors:
                            anchors = [n for n in candidates if n["kind"] not in {"entry", "exit"}
                                       and n["start_byte"] <= target_span[0] and n["end_byte"] >= target_span[1]]
                        anchors.sort(key=lambda n: (n["end_byte"] - n["start_byte"], n["node_id"]))
                        groups = (
                            [[n for n in candidates if _cfg_occurrence(n) == _cfg_occurrence(anchors[0])]]
                            if anchors else []
                        )
                    elif target_line is not None:
                        spanning = [
                            n for n in candidates
                            if n.get("kind") not in {"entry", "exit"}
                            and int(n.get("start_line", 0)) <= target_line <= int(n.get("end_line", 0))
                        ]
                        if spanning:
                            spanning.sort(key=lambda n: (
                                int(n["end_line"]) - int(n["start_line"]),
                                int(n["end_byte"]) - int(n["start_byte"]), str(n["node_id"]),
                            ))
                            groups = [[n for n in candidates if _cfg_occurrence(n) == _cfg_occurrence(spanning[0])]]
                        else:
                            groups = []
                    else:
                        by_occurrence: dict[tuple, list[dict[str, Any]]] = {}
                        for n in candidates:
                            by_occurrence.setdefault(_cfg_occurrence(n), []).append(n)
                        groups = list(by_occurrence.values())

                    gaps.extend(coverage_gaps)
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
                        matches.setdefault(
                            nid,
                            {
                                "schema": CFG_SCHEMA,
                                "function_id": rec["function_id"],
                                "function_name": rec["function_name"],
                                "node_id": nid,
                                "ast_identity": cnode.get("ast_identity"),
                                "kind": cnode.get("kind"),
                                "language": rec["language"],
                                "source_identity": rec["source_identity"],
                                "path": rel_p,
                                "file_sha256": rec["file_sha256"],
                                "start_line": int(cnode.get("start_line", 1)),
                                "end_line": int(cnode.get("end_line", 1)),
                                "statement_text": str(cnode.get("statement_text", "")),
                                "guard_dominators": gdoms,
                            },
                        )

        if not any_ts_shard:
            gaps.append("no accepted job_tree_sitter_ast analysis shards available")
        elif not matches:
            gaps.append("no matching CFG guard-dominated block found; consult coverage gaps before interpreting absence")
        ordered = sorted(
            matches.values(),
            key=lambda m: (m["path"], m["start_line"], m["end_line"], m["node_id"]),
        )
        return ordered[offset:offset + limit], gaps, len(ordered) > offset + limit, offset

    return core._execute(QUERY_GUARD_DOMINATORS, parameters, operation)
