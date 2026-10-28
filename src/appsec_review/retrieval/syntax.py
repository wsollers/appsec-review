"""Bounded syntax-only navigation; reads accepted indices, never target trees or parsers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping

from .syntax_contract import MAX_NAME_BYTES, MODES, SCHEMA
from .model import EntityKind, LogicalIdentity

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
