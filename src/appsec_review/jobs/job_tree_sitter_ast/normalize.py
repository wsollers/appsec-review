from __future__ import annotations

from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation,
)
from appsec_review.storage import atomic_bytes, file_sha256

from .cfg import CFG_SCHEMA, FileCfgResult, GuardDominator, synthesize_file_cfg, write_scope_cfg_artifacts
from .model import GrammarLock, Scope
from .projection import DEFINITIONS, project
from appsec_review.review.dispositions import FIRST_PARTY, SourceDispositions
from appsec_review.retrieval.syntax_contract import SCHEMA as PROJECTION_SCHEMA

# Per-file records of non-first-party files the node budget did not cover (``counts.excluded_files``), so a
# consumer can name the exclusion instead of reporting the file as ``ast_unavailable``. The disposition
# counts stay authoritative; the record list is bounded.
MAX_EXCLUDED_FILE_RECORDS = 10000


NORMALIZER_SCHEMA = "appsec-review/tree-sitter-normalizer/1"


def reusable_shard(metadata_path: Path, artifact_path: Path, index_path: Path, fingerprint: str) -> Mapping[str, Any] | None:
    if not (metadata_path.is_file() and artifact_path.is_file() and index_path.is_file()):
        return None
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if (metadata.get("fingerprint") != fingerprint or
        file_sha256(artifact_path) != metadata.get("artifact", {}).get("sha256") or
        file_sha256(index_path) != metadata.get("index_identity", {}).get("sha256")):
        return None
    cfg_refs = metadata.get("cfg_artifacts")
    if isinstance(cfg_refs, Mapping) and len(metadata_path.parents) >= 3:
        run_root_guess = metadata_path.parents[3]
        for key in ("manifest", "nodes", "edges"):
            ref = cfg_refs.get(key)
            if not isinstance(ref, Mapping):
                return None
            ref_path = run_root_guess / str(ref.get("path", ""))
            if not ref_path.is_file() or file_sha256(ref_path) != ref.get("sha256"):
                return None
    return metadata


def attest_reused_shard(run_root: Path, index_path: Path, metadata: Mapping[str, Any], *,
                        target_snapshot: str) -> None:
    """Register custody of a reused scope shard under the current attempt.

    ``reusable_shard`` verified the shard's bytes against its metadata, so the reusing attempt stands
    behind the same computation and records it exactly as ``IndexBuilder.build`` does for a shard it
    writes. Without this, only the original attempt's receipt exists; under a repair admission after
    an implementation change that receipt is incompatible, and consuming the shard through a manifest
    refuses ("repair cannot relabel an unresolved or incompatible named computation as legacy").
    """
    identity = metadata["index_identity"]
    IndexBuilder(index_path, name=str(identity["name"]), fingerprint=str(metadata["fingerprint"]),
                 target_snapshot=target_snapshot, shard_id=str(identity["shard_id"])).attest_existing(str(identity["sha256"]))


def node_identity(target_snapshot: str, scope: Scope, grammar: GrammarLock,
                  path: str, file_sha256: str, node: Mapping[str, Any]) -> LogicalIdentity:
    return LogicalIdentity.derive(EntityKind.AST_NODE, target_snapshot, {
        "scope_id": scope.scope_id, "grammar_sha256": grammar.sha256, "path": path,
        "file_sha256": file_sha256, "ordinal_path": list(node["ordinal_path"]),
        "type": node["type"], "start_byte": node["start_byte"], "end_byte": node["end_byte"],
    })


def normalize_scope(*, run_root: Path, target_snapshot: str, scope: Scope, grammar: GrammarLock,
                    fingerprint: str, container_output: Mapping[str, Any], producer: Mapping[str, Any],
                    artifact_path: Path, index_path: Path,
                    source_bytes: Mapping[str, bytes] | None = None,
                    dispositions: SourceDispositions | None = None,
                    cfg_dir: Path | None = None,
                    ) -> tuple[Mapping[str, Any], IndexIdentity, Mapping[str, Any]]:
    """Normalize one scope's container output into its ``analysis`` shard.

    A file's disposition comes from the planned scope file (``plan_scopes``) or, failing that, from
    ``dispositions``. A non-first-party file the node budget did not cover is a per-disposition count
    (``excluded_files_by_disposition``), never a gap; its coverage row says why it is partial (T-5016).
    """
    if container_output.get("schema") != "appsec-review/tree-sitter-container-output/1":
        raise ValueError("unsupported Tree-sitter container output schema")
    if container_output.get("scope_id") != scope.scope_id or container_output.get("language") != scope.language:
        raise ValueError("Tree-sitter output scope identity mismatch")
    from appsec_review.jobs.delivery_scope import scope_fields, source_in_scope
    from appsec_review.retrieval.source_resolution import source_native
    sources = {str(item["path"]): item for item in scope.files}
    if any(not source_in_scope(item) for item in sources.values()):
        raise ValueError("out-of-scope source entered AST normalization")
    accepted = {path: str(item["sha256"]) for path, item in sources.items()}

    def disposition_of(path: str) -> str:
        value = sources[path].get("disposition")
        if value:
            return str(value)
        return dispositions.classify(path) if dispositions is not None else FIRST_PARTY

    files_by_disposition: dict[str, int] = {}
    nodes_by_disposition: dict[str, int] = {}
    excluded_by_disposition: dict[str, int] = {}
    excluded_files: list[dict[str, str]] = []
    lines: list[bytes] = []
    gaps = [f"{item.get('path')}: {item.get('reason')}" for item in scope.exclusions]
    diagnostics = files_parsed = bytes_parsed = nodes_parsed = 0
    cfg_file_results: list[FileCfgResult] = []
    builder = IndexBuilder(index_path, name="analysis", fingerprint=fingerprint,
                           target_snapshot=target_snapshot, shard_id=scope.scope_id)
    producer = {**producer, "tree_sitter_cfg": CFG_SCHEMA}
    if source_bytes is not None:
        producer = {**producer, "syntax_projection": PROJECTION_SCHEMA}
    seen_files: set[str] = set()
    for record in container_output.get("records", ()):
        path = str(record.get("path", ""))
        if path not in accepted or path in seen_files:
            raise ValueError("container returned an unaccepted or duplicate source path")
        seen_files.add(path)
        status = str(record.get("status"))
        if record.get("sha256") != accepted[path]:
            raise ValueError("container output source hash mismatch")
        kind = disposition_of(path)
        files_by_disposition[kind] = files_by_disposition.get(kind, 0) + 1
        if status == "TRUNCATED":
            reason = str(record.get("reason", "truncated"))
            if kind == FIRST_PARTY:
                gaps.append(f"{path}: {reason}")
                builder.add_coverage(path, "partial", gaps[-1])
            else:
                excluded_by_disposition[kind] = excluded_by_disposition.get(kind, 0) + 1
                excluded_files.append({"path": path, "disposition": kind, "reason": reason})
                builder.add_coverage(path, "partial", f"{path}: {reason}; {kind} file, the budget is spent on "
                                                      "first-party files first (counted, not a gap)")
            continue
        if sources[path].get("source_backing") and int(record.get("bytes", -1)) != sources[path]["size_bytes"]:
            raise ValueError("generated AST byte count differs from accepted source")
        files_parsed += 1
        bytes_parsed += int(record.get("bytes", 0))
        nodes = tuple(record.get("nodes", ()))
        nodes_parsed += len(nodes)
        nodes_by_disposition[kind] = nodes_by_disposition.get(kind, 0) + len(nodes)
        source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, target_snapshot,
                                           {"path": path, "sha256": accepted[path]})
        ids = {tuple(int(value) for value in node["ordinal_path"]):
               node_identity(target_snapshot, scope, grammar, path, accepted[path], node) for node in nodes}
        projection = {}
        projection_limitations: set[str] = set()
        if source_bytes is not None:
            data = source_bytes[path]
            if hashlib.sha256(data).hexdigest() != accepted[path] or len(data) != int(record["bytes"]):
                raise ValueError("syntax projection source identity differs from accepted parser input")
            for node in nodes:
                if not 0 <= int(node["start_byte"]) <= int(node["end_byte"]) <= len(data):
                    raise ValueError("AST span exceeds accepted source bytes")
            projection = project(nodes, data, grammar=grammar.grammar, source_identity=source_id.value,
                                 identities={key: value.value for key, value in ids.items()},
                                 limitations=projection_limitations)
        raw_file_bytes = source_bytes[path] if (source_bytes is not None and path in source_bytes) else None
        file_cfg = synthesize_file_cfg(
            nodes,
            raw_file_bytes,
            language=grammar.grammar,
            path=path,
            file_sha256=accepted[path],
            source_identity=source_id.value,
            ast_identities={key: value.value for key, value in ids.items()},
        )
        cfg_file_results.append(file_cfg)
        file_cfg_gaps = [
            f"{path}: {fn.function_id}: {gap}" for fn in file_cfg.functions for gap in fn.gaps
        ]
        gaps.extend(file_cfg_gaps)
        if file_cfg.functions:
            builder.add_coverage("cfg:" + source_id.value, "partial" if file_cfg_gaps else "complete",
                                 "; ".join(file_cfg_gaps) or None)
        fn_by_ord = {fn.ordinal_path: fn for fn in file_cfg.functions}
        branch_by_ord = {
            cnode.ordinal_path: cnode
            for fn in file_cfg.functions
            for cnode in fn.nodes
            if cnode.guard_polarity is not None and cnode.ordinal_path in fn.ordinal_to_node_id
        }
        ord_to_block: dict[tuple[int, ...], str] = {}
        ord_to_guards: dict[tuple[int, ...], tuple[GuardDominator, ...]] = {}
        for fn in sorted(file_cfg.functions, key=lambda f: len(f.ordinal_path)):
            ord_to_block.update(fn.ordinal_to_node_id)
            ord_to_guards.update(fn.ordinal_guard_dominators)
        for node in nodes:
            if sources[path].get("source_backing") and not (
                    0 <= int(node["start_byte"]) <= int(node["end_byte"]) <= sources[path]["size_bytes"]):
                raise ValueError("generated AST span exceeds accepted source bytes")
            ordinal = tuple(int(value) for value in node["ordinal_path"])
            identity = ids[ordinal]
            start = tuple(int(value) for value in node["start_point"])
            end = tuple(int(value) for value in node["end_point"])
            location = SourceLocation(
                target_snapshot, path, accepted[path], int(node["start_byte"]), int(node["end_byte"]),
                start[0] + 1, end[0] + 1, start[1] + 1, end[1] + 1,
                {"grammar": grammar.grammar, "ordinal_path": list(ordinal), **source_native(sources[path])},
                "tree-sitter-byte-and-point-exact", 1.0,
            )
            flags = {name: bool(node.get(name)) for name in ("named", "error", "missing", "extra", "has_error")}
            if flags["error"] or flags["missing"]:
                diagnostics += 1
            payload = {"schema": NORMALIZER_SCHEMA, "grammar_native_type": node["type"],
                       "field": node.get("field"), **flags, "scope_id": scope.scope_id,
                       "project_id": scope.project_id, "translation_scope_id": scope.translation_scope_id,
                       "language": scope.language, "syntax_only": True, **scope_fields(sources[path]),
                       **source_native(sources[path]),
                       "canonical_artifact_identity": sources[path].get("canonical_artifact_identity"),
                       "build_unit_id": sources[path].get("build_unit_id"),
                       "workspace_path": sources[path].get("workspace_path")}
            if ordinal in projection:
                payload["syntax"] = projection[ordinal]
            searchable = str(node["type"]) + (
                " " + str(projection[ordinal]["written_name"]) if ordinal in projection else "")
            entity_payload = dict(payload)
            if ordinal in fn_by_ord:
                fn_cfg = fn_by_ord[ordinal]
                entity_payload["cfg"] = {"schema": CFG_SCHEMA, **fn_cfg.to_summary()}
                entity_payload["cfg_nodes"] = [n.to_jsonl_record() for n in fn_cfg.nodes]
                entity_payload["cfg_edges"] = [e.to_jsonl_record() for e in fn_cfg.edges]
                if fn_cfg.function_name not in searchable:
                    searchable = f"{searchable} {fn_cfg.function_name}"
            if ordinal in branch_by_ord:
                bnode = branch_by_ord[ordinal]
                entity_payload["cfg_guard"] = {
                    "node_id": bnode.node_id,
                    "guard_expression": bnode.guard_expression,
                    "guard_polarity": bnode.guard_polarity,
                    "early_exit": bnode.early_exit,
                }
            if ordinal in ord_to_block:
                entity_payload["cfg_block_id"] = ord_to_block[ordinal]
                dom_guards = ord_to_guards.get(ordinal, ())
                if dom_guards:
                    entity_payload["cfg_guard_dominators"] = [g.to_dict() for g in dom_guards]
            builder.add_entity(EntityRecord(identity, "/".join(map(str, ordinal)) or "root",
                                             str(node["type"]), searchable, entity_payload, location))
            normalized = {"identity": identity.value, "path": path, "file_sha256": accepted[path],
                          "location": asdict(location), **payload}
            lines.append(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        for node in nodes:
            ordinal = tuple(int(value) for value in node["ordinal_path"])
            if ordinal:
                builder.add_relation(RelationRecord(RelationKind.CONTAINS, ids[ordinal[:-1]].value,
                    ids[ordinal].value, True, 1.0, payload={"field": node.get("field"),
                    "child_index": ordinal[-1], "syntax_relation": True}))
            else:
                # Duplicate the source entity in this shard so relation closure is independent.
                builder.add_entity(EntityRecord(source_id, path, path, path,
                                                 {"language": scope.language, "sha256": accepted[path],
                                                  **scope_fields(sources[path]), **source_native(sources[path]),
                                                  "canonical_artifact_identity": sources[path].get("canonical_artifact_identity"),
                                                  "build_unit_id": sources[path].get("build_unit_id")},
                                                 SourceLocation(
                                                     target_snapshot, path, accepted[path], 0,
                                                     int(sources[path].get("size_bytes", record.get("bytes", 0))),
                                                     1, int(node["end_point"][0]) + 1, 1,
                                                     int(node["end_point"][1]) + 1,
                                                     {"grammar": grammar.grammar, **source_native(sources[path])},
                                                     "tree-sitter-file-span", 1.0)))
                builder.add_relation(RelationRecord(RelationKind.CONTAINS, source_id.value,
                                                     ids[ordinal].value, True, 1.0,
                                                     payload={"syntax_relation": True}))
        for fn_cfg in file_cfg.functions:
            node_ast_by_id = {n.node_id: n.ast_identity for n in fn_cfg.nodes if n.ast_identity}
            ast_counts = Counter(n.ast_identity for n in fn_cfg.nodes
                                 if n.ast_identity and n.kind not in {"entry", "exit"})
            contextual = {identity for identity, count in ast_counts.items() if count > 1}
            if contextual:
                detail = f"{path}: {fn_cfg.function_id}: cfg_ast_context_projection; use context-specific CFG edges"
                gaps.append(detail)
                builder.add_coverage("cfg-ast-projection:" + fn_cfg.function_id, "partial", detail)
            for cedge in fn_cfg.edges:
                s_ast = node_ast_by_id.get(cedge.source_node_id)
                t_ast = node_ast_by_id.get(cedge.target_node_id)
                if s_ast and t_ast and s_ast != t_ast and not ({s_ast, t_ast} & contextual):
                    builder.add_relation(RelationRecord(
                        RelationKind.FLOWS_TO, s_ast, t_ast, True, 1.0,
                        payload={"edge_kind": cedge.edge_kind, "guard_polarity": cedge.guard_polarity, "syntax_relation": True},
                    ))
            for cnode in fn_cfg.nodes:
                if not cnode.ast_identity:
                    continue
                for gdom in fn_cfg.ordinal_guard_dominators.get(cnode.ordinal_path, ()):
                    if gdom.branch_ast_identity and gdom.branch_ast_identity != cnode.ast_identity:
                        builder.add_relation(RelationRecord(
                            RelationKind.GUARDS, gdom.branch_ast_identity, cnode.ast_identity, True, 1.0,
                            payload={"guard_polarity": gdom.guard_polarity, "branch_arm": gdom.branch_arm, "syntax_relation": True},
                        ))
        if record.get("root_has_error"):
            gaps.append(f"{path}: parse diagnostics present")
        file_gaps = [f"{path}: parse diagnostics present"] if record.get("root_has_error") else []
        if record.get("truncated"):
            if kind == FIRST_PARTY:
                gaps.append(f"{path}: node limit reached")
                file_gaps.append(f"{path}: node limit reached")
            else:
                excluded_by_disposition[kind] = excluded_by_disposition.get(kind, 0) + 1
                excluded_files.append({"path": path, "disposition": kind, "reason": "node limit reached"})
                file_gaps.append(f"{path}: node limit reached; {kind} file, the budget is spent on first-party "
                                 "files first (counted, not a gap)")
        builder.add_coverage(path, "partial" if file_gaps else "complete", "; ".join(file_gaps) or None)
        if source_bytes is not None:
            builder.add_coverage("syntax-projection:" + source_id.value,
                "partial" if grammar.grammar in DEFINITIONS else "unavailable",
                "; ".join(["bounded syntax subset; names, imports and call targets are unresolved",
                           *sorted(projection_limitations)])
                if grammar.grammar in DEFINITIONS else "no syntax projection mapping for this locked grammar")
    missing = sorted(set(accepted) - seen_files)
    gaps.extend(f"{path}: container omitted accepted file" for path in missing)
    for path in missing:
        builder.add_coverage(path, "unavailable", f"{path}: container omitted accepted file")
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_bytes(artifact_path, b"".join(sorted(lines)))
    sha256 = builder.build()
    identity = IndexIdentity("analysis", "appsec-review/retrieval-index/2", sha256, fingerprint,
        index_path.relative_to(run_root).as_posix(), producer, tuple(gaps), scope.scope_id)
    artifact = {"path": artifact_path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(artifact_path), "size_bytes": artifact_path.stat().st_size}
    cfg_functions_built = sum(len(r.functions) for r in cfg_file_results)
    cfg_nodes_emitted = sum(r.total_nodes for r in cfg_file_results)
    cfg_edges_emitted = sum(r.total_edges for r in cfg_file_results)
    cfg_guards_classified = sum(r.total_guards for r in cfg_file_results)
    cfg_languages = sorted({r.language for r in cfg_file_results if r.functions})
    cfg_functions = [fn for result in cfg_file_results for fn in result.functions]
    cfg_artifacts: dict[str, Any] | None = None
    if cfg_dir is not None:
        cfg_artifacts, _ = write_scope_cfg_artifacts(
            run_root=run_root,
            cfg_dir=cfg_dir,
            scope_id=scope.scope_id,
            language=scope.language,
            grammar=grammar.grammar,
            target_snapshot=target_snapshot,
            file_results=cfg_file_results,
        )
    counts: dict[str, Any] = {
        "files_parsed": files_parsed, "bytes_parsed": bytes_parsed,
        "nodes_parsed": nodes_parsed, "diagnostic_count": diagnostics,
        "gap_count": len(gaps),
        "cfg_functions_built": cfg_functions_built,
        "cfg_nodes_emitted": cfg_nodes_emitted,
        "cfg_edges_emitted": cfg_edges_emitted,
        "cfg_guards_classified": cfg_guards_classified,
        "cfg_partial_functions": sum(bool(fn.gaps) for fn in cfg_functions),
        "cfg_truncated_functions": sum(fn.truncated for fn in cfg_functions),
        "cfg_unmodeled_constructs": sum(len(fn.unmodeled_constructs) for fn in cfg_functions),
        "cfg_languages": cfg_languages,
        "dispositions": {"files": dict(sorted(files_by_disposition.items())),
                         "nodes": dict(sorted(nodes_by_disposition.items())),
                         "excluded_files": dict(sorted(excluded_by_disposition.items()))},
        "excluded_files": sorted(excluded_files, key=lambda item: item["path"])[:MAX_EXCLUDED_FILE_RECORDS],
    }
    if cfg_artifacts is not None:
        counts["cfg_artifacts"] = cfg_artifacts
    return artifact, identity, counts
