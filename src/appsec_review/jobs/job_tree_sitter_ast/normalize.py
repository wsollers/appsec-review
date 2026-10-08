from __future__ import annotations

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

from .model import GrammarLock, Scope


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
    return metadata


def node_identity(target_snapshot: str, scope: Scope, grammar: GrammarLock,
                  path: str, file_sha256: str, node: Mapping[str, Any]) -> LogicalIdentity:
    return LogicalIdentity.derive(EntityKind.AST_NODE, target_snapshot, {
        "scope_id": scope.scope_id, "grammar_sha256": grammar.sha256, "path": path,
        "file_sha256": file_sha256, "ordinal_path": list(node["ordinal_path"]),
        "type": node["type"], "start_byte": node["start_byte"], "end_byte": node["end_byte"],
    })


def normalize_scope(*, run_root: Path, target_snapshot: str, scope: Scope, grammar: GrammarLock,
                    fingerprint: str, container_output: Mapping[str, Any], producer: Mapping[str, Any],
                    artifact_path: Path, index_path: Path) -> tuple[Mapping[str, Any], IndexIdentity, Mapping[str, int]]:
    if container_output.get("schema") != "appsec-review/tree-sitter-container-output/1":
        raise ValueError("unsupported Tree-sitter container output schema")
    if container_output.get("scope_id") != scope.scope_id or container_output.get("language") != scope.language:
        raise ValueError("Tree-sitter output scope identity mismatch")
    accepted = {str(item["path"]): str(item["sha256"]) for item in scope.files}
    lines: list[bytes] = []
    gaps = [f"{item.get('path')}: {item.get('reason')}" for item in scope.exclusions]
    diagnostics = files_parsed = bytes_parsed = nodes_parsed = 0
    builder = IndexBuilder(index_path, name="analysis", fingerprint=fingerprint,
                           target_snapshot=target_snapshot, shard_id=scope.scope_id)
    seen_files: set[str] = set()
    for record in container_output.get("records", ()):
        path = str(record.get("path", ""))
        if path not in accepted or path in seen_files:
            raise ValueError("container returned an unaccepted or duplicate source path")
        seen_files.add(path)
        status = str(record.get("status"))
        if record.get("sha256") != accepted[path]:
            raise ValueError("container output source hash mismatch")
        if status == "TRUNCATED":
            gaps.append(f"{path}: {record.get('reason', 'truncated')}")
            builder.add_coverage(path, "partial", gaps[-1])
            continue
        files_parsed += 1
        bytes_parsed += int(record.get("bytes", 0))
        nodes = tuple(record.get("nodes", ()))
        nodes_parsed += len(nodes)
        ids: dict[tuple[int, ...], LogicalIdentity] = {}
        for node in nodes:
            ordinal = tuple(int(value) for value in node["ordinal_path"])
            identity = node_identity(target_snapshot, scope, grammar, path, accepted[path], node)
            ids[ordinal] = identity
            start = tuple(int(value) for value in node["start_point"])
            end = tuple(int(value) for value in node["end_point"])
            location = SourceLocation(
                target_snapshot, path, accepted[path], int(node["start_byte"]), int(node["end_byte"]),
                start[0] + 1, end[0] + 1, start[1] + 1, end[1] + 1,
                {"grammar": grammar.grammar, "ordinal_path": list(ordinal)},
                "tree-sitter-byte-and-point-exact", 1.0,
            )
            flags = {name: bool(node.get(name)) for name in ("named", "error", "missing", "extra", "has_error")}
            if flags["error"] or flags["missing"]:
                diagnostics += 1
            payload = {"schema": NORMALIZER_SCHEMA, "grammar_native_type": node["type"],
                       "field": node.get("field"), **flags, "scope_id": scope.scope_id,
                       "project_id": scope.project_id, "translation_scope_id": scope.translation_scope_id,
                       "language": scope.language, "syntax_only": True}
            builder.add_entity(EntityRecord(identity, "/".join(map(str, ordinal)) or "root",
                                             str(node["type"]), str(node["type"]), payload, location))
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
                source_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, target_snapshot,
                                                    {"path": path, "sha256": accepted[path]})
                # Duplicate the source entity in this shard so relation closure is independent.
                builder.add_entity(EntityRecord(source_id, path, path, path,
                                                 {"language": scope.language, "sha256": accepted[path]}))
                builder.add_relation(RelationRecord(RelationKind.CONTAINS, source_id.value,
                                                     ids[ordinal].value, True, 1.0,
                                                     payload={"syntax_relation": True}))
        if record.get("root_has_error"):
            gaps.append(f"{path}: parse diagnostics present")
        if record.get("truncated"):
            gaps.append(f"{path}: node limit reached")
        builder.add_coverage(path, "partial" if record.get("truncated") else "complete",
                             f"{path}: node limit reached" if record.get("truncated") else None)
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
    counts = {"files_parsed": files_parsed, "bytes_parsed": bytes_parsed,
              "nodes_parsed": nodes_parsed, "diagnostic_count": diagnostics,
              "gap_count": len(gaps)}
    return artifact, identity, counts
