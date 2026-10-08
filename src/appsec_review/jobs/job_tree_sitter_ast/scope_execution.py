from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
from appsec_review.runtime import UnitContext
from appsec_review.storage import atomic_json

from .model import GrammarLock, Scope, scope_fingerprint
from .normalize import NORMALIZER_SCHEMA, normalize_scope, reusable_shard


ExecutorFactory = Callable[[UnitContext], ContainerExecutor]
SCHEMA = "appsec-review/tree-sitter-ast/1"


def _validate_container_output(output: Mapping[str, Any], *, scope: Scope, grammar: GrammarLock,
                               asset_lock: Mapping[str, Any], image_id: str,
                               execution_image_id: str) -> None:
    if execution_image_id != image_id:
        raise ValueError("Tree-sitter execution image identity changed after planning")
    tool = output.get("tool")
    if not isinstance(tool, Mapping) or tool.get("id") != "tool-tree-sitter":
        raise ValueError("Tree-sitter output omitted the locked tool identity")
    expected = {
        "version": asset_lock["tool_version"],
        "tree_sitter": asset_lock["tree_sitter"]["version"],
        "language_pack": asset_lock["language_pack"]["version"],
        "normalizer_schema": asset_lock["normalizer_schema"],
        "architecture": "x86_64",
    }
    if any(tool.get(key) != value for key, value in expected.items()):
        raise ValueError("Tree-sitter output tool identity does not match the asset lock")
    for record in output.get("records", ()):
        if record.get("status") not in {"SUCCEEDED", "PARTIAL", "TRUNCATED"}:
            raise ValueError("Tree-sitter output contains an invalid file disposition")
        if record.get("status") != "TRUNCATED" and record.get("grammar") != grammar.grammar:
            raise ValueError("Tree-sitter output grammar identity does not match the scope lock")


def parse_scope(unit: UnitContext, raw_scope: Mapping[str, Any],
                executor_factory: ExecutorFactory | None = None) -> Mapping[str, Any]:
    loaded = unit.output("load.accepted_inputs")
    settings = unit.job.config.settings
    scope = Scope(**{**raw_scope, "files": tuple(raw_scope["files"]),
                     "exclusions": tuple(raw_scope.get("exclusions", ()))})
    grammar = GrammarLock(**loaded["grammar_locks"][scope.language])
    limits = {"max_file_bytes": int(settings["max_file_bytes"]),
              "max_nodes": int(settings["max_nodes_per_file"]),
              "max_scope_nodes": int(settings["max_nodes_per_scope"])}
    fingerprint = scope_fingerprint(target_snapshot=unit.job.source_fingerprint, scope=scope,
        grammar=grammar, image_id=loaded["image_id"], normalizer_schema=NORMALIZER_SCHEMA, limits=limits)
    artifact_path = unit.job.run_root / "data" / "treesitter" / "shards" / f"{fingerprint}.jsonl"
    index_path = unit.job.run_root / "data" / "indices" / "analysis" / f"{fingerprint}.sqlite"
    metadata_path = unit.job.run_root / "data" / "treesitter" / "shards" / f"{fingerprint}.json"
    metadata = reusable_shard(metadata_path, artifact_path, index_path, fingerprint)
    if metadata is not None:
        return {**metadata, "index_reused": True}
    scratch = (unit.job.run_root / "data" / "treesitter" / "work" / unit.job.attempt_id /
               hashlib.sha256(scope.scope_id.encode()).hexdigest()[:20])
    scratch.mkdir(parents=True, exist_ok=True)
    request = {"schema": "appsec-review/tree-sitter-request/1", "scope_id": scope.scope_id,
               "language": scope.language, "max_nodes": limits["max_nodes"],
               "max_scope_nodes": limits["max_scope_nodes"],
               "max_file_bytes": limits["max_file_bytes"],
               "files": [{"path": item["path"], "sha256": item["sha256"]} for item in scope.files]}
    request_path = scratch / "request.json"
    atomic_json(request_path, request)
    # The production scanner deliberately runs as a different, non-root UID.  Grant it only the
    # permissions needed on this dedicated run-owned boundary: read the immutable request and
    # create its declared output.  The target mount remains read-only.
    request_path.chmod(0o444)
    scratch.chmod(0o733)
    executor = executor_factory(unit) if executor_factory else ContainerExecutor(
        load_catalog(unit.job.repository_root), unit.job.run_root)
    execution = executor.execute(ExecutionRequest("tool-tree-sitter",
        ("/opt/appsec/parser.py", "parse", "--request", "/scratch/request.json",
         "--output", "/scratch/output.json"), unit.job.target_root or Path(), scratch,
        working_directory="/scratch"))
    if execution.exit_code != 0 or execution.timed_out or execution.oom_killed:
        return {"scope_id": scope.scope_id, "language": scope.language, "fingerprint": fingerprint,
                "terminal_status": "FAILED", "gaps": [f"container parser failed with exit {execution.exit_code}"],
                "execution": asdict(execution), "index_reused": False}
    output_path = scratch / "output.json"
    if not output_path.is_file():
        raise ValueError("Tree-sitter container omitted its declared output")
    container_output = json.loads(output_path.read_text(encoding="utf-8"))
    _validate_container_output(container_output, scope=scope, grammar=grammar,
        asset_lock=loaded["asset_lock"], image_id=loaded["image_id"],
        execution_image_id=execution.image_id)
    artifact, identity, counts = normalize_scope(run_root=unit.job.run_root,
        target_snapshot=unit.job.source_fingerprint, scope=scope, grammar=grammar,
        fingerprint=fingerprint, container_output=container_output,
        producer={"job": "job_tree_sitter_ast", "scope_id": scope.scope_id,
                  "image_id": execution.image_id, "grammar": asdict(grammar)},
        artifact_path=artifact_path, index_path=index_path)
    result = {"schema": SCHEMA, "scope_id": scope.scope_id, "project_id": scope.project_id,
              "translation_scope_id": scope.translation_scope_id, "language": scope.language,
              "fingerprint": fingerprint, "grammar": asdict(grammar), "artifact": artifact,
              "index_identity": asdict(identity), "counts": counts, "execution": asdict(execution),
              "gaps": list(identity.gaps), "truncated": any("limit" in gap for gap in identity.gaps),
              "terminal_status": "PARTIAL" if identity.gaps else "SUCCEEDED", "index_reused": False}
    atomic_json(metadata_path, result)
    return result
