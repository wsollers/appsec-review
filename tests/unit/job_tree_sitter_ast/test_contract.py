"""Code-level contract pins, dataset declarations, validator bounds, and node-shard schema parity."""

from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.inventory import compile_glob
from appsec_review.jobs.job_tree_sitter_ast.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_tree_sitter_ast.job import (
    TOPOLOGY as JOB_TOPOLOGY,
    _grammar_locks,
    _read_verified,
    _validate,
    build_job,
)
from appsec_review.jobs.job_tree_sitter_ast.model import GrammarLock, Scope
from appsec_review.jobs.job_tree_sitter_ast.normalize import normalize_scope
from appsec_review.orchestration.topology import wave1_dependencies
from appsec_review.runtime.datasets import validate_declarations
from appsec_review.runtime.registry import builtin_contracts, builtin_registry
from appsec_review.storage import atomic_json, file_sha256

ROOT = Path(__file__).resolve().parents[3]


def test_every_input_requirement_and_dispatch_field_is_pinned() -> None:
    expected = [
        ("job_language_build", "handoff", "appsec-review/job-handoff/2"),
        ("job_language_build", "topology_refinement_inputs", "appsec-review/build-topology-refinement/1"),
        ("job_language_build", "build_actions", "appsec-review/retrieval-index/2"),
        ("job_language_build", "jvm_build_actions", "appsec-review/retrieval-index/2"),
        ("job_language_build", "language_build_receipts", "appsec-review/language-build-handoff/2"),
        ("job_language_build", "build_workspaces", "application/octet-stream"),
        ("job_review_intake", "handoff", "appsec-review/job-handoff/2"),
        ("job_review_intake", "model_preflight", "appsec-review/model-preflight/1"),
        ("job_review_intake", "binary_evidence", "appsec-review/binary-evidence-intake/1"),
        ("job_review_intake", "review_intake", "appsec-review/review-intake/1"),
        ("job_target_catalog", "handoff", "appsec-review/job-handoff/2"),
        ("job_target_catalog", "target_artifact_inputs", "appsec-review/target-artifact-intake/1"),
        ("job_target_catalog", "source_files", "appsec-review/retrieval-index/2"),
        ("job_target_catalog", "declaration_symbols", "appsec-review/retrieval-index/2"),
        ("job_target_catalog", "components", "appsec-review/retrieval-index/2"),
        ("job_target_catalog", "target_documents", "appsec-review/retrieval-index/2"),
        ("job_target_catalog", "build_units", "appsec-review/retrieval-index/2"),
        ("job_target_catalog", "catalog_documents", "appsec-review/target-catalog/1"),
    ]
    assert [asdict(item) for item in CONTRACT.inputs] == [
        {
            "producer": producer,
            "output_kind": kind,
            "schema": schema,
            "authority": "producer_evidence",
            "availability": "required" if (producer, kind) == ("job_target_catalog", "handoff") else "optional",
            "missing": "reject" if (producer, kind) == ("job_target_catalog", "handoff") else "gap",
            "coverage": "allow_partial",
            "channel": "handoff",
        }
        for producer, kind, schema in expected
    ]
    assert {key: value for key, value in asdict(CONTRACT).items() if key != "inputs"} == {
        "schedule_after": ("job_language_build",),
        "dispatch": "review_graph",
        "target_access": "checkout",
        "always_execute": False,
        "propagate_handoff": True,
    }
    job = build_job()
    registered = builtin_registry().build("job_tree_sitter_ast")
    assert registered.job_id == job.job_id == "job_tree_sitter_ast"
    assert job.contract is CONTRACT
    assert job.datasets is DATASETS
    assert job.consumes == ("job_language_build", "job_review_intake", "job_target_catalog")


def test_wave1_dependencies_toggle_language_build_ordering() -> None:
    registered = set(builtin_contracts())
    deps = wave1_dependencies(registered)
    assert deps is not None
    assert "job_language_build" in deps["job_tree_sitter_ast"]
    deps_no_lb = wave1_dependencies(registered - {"job_language_build"})
    assert deps_no_lb is not None
    assert "job_language_build" not in deps_no_lb["job_tree_sitter_ast"]


def test_every_dataset_field_is_pinned() -> None:
    validate_declarations("job_tree_sitter_ast", DATASETS)
    common = {
        "family": "syntax",
        "sensitivity": "internal",
        "indexes": (),
        "shard_prefixes": (),
        "shard_suffixes": (),
        "artifacts": (),
        "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
        "reason": None,
        "required": False,
        "store": "retrieval",
        "authority": "producer_evidence",
    }
    attempt = "data/jobs/job_tree_sitter_ast/attempts/*"
    expected = [
        {
            **common,
            "output_kind": "tree_sitter_ast",
            "step": "parse",
            "schema": "appsec-review/tree-sitter-normalizer/1",
            "disposition": "indexed",
            "description": (
                "Bounded Tree-sitter AST nodes, byte-exact spans, parent relations and unresolved syntax navigation."
            ),
            "indexes": ("analysis",),
            "query_route": "query_syntax subject=source_file/ast_node; find/trace/search index=analysis kind=ast_node",
        },
        {
            **common,
            "output_kind": "tree_sitter_coverage",
            "step": "acceptance",
            "schema": "appsec-review/tree-sitter-ast/1",
            "disposition": "indexed",
            "description": "Per-scope parse dispositions, including unavailable grammars and truncation.",
            "indexes": ("analysis",),
            "shard_prefixes": ("tree-sitter-coverage-",),
            "query_route": "coverage index=analysis",
        },
        {
            **common,
            "output_kind": "tree_sitter_node_shards",
            "step": "parse",
            "schema": "appsec-review/tree-sitter-normalizer/1",
            "disposition": "artifact_only",
            "description": "Normalized Tree-sitter syntax node JSONL shards.",
            "artifacts": ("data/treesitter/shards/*.jsonl",),
            "reason": "same nodes as the accepted analysis shards; kept for deterministic reuse",
        },
        {
            **common,
            "output_kind": "tree_sitter_scope_results",
            "step": "parse",
            "schema": "appsec-review/tree-sitter-ast/1",
            "disposition": "artifact_only",
            "description": "Per-scope Tree-sitter parse metadata and dynamic scope outcomes.",
            "artifacts": (
                "data/treesitter/shards/*.json",
                attempt + "/steps/parse/tasks/dynamic_scopes/dynamic/*.json",
            ),
            "reason": (
                "per-scope metadata records shard reuse and dynamic fan-out outcomes; syntax queries use "
                "accepted analysis shards"
            ),
        },
        {
            **common,
            "output_kind": "tree_sitter_acceptance",
            "step": "acceptance",
            "schema": "appsec-review/tree-sitter-ast/1",
            "disposition": "artifact_only",
            "description": "Accepted Tree-sitter summary, file dispositions, and shard manifest.",
            "artifacts": (attempt + "/steps/acceptance/tasks/publish_handoff/accepted-tree-sitter-ast.json",),
            "reason": "accepted Tree-sitter publication maps files to normalized node shards for syntax consumers",
        },
        {
            **common,
            "output_kind": "generated_source_backing",
            "step": "load",
            "schema": "appsec-review/generated-source-backing/1",
            "disposition": "artifact_only",
            "description": "Bounded accepted generated-source provenance; bytes reside in run-owned shared objects.",
            "artifacts": ("data/treesitter/sources/*.json",),
            "reason": "immutable source custody for AST and downstream resolving spans",
        },
        {
            **common,
            "output_kind": "tree_sitter_tool_io",
            "step": "parse",
            "schema": "appsec-review/container-execution/1",
            "sensitivity": "sensitive",
            "disposition": "protected",
            "description": "Parser container requests, raw output and streams.",
            "artifacts": ("data/treesitter/work/**", "data/treesitter/inputs/**"),
            "reason": "raw tool streams and receipts may contain unredacted target content and host paths",
        },
    ]
    assert [asdict(item) for item in DATASETS] == expected


def test_validator_enforces_topology_step_order_and_numeric_bounds() -> None:
    job_cfg = load_config(ROOT / "appsec-review.toml").job("job_tree_sitter_ast")
    _validate(SimpleNamespace(config=job_cfg), None)

    bad_steps = replace(job_cfg, steps={})
    with pytest.raises(ValueError, match="topology does not match"):
        _validate(SimpleNamespace(config=bad_steps), None)

    bad_load_step = replace(job_cfg.steps["load"], tasks={})
    bad_tasks = replace(job_cfg, steps={**job_cfg.steps, "load": bad_load_step})
    with pytest.raises(ValueError, match="task order mismatch: load"):
        _validate(SimpleNamespace(config=bad_tasks), None)
    assert tuple(JOB_TOPOLOGY) == ("load", "plan", "parse", "acceptance")

    for key, bad_value, match in (
        ("workers", True, "setting is invalid: workers"),
        ("workers", 0, "setting is invalid: workers"),
        ("workers", 33, "exceed the production ceiling"),
        ("max_file_bytes", 16 * 1024 * 1024 + 1, "exceed the production ceiling"),
        ("max_files_per_scope", 1025, "exceed the production ceiling"),
        ("max_source_bytes_per_scope", 128 * 1024 * 1024 + 1, "exceed the production ceiling"),
        ("max_nodes_per_file", 500_001, "exceed the production ceiling"),
        ("max_nodes_per_scope", 500_001, "exceed the production ceiling"),
    ):
        mutated = replace(job_cfg, settings={**job_cfg.settings, key: bad_value})
        with pytest.raises(ValueError, match=match):
            _validate(SimpleNamespace(config=mutated), None)


def test_grammar_locks_and_read_verified_enforce_invariants(tmp_path: Path) -> None:
    locks, doc = _grammar_locks(ROOT)
    assert doc["image_id"] == "tool-tree-sitter"
    assert locks["C/C++"] == locks["C++"]

    fake_repo = tmp_path / "repo"
    lock_file = fake_repo / "containers" / "tools" / "tree-sitter" / "assets.lock.json"
    atomic_json(lock_file, {"schema": "wrong/1", "image_id": "tool-tree-sitter"})
    with pytest.raises(ValueError, match="asset lock identity is invalid"):
        _grammar_locks(fake_repo)

    atomic_json(lock_file, {"schema": "appsec-review/assets-lock/1", "image_id": "wrong-tool"})
    with pytest.raises(ValueError, match="asset lock identity is invalid"):
        _grammar_locks(fake_repo)

    run_root = tmp_path / "run"
    run_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="unavailable or outside the run"):
        _read_verified(run_root, {"path": "../outside.json", "sha256": file_sha256(outside)})
    with pytest.raises(ValueError, match="unavailable or outside the run"):
        _read_verified(run_root, {"path": "missing.json", "sha256": "0" * 64})

    inside = run_root / "list.json"
    inside.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="hash changed"):
        _read_verified(run_root, {"path": "list.json", "sha256": "0" * 64})
    with pytest.raises(ValueError, match="must be an object"):
        _read_verified(run_root, {"path": "list.json", "sha256": file_sha256(inside)})


def test_emitted_node_shard_matches_its_declared_artifact_schema(tmp_path: Path) -> None:
    data = b"x = 1\n"
    digest = hashlib.sha256(data).hexdigest()
    fingerprint = "f" * 64
    scope = Scope(
        "python-scope", "component", ".", "source:component", ".", "Python",
        ({"path": "app.py", "sha256": digest, "size_bytes": len(data), "language": "Python"},),
    )
    grammar = GrammarLock(
        "Python", "python", "https://example.invalid/grammar", "a" * 40, "MIT", "python.so", "b" * 64,
    )
    output = {
        "schema": "appsec-review/tree-sitter-container-output/1",
        "scope_id": scope.scope_id,
        "language": "Python",
        "records": [{
            "path": "app.py",
            "sha256": digest,
            "status": "SUCCEEDED",
            "bytes": len(data),
            "nodes": [{
                "ordinal_path": [],
                "type": "module",
                "named": True,
                "start_byte": 0,
                "end_byte": len(data),
                "start_point": [0, 0],
                "end_point": [1, 0],
            }],
        }],
    }
    artifact_path = tmp_path / "data/treesitter/shards" / f"{fingerprint}.jsonl"
    index_path = tmp_path / "data/indices/analysis" / f"{fingerprint}.sqlite"
    artifact, identity, counts = normalize_scope(
        run_root=tmp_path, target_snapshot="c" * 64, scope=scope, grammar=grammar,
        fingerprint=fingerprint, container_output=output,
        producer={"job": "job_tree_sitter_ast", "scope_id": scope.scope_id},
        artifact_path=artifact_path, index_path=index_path, source_bytes={"app.py": data},
    )
    assert artifact["path"] == f"data/treesitter/shards/{fingerprint}.jsonl"
    assert artifact["sha256"] == hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    assert artifact["size_bytes"] == artifact_path.stat().st_size
    assert identity.shard_id == "python-scope"
    assert identity.gaps == ()
    assert counts == {
        "files_parsed": 1,
        "bytes_parsed": 6,
        "nodes_parsed": 1,
        "diagnostic_count": 0,
        "gap_count": 0,
        "dispositions": {
            "files": {"first_party": 1},
            "nodes": {"first_party": 1},
            "excluded_files": {},
        },
    }
    [record] = [json.loads(line) for line in artifact_path.read_text(encoding="utf-8").splitlines()]
    assert record["path"] == "app.py"
    assert record["file_sha256"] == digest
    assert record["location"]["start_byte"] == 0
    assert record["location"]["end_byte"] == len(data)
    [declaration] = [
        item for item in DATASETS
        if any(compile_glob(pattern).fullmatch(artifact["path"]) for pattern in item.artifacts)
    ]
    assert declaration.output_kind == "tree_sitter_node_shards"
    assert record["schema"] == declaration.schema
