from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import runpy
import stat

import pytest

from appsec_review.jobs.job_tree_sitter_ast import (
    GrammarLock, Scope, partition_scopes, plan_scopes, scope_fingerprint,
)
from appsec_review.jobs.job_tree_sitter_ast.model import SUPPORTED_LANGUAGES
from appsec_review.config import load_config
from appsec_review.jobs.job_tree_sitter_ast.normalize import (
    NORMALIZER_SCHEMA, node_identity, normalize_scope, reusable_shard,
)
from appsec_review.jobs.job_tree_sitter_ast.scope_execution import (
    _validate_container_output, _write_container_request,
)
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "tree_sitter_target"


def _lock(language: str = "Python", grammar: str = "python") -> GrammarLock:
    return GrammarLock(language, grammar, f"https://example.invalid/tree-sitter-{grammar}",
                       "a" * 40, "MIT", f"libtree_sitter_{grammar}.so", "b" * 64)


def _scope(language: str = "Python", digest: str = "c" * 64) -> Scope:
    return Scope("scope-python", "component:0001", "python", "source:component:0001",
                 "python", language, ({"path": "python/app.py", "sha256": digest,
                                       "size_bytes": 10, "language": language},))


def _node(*, ordinal=(), kind="module", error=False, missing=False, end=10):
    return {"ordinal_path": list(ordinal), "field": None, "type": kind, "named": True,
            "error": error, "missing": missing, "extra": False, "has_error": error or missing,
            "start_byte": 0, "end_byte": end, "start_point": [0, 0], "end_point": [0, end]}


def test_scope_routing_is_project_translation_and_language_specific() -> None:
    files = [
        {"path": "native/main.c", "sha256": "1" * 64, "language": "C", "generated": False},
        {"path": "python/app.py", "sha256": "2" * 64, "language": "Python", "generated": False},
        {"path": "web/src/index.ts", "sha256": "3" * 64, "language": "TypeScript", "generated": False},
        {"path": "web/src/view.tsx", "sha256": "4" * 64, "language": "TypeScript", "generated": False},
    ]
    catalog = {"files": files, "components": [
        {"component_id": "native", "root": "native"}, {"component_id": "python", "root": "python"},
        {"component_id": "web", "root": "web"}], "build_units": [
        {"build_unit_id": "native-build", "root": "native"},
        {"build_unit_id": "web-build", "root": "web"}],
        "gaps": [{"path": "web/vendor", "reason": "excluded_directory"}]}
    scopes = plan_scopes(catalog)
    assert {(value.project_id, value.translation_scope_id, value.language) for value in scopes} == {
        ("native", "native-build", "C"), ("python", "source:python", "Python"),
        ("web", "web-build", "TypeScript"), ("web", "web-build", "TSX"),
    }
    assert next(value for value in scopes if value.language == "TypeScript").exclusions[0]["path"] == "web/vendor"


def test_scope_routing_chunks_large_partitions_deterministically() -> None:
    files = [{"path": f"python/{index}.py", "sha256": f"{index:064x}", "language": "Python",
              "generated": False, "size_bytes": 10} for index in range(5)]
    catalog = {"files": files, "components": [{"component_id": "python", "root": "python"}]}
    first = plan_scopes(catalog, max_files_per_scope=2, max_source_bytes_per_scope=100)
    assert [len(scope.files) for scope in first] == [2, 2, 1]
    assert first == plan_scopes(catalog, max_files_per_scope=2, max_source_bytes_per_scope=100)
    assert len({scope.scope_id for scope in first}) == 3


def test_canonical_node_identity_and_scope_fingerprint_are_deterministic_and_partition_local() -> None:
    scope = _scope()
    grammar = _lock()
    node = _node(ordinal=(0, 1), kind="identifier", end=4)
    assert node_identity("snapshot", scope, grammar, "python/app.py", "c" * 64, node) == node_identity(
        "snapshot", scope, grammar, "python/app.py", "c" * 64, dict(reversed(list(node.items()))))
    first = scope_fingerprint(target_snapshot="snapshot", scope=scope, grammar=grammar,
                              image_id="sha256:" + "d" * 64, normalizer_schema=NORMALIZER_SCHEMA,
                              limits={"max_nodes": 10, "max_file_bytes": 100})
    assert first == scope_fingerprint(target_snapshot="snapshot", scope=scope, grammar=grammar,
        image_id="sha256:" + "d" * 64, normalizer_schema=NORMALIZER_SCHEMA,
        limits={"max_file_bytes": 100, "max_nodes": 10})
    changed = replace(scope, files=({**scope.files[0], "sha256": "e" * 64},))
    assert first != scope_fingerprint(target_snapshot="snapshot", scope=changed, grammar=grammar,
        image_id="sha256:" + "d" * 64, normalizer_schema=NORMALIZER_SCHEMA,
        limits={"max_file_bytes": 100, "max_nodes": 10})


def test_normalization_preserves_spans_fields_malformed_flags_and_truncation(tmp_path: Path) -> None:
    scope, grammar = _scope(), _lock()
    output = {"schema": "appsec-review/tree-sitter-container-output/1", "scope_id": scope.scope_id,
              "language": scope.language, "records": [{"kind": "file", "path": "python/app.py",
              "status": "PARTIAL", "sha256": "c" * 64, "bytes": 10, "root_has_error": True,
              "truncated": True, "nodes": [_node(error=True), {**_node(ordinal=(0,), kind="ERROR", missing=True),
              "field": "body"}]}]}
    artifact, identity, counts = normalize_scope(run_root=tmp_path, target_snapshot="snapshot",
        scope=scope, grammar=grammar, fingerprint="f" * 64, container_output=output,
        producer={"job": "fixture"}, artifact_path=tmp_path / "ast.jsonl", index_path=tmp_path / "ast.sqlite")
    rows = [json.loads(line) for line in (tmp_path / artifact["path"]).read_text().splitlines()]
    child = next(row for row in rows if row["field"] == "body")
    assert child["location"]["start_line"] == 1 and child["location"]["start_column"] == 1
    assert child["grammar_native_type"] == "ERROR" and child["missing"] and child["syntax_only"]
    assert counts["diagnostic_count"] == 2 and counts["nodes_parsed"] == 2
    assert any("node limit" in gap for gap in identity.gaps)


def test_unavailable_grammar_is_an_explicit_gap() -> None:
    runnable, gaps = partition_scopes((_scope("Swift"),), {"Python": _lock()})
    assert runnable == ()
    assert gaps == ({"scope_id": "scope-python", "language": "Swift",
                     "terminal_status": "UNAVAILABLE", "reason": "grammar unavailable",
                     "gaps": []},)


def test_supported_languages_have_locked_offline_grammars() -> None:
    lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" /
                       "assets.lock.json").read_text(encoding="utf-8"))
    locked = {item["language"] for item in lock["grammars"]} | {"C/C++"}
    assert locked == SUPPORTED_LANGUAGES
    expected = {
        "Kotlin": ("kotlin", "c8ac3d2627240160b999a2c100de3babbdb8f419",
                   "4ba2c2f1b00fb74350a335aadc287e4bcd82f8cbec2848f644cc95279ad44a1c"),
        "PowerShell": ("powershell", "d398441825243b00e317e87e1829b9d6a3e54ce0",
                       "610c910b6fb4b265894cf8af035d597d87abef2838206bccaa204629034c09c8"),
        "Shell": ("bash", "a06c2e4415e9bc0346c6b86d401879ffb44058f7",
                  "0a3c99ddb5ba49f35fb890d893af8483049bf9d8d7b1261730acc2488e3d3379"),
        "Ruby": ("ruby", "ad907a69da0c8a4f7a943a7fe012712208da6dee",
                 "c1c22f6a62595422e154fabedae9218ee92bf1a307c42965b7272b2531503bf8"),
    }
    identities = {item["language"]: item for item in lock["grammars"]}
    for language, (grammar, revision, digest) in expected.items():
        assert (identities[language]["grammar"], identities[language]["revision"],
                identities[language]["sha256"]) == (grammar, revision, digest)
        assert identities[language]["license"] == "MIT"


def test_container_parser_and_acquisition_route_every_supported_language() -> None:
    # parser.py and acquire_assets.py run inside tool-tree-sitter, which installs the pinned
    # tree-sitter packages; reviews never import them on the host. Run this where they exist.
    pytest.importorskip("tree_sitter_language_pack",
                        reason="tree-sitter packages are installed only in the tool-tree-sitter image")
    parser = runpy.run_path(str(ROOT / "containers" / "tools" / "tree-sitter" / "parser.py"))
    acquisition = runpy.run_path(str(ROOT / "containers" / "tools" / "tree-sitter" /
                                       "acquire_assets.py"))
    assert set(parser["LANGUAGES"]) == SUPPORTED_LANGUAGES
    assert set(parser["LANGUAGES"].values()) == set(acquisition["LANGUAGES"])
    lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" /
                       "assets.lock.json").read_text(encoding="utf-8"))
    for item in lock["grammars"]:
        assert parser["LANGUAGES"][item["language"]] == item["grammar"]


def test_supported_run_grammars_are_runnable_but_unknown_languages_remain_gaps() -> None:
    languages = ("Kotlin", "PowerShell", "Ruby", "Shell")
    scopes = tuple(replace(_scope(language), scope_id=f"scope-{language.lower()}")
                   for language in languages)
    locks = {language: _lock(language, {"Kotlin": "kotlin", "PowerShell": "powershell",
                                       "Ruby": "ruby", "Shell": "bash"}[language]) for language in languages}
    runnable, gaps = partition_scopes((*scopes, _scope("Swift")), locks)
    assert [scope.language for scope in runnable] == list(languages)
    assert gaps == ({"scope_id": "scope-python", "language": "Swift",
                     "terminal_status": "UNAVAILABLE", "reason": "grammar unavailable",
                     "gaps": []},)


def test_container_request_is_readable_and_scratch_is_writable_by_runtime_user(tmp_path: Path) -> None:
    request_path = _write_container_request(tmp_path / "scope", {"schema": "fixture"})
    request_mode = request_path.stat().st_mode
    scratch_mode = request_path.parent.stat().st_mode
    assert request_mode & stat.S_IROTH
    if os.name != "nt":
        assert not request_mode & stat.S_IWOTH
    assert scratch_mode & stat.S_IWOTH
    assert scratch_mode & stat.S_IXOTH


def test_resume_requires_matching_fingerprint_and_both_immutable_hashes(tmp_path: Path) -> None:
    artifact, index, metadata = tmp_path / "a.jsonl", tmp_path / "a.sqlite", tmp_path / "a.json"
    artifact.write_bytes(b"ast\n")
    index.write_bytes(b"index")
    atomic_json(metadata, {"fingerprint": "f" * 64,
                           "artifact": {"sha256": file_sha256(artifact)},
                           "index_identity": {"sha256": file_sha256(index)}})
    assert reusable_shard(metadata, artifact, index, "f" * 64) is not None
    assert reusable_shard(metadata, artifact, index, "0" * 64) is None
    index.write_bytes(b"changed")
    assert reusable_shard(metadata, artifact, index, "f" * 64) is None


def test_container_output_must_match_locked_tool_image_and_grammar_identity() -> None:
    lock = {"tool_version": "1.0.0", "tree_sitter": {"version": "0.26.0"},
            "language_pack": {"version": "1.12.5"},
            "normalizer_schema": NORMALIZER_SCHEMA}
    output = {"tool": {"id": "tool-tree-sitter", "version": "1.0.0",
        "tree_sitter": "0.26.0", "language_pack": "1.12.5",
        "normalizer_schema": NORMALIZER_SCHEMA, "architecture": "x86_64"},
        "records": [{"status": "SUCCEEDED", "grammar": "python"}]}
    _validate_container_output(output, scope=_scope(), grammar=_lock(), asset_lock=lock,
                               image_id="sha256:locked", execution_image_id="sha256:locked")
    output["tool"]["tree_sitter"] = "changed"
    with pytest.raises(ValueError, match="asset lock"):
        _validate_container_output(output, scope=_scope(), grammar=_lock(), asset_lock=lock,
                                   image_id="sha256:locked", execution_image_id="sha256:locked")


def test_both_callers_share_metrics_and_ast_reuse_is_not_an_invocation(tmp_path: Path) -> None:
    from dataclasses import asdict
    from appsec_review.container_runtime import ContainerExecutor, load_catalog
    from appsec_review.jobs.job_tree_sitter_ast.job import _grammar_locks
    from appsec_review.jobs.job_tree_sitter_ast.scope_execution import parse_scope
    from appsec_review.observability import aggregate_run_metrics
    from tests.integration.job_source_history_analysis.test_analysis import LocalDocker, invoke_symbols, symbol_unit

    unit = symbol_unit(tmp_path, {"python/app.py": ("Python", "def check():\n    return 1\n")})
    docker = LocalDocker()
    invoke_symbols(unit, docker)
    locks, assets = _grammar_locks(ROOT)
    tool = load_catalog(ROOT).tool("tool-tree-sitter")
    config = load_config(ROOT / "appsec-review.toml").job("job_tree_sitter_ast")
    ast_unit = replace(unit, job=replace(unit.job, config=config), unit_id="parse.scope", step_id="parse",
                       task_id="scope", outputs={"load.accepted_inputs": {
                           "grammar_locks": {key: asdict(value) for key, value in locks.items()},
                           "asset_lock": assets, "image_id": tool.expected_image_id}})
    scope = _scope(digest=file_sha256(unit.job.target_root / "python/app.py"))
    scope = replace(scope, files=({**scope.files[0],
                                  "size_bytes": (unit.job.target_root / "python/app.py").stat().st_size},))
    factory = lambda context: ContainerExecutor(load_catalog(ROOT), context.job.run_root, runner=docker)
    first = parse_scope(ast_unit, asdict(scope), factory)
    second = parse_scope(ast_unit, asdict(scope), factory)
    assert not first["index_reused"] and second["index_reused"]
    assert first["tree_sitter_invocation_id"] == second["tree_sitter_invocation_id"]
    summary = aggregate_run_metrics(unit.job.run_root)["tree_sitter"]
    assert summary["invocation_count"] == 2 and summary["reused_scope_count"] == 1
    assert len({row["invocation_id"] for row in summary["invocations"]}) == 2
    assert {row["job_id"] for row in summary["by_job_attempt"]} == {
        "job_source_history_analysis", "job_tree_sitter_ast"}
    assert summary["counts"]["files_parsed"] == {"value": 2, "complete": True}
    assert summary["measurements"]["memory_peak_bytes"]["value"] is None
    assert summary["incomplete_accounting"], "mocked counters must not be reported as measured zeros"
