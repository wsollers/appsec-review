"""Tree-sitter shards are secondary producers assigned to the CodeQL scope whose files they parsed (T-5016).

On smoke-cpp run 2026-11-14-0005 the load unit assigned no secondary shard: the clangd job had indexed
nothing (its build unit was BLOCKED_BY_COMPILE on a low-confidence heuristic gap), the Clang AST and IR
shards were empty, and the three populated tree-sitter shards were not a recognised producer.
"""
from __future__ import annotations

from appsec_review.graph.contract import Producer
from appsec_review.jobs.job_code_graph_index import scopes as s
from tests.fixtures.graph.secondary.builder import TREE_SITTER_SCOPE, build_secondary


def _scope(scope_id: str, *paths: str) -> dict:
    return {"scope_id": scope_id, "language": "cpp", "export_status": s.SUCCEEDED,
            "files": [{"path": path, "sha256": "0" * 64} for path in paths]}


def test_tree_sitter_scope_shards_are_a_producer_and_coverage_shards_are_not() -> None:
    assert s.secondary_producer({"name": "analysis", "shard_id": TREE_SITTER_SCOPE,
                                 "producer": {"job": "job_tree_sitter_ast"}}) is Producer.TREE_SITTER
    assert s.secondary_producer({"name": "analysis", "shard_id": "tree-sitter-coverage-attempt_0001",
                                 "producer": {"job": "job_tree_sitter_ast"}}) is None
    assert s.secondary_producer({"name": "observations", "shard_id": TREE_SITTER_SCOPE,
                                 "producer": {"job": "job_tree_sitter_ast"}}) is None
    assert Producer.TREE_SITTER in s.SECONDARY_PRODUCERS and Producer.TREE_SITTER in s.CALL_EDGE_PRODUCERS
    assert "job_tree_sitter_ast" in s.SECONDARY_JOBS and Producer.TREE_SITTER in s.CARD_PRODUCER_ORDER


def test_tree_sitter_and_clangd_shards_go_to_the_scope_holding_their_files(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    shards = list(fixture.shard_set.shards)
    native = _scope("codeql-cpp-native-main", "src/net.c", "src/io.c")
    other = _scope("codeql-cpp-other", "other/x.c")
    assigned = s.assign_secondary(fixture.run_root, shards, [native, other])
    assert [item["shard_id"] for item in assigned["codeql-cpp-native-main"]["tree-sitter"]] == [TREE_SITTER_SCOPE]
    assert [item["shard_id"] for item in assigned["codeql-cpp-native-main"]["clangd"]] == ["clangd-native"]
    assert assigned["codeql-cpp-other"]["tree-sitter"] == [] and assigned["codeql-cpp-other"]["clangd"] == []
    # A shard serves exactly one scope: a second scope sharing one file does not get a copy.
    overlapping = _scope("codeql-cpp-aaa", "src/io.c")
    assigned = s.assign_secondary(fixture.run_root, shards, [native, overlapping])
    owners = [scope_id for scope_id, values in assigned.items() if values["tree-sitter"]]
    assert owners == ["codeql-cpp-native-main"]


def test_a_shard_touching_no_scope_file_is_not_assigned(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    assigned = s.assign_secondary(fixture.run_root, list(fixture.shard_set.shards), [_scope("codeql-cpp-x", "elsewhere/a.c")])
    assert assigned == {"codeql-cpp-x": {producer.value: [] for producer in s.SECONDARY_PRODUCERS}}
