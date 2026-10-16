"""Offline end-to-end acceptance for seeded neighborhoods (docs/architecture/seeded-neighborhoods.md 11).

One run over the 12-translation-unit fixture project (two finding locations: ``src/util.cpp:14`` and
``src/net.cpp:6``) goes through, in order:

* the evidence observation shard that carries the seeds;
* the seeded CodeQL handoff (ledger, export files and manifest; no CodeQL runs);
* the real seeded Clang AST / LLVM IR branch handlers and the real seeded Clang-Tidy / Static Analyzer scope
  handler on recorded output, through injected executors;
* the real ``job_code_graph_index`` and ``job_review_data_indexing`` jobs through ``JobRunner``;
* the retrieval core, the MCP adapter and a review role's scoped adapter over the accepted manifest.

Nothing runs a container.  ``tests/test_seeded_*.py`` cover each producer in isolation.
"""
from __future__ import annotations

import json
from pathlib import Path
import time
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from appsec_review.graph.contract import GRAPH_INDEX
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_code_graph_index import build_job as build_graph_job
from appsec_review.jobs.job_review_data_indexing import build_job as build_indexing_job
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime.runner import JobRunner
from tests import seeded_clang_support as sc
from tests.seeded_pipeline_support import SCOPE, SEED_FUNCTIONS, SNAPSHOT, stage_pipeline

SEEDS = {("src/util.cpp", 14), ("src/net.cpp", 6)}
REPLAYED = ("proj/src/net.cpp", "proj/src/util.cpp")
SECRET = b"s" * 32


def _offline_fts(unit):
    raise RuntimeError("the pinned FTS5 image is not available in the offline end-to-end test")


def _graph(pipeline, *, indexing: bool) -> Mapping[str, Any]:
    outcomes = {"graph": JobRunner(pipeline.config).run(build_graph_job(), run_id=pipeline.run_id,
                                                        target_root=pipeline.target, source_fingerprint=SNAPSHOT)}
    if indexing:
        outcomes["indexing"] = JobRunner(pipeline.config).run(
            build_indexing_job(executor_factory=_offline_fts), run_id=pipeline.run_id, target_root=pipeline.target,
            source_fingerprint=SNAPSHOT)
    return outcomes


def _outputs(outcome: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads((Path(outcome["attempt_root"]) / "result.json").read_text(encoding="utf-8"))["outputs"]


@pytest.fixture(scope="module")
def run(tmp_path_factory) -> SimpleNamespace:
    pipeline = stage_pipeline(tmp_path_factory.mktemp("seeded-e2e"))
    outcomes = _graph(pipeline, indexing=True)
    core = RetrievalCore(pipeline.runs, pipeline.run_id)
    (card,) = core.list_codeql_databases()["results"]
    return SimpleNamespace(pipeline=pipeline, outcomes=outcomes, core=core, card=card, database=card["identity"])


@pytest.fixture(scope="module")
def contradicted(tmp_path_factory) -> SimpleNamespace:
    pipeline = stage_pipeline(tmp_path_factory.mktemp("seeded-contradiction"), contradict=True)
    outcomes = _graph(pipeline, indexing=False)
    return SimpleNamespace(pipeline=pipeline, outcomes=outcomes, core=RetrievalCore(pipeline.runs, pipeline.run_id))


@pytest.fixture(scope="module")
def with_cpg(tmp_path_factory) -> SimpleNamespace:
    """The same run with the opt-in Joern producer enabled (recorded c2cpg and joern-export output)."""
    pipeline = stage_pipeline(tmp_path_factory.mktemp("seeded-cpg"), cpg=True)
    outcomes = _graph(pipeline, indexing=False)
    core = RetrievalCore(pipeline.runs, pipeline.run_id)
    (card,) = core.list_codeql_databases()["results"]
    return SimpleNamespace(pipeline=pipeline, outcomes=outcomes, core=core, card=card, database=card["identity"])


def _seeded_set(identity: Mapping[str, Any]) -> set[tuple[str, int]]:
    return {(path, start) for path, start, _end, status in identity["producer"]["seeded"]["seeds"]
            if status == "resolved"}


def _neighborhood(core: RetrievalCore, database: str, seed: str, **arguments: Any) -> dict[str, Any]:
    return core.query_codeql_neighborhood(database=database, seed=seed, **arguments)


# ---------------------------------------------------------------------------------------- the producers


def test_every_producer_ran_only_the_seeded_units_never_the_whole_program(run) -> None:
    executors = run.pipeline.executors
    assert len(run.pipeline.staged.rows) == 12
    assert executors["ir"].calls == [("ir", REPLAYED), ("cfg", REPLAYED), ("ast", REPLAYED)]
    assert executors["static"].calls == [("clang-tidy", ("src/net.cpp", "src/util.cpp")),
                                         ("clang-static-analyzer", ("src/net.cpp", "src/util.cpp"))]


def test_each_producer_published_the_same_seeded_set_in_its_own_record(run) -> None:
    clang = run.pipeline.clang
    for name in ("ir", "ast", "static"):
        assert _seeded_set(clang[name]["index_identity"]) == SEEDS, name
        assert clang[name]["index_identity"]["producer"]["seeded"]["depth"] == 3
    ledger = run.card["payload"]["seeded"]
    assert {(seed["path"], seed["start_line"]) for seed in ledger["seeds"]} == SEEDS


def test_the_pipeline_jobs_succeeded_with_only_named_gaps(run) -> None:
    for name, outcome in run.outcomes.items():
        assert outcome["status"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, (name, outcome["status"])
    graph = _outputs(run.outcomes["graph"])
    (scope,) = graph["crosscheck.scopes"]["scopes"]
    assert scope["states"]["disagree"] == 0 and scope["states"]["agree"] >= 1
    assert {"llvm-ir", "clang-ast", "clangd"} <= set(scope["producers"])


# ---------------------------------------------------------------------------------------- the card


def test_the_database_card_lists_every_producer_with_its_state_and_depth(run) -> None:
    producers = {item["name"]: item for item in run.card["payload"]["producers"]}
    assert list(producers) == ["codeql-export", "llvm-ir", "clang-ast", "clang-static", "clangd", "joern-cpg"]
    for name in ("codeql-export", "llvm-ir", "clang-ast", "clang-static"):
        assert producers[name]["seeded"] is True and producers[name]["depth"] == 3, name
        assert producers[name]["state"] == "seeded"
    assert producers["clangd"] == {"name": "clangd", "state": "whole_program", "seeded": False, "depth": None, "gaps": []}
    assert producers["joern-cpg"]["state"] == "not_run"
    assert producers["joern-cpg"]["gaps"][0].startswith("producer_not_run:")
    assert producers["llvm-ir"]["gaps"][0].startswith("frontier:")


def test_the_card_and_the_producers_shard_are_byte_identical_across_runs(run, tmp_path_factory) -> None:
    again = stage_pipeline(tmp_path_factory.mktemp("seeded-repeat"))
    _graph(again, indexing=False)

    def digests(pipeline) -> dict[str, str]:
        path, sha = resolve_accepted_manifest(pipeline.run_root)
        manifest, _ = load_verified_manifest(pipeline.run_root, path, sha)
        return {item["shard_id"]: item["sha256"] for item in manifest["indexes"] if item["name"] == GRAPH_INDEX}

    first, second = digests(run.pipeline), digests(again)
    assert any(shard.endswith("-producers") for shard in first) and any(shard.endswith("-database") for shard in first)
    assert first == second
    repeated = RetrievalCore(again.runs, again.run_id)
    left = _neighborhood(run.core, run.database, "src/util.cpp:14", include=["calls", "flow", "diagnostics", "symbols"])
    right = _neighborhood(repeated, run.database, "src/util.cpp:14", include=["calls", "flow", "diagnostics", "symbols"])
    # The cursor is signed per core and the index list names the accepted manifest, which differs by job set.
    assert left["results"] == right["results"] and left["coverage_gaps"] == right["coverage_gaps"]


# ---------------------------------------------------------------------------------------- retrieval


def test_a_seed_returns_facts_from_more_than_one_producer(run) -> None:
    response = _neighborhood(run.core, run.database, "src/util.cpp:14", limit=50,
                             include=["calls", "flow", "diagnostics", "symbols"])
    rows = response["results"]
    kinds = {row["kind"] for row in rows}
    assert {"call_site", "ir_entity", "tool_observation", "symbol"} <= kinds
    producers = {row["payload"]["producer"]["name"] if row["kind"] == "call_site" else row["payload"]["producer"]
                 for row in rows if row["kind"] != "neighborhood_summary"}
    assert {"codeql-export", "llvm-ir", "clang-static", "clangd"} <= producers
    summary = rows[0]
    assert summary["include"] == ["calls", "flow", "diagnostics", "symbols"]
    assert summary["counts"]["flow"] >= 1 and summary["counts"]["diagnostics"] >= 1 and summary["counts"]["symbols"] >= 1


def test_query_code_graph_facts_carry_each_producers_agreement(run) -> None:
    symbol = next(item for item in _neighborhood(run.core, run.database, "src/util.cpp:14")["results"]
                  if item["kind"] == "neighborhood_summary")["subject"]["symbols"][0]["identity"]
    response = run.core.query_code_graph(mode="callees", subject=symbol)
    facts = [row for row in response["results"] if row["payload"]["result"]["callee"]["display"] == "checked_len"]
    assert facts, response["results"]
    states = {item["name"]: item["state"] for item in facts[0]["payload"]["cross_check"]["producers"]}
    assert states["clang-ast"] == "agree" and states["clangd"] == "agree"
    assert facts[0]["payload"]["admissibility"]["direct_eligible"] is True


def test_a_mapped_analyzer_diagnostic_corroborates_the_codeql_sink_and_stays_a_named_gap_otherwise(run) -> None:
    symbol = next(item for item in _neighborhood(run.core, run.database, "src/util.cpp:14")["results"]
                  if item["kind"] == "neighborhood_summary")["subject"]["symbols"][0]["identity"]
    sinks = run.core.query_code_graph(mode="sinks", subject=symbol)["results"]
    (memcpy,) = [row for row in sinks if row["payload"]["result"]["sink_class"] == "memory_write"]
    states = {item["name"]: (item["state"], item["method"]) for item in memcpy["payload"]["cross_check"]["producers"]}
    assert states["clang-static"] == ("agree", "analyzer-diagnostic-in-sink-lines")
    assert memcpy["payload"]["cross_check"]["state"] == "agree"
    assert not [row for row in sinks if row["payload"]["producer"]["name"] == "clang-static"]
    (scope,) = _outputs(run.outcomes["graph"])["crosscheck.scopes"]["scopes"]
    assert any("analyzer_checks_unmapped:" in gap for gap in scope["gaps"])


def test_flow_graphs_reach_the_seed_block_with_dominance(run) -> None:
    rows = _neighborhood(run.core, run.database, "src/util.cpp:14", include=["flow"], limit=50)["results"]
    flow = next(row for row in rows if row.get("kind") == "ir_entity" and row["payload"]["function"] == "copy_field")
    assert flow["payload"]["producer"] == "llvm-ir" and flow["function_depth"] == 0
    assert {block["id"] for block in flow["payload"]["flow"]["blocks"]} == {"bb0", "bb1", "bb2", "bb3"}
    block = flow["seed_block"]
    assert block["start_line"] <= 14 <= block["end_line"] and block["dominated_by"] == ["bb0"]
    assert flow["payload"]["flow"]["def_use"]
    cfg = flow["payload"]["source_cfg"]
    assert cfg["producer"] == "clang-cfg" and any(
        block["terminator"] == "if" and block["condition"] == "src == nullptr" for block in cfg["blocks"])
    assert any(gap.startswith("source_cfg_no_block_lines") for gap in cfg["gaps"])


def test_analyzer_diagnostics_are_filterable_by_seed_function_check_severity_and_trace(run) -> None:
    core = run.core
    by_seed = core.query_observations(seed="proj/src/util.cpp:14")
    assert {row["payload"]["native_rule_id"] if "native_rule_id" in row["payload"] else row["name"]
            for row in by_seed["results"]} >= {"unix.cstring.NullArg"}
    deep = core.query_observations(min_trace_length=2)
    assert {row["name"] for row in deep["results"]} == {"unix.cstring.NullArg", "core.uninitialized.Assign"}
    fixable = core.query_observations(fix_it=True)
    assert {row["name"] for row in fixable["results"]} == {"bugprone-not-null-terminated-result"}


@pytest.mark.parametrize("arguments", [
    {"seed": "no-line"}, {"seed": 7}, {"function": ""}, {"fix_it": "yes"},
    {"min_trace_length": -1}, {"min_trace_length": True}, {"min_trace_length": 100_001},
])
def test_observation_filters_reject_malformed_values(run, arguments) -> None:
    with pytest.raises(ValueError, match="invalid observation filter"):
        run.core.query_observations(**arguments)


def test_cpg_rows_are_absent_with_a_named_gap_while_joern_is_not_enabled(run) -> None:
    response = _neighborhood(run.core, run.database, "src/util.cpp:14", include=["cpg"])
    assert not [row for row in response["results"] if row.get("kind") == "tool_observation"
                and row["payload"].get("fact") == "cpg"]
    assert any(gap.startswith("producer_not_run") for gap in response["coverage_gaps"])


def test_an_enabled_joern_producer_adds_cpg_function_rows_to_the_seeded_neighborhood(with_cpg) -> None:
    producers = {item["name"]: item for item in with_cpg.card["payload"]["producers"]}
    assert producers["joern-cpg"]["state"] == "seeded"
    response = _neighborhood(with_cpg.core, with_cpg.database, "src/util.cpp:14", include=["cpg"], limit=50)
    rows = {row["name"]: row["payload"] for row in response["results"]
            if row.get("kind") == "tool_observation" and row["payload"].get("fact") == "cpg"}
    assert "copy_field" in rows
    copy = rows["copy_field"]
    assert copy["path"] == "src/util.cpp" and copy["callee_matching"] == "name_only" and copy["block_lines"] == "none"
    assert {call["name"] for call in copy["calls"]} >= {"checked_len", "memcpy"}
    assert not any(gap.startswith("producer_not_run") for gap in response["coverage_gaps"])


def test_a_seeds_symbol_lists_its_callers_and_callees_in_the_clangd_identity_space(run) -> None:
    rows = _neighborhood(run.core, run.database, "src/util.cpp:14", include=["symbols"], limit=50)["results"]
    symbol = next(row for row in rows if row.get("kind") == "symbol" and row["name"] == "copy_field")
    payload = symbol["payload"]
    assert payload["identity_space"] == "clangd" and symbol["native_id"].startswith("clangd:")
    assert {item["name"] for item in payload["callers"]} == {"handle_packet", "parse_record"}
    assert [item["name"] for item in payload["callees"]] == ["checked_len"]
    assert payload["cross_reference"][0]["codeql_symbol"].startswith("asr:symbol:")
    assert "usr" not in json.dumps(payload).lower()


def test_a_seed_outside_the_precomputed_neighborhood_is_a_named_gap(run) -> None:
    response = _neighborhood(run.core, run.database, "src/mod_h.cpp:2", include=["flow", "diagnostics", "symbols"])
    assert any(gap.startswith("outside_precomputed_neighborhood") for gap in response["coverage_gaps"])
    assert not [row for row in response["results"] if row.get("kind") in {"ir_entity", "tool_observation", "symbol"}]


# ---------------------------------------------------------------------------------------- the MCP adapter


def _scoped(core: RetrievalCore, scopes: list[str], role: str) -> ScopedRetrievalMcpAdapter:
    package = {"run_id": core.run_id, "manifest_sha256": core.manifest_sha256, "package_id": "pkg",
               "retrieval": {"indexes": ["graph"], "query_sets": [], "entity_ids": [], "graph_scopes": scopes,
                             "max_page_size": 50, "max_pages": 4, "max_depth": 3, "max_response_bytes": 1 << 20}}
    token = issue_capability(package, role=role, round_id="1", secret=SECRET, expires_at=int(time.time()) + 300)
    return ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), package, capability=token, secret=SECRET,
                                     role=role, round_id="1")


def test_a_granted_role_reads_flow_diagnostics_and_symbols_through_the_adapter(run) -> None:
    scoped = _scoped(run.core, [SCOPE], "red")
    listed = scoped.call("list_codeql_databases", {})
    assert [row["identity"] for row in listed["results"]] == [run.database]
    response = scoped.call("query_codeql_neighborhood", {
        "database": run.database, "seed": "src/util.cpp:14", "include": ["flow", "diagnostics", "symbols"], "limit": 50})
    kinds = {row.get("kind") for row in response["results"]}
    assert {"ir_entity", "tool_observation", "symbol"} <= kinds
    diagnostic = next(row for row in response["results"] if row.get("kind") == "tool_observation")
    assert diagnostic["payload"]["trace_length"] == len(diagnostic["payload"]["trace"])
    symbol = next(row for row in response["results"] if row.get("kind") == "symbol" and row["name"] == "copy_field")
    assert symbol["payload"]["callers"] and symbol["payload"]["callees"]


def test_an_ungranted_role_cannot_reach_the_database_or_its_producer_rows(run) -> None:
    scoped = _scoped(run.core, ["py-other"], "red")
    assert scoped.call("list_codeql_databases", {})["results"] == []
    with pytest.raises(ValueError, match="outside review package"):
        scoped.call("query_codeql_neighborhood", {"database": run.database, "seed": "src/util.cpp:14",
                                                  "include": ["symbols"]})
    denied = _scoped(run.core, [], "red")
    assert denied.call("list_codeql_databases", {})["results"] == []


# ---------------------------------------------------------------------------------------- cross-check


def test_a_seeded_clangd_disagreement_contradicts_and_makes_the_fact_ineligible(contradicted) -> None:
    graph = _outputs(contradicted.outcomes["graph"])
    (scope,) = graph["crosscheck.scopes"]["scopes"]
    assert scope["states"]["disagree"] >= 1
    core = contradicted.core
    (card,) = core.list_codeql_databases()["results"]
    summary = next(row for row in _neighborhood(core, card["identity"], "src/net.cpp:6")["results"]
                   if row["kind"] == "neighborhood_summary")
    symbol = summary["subject"]["symbols"][0]["identity"]
    response = core.query_code_graph(mode="callees", subject=symbol)
    (fact,) = [row for row in response["results"] if row["payload"]["result"]["callee"]["display"] == "copy_field"]
    assert fact["payload"]["cross_check"]["state"] == "disagree"
    assert fact["payload"]["admissibility"]["direct_eligible"] is False
    assert fact["payload"]["admissibility"]["ineligibility_reasons"]
