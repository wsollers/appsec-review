from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.cli import GRAPH_JOB_IDS, POST_INDEX_JOB_IDS
from appsec_review.config import load_config
from appsec_review.indexing.input_matrix import INPUT_SOURCES
from appsec_review.indexing.products import PRODUCT_RULES
from appsec_review.jobs.job_review_data_indexing.datasets import CONSUMES
from appsec_review.runtime.registry import builtin_registry
from appsec_review.retrieval import EntityKind, LogicalIdentity
from appsec_review.retrieval.observations import classify
from appsec_review.review.packages import _Assembler
from appsec_review.review.scope import PRODUCERS
from appsec_review.review.units import ContextEntry, _engineering_context


NEW_JOBS = {
    "job_clang_static_analysis",
    "job_test_coverage",
    "job_profile_data",
    "job_dependency_intelligence",
}


def test_engineering_signal_jobs_are_configured_registered_and_accounted() -> None:
    config = load_config("appsec-review.toml")
    assert NEW_JOBS <= set(config.jobs)
    assert NEW_JOBS <= set(builtin_registry().job_ids())
    assert NEW_JOBS <= set(CONSUMES)
    matrix_producers = {producer.removeprefix("planned:")
                        for _source, producers, _state, _queries, _routes in INPUT_SOURCES
                        for producer in producers}
    assert NEW_JOBS <= matrix_producers


def test_engineering_signal_jobs_precede_review_data_indexing() -> None:
    order = {job_id: position for position, job_id in enumerate(GRAPH_JOB_IDS)}
    assert order["job_cpp_compiled_analysis"] < order["job_clang_static_analysis"]
    assert order["job_artifact_indexing"] < order["job_test_coverage"]
    assert order["job_artifact_indexing"] < order["job_profile_data"]
    assert order["job_evidence_collection"] < order["job_dependency_intelligence"]
    assert all(order[job_id] < order["job_review_data_indexing"] for job_id in NEW_JOBS)


def test_engineering_signal_dagster_dependencies_match_current_orchestration() -> None:
    pytest.importorskip("dagster")
    from appsec_review.orchestration.dagster import build_definitions

    graph = build_definitions(Path(__file__).parents[1] / "appsec-review.toml").get_job_def(
        "wave1_review").graph

    def upstream(node: str) -> set[str]:
        mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
        return {output.node_name for outputs in mapping.values() for output in outputs}

    assert upstream("test_coverage__begin") == {"artifact_indexing__finalize"}
    assert upstream("profile_data__begin") == {"artifact_indexing__finalize"}
    assert upstream("clang_static_analysis__begin") == {"cpp_compiled_analysis__finalize"}
    assert {"target_catalog__finalize", "language_build__finalize", "artifact_indexing__finalize",
            "evidence_collection__finalize", "cpp_compiled_analysis__finalize"} == \
        upstream("dependency_intelligence__begin")
    assert "code_graph_index__finalize" in upstream("security_tagging__begin")
    review_upstream = upstream("review_data_indexing__begin")
    assert {"test_coverage__finalize", "profile_data__finalize",
            "dependency_intelligence__finalize", "security_tagging__finalize"} <= review_upstream


def _direct_graph_block(path: str, marker: str) -> str:
    text = Path(path).read_text(encoding="utf-8")
    remainder = text.split(marker, 1)[1]
    return remainder.split("```text", 1)[1].split("```", 1)[0]


def test_operator_docs_track_the_executable_direct_graph() -> None:
    expected = tuple(job.removeprefix("job_") for job in (*GRAPH_JOB_IDS, *POST_INDEX_JOB_IDS))
    for path, marker in (
        ("README.md", "The direct CLI runs this linear graph:"),
        ("docs/operations/wave1-review.md", "commands run this linear graph:"),
    ):
        block = _direct_graph_block(path, marker)
        positions = [block.index(job) for job in expected]
        assert positions == sorted(positions), (path, expected)


def test_architecture_doc_counts_match_the_registries() -> None:
    config = load_config("appsec-review.toml")
    indexing = Path("docs/architecture/indexing-and-query-reuse.md").read_text(encoding="utf-8")
    record = Path("docs/reviews/engineering-signal-jobs-implementation.md").read_text(encoding="utf-8")

    assert f"All {len(config.jobs)} currently registered jobs" in indexing
    assert f"All {len(PRODUCT_RULES)} stage-1 sets" in indexing
    assert f"input-source matrix contains {len(INPUT_SOURCES)}" in record


def test_clang_observations_enter_the_source_sast_review_lane() -> None:
    shard = {"name": "observations", "shard_id": "clang-static-native",
             "producer": {"job": "job_clang_static_analysis"}}
    assert PRODUCERS["source_sast"](shard)
    assert classify({"tool_id": "tool-clang-static-analysis", "category": "source_sast"}) == "source_sast"


def test_coverage_profiles_and_scorecards_seed_hunt_context() -> None:
    coverage_shard = {"name": "analysis", "shard_id": "test-coverage-native",
                      "producer": {"job": "job_test_coverage"}}
    dependency_shard = {"name": "inventory", "shard_id": "dependency-intelligence",
                        "producer": {"job": "job_dependency_intelligence"}}
    profile_shard = {"name": "analysis", "shard_id": "profile-data-native",
                     "producer": {"job": "job_profile_data"}}
    snapshot = "target-sha256:" + "a" * 64
    coverage_id = LogicalIdentity.derive(EntityKind.COVERAGE_CELL, snapshot, {"path": "src/main.c"}).value
    dependency_id = LogicalIdentity.derive(EntityKind.DEPENDENCY_PACKAGE, snapshot, {"name": "libssl"}).value
    scorecard_id = LogicalIdentity.derive(EntityKind.REVIEW_SIGNAL, snapshot, {"dependency": dependency_id}).value
    profile_id = LogicalIdentity.derive(EntityKind.HOTSPOT, snapshot, {"symbol": "main"}).value

    class Store:
        def entities(self, shards, *, kinds=()):
            if shards[0] is coverage_shard:
                yield {"identity": coverage_id, "kind": "coverage_cell",
                       "payload": {"path": "src/main.c", "build_unit_id": "native"}}
            elif shards[0] is profile_shard:
                yield {"identity": profile_id, "kind": "hotspot",
                       "payload": {"source": "src/main.c", "build_unit_id": "native",
                                   "semantics": "context_only", "is_finding": False}}
            else:
                yield {"identity": dependency_id, "kind": "dependency_package", "payload": {}}
                yield {"identity": scorecard_id, "kind": "review_signal", "payload": {}}

    scope = SimpleNamespace(
        store=Store(),
        producer=lambda name: SimpleNamespace(shards=(coverage_shard,) if name == "test_coverage"
                                              else (profile_shard,) if name == "profile_data"
                                              else (dependency_shard,)),
        shard_sha256=lambda shard: "c" * 64 if shard is coverage_shard else
                                   "e" * 64 if shard is profile_shard else "d" * 64,
    )
    by_path, _by_build, dependencies = _engineering_context(scope)
    assert {(entry.id, entry.role) for entry in by_path["src/main.c"]} == {
        (coverage_id, "test_coverage"), (profile_id, "profile_hotspot")}
    assert {(entry.id, entry.role) for entry in dependencies} == {
        (dependency_id, "dependency"), (scorecard_id, "openssf_scorecard")}


def test_context_cap_retains_dependency_and_scorecard_roles() -> None:
    assembler = object.__new__(_Assembler)
    assembler.settings = SimpleNamespace(max_context_entries=2)
    context = [ContextEntry(f"asr:dependency_package:{index:064x}", "dependency_package", "dependency")
               for index in range(1, 4)]
    context.extend(ContextEntry(f"asr:review_signal:{index:064x}", "review_signal", "openssf_scorecard")
                   for index in range(1, 4))
    chosen, omitted, gaps = assembler._cap(context, "unit", "lane_b_hunt")
    assert {item.role for item in chosen} == {"dependency", "openssf_scorecard"}
    assert omitted == 4 and gaps[0].state == "truncated"

