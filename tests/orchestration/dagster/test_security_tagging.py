from __future__ import annotations

from pathlib import Path

from appsec_review.config import load_config
from appsec_review.jobs.job_security_tagging.job import TOPOLOGY
from appsec_review.orchestration.dagster import build_definitions
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.runtime.registry import builtin_registry


def _upstream(graph, node: str) -> set[str]:
    mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
    return {output.node_name for outputs in mapping.values() for output in outputs}


def _ancestors(graph, node: str) -> set[str]:
    seen = set()
    pending = list(_upstream(graph, node))
    while pending:
        current = pending.pop()
        if current not in seen:
            seen.add(current)
            pending.extend(_upstream(graph, current))
    return seen


def test_security_tagging_follows_the_last_retrieval_manifest_publisher() -> None:
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    definitions = build_definitions(config)
    assert definitions.get_job_def("security_tagging").name == "security_tagging"
    graph = definitions.get_job_def("wave1_review").graph
    names = {node.name for node in graph.node_defs}
    expected_nodes = {
        f"security_tagging__{step}__{task}"
        for step, tasks in TOPOLOGY.items()
        for task in tasks
    }
    assert expected_nodes <= names
    assert _upstream(graph, "security_tagging__begin") == {
        "binary_evidence_indexing__finalize",
        "code_graph_index__finalize",
    }
    producers = {
        "binary_evidence_indexing", "code_graph_index", "dependency_intelligence",
        "profile_data", "test_coverage",
    }
    assert {f"{producer}__finalize" for producer in producers} <= _ancestors(graph, "security_tagging__begin")
    jobs = {item["job_id"]: item for item in describe_wave1(load_config(config), builtin_registry())["jobs"]}
    assert {f"job_{producer}" for producer in producers} <= set(jobs["job_security_tagging"]["upstream_handoffs"])
    assert "security_tagging__finalize" in _upstream(graph, "owasp_control_assessment__begin")
    assert _upstream(graph, "security_tagging__crosswalk__apply_crosswalk") >= {
        "security_tagging__collection__source_facts",
        "security_tagging__collection__observation_facts",
        "security_tagging__collection__coverage_gaps",
        "security_tagging__collation__collate_facets",
        "security_tagging__collation__model_pass",
    }
