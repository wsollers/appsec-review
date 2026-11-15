from __future__ import annotations

from pathlib import Path

from appsec_review.jobs.job_security_tagging.job import TOPOLOGY
from appsec_review.orchestration.dagster import build_definitions


def _upstream(graph, node: str) -> set[str]:
    mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
    return {output.node_name for outputs in mapping.values() for output in outputs}


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
    assert {
        "binary_evidence_indexing__finalize",
        "code_graph_index__finalize",
        "dependency_intelligence__finalize",
        "profile_data__finalize",
        "test_coverage__finalize",
    } <= _upstream(graph, "security_tagging__begin")
    assert "security_tagging__finalize" in _upstream(graph, "owasp_control_assessment__begin")
    assert _upstream(graph, "security_tagging__crosswalk__apply_crosswalk") >= {
        "security_tagging__collection__source_facts",
        "security_tagging__collection__observation_facts",
        "security_tagging__collection__coverage_gaps",
        "security_tagging__collation__collate_facets",
        "security_tagging__collation__model_pass",
    }
