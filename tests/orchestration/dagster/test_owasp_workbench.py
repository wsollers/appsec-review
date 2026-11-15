from __future__ import annotations

from pathlib import Path

from appsec_review.orchestration.dagster.adapter import build_definitions


ROOT = Path(__file__).resolve().parents[3]


def test_owasp_dag_has_parallel_cells_join_and_publication() -> None:
    graph = build_definitions(ROOT / "appsec-review.toml").get_job_def(
        "owasp_control_assessment").graph
    names = {node.name for node in graph.node_defs}
    cells = {f"standalone__owasp_control_assessment__validation__cell_0{index}" for index in range(1, 5)}
    assert cells <= names
    join = "standalone__owasp_control_assessment__join__deterministic_join"
    verify = "standalone__owasp_control_assessment__verification__independent_review"
    publication = "standalone__owasp_control_assessment__publication__publish_indexes"

    def upstream(node: str) -> set[str]:
        mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
        return {output.node_name for outputs in mapping.values() for output in outputs}

    assert cells <= upstream(verify)
    assert verify in upstream(join)
    assert join in upstream(publication)
