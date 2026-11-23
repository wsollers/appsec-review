from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("dagster")

from appsec_review.orchestration.dagster.adapter import build_definitions


def _upstream(graph, node: str) -> set[str]:
    mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
    return {output.node_name for outputs in mapping.values() for output in outputs}


def _ancestors(graph, node: str) -> set[str]:
    seen: set[str] = set()
    stack = list(_upstream(graph, node))
    while stack:
        current = stack.pop()
        if current not in seen:
            seen.add(current)
            stack.extend(_upstream(graph, current))
    return seen


def test_post_build_job_is_ordered_between_cpp_build_and_evidence_assembly() -> None:
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    definitions = build_definitions(config)
    assert definitions.get_job_def("post_build_security_assessment").name == "post_build_security_assessment"
    graph = definitions.get_job_def("wave1_review").graph
    names = {node.name for node in graph.node_defs}
    assert {
        "post_build_security_assessment__load__accepted_cpp_build",
        "post_build_security_assessment__provenance__native_units",
        "post_build_security_assessment__inspection__native_units",
        "post_build_security_assessment__deterministic__native_units",
        "post_build_security_assessment__inference__native_units",
        "post_build_security_assessment__index__native_units",
        "post_build_security_assessment__publication__publish_handoff",
    } <= names
    assert "cpp_compiled_analysis__finalize" in _upstream(
        graph, "post_build_security_assessment__begin")
    assert "target_analysis_plan__finalize" in _upstream(
        graph, "evidence_collection__begin")
    assert "post_build_security_assessment__finalize" in _upstream(
        graph, "codeql_analysis__begin")
    assert {
        "post_build_security_assessment__finalize", "evidence_collection__finalize",
    } <= _ancestors(graph, "owasp_control_assessment__begin")
    assert _upstream(graph, "post_build_security_assessment__inspection__native_units") == {
        "post_build_security_assessment__begin", "post_build_security_assessment__provenance__native_units"}
    assert len(_upstream(graph, "post_build_security_assessment__publication__publish_handoff")) == 2
