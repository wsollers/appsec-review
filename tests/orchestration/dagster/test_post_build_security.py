from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("dagster")

from appsec_review.orchestration.dagster import build_definitions


def _upstream(graph, node: str) -> set[str]:
    mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
    return {output.node_name for outputs in mapping.values() for output in outputs}


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
    assert {
        "post_build_security_assessment__finalize", "evidence_collection__finalize",
    } <= _upstream(graph, "owasp_control_assessment__begin")
    assert _upstream(graph, "post_build_security_assessment__inspection__native_units") == {
        "post_build_security_assessment__begin", "post_build_security_assessment__provenance__native_units"}
    assert len(_upstream(graph, "post_build_security_assessment__publication__publish_handoff")) == 2


@pytest.mark.skipif(not os.environ.get("APPSEC_CPP_ACCEPTANCE_TARGET"),
                    reason="live 12-case C++ acceptance target/image was not supplied")
def test_live_cpp_post_build_acceptance_uses_real_dagster_path(monkeypatch) -> None:
    target = Path(os.environ["APPSEC_CPP_ACCEPTANCE_TARGET"]).resolve(strict=True)
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    result = build_definitions(config).get_job_def("wave1_review").execute_in_process()
    assert result.success
    run_ids = set()
    for event in result.all_node_events:
        if event.is_step_output and event.step_key == "post_build_security_assessment__finalize":
            metadata = event.event_specific_data.metadata
            if "application_run_id" in metadata:
                run_ids.add(metadata["application_run_id"].value)
    assert len(run_ids) == 1
    run_root = config.parent / "runs" / run_ids.pop()
    accepted = json.loads((run_root / "data" / "indices" / "accepted.json").read_text(encoding="utf-8"))
    assert "build-security" in accepted["manifest_path"]
