from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("dagster")

from appsec_review.orchestration.dagster.adapter import build_definitions


def test_real_completion_graph_certifies_every_producer_before_gate_only_report() -> None:
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    graph = build_definitions(config).get_job_def("wave1_review").graph
    expected = {
        "poc_generation": ("inference_security_review",),
        "remediation_planning": ("inference_security_review", "poc_generation"),
        "remediation_validation": ("remediation_planning",),
        "dossier_publication": (
            "inference_security_review", "poc_generation",
            "remediation_planning", "remediation_validation"),
        "final_publication_gate": (
            "inference_security_review", "poc_generation",
            "remediation_planning", "remediation_validation", "dossier_publication"),
        "final_report_publication": ("final_publication_gate",),
    }
    for job, parents in expected.items():
        dependencies = graph.dependency_structure.input_to_upstream_outputs_for_node(f"{job}__begin")
        actual = {output.node_name for outputs in dependencies.values() for output in outputs}
        assert actual == {f"{parent}__finalize" for parent in parents}
