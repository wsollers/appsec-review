from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review import cli
from appsec_review.jobs.job_final_publication_gate import verify
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.registry import builtin_registry


def _manifests(monkeypatch: pytest.MonkeyPatch, lead: str, hunt: str) -> dict:
    contents = {"lead": lead, "hunt": hunt}
    monkeypatch.setattr(verify, "read_bound_json", lambda root, ref: {
        "package_manifest": {"path": ref["path"], "sha256": "x"},
        "package_manifest_content_sha256": contents[ref["path"]]})
    monkeypatch.setattr(verify, "resolve_bound", lambda root, ref: ref["path"])
    monkeypatch.setattr(verify, "verify_package_manifest", lambda lane: {"content_sha256": contents[lane]})
    return {f"packages.assemble_{lane}_packages": {"artifact": {"path": lane, "sha256": "x"}}
            for lane in contents}


def test_gate_binds_both_lead_and_hunt_package_manifests_to_the_handoff(monkeypatch, tmp_path: Path) -> None:
    outputs = _manifests(monkeypatch, "a" * 64, "b" * 64)
    verify._verify_package_manifests(tmp_path, outputs, {
        "package_manifest_sha256": "b" * 64, "lead_package_manifest_sha256": "a" * 64})
    with pytest.raises(IntegrityError, match="lead package manifest"):
        verify._verify_package_manifests(tmp_path, outputs, {
            "package_manifest_sha256": "b" * 64, "lead_package_manifest_sha256": "c" * 64})
    with pytest.raises(IntegrityError, match="lead package manifest"):
        verify._verify_package_manifests(tmp_path, outputs, {"package_manifest_sha256": "b" * 64})


def test_cli_graph_runs_every_registered_wave1_job() -> None:
    registered = set(builtin_registry().job_ids()) - {"job_third_party_data_sync"}
    graph = cli.GRAPH_JOB_IDS + cli.POST_INDEX_JOB_IDS
    assert set(graph) == registered and len(graph) == len(registered)
    for job in ("job_ci_configuration_analysis", "job_post_build_security_assessment",
                "job_owasp_control_assessment", "job_security_tagging"):
        assert job in cli.GRAPH_JOB_IDS
    assert cli.GRAPH_JOB_IDS[-1] == "job_review_data_indexing"
    assert cli.POST_INDEX_JOB_IDS[-1] == "job_final_report_publication"


def test_registry_refuses_configured_and_registered_job_drift() -> None:
    registry = builtin_registry()
    registry.require_matches(registry.job_ids(), surface="CLI")
    with pytest.raises(ValueError, match="CLI job/config mismatch"):
        registry.require_matches(tuple(registry.job_ids())[1:], surface="CLI")
    with pytest.raises(ValueError, match="missing_registration"):
        registry.require_matches((*registry.job_ids(), "job_unknown"), surface="CLI")
