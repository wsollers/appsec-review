from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.orchestration.topology import (
    describe_wave1, launch_upstream_handoffs, tagged_upstream_handoffs, upstream_closure, wave1_dependencies)
from appsec_review.runtime.registry import builtin_registry

ROOT = Path(__file__).resolve().parents[2]


def test_wave1_order_is_topological_and_closure_follows_propagation() -> None:
    described = describe_wave1(load_config(ROOT / "appsec-review.toml"), builtin_registry())
    jobs = {item["job_id"]: item for item in described["jobs"]}
    seen: set[str] = set()
    for item in described["jobs"]:
        assert set(item["dependencies"]) <= seen
        seen.add(item["job_id"])
    # Non-propagating gates never reach a downstream job; everything else is transitive.
    assert jobs["job_review_intake"]["upstream_handoffs"] == []
    assert jobs["job_target_catalog"]["upstream_handoffs"] == ["job_review_intake"]
    assert jobs["job_change_context_analysis"]["upstream_handoffs"] == [
        "job_ci_configuration_analysis", "job_language_build", "job_project_build",
        "job_review_intake", "job_source_history_analysis",
        "job_target_analysis_plan", "job_target_catalog", "job_tree_sitter_ast"]
    assert "job_model_connectivity" not in jobs["job_codeql_analysis"]["upstream_handoffs"]


def test_disabled_jobs_are_transparent_and_closure_is_transitive() -> None:
    registered = {"job_model_connectivity", "job_review_intake", "job_target_catalog", "job_target_analysis_plan"}
    dependencies = wave1_dependencies(registered)
    assert list(dependencies) == ["job_model_connectivity", "job_review_intake", "job_target_catalog",
                                  "job_target_analysis_plan"]
    assert dependencies["job_target_analysis_plan"] == ("job_target_catalog",)
    assert wave1_dependencies({"job_review_intake"}) is None
    assert upstream_closure("job_target_analysis_plan", dependencies,
                            {"job_review_intake", "job_target_catalog"}) == (
        "job_review_intake", "job_target_catalog")


@pytest.mark.parametrize("export_enabled,poc_enabled", [(False, False), (False, True),
                                                       (True, False), (True, True)])
def test_optional_publications_are_independent_and_report_closes_every_tail(
        export_enabled: bool, poc_enabled: bool) -> None:
    registered = {
        "job_model_connectivity", "job_review_intake", "job_target_catalog",
        "job_target_analysis_plan", "job_review_data_indexing", "job_review_package_assembly",
        "job_document_issue_analysis", "job_inference_security_review",
        "job_final_publication_gate", "job_final_report_publication",
    }
    tails = tuple(job_id for job_id, enabled in (
        ("job_openvex_export", export_enabled), ("job_poc_generation", poc_enabled)) if enabled)
    registered.update(tails)
    dependencies = wave1_dependencies(registered)
    assert dependencies is not None
    assert dependencies["job_final_report_publication"] == (tails or ("job_final_publication_gate",))
    for tail in tails:
        assert dependencies[tail] == ("job_final_publication_gate",)
        assert "job_inference_security_review" in upstream_closure(tail, dependencies, registered)
        assert not (set(tails) - {tail}) & set(upstream_closure(tail, dependencies, registered))
    seen = set()
    for job_id, upstream in dependencies.items():
        assert set(upstream) <= seen
        seen.add(job_id)
    depended_on = {job_id for upstream in dependencies.values() for job_id in upstream}
    assert set(dependencies) - depended_on == {"job_final_report_publication"}


def test_enabled_owasp_uses_tags_graph_and_classification_before_hunting() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    jobs = dict(config.jobs)
    owasp = jobs["job_owasp_control_assessment"]
    jobs[owasp.job_id] = replace(owasp, settings={**owasp.settings, "enabled": True})
    described = describe_wave1(replace(config, jobs=jobs), builtin_registry())
    by_id = {item["job_id"]: item for item in described["jobs"]}
    seen = set()
    for item in described["jobs"]:
        assert set(item["dependencies"]) <= seen
        seen.add(item["job_id"])
    upstream = by_id[owasp.job_id]["upstream_handoffs"]
    assert {"job_security_tagging", "job_review_prioritization", "job_code_graph_index"} <= set(upstream)
    assert owasp.job_id in by_id["job_review_data_indexing"]["upstream_handoffs"]
    assert owasp.job_id in by_id["job_review_package_assembly"]["upstream_handoffs"]
    assert owasp.job_id in by_id["job_inference_security_review"]["upstream_handoffs"]
    assert owasp.job_id not in by_id["job_security_tagging"]["upstream_handoffs"]


def _accepted(run_root: Path, job_id: str, status: str = "ACCEPTED") -> str:
    handoff = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001" / "handoff.json"
    handoff.parent.mkdir(parents=True)
    handoff.write_text(json.dumps({"job_id": job_id, "status": status}), encoding="utf-8")
    digest = hashlib.sha256(handoff.read_bytes()).hexdigest()
    (run_root / "data" / "jobs" / job_id / "latest.json").write_text(json.dumps({
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": digest}), encoding="utf-8")
    return digest


def test_tagged_upstream_handoffs_must_be_the_runs_accepted_handoffs(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    run_root = runs / "2026-10-16-0004"
    intake = _accepted(run_root, "job_review_intake")
    rejected = _accepted(run_root, "job_target_catalog", status="REJECTED")
    tag = json.dumps({"job_review_intake": intake})
    tags = {"appsec/application_run_id": "2026-10-16-0004", "appsec/upstream_handoffs": tag}
    assert launch_upstream_handoffs(runs, tags, in_graph=False) == {"job_review_intake": intake}
    assert launch_upstream_handoffs(runs, {"appsec/application_run_id": "2026-10-16-0004"}, in_graph=False) is None
    with pytest.raises(ValueError, match="in-graph"):
        launch_upstream_handoffs(runs, tags, in_graph=True)
    with pytest.raises(ValueError, match="requires appsec/application_run_id"):
        launch_upstream_handoffs(runs, {"appsec/upstream_handoffs": tag}, in_graph=False)
    with pytest.raises(ValueError, match="not the run's accepted handoff"):
        tagged_upstream_handoffs(run_root, json.dumps({"job_review_intake": "0" * 64}))
    with pytest.raises(ValueError, match="no accepted handoff"):
        tagged_upstream_handoffs(run_root, json.dumps({"job_project_build": intake}))
    with pytest.raises(ValueError, match="not an accepted handoff"):
        tagged_upstream_handoffs(run_root, json.dumps({"job_target_catalog": rejected}))
    with pytest.raises(ValueError, match="JSON object"):
        tagged_upstream_handoffs(run_root, "[]")
    handoff = run_root / "data" / "jobs" / "job_review_intake" / "attempts" / "attempt_0001" / "handoff.json"
    handoff.write_text(handoff.read_text() + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match its digest"):
        tagged_upstream_handoffs(run_root, tag)
