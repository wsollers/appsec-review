from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_ci_configuration_analysis import build_job
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from tests.ci_support import FakeExecutor
from tests.container_fixture import copy_containers


ROOT = Path(__file__).resolve().parents[2]


def isolated_config(tmp_path: Path):
    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    copy_containers(ROOT, tmp_path)
    return load_config(tmp_path / "appsec-review.toml")


@pytest.mark.live
@pytest.mark.requires_target("appsec-multi-vuln")
def test_live_target_acceptance_is_static_offline_resumable_and_queryable(tmp_path: Path) -> None:
    config = isolated_config(tmp_path)
    target = ROOT / "targets" / "appsec-multi-vuln"
    calls: list[tuple[str, tuple[str, ...]]] = []
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    jobs = (build_intake(), build_catalog(), build_job(executor_factory=factory))
    fingerprint = source_fingerprint(target)
    outcome = GraphRunner(config, jobs).run(target_root=target, source_fingerprint=fingerprint)
    run_id = outcome["run_id"]
    ci = outcome["jobs"]["job_ci_configuration_analysis"]["result"]["outputs"]
    classified = ci["ci_discovery.classify_providers"]
    assert {item["provider"] for item in classified["definitions"]} >= {
        "github", "azure", "gitlab", "circleci", "bitbucket", "jenkins", "teamcity"}
    assert all("/target/" in argv[-1] for _, argv in calls)
    assert {tool for tool, _ in calls} == {"tool-zizmor", "tool-checkov", "tool-actionlint"}
    assert all("--offline" in argv for tool, argv in calls if tool == "tool-zizmor")
    assert all("--file" in argv for tool, argv in calls if tool == "tool-checkov")
    published = ci["ci_coverage.publish_handoff"]
    assert published["finding_count"] > 0
    assert published["index_manifest"]["sha256"]
    assert not any("appsec-multi-vuln-guide" in json.dumps(value) for value in ci.values())
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    queried = core.query_ci_configuration(provider="github", limit=100)
    assert queried["results"] and all(item["payload"]["provider"] == "github" for item in queried["results"])
    before = list(calls)
    resumed = GraphRunner(config, jobs).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert [item["action"] for item in resumed["decisions"]] == ["REUSE", "REUSE", "REUSE"]
    assert calls == before


@pytest.mark.live
@pytest.mark.requires_target("appsec-multi-vuln")
def test_failed_linter_is_a_gap_and_sibling_results_survive(tmp_path: Path) -> None:
    config = isolated_config(tmp_path)
    target = ROOT / "targets" / "appsec-multi-vuln"
    calls: list[tuple[str, tuple[str, ...]]] = []
    factory = lambda unit: FakeExecutor(unit.job.repository_root, unit.job.run_root, calls)
    outcome = GraphRunner(config, (build_intake(), build_catalog(), build_job(
        executor_factory=factory, fail_tool="github_zizmor"))).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    outputs = outcome["jobs"]["job_ci_configuration_analysis"]["result"]["outputs"]
    assert outputs["ci_analysis.github_zizmor_scan"]["terminal_status"] == "FAILED"
    assert outputs["ci_analysis.github_schema_scan"]["terminal_status"] == "SUCCEEDED"
    assert outputs["ci_correlation.correlate_findings"]["finding_count"] > 0
    assert any("injected bounded failure" in gap for gap in outputs["ci_coverage.join_coverage"]["gaps"])


@pytest.mark.live
@pytest.mark.requires_target("appsec-multi-vuln")
def test_target_and_runtime_cannot_see_evaluator_oracle() -> None:
    target = ROOT / "targets" / "appsec-multi-vuln"
    fixtures = [
        target / ".github/workflows/verify.yml", target / "azure-pipelines.yml",
        target / ".gitlab-ci.yml", target / ".circleci/config.yml",
        target / "bitbucket-pipelines.yml", target / "Jenkinsfile",
        target / ".teamcity/settings.kts",
    ]
    for path in fixtures:
        value = path.read_text(encoding="utf-8").lower()
        assert not any(token in path.name.lower() for token in
                       {"vulnerable", "bad", "insecure", "answer", "expected"})
        assert "expected finding" not in value and "ci-" not in value
    assert "appsec-multi-vuln-guide" not in (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
