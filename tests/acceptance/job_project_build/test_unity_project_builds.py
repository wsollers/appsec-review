"""T-113: manual provisioned-Editor acceptance. Not run by the integration-tier walk.

APPSEC_UNITY_INTEGRATION_CONFIG must name an operator-prepared central TOML configuration
with Unity enabled and a licensed, immutable Linux64/Mono capability matching the fixture.
No engine/image/license is installed or acquired by these tests.
"""

from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path
import shutil

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_artifact_indexing import build_job as build_artifacts
from appsec_review.jobs.job_language_build import build_job as build_languages, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan, load_accepted_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from appsec_review.storage import atomic_json


FIXTURE = Path(__file__).parents[2] / "fixtures" / "unity_workflow"


def run_provisioned_unity(tmp_path: Path):
    configured = os.environ.get("APPSEC_UNITY_INTEGRATION_CONFIG")
    assert configured, "Set APPSEC_UNITY_INTEGRATION_CONFIG to an explicitly provisioned Unity TOML config"
    config = load_config(Path(configured))
    assert config.job("job_project_build").settings.get("unity", {}).get("enabled") is True
    runs = tmp_path / "runs"
    config = replace(
        config, runtime=replace(config.runtime, runs_dir=runs, metadata_dir=runs / "metadata"),
        telemetry_report=replace(config.telemetry_report, enabled=False))
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    # Inventory regressions include fictional registry packages; actual build validation must
    # not try resolving them or silently substitute a mocked package manager.
    atomic_json(target / "Packages" / "manifest.json", {
        "dependencies": {"com.unity.modules.physics": "1.0.0"}})
    atomic_json(target / "Packages" / "packages-lock.json", {"dependencies": {
        "com.unity.modules.physics": {
            "version": "1.0.0", "depth": 0, "source": "builtin", "dependencies": {}}}})
    (target / "ProjectSettings" / "ProjectVersion.txt").write_text(
        "m_EditorVersion: 2022.3.62f1\n", encoding="utf-8")
    snapshot = source_fingerprint(target)
    outcome = GraphRunner(config, [
        build_intake(), build_catalog(), build_plan(), build_projects(), build_languages(), build_artifacts(),
    ]).run(target_root=target, source_fingerprint=snapshot)
    assert source_fingerprint(target) == snapshot, "Unity execution changed original fixture source"
    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, outcome
    run_root = runs / outcome["run_id"]
    return run_root, load_accepted_plan(run_root), load_accepted_builds(run_root), load_accepted_language_build(run_root)


def test_provisioned_unity_build_is_receipt_backed_and_not_rebuilt_by_dotnet(tmp_path: Path) -> None:
    run_root, plan, project, language = run_provisioned_unity(tmp_path)
    action, = plan["build_topology"]["build_actions"]
    assert action["engine"]["kind"] == "unity" and action["recipe"] is None
    engine, = project["probe_receipts"]
    assert engine["build_system"] == "unity" and engine["terminal_status"] == "SUCCEEDED"
    assert engine["artifacts"] and len(engine["commands"]) >= 2
    assert engine["commands"][-1]["exit_code"] == 0
    assert not project["build_dispatches"], "Unity must not be replayed as a generic .NET build"
    assert language["receipts"] == [engine]
    for artifact in engine["artifacts"]:
        assert (run_root / artifact["path"]).is_file()
