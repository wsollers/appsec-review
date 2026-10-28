from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
import re

import pytest

from appsec_review import cli
from appsec_review.cli import GRAPH_JOB_IDS, main
from appsec_review.config import load_config
from appsec_review.jobs.job_review_data_indexing.job import _resolved_steps
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.runtime import active_job_ids
from appsec_review.runtime.registry import builtin_registry


ROOT = Path(__file__).parents[1]


def _set_enabled(source: str, job_id: str, enabled: bool) -> str:
    pattern = rf"(\[jobs\.{re.escape(job_id)}\.settings\][\s\S]*?\nenabled = )(?:true|false)(\n)"
    replaced, count = re.subn(pattern, rf"\g<1>{str(enabled).lower()}\g<2>", source, count=1)
    assert count == 1
    return replaced


def test_disabled_cpg_job_is_absent_from_the_application_graph() -> None:
    config = load_config(ROOT / "appsec-review.toml")

    selected = active_job_ids(config, GRAPH_JOB_IDS)

    assert "job_cpg_analysis" not in selected
    assert "job_cpp_symbol_index" in selected
    assert "job_codeql_analysis" in selected


def test_enabled_cpg_job_is_present_in_the_application_graph(tmp_path: Path) -> None:
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_set_enabled(source, "job_cpg_analysis", True), encoding="utf-8")
    config = load_config(config_path)

    assert "job_cpg_analysis" in active_job_ids(config, GRAPH_JOB_IDS)


def test_job_level_enabled_flag_is_generic(tmp_path: Path) -> None:
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    config_path = tmp_path / "appsec-review.toml"
    source = _set_enabled(source, "job_codeql_analysis", False)
    source = source.replace('execution_mode = "auto"', 'execution_mode = "disabled"', 1)
    config_path.write_text(source, encoding="utf-8")
    config = load_config(config_path)

    selected = active_job_ids(config, GRAPH_JOB_IDS)

    assert "job_codeql_analysis" not in selected
    assert "job_cpg_analysis" not in selected
    assert "job_evidence_collection" in selected


def test_direct_dispatch_rejects_disabled_cpg_job() -> None:
    with pytest.raises(ValueError, match="job is disabled by configuration: job_cpg_analysis"):
        main(["--config", str(ROOT / "appsec-review.toml"), "run", "job_cpg_analysis"])


@pytest.mark.parametrize("command", ["start", "resume", "plan-resume"])
@pytest.mark.parametrize("tagging_enabled,owasp_enabled", [
    (True, True), (True, False), (False, True), (False, False),
])
def test_direct_graph_routes_enabled_owasp_after_tags_and_before_hunting(
    monkeypatch, tmp_path: Path, command: str, tagging_enabled: bool, owasp_enabled: bool,
) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    jobs = dict(config.jobs)
    for job_id, enabled in (
        ("job_security_tagging", tagging_enabled), ("job_owasp_control_assessment", owasp_enabled),
    ):
        jobs[job_id] = replace(jobs[job_id], settings={**jobs[job_id].settings, "enabled": enabled})
    config = replace(config, jobs=jobs)
    captured_jobs: list[str] = []
    captured_force: list[str | None] = []

    class CapturingGraph:
        def __init__(self, _config, selected_jobs):
            captured_jobs.extend(job.job_id for job in selected_jobs)

        def plan(self, *_args, force_from=None, **_kwargs):
            captured_force.append(force_from)
            return ()

        def run(self, *, force_from=None, **_kwargs):
            captured_force.append(force_from)
            return {"run_id": "r", "status": "SUCCEEDED", "decisions": [], "jobs": {}}

    monkeypatch.setattr(cli, "load_config", lambda *_args, **_kwargs: config)
    monkeypatch.setattr(cli, "GraphRunner", CapturingGraph)
    monkeypatch.setattr(cli, "source_fingerprint", lambda _target: "test-source-fingerprint")
    argv = [command, "--target", str(tmp_path)]
    force_from = None
    if command != "start":
        argv.extend(["--run-id", "r"])
        force_from = ("job_owasp_control_assessment" if owasp_enabled else
                      "job_security_tagging" if tagging_enabled else None)
        if force_from:
            argv.extend(["--force-from", force_from])
    assert main(argv) == 0
    assert captured_force == [force_from]
    assert ("job_security_tagging" in captured_jobs) is tagging_enabled
    assert ("job_owasp_control_assessment" in captured_jobs) is owasp_enabled
    chain = (
        "job_review_prioritization", "job_code_graph_index",
        *(("job_security_tagging",) if tagging_enabled else ()),
        *(("job_owasp_control_assessment",) if owasp_enabled else ()),
        "job_review_data_indexing", "job_review_package_assembly", "job_inference_security_review",
    )
    assert tuple(job_id for job_id in captured_jobs if job_id in chain) == chain
    wave = describe_wave1(config, builtin_registry())
    assert tuple(item["job_id"] for item in wave["jobs"] if item["job_id"] in chain) == chain


@pytest.mark.parametrize("command", ["resume", "plan-resume"])
@pytest.mark.parametrize("job_id", ["job_security_tagging", "job_owasp_control_assessment"])
def test_direct_graph_cannot_force_a_disabled_owasp_or_tagging_job(
    monkeypatch, tmp_path: Path, command: str, job_id: str,
) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    jobs = dict(config.jobs)
    jobs[job_id] = replace(jobs[job_id], settings={**jobs[job_id].settings, "enabled": False})
    monkeypatch.setattr(cli, "load_config", lambda *_args, **_kwargs: replace(config, jobs=jobs))
    with pytest.raises(ValueError, match=f"cannot force from disabled job: {job_id}"):
        main([command, "--run-id", "r", "--target", str(tmp_path), "--force-from", job_id])


def test_disabled_cpg_job_is_absent_from_resolved_inventory(tmp_path: Path) -> None:
    configuration = tmp_path / "data" / "configuration"
    configuration.mkdir(parents=True)
    resolved = json.dumps({"jobs": {
        "job_cpg_analysis": {"settings": {"enabled": False}, "steps": {"load": {}}},
        "job_review_intake": {"settings": {}, "steps": {"intake": {}}},
    }}, sort_keys=True).encode()
    (configuration / "resolved.json").write_bytes(resolved)
    (configuration / "manifest.json").write_text(json.dumps({
        "resolved_sha256": hashlib.sha256(resolved).hexdigest(),
    }), encoding="utf-8")

    assert _resolved_steps(tmp_path) == {"job_review_intake": ["intake"]}
