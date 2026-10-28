from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.runtime import active_job_ids
from appsec_review.runtime.launch import TARGET_INDEPENDENT_JOBS, TARGET_JOBS, launch_inputs
from appsec_review.runtime.registry import builtin_registry


ROOT = Path(__file__).resolve().parents[1]
EXPORT = "job_openvex_export"
GATE = "job_final_publication_gate"
REVIEW = "job_inference_security_review"
REPORT = "job_final_report_publication"
POC = "job_poc_generation"


def settings_text(text: str, table: str, changes: dict[str, str]) -> str:
    start = text.index(f"[jobs.{table}.settings]\n")
    end = text.find("\n[", start + 1)
    if end == -1:
        end = len(text)
    section = text[start:end]
    for key, value in changes.items():
        lines = section.splitlines(keepends=True)
        matches = [index for index, line in enumerate(lines) if line.startswith(key + " = ")]
        assert len(matches) == 1
        lines[matches[0]] = f"{key} = {value}\n"
        section = "".join(lines)
    return text[:start] + section + text[end:]


def export_config(tmp_path: Path, *, disabled_prerequisite: str | None = None,
                  missing_prerequisite: str | None = None):
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    text = settings_text(text, EXPORT, {
        "enabled": "true", "author": '"Example security team"',
        "action_statement": '"Restrict access until the reviewed findings are remediated."',
        "repository_iri": '"https://example.test/repository"',
    })
    if disabled_prerequisite is not None:
        text = settings_text(text, disabled_prerequisite, {"enabled": "false"})
    if missing_prerequisite is not None:
        retained = []
        omitted = False
        prefix = f"jobs.{missing_prerequisite}"
        for line in text.splitlines(keepends=True):
            if line.startswith("["):
                heading = line.strip().strip("[]")
                omitted = heading == prefix or heading.startswith(prefix + ".")
            if not omitted:
                retained.append(line)
        text = "".join(retained)
    path = tmp_path / "appsec-review.toml"
    path.write_text(text, encoding="utf-8")
    return load_config(path, profile="dev", overlay="")


def test_export_defaults_are_typed_disabled_and_have_no_target_access():
    from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
    from appsec_review import cli

    config = load_config(ROOT / "appsec-review.toml", profile="dev", overlay="")
    job = config.job(EXPORT)
    assert isinstance(job.typed_settings, OpenVexExportSettings)
    assert job.typed_settings.enabled is False
    assert EXPORT not in active_job_ids(config, config.jobs)
    assert EXPORT not in cli.MANUAL_JOB_IDS
    assert EXPORT in TARGET_INDEPENDENT_JOBS and EXPORT not in TARGET_JOBS
    inputs = launch_inputs(builtin_registry().build(EXPORT), target=ROOT / "not-a-target",
                           upstream_handoffs={GATE: "a" * 64})
    assert inputs.target_root is None and inputs.source_fingerprint == "none"
    assert inputs.upstream_handoffs == {GATE: "a" * 64}


@pytest.mark.parametrize("prerequisite,missing", [(GATE, False), (GATE, True), (REVIEW, True)])
def test_enabled_export_refuses_an_unavailable_prerequisite(tmp_path, prerequisite, missing):
    with pytest.raises(ValueError, match=f"requires enabled {prerequisite}"):
        export_config(tmp_path, **{("missing_prerequisite" if missing else "disabled_prerequisite"): prerequisite})


@pytest.mark.parametrize("poc_enabled", [False, True])
def test_enabled_export_is_post_gate_in_both_drivers_without_changing_gate_only_report(tmp_path, poc_enabled):
    from appsec_review import cli

    config = export_config(tmp_path)
    jobs = dict(config.jobs)
    poc = jobs[POC]
    jobs[POC] = replace(poc, settings={**poc.settings, "enabled": poc_enabled})
    config = replace(config, jobs=jobs)
    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="OpenVEX unit")
    described = describe_wave1(config, registry)
    entries = {item["job_id"]: item for item in described["jobs"]}
    assert entries[EXPORT]["dependencies"] == [GATE]
    assert {GATE, REVIEW} <= set(entries[EXPORT]["upstream_handoffs"])
    assert entries[REPORT]["dependencies"] == [GATE]
    assert registry.build(REPORT).consumes == (GATE,)
    direct = active_job_ids(config, (*cli.GRAPH_JOB_IDS, *cli.POST_INDEX_JOB_IDS))
    assert direct.index(GATE) < direct.index(EXPORT) < direct.index(REPORT)
    if poc_enabled:
        assert direct.index(POC) < direct.index(GATE)
    assert set(direct) == set(entries)


def test_export_is_a_declared_protected_downstream_dataset_not_an_index_input():
    from appsec_review.jobs.job_openvex_export.datasets import DATASETS
    from appsec_review.jobs.job_review_data_indexing.job import DOWNSTREAM_JOBS

    registry = builtin_registry()
    assert registry.build(EXPORT).consumes == (GATE, REVIEW)
    assert registry.build(REPORT).consumes == (GATE,)
    assert EXPORT in DOWNSTREAM_JOBS
    assert {item.output_kind for item in DATASETS} == {
        "openvex_verified_inputs", "openvex_documents", "openvex_export_accounting",
    }
    assert all(item.disposition == "protected" and item.sensitivity == "sensitive"
               and item.family == "inference_review" and item.query_route for item in DATASETS)


def test_cli_refuses_disabled_export_before_creating_a_run(monkeypatch):
    from appsec_review import cli

    def forbidden(*_args, **_kwargs):
        pytest.fail("disabled export must not instantiate a runner")

    monkeypatch.setattr(cli, "JobRunner", forbidden)
    with pytest.raises(ValueError, match="job is disabled by configuration: job_openvex_export"):
        cli.main(["--config", str(ROOT / "appsec-review.toml"), "--profile", "dev",
                  "run", EXPORT])
