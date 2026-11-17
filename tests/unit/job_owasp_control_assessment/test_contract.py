"""Unit contract and validator tests for job_owasp_control_assessment."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_owasp_control_assessment import build_job
from appsec_review.jobs.job_owasp_control_assessment import job as job_module
from appsec_review.jobs.job_owasp_control_assessment.datasets import CONTRACT, DATASETS
from appsec_review.runtime import UnitContext
from appsec_review.runtime.inputs import feed_input_identity
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json
from tests.test_owasp_assessment_job import accepted_fixture, context_for


ROOT = Path(__file__).resolve().parents[3]


def test_job_contract_datasets_and_registry_parity() -> None:
    job = build_job()
    registered = builtin_registry().build("job_owasp_control_assessment")
    assert job.job_id == registered.job_id == "job_owasp_control_assessment"
    assert job.name == "owasp_control_assessment"
    assert job.schema_identity == job_module.SCHEMA == "appsec-review/owasp-workbench-result/1"
    assert job.datasets == DATASETS
    assert job.contract == CONTRACT
    assert job.external_input_identity is feed_input_identity
    assert {dataset.output_kind for dataset in DATASETS} == {
        "owasp_model_receipts", "owasp_workbench", "owasp_documents", "owasp_control_gaps",
    }
    expected_units = tuple(
        f"{step}.{task}"
        for step, tasks in job_module.TOPOLOGY.items()
        for task in tasks
    )
    assert tuple(unit.unit_id for unit in job.units) == expected_units
    config = load_config(ROOT / "appsec-review.toml").job("job_owasp_control_assessment")
    assert tuple(config.steps) == tuple(job_module.TOPOLOGY)
    for step_id, tasks in job_module.TOPOLOGY.items():
        assert tuple(config.step(step_id).tasks) == tasks


def test_sources_requires_standards_mapping() -> None:
    with pytest.raises(ValueError, match="OWASP standards source settings are required"):
        job_module._sources({})
    with pytest.raises(ValueError, match="OWASP standards source settings are required"):
        job_module._sources({"standards": "invalid"})


def test_validate_config_rejects_step_and_task_mismatches_and_fixture_catalogs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = accepted_fixture(tmp_path)
    context = context_for(fixture)

    dropped_steps = {k: v for k, v in context.config.steps.items() if k != "publication"}
    bad_step_context = replace(context, config=replace(context.config, steps=dropped_steps))
    with pytest.raises(ValueError, match="OWASP workbench topology does not match central configuration"):
        job_module._validate_config(bad_step_context, None)

    existing_step = context.config.step("standards_selection")
    reordered_tasks = {"select_profiles": existing_step.task("select_profiles")}
    mutated_steps = dict(context.config.steps)
    mutated_steps["standards_selection"] = replace(existing_step, tasks=reordered_tasks)
    bad_task_context = replace(context, config=replace(context.config, steps=mutated_steps))
    with pytest.raises(ValueError, match="OWASP workbench task order mismatch: standards_selection"):
        job_module._validate_config(bad_task_context, None)

    monkeypatch.setattr(
        job_module, "load_catalogs",
        lambda _repo_root, _sources: {"ASVS": SimpleNamespace(fixture=True)},
    )
    with pytest.raises(ValueError, match="assessment requires complete acquired catalogs"):
        job_module._validate_config(context, None)


def test_fixture_or_accepted_inputs_rejects_missing_or_invalid_qualification_and_target_mismatch(
    tmp_path: Path,
) -> None:
    fixture = accepted_fixture(tmp_path)
    qual_context = context_for(fixture, mode="qualification")
    qual_settings = deepcopy(dict(qual_context.config.settings))
    qual_context = replace(qual_context, config=replace(qual_context.config, settings=qual_settings))
    qual_unit = UnitContext(
        qual_context, "characterization.load_inputs", "characterization", "load_inputs",
        qual_context.attempt_root / "unit", {},
    )

    with pytest.raises(ValueError, match="explicit qualification mode requires the run-owned qualification input"):
        job_module._fixture_or_accepted_inputs(qual_unit)

    fixture_input = fixture.run_root / "data" / "inputs" / "owasp-workbench.json"
    atomic_json(fixture_input, {"schema": "appsec-review/unsupported-owasp-input/99"})
    with pytest.raises(ValueError, match="OWASP fixture input schema is unsupported"):
        job_module._fixture_or_accepted_inputs(qual_unit)
    fixture_input.unlink()

    mismatch_context = replace(
        context_for(fixture),
        evidence_target_snapshot="target-sha256:" + "f" * 64,
    )
    mismatch_unit = UnitContext(
        mismatch_context, "characterization.load_inputs", "characterization", "load_inputs",
        mismatch_context.attempt_root / "unit", {},
    )
    with pytest.raises(ValueError, match="OWASP accepted evidence target differs"):
        job_module._fixture_or_accepted_inputs(mismatch_unit)
