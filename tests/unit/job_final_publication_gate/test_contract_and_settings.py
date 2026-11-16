"""Contract, dataset, topology, and settings unit tests for job_final_publication_gate."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA
from appsec_review.jobs.job_final_publication_gate import build_job
from appsec_review.jobs.job_final_publication_gate.datasets import DATASETS
from appsec_review.jobs.job_final_publication_gate.job import CONTRACT, JOB_ID, TOPOLOGY, _validate
from appsec_review.jobs.job_final_publication_gate.settings import (
    SCHEMA_MAX_PACKAGES, FinalPublicationGateSettings,
)
from appsec_review.runtime.registry import builtin_registry

ROOT = Path(__file__).resolve().parents[3]


def test_settings_parse_valid_bounds_and_reject_invalid_mappings() -> None:
    parsed = FinalPublicationGateSettings.from_mapping({"enabled": True, "max_packages": 1})
    assert parsed.enabled is True
    assert parsed.max_packages == 1
    upper = FinalPublicationGateSettings.from_mapping({"enabled": False, "max_packages": SCHEMA_MAX_PACKAGES})
    assert upper.enabled is False
    assert upper.max_packages == SCHEMA_MAX_PACKAGES

    for bad in (
        None,
        "not-a-mapping",
        {"enabled": True},
        {"enabled": True, "max_packages": 10, "extra": 1},
    ):
        with pytest.raises(ValueError, match="documented keys"):
            FinalPublicationGateSettings.from_mapping(bad)  # type: ignore[arg-type]

    for bad_enabled in (1, "true", None):
        with pytest.raises(ValueError, match="enabled must be a boolean"):
            FinalPublicationGateSettings.from_mapping({"enabled": bad_enabled, "max_packages": 10})

    for bad_limit in (True, False, 0, -5, SCHEMA_MAX_PACKAGES + 1, "10", 1.5):
        with pytest.raises(ValueError, match="max_packages must be an integer"):
            FinalPublicationGateSettings.from_mapping({"enabled": True, "max_packages": bad_limit})


def test_job_contract_datasets_registry_and_input_validator_parity() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job_cfg = config.job(JOB_ID)
    job = builtin_registry().build(JOB_ID)
    assert job.job_id == JOB_ID
    assert job.schema_identity == FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA
    assert job.contract == CONTRACT
    assert job.datasets == DATASETS
    assert len(DATASETS) == 1
    assert {d.output_kind for d in DATASETS} == {"publication_gate_decisions"}
    assert tuple(u.unit_id for u in job.units) == (
        "load.verify_review",
        "gate.classify",
        "acceptance.publish_handoff",
    )
    assert {
        "job_inference_security_review",
        "job_poc_generation",
        "job_remediation_planning",
        "job_remediation_validation",
        "job_dossier_publication",
        "job_language_build",
    } <= set(job.consumes)
    assert job.consumes == CONTRACT.consumes

    valid_ctx = SimpleNamespace(config=job_cfg)
    _validate(valid_ctx, None)

    wrong_steps = SimpleNamespace(
        config=SimpleNamespace(steps={"load": None, "gate": None}, step=job_cfg.step, settings=job_cfg.settings)
    )
    with pytest.raises(ValueError, match="topology does not match"):
        _validate(wrong_steps, None)

    def broken_step(name: str):
        if name == "gate":
            return SimpleNamespace(tasks=("wrong_task",))
        return job_cfg.step(name)

    wrong_tasks = SimpleNamespace(
        config=SimpleNamespace(steps=TOPOLOGY, step=broken_step, settings=job_cfg.settings)
    )
    with pytest.raises(ValueError, match="task configuration mismatch: gate"):
        _validate(wrong_tasks, None)

    wrong_settings = SimpleNamespace(
        config=SimpleNamespace(steps=TOPOLOGY, step=job_cfg.step, settings={"enabled": True, "max_packages": 0})
    )
    with pytest.raises(ValueError, match="max_packages"):
        _validate(wrong_settings, None)

    direct = build_job(repository_root=ROOT)
    assert direct.job_id == JOB_ID
