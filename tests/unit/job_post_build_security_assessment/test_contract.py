from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config import JobConfig, StepConfig, load_config
from appsec_review.jobs import job_post_build_security_assessment
from appsec_review.jobs.job_post_build_security_assessment import build_job
from appsec_review.jobs.job_post_build_security_assessment.assessment import SCHEMA
from appsec_review.jobs.job_post_build_security_assessment.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_post_build_security_assessment.job import TOPOLOGY, _validate_config
from appsec_review.runtime.contracts import DispatchClass, EvidenceAuthority, TargetAccess
from appsec_review.runtime.registry import builtin_registry

ROOT = Path(__file__).resolve().parents[3]


def _central_job_config() -> JobConfig:
    return load_config(ROOT / "appsec-review.toml").job("job_post_build_security_assessment")


def test_public_package_exports_datasets_contract_and_unit_topology() -> None:
    assert job_post_build_security_assessment.__all__ == ["PROJECT_TASKS", "build_job"]
    job = build_job()
    assert job.job_id == "job_post_build_security_assessment"
    assert job.name == "post_build_security_assessment"
    assert job.schema_identity == SCHEMA
    assert job.datasets == DATASETS
    assert job.contract == CONTRACT
    assert job.consumes == CONSUMES

    by_kind = {item.output_kind: item for item in DATASETS}
    assert sorted(by_kind) == ["build_security", "build_security_documents"]
    assert by_kind["build_security"].disposition == "indexed"
    assert by_kind["build_security"].query_route == "query_build_security"
    assert by_kind["build_security_documents"].disposition == "artifact_only"

    assert CONTRACT.schedule_after == ("job_cpp_compiled_analysis",)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert set(CONSUMES) == {
        "job_build_environment_analysis",
        "job_cpp_compiled_analysis",
        "job_language_build",
        "job_project_build",
        "job_target_analysis_plan",
        "job_target_catalog",
    }
    authorities = {
        (item.producer, item.output_kind): item.authority for item in CONTRACT.inputs
    }
    assert authorities[("job_build_environment_analysis", "handoff")] is EvidenceAuthority.OPERATIONAL
    assert authorities[("job_cpp_compiled_analysis", "handoff")] is EvidenceAuthority.PRODUCER_EVIDENCE
    assert authorities[("job_language_build", "language_build_receipts")] is EvidenceAuthority.PRODUCER_EVIDENCE

    units = {unit.unit_id: unit for unit in job.units}
    assert list(units) == [
        "load.accepted_cpp_build",
        "provenance.native_units",
        "inspection.native_units",
        "deterministic.native_units",
        "inference.native_units",
        "index.native_units",
        "publication.publish_handoff",
    ]
    assert units["load.accepted_cpp_build"].dependencies == ()
    assert units["provenance.native_units"].dependencies == ("load.accepted_cpp_build",)
    assert units["inspection.native_units"].dependencies == ("provenance.native_units",)
    assert units["deterministic.native_units"].dependencies == (
        "provenance.native_units",
        "inspection.native_units",
    )
    assert units["inference.native_units"].dependencies == (
        "provenance.native_units",
        "inspection.native_units",
        "deterministic.native_units",
    )
    assert units["index.native_units"].dependencies == (
        "load.accepted_cpp_build",
        "provenance.native_units",
        "inspection.native_units",
        "deterministic.native_units",
        "inference.native_units",
    )
    assert units["publication.publish_handoff"].dependencies == ("index.native_units",)

    registry = builtin_registry()
    built = registry.build("job_post_build_security_assessment")
    assert built.job_id == "job_post_build_security_assessment"


def test_validate_config_accepts_central_toml_and_rejects_invalid_settings() -> None:
    base = _central_job_config()
    _validate_config(SimpleNamespace(config=base), None)

    reordered_steps = MappingProxyType({k: base.steps[k] for k in reversed(list(TOPOLOGY))})
    with pytest.raises(ValueError, match="topology does not match central configuration"):
        _validate_config(SimpleNamespace(config=replace(base, steps=reordered_steps)), None)

    bad_tasks = dict(base.steps)
    bad_tasks["inspection"] = replace(base.steps["inspection"], tasks=MappingProxyType({}))
    with pytest.raises(ValueError, match="task order mismatch: inspection"):
        _validate_config(SimpleNamespace(config=replace(base, steps=MappingProxyType(bad_tasks))), None)

    with pytest.raises(ValueError, match="model settings are incomplete"):
        _validate_config(SimpleNamespace(config=replace(base, settings=MappingProxyType({}))), None)

    base_model = dict(base.settings["model"])
    with pytest.raises(ValueError, match="model settings are incomplete"):
        incomplete = {k: v for k, v in base_model.items() if k != "retries"}
        _validate_config(
            SimpleNamespace(config=replace(base, settings=MappingProxyType({"model": incomplete}))),
            None,
        )

    with pytest.raises(ValueError, match="enabled setting must be boolean"):
        _validate_config(
            SimpleNamespace(
                config=replace(base, settings=MappingProxyType({"model": {**base_model, "enabled": 1}}))
            ),
            None,
        )

    for key, bad_val in [
        ("max_input_tokens", 0),
        ("max_input_tokens", True),
        ("max_output_tokens", -1),
        ("timeout_seconds", 0),
    ]:
        with pytest.raises(ValueError, match=f"model bound is invalid: {key}"):
            _validate_config(
                SimpleNamespace(
                    config=replace(base, settings=MappingProxyType({"model": {**base_model, key: bad_val}}))
                ),
                None,
            )

    for bad_retries in (-1, 6, True):
        with pytest.raises(ValueError, match="retries must be between zero and five"):
            _validate_config(
                SimpleNamespace(
                    config=replace(
                        base,
                        settings=MappingProxyType({"model": {**base_model, "retries": bad_retries}}),
                    )
                ),
                None,
            )
