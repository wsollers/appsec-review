"""Contract, dataset, configuration, and topology parity unit tests for job_review_package_assembly."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs import job_review_package_assembly as package
from appsec_review.jobs.job_review_package_assembly import datasets as datasets_module
from appsec_review.jobs.job_review_package_assembly.datasets import CONTRACT, CONSUMES, DATASETS
from appsec_review.jobs.job_review_package_assembly.job import (
    JOB_ID,
    SCHEMA,
    TOPOLOGY,
    _validate_config,
    build_job,
)
from appsec_review.runtime.contracts import (
    Availability,
    DispatchClass,
    EvidenceAuthority,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.runtime.registry import builtin_registry


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_package_exports_and_registry_parity() -> None:
    assert package.__all__ == ("build_job",)
    assert package.build_job is build_job
    assert JOB_ID == "job_review_package_assembly"
    assert SCHEMA == "appsec-review/review-package-assembly/1"
    assert TOPOLOGY == {"publication": ("publish_packages",)}

    registry = builtin_registry()
    built = registry.build(JOB_ID)
    assert built.job_id == JOB_ID
    assert built.name == "review_package_assembly"
    assert built.schema_identity == SCHEMA
    assert built.datasets == DATASETS
    assert built.contract == CONTRACT
    assert built.consumes == CONSUMES == CONTRACT.consumes
    assert datasets_module.CONSUMES == CONSUMES
    assert tuple(unit.unit_id for unit in built.units) == ("publication.publish_packages",)


def test_datasets_and_contract_pins() -> None:
    assert len(DATASETS) == 1
    declaration = DATASETS[0]
    assert declaration.output_kind == "review_packages"
    assert declaration.step == "publication"
    assert declaration.family == "precomputed"
    assert declaration.schema == "appsec-review/review-package-manifest/2"
    assert declaration.disposition == "artifact_only"
    assert declaration.artifacts == ("data/review-packages/*/*.json",)
    assert declaration.reason

    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert CONTRACT.schedule_after == ("job_review_data_indexing",)

    indexing_handoff = [
        req
        for req in CONTRACT.inputs
        if req.producer == "job_review_data_indexing" and req.output_kind == "handoff"
    ]
    assert len(indexing_handoff) == 1
    assert indexing_handoff[0].availability is Availability.REQUIRED
    assert indexing_handoff[0].missing is MissingPolicy.REJECT
    assert indexing_handoff[0].authority is EvidenceAuthority.PRODUCER_EVIDENCE


def test_validate_config_accepts_central_config_and_rejects_mismatches() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    job_cfg = config.job(JOB_ID)
    _validate_config(SimpleNamespace(config=job_cfg), None)

    # Extra or missing step rejected
    with pytest.raises(ValueError, match="topology differs from central configuration"):
        _validate_config(SimpleNamespace(config=replace(job_cfg, steps={})), None)

    # Task mismatch rejected
    bad_step = replace(job_cfg.step("publication"), tasks={})
    with pytest.raises(ValueError, match="task differs from central configuration"):
        _validate_config(
            SimpleNamespace(config=replace(job_cfg, steps={"publication": bad_step})),
            None,
        )

    # Invalid max_page_size values rejected (including bool subclass of int, 0, >100, non-int)
    for invalid in (True, False, 0, -1, 101, "20", None):
        altered = replace(job_cfg, settings=MappingProxyType({"max_page_size": invalid}))
        with pytest.raises(ValueError, match="max_page_size must be an integer from 1 through 100"):
            _validate_config(SimpleNamespace(config=altered), None)

    # Boundary valid values 1 and 100 accepted
    for boundary in (1, 100):
        valid_cfg = replace(job_cfg, settings=MappingProxyType({"max_page_size": boundary}))
        _validate_config(SimpleNamespace(config=valid_cfg), None)
