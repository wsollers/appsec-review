"""Contract, dataset, configuration, and topology parity unit tests for job_review_data_indexing."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs import job_review_data_indexing as package
from appsec_review.jobs.job_review_data_indexing import datasets as datasets_module
from appsec_review.jobs.job_review_data_indexing import job as job_module
from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT, CONSUMES, DATASETS
from appsec_review.jobs.job_review_data_indexing.job import (
    FOLLOW_UP_STATUS,
    GRAPH_DEPENDENT,
    GRAPH_FOLLOW_UP,
    INVENTORY_RULE,
    JOB_ID,
    PRODUCT_SETS,
    SCHEMA,
    TOPOLOGY,
    _validate,
    build_job,
    downstream_jobs,
    registry_providers,
)
from appsec_review.runtime.contracts import DispatchClass, EvidenceAuthority, InputChannel, TargetAccess
from appsec_review.runtime.inputs import feed_input_identity
from appsec_review.runtime.registry import builtin_registry


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_package_exports_and_lazy_downstream_jobs_attribute() -> None:
    assert package.__all__ == ["JOB_ID", "build_job"]
    assert package.JOB_ID == JOB_ID == "job_review_data_indexing"
    assert package.build_job is build_job
    expected_downstream = downstream_jobs()
    assert expected_downstream == job_module.DOWNSTREAM_JOBS
    assert "job_inference_security_review" in expected_downstream or "job_poc_generation" in expected_downstream
    assert JOB_ID not in expected_downstream
    with pytest.raises(AttributeError, match="NO_SUCH_EXPORT"):
        getattr(job_module, "NO_SUCH_EXPORT")


def test_datasets_and_contract_match_registry_and_central_configuration() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    job_config = config.job(JOB_ID)
    assert tuple(job_config.steps) == tuple(TOPOLOGY)
    for step, tasks in TOPOLOGY.items():
        assert tuple(job_config.step(step).tasks) == tasks
    assert len(PRODUCT_SETS) == 11

    registry = builtin_registry()
    built = registry.build(JOB_ID)
    assert built.job_id == JOB_ID
    assert built.schema_identity == SCHEMA == "appsec-review/review-data-indexing/1"
    assert INVENTORY_RULE == "appsec-review/dataset-inventory-index/2"
    assert built.datasets == DATASETS
    assert built.contract == CONTRACT
    assert built.consumes == CONSUMES == CONTRACT.consumes
    assert built.external_input_identity is feed_input_identity
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert "job_threat_model_generation" in CONTRACT.schedule_after
    assert "job_owasp_control_assessment" in CONTRACT.schedule_after

    kinds = {item.output_kind: item for item in DATASETS}
    assert set(kinds) == {
        "accepted_input_summary",
        "cross_domain_links",
        "precomputed_products",
        "derived_checkpoints",
        "fts_image_validation",
        "dataset_audit_report",
        "coverage_matrices",
        "dataset_inventory",
    }
    assert kinds["dataset_inventory"].required is True
    assert kinds["dataset_inventory"].disposition == "indexed"
    assert kinds["cross_domain_links"].disposition == "indexed"
    assert kinds["precomputed_products"].disposition == "indexed"
    for artifact_kind in (
        "accepted_input_summary",
        "derived_checkpoints",
        "fts_image_validation",
        "dataset_audit_report",
        "coverage_matrices",
    ):
        assert kinds[artifact_kind].disposition == "artifact_only"
        assert kinds[artifact_kind].reason

    external = [req for req in CONTRACT.inputs if req.channel is InputChannel.EXTERNAL]
    assert len(external) == 1
    assert external[0].producer == "job_third_party_data_sync"
    assert external[0].output_kind == "feed_snapshot"
    assert external[0].authority is EvidenceAuthority.REFERENCE
    assert datasets_module.CONSUMES == CONSUMES

    unit_ids = tuple(unit.unit_id for unit in built.units)
    assert unit_ids == (
        "load.accepted_inputs",
        "links.cross_domain",
        *(f"precompute.{name}" for name in PRODUCT_SETS),
        "fts.image_validation",
        "audit.inventory",
        "matrix.coverage",
        "publish.inventory_index",
    )


def test_registry_providers_and_follow_up_constants() -> None:
    job_ids, declarations, consumes = registry_providers()
    registry = builtin_registry()
    assert job_ids == registry.job_ids()
    assert JOB_ID in declarations and declarations[JOB_ID] == DATASETS
    assert consumes[JOB_ID] == CONSUMES
    assert FOLLOW_UP_STATUS == "pending_follow_up"
    assert GRAPH_DEPENDENT == frozenset({"hotspot_context", "review_package"})
    assert len(GRAPH_FOLLOW_UP) == 6


def test_input_validator_enforces_step_and_task_topology() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    job_config = config.job(JOB_ID)
    _validate(SimpleNamespace(config=job_config), None)

    missing_step = dict(job_config.steps)
    missing_step.pop("publish")
    with pytest.raises(ValueError, match="topology does not match central configuration"):
        _validate(SimpleNamespace(config=replace(job_config, steps=missing_step)), None)

    bad_step = replace(job_config.step("audit"), tasks={})
    altered_steps = {**job_config.steps, "audit": bad_step}
    with pytest.raises(ValueError, match="task configuration mismatch: audit"):
        _validate(SimpleNamespace(config=replace(job_config, steps=altered_steps)), None)
