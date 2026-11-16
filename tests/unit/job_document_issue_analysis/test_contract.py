"""Contract, dataset, topology, registry, and config validation tests for job_document_issue_analysis."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_document_issue_analysis import build_job as package_build_job
from appsec_review.jobs.job_document_issue_analysis.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_document_issue_analysis.job import (
    JOB_ID,
    SCHEMA,
    UNADJUDICATED_GAP,
    _schema_path,
    _validate_config,
    build_job,
)
from appsec_review.runtime.contracts import (
    Availability,
    DispatchClass,
    EvidenceAuthority,
    InputChannel,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.runtime.registry import builtin_registry


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_job_contract_datasets_and_registry_parity() -> None:
    assert package_build_job is build_job
    job = build_job()
    assert job.job_id == JOB_ID == "job_document_issue_analysis"
    assert job.name == "document_issue_analysis"
    assert job.schema_identity == SCHEMA == "appsec-review/document-issue-ledger/1"
    assert [unit.unit_id for unit in job.units] == ["analysis.map_and_adjudicate"]
    assert _schema_path().is_file()
    assert "not adjudicated" in UNADJUDICATED_GAP

    assert len(DATASETS) == 1
    ds = DATASETS[0]
    assert ds.output_kind == "document_issue_ledger"
    assert ds.step == "analysis"
    assert ds.family == "documents"
    assert ds.disposition == "artifact_only"
    assert ds.authority is EvidenceAuthority.PROVISIONAL
    assert ds.artifacts == (
        "data/document-issues/*/ledger.json",
        "data/jobs/job_document_issue_analysis/attempts/*/shared/document-issues/*.json",
    )

    CONTRACT.validate(JOB_ID)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.schedule_after == ("job_review_package_assembly",)
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert job.consumes == CONSUMES == CONTRACT.consumes

    pkg_req = next(
        req
        for req in CONTRACT.inputs
        if req.producer == "job_review_package_assembly" and req.output_kind == "handoff"
    )
    assert pkg_req.channel is InputChannel.HANDOFF
    assert pkg_req.availability is Availability.REQUIRED
    assert pkg_req.missing is MissingPolicy.REJECT
    assert pkg_req.authority is EvidenceAuthority.PRODUCER_EVIDENCE

    reg = builtin_registry()
    built = reg.build(JOB_ID)
    assert built.job_id == JOB_ID
    assert built.datasets == DATASETS
    assert built.contract == CONTRACT


def test_central_config_matches_validator() -> None:
    cfg = load_config(REPO_ROOT / "appsec-review.toml")
    job_cfg = cfg.job(JOB_ID)
    assert dict(job_cfg.settings) == {
        "max_source_files": 20000,
        "max_source_file_bytes": 1048576,
    }
    _validate_config(SimpleNamespace(config=job_cfg), None)


@pytest.mark.parametrize(
    "bad_settings",
    [
        {},
        {"max_source_files": 20000},
        {"max_source_files": 20000, "max_source_file_bytes": 1024, "extra": 1},
        {"max_source_files": 0, "max_source_file_bytes": 1024},
        {"max_source_files": 10, "max_source_file_bytes": 0},
        {"max_source_files": -5, "max_source_file_bytes": 1024},
        {"max_source_files": True, "max_source_file_bytes": 1024},
        {"max_source_files": 10, "max_source_file_bytes": False},
        {"max_source_files": "10", "max_source_file_bytes": 1024},
        {"max_source_files": 10, "max_source_file_bytes": None},
    ],
    ids=[
        "empty",
        "missing-bytes",
        "extra-key",
        "zero-files",
        "zero-bytes",
        "negative-files",
        "bool-files",
        "bool-bytes",
        "str-files",
        "none-bytes",
    ],
)
def test_validate_config_rejects_invalid_settings(bad_settings: dict[str, object]) -> None:
    base_cfg = load_config(REPO_ROOT / "appsec-review.toml").job(JOB_ID)
    bad_cfg = replace(base_cfg, settings=MappingProxyType(bad_settings))
    with pytest.raises(ValueError, match="document issue analysis requires positive bounded source settings"):
        _validate_config(SimpleNamespace(config=bad_cfg), None)


def test_validate_config_rejects_mismatched_steps_or_tasks() -> None:
    base_cfg = load_config(REPO_ROOT / "appsec-review.toml").job(JOB_ID)
    wrong_steps = replace(base_cfg, steps=MappingProxyType({"other": base_cfg.step("analysis")}))
    with pytest.raises(ValueError, match="document issue analysis topology differs from central configuration"):
        _validate_config(SimpleNamespace(config=wrong_steps), None)

    existing_task = base_cfg.step("analysis").task("map_and_adjudicate")
    wrong_tasks = replace(
        base_cfg,
        steps=MappingProxyType(
            {
                "analysis": replace(
                    base_cfg.step("analysis"),
                    tasks=MappingProxyType({"wrong_task": replace(existing_task, task_id="wrong_task")}),
                )
            }
        ),
    )
    with pytest.raises(ValueError, match="document issue analysis topology differs from central configuration"):
        _validate_config(SimpleNamespace(config=wrong_tasks), None)
