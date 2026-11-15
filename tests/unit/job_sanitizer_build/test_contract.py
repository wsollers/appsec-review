"""Contract, registry, and topology tests for ``job_sanitizer_build``."""

from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import SANITIZER_BUILD_HANDOFF_SCHEMA
from appsec_review.jobs.job_sanitizer_build import JOB_ID, build_job
from appsec_review.jobs.job_sanitizer_build.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_sanitizer_build.job import _validate
from appsec_review.orchestration.topology import describe_wave1, wave1_dependencies
from appsec_review.runtime.contracts import (
    Availability,
    DispatchClass,
    EvidenceAuthority,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.runtime.registry import builtin_registry


ROOT = Path(__file__).resolve().parents[3]


def test_job_identity_and_unit_dag() -> None:
    job = build_job()
    assert job.job_id == JOB_ID == "job_sanitizer_build"
    assert job.name == "sanitizer_build"
    assert job.schema_identity == SANITIZER_BUILD_HANDOFF_SCHEMA
    assert [(u.unit_id, u.dependencies) for u in job.units] == [
        ("load.accepted_native", ()),
        ("build.units", ("load.accepted_native",)),
        ("acceptance.publish_handoff", ("load.accepted_native", "build.units")),
    ]


def test_datasets_and_contract_declarations() -> None:
    assert len(DATASETS) == 2
    assert {item.output_kind: item.disposition for item in DATASETS} == {
        "sanitizer_build_summary": "artifact_only",
        "sanitizer_build_workspaces": "protected",
    }
    protected = next(item for item in DATASETS if item.disposition == "protected")
    assert protected.artifacts == ("data/sanitizer/**",)
    assert protected.sensitivity == "sensitive"

    assert len(CONTRACT.inputs) == 6
    assert CONSUMES == ("job_language_build",)
    handoff_req = CONTRACT.inputs[0]
    assert handoff_req.producer == "job_language_build"
    assert handoff_req.output_kind == "handoff"
    assert handoff_req.availability is Availability.REQUIRED
    assert handoff_req.missing is MissingPolicy.REJECT
    assert all(inp.authority is EvidenceAuthority.PRODUCER_EVIDENCE for inp in CONTRACT.inputs)
    assert CONTRACT.schedule_after == ("job_language_build",)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True


def test_topology_places_the_job_after_language_build_with_one_terminal_job() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    jobs = {item["job_id"]: item for item in describe_wave1(config, registry)["jobs"]}
    assert jobs[JOB_ID]["dependencies"] == ["job_language_build"]
    assert "job_language_build" in jobs[JOB_ID]["upstream_handoffs"]
    depended = {dependency for item in jobs.values() for dependency in item["dependencies"]}
    assert set(jobs) - depended == {"job_final_report_publication", "job_openvex_export"}
    consumers = [job_id for job_id, item in jobs.items() if JOB_ID in item["dependencies"]]
    assert consumers == ["job_review_data_indexing"]
    for sibling in (
        "job_cpp_compiled_analysis",
        "job_codeql_analysis",
        "job_clang_static_analysis",
        "job_post_build_security_assessment",
        "job_security_tagging",
    ):
        assert JOB_ID not in jobs[sibling]["upstream_handoffs"]


def test_only_the_dataset_inventory_declares_the_job_as_consumed() -> None:
    declaring = []
    for job_id in builtin_registry().job_ids():
        try:
            module = importlib.import_module(f"appsec_review.jobs.{job_id}.datasets")
        except ModuleNotFoundError:
            continue
        if JOB_ID in getattr(module, "CONSUMES", ()):
            declaring.append(job_id)
    assert declaring == ["job_review_data_indexing"]


def test_disabled_job_is_transparent_to_topology() -> None:
    registered = {
        job_id
        for job_id in builtin_registry().job_ids()
        if job_id
        not in {
            JOB_ID,
            "job_third_party_data_sync",
            "job_inference_security_review",
            "job_final_publication_gate",
            "job_final_report_publication",
        }
    }
    dependencies = wave1_dependencies(registered)
    assert JOB_ID not in dependencies
    assert all(JOB_ID not in values for values in dependencies.values())


def test_validate_accepts_central_config_and_rejects_mismatched_steps_or_tasks() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job_cfg = config.job(JOB_ID)
    _validate(SimpleNamespace(config=job_cfg), None)

    bad_steps = SimpleNamespace(
        config=SimpleNamespace(steps=("load", "acceptance"), step=job_cfg.step, settings=job_cfg.settings)
    )
    with pytest.raises(ValueError, match="topology does not match central configuration"):
        _validate(bad_steps, None)

    bad_task = SimpleNamespace(
        config=SimpleNamespace(
            steps=("load", "build", "acceptance"),
            step=lambda s: SimpleNamespace(tasks=("wrong",) if s == "build" else job_cfg.step(s).tasks),
            settings=job_cfg.settings,
        )
    )
    with pytest.raises(ValueError, match="task configuration mismatch: build"):
        _validate(bad_task, None)
