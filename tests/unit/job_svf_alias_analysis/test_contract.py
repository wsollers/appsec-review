"""Contract, registry, topology, dataset, and config-validator tests for job_svf_alias_analysis."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import SVF_ALIAS_HANDOFF_SCHEMA
import appsec_review.jobs.job_svf_alias_analysis as svf_pkg
from appsec_review.jobs.job_svf_alias_analysis import (
    JOB_ID, RETIREMENT_REASON, TOOL_ID, build_job, retirement_metadata,
)
from appsec_review.jobs.job_svf_alias_analysis.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_svf_alias_analysis.job import (
    ADAPTER,
    ARGV,
    DRIVER_SCHEMA,
    FACT_SCHEMA,
    OBJECT_SCHEMA,
    PLAN_SCHEMA,
    RESULT_SCHEMA,
    _validate,
)
from appsec_review.runtime.contracts import Availability, DispatchClass, MissingPolicy, TargetAccess
from appsec_review.runtime.registry import builtin_registry
from tests.fixtures.svf.builder import SETTINGS


ROOT = Path(__file__).resolve().parents[3]


def test_job_identity_and_unit_dag() -> None:
    job = build_job()
    assert job.job_id == JOB_ID == "job_svf_alias_analysis"
    assert job.name == "svf_alias_analysis"
    assert TOOL_ID == "tool-svf"
    assert PLAN_SCHEMA == "appsec-review/svf-plan/1"
    assert RESULT_SCHEMA == "appsec-review/svf-run/1"
    assert DRIVER_SCHEMA == "appsec-review/svf-alias-output/1"
    assert FACT_SCHEMA == "appsec-review/svf-alias-record/1"
    assert OBJECT_SCHEMA == "appsec-review/svf-memory-object/1"
    assert ADAPTER.startswith("svf-alias-adapter/")
    assert ARGV == ("/opt/appsec/svf.py", "run", "/scratch/plan.json", "/scratch/result.json")
    assert job.schema_identity == SVF_ALIAS_HANDOFF_SCHEMA
    assert {u.unit_id: u.dependencies for u in job.units} == {
        "load.accepted_cpp": (),
        "analyze.scopes": ("load.accepted_cpp",),
        "acceptance.publish_handoff": ("load.accepted_cpp", "analyze.scopes"),
    }


def test_datasets_and_contract_declarations() -> None:
    by_id = {ds.output_kind: ds for ds in DATASETS}
    assert set(by_id) == {
        "svf_alias_sets",
        "svf_alias_scope_coverage",
        "svf_alias_summary",
        "svf_alias_raw",
    }
    assert by_id["svf_alias_sets"].disposition == "indexed"
    assert by_id["svf_alias_scope_coverage"].disposition == "indexed"
    assert by_id["svf_alias_summary"].disposition == "artifact_only"
    assert by_id["svf_alias_raw"].disposition == "protected"

    assert CONTRACT.dispatch == DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access == TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert CONTRACT.schedule_after == ("job_cpp_compiled_analysis",)
    assert len(CONTRACT.inputs) == 21
    assert CONSUMES == CONTRACT.consumes == (
        "job_cpp_compiled_analysis",
        "job_evidence_collection",
        "job_target_catalog",
    )
    required = [req for req in CONTRACT.inputs if req.availability == Availability.REQUIRED]
    assert len(required) == 1
    assert required[0].producer == "job_cpp_compiled_analysis"
    assert required[0].output_kind == "handoff"
    assert required[0].missing == MissingPolicy.REJECT


def test_registry_and_central_config_parity() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    job = registry.build(JOB_ID)
    job_cfg = config.job(JOB_ID)
    _validate(SimpleNamespace(config=job_cfg), {})
    assert job.consumes == CONSUMES


def test_validate_rejects_mismatched_tasks() -> None:
    valid = {
        "load": ("accepted_cpp",),
        "analyze": ("scopes",),
        "acceptance": ("publish_handoff",),
    }
    for step in ("load", "analyze", "acceptance"):
        bad = {**valid, step: ("wrong_task",)}
        cfg = SimpleNamespace(
            steps=tuple(bad.keys()),
            step=lambda name, m=bad: SimpleNamespace(tasks=m[name]),
            settings=SETTINGS,
        )
        with pytest.raises(ValueError, match=f"task configuration mismatch: {step}"):
            _validate(SimpleNamespace(config=cfg), {})


def test_svf_retirement_metadata() -> None:
    assert set(svf_pkg.__all__) == {"JOB_ID", "RETIREMENT_REASON", "TOOL_ID", "build_job", "retirement_metadata"}
    assert RETIREMENT_REASON == "retired_by_policy_oom_replaced_by_alternate_cpg"
    assert retirement_metadata() == {
        "retired": True,
        "reason": "retired_by_policy_oom_replaced_by_alternate_cpg",
        "tool_id": "tool-svf",
        "manual_only": True,
        "replacement": "alternate_cpg",
    }
