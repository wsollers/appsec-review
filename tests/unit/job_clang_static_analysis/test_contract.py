"""Contract, registry, topology, dataset, and config-validator tests for job_clang_static_analysis."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import pytest

from appsec_review.config import load_config
from appsec_review.jobs.engineering_contracts import CLANG_STATIC_HANDOFF_SCHEMA
from appsec_review.jobs.job_clang_static_analysis import JOB_ID, TOOL_ID, build_job
from appsec_review.jobs.job_clang_static_analysis.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_clang_static_analysis.job import (
    ADAPTER,
    ENGINES,
    OUTPUT_SCHEMA,
    _validate,
    _validated_settings,
)
from appsec_review.runtime.contracts import Availability, DispatchClass, MissingPolicy, TargetAccess
from appsec_review.runtime.registry import builtin_registry

from .support import SETTINGS


ROOT = Path(__file__).resolve().parents[3]


def test_job_identity_and_unit_dag() -> None:
    job = build_job()
    assert job.job_id == JOB_ID == "job_clang_static_analysis"
    assert job.name == "clang_static_analysis"
    assert TOOL_ID == "tool-clang-static-analysis"
    assert OUTPUT_SCHEMA == "appsec-review/clang-static-output/1"
    assert ADAPTER.startswith("clang-static-adapter/")
    assert ENGINES == ("clang-tidy", "clang-static-analyzer")
    assert job.schema_identity == CLANG_STATIC_HANDOFF_SCHEMA
    assert {unit.unit_id: unit.dependencies for unit in job.units} == {
        "load.accepted_cpp": (),
        "analyze.scopes": ("load.accepted_cpp",),
        "acceptance.publish_handoff": ("load.accepted_cpp", "analyze.scopes"),
    }


def test_datasets_and_contract_declarations() -> None:
    by_id = {ds.output_kind: ds for ds in DATASETS}
    assert set(by_id) == {
        "clang_static_observations",
        "clang_static_scope_coverage",
        "clang_static_summary",
        "clang_static_raw",
    }
    assert by_id["clang_static_observations"].disposition == "indexed"
    assert by_id["clang_static_scope_coverage"].disposition == "indexed"
    assert by_id["clang_static_summary"].disposition == "artifact_only"
    assert by_id["clang_static_raw"].disposition == "protected"

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


def _fake_config(steps: dict[str, tuple[str, ...]], settings: dict | None = None):
    return SimpleNamespace(
        steps=tuple(steps.keys()),
        step=lambda name: SimpleNamespace(tasks=steps[name]),
        settings=settings if settings is not None else SETTINGS,
    )


def test_validate_rejects_mismatched_steps_tasks_and_settings() -> None:
    valid = {
        "load": ("accepted_cpp",),
        "analyze": ("scopes",),
        "acceptance": ("publish_handoff",),
    }
    _validate(SimpleNamespace(config=_fake_config(valid)), {})

    with pytest.raises(ValueError, match="topology does not match"):
        _validate(SimpleNamespace(config=_fake_config({"load": ("accepted_cpp",)})), {})

    for step in ("load", "analyze", "acceptance"):
        bad = {**valid, step: ("wrong_task",)}
        with pytest.raises(ValueError, match=f"task configuration mismatch: {step}"):
            _validate(SimpleNamespace(config=_fake_config(bad)), {})

    with pytest.raises(ValueError, match="clang_tidy_checks must be a non-empty string list"):
        _validated_settings({**SETTINGS, "clang_tidy_checks": []})
    with pytest.raises(ValueError, match="clang_tidy_checks must be a non-empty string list"):
        _validated_settings({**SETTINGS, "clang_tidy_checks": [""]})

    with pytest.raises(ValueError, match="clang_analyzer_checkers must be a non-empty string list"):
        _validated_settings({**SETTINGS, "clang_analyzer_checkers": []})
    with pytest.raises(ValueError, match="clang_analyzer_checkers must be a non-empty string list"):
        _validated_settings({**SETTINGS, "clang_analyzer_checkers": [123]})

    for key in ("workers", "max_output_bytes", "max_diagnostics_per_scope"):
        with pytest.raises(ValueError, match="numeric bounds must be positive"):
            _validated_settings({**SETTINGS, key: 0})
