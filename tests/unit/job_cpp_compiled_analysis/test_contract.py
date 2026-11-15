"""Contract, registry, topology, dataset, and config-validator tests for job_cpp_compiled_analysis."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_cpp_compiled_analysis import PROJECT_TASKS, build_job
from appsec_review.jobs.job_cpp_compiled_analysis.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_cpp_compiled_analysis.job import (
    BRANCHES,
    BRANCH_IDENTITY,
    SCHEMA,
    _implementation_files,
    _validate_config,
)
from appsec_review.runtime.contracts import Availability, DispatchClass, MissingPolicy, TargetAccess
from appsec_review.runtime.registry import builtin_registry


ROOT = Path(__file__).resolve().parents[3]


def test_job_identity_units_and_implementation_files() -> None:
    job = build_job()
    assert job.job_id == "job_cpp_compiled_analysis"
    assert job.name == "cpp_compiled_analysis"
    assert job.schema_identity == SCHEMA == "appsec-review/cpp-compiled-analysis/2"
    assert PROJECT_TASKS == ("projects",)
    assert BRANCHES == ("compiled", "ast", "ir", "infer", "binary")
    assert set(BRANCH_IDENTITY) == set(BRANCHES)
    unit_map = {unit.unit_id: unit.dependencies for unit in job.units}
    assert unit_map == {
        "plan.accepted_cpp_plan": (),
        "prepare.projects": ("plan.accepted_cpp_plan",),
        "catalog.projects": ("prepare.projects",),
        "compiled.projects": ("catalog.projects",),
        "ir.projects": ("catalog.projects",),
        "ast.projects": ("catalog.projects", "ir.projects"),
        "infer.projects": ("catalog.projects",),
        "binary.projects": ("catalog.projects",),
        "acceptance.publish_handoff": (
            "compiled.projects",
            "ast.projects",
            "ir.projects",
            "infer.projects",
            "binary.projects",
        ),
    }
    impl = _implementation_files()
    assert all(path.is_file() for path in impl)
    assert any(path.name == "job.py" for path in impl)
    assert any(path.name == "seeded.py" for path in impl)
    assert any(path.name == "llvm_ir.py" for path in impl)


def test_datasets_and_contract_declarations() -> None:
    by_id = {ds.output_kind: ds for ds in DATASETS}
    assert set(by_id) == {
        "cpp_build_graph",
        "clang_ast",
        "llvm_ir",
        "infer_observations",
        "binary_symbols",
        "cpp_blocked_branches",
        "cpp_plan_and_summary",
        "cpp_case_material",
    }
    assert by_id["cpp_build_graph"].disposition == "indexed"
    assert by_id["clang_ast"].disposition == "indexed"
    assert by_id["llvm_ir"].disposition == "indexed"
    assert by_id["infer_observations"].disposition == "indexed"
    assert by_id["binary_symbols"].disposition == "indexed"
    assert by_id["cpp_blocked_branches"].disposition == "indexed"
    assert by_id["cpp_plan_and_summary"].disposition == "artifact_only"
    assert by_id["cpp_case_material"].disposition == "protected"

    assert CONTRACT.dispatch == DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access == TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert CONTRACT.schedule_after == ("job_language_build", "job_evidence_collection")
    assert len(CONTRACT.inputs) == 22
    producers = {req.producer for req in CONTRACT.inputs}
    assert producers == {
        "job_evidence_collection",
        "job_language_build",
        "job_target_analysis_plan",
        "job_target_catalog",
    }
    required = [req for req in CONTRACT.inputs if req.availability == Availability.REQUIRED]
    assert len(required) == 1
    assert required[0].producer == "job_language_build"
    assert required[0].output_kind == "handoff"
    assert required[0].missing == MissingPolicy.REJECT


def test_registry_and_central_config_parity() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    registry = builtin_registry()
    job = registry.build("job_cpp_compiled_analysis")
    job_cfg = config.job("job_cpp_compiled_analysis")
    context = SimpleNamespace(config=job_cfg)
    _validate_config(context, {})
    assert job.consumes == (
        "job_evidence_collection",
        "job_language_build",
        "job_target_analysis_plan",
        "job_target_catalog",
    )


def _fake_config(steps: dict[str, tuple[str, ...]]):
    return SimpleNamespace(
        steps=tuple(steps.keys()),
        step=lambda name: SimpleNamespace(tasks=steps[name]),
    )


def test_validate_config_rejects_mismatched_steps_and_tasks() -> None:
    valid = {
        "plan": ("accepted_cpp_plan",),
        "prepare": ("projects",),
        "catalog": ("projects",),
        "compiled": ("projects",),
        "ast": ("projects",),
        "ir": ("projects",),
        "infer": ("projects",),
        "binary": ("projects",),
        "acceptance": ("publish_handoff",),
    }
    _validate_config(SimpleNamespace(config=_fake_config(valid)), {})

    missing_step = {k: v for k, v in valid.items() if k != "binary"}
    with pytest.raises(ValueError, match="topology does not match"):
        _validate_config(SimpleNamespace(config=_fake_config(missing_step)), {})

    bad_plan = {**valid, "plan": ("wrong_task",)}
    with pytest.raises(ValueError, match="plan task configuration is invalid"):
        _validate_config(SimpleNamespace(config=_fake_config(bad_plan)), {})

    bad_branch = {**valid, "ast": ("wrong_task",)}
    with pytest.raises(ValueError, match="project task configuration mismatch: ast"):
        _validate_config(SimpleNamespace(config=_fake_config(bad_branch)), {})

    bad_accept = {**valid, "acceptance": ("wrong_task",)}
    with pytest.raises(ValueError, match="acceptance task configuration is invalid"):
        _validate_config(SimpleNamespace(config=_fake_config(bad_accept)), {})
