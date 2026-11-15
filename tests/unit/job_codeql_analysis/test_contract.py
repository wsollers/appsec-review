"""Contract, registry, topology, and configuration validation tests for job_codeql_analysis."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.input_matrix import INPUT_SOURCES
import appsec_review.jobs.job_codeql_analysis as codeql_pkg
from appsec_review.jobs.job_codeql_analysis import CodeQLPlan, CodeQLScope, build_codeql_plan, build_job
from appsec_review.jobs.job_codeql_analysis.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_codeql_analysis.job import (
    FrameworkIntegrityError,
    SCHEMA,
    _validate_config,
    _validate_scope_assets,
    publication_status,
)
from appsec_review.jobs.job_codeql_analysis.planning import SCOPE_SCHEMA
from appsec_review.codeql.runtime import load_asset_lock
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.runtime.contracts import DispatchClass, EvidenceAuthority, TargetAccess
from appsec_review.runtime.registry import builtin_registry


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_package_exports_and_registry_topology_parity() -> None:
    assert set(codeql_pkg.__all__) == {"CodeQLPlan", "CodeQLScope", "build_codeql_plan", "build_job"}
    assert CodeQLPlan is not None and CodeQLScope is not None and build_codeql_plan is not None

    config = load_config(REPO_ROOT / "appsec-review.toml")
    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="central configuration")
    job = registry.build("job_codeql_analysis")
    assert job.job_id == "job_codeql_analysis"
    assert job.name == "codeql_analysis"
    assert job.schema_identity == SCHEMA
    assert job.implementation_identity is None
    assert job.validation_identity is None
    assert [u.unit_id for u in job.units] == [
        "plan.inventory",
        "execution.scopes",
        "acceptance.publish_handoff",
    ]
    assert job.units[0].dependencies == ()
    assert job.units[1].dependencies == ("plan.inventory",)
    assert job.units[2].dependencies == ("execution.scopes",)

    job_cfg = config.job("job_codeql_analysis")
    _validate_config(SimpleNamespace(config=job_cfg), None)

    wave1 = {entry["job_id"]: entry for entry in describe_wave1(config, registry)["jobs"]}
    assert "job_codeql_analysis" in wave1
    order = [entry["job_id"] for entry in describe_wave1(config, registry)["jobs"]]
    assert order.index("job_language_build") < order.index("job_codeql_analysis")
    assert order.index("job_codeql_analysis") < order.index("job_code_graph_index")

    matrix_by_name = {row[0]: row for row in INPUT_SOURCES}
    assert "codeql_sarif" in matrix_by_name
    assert "job_codeql_analysis" in matrix_by_name["codeql_sarif"][1]


def test_contract_and_dataset_declarations() -> None:
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert CONSUMES == CONTRACT.consumes
    assert "job_target_catalog" in CONSUMES
    assert "job_language_build" in CONSUMES

    by_producer = {}
    for req in CONTRACT.inputs:
        by_producer.setdefault(req.producer, set()).add(req.authority)
    assert by_producer["job_change_context_analysis"] == {EvidenceAuthority.ROUTING_CONTEXT}
    assert by_producer["job_language_build"] == {EvidenceAuthority.PRODUCER_EVIDENCE}

    kinds = [d.output_kind for d in DATASETS]
    assert kinds == [
        "codeql_predecessor_import",
        "codeql_graph_export",
        "codeql_observations",
        "codeql_plan_and_summary",
        "codeql_cache_initialization",
        "codeql_scope_material",
    ]


def test_validate_config_rejects_mismatched_steps_tasks_and_workers() -> None:
    bad_steps = SimpleNamespace(steps={"plan": object()})
    with pytest.raises(ValueError, match="topology does not match"):
        _validate_config(SimpleNamespace(config=bad_steps), None)

    def _cfg(*, bad_step: str = "", step_workers: int = 1, task_workers: int = 1):
        steps = {
            "plan": ("inventory",),
            "execution": ("scopes",),
            "acceptance": ("publish_handoff",),
        }
        if bad_step:
            steps[bad_step] = ("wrong_task",)

        def _get_step(name: str):
            t_names = steps[name]
            return SimpleNamespace(
                workers=step_workers if name == "execution" else 1,
                tasks={t: SimpleNamespace(workers=task_workers if name == "acceptance" else 1) for t in t_names},
            )

        return SimpleNamespace(steps=steps, step=_get_step, typed_settings=None)

    with pytest.raises(ValueError, match="task configuration mismatch: execution"):
        _validate_config(SimpleNamespace(config=_cfg(bad_step="execution")), None)

    with pytest.raises(ValueError, match="settings.concurrency is the only action fan-out control"):
        _validate_config(SimpleNamespace(config=_cfg(step_workers=2)), None)

    with pytest.raises(ValueError, match="settings.concurrency is the only action fan-out control"):
        _validate_config(SimpleNamespace(config=_cfg(task_workers=2)), None)


def test_validate_scope_assets_checks_mode_pack_additional_and_custom_locks() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    settings = config.job("job_codeql_analysis").typed_settings
    lock = load_asset_lock(REPO_ROOT)

    py_scope = CodeQLScope(
        schema=SCOPE_SCHEMA,
        scope_id="codeql-unit-py",
        language="python",
        source_languages=("Python",),
        mode="none",
        root=".",
        files=({"path": "app.py", "sha256": "a" * 64, "size_bytes": 10},),
        build_unit_id=None,
        build_receipt_fingerprint=None,
        environment_identity="b" * 64,
        commands_permitted=False,
    )
    _validate_scope_assets(py_scope, settings, lock)

    unknown_scope = replace(py_scope, language="cobol")
    with pytest.raises(FrameworkIntegrityError, match="mode differs from central configuration"):
        _validate_scope_assets(unknown_scope, settings, lock)

    bad_mode_scope = CodeQLScope(
        schema=SCOPE_SCHEMA,
        scope_id="codeql-unit-py-manual",
        language="python",
        source_languages=("Python",),
        mode="manual",
        root=".",
        files=py_scope.files,
        build_unit_id="u1",
        build_receipt_fingerprint="f1",
        environment_identity="b" * 64,
        commands_permitted=True,
    )
    with pytest.raises(FrameworkIntegrityError, match="mode differs from central configuration"):
        _validate_scope_assets(bad_mode_scope, settings, lock)

    bad_lock_pack = {**lock, "query_packs": {**lock["query_packs"], "python": {**lock["query_packs"]["python"], "version": "0.0.0"}}}
    with pytest.raises(FrameworkIntegrityError, match="query assets differ from the lock"):
        _validate_scope_assets(py_scope, settings, bad_lock_pack)

    bad_lock_additional = {
        **lock,
        "query_packs": {
            **lock["query_packs"],
            "python": {**lock["query_packs"]["python"], "additional_suites": [{"query_id": "extra"}]},
        },
    }
    with pytest.raises(FrameworkIntegrityError, match="additional query assets differ from the lock"):
        _validate_scope_assets(py_scope, settings, bad_lock_additional)

    bad_lock_custom = {**lock, "custom_query_packs": {**lock.get("custom_query_packs", {}), "python": [{"query_id": "c1"}]}}
    with pytest.raises(FrameworkIntegrityError, match="custom query assets differ from the lock"):
        _validate_scope_assets(py_scope, settings, bad_lock_custom)


def test_publication_status_distinguishes_clean_from_uncovered_outcomes() -> None:
    assert publication_status(
        [{"disposition": "PROCESSED"}],
        [{"terminal_status": "SUCCEEDED"}],
        exports=[{"export_status": "SUCCEEDED", "gaps": []}],
    ) == "SUCCEEDED"
    assert publication_status(
        [{"disposition": "GAP"}],
        [{"terminal_status": "SUCCEEDED"}],
    ) == "COMPLETED_WITH_GAPS"
    assert publication_status(
        [{"disposition": "PROCESSED"}],
        [{"terminal_status": "FAILED"}],
    ) == "COMPLETED_WITH_GAPS"
    assert publication_status(
        [{"disposition": "PROCESSED"}],
        [{"terminal_status": "SUCCEEDED"}],
        exports=[{"export_status": "SUCCEEDED", "gaps": ["truncated"]}],
    ) == "COMPLETED_WITH_GAPS"
