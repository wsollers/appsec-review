"""Contract, input-validator, and helper unit tests for job_inference_security_review."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_inference_security_review.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_inference_security_review.job import (
    JOB_ID,
    LEDGER_UNITS,
    SCHEMA,
    TOPOLOGY,
    _artifact,
    _check_isolation,
    _excluded,
    _read,
    _settings,
    _status,
    available_sources,
    build_job,
    package_works,
    review_index_names,
    run_sources,
)
from appsec_review.observability import EventLog
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.job import JobContext
from appsec_review.runtime.registry import builtin_registry
from appsec_review.runtime.units import UnitContext
from appsec_review.storage import atomic_json, file_sha256

ROOT = Path(__file__).resolve().parents[3]


def _job_context(tmp_path: Path, *, config=None, target_root: Path | None = None) -> JobContext:
    loaded = load_config(ROOT / "appsec-review.toml")
    job_cfg = config if config is not None else loaded.job(JOB_ID)
    run_root = tmp_path / "run"
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt-1"
    attempt_root.mkdir(parents=True, exist_ok=True)
    return JobContext(
        run_id="run-unit-1",
        attempt_id="attempt-1",
        trigger="cli",
        repository_root=ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=attempt_root / "meta",
        orchestration={},
        config=job_cfg,
        events=EventLog(attempt_root / "events.jsonl"),
        target_root=target_root,
        contract=CONTRACT,
    )


def test_contract_datasets_topology_and_registry_parity(tmp_path: Path) -> None:
    job = build_job(repository_root=ROOT)
    assert job.job_id == JOB_ID
    assert job.schema_identity == SCHEMA
    assert job.contract == CONTRACT
    assert job.datasets == DATASETS
    assert len(DATASETS) == 13
    assert {item.output_kind for item in DATASETS} == {
        "accepted_scope",
        "lead_triage",
        "review_packages",
        "review_cells",
        "claim_ledger",
        "attack_chains",
        "review_audit_metadata",
        "review_decision_audit",
        "review_decisions",
        "review_verification_coverage",
        "review_decision_bases",
        "review_audit_continuations",
        "scores_and_findings",
    }
    expected_units = tuple(
        f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks
    )
    assert tuple(unit.unit_id for unit in job.units) == expected_units
    assert set(LEDGER_UNITS).issubset(expected_units)

    reg_job = builtin_registry().build(JOB_ID)
    assert reg_job.job_id == JOB_ID
    assert reg_job.contract == CONTRACT
    assert reg_job.datasets == DATASETS

    ctx = _job_context(tmp_path)
    for validator in job.input_validators:
        validator(ctx, None)


def test_input_validator_rejects_mismatched_steps_tasks_and_untyped_settings(tmp_path: Path) -> None:
    job = build_job(repository_root=ROOT)
    validator = job.input_validators[0]
    loaded = load_config(ROOT / "appsec-review.toml")
    base_cfg = loaded.job(JOB_ID)

    missing_step_cfg = replace(
        base_cfg,
        steps=MappingProxyType({k: v for k, v in base_cfg.steps.items() if k != "scoring"}),
    )
    with pytest.raises(ValueError, match="topology does not match configuration"):
        validator(_job_context(tmp_path / "s1", config=missing_step_cfg), None)

    bad_task_step = replace(base_cfg.steps["scoring"], tasks=MappingProxyType({}))
    bad_tasks_cfg = replace(
        base_cfg,
        steps=MappingProxyType({**base_cfg.steps, "scoring": bad_task_step}),
    )
    with pytest.raises(ValueError, match="task order mismatch: scoring"):
        validator(_job_context(tmp_path / "s2", config=bad_tasks_cfg), None)

    untyped_cfg = replace(base_cfg, typed_settings=None)
    untyped_ctx = _job_context(tmp_path / "s3", config=untyped_cfg)
    with pytest.raises(ValueError, match="settings are not typed"):
        validator(untyped_ctx, None)

    u_ctx = UnitContext(
        job=untyped_ctx,
        unit_id="scope.accept_manifest",
        step_id="scope",
        task_id="accept_manifest",
        unit_root=untyped_ctx.attempt_root / "u",
        outputs={},
    )
    with pytest.raises(ValueError, match="settings are not typed"):
        _settings(u_ctx)


def test_status_artifact_and_read_integrity_guards(tmp_path: Path) -> None:
    assert _status([]) == "SUCCEEDED"
    assert _status(["gap-1"]) == "COMPLETED_WITH_GAPS"

    run_root = tmp_path / "run"
    payload = run_root / "data" / "doc.json"
    atomic_json(payload, {"hello": "world"})
    ref = _artifact(run_root, payload)
    assert ref["path"] == "data/doc.json"
    assert _read(run_root, ref) == {"hello": "world"}

    with pytest.raises(IntegrityError, match="changed after acceptance"):
        _read(run_root, {"path": "../outside.json", "sha256": ref["sha256"]})

    with pytest.raises(IntegrityError, match="changed after acceptance"):
        _read(run_root, {"path": "data/missing.json", "sha256": ref["sha256"]})

    with pytest.raises(IntegrityError, match="changed after acceptance"):
        _read(run_root, {"path": "data/doc.json", "sha256": "0" * 64})


def test_check_isolation_and_excluded_reject_evaluator_and_target_guidance(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"target_root": "/safe/repo"}), encoding="utf-8")
    clean_scope = SimpleNamespace(
        manifest_path=manifest_path,
        shards=[{"relative_path": "data/indexes/source/index.sqlite"}],
        source_files=[
            SimpleNamespace(identity="f1", path="src/main.py"),
            SimpleNamespace(identity="f2", path="AGENTS.md"),
            SimpleNamespace(identity="f3", path="sub/.github/copilot-instructions.md"),
            SimpleNamespace(identity="f4", path="pkg/.cursor/rules/sec.mdc"),
            SimpleNamespace(identity="f5", path="appsec-multi-vuln-guide/expected.json"),
        ],
    )
    assert _excluded(clean_scope) == {"f2", "f3", "f4", "f5"}

    with pytest.raises(IntegrityError, match="accepted inputs name an evaluator root"):
        _check_isolation(clean_scope)

    safe_scope = SimpleNamespace(
        manifest_path=manifest_path,
        shards=[{"relative_path": "data/indexes/source/index.sqlite"}],
        source_files=[SimpleNamespace(identity="f1", path="src/main.py")],
    )
    _check_isolation(safe_scope)

    bad_shard_scope = SimpleNamespace(
        manifest_path=manifest_path,
        shards=[{"relative_path": "appsec-multi-vuln-guide/index.sqlite"}],
        source_files=[],
    )
    with pytest.raises(IntegrityError, match="accepted inputs name an evaluator root"):
        _check_isolation(bad_shard_scope)

    manifest_path.write_text(
        json.dumps({"target_root": "/tmp/appsec-multi-vuln-guide"}), encoding="utf-8"
    )
    with pytest.raises(IntegrityError, match="accepted inputs name an evaluator root"):
        _check_isolation(safe_scope)


def test_sources_index_names_and_package_works_tamper_guard(tmp_path: Path) -> None:
    assert run_sources(["source"]) == ()
    assert run_sources(["source", "control_evidence"]) == ("owasp_workbench",)
    assert "owasp_workbench" in available_sources(["control_evidence"], ["sink_site", "entry_point"])

    assert review_index_names(
        [
            {"name": "source"},
            {"name": "binary", "producer": {"binary_id": ""}},
        ]
    ) == ("source",)
    assert review_index_names(
        [
            {"name": "source"},
            {"name": "binary", "producer": {"binary_id": "bin-1"}},
        ]
    ) == ("binary", "source")

    run_root = tmp_path / "run"
    pkg_path = run_root / "pkg.json"
    atomic_json(pkg_path, {"schema": "appsec-review/review-package/7", "package_id": "pkg-1", "lead_menu": []})
    good_doc = {
        "packages": [
            {
                "package_id": "pkg-1",
                "lane": "lead",
                "sha256": file_sha256(pkg_path),
                "unit_key": "u1",
                "rank": [1, "pkg-1"],
                "basis": "b1",
                "entities": ["e1"],
                "path": "pkg.json",
            }
        ]
    }
    works = package_works(run_root, good_doc)
    assert len(works) == 1 and works[0].package_id == "pkg-1"

    bad_doc = {
        "packages": [
            {
                "package_id": "pkg-1",
                "lane": "lead",
                "sha256": "f" * 64,
                "unit_key": "u1",
                "rank": [1, "pkg-1"],
                "basis": "b1",
                "entities": ["e1"],
                "path": "pkg.json",
            }
        ]
    }
    with pytest.raises(IntegrityError, match="review package changed after assembly"):
        package_works(run_root, bad_doc)
