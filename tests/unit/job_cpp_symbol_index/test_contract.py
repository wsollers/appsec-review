"""Contract, configuration, topology, and dataset tests for job_cpp_symbol_index."""

from __future__ import annotations

from pathlib import Path
from dataclasses import replace
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_cpp_symbol_index import JOB_ID, build_job
from appsec_review.jobs.job_cpp_symbol_index.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_cpp_symbol_index.job import SCHEMA, _validate
from appsec_review.orchestration.topology import describe_wave1
from appsec_review.runtime.contracts import (
    Availability,
    DispatchClass,
    EvidenceAuthority,
    MissingPolicy,
    TargetAccess,
)
from appsec_review.runtime.registry import builtin_registry


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_registry_and_central_config_parity() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    registry = builtin_registry()
    job = registry.build(JOB_ID)
    assert job.job_id == JOB_ID == "job_cpp_symbol_index"
    assert job.name == "cpp_symbol_index"
    assert job.schema_identity == SCHEMA == "appsec-review/cpp-symbol-index/1"
    assert tuple(u.unit_id for u in job.units) == (
        "load.accepted_cpp",
        "index.scopes",
        "acceptance.publish_handoff",
    )
    assert job.units[1].dependencies == ("load.accepted_cpp",)
    assert job.units[2].dependencies == ("load.accepted_cpp", "index.scopes")

    job_cfg = config.job(JOB_ID)
    assert tuple(job_cfg.steps) == ("load", "index", "acceptance")
    assert tuple(job_cfg.step("load").tasks) == ("accepted_cpp",)
    assert tuple(job_cfg.step("index").tasks) == ("scopes",)
    assert tuple(job_cfg.step("acceptance").tasks) == ("publish_handoff",)
    _validate(SimpleNamespace(config=job_cfg), {})


def test_validate_rejects_mismatched_steps_and_tasks() -> None:
    bad_steps = SimpleNamespace(steps=("load", "acceptance"))
    with pytest.raises(ValueError, match="topology does not match central configuration"):
        _validate(SimpleNamespace(config=bad_steps), {})

    for bad_step, bad_tasks in (
        ("load", ("wrong",)),
        ("index", ("wrong",)),
        ("acceptance", ("wrong",)),
    ):
        step_map = {
            "load": SimpleNamespace(tasks=("accepted_cpp",)),
            "index": SimpleNamespace(tasks=("scopes",)),
            "acceptance": SimpleNamespace(tasks=("publish_handoff",)),
            bad_step: SimpleNamespace(tasks=bad_tasks),
        }
        cfg = SimpleNamespace(steps=("load", "index", "acceptance"), step=step_map.__getitem__)
        with pytest.raises(ValueError, match=f"task configuration mismatch: {bad_step}"):
            _validate(SimpleNamespace(config=cfg), {})


def test_contract_inputs_and_datasets_are_complete() -> None:
    job = build_job()
    assert job.contract is CONTRACT
    assert job.datasets == DATASETS
    assert CONSUMES == CONTRACT.consumes == (
        "job_cpp_compiled_analysis",
        "job_evidence_collection",
        "job_target_catalog",
    )
    assert CONTRACT.schedule_after == ("job_cpp_compiled_analysis",)
    assert CONTRACT.dispatch == DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access == TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True

    cpp_handoff = next(
        req
        for req in CONTRACT.inputs
        if req.producer == "job_cpp_compiled_analysis" and req.output_kind == "handoff"
    )
    assert cpp_handoff.authority == EvidenceAuthority.PRODUCER_EVIDENCE
    assert cpp_handoff.availability == Availability.REQUIRED
    assert cpp_handoff.missing == MissingPolicy.REJECT

    by_kind = {item.output_kind: item for item in DATASETS}
    assert set(by_kind) == {"clangd_symbols", "clangd_coverage", "clangd_summary", "clangd_tool_io"}
    assert by_kind["clangd_symbols"].disposition == "indexed"
    assert by_kind["clangd_symbols"].indexes == ("analysis",)
    assert by_kind["clangd_symbols"].shard_prefixes == ("clangd-",)
    assert by_kind["clangd_coverage"].disposition == "indexed"
    assert by_kind["clangd_coverage"].shard_prefixes == ("clangd-coverage-",)
    assert by_kind["clangd_summary"].disposition == "artifact_only"
    assert by_kind["clangd_tool_io"].disposition == "protected"


def test_shared_topology_places_symbol_index_between_cpp_build_and_code_graph() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    wave = describe_wave1(config, builtin_registry())
    by_id = {entry["job_id"]: entry for entry in wave["jobs"]}
    entry = by_id[JOB_ID]
    assert "job_cpp_compiled_analysis" in entry["dependencies"]
    assert JOB_ID in by_id["job_codeql_analysis"]["dependencies"]
    assert JOB_ID in by_id["job_code_graph_index"]["upstream_handoffs"]


@pytest.mark.parametrize("name", (
    "workers", "max_documents_per_scope", "max_symbols_per_scope",
    "max_relations_per_scope", "locations_per_relation",
))
@pytest.mark.parametrize("value", (0, -1, True, 1.5, "2", None))
def test_invalid_index_settings_fail_before_job_execution(name: str, value: object) -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml").job(JOB_ID)
    config = replace(config, settings={**config.settings, name: value})
    validator = build_job().input_validators[0]
    with pytest.raises(ValueError, match=name + ".*positive integer"):
        validator(SimpleNamespace(config=config), {})


@pytest.mark.parametrize("value", (1, 10**10))
def test_positive_index_settings_have_no_undeclared_upper_cap(value: int) -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml").job(JOB_ID)
    settings = {**config.settings, **{name: value for name in (
        "workers", "max_documents_per_scope", "max_symbols_per_scope",
        "max_relations_per_scope", "locations_per_relation",
    )}}
    _validate(SimpleNamespace(config=replace(config, settings=settings)), {})


def test_unknown_index_setting_is_rejected_before_job_execution() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml").job(JOB_ID)
    config = replace(config, settings={**config.settings, "locations_per_relations": 8})
    with pytest.raises(ValueError, match="unknown.*locations_per_relations"):
        build_job().input_validators[0](SimpleNamespace(config=config), {})
