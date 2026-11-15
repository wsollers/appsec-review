"""Contract, registry, topology, and configuration tests for job_cpg_analysis."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.input_matrix import INPUT_SOURCES
import appsec_review.jobs.job_cpg_analysis as cpg_pkg
from appsec_review.jobs.job_cpg_analysis import JOB_ID, JOERN_DISABLED, JOERN_GAP, build_job
from appsec_review.jobs.job_cpg_analysis.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_cpg_analysis.job import SCHEMA, _validate
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


def test_package_exports_and_registry_topology_parity() -> None:
    assert set(cpg_pkg.__all__) == {"JOB_ID", "JOERN_DISABLED", "JOERN_GAP", "build_job"}
    assert JOB_ID == "job_cpg_analysis"
    assert JOERN_GAP.startswith("BLOCKED:")
    assert JOERN_DISABLED.startswith("DISABLED:")

    config = load_config(REPO_ROOT / "appsec-review.toml")
    registry = builtin_registry()
    registry.require_matches(config.jobs, surface="central configuration")
    job = registry.build(JOB_ID)
    assert job.job_id == JOB_ID
    assert job.name == "cpg_analysis"
    assert job.schema_identity == SCHEMA
    assert job.implementation_identity is None
    assert [u.unit_id for u in job.units] == [
        "load.accepted_cpp",
        "generate.scopes",
        "acceptance.publish_handoff",
    ]
    assert job.units[0].dependencies == ()
    assert job.units[1].dependencies == ("load.accepted_cpp",)
    assert job.units[2].dependencies == ("load.accepted_cpp", "generate.scopes")

    job_cfg = config.job(JOB_ID)
    assert job_cfg.settings["enabled"] is False
    assert job_cfg.settings["workers"] == 1
    assert job_cfg.settings["max_cpg_bytes"] == 2147483648
    assert job_cfg.settings["seeded"]["unit_limit"] == 64
    assert job_cfg.settings["seeded"]["include_scan_files"] == 4000
    default_wave = describe_wave1(config, registry)
    assert JOB_ID not in {entry["job_id"] for entry in default_wave["jobs"]}
    enabled_wave = describe_wave1(config, registry, include=(JOB_ID,))
    wave1 = {entry["job_id"]: entry for entry in enabled_wave["jobs"]}
    assert JOB_ID in wave1
    assert wave1[JOB_ID]["dependencies"] == ["job_cpp_compiled_analysis"]
    assert set(wave1[JOB_ID]["upstream_handoffs"]) == {
        "job_cpp_compiled_analysis",
        "job_target_catalog",
        "job_evidence_collection",
    }
    order = [entry["job_id"] for entry in enabled_wave["jobs"]]
    assert order.index(JOB_ID) < order.index("job_review_data_indexing")

    matrix_by_name = {row[0]: row for row in INPUT_SOURCES}
    assert matrix_by_name["joern_cpg"] == (
        "joern_cpg",
        ("job_cpg_analysis",),
        "artifact_only",
        (),
        ("coverage",),
    )


def test_contract_and_dataset_declarations() -> None:
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False
    assert CONTRACT.propagate_handoff is True
    assert CONTRACT.schedule_after == ("job_cpp_compiled_analysis",)
    assert len(CONTRACT.inputs) == 21
    assert CONSUMES == CONTRACT.consumes == (
        "job_cpp_compiled_analysis",
        "job_evidence_collection",
        "job_target_catalog",
    )

    first = CONTRACT.inputs[0]
    assert (first.producer, first.output_kind, first.schema) == (
        "job_cpp_compiled_analysis",
        "handoff",
        "appsec-review/job-handoff/2",
    )
    assert first.authority is EvidenceAuthority.PRODUCER_EVIDENCE
    assert first.availability is Availability.REQUIRED
    assert first.missing is MissingPolicy.REJECT
    assert all(inp.authority is EvidenceAuthority.PRODUCER_EVIDENCE for inp in CONTRACT.inputs)

    assert [d.output_kind for d in DATASETS] == [
        "cpg_graph_coverage",
        "cpg_scope_coverage",
        "cpg_summary",
        "cpg_binary",
    ]
    by_id = {d.output_kind: d for d in DATASETS}
    assert by_id["cpg_graph_coverage"].disposition == "indexed"
    assert by_id["cpg_scope_coverage"].disposition == "indexed"
    assert by_id["cpg_summary"].disposition == "artifact_only"
    assert by_id["cpg_binary"].disposition == "protected"


def test_input_validator_enforces_step_and_task_configuration() -> None:
    config = load_config(REPO_ROOT / "appsec-review.toml")
    _validate(SimpleNamespace(config=config.job(JOB_ID)), None)

    bad_steps = SimpleNamespace(config=SimpleNamespace(steps=("load", "acceptance")))
    with pytest.raises(ValueError, match="CPG-analysis topology does not match central configuration"):
        _validate(bad_steps, None)

    def _step_mismatch(step_name: str):
        if step_name == "generate":
            return SimpleNamespace(tasks=("wrong_task",))
        return config.job(JOB_ID).step(step_name)

    bad_tasks = SimpleNamespace(
        config=SimpleNamespace(
            steps=("load", "generate", "acceptance"),
            step=_step_mismatch,
        )
    )
    with pytest.raises(ValueError, match="CPG-analysis task configuration mismatch: generate"):
        _validate(bad_tasks, None)
