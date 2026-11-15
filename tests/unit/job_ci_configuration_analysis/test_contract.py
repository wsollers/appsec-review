"""Contract, configuration, topology, and input-validator unit tests for job_ci_configuration_analysis."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import appsec_review.jobs.job_ci_configuration_analysis as pkg
from appsec_review.jobs.job_ci_configuration_analysis.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_ci_configuration_analysis.job import (
    JOB_ID,
    PROVIDER_TOOLS,
    SPECS,
    TOPOLOGY,
    ToolSpec,
    analysis_bounds,
    build_job,
)
from appsec_review.runtime import plan_jobs
from appsec_review.runtime.contracts import (
    Availability,
    DispatchClass,
    EvidenceAuthority,
    MissingPolicy,
    TargetAccess,
)
from tests.unit.job_ci_configuration_analysis.support import (
    attempt_scope,
    isolated_config,
    make_unit_context,
)


def test_package_exports_and_job_contract_declarations() -> None:
    assert set(pkg.__all__) == {
        "PROVIDER_TOOLS",
        "TOPOLOGY",
        "build_job",
        "discover_ci_definitions",
    }
    assert {d.output_kind for d in DATASETS} == {
        "ci_observations",
        "ci_findings",
        "ci_documents",
        "ci_tool_io",
    }
    by_id = {d.output_kind: d for d in DATASETS}
    assert by_id["ci_observations"].disposition == "indexed"
    assert by_id["ci_findings"].disposition == "indexed"
    assert by_id["ci_documents"].disposition == "artifact_only"
    assert by_id["ci_tool_io"].disposition == "protected"

    assert CONTRACT.schedule_after == ("job_target_catalog",)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH
    assert CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.propagate_handoff is True
    assert CONSUMES == CONTRACT.consumes
    assert len(CONTRACT.inputs) == 8
    handoff_req = next(req for req in CONTRACT.inputs if req.output_kind == "handoff")
    assert handoff_req.producer == "job_target_catalog"
    assert handoff_req.availability is Availability.REQUIRED
    assert handoff_req.missing is MissingPolicy.REJECT
    assert handoff_req.authority is EvidenceAuthority.PRODUCER_EVIDENCE


def test_tool_spec_properties_and_dag_topology(tmp_path: Path) -> None:
    ext_fw = ToolSpec("github", "checkov", "tool-checkov", "external", "github_actions")
    ext_plain = ToolSpec("github", "zizmor", "tool-zizmor", "external")
    static_spec = ToolSpec("github", "schema", "ci-schema", "static")
    assert ext_fw.key == "github_checkov"
    assert ext_fw.input_support == "ci:tool-checkov:github_actions"
    assert ext_plain.input_support == "ci:tool-zizmor"
    assert static_spec.input_support is None

    job = build_job(executor_factory=lambda unit: None)
    assert job.job_id == JOB_ID
    assert job.contract == CONTRACT
    assert job.datasets == DATASETS
    assert job.strict_gaps is True
    assert set(PROVIDER_TOOLS) == {
        "github",
        "azure",
        "gitlab",
        "circleci",
        "bitbucket",
        "jenkins",
        "teamcity",
        "other",
    }

    plan = plan_jobs((job,))
    scans = [node for node in plan.nodes if node.unit_id.startswith("ci_analysis.")]
    assert len(scans) == len(SPECS)
    assert all(
        node.dependencies == ("job_ci_configuration_analysis.ci_discovery.classify_providers",)
        for node in scans
    )
    join = plan.node("job_ci_configuration_analysis.ci_coverage.join_coverage")
    assert "job_ci_configuration_analysis.ci_correlation.correlate_findings" in join.dependencies
    assert len([item for item in join.dependencies if ".ci_observation_publication." in item]) == len(SPECS)

    # Central appsec-review.toml topology matches TOPOLOGY step-for-step and task-for-task.
    cfg = isolated_config(tmp_path)
    job_cfg = cfg.job(JOB_ID)
    assert tuple(job_cfg.steps) == tuple(TOPOLOGY)
    for step_name, expected_tasks in TOPOLOGY.items():
        assert tuple(job_cfg.step(step_name).tasks) == expected_tasks


@pytest.mark.parametrize(
    ("overrides", "expected_msg"),
    [
        ({"max_files": 0}, "outside the supported range"),
        ({"max_files": 5001}, "outside the supported range"),
        ({"max_file_bytes": 0}, "outside the supported range"),
        ({"max_file_bytes": 16 * 1024 * 1024 + 1}, "outside the supported range"),
        ({"max_observations_per_tool": 0}, "observation bound is outside"),
        ({"max_observations_per_tool": 100001}, "observation bound is outside"),
    ],
)
def test_analysis_bounds_rejects_out_of_range_values(
    overrides: dict[str, int],
    expected_msg: str,
) -> None:
    base = {"max_files": 128, "max_file_bytes": 1_048_576, "max_observations_per_tool": 5_000}
    with pytest.raises(ValueError, match=expected_msg):
        analysis_bounds({**base, **overrides})


def test_analysis_bounds_accepts_defaults_and_boundary_extremes() -> None:
    assert analysis_bounds({}) == (128, 1_048_576, 5_000)
    assert analysis_bounds(
        {"max_files": 1, "max_file_bytes": 1, "max_observations_per_tool": 1}
    ) == (1, 1, 1)
    assert analysis_bounds(
        {"max_files": 5000, "max_file_bytes": 16 * 1024 * 1024, "max_observations_per_tool": 100000}
    ) == (5000, 16 * 1024 * 1024, 100000)


def test_input_validator_enforces_target_root_topology_bounds_and_catalog_fingerprint(
    tmp_path: Path,
) -> None:
    job = build_job(executor_factory=lambda u: None)
    validator = job.input_validators[0]

    # 1. Valid context passes cleanly.
    unit_ok, _, _ = make_unit_context(tmp_path / "ok")
    with attempt_scope(unit_ok):
        validator(unit_ok.job, None)

    # 2. Missing target_root raises ValueError.
    unit_no_target, _, _ = make_unit_context(tmp_path / "no_target")
    unit_no_target.job.target_root = None
    with pytest.raises(ValueError, match="requires a graph-provided target root"):
        validator(unit_no_target.job, None)

    # 3. Step order mismatch raises ValueError.
    unit_bad_steps, _, _ = make_unit_context(tmp_path / "bad_steps")
    unit_bad_steps.job.config.steps = {"ci_discovery": unit_bad_steps.job.config.steps["ci_discovery"]}
    with pytest.raises(ValueError, match="topology does not match"):
        validator(unit_bad_steps.job, None)

    # 4. Task order mismatch within a step raises ValueError.
    unit_bad_tasks, _, _ = make_unit_context(tmp_path / "bad_tasks")
    unit_bad_tasks.job.config.steps["ci_discovery"] = SimpleNamespace(tasks={"discover_definitions": None})
    with pytest.raises(ValueError, match="task order mismatch: ci_discovery"):
        validator(unit_bad_tasks.job, None)

    # 5. Out-of-range analysis bounds raise ValueError.
    unit_bad_bounds, _, _ = make_unit_context(tmp_path / "bad_bounds", settings_override={"max_files": 0})
    with pytest.raises(ValueError, match="outside the supported range"):
        validator(unit_bad_bounds.job, None)

    # 6. Catalog fingerprint mismatch raises ValueError.
    unit_fp_mismatch, _, _ = make_unit_context(
        tmp_path / "fp_mismatch",
        source_fingerprint="a" * 64,
        catalog_fingerprint="b" * 64,
    )
    with attempt_scope(unit_fp_mismatch):
        with pytest.raises(ValueError, match="fingerprint does not match"):
            validator(unit_fp_mismatch.job, None)
