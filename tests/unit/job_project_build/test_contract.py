"""job_project_build: the declared inputs and outputs are the job's contract.

Every file the job reads comes from an upstream handoff named in ``CONTRACT.inputs``; every file it
writes is claimed by a ``DATASETS`` declaration. These tests pin both, and check that the one
document the job hands downstream lands inside its own declared artifact glob.
"""
from __future__ import annotations

from fnmatch import fnmatch
import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
import pytest

from appsec_review.jobs.job_project_build.datasets import CONSUMES, CONTRACT, DATASETS
from appsec_review.jobs.job_project_build.job import SCHEMA, build_job
from appsec_review.jobs.job_project_build.repair import REPAIR_SCHEMA, apply_repair
from appsec_review.runtime.contracts import (
    Availability, DispatchClass, EvidenceAuthority, InputChannel, MissingPolicy, TargetAccess,
)


def test_inputs_name_every_upstream_job_and_the_plan_handoff_is_the_one_hard_requirement() -> None:
    by_job: dict[str, set[str]] = {}
    for requirement in CONTRACT.inputs:
        by_job.setdefault(requirement.producer, set()).add(requirement.output_kind)
    assert by_job == {
        "job_build_environment_analysis": {"handoff", "build_environment"},
        "job_review_intake": {"handoff", "model_preflight", "binary_evidence", "review_intake"},
        "job_target_analysis_plan": {"handoff", "planning_feedback_cache", "analysis_plan", "analysis_plan_documents"},
        "job_target_catalog": {"handoff", "target_artifact_inputs", "source_files", "declaration_symbols",
                               "components", "target_documents", "build_units", "catalog_documents"},
    }
    required = [(item.producer, item.output_kind) for item in CONTRACT.inputs
                if item.availability is Availability.REQUIRED or item.missing is MissingPolicy.REJECT]
    assert required == [("job_target_analysis_plan", "handoff")]
    handoffs = {item.producer: item.schema for item in CONTRACT.inputs if item.output_kind == "handoff"}
    assert set(handoffs.values()) == {"appsec-review/job-handoff/2"}
    assert CONTRACT.consumes == tuple(sorted(by_job))
    assert CONTRACT.schedule_after == ("job_target_analysis_plan",)
    assert CONTRACT.dispatch is DispatchClass.REVIEW_GRAPH and CONTRACT.target_access is TargetAccess.CHECKOUT
    assert CONTRACT.always_execute is False and CONTRACT.propagate_handoff is True


def test_outputs_are_declared_per_step_with_their_schema_and_disposition() -> None:
    declared = {item.output_kind: item for item in DATASETS}
    assert set(declared) == {"topology_refinement_inputs", "project_build_dispatch", "probe_workspaces",
                             "image_build_streams"}
    assert declared["project_build_dispatch"].step == "acceptance"
    assert declared["project_build_dispatch"].schema == SCHEMA
    assert declared["project_build_dispatch"].sensitivity == "sensitive"
    assert declared["topology_refinement_inputs"].step == "plan"
    assert declared["probe_workspaces"].step == "probe" and declared["image_build_streams"].step == "image"
    steps = {unit.unit_id.split(".")[0] for unit in build_job().units}
    assert {item.step for item in DATASETS} <= steps
    assert all(item.family == "build" for item in DATASETS)
    assert all(item.artifacts for item in DATASETS), "every output kind claims run-owned files"


def test_the_published_dispatch_document_lands_inside_its_declared_artifact_glob() -> None:
    dispatch = next(item for item in DATASETS if item.output_kind == "project_build_dispatch")
    published = "data/jobs/job_project_build/attempts/attempt_0001/artifacts/project-build/accepted-project-build-dispatch.json"
    assert any(fnmatch(published, pattern) for pattern in dispatch.artifacts), dispatch.artifacts
    elsewhere = "data/jobs/job_language_build/attempts/attempt_0001/artifacts/project-build/x.json"
    assert not any(fnmatch(elsewhere, pattern) for pattern in dispatch.artifacts)
    probes = next(item for item in DATASETS if item.output_kind == "probe_workspaces")
    assert any(fnmatch("data/build/probes/build-unit-x/attempts/attempt_0001/probe-001/workspace/a.o", pattern)
               for pattern in probes.artifacts)


def test_the_job_carries_the_contract_and_declarations_it_was_built_from() -> None:
    job = build_job()
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert job.consumes == CONTRACT.consumes == CONSUMES


def test_every_input_requirement_and_dataset_field_is_pinned() -> None:
    for item in CONTRACT.inputs:
        expected_authority = (
            EvidenceAuthority.OPERATIONAL
            if item.producer == "job_build_environment_analysis"
            else EvidenceAuthority.PRODUCER_EVIDENCE
        )
        assert item.authority is expected_authority
        if (item.producer, item.output_kind) == ("job_target_analysis_plan", "handoff"):
            assert item.availability is Availability.REQUIRED
            assert item.missing is MissingPolicy.REJECT
            assert item.channel is InputChannel.HANDOFF
        else:
            assert item.availability is Availability.OPTIONAL
            assert item.missing is MissingPolicy.GAP
            assert item.channel is InputChannel.HANDOFF
    declared = {item.output_kind: item for item in DATASETS}
    assert declared["topology_refinement_inputs"].disposition == "protected"
    assert declared["project_build_dispatch"].disposition == "artifact_only"
    assert declared["probe_workspaces"].disposition == "protected"
    assert declared["image_build_streams"].disposition == "protected"
    assert all(item.reason for item in DATASETS)


@pytest.mark.parametrize("boundary", ["runtime", "json-schema"])
def test_repair_contract_rejects_legacy_schema(boundary: str) -> None:
    """The job-pass contract admits the current schema only, not a compatible older version."""
    recipe = {"image_profile": "native", "system_packages": [], "environment": {},
              "dependency_files": [], "reason": "accepted fixture recipe"}
    proposal = {"schema": REPAIR_SCHEMA, "system_packages": ["libssl-dev"], "environment": {},
                "package_manager": None, "dependency_restores": [], "reason": "fixture repair"}
    legacy = {**proposal, "schema": "appsec-review/build-image-repair/2"}
    if boundary == "runtime":
        repaired = apply_repair(recipe, proposal, build_system="cmake")
        assert repaired["system_packages"] == ["libssl-dev"]
        assert recipe["system_packages"] == []
        with pytest.raises(ValueError, match="repair proposal schema is unsupported"):
            apply_repair(recipe, legacy, build_system="cmake")
    else:
        path = Path(__file__).resolve().parents[3] / "docs/schemas/build-image-repair.schema.json"
        schema = json.loads(path.read_bytes())
        assert schema["$id"] == REPAIR_SCHEMA == "appsec-review/build-image-repair/3"
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(proposal)
        with pytest.raises(ValidationError):
            validator.validate(legacy)
