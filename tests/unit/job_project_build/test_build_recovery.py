from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from appsec_review.jobs.job_project_build.repair import (
    FailureKind, REPAIR_SCHEMA, RepairStopped, apply_repair, diagnose_failure,
    proposal_identity, validate_repair_proposal,
)


@pytest.mark.parametrize("evidence,kind", [
    ({"image_evidence": ("pinned image inventory lacks accepted system library",)}, FailureKind.IMAGE_ENVIRONMENT),
    ({"prerequisite_gaps": ("accepted producer A not yet built",)}, FailureKind.MISSING_PREREQUISITE),
    ({"source_context_gaps": ("../include/a.h omitted from old unit clone",)}, FailureKind.SOURCE_CONTEXT),
    ({"capability_gaps": ("unavailable_native_windows_toolchain",)}, FailureKind.UNSUPPORTED_CAPABILITY),
    ({"capture_gaps": ("ptrace collector failed",)}, FailureKind.CAPTURE),
    ({"stderr": "unknown target install-headers"}, FailureKind.COMMAND_RECIPE),
    ({"stderr": "undefined reference to A"}, FailureKind.COMPILER_LINKER),
    ({"stderr": "fatal error: ../shared/a.h: No such file or directory"}, FailureKind.COMPILER_LINKER),
    ({"stderr": "pkg-config: package A not found"}, FailureKind.UNKNOWN),
    ({"timed_out": True}, FailureKind.UNKNOWN),
])
def test_failure_diagnosis_does_not_guess_apt_from_missing_relative_inputs(evidence, kind):
    diagnosis = diagnose_failure(exit_code=2, **evidence)
    assert diagnosis.kind == kind
    assert diagnosis.image_repairable == (kind == FailureKind.IMAGE_ENVIRONMENT)
    assert diagnosis.view()["image_repairable"] == diagnosis.image_repairable


def test_source_and_capture_evidence_override_speculative_image_hypothesis():
    diagnosis = diagnose_failure(
        exit_code=2, image_evidence=("tool may be missing",),
        source_context_gaps=("required sibling tree was not copied",),
    )
    assert diagnosis.kind == FailureKind.SOURCE_CONTEXT
    assert not diagnosis.image_repairable
    diagnosis = diagnose_failure(exit_code=0, capture_gaps=("capture record missing",))
    assert diagnosis.kind == FailureKind.CAPTURE


def _proposal(**fields):
    return {"schema": REPAIR_SCHEMA, "system_packages": [], "environment": {},
            "package_manager": None, "dependency_restores": [], "reason": "accepted image evidence",
            **fields}


def _recipe():
    return {"image_profile": "native", "system_packages": [], "environment": {},
            "dependency_files": [], "reason": "accepted build"}


def test_non_image_outcome_is_typed_terminal_not_an_exception_retry():
    refusal = {"schema": REPAIR_SCHEMA, "outcome": "NOT_IMAGE_REPAIRABLE",
               "reason": "restore the complete committed sibling layout; image cause unproven"}
    assert validate_repair_proposal(refusal, recipe=_recipe(), build_system="cmake") == ()
    with pytest.raises(RepairStopped) as stopped:
        apply_repair(_recipe(), refusal, build_system="cmake")
    assert stopped.value.reason_code == "not_image_repairable"
    assert validate_repair_proposal({**refusal, "system_packages": []},
                                    recipe=_recipe(), build_system="cmake")


def test_normalized_no_op_has_terminal_reason_and_duplicate_identity_ignores_explanation():
    with pytest.raises(RepairStopped) as stopped:
        apply_repair(_recipe(), _proposal(), build_system="cmake")
    assert stopped.value.reason_code == "normalized_no_op"
    first = _proposal(system_packages=["zlib1g-dev", "libssl-dev"])
    second = _proposal(system_packages=["libssl-dev", "zlib1g-dev"], reason="different wording",
                       outcome="IMAGE_REPAIR")
    assert proposal_identity(first) == proposal_identity(second)
    assert proposal_identity(first) != proposal_identity(_proposal(system_packages=["libssl-dev"]))


@pytest.mark.parametrize("proposal", [
    _proposal(system_packages=["libssl-dev"], outcome="IMAGE_REPAIR"),
    _proposal(schema="appsec-review/build-image-repair/2"),
    {"schema": REPAIR_SCHEMA, "outcome": "NOT_IMAGE_REPAIRABLE", "reason": "missing prerequisite"},
])
def test_repair_schema_preserves_bounded_compatibility_and_explicit_refusal(proposal):
    schema = json.loads((Path(__file__).resolve().parents[3] / "docs/schemas/build-image-repair.schema.json").read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(proposal, schema)
    assert not validate_repair_proposal(proposal, recipe=_recipe(), build_system="cmake")


@pytest.mark.parametrize("proposal", [
    _proposal(system_packages=["curl;evil"]),
    _proposal(environment={"HTTP_PROXY": "https://foreign.invalid"}),
    _proposal(package_manager="download-this"),
    _proposal(dependency_restores=[{"manifest": "../unaccepted"}]),
    _proposal(outcome="RUN_HOST_COMMAND"),
    {**_proposal(), "Dockerfile": "FROM remote"},
])
def test_image_recovery_does_not_expand_closed_allowlists(proposal):
    assert validate_repair_proposal(proposal, recipe=_recipe(), build_system="cmake")
