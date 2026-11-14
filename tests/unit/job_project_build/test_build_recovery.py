from __future__ import annotations

from copy import deepcopy
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


def _schema_validator():
    path = Path(__file__).resolve().parents[3] / "docs/schemas/build-image-repair.schema.json"
    schema = json.loads(path.read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_non_image_outcome_is_typed_terminal_not_an_exception_retry():
    refusal = {"schema": REPAIR_SCHEMA, "outcome": "NOT_IMAGE_REPAIRABLE",
               "reason": "restore the complete committed sibling layout; image cause unproven"}
    recipe = _recipe()
    original = deepcopy((recipe, refusal))
    validator = _schema_validator()
    validator.validate(refusal)
    assert validate_repair_proposal(refusal, recipe=recipe, build_system="cmake") == ()
    with pytest.raises(RepairStopped) as stopped:
        apply_repair(recipe, refusal, build_system="cmake")
    assert stopped.value.reason_code == "not_image_repairable"
    assert str(stopped.value) == refusal["reason"]
    for field in ("system_packages", "environment", "package_manager", "dependency_restores"):
        invalid = {**refusal, field: _proposal()[field]}
        invalid_original = deepcopy(invalid)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(invalid)
        assert validate_repair_proposal(invalid, recipe=recipe, build_system="cmake") == (
            "repair proposal fields are invalid",)
        with pytest.raises(ValueError, match="repair proposal fields are invalid") as rejected:
            apply_repair(recipe, invalid, build_system="cmake")
        assert type(rejected.value) is ValueError
        assert invalid == invalid_original
    assert (recipe, refusal) == original


def test_normalized_no_op_has_terminal_reason_and_duplicate_identity_ignores_explanation():
    recipe, proposal = _recipe(), _proposal()
    original = deepcopy((recipe, proposal))
    _schema_validator().validate(proposal)
    assert validate_repair_proposal(proposal, recipe=recipe, build_system="cmake") == ()
    with pytest.raises(RepairStopped) as stopped:
        apply_repair(recipe, proposal, build_system="cmake")
    assert stopped.value.reason_code == "normalized_no_op"
    assert (recipe, proposal) == original
    first = _proposal(system_packages=["zlib1g-dev", "libssl-dev"])
    second = _proposal(system_packages=["libssl-dev", "zlib1g-dev"], reason="different wording",
                       outcome="IMAGE_REPAIR")
    assert proposal_identity(first) == proposal_identity(second)
    assert proposal_identity(first) != proposal_identity(_proposal(system_packages=["libssl-dev"]))


@pytest.mark.parametrize("proposal", [
    _proposal(system_packages=["libssl-dev"]),
    _proposal(system_packages=["libssl-dev"], outcome="IMAGE_REPAIR"),
    {"schema": REPAIR_SCHEMA, "outcome": "NOT_IMAGE_REPAIRABLE", "reason": "missing prerequisite"},
], ids=["implicit-image", "explicit-image", "refusal"])
def test_current_repair_schema_preserves_accepted_forms(proposal):
    recipe = _recipe()
    original = deepcopy((recipe, proposal))
    _schema_validator().validate(proposal)
    assert validate_repair_proposal(proposal, recipe=recipe, build_system="cmake") == ()
    if proposal.get("outcome") == "NOT_IMAGE_REPAIRABLE":
        with pytest.raises(RepairStopped) as stopped:
            apply_repair(recipe, proposal, build_system="cmake")
        assert stopped.value.reason_code == "not_image_repairable"
        assert str(stopped.value) == proposal["reason"]
    else:
        repaired = apply_repair(recipe, proposal, build_system="cmake")
        assert repaired == {**recipe, "system_packages": ["libssl-dev"],
                            "reason": f"{recipe['reason']} Image repair: {proposal['reason']}"}
        assert repaired is not recipe
    assert (recipe, proposal) == original


@pytest.mark.parametrize("boundary", ["runtime", "json-schema"])
@pytest.mark.parametrize("shape", ["image", "refusal"])
@pytest.mark.parametrize("schema_field", [
    pytest.param({"schema": "appsec-review/build-image-repair/2"}, id="legacy"),
    pytest.param({"schema": "appsec-review/build-image-repair/999"}, id="unknown"),
    pytest.param({}, id="missing"),
    pytest.param({"schema": None}, id="null"),
    pytest.param({"schema": 3}, id="integer"),
    pytest.param({"schema": True}, id="boolean"),
    pytest.param({"schema": []}, id="array"),
    pytest.param({"schema": {}}, id="object"),
    pytest.param({"schema": ""}, id="empty"),
    pytest.param({"schema": REPAIR_SCHEMA + " "}, id="whitespace"),
])
def test_unsupported_repair_versions_are_rejected_before_application(boundary, shape, schema_field):
    recipe = _recipe()
    proposal = (_proposal(system_packages=["libssl-dev"]) if shape == "image" else
                {"schema": REPAIR_SCHEMA, "outcome": "NOT_IMAGE_REPAIRABLE",
                 "reason": "missing prerequisite"})
    del proposal["schema"]
    proposal.update(deepcopy(schema_field))
    original = deepcopy((recipe, proposal))
    if boundary == "json-schema":
        with pytest.raises(jsonschema.ValidationError):
            _schema_validator().validate(proposal)
    else:
        message = ("repair proposal fields are invalid" if "schema" not in proposal else
                   "repair proposal schema is unsupported")
        errors = validate_repair_proposal(proposal, recipe=recipe, build_system="cmake")
        with pytest.raises(ValueError, match=message) as rejected:
            apply_repair(recipe, proposal, build_system="cmake")
        assert type(rejected.value) is ValueError
        assert errors == (message,)
    assert (recipe, proposal) == original


@pytest.mark.parametrize("proposal", [
    _proposal(system_packages=["curl;evil"]),
    _proposal(environment={"HTTP_PROXY": "https://foreign.invalid"}),
    _proposal(package_manager="download-this"),
    _proposal(dependency_restores=[{"manifest": "../unaccepted"}]),
    _proposal(outcome="RUN_HOST_COMMAND"),
    {**_proposal(), "Dockerfile": "FROM remote"},
])
def test_image_recovery_does_not_expand_closed_allowlists(proposal):
    recipe = _recipe()
    original = deepcopy((recipe, proposal))
    assert validate_repair_proposal(proposal, recipe=recipe, build_system="cmake")
    with pytest.raises(ValueError) as rejected:
        apply_repair(recipe, proposal, build_system="cmake")
    assert type(rejected.value) is ValueError
    assert (recipe, proposal) == original
