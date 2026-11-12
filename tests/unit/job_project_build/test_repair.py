"""job_project_build.repair: failure diagnosis, proposal identity, the closed repair vocabulary
offered to the model, recorded-repair validation and the terminal repair dispositions."""
from __future__ import annotations

import pytest

from appsec_review.jobs.job_project_build.repair import (
    MAX_DEPENDENCY_RESTORES, MAX_REPAIR_ENVIRONMENT, MAX_SYSTEM_PACKAGES, REPAIR_SCHEMA, FailureKind,
    RepairStopped, apply_repair, diagnose_failure, image_repair_errors, proposal_identity, repair_options,
)
from tests.unit.job_project_build.test_project_build_helpers import _repair, _repair_recipe


# --- diagnose_failure -------------------------------------------------------------------------------

def test_explicit_evidence_classes_take_precedence_in_a_fixed_order() -> None:
    diagnosis = diagnose_failure(exit_code=1, stderr="fatal error: x.h: No such file",
                                 image_evidence=["apt: libx missing"], capability_gaps=["no ptrace"],
                                 prerequisite_gaps=["producer absent"], source_context_gaps=["no src"],
                                 capture_gaps=["capture short"])
    assert diagnosis.kind is FailureKind.UNSUPPORTED_CAPABILITY and diagnosis.evidence == ("no ptrace",)
    assert diagnose_failure(exit_code=1, prerequisite_gaps=["p"], source_context_gaps=["s"],
                            image_evidence=["i"]).kind is FailureKind.MISSING_PREREQUISITE
    assert diagnose_failure(exit_code=1, source_context_gaps=["s"], capture_gaps=["c"],
                            image_evidence=["i"]).kind is FailureKind.SOURCE_CONTEXT
    assert diagnose_failure(exit_code=1, capture_gaps=["c"], image_evidence=["i"]).kind is FailureKind.CAPTURE
    image = diagnose_failure(exit_code=1, image_evidence=["apt: libx missing"], gaps=["ignored"])
    assert image.kind is FailureKind.IMAGE_ENVIRONMENT and image.image_repairable is True
    assert image.view() == {"kind": "IMAGE_ENVIRONMENT",
                            "reason": "accepted evidence identifies an image/environment gap",
                            "evidence": ["apt: libx missing"], "image_repairable": True}


@pytest.mark.parametrize(("stderr", "timed_out", "kind", "reason"), [
    ("", True, FailureKind.UNKNOWN, "bounded command timed out; cause is unproven"),
    ("clang: error: unknown argument: '-fno-such'", False, FailureKind.COMMAND_RECIPE,
     "command or build target was rejected"),
    ("make: *** No rule to make target 'all'.  Stop.", False, FailureKind.COMMAND_RECIPE,
     "command or build target was rejected"),
    ("main.cpp:3:10: fatal error: missing.h: No such file or directory", False, FailureKind.COMPILER_LINKER,
     "compiler/linker failed; an image repair is not established"),
    ("/usr/bin/ld: cannot find -lssl", False, FailureKind.COMPILER_LINKER,
     "compiler/linker failed; an image repair is not established"),
    ("undefined reference to `foo'", False, FailureKind.COMPILER_LINKER,
     "compiler/linker failed; an image repair is not established"),
    ("something else entirely", False, FailureKind.UNKNOWN, "failure cause is unproven (exit_code=2)"),
], ids=["timeout", "unknown-argument", "no-rule", "fatal-error", "missing-lib", "undefined-ref", "unknown"])
def test_stderr_classification_never_proposes_an_image_repair(stderr, timed_out, kind, reason) -> None:
    diagnosis = diagnose_failure(exit_code=2, timed_out=timed_out, stderr=stderr, gaps=["g1", 7])
    assert diagnosis.kind is kind and diagnosis.reason == reason
    assert diagnosis.evidence == ("g1", "7") and diagnosis.image_repairable is False


def test_a_timeout_is_unknown_even_when_stderr_looks_like_a_recipe_error() -> None:
    assert diagnose_failure(exit_code=None, timed_out=True, stderr="unknown option").kind is FailureKind.UNKNOWN


# --- proposal_identity ------------------------------------------------------------------------------

def test_proposal_identity_ignores_explanation_and_schema_and_normalizes_set_like_fields() -> None:
    base = _repair(system_packages=["zlib1g-dev", "libssl-dev"],
                   dependency_restores=[{"manifest": "b/pom.xml"}, {"manifest": "a/pom.xml"}])
    same = {**base, "reason": "different words", "schema": "appsec-review/build-image-repair/2",
            "system_packages": ["libssl-dev", "zlib1g-dev"],
            "dependency_restores": [{"manifest": "a/pom.xml"}, {"manifest": "b/pom.xml"}]}
    assert proposal_identity(base) == proposal_identity(same)
    assert proposal_identity(base) != proposal_identity({**base, "system_packages": ["libssl-dev"]})
    assert proposal_identity(base) != proposal_identity({**base, "outcome": "NOT_IMAGE_REPAIRABLE"})
    assert proposal_identity(base) == proposal_identity({**base, "outcome": "IMAGE_REPAIR"})


# --- repair_options ---------------------------------------------------------------------------------

def test_repair_options_offer_only_the_family_vocabulary_and_restorable_manifests() -> None:
    recipe = _repair_recipe("python", "pkg", ["pkg/pyproject.toml", "pkg/requirements-build.txt"],
                            build_system="python", commands=[["python", "-m", "build"]])
    options = repair_options(recipe, "python")
    assert "PIP_BREAK_SYSTEM_PACKAGES" in options["environment_names"]
    assert options["environment_names"] == sorted(options["environment_names"])
    assert "NPM_CONFIG_LEGACY_PEER_DEPS" not in options["environment_names"]
    assert options["restorable_manifests"] == ["pkg/requirements-build.txt"]
    assert options["limits"] == {"system_packages": MAX_SYSTEM_PACKAGES, "environment": MAX_REPAIR_ENVIRONMENT,
                                 "dependency_restores": MAX_DEPENDENCY_RESTORES}
    node = _repair_recipe("node", "web", ["web/package.json"], build_system="node", commands=[["tsc"]])
    assert set(repair_options(node, "node")["package_managers"]) >= {"npm", "pnpm", "yarn"}
    assert repair_options(recipe, "python")["package_managers"] == {}
    unknown = repair_options(_repair_recipe("other", "x", [], build_system="other", commands=[]), "other")
    assert unknown["environment_names"] == [] and unknown["restorable_manifests"] == []


# --- image_repair_errors ----------------------------------------------------------------------------

def test_a_recorded_repair_validates_only_when_applied_and_normalized() -> None:
    recipe = _repair_recipe("python", "pkg", ["pkg/pyproject.toml", "pkg/requirements-build.txt"],
                            build_system="python", commands=[["python", "-m", "build"]])
    repaired = apply_repair(recipe, _repair(environment={"PIP_BREAK_SYSTEM_PACKAGES": "1"},
                                            dependency_restores=[{"manifest": "pkg/requirements-build.txt"}]),
                            build_system="python")
    assert image_repair_errors(repaired, "python") == []
    assert image_repair_errors(recipe, "python") == ["image_repairs fields are invalid"]
    partial = {**repaired, "image_repairs": {"environment": {}}}
    assert image_repair_errors(partial, "python") == ["image_repairs fields are invalid"]
    unapplied = {**repaired, "environment": {}}
    assert "image_repairs environment is not applied to the recipe environment" in image_repair_errors(unapplied, "python")
    denormalized = {**repaired, "image_repairs": {**repaired["image_repairs"], "dependency_restores": [
        {"manager": "npm", "manifest": "pkg/requirements-build.txt"}]}}
    assert image_repair_errors(denormalized, "python") == ["image_repairs dependency_restores are not normalized"]
    foreign = {**repaired, "image_repairs": {**repaired["image_repairs"], "dependency_restores": [
        {"manager": "pip", "manifest": "pkg/pyproject.toml"}]}}
    assert any(error.startswith("image_repairs: ") for error in image_repair_errors(foreign, "python"))


# --- terminal dispositions --------------------------------------------------------------------------

def test_not_image_repairable_and_no_op_proposals_stop_the_repair_loop_with_typed_reasons() -> None:
    recipe = _repair_recipe("native", "lib", ["lib/CMakeLists.txt"], build_system="cmake",
                            commands=[["cmake", "--build", "lib/build"]])
    refusal = {"schema": REPAIR_SCHEMA, "outcome": "NOT_IMAGE_REPAIRABLE", "reason": "the recipe is wrong"}
    with pytest.raises(RepairStopped) as stopped:
        apply_repair(recipe, refusal, build_system="cmake")
    assert stopped.value.reason_code == "not_image_repairable" and str(stopped.value) == "the recipe is wrong"
    with pytest.raises(RepairStopped) as stopped:
        apply_repair(recipe, _repair(), build_system="cmake")
    assert stopped.value.reason_code == "normalized_no_op"
    assert _repair()["schema"] == REPAIR_SCHEMA
    repaired = apply_repair(recipe, _repair(system_packages=["libssl-dev"]), build_system="cmake")
    assert repaired["reason"].endswith("Image repair: bounded repair") and "image_repairs" not in repaired
    with pytest.raises(RepairStopped):
        apply_repair(repaired, _repair(system_packages=["libssl-dev"]), build_system="cmake")
