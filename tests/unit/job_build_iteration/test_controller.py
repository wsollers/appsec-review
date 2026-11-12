"""job_build_iteration: the controller's own code-level behaviour with a fake invoker and a fake
worker: a refused dispatch is a producer status, a gap receipt keeps the language-build contract,
and every recipe command is bound to its verified phase cwd. No Dagster, no engine."""
from __future__ import annotations

import hashlib
from unittest.mock import Mock

import pytest

from appsec_review.jobs.build_iterations import prepare_recipe_command
from appsec_review.jobs.build_workspace import BuildWorkspace
from tests.unit.job_build_iteration.support import controller, fixture


def test_a_refused_dispatch_reports_a_producer_status(tmp_path):
    """A dispatch whose inputs are refused is a unit output, so its status is a ProducerStatus.

    Review 2026-11-11-0003 failed at ``language_build`` publication because this result said
    ``BLOCKED_BY_DEPENDENCY``, which is not in the closed vocabulary. Why it is blocked is a fact.
    """
    from appsec_review.interchange import ProducerStatus

    source, _documents, run, graph, dispatches = fixture(tmp_path)
    worker = Mock()
    result = controller(source, run, graph, dispatches, releases={}).run(worker, invoke=Mock())
    worker.assert_not_called()
    statuses = {status.value for status in ProducerStatus}
    assert result["terminal_status"] == ProducerStatus.BLOCKED.value
    assert result["availability"] == "blocked_by_dependency"
    assert result["gaps"], "a blocked dispatch names why"
    assert set(result["states"].values()) <= statuses
    assert {item["terminal_status"] for item in result["receipts"]} <= statuses


@pytest.mark.parametrize("family", ["native", "dotnet", "go", "java", "node", "php", "python", "ruby"])
@pytest.mark.parametrize("failed", [False, True])
def test_gap_receipt_preserves_language_contract_and_negative_evidence(tmp_path, family, failed):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    dispatches[0]["family"] = family
    scheduler = controller(source, run, graph, dispatches)
    receipt = scheduler._gap(dispatches[0]["build_unit_id"], "unavailable prerequisite", failed=failed)
    assert receipt == {
        "schema": "appsec-review/language-build-receipt/1",
        "source_fingerprint": graph["source_fingerprint"],
        "build_unit_id": dispatches[0]["build_unit_id"], "family": family,
        "root": dispatches[0]["root"], "terminal_status": "FAILED" if failed else "BLOCKED",
        "artifacts": [], "commands": [], "gaps": ["unavailable prerequisite"],
    }


def test_phase_cwd_binds_cmake_source_and_build_and_preserves_target_operands(tmp_path):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    workspace = BuildWorkspace(run)
    workspace.materialize(source, graph["source_fingerprint"])
    accepted = next(item for item in dispatches if item["root"] == "b")
    recipe = {**accepted["recipe"], "execution_cwd": {"configure": "b/build", "build": "b/build"}}
    configure = ("cmake", "-S", "..", "-B", ".")
    assert prepare_recipe_command(workspace.paths.target, accepted, recipe, "configure", configure) == (
        configure, "b/build")
    build = ("cmake", "--build", ".", "--target", "b", "--", "b/target")
    assert prepare_recipe_command(workspace.paths.target, accepted, recipe, "build", build) == (build, "b/build")
    with pytest.raises(ValueError, match="wrong accepted source"):
        prepare_recipe_command(workspace.paths.target, accepted, recipe, "configure",
                               ("cmake", "-S", ".", "-B", "."))
    assert prepare_recipe_command(
        workspace.paths.target, accepted, recipe, "configure", ("cmake", "-Sb", "-Bb/build")) == (
            configure[:1] + ("-S..", "-B."), "b/build")
    assert not (source / "b/build").exists()


def test_make_applies_all_directory_operands_before_explicit_driver_without_rebasing_targets(tmp_path):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    makefile = source / "b/Makefile"
    makefile.write_bytes(b"b/target:\n\tcc b.c -o build/B\n")
    workspace = BuildWorkspace(run)
    workspace.materialize(source, graph["source_fingerprint"])
    accepted = next(item for item in dispatches if item["root"] == "b")
    accepted["descriptor_package"]["documents"].append({
        "path": "b/Makefile", "sha256": hashlib.sha256(makefile.read_bytes()).hexdigest()})
    recipe = {**accepted["recipe"], "execution_cwd": {"build": "b/build"}}
    command = ("make", "-f", "Makefile", "-C", "..", "b/target")
    assert prepare_recipe_command(workspace.paths.target, accepted, recipe, "build", command) == (
        command, "b/build")
    wrong = ("make", "-C", ".", "b/target")
    with pytest.raises(ValueError, match="default driver is absent"):
        prepare_recipe_command(workspace.paths.target, accepted, recipe, "build", wrong)
    (workspace.paths.target / "b/Makefile").write_bytes(b"replaced\n")
    with pytest.raises(ValueError, match="unchanged accepted source descriptor"):
        prepare_recipe_command(workspace.paths.target, accepted, recipe, "build", command)


def test_each_phase_rechecks_cwd_after_configure_and_refuses_symlinked_build(tmp_path):
    source, _documents, run, graph, dispatches = fixture(tmp_path)
    workspace = BuildWorkspace(run)
    workspace.materialize(source, graph["source_fingerprint"])
    accepted = next(item for item in dispatches if item["root"] == "b")
    recipe = {**accepted["recipe"], "execution_cwd": {"build": "b/build"}}
    assert prepare_recipe_command(
        workspace.paths.target, accepted, recipe, "configure",
        ("cmake", "-S", ".", "-B", "build"))[1] == "b"
    (workspace.paths.target / "b/build").rmdir()
    (workspace.paths.target / "b/build").symlink_to(workspace.paths.target / "a", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        prepare_recipe_command(workspace.paths.target, accepted, recipe, "build",
                               ("cmake", "--build", "."))
