"""job_build_iteration: workspace resume after a failed or interrupted iteration, over a synthetic
accepted native action. The worker and the invoker are fakes; the accepted plan is published by a
one-unit synthetic producer through JobRunner (the admission rules, not a hand-written pointer)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.build_topology_artifacts import guard_action
from appsec_review.storage import atomic_json
from tests.test_build_topology_refinement import _native, accepted_native


def _iterations(runner, root: Path, graph, action):
    from appsec_review.config.build_selection import parse_build_selection
    from appsec_review.jobs.build_iterations import BuildIterations
    target = root.parent / "synthetic-target"
    target.mkdir(exist_ok=True)
    for document in _native()["descriptor_package"]["documents"]:
        (target / document["path"]).write_text(document["content"], encoding="utf-8")
    selection = parse_build_selection(runner.config.job("job_project_build").settings["build_selection"])
    return BuildIterations(root, target, graph, [action],
                           configuration={"build_selection": selection.view()},
                           releases=runner.config.review_policy.releases.view(),
                           execution_identity="synthetic-executor/1", output_policy_identity="synthetic-outputs/1")


def _failing_worker(root: Path):
    from appsec_review.jobs.build_iterations import IterationOutcome
    from appsec_review.jobs.build_workspace import BuildWorkspace

    def worker(request, _run_id):
        paths = BuildWorkspace(root).paths
        (paths.target / "main.c").write_text("damaged by the failed compiler\n", encoding="utf-8")
        (paths.install / "partial.o").write_bytes(b"partial")
        return IterationOutcome({"build_unit_id": request["node_id"], "terminal_status": "FAILED",
                                 "gaps": ["synthetic compiler failure"]}, (), True)
    return worker


def _succeeding_worker(root: Path, graph, action):
    from appsec_review.config.build_selection import AXES
    from appsec_review.jobs.build_iterations import IterationOutcome
    from appsec_review.jobs.build_topology import proven_product_axes
    from appsec_review.jobs.build_workspace import BuildWorkspace, ProductSpec
    from tests.capture_fakes import minimal_elf
    axes = dict.fromkeys(AXES) | {key: value for key, value in proven_product_axes(
        guard_action(root, action, graph=graph)).items() if value is not None}
    node = next(item for item in graph["nodes"] if item["build_unit_id"] == action["build_unit_id"])
    product = node["products"][0]

    def worker(request, _run_id):
        path = BuildWorkspace(root).paths.target / "build/control"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(minimal_elf())
        return IterationOutcome({"build_unit_id": request["node_id"], "terminal_status": "SUCCEEDED",
                                 "gaps": [], "artifacts": []},
                                (ProductSpec("target/build/control", product["kind"], product["product_id"],
                                             product["interface"], product["variant"],
                                             {"executable": "executable"}[product["kind"]], axes),), True)
    return worker


def _invoke(request, _label, execute):
    return execute(request, "synthetic-dagster-run")


def test_workspace_resume_after_failed_iteration_rollback_needs_no_ledger(tmp_path):
    from appsec_review.jobs.build_iterations import resume_build_workspace
    from appsec_review.jobs.build_workspace import BuildWorkspace
    runner, root, graph, action = accepted_native(tmp_path)
    uid = action["build_unit_id"]
    controller = _iterations(runner, root, graph, action)
    result = controller.run(_failing_worker(root), invoke=_invoke)
    assert result["states"] == {uid: "FAILED"}
    failed = next(item for item in result["receipts"] if item["build_unit_id"] == uid)
    assert "synthetic compiler failure" in failed["gaps"]
    prepared_dir = root / "data/build/iterations/prepared"
    failure_evidence = {path.name: path.read_bytes() for path in sorted(prepared_dir.iterdir())}
    assert len(failure_evidence) == 1
    assert not (root / "data/build/iterations/ledger.json").exists()
    assert not (root / "data/build/iterations/pending.json").exists()
    workspace = BuildWorkspace(root)
    with workspace.writer() as writer:
        rolled_back = writer.state()
    assert rolled_back["attempt"] is None
    resume_build_workspace(root)
    with workspace.writer() as writer:
        resumed = writer.state()
        assert not writer.committed_generation()["accepted"]
    assert resumed["condition"] == "clean" and resumed["generation"] == rolled_back["generation"]
    assert (workspace.paths.target / "main.c").read_text() == _native()["descriptor_package"]["documents"][1]["content"]
    assert not (workspace.paths.install / "partial.o").exists()

    rerun = _iterations(runner, root, graph, action).run(_succeeding_worker(root, graph, action), invoke=_invoke)
    assert rerun["states"] == {uid: "SUCCEEDED"}
    assert not next(item for item in rerun["receipts"] if item["build_unit_id"] == uid)["gaps"]
    ledger = json.loads((root / "data/build/iterations/ledger.json").read_bytes())
    assert ledger["order"] == [uid] and ledger["nodes"][uid]["before_generation"] == rolled_back["generation"]
    assert not (root / "data/build/iterations/pending.json").exists()
    with workspace.writer() as writer:
        assert writer.committed_generation()["accepted"]
        assert writer.state()["generation"] == ledger["nodes"][uid]["generation"] != rolled_back["generation"]
        assert writer.state()["attempt"] is None
    assert (workspace.paths.target / "build/control").exists()
    for name, data in failure_evidence.items():
        assert (prepared_dir / name).read_bytes() == data


@pytest.mark.parametrize("state", ["unfinished-attempt", "accepted-without-admission", "corrupt-state"])
def test_workspace_resume_without_ledger_refuses_non_pristine_state(tmp_path, state):
    from appsec_review.jobs.build_iterations import resume_build_workspace
    from appsec_review.jobs.build_workspace import BuildWorkspace, NodeBinding, ReconstructionMiss, WorkspaceError
    runner, root, graph, action = accepted_native(tmp_path)
    controller = _iterations(runner, root, graph, action)
    workspace = BuildWorkspace(root)
    if state == "accepted-without-admission":
        result = controller.run(_succeeding_worker(root, graph, action), invoke=_invoke)
        assert result["states"] == {action["build_unit_id"]: "SUCCEEDED"}
        (root / "data/build/iterations/ledger.json").unlink()
    else:
        controller.run(_failing_worker(root), invoke=_invoke)
    state_path = root / workspace.state_relative
    if state == "unfinished-attempt":
        with workspace.writer() as writer:
            writer.begin_attempt(NodeBinding(
                action["build_unit_id"], "synthetic-source", "structural-topology", "release-config",
                "recipe", "sha256:" + "a" * 64, "synthetic-toolchain/1", (), "capture-contract",
                "expected-products"), "interrupted-attempt-1", writer.state()["generation"])
    if state == "corrupt-state":
        atomic_json(state_path, {**json.loads(state_path.read_bytes()), "condition": "unknown"})
    before = state_path.read_bytes()
    expected = (ReconstructionMiss, "invalid committed workspace state") if state == "corrupt-state" else (
        WorkspaceError, "lacks accepted or pending recipe admission")
    with pytest.raises(expected[0], match=expected[1]):
        resume_build_workspace(root)
    assert state_path.read_bytes() == before
