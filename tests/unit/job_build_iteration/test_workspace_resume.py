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
        path.write_bytes(minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2"))
        return IterationOutcome({"build_unit_id": request["node_id"], "terminal_status": "SUCCEEDED",
                                 "gaps": [], "artifacts": []},
                                (ProductSpec("target/build/control", product["kind"], product["product_id"],
                                             product["interface"], product["variant"],
                                             {"executable": "executable"}[product["kind"]], axes),), True)
    return worker


def _invoke(request, _label, execute):
    return execute(request, "synthetic-dagster-run")


@pytest.mark.parametrize("rejected", [False, True], ids=["provenance", "rejected"])
@pytest.mark.parametrize("prior_failure", [False, True], ids=["fresh", "after-failure"])
@pytest.mark.parametrize("wrapped", [False, True], ids=["direct", "wrapped"])
def test_built_gap_receipt_is_not_a_build_failure_or_a_clean_checkpoint(tmp_path, rejected, prior_failure, wrapped):
    from dataclasses import replace
    from appsec_review.jobs.job_project_build.enforcement import scoped_gaps
    from appsec_review.jobs.build_iterations import durable_artifacts
    from appsec_review.jobs.build_workspace import BuildWorkspace
    from appsec_review.storage.shared import reference

    runner, root, graph, action = accepted_native(tmp_path)
    scheduler = _iterations(runner, root, graph, action)
    gaps = scoped_gaps(["capture_empty"], "execute.native", action["build_unit_id"])
    prior_evidence = {}
    if prior_failure:
        assert scheduler.run(_failing_worker(root), invoke=_invoke)["states"] == {
            action["build_unit_id"]: "FAILED"}
        prior_evidence = {p: p.read_bytes() for p in (root / "artifacts/build/iterations/failures").glob("*.json")}
        assert prior_evidence

    def worker(request, run_id):
        outcome = _succeeding_worker(root, graph, action)(request, run_id)
        product = BuildWorkspace(root).paths.target / "build/control"
        artifacts = [{**reference(root, product), "workspace_path": "build/control", "kind": "executable"}]
        receipt = {**outcome.receipt, "family": "native", "build_outcome": "built",
                   "terminal_status": "COMPLETED_WITH_GAPS", "gaps": gaps,
                   "workspace": BuildWorkspace(root).paths.target.relative_to(root).as_posix(),
                   "artifacts": [] if rejected else artifacts,
                   "rejected_artifacts": artifacts if rejected else []}
        return replace(outcome, receipt=durable_artifacts(root, receipt))

    def invoke(request, label, execute):
        try:
            return _invoke(request, label, execute)
        except RuntimeError:
            if not wrapped:
                raise
            raise RuntimeError("build iteration invocation failed") from None

    result = scheduler.run(worker, invoke=invoke)
    assert result["states"] == {action["build_unit_id"]: "BLOCKED"}
    assert result["receipts"][0]["build_outcome"] == "built"
    assert result["receipts"][0]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["receipts"][0]["gaps"] == gaps
    assert result["gaps"] == [*gaps, *(
        f"topology:{gap['code']}: {gap['reason']}" for gap in graph["coverage_gaps"])]
    assert result["receipts"][0]["workspace"] is None
    assert not scheduler.ledger_path.exists()
    assert not (root / "data/build/iterations/failures" / f"{action['build_unit_id']}.json").exists()
    assert {p: p.read_bytes() for p in prior_evidence} == prior_evidence
    with scheduler.workspace.writer() as writer:
        assert not writer.committed_generation()["accepted"]
    assert not (scheduler.workspace.paths.target / "build/control").exists()


@pytest.mark.parametrize("outcome", ["failed", "not_run"])
def test_clean_status_cannot_checkpoint_an_unbuilt_receipt(tmp_path, outcome):
    from dataclasses import replace

    runner, root, graph, action = accepted_native(tmp_path)
    scheduler = _iterations(runner, root, graph, action)

    def worker(request, run_id):
        result = _succeeding_worker(root, graph, action)(request, run_id)
        return replace(result, receipt={**result.receipt, "build_outcome": outcome})

    result = scheduler.run(worker, invoke=_invoke)
    assert result["states"] == {action["build_unit_id"]: "FAILED"}
    assert result["receipts"][0]["artifacts"] == []
    assert not scheduler.ledger_path.exists()


@pytest.mark.parametrize("reader", ["reuse", "recovery"])
def test_committed_gap_receipt_cannot_gain_clean_checkpoint_authority(tmp_path, reader):
    from appsec_review.jobs.build_iterations import read_reference, retain
    from appsec_review.jobs.build_workspace import WorkspaceError

    runner, root, graph, action = accepted_native(tmp_path)
    scheduler = _iterations(runner, root, graph, action)
    scheduler.run(_succeeding_worker(root, graph, action), invoke=_invoke)
    ledger = json.loads(scheduler.ledger_path.read_bytes())
    entry = ledger["nodes"][action["build_unit_id"]]
    completion = read_reference(root, entry["completion"])
    receipt = read_reference(root, entry["receipt"])
    receipt.update(terminal_status="COMPLETED_WITH_GAPS", build_outcome="built", gaps=["capture_empty"])
    receipt_ref = retain(root, "receipts", receipt)
    before = (root / scheduler.workspace.state_relative).read_bytes()
    if reader == "reuse":
        entry["receipt"] = receipt_ref
        entry["completion"] = retain(root, "completed", {**completion, "receipt": receipt_ref})
        atomic_json(scheduler.ledger_path, ledger)
        result = scheduler.run(lambda *_: pytest.fail("gap checkpoint must not dispatch"), invoke=_invoke)
        assert result["terminal_status"] == "BLOCKED"
        assert any("successful immutable receipt" in gap for gap in result["gaps"])
    else:
        prepared = read_reference(root, completion["prepared"])
        request = read_reference(root, completion["request"])
        atomic_json(root / "data/build/iterations/prepared" / f"{request['attempt_id']}.json",
                    {"prepared": retain(root, "prepared", {**prepared, "receipt": receipt_ref})})
        scheduler.ledger_path.unlink()
        atomic_json(root / "data/build/iterations/pending.json", {
            "request": completion["request"], "before_generation": entry["before_generation"]})
        with pytest.raises(WorkspaceError, match="successful immutable receipt"):
            scheduler._recover()
        assert not scheduler.ledger_path.exists()
    assert (root / scheduler.workspace.state_relative).read_bytes() == before


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
