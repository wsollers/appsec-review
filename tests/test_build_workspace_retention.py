from __future__ import annotations

import json

import pytest

from appsec_review.config.build_workspaces import BuildWorkspacePolicy
from appsec_review.jobs.build_workspace import ReconstructionMiss, WorkspaceError, sweep_workspaces
from appsec_review.storage.lock import FileLock, LockUnavailable
from tests.test_build_workspace import binding, build_a, make_workspace


def terminal_runs(tmp_path, count=4):
    runs = [make_workspace(tmp_path, f"run-{index}") for index in range(1, count + 1)]
    for workspace, _, _ in runs:
        workspace.mark_terminal(workers_stopped=True)
    return runs


def test_run_four_keep_three_purges_only_owned_tree_and_preserves_evidence(tmp_path):
    runs = terminal_runs(tmp_path)
    oldest, source, generation = runs[0]
    durable = oldest.run_dir / "artifacts" / "important-evidence"
    durable.write_bytes(b"preserve")
    unrelated = oldest.run_dir / "workspace" / "not-build"
    unrelated.mkdir()
    (unrelated / "keep").write_bytes(b"unclaimed")
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert report.deleted == [str(oldest.root)]
    assert not report.failures
    assert not oldest.root.exists()
    assert all(workspace.root.exists() for workspace, _, _ in runs[1:])
    assert durable.read_bytes() == b"preserve"
    assert (unrelated / "keep").read_bytes() == b"unclaimed"
    assert (source / "make.conf").read_bytes() == b"CC=cc\n"
    inventory = json.loads((oldest.run_dir / "data/build/workspace/deletion.json").read_bytes())
    assert inventory["paths"] == ["workspace/build"]
    assert inventory["status"] == "deleted"
    with oldest.writer() as writer:
        assert writer.state()["purged"] is True
        with pytest.raises(ReconstructionMiss, match="purged"):
            writer.begin_attempt(binding(), "after-purge", generation)
        assert writer.resume() == generation
        assert writer.state()["purged"] is False
        assert (writer.paths.target / "make.conf").read_bytes() == b"CC=cc\n"


def test_accepted_references_survive_purge_and_rehydrate_without_recompile(tmp_path):
    oldest, _, initial = make_workspace(tmp_path)
    record, _ = build_a(oldest, initial)
    oldest.mark_terminal(workers_stopped=True)
    for index in range(2, 5):
        workspace, _, _ = make_workspace(tmp_path, f"run-{index}")
        workspace.mark_terminal(workers_stopped=True)
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert report.deleted == [str(oldest.root)]
    assert (oldest.run_dir / record.reference["path"]).is_file()
    assert not any(str(oldest.root) in str(value) for value in record.reference.values())
    with oldest.writer() as writer:
        writer.resume()
        assert writer.verify_product(record, binding()).identity == record.identity
        assert (writer.paths.install / "lib/liba.so").read_bytes() == b"verified-A-library"


@pytest.mark.parametrize("hold", ["preserved", "resume-held", "external-worker", "external-lease"])
def test_held_oldest_is_retained_and_released_explicitly(tmp_path, hold):
    runs = terminal_runs(tmp_path)
    oldest = runs[0][0]
    oldest.set_hold(hold, held=True)
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert not report.deleted
    assert report.retained[str(oldest.root)] == f"held:{hold}"
    oldest.set_hold(hold, held=False)
    assert sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy()).deleted == [str(oldest.root)]


def test_active_nonterminal_and_claimed_terminal_workspaces_are_not_deleted(tmp_path):
    runs = terminal_runs(tmp_path)
    oldest = runs[0][0]
    active, _, _ = make_workspace(tmp_path, "active")
    with oldest.writer():
        report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
        assert not report.deleted
        assert report.retained[str(oldest.root)] == "writer_or_resume_claim"
        assert active.root.exists()
    assert oldest.root.exists()


def test_resume_acquisition_and_sweep_share_serialization_lock(tmp_path):
    oldest = terminal_runs(tmp_path)[0][0]
    with FileLock(oldest.lifecycle_lock):
        with pytest.raises(LockUnavailable):
            with oldest.writer():
                pytest.fail("resume raced cleanup")
        with pytest.raises(LockUnavailable):
            sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert oldest.root.exists()


def test_zero_disables_deletion_not_evidence_retention(tmp_path):
    runs = terminal_runs(tmp_path)
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy(0))
    assert not report.deleted
    assert not report.failures
    assert all(report.retained[str(workspace.root)] == "retention_disabled" for workspace, _, _ in runs)


@pytest.mark.parametrize("mutation", [
    {"disposable": "../../source"},
    {"run_dir": "/"},
    {"ownership_id": "unowned"},
    {"holds": []},
    {"terminal_ns": True},
])
def test_malformed_ownership_refuses_deletion_with_explicit_failure(tmp_path, mutation):
    oldest = terminal_runs(tmp_path)[0][0]
    owner_path = oldest.run_dir / "data/build/workspace/owner.json"
    owner = json.loads(owner_path.read_bytes())
    owner.update(mutation)
    owner_path.write_text(json.dumps(owner))
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert str(oldest.run_dir) in report.failures
    assert oldest.root.exists()
    assert not report.deleted


def test_replaced_disposable_root_symlink_cannot_delete_external_tree(tmp_path):
    oldest = terminal_runs(tmp_path)[0][0]
    moved = oldest.run_dir / "workspace" / "saved-build"
    oldest.root.rename(moved)
    oldest.root.symlink_to(tmp_path / "source", target_is_directory=True)
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert report.failures
    assert not report.deleted
    assert (tmp_path / "source/make.conf").read_bytes() == b"CC=cc\n"
    assert moved.is_dir()


def test_terminal_requires_cleanup_and_unfinished_attempt_cannot_be_purged(tmp_path):
    workspace, _, generation = make_workspace(tmp_path)
    with pytest.raises(WorkspaceError, match="cleanup"):
        workspace.mark_terminal(workers_stopped=False)
    with workspace.writer() as writer:
        writer.begin_attempt(binding(), "running", generation)
    with pytest.raises(WorkspaceError, match="unfinished"):
        workspace.mark_terminal(workers_stopped=True)


def test_sweep_removes_registered_replay_bytes_but_not_trial_receipts(tmp_path):
    oldest, _, initial = make_workspace(tmp_path)
    with oldest.writer() as writer:
        replay = writer.create_replay("trial-1", initial)
    replay.mark_terminal(workers_stopped=True)
    evidence = oldest.run_dir / "data/build/workspace/replays/trial-receipt.json"
    evidence.write_bytes(b'{"trial":"preserved"}\n')
    oldest.mark_terminal(workers_stopped=True)
    for index in range(2, 5):
        run, _, _ = make_workspace(tmp_path, f"run-{index}")
        run.mark_terminal(workers_stopped=True)
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert report.deleted == [str(oldest.root), str(replay.root)]
    assert evidence.read_bytes() == b'{"trial":"preserved"}\n'
    assert (oldest.run_dir / replay.owner_relative).is_file()
    assert (oldest.run_dir / replay.state_relative).is_file()
    with replay.writer() as writer:
        writer.resume()
        assert writer.paths.target.is_dir()


@pytest.mark.parametrize("claim", ["active", "held", "writer"])
def test_active_held_or_claimed_replay_blocks_entire_parent_purge(tmp_path, claim):
    oldest = terminal_runs(tmp_path)[0][0]
    with oldest.writer() as writer:
        replay = writer.create_replay("active-trial")
    if claim != "active":
        replay.mark_terminal(workers_stopped=True)
    if claim == "held":
        replay.set_hold("worker-lease", held=True)
    if claim == "writer":
        with replay.writer():
            report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    else:
        report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert not report.deleted
    assert oldest.root.exists()
    assert replay.root.exists()


def test_failed_deletion_is_reported_and_exact_inventory_can_be_retried(tmp_path, monkeypatch):
    from appsec_review.jobs import build_workspace

    oldest = terminal_runs(tmp_path)[0][0]
    actual_remove = build_workspace._remove_tree

    def fail_remove(path):
        raise PermissionError(f"simulated filesystem denial: {path}")

    monkeypatch.setattr(build_workspace, "_remove_tree", fail_remove)
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert str(oldest.root) in report.failures
    assert oldest.root.exists()
    inventory = json.loads((oldest.run_dir / "data/build/workspace/deletion.json").read_bytes())
    assert inventory["status"] == "deleting"
    assert inventory["paths"] == ["workspace/build"]
    monkeypatch.setattr(build_workspace, "_remove_tree", actual_remove)
    report = sweep_workspaces(tmp_path / "runs", BuildWorkspacePolicy())
    assert report.deleted == [str(oldest.root)]
    assert not report.failures
