from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from appsec_review.observability.retention import CATALOG, JOURNAL, apply_retention, plan_retention
from appsec_review.storage import FileLock, LockUnavailable, atomic_json


def store(root):
    root.mkdir(mode=0o700)
    paths = ["run1/data/accepted.json", "run1/data/shared.bin", "run2/data/unused.bin",
             "run2/data/cycle-a.bin", "run2/data/cycle-b.bin"]
    nodes = []
    for path in paths:
        leaf = root / path
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_bytes(path.encode())
        nodes.append({"path": path, "run_id": path.split("/")[0],
                      "sha256": hashlib.sha256(path.encode()).hexdigest(),
                      "role": "accepted_receipt" if "accepted" in path else "artifact",
                      "retain": False, "references": []})
    nodes[0]["references"] = [paths[1]]
    nodes[3]["references"], nodes[4]["references"] = [paths[4]], [paths[3]]
    catalog = {"schema": "appsec-review/retention-catalog/1", "custody": "sealed_offline",
               "owner": "synthetic-fixture", "objects": nodes,
               "runs": {name: {"state": "terminal", "leases": [], "repair_hold": False}
                        for name in ("run1", "run2")}}
    atomic_json(root / CATALOG, catalog)
    return catalog


def test_dry_run_preserves_accepted_evidence_shared_objects_and_collects_unrooted_cycles(tmp_path):
    root = tmp_path / "store"
    catalog = store(root)
    first = plan_retention(root)
    assert first == plan_retention(root) and not first["holds"]
    assert len(first["delete"]) == 3
    assert apply_retention(root, first)["status"] == "dry_run"
    assert all((root / row["path"]).exists() for row in catalog["objects"])
    applied = apply_retention(root, first, apply=True)
    assert len(applied["deleted"]) == 3
    assert (root / "run1/data/accepted.json").is_file()
    assert (root / "run1/data/shared.bin").is_file()
    assert apply_retention(root, first, apply=True) == applied


@pytest.mark.parametrize("hold", ["active", "held", "lease", "repair"])
def test_active_leased_held_and_cross_run_dependencies_are_roots(tmp_path, hold):
    root = tmp_path / "store"
    catalog = store(root)
    run = catalog["runs"]["run2"]
    if hold in {"active", "held"}:
        run["state"] = hold
    elif hold == "lease":
        run["leases"] = ["claim"]
    else:
        run["repair_hold"] = True
    catalog["objects"][2]["references"] = ["run1/data/shared.bin"]
    atomic_json(root / CATALOG, catalog)
    assert plan_retention(root)["delete"] == []


def test_changed_claims_unknown_files_and_concurrent_claims_refuse_apply(tmp_path):
    root = tmp_path / "store"
    catalog = store(root)
    plan = plan_retention(root)
    with FileLock(root / ".retention.lock"):
        with pytest.raises(LockUnavailable):
            apply_retention(root, plan, apply=True)
    catalog["runs"]["run2"]["leases"] = ["new-claim"]
    atomic_json(root / CATALOG, catalog)
    with pytest.raises(ValueError, match="changed"):
        apply_retention(root, plan, apply=True)
    (root / "unknown").write_text("not garbage")
    assert plan_retention(root)["holds"]


@pytest.mark.parametrize("mode", ["symlink", "traversal", "missing_reference", "legacy", "hardlink", "malformed_owner"])
def test_unknown_ownership_paths_and_legacy_roots_are_holds(tmp_path, mode):
    root = tmp_path / "store"
    catalog = store(root)
    if mode == "symlink":
        (root / "unexpected").symlink_to(tmp_path, target_is_directory=True)
    elif mode == "traversal":
        catalog["objects"][0]["path"] = "../outside"
        atomic_json(root / CATALOG, catalog)
    elif mode == "missing_reference":
        catalog["objects"][0]["references"] = ["unknown/data/object"]
        atomic_json(root / CATALOG, catalog)
    elif mode == "legacy":
        (root / CATALOG).unlink()
    elif mode == "malformed_owner":
        catalog["owner"] = True
        atomic_json(root / CATALOG, catalog)
    else:
        os.link(root / "run1/data/shared.bin", tmp_path / "alias")
    plan = plan_retention(root)
    assert plan["holds"] and plan["delete"] == []
    with pytest.raises(ValueError, match="held"):
        apply_retention(root, plan, apply=True)


def test_interrupted_deletion_requires_exact_original_plan_and_resumes(tmp_path, monkeypatch):
    root = tmp_path / "store"
    store(root)
    plan = plan_retention(root)
    unlink = os.unlink
    failed = False
    def interrupted(name, **kwargs):
        nonlocal failed
        unlink(name, **kwargs)
        if not failed:
            failed = True
            raise OSError("simulated power loss after unlink")
    monkeypatch.setattr(os, "unlink", interrupted)
    with pytest.raises(OSError, match="power loss"):
        apply_retention(root, plan, apply=True)
    assert json.loads((root / JOURNAL).read_text())["pending"]
    assert plan_retention(root)["holds"]
    monkeypatch.setattr(os, "unlink", unlink)
    assert apply_retention(root, plan, apply=True)["status"] == "applied"


def test_accepted_job_paths_are_protected_even_if_mislabelled(tmp_path):
    root = tmp_path / "store"
    catalog = store(root)
    path = root / "run2/data/jobs/job/receipt.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"accepted evidence")
    catalog["objects"].append({"path": path.relative_to(root).as_posix(), "run_id": "run2",
                               "role": "artifact", "retain": False, "references": [],
                               "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    atomic_json(root / CATALOG, catalog)
    assert path.relative_to(root).as_posix() in plan_retention(root)["retained"]


def test_unknown_empty_roots_and_nonregular_files_fail_closed(tmp_path):
    root = tmp_path / "store"
    store(root)
    (root / "unregistered-root").mkdir()
    assert plan_retention(root)["holds"]
    (root / "unregistered-root").rmdir()
    path = root / "run2/data/unused.bin"
    path.unlink()
    os.mkfifo(path)
    assert plan_retention(root)["holds"]


def test_control_file_aliases_cannot_bypass_exclusive_store_custody(tmp_path):
    root = tmp_path / "store"
    store(root)
    os.link(root / CATALOG, tmp_path / "catalog-alias")
    assert plan_retention(root)["holds"]
    (tmp_path / "catalog-alias").unlink()
    plan = plan_retention(root)
    external = tmp_path / "external-lock"
    external.write_bytes(b"0")
    os.link(external, root / ".retention.lock")
    with pytest.raises(ValueError, match="ownership"):
        apply_retention(root, plan, apply=True)


def test_write_ahead_journal_directory_is_durable_before_deletion(tmp_path, monkeypatch):
    from appsec_review.observability import retention
    root = tmp_path / "store"
    store(root)
    plan = plan_retention(root)
    events = []
    sync, unlink = retention.timed_fsync, os.unlink
    def recorded_sync(descriptor):
        events.append("directory_fsync")
        sync(descriptor)
    def recorded_unlink(name, **kwargs):
        events.append("unlink")
        unlink(name, **kwargs)
    monkeypatch.setattr(retention, "timed_fsync", recorded_sync)
    monkeypatch.setattr(os, "unlink", recorded_unlink)
    apply_retention(root, plan, apply=True)
    assert events[0] == "directory_fsync"
    assert events.count("unlink") == len(plan["delete"])
    assert events.count("directory_fsync") == 3 * len(plan["delete"])


def test_journal_directory_sync_failure_deletes_nothing(tmp_path, monkeypatch):
    from appsec_review.observability import retention
    root = tmp_path / "store"
    catalog = store(root)
    plan = plan_retention(root)
    def failed_sync(descriptor):
        raise OSError("directory sync failed")
    monkeypatch.setattr(retention, "timed_fsync", failed_sync)
    with pytest.raises(OSError, match="directory sync"):
        apply_retention(root, plan, apply=True)
    assert all((root / item["path"]).is_file() for item in catalog["objects"])
