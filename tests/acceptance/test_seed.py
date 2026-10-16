from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

import pytest

from appsec_review.acceptance.seed import (
    BlobStore, SeedError, resolve_chain, restore, snapshot, verify)
from tests.acceptance.support import RUN_ID, make_job

UID, GID = os.getuid(), os.getgid()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    make_job(repo / "runs" / RUN_ID, "job_a", dagster_run_id="d1")
    os.symlink("attempts/attempt_0001/handoff.json", repo / "runs" / RUN_ID / "data" / "jobs" / "job_a" / "link")
    (repo / "data" / "feeds").mkdir(parents=True)
    (repo / "data" / "feeds" / "current.json").write_text("{\"snapshot\": 1}")
    return repo


def _snap(repo: Path, store: BlobStore, job: str, base: str | None):
    return snapshot(repo, store, repo / "test" / "acceptance" / "v1" / "seeds", tag="v1", job_id=job,
                    app_run_id=RUN_ID, base_job=base, expected_uid=UID, expected_gid=GID,
                    shared_roots=("data",), exclude=("data/acceptance-seeds",),
                    extra={"topology": [], "target": "/opt/app/targets/t"})


def test_seed_chain_restores_byte_identical_and_deduplicates(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    store = BlobStore(repo / "data" / "acceptance-seeds")
    first = _snap(repo, store, "job_a", None)
    make_job(repo / "runs" / RUN_ID, "job_b", dagster_run_id="d2", artifact_text="{\"b\": true}")
    (repo / "runs" / RUN_ID / "data" / "jobs" / "job_a" / "link").unlink()
    second = _snap(repo, store, "job_b", "job_a")
    assert first["base"] is None and second["base"] == "job_a"
    assert f"runs/{RUN_ID}/data/jobs/job_a/link" in second["removed"]
    assert all(path.startswith(f"runs/{RUN_ID}/data/jobs/job_b") or path.endswith(("jobs", "data"))
               or path == f"runs/{RUN_ID}/data/jobs" for path in second["entries"])
    # job_a's unchanged blobs are not copied again.
    assert second["totals"]["added_blob_bytes"] < second["totals"]["bytes"]
    manifests = repo / "test" / "acceptance" / "v1" / "seeds"
    json.loads((manifests / "after-job_b.manifest.json").read_text())  # valid JSON, one entry per line
    header, entries = resolve_chain(manifests, "job_b")
    assert verify(repo, header, entries, expected_uid=UID, expected_gid=GID) == []

    original = {path: (repo / path).read_bytes() for path, entry in entries.items() if entry["type"] == "file"}
    shutil.rmtree(repo / "runs" / RUN_ID)
    issues = restore(repo, store, header, entries, expected_uid=UID, expected_gid=GID,
                     chown=lambda path, uid, gid: None)
    assert issues == []
    assert {path: (repo / path).read_bytes() for path in original} == original

    header_a, entries_a = resolve_chain(manifests, "job_a")
    shutil.rmtree(repo / "runs" / RUN_ID)
    assert restore(repo, store, header_a, entries_a, expected_uid=UID, expected_gid=GID,
                   chown=lambda path, uid, gid: None) == []
    assert (repo / "runs" / RUN_ID / "data" / "jobs" / "job_a" / "link").is_symlink()
    assert not (repo / "runs" / RUN_ID / "data" / "jobs" / "job_b").exists()


def test_verify_reports_mismatch_missing_extra_mode_and_owner(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    store = BlobStore(repo / "data" / "acceptance-seeds")
    _snap(repo, store, "job_a", None)
    header, entries = resolve_chain(repo / "test" / "acceptance" / "v1" / "seeds", "job_a")
    attempt = repo / "runs" / RUN_ID / "data" / "jobs" / "job_a" / "attempts" / "attempt_0001"
    (attempt / "artifacts" / "out.json").write_text("{\"items\": [9, 9]}")  # same size, other bytes
    (attempt / "status.json").unlink()
    (attempt / "stray.txt").write_text("x")
    os.chmod(attempt / "claim.json", 0o600)
    real_lstat = os.lstat

    def lstat(path: str):
        info = real_lstat(path)
        if path.endswith("result.json"):
            values = list(info)
            values[4] = 0
            return os.stat_result(values)
        return info

    issues = {(issue.kind, Path(issue.path).name)
              for issue in verify(repo, header, entries, expected_uid=UID, expected_gid=GID, lstat=lstat)}
    assert ("sha256", "out.json") in issues
    assert ("missing", "status.json") in issues
    assert ("extra", "stray.txt") in issues
    assert ("mode", "claim.json") in issues
    assert ("owner", "result.json") in issues


def test_restore_refuses_existing_run_missing_blobs_and_tampered_chain(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    store = BlobStore(repo / "data" / "acceptance-seeds")
    _snap(repo, store, "job_a", None)
    manifests = repo / "test" / "acceptance" / "v1" / "seeds"
    header, entries = resolve_chain(manifests, "job_a")
    with pytest.raises(SeedError, match="exists"):
        restore(repo, store, header, entries, expected_uid=UID, expected_gid=GID)
    shutil.rmtree(repo / "runs" / RUN_ID)
    blob = next(entry["sha256"] for entry in entries.values() if entry["type"] == "file")
    os.chmod(store.path(blob), 0o644)
    store.path(blob).unlink()
    with pytest.raises(SeedError, match="lacks"):
        restore(repo, store, header, entries, expected_uid=UID, expected_gid=GID)
    path = manifests / "after-job_a.manifest.json"
    path.write_text(path.read_text().replace('"mode": "0644"', '"mode": "0600"', 1))
    with pytest.raises(SeedError, match="full_sha256"):
        resolve_chain(manifests, "job_a")


def test_shared_inputs_are_verified_and_restored_only_on_request(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    store = BlobStore(repo / "data" / "acceptance-seeds")
    _snap(repo, store, "job_a", None)
    header, entries = resolve_chain(repo / "test" / "acceptance" / "v1" / "seeds", "job_a")
    (repo / "data" / "feeds" / "current.json").write_text("{\"snapshot\": 2}")
    shutil.rmtree(repo / "runs" / RUN_ID)
    issues = restore(repo, store, header, entries, expected_uid=UID, expected_gid=GID,
                     chown=lambda path, uid, gid: None)
    assert {(issue.kind, Path(issue.path).name) for issue in issues} == {("sha256", "current.json")}
    shutil.rmtree(repo / "runs" / RUN_ID)
    assert restore(repo, store, header, entries, expected_uid=UID, expected_gid=GID, restore_shared=True,
                   chown=lambda path, uid, gid: None) == []
    assert (repo / "data" / "feeds" / "current.json").read_text() == "{\"snapshot\": 1}"


def test_restore_sets_the_manifest_owner(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    store = BlobStore(repo / "data" / "acceptance-seeds")
    _snap(repo, store, "job_a", None)
    header, entries = resolve_chain(repo / "test" / "acceptance" / "v1" / "seeds", "job_a")
    shutil.rmtree(repo / "runs" / RUN_ID)
    calls = []
    restore(repo, store, header, entries, expected_uid=UID, expected_gid=GID,
            chown=lambda path, uid, gid: calls.append((uid, gid)))
    assert calls and set(calls) == {(UID, GID)}

    def refuse(path, uid, gid):
        raise PermissionError(path)

    shutil.rmtree(repo / "runs" / RUN_ID)
    issues = restore(repo, store, header, entries, expected_uid=UID, expected_gid=GID, chown=refuse)
    assert issues and {issue.kind for issue in issues} == {"owner"}
