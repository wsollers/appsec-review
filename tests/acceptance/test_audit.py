from __future__ import annotations

import os
from pathlib import Path

from appsec_review.acceptance.audit import audit_attempt, audit_job_writes, audit_tree
from tests.acceptance.support import RUN_ID, make_job

UID, GID = os.getuid(), os.getgid()


def _kinds(findings) -> dict[str, set[str]]:
    kinds: dict[str, set[str]] = {}
    for item in findings:
        kinds.setdefault(item.kind, set()).add(Path(item.path).name)
    return kinds


def test_audit_reports_owner_mode_symlink_and_scratch_problems(tmp_path: Path) -> None:
    run = tmp_path / RUN_ID
    (run / "data").mkdir(parents=True)
    (run / "data" / "good.json").write_text("{}")
    (run / "data" / "root.json").write_text("{}")
    (run / "data" / "foreign.json").write_text("{}")
    (run / "data" / "open.json").write_text("{}")
    os.chmod(run / "data" / "open.json", 0o666)
    (run / "data" / "secret.json").write_text("{}")
    os.chmod(run / "data" / "secret.json", 0o000)
    os.symlink("/opt/project/node_modules", run / "data" / "dangling")
    os.symlink(str(tmp_path), run / "data" / "escaping")
    os.symlink("good.json", run / "data" / "inside")
    scratch = run / "data" / ".appsec-review-build-scratch.T70GHa"
    (scratch / "nested").mkdir(parents=True)
    (scratch / "nested" / "file").write_text("x")
    (run / "data" / ".tmp-abcdef12").write_text("partial")
    real_lstat = os.lstat

    def lstat(path: str):
        info = real_lstat(path)
        overrides = {"root.json": (0, 0), "foreign.json": (UID + 1, GID)}
        if Path(path).name in overrides:
            uid, gid = overrides[Path(path).name]
            values = list(info)
            values[4], values[5] = uid, gid
            return os.stat_result(values)
        return info

    def access(path: str, mode: int) -> bool:
        return Path(path).name != "secret.json" and os.access(path, mode)

    try:
        findings = audit_tree([run], expected_uid=UID, expected_gid=GID, allowed_link_roots=[run],
                              lstat=lstat, access=access)
    finally:
        os.chmod(run / "data" / "secret.json", 0o600)
    kinds = _kinds(findings)
    assert kinds["root-owned"] == {"root.json"}
    assert kinds["owner"] == {"foreign.json"}
    assert "open.json" in kinds["world-writable"]
    assert kinds["unreadable"] == {"secret.json"}
    assert kinds["dangling-symlink"] == {"dangling"}
    assert kinds["escaping-symlink"] == {"escaping"}
    # The scratch directory is reported once, not once per descendant.
    assert kinds["scratch-leftover"] == {".appsec-review-build-scratch.T70GHa", ".tmp-abcdef12"}
    assert not any(item.path.endswith(("good.json", "inside")) for item in findings)


def test_audit_window_skips_entries_older_than_the_job(tmp_path: Path) -> None:
    run = tmp_path / RUN_ID
    (run / "old").mkdir(parents=True)
    os.chmod(run / "old", 0o777)
    os.utime(run / "old", (1, 1))
    assert audit_tree([run], expected_uid=UID, expected_gid=GID, since=None)
    old_only = audit_tree([run / "old"], expected_uid=UID, expected_gid=GID,
                          since=os.lstat(run / "old").st_ctime + 10)
    assert old_only == []


def test_attempt_receipts_and_handoff_artifacts_are_required(tmp_path: Path) -> None:
    run = tmp_path / RUN_ID
    attempt = make_job(run, "job_x", dagster_run_id="d1")
    assert audit_attempt(run, "job_x", attempt, dagster_status="SUCCESS") == []
    (attempt / "artifacts" / "out.json").write_text("{\"items\": [3]}")
    assert {item.kind for item in audit_attempt(run, "job_x", attempt)} == {"artifact-mismatch"}
    (attempt / "artifacts" / "out.json").unlink()
    assert {item.kind for item in audit_attempt(run, "job_x", attempt)} == {"missing-expected"}
    (run / "data" / "jobs" / "job_x" / "latest.json").unlink()
    assert any("latest.json" in item.path for item in audit_attempt(run, "job_x", attempt))
    assert audit_attempt(run, "job_y", None)[0].kind == "missing-expected"


def test_running_attempt_after_terminal_dagster_run_is_stale(tmp_path: Path) -> None:
    run = tmp_path / RUN_ID
    attempt = make_job(run, "job_x", dagster_run_id="d1", status="RUNNING")
    kinds = {item.kind for item in audit_job_writes(run, "job_x", attempt, expected_uid=UID, expected_gid=GID,
                                                     since=None, dagster_status="FAILURE")}
    assert "stale-status" in kinds


def test_scratch_referenced_by_the_job_records_is_evidence_not_a_leftover(tmp_path: Path) -> None:
    run = tmp_path / RUN_ID
    attempt = make_job(run, "job_x", dagster_run_id="d1")
    task = attempt / "steps" / "scan" / "tasks" / "tool"
    kept = task / "scratch" / "file_0001" / "raw"
    kept.mkdir(parents=True)
    (kept / "stdout.bin").write_bytes(b"out")
    stray = attempt / "steps" / "scan" / "tasks" / "other" / "scratch"
    stray.mkdir(parents=True)
    (task / "result.json").write_text(
        '{"raw": ["' + (kept / "stdout.bin").relative_to(run).as_posix() + '"]}', encoding="utf-8")
    findings = audit_job_writes(run, "job_x", attempt, expected_uid=UID, expected_gid=GID, since=None)
    leftovers = {item.path for item in findings if item.kind == "scratch-leftover"}
    assert leftovers == {str(stray)}


def test_target_toolchain_tmp_in_a_build_workspace_is_not_a_leftover(tmp_path: Path) -> None:
    run = tmp_path / RUN_ID
    tree = run / "data" / "build" / "probes" / "u" / "workspace" / "projects" / "native"
    (tree / "build" / "CMakeFiles" / "CompilerIdC" / "tmp").mkdir(parents=True)
    (tree / ".appsec-review-build-scratch.AoX3Ze").mkdir()
    findings = audit_tree([run], expected_uid=UID, expected_gid=GID)
    assert _kinds(findings).get("scratch-leftover") == {".appsec-review-build-scratch.AoX3Ze"}
