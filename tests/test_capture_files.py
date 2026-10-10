"""Post-build file evidence: path resolution, inventory hashing, and response-file snapshots."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from appsec_review.config import BuildCaptureConfig
from appsec_review.container_runtime import BuildProfile, CaptureScope, verify_capture_record
from appsec_review.container_runtime.capture_files import (
    CaptureRoots, build_file_inventory, resolve_file_events, snapshot_response_files,
)
from tests.capture_fakes import SYNTHETIC_SECRET, simulated_executor


IMAGE = "sha256:" + "d" * 64


def _roots(workspace: Path, directory: str = "/workspace/unit") -> CaptureRoots:
    return CaptureRoots("/workspace", workspace, "/capture", IMAGE, directory)


def _event(ordinal: int, kind: str, pid: int = 10, **fields) -> dict:
    return {"ordinal": ordinal, "timestamp_ns": ordinal, "kind": kind, "pid": pid, "tid": pid,
            "result": fields.pop("result", 0), **fields}


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_resolution_inherits_directories_across_forks_and_directory_changes() -> None:
    events = [
        _event(1, "directory_change", path="sub"),
        _event(2, "process_fork", child_pid=11),
        _event(3, "file_unlink", pid=11, path="old.o"),
        _event(4, "directory_change", pid=11, path="/workspace/other"),
        _event(5, "file_rename", pid=11, source="a.tmp", target="../unit/a"),
        _event(6, "file_open", path="x.h", directory="/workspace/explicit", access="read"),
        _event(7, "file_open", path="ignored", resolved="/workspace/real/x.h", access="read", result=3),
        _event(8, "file_open", path="<redacted: secret scan disposition>", access="read"),
        _event(9, "file_open", path="cut", path_truncated=True, access="read"),
    ]
    resolved, skipped = resolve_file_events(events, "/workspace/unit")
    assert [(item.pid, item.operation, item.path) for item in resolved] == [
        (11, "unlink", "/workspace/unit/sub/old.o"),
        (11, "rename-source", "/workspace/other/a.tmp"),
        (11, "rename-target", "/workspace/unit/a"),
        (10, "read", "/workspace/explicit/x.h"),
        (10, "read", "/workspace/real/x.h"),
    ]
    assert skipped == {"redacted": 1, "truncated": 1}


def test_roots_classify_workspace_capture_image_ephemeral_and_virtual(tmp_path: Path) -> None:
    roots = _roots(tmp_path)
    assert roots.classify("/workspace/unit/a.c") == ("workspace", "unit/a.c")
    assert roots.classify("/capture/events.jsonl")[0] == "capture"
    assert roots.classify("/usr/include/stdio.h") == ("image", "/usr/include/stdio.h")
    assert roots.classify("/tmp/cc123.s")[0] == "ephemeral"
    assert roots.classify("/dev/shm/x")[0] == "ephemeral"
    assert roots.classify("/proc/self/maps")[0] == "virtual"
    assert roots.classify("/workspacex/a")[0] == "image"


def test_inventory_deduplicates_reuses_snapshot_hashes_and_hashes_only_the_rest(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "unit").mkdir(parents=True)
    (workspace / "unit" / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (workspace / "unit" / "gen.h").write_text("#define GENERATED 1\n", encoding="utf-8")
    (workspace / "unit" / "out.o").write_bytes(b"object")
    snapshot_digest = "f" * 64  # deliberately not the real digest: proves the snapshot is reused
    snapshot = {"unit/main.c": {"sha256": snapshot_digest,
                                "size_bytes": (workspace / "unit" / "main.c").stat().st_size}}
    events = [
        _event(1, "file_open", path="main.c", resolved="/workspace/unit/main.c", access="read", result=3),
        _event(2, "file_open", path="main.c", resolved="/workspace/unit/main.c", access="read", result=3),
        _event(3, "file_open", path="missing.h", directory="/workspace/unit", access="read", result=-1,
               errno="ENOENT"),
        _event(4, "file_open", path="gen.h", resolved="/workspace/unit/gen.h", access="write",
               creates=True, result=4),
        _event(5, "file_open", path="gen.h", resolved="/workspace/unit/gen.h", access="read", result=4),
        _event(6, "file_open", path="out.o.tmp", resolved="/workspace/unit/out.o.tmp", access="write",
               creates=True, result=5),
        _event(7, "file_rename", source="out.o.tmp", target="out.o"),
        _event(8, "file_open", path="/usr/include/stdio.h", resolved="/usr/include/stdio.h", access="read",
               result=6),
        _event(9, "file_open", path="/tmp/cc1.s", resolved="/tmp/cc1.s", access="write", creates=True,
               result=7),
        _event(10, "file_open", path="/proc/self/status", resolved="/proc/self/status", access="read",
               result=8),
        _event(11, "file_open", path="/capture/x", resolved="/capture/x", access="read", result=9),
        _event(12, "file_open", path=".", resolved="/workspace/unit", access="read", result=10),
        _event(13, "file_open", path="cfg.txt", resolved="/workspace/unit/cfg.txt", access="read", result=3),
        _event(14, "file_open", path="cfg.txt", resolved="/workspace/unit/cfg.txt", access="write", result=3),
    ]
    (workspace / "unit" / "cfg.txt").write_text("rewritten\n", encoding="utf-8")
    output = tmp_path / "files.jsonl"
    summary = build_file_inventory(events, _roots(workspace), output, snapshot=snapshot,
                                   count_limit=100)
    rows = {(row["root"], row["path"]): row for row in _rows(output)}
    main = rows[("workspace", "unit/main.c")]
    assert main["status"] == "snapshot" and main["sha256"] == snapshot_digest and main["reads"] == 2
    generated = rows[("workspace", "unit/gen.h")]
    assert generated["status"] == "hashed" and generated["created"] is True
    assert generated["sha256"] == hashlib.sha256(b"#define GENERATED 1\n").hexdigest()
    assert generated["modified_after_read"] is False
    assert rows[("workspace", "unit/out.o")]["status"] == "hashed"
    tmp_object = rows[("workspace", "unit/out.o.tmp")]
    assert tmp_object["status"] == "absent" and tmp_object["renamed_away"] is True
    assert rows[("image", "/usr/include/stdio.h")] == {
        **rows[("image", "/usr/include/stdio.h")], "status": "immutable", "image_id": IMAGE}
    assert "sha256" not in rows[("image", "/usr/include/stdio.h")]
    assert rows[("ephemeral", "/tmp/cc1.s")]["status"] == "ephemeral"
    assert rows[("workspace", "unit/cfg.txt")]["modified_after_read"] is True
    assert not any(key[1].endswith("missing.h") for key in rows)
    assert ("virtual", "/proc/self/status") not in rows and not any(key[0] == "capture" for key in rows)
    counts = summary["counts"]
    assert counts["failed_opens"] == 1 and counts["snapshot_reused"] == 1
    assert counts["hashed_files"] == 3 and counts["image_files"] == 1 and counts["absent"] == 1
    assert counts["modified_after_read"] == 1 and counts["virtual_events"] == 1
    assert counts["capture_events"] == 1 and counts["directories"] == 1
    assert rows[("workspace", "unit")]["status"] == "directory"
    assert summary["gaps"] == [] and summary["capped"] is False
    assert set(summary["timing_seconds"]) == {"resolve", "hash", "total"}


def test_inventory_rehashes_snapshot_files_the_build_wrote_or_resized(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "unit").mkdir(parents=True)
    (workspace / "unit" / "a.c").write_text("changed\n", encoding="utf-8")
    snapshot = {"unit/a.c": {"sha256": "0" * 64, "size_bytes": 3}}
    events = [_event(1, "file_open", path="a.c", resolved="/workspace/unit/a.c", access="read", result=3)]
    output = tmp_path / "files.jsonl"
    build_file_inventory(events, _roots(workspace), output, snapshot=snapshot, count_limit=10)
    (row,) = _rows(output)
    assert row["status"] == "hashed" and row["sha256"] == hashlib.sha256(b"changed\n").hexdigest()


def test_inventory_retention_limit_is_a_named_gap(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    events = [_event(index, "file_open", path=f"/usr/lib/{index}.so", resolved=f"/usr/lib/{index}.so",
                     access="read", result=3) for index in range(1, 6)]
    summary = build_file_inventory(events, _roots(workspace), tmp_path / "files.jsonl", snapshot=None,
                                   count_limit=2)
    assert summary["capped"] is True and summary["counts"]["retained"] == 2
    assert summary["gaps"] == ["file inventory retention limit reached"]


def test_response_files_are_retained_only_when_the_process_read_them(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "unit" / "obj").mkdir(parents=True)
    (workspace / "unit" / "obj" / "a.rsp").write_text("-DVALUE=1 /I include\n", encoding="utf-8")
    (workspace / "unit" / "big.rsp").write_text("x" * 64, encoding="utf-8")
    capture = tmp_path / "capture"
    capture.mkdir()
    events = [
        _event(1, "process_exec", argv=["clang-cl", "@obj/a.rsp", "@not-a-response-file"]),
        _event(2, "file_open", path="obj/a.rsp", resolved="/workspace/unit/obj/a.rsp", access="read",
               result=3),
        _event(3, "process_exec", pid=20, argv=["clang-cl", "@/workspace/unit/obj/a.rsp"]),
        _event(4, "file_open", pid=20, path="/workspace/unit/obj/a.rsp",
               resolved="/workspace/unit/obj/a.rsp", access="read", result=3),
        _event(5, "process_exec", pid=30, argv=["link", "@gone.rsp", "@/tmp/t.rsp", "@big.rsp"]),
        _event(6, "file_open", pid=30, path="gone.rsp", resolved="/workspace/unit/gone.rsp",
               access="read", result=3),
        _event(7, "file_open", pid=30, path="/tmp/t.rsp", resolved="/tmp/t.rsp", access="read", result=4),
        _event(8, "file_open", pid=30, path="big.rsp", resolved="/workspace/unit/big.rsp", access="read",
               result=5),
    ]
    snapshots, gaps = snapshot_response_files(events, _roots(workspace), capture,
                                              count_limit=10, bytes_limit=32)
    (entry,) = snapshots
    assert entry["path"] == "unit/obj/a.rsp"
    assert (capture / entry["uri"]).read_text(encoding="utf-8") == "-DVALUE=1 /I include\n"
    assert [reference["pid"] for reference in entry["references"]] == [10, 20]
    assert gaps == [
        "response file was removed before it could be retained: unit/gone.rsp",
        "response file outside the workspace was not retained: /tmp/t.rsp",
        "response file exceeds the 32-byte bound: unit/big.rsp",
    ]


def test_captured_build_records_verified_inventory_and_sanitized_response_files(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "unit").mkdir(parents=True)
    (workspace / "unit" / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")

    def behavior(argv, workspace_root, _directory, _environment, container):
        unit = workspace_root / "unit"
        (unit / "build").mkdir()
        (unit / "build" / "args.rsp").write_text(f"-DTOKEN={SYNTHETIC_SECRET}\n", encoding="utf-8")
        (unit / "build" / "safe.rsp").write_text("-O2\n", encoding="utf-8")
        (unit / "build" / "main.o").write_bytes(b"object")
        container.exec("/usr/bin/clang", ["clang", "@build/args.rsp", "@build/safe.rsp", "-c", "main.c"])
        container.syscall('openat(AT_FDCWD</workspace/unit>, "build/args.rsp", O_RDONLY)',
                          "3</workspace/unit/build/args.rsp>")
        container.syscall('openat(AT_FDCWD</workspace/unit>, "build/safe.rsp", O_RDONLY)',
                          "3</workspace/unit/build/safe.rsp>")
        container.syscall('openat(AT_FDCWD</workspace/unit>, "main.c", O_RDONLY)',
                          "3</workspace/unit/main.c>")
        container.syscall('openat(AT_FDCWD</workspace/unit>, "inc/none.h", O_RDONLY)',
                          "-1 ENOENT (No such file or directory)")
        container.syscall('openat(AT_FDCWD</workspace/unit>, "build/main.o", O_WRONLY|O_CREAT|O_TRUNC, 0666)',
                          "4</workspace/unit/build/main.o>")
        container.syscall('openat(AT_FDCWD</workspace/unit>, "/usr/include/stdio.h", O_RDONLY)',
                          "5</usr/include/stdio.h>")
        return 0, b"", b""

    executor = simulated_executor(BuildProfile("native", "build-cpp:local", IMAGE, "10001:10001"), behavior)
    capture = tmp_path / "capture"
    scope = CaptureScope("2026-10-10-0001", "job_project_build", "attempt_0001", "build-unit-c", "native")
    main = workspace / "unit" / "main.c"
    snapshot = {"unit/main.c": {"sha256": hashlib.sha256(main.read_bytes()).hexdigest(),
                                "size_bytes": main.stat().st_size, "mtime_ns": main.stat().st_mtime_ns}}
    result = executor.execute_captured(
        ("clang", "-c", "main.c"), workspace=workspace, working_directory="unit", environment={},
        capture_directory=capture, capture_config=BuildCaptureConfig(
            "ptrace", 1000, 32, 4096, True, 128, 16384, (), 1024, 100, 100),
        scope=scope, snapshot_files=snapshot)
    record = json.loads(result.capture_record.read_text(encoding="utf-8"))
    verify_capture_record(result.capture_record, run_root=tmp_path, scope=scope)
    inventory = record["file_inventory"]
    assert inventory["uri"] == "files.jsonl" and inventory["counts"]["failed_opens"] == 1
    assert inventory["counts"]["snapshot_reused"] == 1 and inventory["counts"]["image_files"] == 1
    rows = {row["path"]: row for row in _rows(capture / "files.jsonl")}
    assert rows["unit/main.c"]["status"] == "snapshot" and rows["unit/build/main.o"]["status"] == "hashed"
    responses = {entry["path"]: entry for entry in record["response_files"]["records"]}
    assert set(responses) == {"unit/build/args.rsp", "unit/build/safe.rsp"}
    assert (capture / responses["unit/build/safe.rsp"]["uri"]).read_text(encoding="utf-8") == "-O2\n"
    # The secret-bearing response file went through the capture secret scan and was sanitized.
    assert SYNTHETIC_SECRET not in (capture / responses["unit/build/args.rsp"]["uri"]).read_text(
        encoding="utf-8")
    assert SYNTHETIC_SECRET not in "".join(
        path.read_text(encoding="utf-8", errors="replace") for path in capture.rglob("*") if path.is_file())
