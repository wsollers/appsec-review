from __future__ import annotations

import json
from pathlib import Path

from appsec_review.config import BuildCaptureConfig
from appsec_review.container_runtime import BuildExecutionRecorder, CaptureScope
from appsec_review.container_runtime.build_capture import record_strace_files


def _recorder(tmp_path: Path, *, event_limit: int = 20) -> BuildExecutionRecorder:
    return BuildExecutionRecorder(
        tmp_path / "capture", CaptureScope(
            "2026-10-09-0001", "job_project_build", "attempt_0001", "build-unit-cpp", "native"),
        BuildCaptureConfig("ptrace", event_limit, 3, 64, True, 8, 256, ("SECRET_VALUE",),
                           16, 10, 1024, 10),
        {"backend": "ptrace", "image_id": "sha256:" + "a" * 64,
         "event_kinds": sorted(("process_fork", "process_exec", "process_exit", "file_open", "connect"))},
    )


def test_execution_record_retains_required_events_and_stream_hashes(tmp_path: Path) -> None:
    recorder = _recorder(tmp_path)
    events = (
        {"kind": "process_fork", "monotonic_ns": 1, "pid": 10, "tid": 10, "child_pid": 11},
        {"kind": "process_exec", "monotonic_ns": 2, "pid": 11, "tid": 11,
         "argv": ["clang++", "main.cpp", "-o", "app"]},
        {"kind": "file_open", "monotonic_ns": 3, "pid": 11, "tid": 11,
         "path": "/workspace/native/main.cpp"},
        {"kind": "connect", "monotonic_ns": 4, "pid": 11, "tid": 11,
         "address_family": 2, "address": "192.0.2.1", "port": 443, "result": 0},
        {"kind": "process_exit", "monotonic_ns": 5, "pid": 11, "tid": 11, "exit_code": 0},
    )
    assert all(recorder.add(event) for event in events)
    stdout, stderr = recorder.root / "stdout", recorder.root / "stderr"
    stdout.write_bytes(b"ok\n")
    stderr.write_bytes(b"")
    record_path = recorder.finish(
        argv=("cmake", "--build", "build"), working_directory="native", exit_code=0,
        timed_out=False, stdout_path=stdout, stderr_path=stderr)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["schema"] == "appsec-review/build-execution-record/1"
    assert record["events"]["counts"] == {
        "connect": 1, "file_open": 1, "process_exec": 1, "process_exit": 1, "process_fork": 1}
    assert record["coverage"] == {"complete": True, "gaps": []}
    rows = [json.loads(line) for line in (recorder.root / "events.jsonl").read_text().splitlines()]
    assert rows[1]["argv"] == ["clang++", "main.cpp", "-o"]
    assert rows[1]["argv_truncated"] is True
    assert rows[2]["path_truncated"] is True


def test_execution_record_names_caps_drops_invalid_and_missing_events(tmp_path: Path) -> None:
    recorder = _recorder(tmp_path, event_limit=1)
    assert recorder.add({"kind": "process_exec", "monotonic_ns": 1, "pid": 1, "tid": 1,
                         "argv": ["clang++"]})
    assert not recorder.add({"kind": "file_open", "monotonic_ns": 2, "pid": 1, "tid": 1,
                             "path": "/workspace/main.cpp"})
    assert not recorder.add({"kind": "unknown", "monotonic_ns": 3, "pid": 1, "tid": 1})
    stdout, stderr = recorder.root / "stdout", recorder.root / "stderr"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"warning")
    path = recorder.finish(argv=("clang++",), working_directory=".", exit_code=1,
                           timed_out=False, stdout_path=stdout, stderr_path=stderr,
                           collector_dropped=2, collector_errors=("collector shutdown was forced",))
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["events"]["observed"] == 3 and record["events"]["retained"] == 1
    assert record["events"]["capped"] is True
    assert record["coverage"]["complete"] is False
    assert len(record["coverage"]["gaps"]) == 4


def test_strace_normalizer_captures_process_file_and_egress_calls(tmp_path: Path) -> None:
    recorder = _recorder(tmp_path)
    trace = tmp_path / "trace.42"
    trace.write_text(
        '1700000000.000001 execve("/usr/bin/clang++", ["clang++", "main.cpp"], '
        '["NORMAL=value", "SECRET_VALUE=do-not-retain"]) = 0\n'
        '1700000000.000002 openat(AT_FDCWD, "/workspace/native/main.cpp", O_RDONLY) = 3\n'
        '1700000000.000003 clone(child_stack=NULL, flags=SIGCHLD) = 43\n'
        '1700000000.000004 connect(3, {sa_family=AF_INET, sin_port=htons(443), '
        'sin_addr=inet_addr("192.0.2.1")}, 16) = 0\n'
        '1700000000.000005 exit_group(0) = ?\n', encoding="utf-8")
    assert record_strace_files((trace,), recorder) == ()
    stdout, stderr = recorder.root / "stdout", recorder.root / "stderr"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"")
    path = recorder.finish(argv=("clang++", "main.cpp"), working_directory="native",
                           exit_code=0, timed_out=False, stdout_path=stdout, stderr_path=stderr)
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["events"]["counts"] == {
        "connect": 1, "file_open": 1, "process_exec": 1, "process_exit": 1, "process_fork": 1}
    event_rows = [json.loads(line) for line in (recorder.root / "events.jsonl").read_text().splitlines()]
    process_exec = next(row for row in event_rows if row["kind"] == "process_exec")
    assert process_exec["argv"] == ["clang++", "main.cpp"]
    assert process_exec["envp"] == [
        {"name": "NORMAL", "redacted": False, "value": "value"},
        {"name": "SECRET_VALUE", "redacted": True, "value": "<redacted>"},
    ]
    assert process_exec["envp_captured"] is True
    assert process_exec["envp_redacted_names"] == ["SECRET_VALUE"]
    assert "do-not-retain" not in (recorder.root / "events.jsonl").read_text(encoding="utf-8")
    connect = next(row for row in event_rows if row["kind"] == "connect")
    assert connect["address_family"] == 2 and connect["address"] == "192.0.2.1"
    assert connect["port"] == 443 and connect["result"] == 0
