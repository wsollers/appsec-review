from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import BuildCaptureConfig
from appsec_review.container_runtime import (
    BuildExecutionRecorder, BuildProfile, CaptureIntegrityError, CaptureScope, verify_capture_record,
)
from appsec_review.container_runtime.build_capture import record_strace_files
from tests.capture_fakes import simulated_executor


def _recorder(tmp_path: Path, *, event_limit: int = 20) -> BuildExecutionRecorder:
    return BuildExecutionRecorder(
        tmp_path / "capture", CaptureScope(
            "2026-10-09-0001", "job_project_build", "attempt_0001", "build-unit-cpp", "native"),
        BuildCaptureConfig("ptrace", event_limit, 3, 64, True, 8, 256, ("SECRET_VALUE",),
                           16, 10, 10),
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
        '1700000000.000005 exit_group(0) = ?\n'
        '1700000000.000006 execve("/opt/missing/ld", ["ld", "main.o"], ["NORMAL=value"]) = '
        '-1 ENOENT (No such file or directory)\n', encoding="utf-8")
    assert record_strace_files((trace,), recorder) == ()
    stdout, stderr = recorder.root / "stdout", recorder.root / "stderr"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"")
    path = recorder.finish(argv=("clang++", "main.cpp"), working_directory="native",
                           exit_code=0, timed_out=False, stdout_path=stdout, stderr_path=stderr)
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["events"]["counts"] == {
        "connect": 1, "file_open": 1, "process_exec": 2, "process_exit": 1, "process_fork": 1}
    event_rows = [json.loads(line) for line in (recorder.root / "events.jsonl").read_text().splitlines()]
    process_exec = next(row for row in event_rows if row["kind"] == "process_exec")
    assert process_exec["argv"] == ["clang++", "main.cpp"]
    # The kernel-resolved path and outcome separate a real execution from a PATH search miss.
    assert process_exec["executable"] == "/usr/bin/clang++" and process_exec["result"] == 0
    missed = [row for row in event_rows if row["kind"] == "process_exec"][1]
    assert missed["executable"] == "/opt/missing/ld" and missed["result"] == -1
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


def test_strace_normalizer_accepts_exact_detach_metadata_but_rejects_malformed_rows(
        tmp_path: Path) -> None:
    recorder = _recorder(tmp_path)
    trace = tmp_path / "trace.42"
    trace.write_text(
        "1700000000.000001 ???( <detached ...>\n"
        "1700000000.000002 exit_group(0 <detached ...>\n",
        encoding="utf-8",
    )
    assert record_strace_files((trace,), recorder) == ()
    malformed = tmp_path / "trace.43"
    malformed.write_text("1700000000.000002 ???( malformed\n", encoding="utf-8")
    assert record_strace_files((malformed,), recorder) == ("unparsed trace row: trace.43:1",)


def _capture(tmp_path: Path) -> tuple[Path, Path, CaptureScope]:
    run_root = tmp_path / "run"
    workspace = run_root / "workspace"
    (workspace / "unit").mkdir(parents=True)
    scope = CaptureScope("2026-10-09-0001", "job_language_build", "attempt_0001", "build-unit-rust", "rust")

    def behavior(argv, _workspace, _directory, _environment, container):
        container.exec("/usr/bin/rustc", ["rustc", "main.rs"])
        container.tool_call("rustc", ["main.rs"], executable="/usr/bin/rustc", stdout=b"compiled")
        return 0, b"out", b"err"

    executor = simulated_executor(
        BuildProfile("rust", "build-rust:local", "sha256:" + "a" * 64, "10001:10001"), behavior)
    result = executor.execute_captured(
        ("rustc", "main.rs"), workspace=workspace, working_directory="unit", environment={},
        capture_directory=run_root / "capture" / "command-001",
        capture_config=BuildCaptureConfig("ptrace", 100, 32, 4096, True, 128, 16384, (), 1024, 100, 100),
        scope=scope)
    return run_root, result.capture_record, scope


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rewrite(record: Path, change) -> None:
    document = json.loads(record.read_text(encoding="utf-8"))
    change(document)
    record.write_text(json.dumps(document), encoding="utf-8")


def test_capture_verification_returns_hash_bound_identity_and_parsed_members(tmp_path: Path) -> None:
    run_root, record, scope = _capture(tmp_path)
    verified = verify_capture_record(record, run_root=run_root, scope=scope)
    assert verified.identity["path"] == "capture/command-001/record.json"
    assert verified.identity["sha256"] == _digest(record) and verified.identity["complete"] is True
    findings = run_root / verified.identity["secret_findings"]["path"]
    assert verified.identity["secret_findings"] == {
        "path": "capture/command-001/secret-scan/findings.json", "sha256": _digest(findings), "count": 0}
    assert verified.gaps == ()
    assert [event["executable"] for event in verified.events() if event["kind"] == "process_exec"] == [
        "/usr/bin/rustc"]
    assert [call["record"]["tool"] for call in verified.tool_calls] == ["rustc"]
    assert verified.execution["report"]["uri"] == "gitleaks.json"


def _tamper_event_schema(record: Path) -> None:
    events = record.parent / "events.jsonl"
    events.write_text(events.read_text(encoding="utf-8").replace(
        "appsec-review/build-syscall-event/1", "appsec-review/build-syscall-event/0"), encoding="utf-8")
    _rewrite(record, lambda document: document["events"].update(sha256=_digest(events)))


def _tamper_event_symlink(record: Path) -> None:
    events = record.parent / "events.jsonl"
    outside = record.parent.parent / "outside-events.jsonl"
    events.rename(outside)
    events.symlink_to(outside)


def _tamper_tool_schema(record: Path) -> None:
    tool = next((record.parent / "tool-calls").glob("*/record.json"))
    _rewrite(tool, lambda document: document.update(schema="appsec-review/build-tool-call/0"))
    _rewrite(record, lambda document: document["tool_calls"]["records"][0].update(sha256=_digest(tool)))


def _tamper_findings_schema(record: Path) -> None:
    findings = record.parent / "secret-scan" / "findings.json"
    _rewrite(findings, lambda document: document.update(retained=7))
    _rewrite(record, lambda document: document["secret_scan"]["findings"].update(sha256=_digest(findings)))


def _tamper_scanner_receipt(record: Path) -> None:
    execution = record.parent / "secret-scan" / "execution.json"
    _rewrite(execution, lambda document: document.update(schema="appsec-review/other/1"))
    _rewrite(record, lambda document: document["secret_scan"]["execution"].update(sha256=_digest(execution)))


@pytest.mark.parametrize(("tamper", "message"), [
    (lambda record: (record.parent / "events.jsonl").write_text("", encoding="utf-8"),
     "member identity changed"),
    (_tamper_event_schema, "syscall event schema is invalid"),
    (lambda record: _rewrite(record, lambda document: document["events"].update(retained=99)),
     "syscall event count is inconsistent"),
    (lambda record: _rewrite(record, lambda document: document["events"].update(uri="../command-001/events.jsonl")),
     "URI is not normalized"),
    (_tamper_event_symlink, "member escaped its root"),
    (lambda record: (record.parent / "stderr").write_bytes(b"changed"), "member identity changed"),
    (lambda record: next((record.parent / "tool-calls").glob("*/stdout")).write_bytes(b"changed"),
     "member identity changed"),
    (_tamper_tool_schema, "tool-call schema is invalid"),
    (lambda record: (record.parent / "secret-scan" / "findings.json").write_text("{}", encoding="utf-8"),
     "member identity changed"),
    (_tamper_findings_schema, "secret findings are invalid"),
    (_tamper_scanner_receipt, "secret scan receipt is invalid"),
    (lambda record: (record.parent / "secret-scan" / "gitleaks.json").write_text("[{}]", encoding="utf-8"),
     "member identity changed"),
    (lambda record: _rewrite(record, lambda document: document.update(schema="appsec-review/other/1")),
     "record identity is invalid"),
    (lambda record: _rewrite(record, lambda document: document["scope"].update(attempt_id="attempt_0002")),
     "record identity is invalid"),
    (lambda record: _rewrite(record, lambda document: document["coverage"].update(gaps=["hidden"])),
     "coverage disposition is inconsistent"),
    (lambda record: record.write_text("not json", encoding="utf-8"), "capture is unreadable"),
], ids=["event-hash", "event-schema", "event-count", "member-path", "member-symlink", "stream-hash",
        "tool-stream-hash", "tool-schema", "findings-hash", "findings-schema", "scanner-receipt-schema",
        "gitleaks-report-hash", "record-schema", "record-scope", "coverage", "record-unreadable"])
def test_capture_verification_rejects_hash_schema_path_and_scope_tampering(
        tmp_path: Path, tamper, message: str) -> None:
    run_root, record, scope = _capture(tmp_path)
    tamper(record)
    with pytest.raises(CaptureIntegrityError, match=message):
        verify_capture_record(record, run_root=run_root, scope=scope)


def test_capture_verification_binds_the_callers_scope_and_run(tmp_path: Path) -> None:
    run_root, record, scope = _capture(tmp_path)
    for other in (CaptureScope(scope.run_id, "job_project_build", scope.attempt_id, scope.build_unit_id, "rust"),
                  CaptureScope("2026-10-09-0002", scope.job_id, scope.attempt_id, scope.build_unit_id, "rust"),
                  CaptureScope(scope.run_id, scope.job_id, scope.attempt_id, "build-unit-other", "rust")):
        with pytest.raises(CaptureIntegrityError, match="record identity is invalid"):
            verify_capture_record(record, run_root=run_root, scope=other)
    elsewhere = tmp_path / "other-run"
    elsewhere.mkdir()
    with pytest.raises(CaptureIntegrityError, match="escaped the run"):
        verify_capture_record(record, run_root=elsewhere, scope=scope)
