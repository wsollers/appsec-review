"""Debug retention of raw strace files through the real capture executor."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import BuildCaptureConfig
from appsec_review.container_runtime import BuildProfile, CaptureScope, verify_capture_record
from appsec_review.container_runtime.build_capture import (
    REQUIRED_EVENT_KINDS, BuildExecutionRecorder, CaptureIntegrityError, record_strace_files,
)
from appsec_review.container_runtime.raw_traces import reference_raw_traces, retain_raw_traces
from tests.capture_fakes import SYNTHETIC_SECRET, simulated_executor


SCOPE = CaptureScope("2026-10-15-0001", "job_project_build", "attempt_0001", "build-unit-dotnet", "dotnet")
# Row shapes taken from a real `dotnet build` capture of multivuln case-014 in the .NET image:
# the CLR debugger-pipe thread blocks in openat on a FIFO and is killed by exit_group, so strace
# prints its first (and only) row with an unknown result.
CLR_PIPE_ROW = ('1792035762.201566 openat(AT_FDCWD</workspace>, "/tmp/clr-debug-pipe-12-262485-in", '
                'O_RDONLY) = ?\n')
UNPARSEABLE_ROW = '1792035762.201600 openat(AT_FDCWD, 0x7ffd1234, O_RDONLY) = 3\n'


def _config(**changes) -> BuildCaptureConfig:
    base = BuildCaptureConfig("ptrace", 1000, 32, 4096, True, 128, 16384, ("NUGET_AUTH_TOKEN",),
                              1024, 100, 100, retain_raw_traces=True, raw_trace_bytes_limit=1 << 20)
    return dataclasses.replace(base, **changes)


def _capture(tmp_path: Path, config: BuildCaptureConfig, *, rows: dict[int, str] | None = None,
             secret_in_trace: bool = False, envp: tuple[str, ...] = ()):
    workspace = tmp_path / "workspace"
    (workspace / "unit").mkdir(parents=True, exist_ok=True)

    def behavior(_argv, _workspace, _directory, _environment, container):
        container.exec("/usr/bin/dotnet", ["dotnet", "build"], envp=envp or None)
        container.open("/workspace/unit/case.csproj")
        if secret_in_trace:
            container.open(f"/workspace/unit/{SYNTHETIC_SECRET}.cs")
        for pid, text in (rows or {}).items():
            with (container.root / f"trace.{pid}").open("a", encoding="utf-8") as stream:
                stream.write(text)
        return 0, b"Build succeeded.\n", b""

    executor = simulated_executor(
        BuildProfile("dotnet", "build-dotnet:local", "sha256:" + "c" * 64, "10001:10001"), behavior)
    capture = tmp_path / "capture"
    result = executor.execute_captured(
        ("dotnet", "build"), workspace=workspace, working_directory="unit", environment={},
        capture_directory=capture, capture_config=config, scope=SCOPE)
    record = json.loads(result.capture_record.read_text(encoding="utf-8"))
    return capture, result, record


def test_real_clr_debug_pipe_first_row_is_a_complete_unfinished_open(tmp_path: Path) -> None:
    recorder = BuildExecutionRecorder(tmp_path / "capture", SCOPE, _config(),
                                      {"backend": "ptrace", "image_id": "sha256:" + "a" * 64,
                                       "event_kinds": sorted(REQUIRED_EVENT_KINDS)})
    trace = tmp_path / "trace.17"
    trace.write_text(CLR_PIPE_ROW, encoding="utf-8")
    assert record_strace_files((trace,), recorder) == ()
    recorder.flush()
    (event,) = [json.loads(line) for line in (recorder.root / "events.jsonl").read_text().splitlines()]
    assert event["kind"] == "file_open" and event["path"] == "/tmp/clr-debug-pipe-12-262485-in"
    assert event["result"] == -1 and event["unfinished"] is True


def test_raw_traces_are_retained_hashed_and_verified_when_enabled(tmp_path: Path) -> None:
    capture, _result, record = _capture(tmp_path, _config(), rows={17: CLR_PIPE_ROW})
    raw = record["raw_traces"]
    assert raw["enabled"] is True and raw["truncated"] is False
    assert raw["bytes_limit"] == 1 << 20 and raw["observed_files"] == len(raw["records"]) >= 2
    item = next(entry for entry in raw["records"] if entry["source"] == "trace.17")
    retained = capture / item["uri"]
    assert item["uri"] == "raw-traces/trace.17" and retained.read_text(encoding="utf-8") == CLR_PIPE_ROW
    assert item["sha256"] == hashlib.sha256(retained.read_bytes()).hexdigest()
    assert item["retained_lines"] == 1 and item["truncated"] is False
    assert not tuple(capture.glob("trace*"))
    assert record["coverage"] == {"complete": True, "gaps": []}
    verified = verify_capture_record(capture / "record.json", run_root=tmp_path, scope=SCOPE)
    assert verified.document["raw_traces"] == raw

    retained.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(CaptureIntegrityError):
        verify_capture_record(capture / "record.json", run_root=tmp_path, scope=SCOPE)


def test_raw_traces_are_discarded_when_disabled(tmp_path: Path) -> None:
    capture, _result, record = _capture(tmp_path, _config(retain_raw_traces=False), rows={17: CLR_PIPE_ROW})
    assert record["raw_traces"] == {"enabled": False}
    assert not (capture / "raw-traces").exists() and not tuple(capture.glob("trace*"))
    verify_capture_record(capture / "record.json", run_root=tmp_path, scope=SCOPE)


def test_raw_trace_byte_cap_keeps_whole_lines_and_flags_truncation(tmp_path: Path) -> None:
    rows = "".join(f"1792035762.2{index:05d} chdir(\"/workspace/unit\") = 0\n" for index in range(40))
    trace = tmp_path / "trace.30"
    trace.write_text(rows, encoding="utf-8")
    later = tmp_path / "trace.31"
    later.write_text(CLR_PIPE_ROW, encoding="utf-8")
    line = len(rows.splitlines(keepends=True)[0])
    raw = retain_raw_traces(tmp_path, (later, trace), bytes_limit=line * 3 + 5)
    first, second = raw["records"]
    assert first["source"] == "trace.30" and first["truncated"] is True
    assert first["retained_lines"] == 3 and first["retained_bytes"] == line * 3
    assert (tmp_path / first["uri"]).read_bytes() == rows.encode()[:line * 3]
    assert second == {"source": "trace.31", "bytes": len(CLR_PIPE_ROW), "retained": False,
                      "retained_bytes": 0, "retained_lines": 0, "truncated": True}
    assert raw["truncated"] is True and raw["retained_bytes"] <= raw["bytes_limit"]
    assert raw["observed_bytes"] == len(rows) + len(CLR_PIPE_ROW)


def test_raw_traces_pass_through_secret_scan_and_envp_redaction(tmp_path: Path) -> None:
    capture, result, record = _capture(
        tmp_path, _config(), secret_in_trace=True,
        envp=("PATH=/usr/bin", "NUGET_AUTH_TOKEN=not-a-gitleaks-pattern-but-configured"))
    raw_text = "".join(path.read_text(encoding="utf-8", errors="replace")
                       for path in (capture / "raw-traces").iterdir())
    assert SYNTHETIC_SECRET not in raw_text
    assert "not-a-gitleaks-pattern-but-configured" not in raw_text
    assert record["secret_scan"]["findings"]["count"] > 0
    for item in record["raw_traces"]["records"]:
        assert item["sha256"] == hashlib.sha256((capture / item["uri"]).read_bytes()).hexdigest()


def test_unparsed_row_gap_names_the_retained_file_and_line(tmp_path: Path) -> None:
    _capture_root, _result, record = _capture(tmp_path, _config(), rows={21: CLR_PIPE_ROW + UNPARSEABLE_ROW})
    assert record["coverage"]["gaps"] == [
        "unparsed openat row: trace.21:2 (retained as raw-traces/trace.21 line 2)"]
    disabled = tmp_path / "disabled"
    _capture_root, _result, record = _capture(disabled, _config(retain_raw_traces=False),
                                              rows={21: UNPARSEABLE_ROW})
    assert record["coverage"]["gaps"] == [
        "unparsed openat row: trace.21:1 "
        "(raw trace not retained: build_capture.retain_raw_traces is disabled)"]


def test_gap_reference_distinguishes_truncated_and_omitted_traces() -> None:
    raw = {"records": [{"source": "trace.1", "retained": True, "uri": "raw-traces/trace.1",
                        "retained_lines": 2},
                       {"source": "trace.2", "retained": False, "retained_lines": 0}]}
    assert reference_raw_traces(("unparsed openat row: trace.1:3", "unparsed connect row: trace.2:1",
                                 "kernel collector reported dropped events"), raw) == (
        "unparsed openat row: trace.1:3 (raw-traces/trace.1 was truncated before line 3)",
        "unparsed connect row: trace.2:1 (raw trace not retained: raw_trace_bytes_limit reached)",
        "kernel collector reported dropped events")


def test_raw_trace_settings_are_typed_and_bounded() -> None:
    with pytest.raises(ValueError, match="retain_raw_traces"):
        _config(retain_raw_traces="yes")
    for limit in (0, 2 * 1024 * 1024 * 1024, 1.5):
        with pytest.raises(ValueError, match="raw_trace_bytes_limit"):
            _config(raw_trace_bytes_limit=limit)


def test_solution_build_with_many_processes_keeps_every_trace_and_unfinished_open(tmp_path: Path) -> None:
    """A synthetic multi-project .sln build: several MSBuild nodes and csc processes, each with
    CLR debugger-pipe threads killed mid-openat, all normalize without gaps and are retained."""
    projects = ("src/Api/Api.csproj", "src/Core/Core.csproj", "tests/Core.Tests/Core.Tests.csproj")
    rows: dict[int, str] = {}
    for index, project in enumerate(projects):
        node, thread = 300 + index * 10, 301 + index * 10
        rows[node] = (f'1792035762.3{index}0001 openat(AT_FDCWD</workspace/app>, '
                      f'"/workspace/app/{project}", O_RDONLY|O_CLOEXEC) = 9</workspace/app/{project}>\n')
        rows[thread] = (f'1792035762.3{index}0002 openat(AT_FDCWD</workspace/app>, '
                        f'"/tmp/clr-debug-pipe-{node}-1-in", O_RDONLY) = ?\n')
    capture, _result, record = _capture(tmp_path, _config(), rows=rows)
    assert record["coverage"] == {"complete": True, "gaps": []}
    retained = {item["source"] for item in record["raw_traces"]["records"] if item["retained"]}
    assert {f"trace.{pid}" for pid in rows} <= retained
    events = [json.loads(line) for line in (capture / "events.jsonl").read_text().splitlines()]
    opened = {event["path"] for event in events if event["kind"] == "file_open"}
    assert {f"/workspace/app/{project}" for project in projects} <= opened
    assert sum(1 for event in events if event.get("unfinished")) >= len(projects)
