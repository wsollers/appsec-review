from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from appsec_review.jobs.job_language_build import dotnet, native, rust
from appsec_review.jobs.job_language_build.capture import (
    CapturedBuildDescriptor,
    ReconciliationLimits,
    ToolIdentity,
    reconcile_captured_build,
)


class Capture:
    def __init__(self, events: Sequence[object], *, calls: Sequence[Mapping[str, Any]] = (),
                 observed: int | None = None, call_observed: int | None = None,
                 gaps: Sequence[str] = ()) -> None:
        self._events = tuple(events)
        self.tool_calls = tuple(calls)
        self.gaps = tuple(gaps)
        self.identity = {"sha256": "a" * 64}
        self.document = {
            "events": {"observed": len(events) if observed is None else observed,
                       "retained": len(events)},
            "tool_calls": {"observed": len(calls) if call_observed is None else call_observed,
                           "retained": len(calls)},
        }

    def events(self):
        yield from self._events


def _row(tool: str, kind: str, argv: Sequence[str], _workspace: Path, _directory: str,
         origin: str) -> dict[str, Any]:
    return {"tool": tool, "tool_kind": kind, "argv": list(argv), "argv_sha256": "b" * 64,
            "inputs": [], "outputs": [], "origin": origin, "mapping_confidence": 1.0}


def _classify(executable: str, _argv: Sequence[str]) -> ToolIdentity | None:
    name = PurePosixPath(executable).name
    return ToolIdentity(name, "compiler") if name in {"cc", "clang"} else None


DESCRIPTOR = CapturedBuildDescriptor(
    family="fixture", capture_identity="fixture/capture/1",
    provenance_schema="fixture/provenance/1", catalog_label="fixture",
    classify_tool=_classify, build_invocation=_row,
    missing_tool_gap="fixture compiler was not observed",
)


def _exec(executable: str, argv: Sequence[str], *, result: int = 0, ordinal: int = 1,
          truncated: bool = False, redacted_names: Sequence[str] = ()) -> dict[str, Any]:
    return {"kind": "process_exec", "ordinal": ordinal, "executable": executable,
            "argv": list(argv), "argv_truncated": truncated, "result": result,
            "envp_captured": True, "envp_redacted_names": list(redacted_names)}


def _call(tool: str, argv: Sequence[str]) -> dict[str, Any]:
    return {"uri": f"tool-calls/{tool}/record.json", "sha256": "c" * 64,
            "record": {"tool": tool, "argv": list(argv), "exit_code": 0,
                       "stdout": {"sha256": "d" * 64},
                       "stderr": {"sha256": "e" * 64}}}


def test_generic_reconciler_success_failed_exec_and_secondary_wrapper(tmp_path: Path) -> None:
    capture = Capture([
        _exec("/usr/bin/cc", ["cc", "-c", "ok.c"]),
        _exec("/missing/cc", ["cc", "-c", "missing.c"], result=-1),
    ], calls=[_call("cc", ["cc", "-c", "ok.c"])])
    result = reconcile_captured_build([(1, capture)], tmp_path, ".", DESCRIPTOR)
    assert len(result.rows) == 1
    assert result.rows[0]["mapping"] == "syscall-process-exec+tool-call"
    assert result.facts["process_exec_events"] == 2
    assert result.facts["failed_exec_events"] == 1


def test_generic_reconciler_redaction_envp_connect_and_wrapper_only_negative(
        tmp_path: Path) -> None:
    capture = Capture([
        {"kind": "connect", "ordinal": 1, "address": "192.0.2.1", "port": 443},
        _exec("<redacted: secret scan disposition>",
              ["<redacted: secret scan disposition>"], redacted_names=["TOKEN"]),
        _exec("/usr/bin/clang", ["clang", "-c", "ok.c"], redacted_names=["PASSWORD"]),
    ], calls=[_call("cc", ["cc", "-c", "phantom.c"])])
    result = reconcile_captured_build([(1, capture)], tmp_path, ".", DESCRIPTOR)
    assert [row["tool"] for row in result.rows] == ["clang"]
    assert result.facts["redacted_exec_events"] == 1
    assert result.facts["connect_events"] == 1
    assert result.facts["envp_events"] == 2
    assert result.facts["envp_redacted_names"] == ["PASSWORD", "TOKEN"]
    assert result.facts["unreconciled_tool_calls"] == 1
    assert any("no matching successful process-exec" in gap for gap in result.gaps)
    assert all(row["tool"] != "cc" for row in result.rows)


def test_generic_reconciler_accounts_for_capture_loss_and_row_truncation(tmp_path: Path) -> None:
    capture = Capture([
        _exec("/usr/bin/cc", ["cc", "-c", "one.c"]),
        _exec("/usr/bin/clang", ["clang", "-c", "two.c"]),
    ], observed=5, call_observed=3, gaps=["syscall event retention limit reached"])
    result = reconcile_captured_build(
        [(1, capture)], tmp_path, ".", DESCRIPTOR,
        limits=ReconciliationLimits(invocation_count=1))
    assert len(result.rows) == 1
    assert result.facts["event_records_lost"] == 3
    assert result.facts["tool_call_records_lost"] == 3
    assert result.facts["capture_gap_count"] == 1
    assert any("catalog truncated" in gap for gap in result.gaps)


def test_generic_reconciler_rejects_malformed_records_without_creating_claims(
        tmp_path: Path) -> None:
    capture = Capture([
        ["not", "an", "event"],
        {"kind": "process_exec", "executable": "/usr/bin/cc", "argv": "cc", "result": 0},
    ], calls=[{"uri": "bad", "sha256": "f" * 64,
               "record": {"tool": "cc", "argv": "cc"}}])
    result = reconcile_captured_build([(1, capture)], tmp_path, ".", DESCRIPTOR)
    assert result.rows == ()
    assert result.facts["malformed_records"] == 3
    assert any("malformed" in gap for gap in result.gaps)


def test_generic_reconciler_keeps_each_command_record_and_its_event_ordinals_apart(
        tmp_path: Path) -> None:
    first = Capture([_exec("/usr/bin/cc", ["cc", "--version"], ordinal=4)])
    second = Capture([_exec("/usr/bin/cc", ["cc", "--version"], ordinal=9),
                      _exec("/usr/bin/cc", ["/usr/bin/cc", "--version"], ordinal=12)],
                     calls=[_call("cc", ["cc", "--version"])])
    first.identity, second.identity = {"sha256": "1" * 64}, {"sha256": "2" * 64}
    result = reconcile_captured_build([(1, first), (2, second)], tmp_path, ".", DESCRIPTOR)
    # The same argv under two commands is two rows; ordinals resolve in the record each names.
    assert [(row["evidence"]["capture_record_sha256"], row["evidence"]["process_exec"]["event_ordinals"],
             row["origin"], row["mapping"]) for row in result.rows] == [
        ("1" * 64, [4], "execution-capture:command-001:event-4", "syscall-process-exec"),
        ("2" * 64, [9, 12], "execution-capture:command-002:event-9", "syscall-process-exec+tool-call")]
    # A wrapper record reconciles only onto an exec of its own command.
    only_exec = Capture([_exec("/usr/bin/cc", ["cc", "--version"])])
    only_call = Capture([], calls=[_call("cc", ["cc", "--version"])])
    result = reconcile_captured_build([(1, only_exec), (2, only_call)], tmp_path, ".", DESCRIPTOR)
    assert [row["mapping"] for row in result.rows] == ["syscall-process-exec"]
    assert result.facts["unreconciled_tool_calls"] == 1
    # A launcher or proxy and the binary it starts are separate rows, so every ordinal resolves
    # to the executable its row names; the wrapper record attaches to the image-owned one.
    chained = Capture([_exec("/capture/wrappers/cc", ["cc", "-c", "a.c"], ordinal=1),
                       _exec("/opt/proxy/cc", ["cc", "-c", "a.c"], ordinal=2),
                       _exec("/usr/bin/cc", ["/usr/bin/cc", "-c", "a.c"], ordinal=3)],
                      calls=[_call("cc", ["cc", "-c", "a.c"])])
    result = reconcile_captured_build([(1, chained)], tmp_path, ".", DESCRIPTOR)
    assert [(row["evidence"]["process_exec"]["executable"], row["evidence"]["process_exec"]["event_ordinals"],
             row["mapping"]) for row in result.rows] == [
        ("/capture/wrappers/cc", [1], "syscall-process-exec"),
        ("/opt/proxy/cc", [2], "syscall-process-exec+tool-call"),
        ("/usr/bin/cc", [3], "syscall-process-exec")]


def test_generic_reconciler_never_takes_identity_from_argv0_or_a_missing_kernel_path(
        tmp_path: Path) -> None:
    complete = _exec("/usr/bin/cc", ["cc", "-c", "ok.c"])
    capture = Capture([
        _exec("", ["cc", "-c", "spoof.c"]),
        _exec("/usr/bin/true", ["/usr/bin/cc", "-c", "spoof.c"]),
        _exec("/workspace/tool.sh", ["cc", "-c", "spoof.c"]),
        {key: value for key, value in complete.items() if key != "executable"},
        {key: value for key, value in complete.items() if key != "result"},
    ])
    result = reconcile_captured_build([(1, capture)], tmp_path, ".", DESCRIPTOR)
    assert result.rows == ()
    # An event with no kernel path or no result is not an observed exec.
    assert result.facts["malformed_records"] == 2
    # An unclassified exec with no absolute path or below a build-writable mount is counted.
    assert result.facts["untrusted_location_exec_events"] == 2


def test_generic_reconciler_reports_a_truncated_tool_argv_instead_of_hashing_it(
        tmp_path: Path) -> None:
    capture = Capture([_exec("/usr/bin/cc", ["cc", "-c"], truncated=True),
                       _exec("/usr/bin/make", ["make"], truncated=True),
                       _exec("/usr/bin/clang", ["clang", "-c", "ok.c"])],
                      calls=[_call("cc", ["cc", "-c"])])
    result = reconcile_captured_build([(1, capture)], tmp_path, ".", DESCRIPTOR)
    assert [row["tool"] for row in result.rows] == ["clang"]
    assert result.facts["truncated_tool_exec_events"] == 1
    assert result.facts["unreconciled_tool_calls"] == 1
    assert ("1 toolchain process-exec events had truncated argv; their tool provenance is "
            "unavailable") in result.gaps


@pytest.mark.parametrize(("descriptor", "executable", "wrapper", "argv", "expected"), [
    (dotnet.CAPTURE_DESCRIPTOR, "/usr/bin/dotnet",
     "dotnet", ["dotnet", "/sdk/Roslyn/bincore/csc.dll", "/out:app.dll", "Program.cs"],
     "compiler"),
    (native.CAPTURE_DESCRIPTOR, "/usr/bin/clang",
     "clang", ["clang", "-c", "main.c", "-o", "main.o"], "compiler"),
    (rust.CAPTURE_DESCRIPTOR, "/usr/bin/rustc",
     "rustc", ["rustc", "src/lib.rs", "-o", "target/lib.rlib"], "compiler"),
])
def test_generic_reconciliation_contract_is_shared_by_all_descriptor_languages(
        tmp_path: Path, descriptor: CapturedBuildDescriptor, executable: str, wrapper: str,
        argv: list[str], expected: str) -> None:
    result = reconcile_captured_build(
        [(1, Capture([
            {"kind": "connect", "ordinal": 1, "address": "192.0.2.5", "port": 443},
            _exec(executable, argv, redacted_names=["TOKEN"]),
            _exec(executable, [*argv[:-1], "failed-input"], result=-1),
        ], calls=[_call(wrapper, argv)]))], tmp_path, ".", descriptor)
    assert len(result.rows) == 1
    assert result.rows[0]["tool_kind"] == expected
    assert result.rows[0]["mapping"] == "syscall-process-exec+tool-call"
    assert result.facts["failed_exec_events"] == 1
    assert result.facts["connect_events"] == 1
    assert result.facts["envp_redacted_names"] == ["TOKEN"]




def _pid_exec(
    executable: str,
    argv: Sequence[str],
    *,
    pid: int,
    ordinal: int,
    result: int = 0,
) -> dict[str, Any]:
    return {
        "kind": "process_exec",
        "pid": pid,
        "ordinal": ordinal,
        "timestamp_ns": ordinal * 1000,
        "executable": executable,
        "argv": list(argv),
        "argv_truncated": False,
        "result": result,
        "envp_captured": False,
        "envp_redacted_names": [],
    }


def _fork(pid: int, child_pid: int, ordinal: int) -> dict[str, Any]:
    return {
        "kind": "process_fork",
        "pid": pid,
        "child_pid": child_pid,
        "ordinal": ordinal,
        "timestamp_ns": ordinal * 1000,
    }


def _chdir(pid: int, path: str, ordinal: int) -> dict[str, Any]:
    return {
        "kind": "directory_change",
        "pid": pid,
        "path": path,
        "result": 0,
        "ordinal": ordinal,
        "timestamp_ns": ordinal * 1000,
    }


def _cwd_call(
    index: int,
    tool: str,
    argv: Sequence[str],
    working_directory: object = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "tool": tool,
        "argv": list(argv),
        "exit_code": 0,
        "stdout": {"bytes": 0, "truncated": False},
        "stderr": {"bytes": 0, "truncated": False},
        "response_files": {"observed": 0, "references": []},
    }
    if working_directory is not None:
        record["working_directory"] = working_directory
    return {
        "uri": f"tool-calls/{index:08d}-{tool}/record.json",
        "sha256": f"{index:064x}"[-64:],
        "record": record,
    }


def test_cmake_probe_repeated_argv_across_distinct_cwds_reconciles_without_gaps(
    tmp_path: Path,
) -> None:
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "compile_commands.json").write_text("[]\n", encoding="utf-8")
    (tmp_path / "build" / "libsmoke.a").write_bytes(b"!<arch>\n")
    scratch_c = "/workspace/build/CMakeFiles/CMakeScratch/TryCompile-0001"
    scratch_cxx = "/workspace/build/CMakeFiles/CMakeScratch/TryCompile-0002"

    configure_events: list[dict[str, Any]] = [
        _pid_exec("/capture/wrappers/cmake", ["cmake", "-S", ".", "-B", "build", "-G", "Ninja"], pid=10, ordinal=1),
        _pid_exec("/usr/bin/cmake", ["/usr/bin/cmake", "-S", ".", "-B", "build", "-G", "Ninja"], pid=10, ordinal=2),
        _pid_exec("/capture/wrappers/ninja", ["/capture/wrappers/ninja", "--version"], pid=11, ordinal=3),
        _pid_exec("/usr/bin/ninja", ["/usr/bin/ninja", "--version"], pid=11, ordinal=4),
        _fork(10, 20, 5),
        _chdir(20, scratch_c, 6),
        _pid_exec("/capture/wrappers/ninja", ["/capture/wrappers/ninja", "--version"], pid=20, ordinal=7),
        _pid_exec("/usr/bin/ninja", ["/usr/bin/ninja", "--version"], pid=20, ordinal=8),
        _pid_exec("/capture/wrappers/clang", ["/capture/wrappers/clang", "-Wl,--help"], pid=20, ordinal=9),
        _pid_exec("/usr/bin/clang", ["/usr/bin/clang", "-Wl,--help"], pid=20, ordinal=10),
        _pid_exec("/capture/wrappers/clang++", ["/capture/wrappers/clang++", "-Wl,--help"], pid=20, ordinal=11),
        _pid_exec("/usr/bin/clang++", ["/usr/bin/clang++", "-Wl,--help"], pid=20, ordinal=12),
        _fork(10, 30, 13),
        _chdir(30, scratch_cxx, 14),
        _pid_exec("/capture/wrappers/ninja", ["/capture/wrappers/ninja", "--version"], pid=30, ordinal=15),
        _pid_exec("/usr/bin/ninja", ["/usr/bin/ninja", "--version"], pid=30, ordinal=16),
        _pid_exec("/capture/wrappers/clang", ["/capture/wrappers/clang", "-Wl,--help"], pid=30, ordinal=17),
        _pid_exec("/usr/bin/clang", ["/usr/bin/clang", "-Wl,--help"], pid=30, ordinal=18),
        _pid_exec("/capture/wrappers/clang++", ["/capture/wrappers/clang++", "-Wl,--help"], pid=30, ordinal=19),
        _pid_exec("/usr/bin/clang++", ["/usr/bin/clang++", "-Wl,--help"], pid=30, ordinal=20),
    ]
    configure_calls = [
        _cwd_call(1, "cmake", ["cmake", "-S", ".", "-B", "build", "-G", "Ninja"], "/workspace"),
        _cwd_call(2, "ninja", ["ninja", "--version"], "/workspace"),
        _cwd_call(3, "ninja", ["ninja", "--version"], scratch_c),
        _cwd_call(4, "clang", ["clang", "-Wl,--help"], scratch_c),
        _cwd_call(5, "clang++", ["clang++", "-Wl,--help"], scratch_c),
        _cwd_call(6, "ninja", ["ninja", "--version"], scratch_cxx),
        _cwd_call(7, "clang", ["clang", "-Wl,--help"], scratch_cxx),
        _cwd_call(8, "clang++", ["clang++", "-Wl,--help"], scratch_cxx),
    ]
    build_events: list[dict[str, Any]] = [
        _pid_exec("/usr/bin/cmake", ["/usr/bin/cmake", "--build", "build"], pid=40, ordinal=1),
        _fork(40, 41, 2),
        _chdir(41, "/workspace/build", 3),
        _pid_exec("/usr/bin/cmake", ["/usr/bin/cmake", "-E", "rm", "-f", "libsmoke.a"], pid=41, ordinal=4),
    ]
    build_calls = [
        _cwd_call(1, "cmake", ["cmake", "--build", "build"], "/workspace"),
    ]

    result = reconcile_captured_build(
        [
            (1, Capture(configure_events, calls=configure_calls)),
            (2, Capture(build_events, calls=build_calls)),
        ],
        tmp_path,
        ".",
        native.CAPTURE_DESCRIPTOR,
    )

    assert result.facts["tool_call_records"] == 9
    assert result.facts["unreconciled_tool_calls"] == 0
    assert result.gaps == ()

    reconciled_image_rows = [
        (row["tool"], row["working_directory"], row["mapping"])
        for row in result.rows
        if str(row["evidence"]["process_exec"]["executable"]).startswith("/usr/bin/")
    ]
    assert reconciled_image_rows == [
        ("cmake", ".", "syscall-process-exec+tool-call"),
        ("ninja", ".", "syscall-process-exec+tool-call"),
        ("ninja", "build/CMakeFiles/CMakeScratch/TryCompile-0001", "syscall-process-exec+tool-call"),
        ("clang", "build/CMakeFiles/CMakeScratch/TryCompile-0001", "syscall-process-exec+tool-call"),
        ("clang++", "build/CMakeFiles/CMakeScratch/TryCompile-0001", "syscall-process-exec+tool-call"),
        ("ninja", "build/CMakeFiles/CMakeScratch/TryCompile-0002", "syscall-process-exec+tool-call"),
        ("clang", "build/CMakeFiles/CMakeScratch/TryCompile-0002", "syscall-process-exec+tool-call"),
        ("clang++", "build/CMakeFiles/CMakeScratch/TryCompile-0002", "syscall-process-exec+tool-call"),
        ("cmake", ".", "syscall-process-exec+tool-call"),
        ("cmake", "build", "syscall-process-exec"),
    ]
    wrapper_mappings = {
        row["mapping"]
        for row in result.rows
        if str(row["evidence"]["process_exec"]["executable"]).startswith("/capture/wrappers/")
    }
    assert wrapper_mappings == {"syscall-process-exec"}

    cmake_configure = next(
        row for row in result.rows
        if row["tool"] == "cmake" and "-G" in row["argv"] and row["mapping"] == "syscall-process-exec+tool-call"
    )
    assert [out["workspace_path"] for out in cmake_configure["outputs"]] == ["build/compile_commands.json"]
    for non_configure in (
        row for row in result.rows
        if row["tool"] == "cmake" and ("--build" in row["argv"] or "-E" in row["argv"])
    ):
        assert non_configure["outputs"] == []


def test_reconciler_enforces_per_directory_exec_budget_and_validates_cwd_fields(
    tmp_path: Path,
) -> None:
    events = [
        _pid_exec("/usr/bin/clang", ["clang", "-Wl,--help"], pid=10, ordinal=1),
        _fork(10, 11, 2),
        _chdir(11, "/workspace/sub", 3),
        _pid_exec("/usr/bin/clang", ["clang", "-Wl,--help"], pid=11, ordinal=4),
        _pid_exec("/usr/bin/cc", ["cc", "-c", "single.c"], pid=10, ordinal=5),
    ]
    calls = [
        _cwd_call(1, "clang", ["clang", "-Wl,--help"], "/workspace"),
        _cwd_call(2, "clang", ["clang", "-Wl,--help"], "/workspace"),  # exceeds /workspace count=1
        _cwd_call(3, "clang", ["clang", "-Wl,--help"], "/workspace/other"),  # unmatched cwd
        _cwd_call(4, "clang", ["clang", "-Wl,--help"]),  # legacy omitted cwd with multi-dir execs -> ambiguous
        _cwd_call(5, "cc", ["cc", "-c", "single.c"]),  # legacy omitted cwd with single-dir exec -> reconciles
        _cwd_call(6, "clang", ["clang", "-Wl,--help"], "<redacted: secret detected by gitleaks>"),
        _cwd_call(7, "clang", ["clang", "-Wl,--help"], ""),
    ]

    result = reconcile_captured_build([(1, Capture(events, calls=calls))], tmp_path, ".", DESCRIPTOR)

    assert result.facts["unreconciled_tool_calls"] == 3
    assert result.facts["redacted_tool_calls"] == 1
    assert result.facts["malformed_records"] == 1
    by_key = {(row["tool"], row["working_directory"]): row["mapping"] for row in result.rows}
    assert by_key == {
        ("clang", "."): "syscall-process-exec+tool-call",
        ("clang", "sub"): "syscall-process-exec",
        ("cc", "."): "syscall-process-exec+tool-call",
    }
