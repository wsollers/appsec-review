from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from appsec_review.jobs.job_language_build import dotnet, go, native, rust
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


def _classify(name: str, _argv: Sequence[str]) -> ToolIdentity | None:
    return ToolIdentity(name, "compiler") if name in {"cc", "clang"} else None


DESCRIPTOR = CapturedBuildDescriptor(
    family="fixture", capture_identity="fixture/capture/1",
    provenance_schema="fixture/provenance/1", catalog_label="fixture",
    classify_tool=_classify, build_invocation=_row,
    missing_tool_gap="fixture compiler was not observed",
)


def _exec(executable: str, argv: Sequence[str], *, result: int = 0,
          redacted_names: Sequence[str] = ()) -> dict[str, Any]:
    return {"kind": "process_exec", "ordinal": 1, "executable": executable,
            "argv": list(argv), "result": result, "envp_captured": True,
            "envp_redacted_names": list(redacted_names)}


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


@pytest.mark.parametrize(("descriptor", "executable", "wrapper", "argv", "expected"), [
    (dotnet.CAPTURE_DESCRIPTOR, "/usr/bin/dotnet",
     "dotnet", ["dotnet", "/sdk/Roslyn/bincore/csc.dll", "/out:app.dll", "Program.cs"],
     "compiler"),
    (native.CAPTURE_DESCRIPTOR, "/usr/bin/clang",
     "clang", ["clang", "-c", "main.c", "-o", "main.o"], "compiler"),
    (rust.CAPTURE_DESCRIPTOR, "/usr/bin/rustc",
     "rustc", ["rustc", "src/lib.rs", "-o", "target/lib.rlib"], "compiler"),
    (go.CAPTURE_DESCRIPTOR, "/usr/local/go/pkg/tool/linux_amd64/compile",
     "compile", ["compile", "-o", "/tmp/main.a", "main.go"], "compiler"),
])
def test_generic_reconciliation_contract_is_shared_by_all_captured_languages(
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
