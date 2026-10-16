"""Unit tests for the tool-svf wrapper (containers/tools/svf/svf.py) with its process runner faked."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
BOUNDS = {"max_module_bitcode_bytes": 1024, "max_module_output_bytes": 4096, "field_limit": 64, "max_sites": 10,
          "max_pts_size": 8, "max_indirect_calls": 4, "max_targets_per_call": 4, "max_unmodeled_names": 4,
          "compile_timeout_seconds": 5, "link_timeout_seconds": 5, "module_timeout_seconds": 10,
          "andersen_time_limit_seconds": 8}


def _wrapper():
    path = ROOT / "containers" / "tools" / "svf" / "svf.py"
    spec = importlib.util.spec_from_file_location("svf_wrapper", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bitcode_argv_keeps_semantic_flags_and_forces_debug_O0_bitcode() -> None:
    svf = _wrapper()
    argv = svf.bitcode_argv(
        ["clang++", "-std=c++20", "-DMODE=2", "-I/target/source/include", "-O2", "-g3", "-flto=thin",
         "-fsanitize=address", "-MD", "-MF", "deps.d", "-Werror", "-c", "/target/source/a.cpp", "-o",
         "/target/build/a.o"], "/scratch/bitcode/tu-0000.bc")
    assert argv[0] == "clang++-18"
    assert argv[1:5] == ["-std=c++20", "-DMODE=2", "-I/target/source/include", "/target/source/a.cpp"]
    assert argv[5:] == ["-c", "-emit-llvm", "-g", "-O0", "-Xclang", "-disable-O0-optnone", "-Wno-everything",
                        "-o", "/scratch/bitcode/tu-0000.bc"]
    assert svf.bitcode_argv(["clang", "x.c"], "o.bc")[0] == "clang-18"


class FakeRunner:
    """Stands in for clang, llvm-link and the driver; writes the files each would write."""

    def __init__(self, *, compile_fail=(), link=None, analysis=None, output=None, bitcode_bytes=8):
        self.compile_fail = set(compile_fail)
        self.link = link or {"exit_code": 0, "timeout": False, "stderr": ""}
        self.analysis = analysis or {"exit_code": 0, "timeout": False, "stderr": ""}
        self.output = output
        self.bitcode_bytes = bitcode_bytes
        self.calls: list[list[str]] = []

    def __call__(self, argv, cwd, timeout):
        self.calls.append(list(argv))
        if argv[0].startswith("clang"):
            index = int(Path(argv[-1]).stem.split("-")[1])
            if index in self.compile_fail:
                return {"exit_code": 1, "timeout": False, "stderr": "error: boom"}
            Path(argv[-1]).write_bytes(b"BC")
            return {"exit_code": 0, "timeout": False, "stderr": ""}
        if argv[0].endswith("llvm-link-21"):
            if self.link["exit_code"] == 0:
                Path(argv[2]).write_bytes(b"x" * self.bitcode_bytes)
            return self.link
        request = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        if self.analysis["exit_code"] == 0 and not self.analysis["timeout"]:
            Path(request["output"]).write_text(self.output or json.dumps({"schema": "appsec-review/svf-alias-output/1"}),
                                               encoding="utf-8")
        return self.analysis


def _scratch(tmp_path: Path, modules) -> Path:
    scratch = tmp_path / "scratch"
    scratch.mkdir(parents=True)
    (scratch / "compile_commands.json").write_text(json.dumps([
        {"directory": "/target/source", "file": f"/target/source/{name}", "arguments": ["clang", "-c", name]}
        for name in ("a.c", "b.c", "c.c")]), encoding="utf-8")
    (scratch / "plan.json").write_text(json.dumps({"schema": "appsec-review/svf-plan/1", "modules": modules,
                                                   "bounds": BOUNDS}), encoding="utf-8")
    return scratch


def _run(tmp_path: Path, runner: FakeRunner, modules, monkeypatch):
    svf = _wrapper()
    monkeypatch.setattr(svf, "_run", runner)
    scratch = _scratch(tmp_path, modules)
    assert svf.run(scratch / "plan.json", scratch / "result.json") == 0
    return json.loads((scratch / "result.json").read_text(encoding="utf-8")), scratch


LINKED = [{"module_id": "m-1", "kind": "link", "label": "build/app", "compile_indexes": [0, 1]}]


def test_successful_module_is_compiled_linked_analyzed_and_bitcode_is_removed(tmp_path, monkeypatch) -> None:
    runner = FakeRunner()
    result, scratch = _run(tmp_path, runner, LINKED, monkeypatch)
    module = result["modules"][0]
    assert result["schema"] == "appsec-review/svf-run/1" and result["tool_version"] == "3.3.0"
    assert module["status"] == "analyzed" and module["gaps"] == [] and module["linked_inputs"] == 2
    assert module["output"] == "modules/m-1/alias.json" and (scratch / module["output"]).is_file()
    assert not (scratch / "modules" / "m-1" / "module.bc").exists()
    request = json.loads((scratch / "modules" / "m-1" / "request.json").read_text(encoding="utf-8"))
    assert request["extapi"] == "/opt/svf/lib/extapi.bc" and request["bounds"]["max_sites"] == 10
    assert [call[0] for call in runner.calls] == ["clang-18", "clang-18", "/opt/svf/bin/llvm-link-21",
                                                   "/opt/svf/bin/svf-alias-export"]
    assert [item["produced"] for item in result["compile"]] == [True, True]


def test_unit_without_bitcode_is_a_module_gap_and_the_rest_still_links(tmp_path, monkeypatch) -> None:
    result, _ = _run(tmp_path, FakeRunner(compile_fail={1}), LINKED, monkeypatch)
    module = result["modules"][0]
    assert module["status"] == "analyzed" and module["linked_inputs"] == 1
    assert module["gaps"] == ["missing_bitcode: compile unit 1 (/target/source/b.c) did not produce bitcode"]
    result, _ = _run(tmp_path / "all", FakeRunner(compile_fail={0, 1}), LINKED, monkeypatch)
    assert result["modules"][0]["status"] == "no_bitcode"


def test_link_failure_debug_warnings_and_oversized_modules_are_reported(tmp_path, monkeypatch) -> None:
    failed = FakeRunner(link={"exit_code": 1, "timeout": False, "stderr": "duplicate symbol: f"})
    result, _ = _run(tmp_path / "a", failed, LINKED, monkeypatch)
    assert result["modules"][0]["status"] == "link_failed" and "duplicate symbol" in result["modules"][0]["gaps"][0]
    warned = FakeRunner(link={"exit_code": 0, "timeout": False,
                              "stderr": "warning: ignoring invalid debug info in a.bc\nwarning: ignoring invalid debug info in b.bc"})
    result, _ = _run(tmp_path / "b", warned, LINKED, monkeypatch)
    assert result["modules"][0]["debug_info_warnings"] == 2
    result, _ = _run(tmp_path / "c", FakeRunner(bitcode_bytes=2048), LINKED, monkeypatch)
    assert result["modules"][0]["status"] == "too_large"


def test_andersen_time_limit_timeout_crash_and_oversized_output_are_named(tmp_path, monkeypatch) -> None:
    cases = {
        "andersen_time_limit": FakeRunner(analysis={"exit_code": 101, "timeout": False, "stderr": ""}),
        "timeout": FakeRunner(analysis={"exit_code": None, "timeout": True, "stderr": ""}),
        "crash": FakeRunner(analysis={"exit_code": 134, "timeout": False, "stderr": "Assertion failed"}),
        "oversized": FakeRunner(output="x" * 5000),
    }
    statuses = {}
    for name, runner in cases.items():
        result, _ = _run(tmp_path / name, runner, LINKED, monkeypatch)
        statuses[name] = (result["modules"][0]["status"], " ".join(result["modules"][0]["gaps"]))
    assert statuses["andersen_time_limit"][0] == "andersen_time_limit"
    assert statuses["timeout"] == ("analysis_failed", statuses["timeout"][1]) and "timed out" in statuses["timeout"][1]
    assert "status 134" in statuses["crash"][1] and "Assertion failed" in statuses["crash"][1]
    assert "byte bound" in statuses["oversized"][1]


def test_plan_schema_and_compile_indexes_are_validated(tmp_path, monkeypatch) -> None:
    svf = _wrapper()
    monkeypatch.setattr(svf, "_run", FakeRunner())
    scratch = _scratch(tmp_path, [{"module_id": "m", "kind": "link", "label": "x", "compile_indexes": [7]}])
    with pytest.raises(SystemExit, match="outside the compile database"):
        svf.run(scratch / "plan.json", scratch / "result.json")
    plan = json.loads((scratch / "plan.json").read_text(encoding="utf-8"))
    (scratch / "plan.json").write_text(json.dumps({**plan, "schema": "other"}), encoding="utf-8")
    with pytest.raises(SystemExit, match="schema"):
        svf.run(scratch / "plan.json", scratch / "result.json")
    assert svf.main(["svf.py", "version"]) == 0
    assert svf.main(["svf.py"]) == 2
