from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import plistlib
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[3]


def _driver():
    path = ROOT / "containers" / "tools" / "clang-static-analysis" / "clang-static.py"
    spec = importlib.util.spec_from_file_location("clang_static_driver", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_clang_tidy_text_diagnostic_is_normalized() -> None:
    driver = _driver()
    records = driver._text_diagnostics(
        "/target/source/main.cpp:7:9: warning: unchecked return [bugprone-unused-return-value]\n",
        engine="clang-tidy", default_rule="driver",
    )
    assert records == [{
        "rule_id": "bugprone-unused-return-value", "message": "unchecked return",
        "severity": "warning", "path": "/target/source/main.cpp", "line": 7,
        "column": 9, "notes": [], "fix_it": False, "trace_length": 0, "trace_truncated": False,
    }]


def test_clang_tidy_fix_it_hint_is_a_boolean_only() -> None:
    driver = _driver()
    records = driver._text_diagnostics(
        "/target/source/main.cpp:7:9: warning: use nullptr [modernize-use-nullptr]\n"
        'fix-it:"/target/source/main.cpp":{7:9-7:10}:"nullptr"\n',
        engine="clang-tidy", default_rule="driver",
    )
    assert records[0]["fix_it"] is True and "nullptr\"" not in str(records[0]["notes"])


def test_unit_outcome_names_the_compiler_failure() -> None:
    driver = _driver()
    row = {"file": "/target/source/a.cpp", "directory": "/target/source",
           "arguments": ["clang++", "/target/source/a.cpp"], "source_sha256": "a" * 64}
    unit = driver._unit(row, 1, "x\n/target/source/a.cpp:1:1: error: boom\n")
    assert unit["exit_code"] == 1 and "boom" in unit["message"]
    assert driver._unit(row, 0, "")["message"] == ""


def test_static_analyzer_plist_retains_path_notes(tmp_path: Path) -> None:
    driver = _driver()
    report = tmp_path / "result.plist"
    report.write_bytes(plistlib.dumps({
        "files": ["/target/source/main.cpp"],
        "diagnostics": [{
            "check_name": "core.NullDereference", "description": "Dereference of null pointer",
            "location": {"file": 0, "line": 4, "col": 3},
            "path": [{"location": {"line": 3, "col": 5}, "message": "Null assigned here"}],
        }],
    }))
    records = driver._plist_diagnostics(report)
    assert records[0]["rule_id"] == "core.NullDereference"
    assert records[0]["path"] == "/target/source/main.cpp"
    assert records[0]["notes"] == [{"message": "Null assigned here", "line": 3, "column": 5}]


def _database(tmp_path, rows=1):
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps([
        {"file": f"/target/source/unit{index}.cpp", "directory": "/target/build/nested",
         "source_sha256": "a" * 64,
         "arguments": ["clang++", "-I../../source/include", f"/target/source/unit{index}.cpp"]}
        for index in range(rows)
    ]))
    return database


def test_analyzer_runs_in_the_accepted_rebased_compile_directory(monkeypatch, tmp_path):
    from appsec_review.jobs.cpp_index_scopes import container_compile_database

    driver = _driver()
    rows = container_compile_database("native", [{
        "target_path": "native/main.cpp", "directory": "/scratch/build/nested",
        "arguments": ["clang++", "-I../../source/include", "/scratch/source/main.cpp"],
    }])
    database = tmp_path / "compile_commands.json"
    rows = [{**row, "source_sha256": "a" * 64} for row in rows]
    database.write_text(json.dumps(rows))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return 0, "", False

    monkeypatch.setattr(driver, "_run", run)
    units = []
    driver.analyze(database, "core", units)
    assert calls[0][1].get("cwd") == "/target/build/nested"
    assert "-I../../source/include" in calls[0][0]
    assert "/target/source/main.cpp" in calls[0][0]
    assert units[0]["exit_code"] == 0


def test_capture_drains_in_bounded_chunks_instead_of_buffering_everything(monkeypatch):
    driver = _driver()
    monkeypatch.setattr(driver, "MAX_CAPTURE", 7)
    reads = []
    seen = []

    class Stream(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= 65536
            reads.append(size)
            return super().read(size)

    class Process:
        def __init__(self, argv, **kwargs):
            seen.append(kwargs)
            self.stdout = Stream(b"1234567" + b"x" * 100000)
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            self.stdout.close()
        def wait(self):
            return 3

    monkeypatch.setattr(driver.subprocess, "Popen", Process)
    monkeypatch.setattr(driver.subprocess, "run",
                        lambda *_a, **_kw: SimpleNamespace(stdout=b"1234567" + b"x" * 100000, returncode=3))
    assert driver._run(["inert"]) == (3, "1234567", True)
    assert len(reads) >= 3
    assert seen[0]["stderr"] == driver.subprocess.STDOUT


def test_tidy_notes_keep_cross_file_points_and_explicit_trace_cuts():
    driver = _driver()
    text = "/target/source/main.cpp:1:1: warning: problem [bugprone-test]\n"
    text += "".join(f"/target/source/header.h:2:3: note: cause {index}\n" for index in range(257))
    records = driver._text_diagnostics(text, engine="clang-tidy", default_rule="driver")
    assert len(records[0]["notes"]) == 256
    assert records[0]["notes"][0] == {
        "message": "cause 0", "path": "/target/source/header.h", "line": 2, "column": 3,
    }
    assert records[0]["trace_length"] == 257
    assert records[0]["trace_truncated"] is True


def test_plist_preserves_cross_file_ranges_nested_notes_and_trace_cuts(tmp_path):
    driver = _driver()
    report = tmp_path / "result.plist"
    point = {"file": 1, "line": 2, "col": 3}
    report.write_bytes(plistlib.dumps({
        "files": ["/target/source/main.cpp", "/target/source/header.h"],
        "diagnostics": [{
            "location": {"file": 0, "line": 1, "col": 1}, "description": "problem",
            "ranges": [[point, {**point, "col": 4}]],
            "path": [{"kind": "call", "path": [
                {"location": point, "message": "cause", "ranges": [[point, point]]}
                for _ in range(257)
            ]}],
        }],
    }))
    record = driver._plist_diagnostics(report)[0]
    assert len(record["notes"]) == 256 and record["trace_length"] == 257
    assert record["trace_truncated"] is True
    assert record["notes"][0]["path"] == "/target/source/header.h"
    assert record["ranges"][0][1]["column"] == 4
    assert record["notes"][0]["ranges"][0][0]["path"] == "/target/source/header.h"


@pytest.mark.parametrize("action", ["analyze", "tidy"])
def test_engine_accumulation_is_bounded_before_serialization(monkeypatch, tmp_path, action):
    driver = _driver()
    database = _database(tmp_path, 3)
    text = "/target/source/unit0.cpp:1:1: warning: problem [bugprone-test]\n" * 4
    monkeypatch.setattr(driver, "_run", lambda *_a, **_kw: (0, text, False))
    units = []
    diagnostics, truncated, code = getattr(driver, action)(
        database, "core", units, max_diagnostics=2)
    assert len(diagnostics) == 2 and truncated and code == 0
    assert len(units) == 3 and all(unit["exit_code"] == 0 for unit in units)
    assert diagnostics.retained_bytes <= driver.MAX_CAPTURE
    monkeypatch.setattr(driver, "MAX_CAPTURE", 1)
    diagnostics, truncated, _ = getattr(driver, action)(database, "core", [], max_diagnostics=2)
    assert not diagnostics and truncated and diagnostics.retained_bytes == 0


def test_oversize_plist_is_not_loaded_or_parsed(monkeypatch, tmp_path):
    driver = _driver()
    monkeypatch.setattr(driver, "MAX_CAPTURE", 16)
    report = tmp_path / "result.plist"
    report.write_bytes(b"x" * 17)
    monkeypatch.setattr(driver.plistlib, "loads", lambda _data: pytest.fail("oversize plist parsed"))
    records = driver._plist_diagnostics(report)
    assert not records and records.truncated


def test_tidy_explicit_config_prevents_project_check_selection(monkeypatch, tmp_path):
    driver = _driver()
    database = _database(tmp_path)
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return 0, "", False

    monkeypatch.setattr(driver, "_run", run)
    driver.tidy(database, "bugprone-*,-bugprone-easily-swappable-parameters", [])
    assert "--checks=-*,bugprone-*,-bugprone-easily-swappable-parameters" in calls[0]
    configs = [arg.removeprefix("--config=") for arg in calls[0] if arg.startswith("--config=")]
    assert len(configs) == 1 and json.loads(configs[0])["InheritParentConfig"] is False


def test_real_wrapper_serialization_reports_trace_cut_to_job_parser(monkeypatch, tmp_path):
    from appsec_review.jobs.job_clang_static_analysis.job import _read_output

    driver = _driver()
    database = _database(tmp_path)
    text = "../../source/unit0.cpp:1:1: warning: problem [bugprone-test]\n"
    text += "../../source/header.h:2:3: note: cause\n" * 257
    monkeypatch.setattr(driver, "_run", lambda *_a, **_kw: (0, text, False))
    output = tmp_path / "tidy.json"
    assert driver.main(["tidy", str(database), str(output), "2", "bugprone-*"]) == 0
    records, gaps = _read_output(output, engine="clang-tidy", max_bytes=1 << 20, max_diagnostics=2)
    assert records[0]["path"] == "/target/source/unit0.cpp"
    assert records[0]["notes"][0]["path"] == "/target/source/header.h"
    assert records[0]["trace_length"] == 257 and len(records[0]["notes"]) == 256
    assert records[0]["trace_truncated"] and any("trace truncated" in gap for gap in gaps)
    document = json.loads(output.read_text())
    assert document["truncated"] and document["units"][0]["exit_code"] == 0


def test_one_plist_trace_cut_does_not_suppress_later_text_diagnostics(monkeypatch, tmp_path):
    driver = _driver()
    database = _database(tmp_path, 2)

    def run(argv, **kwargs):
        if "/target/source/unit0.cpp" in argv:
            output = Path(argv[-1])
            output.write_bytes(plistlib.dumps({
                "files": ["/target/source/unit0.cpp"], "diagnostics": [{
                    "location": {"file": 0, "line": 1, "col": 1}, "description": "first",
                    "path": [{"message": "cause", "location": {"file": 0, "line": 1, "col": 1}}] * 257,
                }],
            }))
            return 0, "", False
        return 0, "/target/source/unit1.cpp:1:1: warning: second [driver]\n", False

    monkeypatch.setattr(driver, "_run", run)
    records, truncated, _ = driver.analyze(database, "core", [])
    assert truncated and [record["message"] for record in records] == ["first", "second"]
