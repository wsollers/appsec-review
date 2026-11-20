"""Constructed LLVM 18.1.8 emitter-shape fixtures, not captured compiler output.

Shape authority: llvmorg-18.1.8/clang/lib/StaticAnalyzer/Core/PlistDiagnostics.cpp,
printBugPath, ReportNote, ReportCall, ReportEvent, ReportControlFlow and ReportPopUp.
"""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import plistlib
import sqlite3

import pytest

from appsec_review.jobs.job_clang_static_analysis import job
from appsec_review.storage import file_sha256
from .support import FakeExecutor, _scope, _unit
from .test_clang_static_tool import ROOT, _driver


def _emitter_shape():
    main = {"file": 0, "line": 1, "col": 1}
    header = {"file": 1, "line": 1, "col": 2}
    document = {"files": ["/target/source/main.cpp", "/target/source/header.h"], "diagnostics": [{
        "check_name": "core.NullDereference", "description": "example diagnostic", "location": main,
        "notes": [{"location": header, "message": "standalone note", "extended_message": "standalone note",
                   "ranges": [[header, header]], "fixits": [{"remove_range": [header, header], "insert_string": ""}]}],
        "path": [
            {"kind": "event", "depth": 0, "location": main, "message": "call entry", "key_event": True},
            {"kind": "event", "depth": 1, "location": header, "message": "inside callee", "ranges": [[header, header]]},
            {"kind": "control", "edges": [{"start": [main, main], "end": [header, header]}]},
            {"kind": "pop-up", "location": header, "message": "explanation", "ranges": [[header, header]]},
            {"kind": "event", "depth": 0, "location": main, "message": "call exit"},
        ],
    }]}
    for piece in document["diagnostics"][0]["path"]:
        if "message" in piece:
            piece["extended_message"] = piece["message"]
    return document


def test_emitter_shaped_notes_flat_calls_and_control_ranges_reach_admitted_reader(monkeypatch, tmp_path):
    scope, unit = _scope(tmp_path), _unit(tmp_path)
    header = scope.case_root / "source/header.h"
    header.write_text("abc\n")
    accepted = {"scratch_path": "source/header.h", "target_path": "native/header.h", "sha256": file_sha256(header)}
    scope = replace(scope, files=(*scope.files, accepted), _by_relative={**scope._by_relative, "header.h": accepted})
    driver = _driver()

    def compiler(argv, **kwargs):
        if "--analyze" in argv:
            Path(argv[-1]).write_bytes(plistlib.dumps(_emitter_shape()))
        return 0, "", False

    monkeypatch.setattr(driver, "_run", compiler)

    class Executor(FakeExecutor):
        def execute(self, request):
            result = super().execute(request)
            assert driver.main([request.argv[1], str(request.scratch_root / "compile_commands.json"),
                                str(request.scratch_root / f"{request.argv[1]}.json"),
                                request.argv[4], request.argv[5]]) == 0
            return result

    result = job._analyze_scope(unit, scope, lambda _u: Executor(unit.job.run_root))
    assert result["observation_count"] == 1 and not result["gaps"]
    with sqlite3.connect(unit.job.run_root / result["index_identity"]["relative_path"]) as db:
        payload = json.loads(db.execute("select payload_json from entities where kind='tool_observation'").fetchone()[0])
    assert payload["trace_length"] == payload["trace_retained_count"] == 6
    assert not payload["trace_truncated"] and payload["trace_omissions"] == {}
    trace = payload["trace"]
    assert trace[0]["origin"] == "notes" and trace[0]["message"] == "standalone note"
    assert trace[0]["location"]["file_sha256"] == file_sha256(header)
    assert trace[0]["ranges"][0]["location"]["start_byte"] == 1
    assert trace[0]["ranges"][0]["reported_end"]["column"] == 2
    assert [piece["depth"] for piece in trace if piece["kind"] == "event"] == [0, 1, 0]
    assert trace[1]["key_event"] is True
    control = trace[3]
    assert control["kind"] == "control" and "gap" not in control
    assert control["edges"][0]["start"]["path"] == "native/main.cpp"
    assert control["edges"][0]["end"]["path"] == "native/header.h"
    assert control["edges"][0]["end"]["end_byte"] == 2
    assert control["edges"][0]["reported_end"]["end_column"] == 2
    assert "<truncated>" not in json.dumps(trace)
    assert payload["fix_it"] is True


def test_combined_note_path_and_detail_bounds_report_exact_omissions(tmp_path):
    document = _emitter_shape()
    diagnostic = document["diagnostics"][0]
    note = deepcopy(diagnostic["notes"][0])
    diagnostic["notes"] = [deepcopy(note) for _ in range(128)]
    diagnostic["notes"][0]["message"] = diagnostic["notes"][0]["extended_message"] = "x" * 4097
    diagnostic["notes"][0]["ranges"] *= 17
    control = deepcopy(diagnostic["path"][2])
    control["edges"] *= 17
    diagnostic["path"] = [control] + [deepcopy(diagnostic["path"][0]) for _ in range(128)]
    source = tmp_path / "synthetic-boundary.plist"
    source.write_bytes(plistlib.dumps(document))
    driver = _driver()
    records = driver._plist_diagnostics(source)
    record = records[0]
    assert record["trace_length"] == 257 and len(record["notes"]) == 256
    assert record["trace_omissions"] == {"steps": 1, "ranges": 1, "edges": 1, "message_characters": 1}
    assert record["trace_truncated"] and records.truncated
    assert len(record["notes"][0]["ranges"]) == len(record["notes"][128]["edges"]) == 16
    assert len(record["notes"][0]["message"]) == 4096
    output = tmp_path / "output.json"
    output.write_text(json.dumps({"schema": job.OUTPUT_SCHEMA, "engine": "clang-static-analyzer",
                                  "diagnostics": records, "truncated": records.truncated}))
    admitted, gaps = job._read_output(output, engine="clang-static-analyzer", max_bytes=1 << 20, max_diagnostics=1)
    assert admitted[0]["trace_omissions"] == record["trace_omissions"]
    assert gaps


@pytest.mark.parametrize("malformation", ["notes-shape", "nested-call", "bad-edge"])
def test_synthetic_malformed_plist_pieces_are_not_silently_complete(tmp_path, malformation):
    document = _emitter_shape()
    diagnostic = document["diagnostics"][0]
    if malformation == "notes-shape":
        diagnostic["notes"] = {"message": "not an array"}
    elif malformation == "nested-call":
        diagnostic["path"] = [{"kind": "call", "path": diagnostic["path"]}]
    else:
        diagnostic["path"][2]["edges"][0]["end"] = []
    path = tmp_path / "malformed.plist"
    path.write_bytes(plistlib.dumps(document))
    with pytest.raises(ValueError):
        _driver()._plist_diagnostics(path)


def test_existing_version_attributed_empty_plists_do_not_prove_positive_fidelity():
    driver = _driver()
    for name in ("net.plist", "util.plist"):
        path = ROOT / "tests/fixtures/seeded_clang/project" / name
        document = plistlib.loads(path.read_bytes())
        assert document["clang_version"] == "Ubuntu clang version 18.1.3 (1ubuntu1)"
        assert document["diagnostics"] == []
        assert driver._plist_diagnostics(path) == []


@pytest.mark.parametrize("malformation", ["depth", "edge-bound", "omission-count"])
def test_admitted_reader_rejects_malformed_trace_metadata(tmp_path, malformation):
    path = tmp_path / "native-shaped.plist"
    path.write_bytes(plistlib.dumps(_emitter_shape()))
    records = _driver()._plist_diagnostics(path)
    if malformation == "depth":
        records[0]["notes"][1]["depth"] = -1
    elif malformation == "edge-bound":
        records[0]["notes"][3]["edges"] *= 17
    else:
        records[0]["trace_omissions"] = {"steps": 1}
    output = tmp_path / "output.json"
    output.write_text(json.dumps({"schema": job.OUTPUT_SCHEMA, "engine": "clang-static-analyzer",
                                  "diagnostics": records}))
    parsed, gaps = job._read_output(output, engine="clang-static-analyzer", max_bytes=1 << 20, max_diagnostics=1)
    assert not parsed and gaps
