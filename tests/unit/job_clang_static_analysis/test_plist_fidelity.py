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


def _publish_plist(monkeypatch, tmp_path, document, *, main_bytes=None):
    scope, unit = _scope(tmp_path), _unit(tmp_path)
    if main_bytes is not None:
        main = scope.case_root / "source/main.cpp"
        main.write_bytes(main_bytes)
        accepted_main = {**scope.files[0], "sha256": file_sha256(main)}
        scope = replace(scope, files=(accepted_main,), _by_relative={"main.cpp": accepted_main})
    header = scope.case_root / "source/header.h"
    header.write_text("abc\n")
    accepted = {"scratch_path": "source/header.h", "target_path": "native/header.h", "sha256": file_sha256(header)}
    scope = replace(scope, files=(*scope.files, accepted), _by_relative={**scope._by_relative, "header.h": accepted})
    driver = _driver()

    def compiler(argv, **kwargs):
        if "--analyze" in argv:
            Path(argv[-1]).write_bytes(plistlib.dumps(document))
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
    with sqlite3.connect(unit.job.run_root / result["index_identity"]["relative_path"]) as db:
        payloads = [json.loads(row[0]) for row in db.execute("select payload_json from entities where kind='tool_observation'")]
    return scope, unit, result, payloads


def test_emitter_shaped_notes_flat_calls_and_control_ranges_reach_admitted_reader(monkeypatch, tmp_path):
    scope, _unit_context, result, payloads = _publish_plist(monkeypatch, tmp_path, _emitter_shape())
    header = scope.case_root / "source/header.h"
    assert result["observation_count"] == 1 and not result["gaps"]
    [payload] = payloads
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


@pytest.mark.parametrize("start,end,note_column,primary_column,valid_range", [
    (5, 6, 5, 1, True),
    (6, 6, 5, 1, False),
    (5, 5, 5, 1, False),
    (5, 9, 5, 1, False),
    (5, 8, 5, 1, False),
    (5, 6, 6, 1, True),
    (5, 6, 5, 6, True),
], ids=["utf8-last-byte", "continuation-start", "split-end", "past-eof", "newline-end",
        "invalid-note-point", "invalid-diagnostic-point"])
def test_plist_inclusive_byte_ends_do_not_relax_point_or_start_validation(
        monkeypatch, tmp_path, start, end, note_column, primary_column, valid_range):
    document = _emitter_shape()
    diagnostic = document["diagnostics"][0]
    diagnostic["location"]["col"] = primary_column
    pair = [{"file": 0, "line": 1, "col": start}, {"file": 0, "line": 1, "col": end}]
    diagnostic["notes"] = [{"location": {"file": 0, "line": 1, "col": note_column},
                           "message": "range note", "ranges": [pair]}]
    diagnostic["path"] = [{"kind": "control", "edges": [{"start": pair, "end": pair}]}]
    source = "int é;\n".encode("utf-8")
    scope, _, result, payloads = _publish_plist(monkeypatch, tmp_path, document, main_bytes=source)
    if primary_column == 6:
        assert not payloads and any("diagnostic span" in gap for gap in result["gaps"])
        return
    [payload] = payloads
    note, control = payload["trace"]
    locations = [note["ranges"][0]["location"], control["edges"][0]["start"], control["edges"][0]["end"]]
    if valid_range:
        for location in locations:
            assert location is not None
            assert (location["start_byte"], location["end_byte"]) == (4, 6)
            assert (location["start_column"], location["end_column"]) == (5, 6)
            assert source[location["start_byte"]:location["end_byte"]].decode("utf-8") == "é"
            assert location["file_sha256"] == file_sha256(scope.case_root / "source/main.cpp")
    else:
        assert locations == [None, None, None] and result["gaps"]
    if note_column == 6:
        assert note["location"] is None and "gap" in note
    else:
        assert note["location"] is not None


@pytest.mark.parametrize("display_cut", [False, True], ids=["one-step-edge-loss", "upstream-and-display-loss"])
def test_graph_publication_keeps_upstream_detail_omissions_separate_from_display_clipping(
        monkeypatch, tmp_path, display_cut):
    from appsec_review.indexing.store import ShardSet
    from appsec_review.jobs.job_code_graph_index import producers
    from appsec_review.retrieval import IndexBuilder

    document = _emitter_shape()
    diagnostic = document["diagnostics"][0]
    control = deepcopy(diagnostic["path"][2])
    control["edges"] *= 17
    if display_cut:
        diagnostic["notes"][0]["ranges"] *= 17
        diagnostic["notes"][0]["message"] = diagnostic["notes"][0]["extended_message"] = "x" * 4097
        diagnostic["path"] = [control] + [deepcopy(diagnostic["path"][0]) for _ in range(255)]
        expected = {"steps": 1, "ranges": 1, "edges": 1, "message_characters": 1}
    else:
        diagnostic["notes"] = []
        diagnostic["path"] = [control]
        expected = {"edges": 1}
    _, unit, result, [source] = _publish_plist(monkeypatch, tmp_path, document)
    assert source["trace_omissions"] == expected
    shard = result["index_identity"]
    out = producers.ProducerRows()
    producers._diagnostic_rows(ShardSet(unit.job.run_root, [shard]), [shard],
                               {"scope_id": "scope", "language": "cpp", "build_unit_id": "unit"},
                               unit.job.source_fingerprint, out)
    graph_path = unit.job.run_root / "data/indices/graph/clang-omissions.sqlite"
    builder = IndexBuilder(graph_path, name="graph", fingerprint="a" * 64,
                           target_snapshot=unit.job.source_fingerprint, shard_id="clang-omissions")
    for entity in out.entities:
        builder.add_entity(entity)
    builder.build()
    with sqlite3.connect(graph_path) as db:
        [payload] = [json.loads(row[0]) for row in db.execute("select payload_json from entities")]
    assert payload["trace_omissions"] == expected
    assert payload["trace_display_omissions"] == (
        {"steps": len(source["trace"]) - producers.MAX_TRACE_STEPS} if display_cut else {})
    assert payload["trace_retained_count"] == len(payload["trace"])
    assert payload["trace_truncated"]
    assert any("edges=1" in gap for gap in out.gaps)
    assert not any("retains 1 of 1 steps" in gap for gap in out.gaps)


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
