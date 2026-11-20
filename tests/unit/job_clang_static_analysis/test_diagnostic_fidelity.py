"""Clang diagnostic custody, bounded traces and real producer/consumer projection."""
from dataclasses import replace
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.jobs.job_clang_static_analysis import job
from appsec_review.storage import file_sha256
from .support import SETTINGS, FakeExecutor, _scope, _unit


def _record(**values):
    return {"rule_id": "test", "message": "problem", "engine": "clang-tidy",
            "path": "/target/source/main.cpp", "line": 1, "column": 1,
            "end_line": 1, "end_column": 1, **values}


@pytest.mark.parametrize("span", [
    {"end_line": None}, {"end_column": "2"}, {"end_column": True},
    {"end_line": 0}, {"end_column": 0}, {"column": 4, "end_column": 2},
])
def test_malformed_optional_spans_are_output_gaps_not_exceptions(tmp_path, span):
    output = tmp_path / "output.json"
    output.write_text(json.dumps({"schema": job.OUTPUT_SCHEMA, "engine": "clang-tidy",
                                  "diagnostics": [_record(**span)]}))
    records, gaps = job._read_output(output, engine="clang-tidy", max_bytes=4096, max_diagnostics=2)
    assert not records and any("span" in gap for gap in gaps)


@pytest.mark.parametrize("span", [
    {"line": 1000, "end_line": 1000}, {"column": 1000, "end_column": 1000},
    {"end_line": 1000}, {"line": 2, "end_line": 1},
])
def test_out_of_source_spans_never_become_exact_eof_locations(tmp_path, span):
    scope = _scope(tmp_path)
    location, _accepted = job._location(scope, _record(**span))
    assert location is None


def test_multiline_utf8_crlf_span_retains_original_coordinates(tmp_path):
    scope = _scope(tmp_path)
    source = scope.case_root / "source/main.cpp"
    source.write_bytes("éx\r\nxy\n".encode())
    accepted = {**scope.files[0], "sha256": file_sha256(source)}
    scope = replace(scope, files=(accepted,), _by_relative={"main.cpp": accepted})
    location, _ = job._location(scope, _record(column=3, end_line=2, end_column=1))
    assert location is not None
    assert (location.start_byte, location.end_byte) == (2, 6)
    assert location.producer_location["column"] == 3
    assert location.producer_location["end_column"] == 1
    assert job._location(scope, _record(column=2, end_column=2))[0] is None
    assert job._location(scope, _record(column=5, end_column=5))[0] is None


def test_diagnostic_limit_matches_wrapper_admission():
    assert job._validated_settings({**SETTINGS, "max_diagnostics_per_scope": 100000})
    with pytest.raises(ValueError, match="100000"):
        job._validated_settings({**SETTINGS, "max_diagnostics_per_scope": 100001})


def test_resolving_trace_ranges_and_cuts_survive_real_shard_projection(tmp_path):
    """Synthetic normalized-envelope boundary; not a captured/native plist fixture."""
    from appsec_review.indexing.store import ShardSet
    from appsec_review.jobs.job_code_graph_index.producers import ProducerRows, _diagnostic_rows

    scope, unit = _scope(tmp_path), _unit(tmp_path)
    header = scope.case_root / "source/header.h"
    header.write_text("abc\n")
    accepted = {"scratch_path": "source/header.h", "target_path": "native/header.h",
                "sha256": file_sha256(header)}
    scope = replace(scope, files=(*scope.files, accepted),
                    _by_relative={**scope._by_relative, "header.h": accepted})

    class Executor(FakeExecutor):
        def execute(self, request):
            result = super().execute(request)
            path = request.scratch_root / f"{request.argv[1]}.json"
            document = json.loads(path.read_text())
            point = {"path": "/target/source/header.h", "line": 1, "column": 2}
            document["diagnostics"][0].update(
                notes=[{**point, "message": "cause", "ranges": [[point, point]]}],
                ranges=[[point, point]], trace_length=257, trace_truncated=True)
            path.write_text(json.dumps(document))
            return result

    result = job._analyze_scope(unit, scope, lambda _u: Executor(unit.job.run_root))
    identity = result["index_identity"]
    with sqlite3.connect(unit.job.run_root / identity["relative_path"]) as db:
        payload = json.loads(db.execute("select payload_json from entities where kind='tool_observation'").fetchone()[0])
    assert payload["trace"][0]["location"]["path"] == "native/header.h"
    assert payload["trace"][0]["location"]["file_sha256"] == file_sha256(header)
    assert payload["trace"][0]["ranges"][0]["location"]["start_byte"] == 1
    assert payload["ranges"][0]["location"]["path"] == "native/header.h"
    out = ProducerRows()
    _diagnostic_rows(ShardSet(unit.job.run_root, [identity]), [identity],
                     {"scope_id": "scope", "language": "cpp", "build_unit_id": "unit"}, "f" * 64, out)
    assert len(out.entities) == 2
    assert out.entities[0].payload["trace_truncated"] is True
    assert out.entities[0].payload["trace_length"] == 257
    assert out.entities[0].payload["trace_retained_count"] == 1
    assert out.entities[0].payload["ranges"] == payload["ranges"]
    assert any("trace" in gap for gap in result["gaps"])
    assert any("trace" in gap for gap in out.gaps)


def test_unresolved_trace_is_retained_as_unresolved_not_guessed(tmp_path):
    scope, unit = _scope(tmp_path), _unit(tmp_path)

    class Executor(FakeExecutor):
        def execute(self, request):
            result = super().execute(request)
            path = request.scratch_root / f"{request.argv[1]}.json"
            document = json.loads(path.read_text())
            document["diagnostics"][0]["notes"] = [
                {"message": "unmapped", "path": "/not-accepted/header.h", "line": 1, "column": 2},
                {"message": "missing path", "line": 1, "column": 2},
            ]
            path.write_text(json.dumps(document))
            return result

    result = job._analyze_scope(unit, scope, lambda _u: Executor(unit.job.run_root))
    assert result["observation_count"] == 2
    assert any("trace" in gap and "resolve" in gap for gap in result["gaps"])
    with sqlite3.connect(unit.job.run_root / result["index_identity"]["relative_path"]) as db:
        payload = json.loads(db.execute("select payload_json from entities where kind='tool_observation'").fetchone()[0])
    assert all(step["location"] is None and step["gap"] for step in payload["trace"])
