"""Seeded Clang AST and LLVM IR (docs/architecture/seeded-neighborhoods.md 5, 6, 7), on the 12-unit fixture."""
from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sqlite3

import pytest

from appsec_review import seeding
from appsec_review.jobs.job_cpp_compiled_analysis import build_job, seeded
from tests import seeded_clang_support as sc

REPLAYED = ("proj/src/net.cpp", "proj/src/util.cpp")


def _handlers(executor):
    job = build_job(executor_factory=lambda unit: executor)
    return {unit.unit_id: unit for unit in job.units}


def _run(staged, executor, name: str, *, seeded_settings=sc.SEEDED, ir=None):
    """Run the real branch handler of one unit against the staged project."""
    outputs = {"catalog.projects": {"projects": {sc.CASE: staged.cataloged}}}
    if ir is not None:
        outputs["ir.projects"] = ir
    unit = staged.unit(f"{name}.projects", outputs, seeded=seeded_settings)
    return _handlers(executor)[f"{name}.projects"].handler(unit), unit


def _pair(staged, executor, **kwargs):
    ir, _ = _run(staged, executor, "ir", **kwargs)
    ast, _ = _run(staged, executor, "ast", ir=ir, **kwargs)
    return ir, ast


def _rows(staged, output: dict, table: str = "entities") -> list[tuple]:
    path = staged.run_root / output["projects"][sc.CASE]["artifact"]["path"]
    return sqlite3.connect(path).execute(f"select * from {table}").fetchall()


def _coverage(staged, output: dict) -> list[tuple]:
    path = staged.run_root / output["projects"][sc.CASE]["artifact"]["path"]
    return sqlite3.connect(path).execute("select area, status, gap from coverage").fetchall()


class CannedExecutor(sc.FixtureExecutor):
    """Replace only the external compiler output; parsing, seeding and publication stay real."""

    def __init__(self, staged, *, ir=None, ast=None):
        super().__init__(staged.run_root)
        self.ir, self.ast = ir or {}, ast

    def execute(self, request):
        result = super().execute(request)
        mode = request.argv[1]
        rows = json.loads((request.scratch_root / f"replay-{mode}.json").read_text())
        for index, row in enumerate(rows):
            stem = Path(row["file"]).stem
            destination = request.scratch_root / "analysis" / mode
            if mode == "ir" and stem in self.ir:
                (destination / f"tu-{index:04d}.ll").write_text(self.ir[stem], encoding="utf-8")
            elif mode == "ast" and self.ast is not None:
                (destination / f"tu-{index:04d}.json").write_text(self.ast, encoding="utf-8")
        return result


def _canned_ir(definitions, path="src/util.cpp"):
    """Tiny clang-shaped text, not pre-normalized IrFunction objects."""
    lines = []
    for index, (linkage, name, line, calls, internal) in enumerate(definitions, 1):
        lines += [f'define {"internal " if internal else ""}i32 @{linkage}() !dbg !{index} {{',
                  "entry:"]
        lines += [f"  call i32 @{callee}(), !dbg !{100 + index}" for callee in calls]
        lines += [f"  ret i32 0, !dbg !{100 + index}", "}",
                  f'!{index} = distinct !DISubprogram(name: "{name}", file: !200, line: {line})',
                  f"!{100 + index} = !DILocation(line: {line + 1}, column: 3, scope: !{index})"]
    return "\n".join([*lines, f'!200 = !DIFile(filename: "{path}", directory: "/scratch/source")'])


def _indexed(staged, output):
    path = staged.run_root / output["projects"][sc.CASE]["artifact"]["path"]
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


@pytest.mark.parametrize("targets", [("_Z1fi",), ("_Z1fd",), ("_Z1fi", "_Z1fd")])
def test_overload_linkage_controls_exact_edges_and_neighborhood(tmp_path, targets):
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 12)])
    text = _canned_ir([
        ("_Z1fd", "f", 3, (), False), ("_Z1fi", "f", 8, (), False),
        ("_Z10copy_fieldv", "copy_field", 11, targets, False),
    ])
    ir, _ = _run(staged, CannedExecutor(staged, ir={"util": text}), "ir")
    with _indexed(staged, ir) as db:
        entities = {row["identity"]: json.loads(row["payload_json"]) for row in db.execute("select * from entities")}
        edges = [(entities[row["source_id"]]["linkage_name"], entities[row["target_id"]]["linkage_name"], row["exact"])
                 for row in db.execute("select * from relations where kind='CALLS'")]
    assert sorted(edges) == sorted(("_Z10copy_fieldv", target, 1) for target in targets)
    assert {item["linkage_name"] for item in entities.values()} == {"_Z10copy_fieldv", *targets}
    result = ir["projects"][sc.CASE]
    assert result["seeded"]["neighborhood_function_count"] == 1 + len(targets)
    assert len(result["handoff"]["ranges"]) == 1 + len(targets)


@pytest.mark.parametrize("internal", [False, True])
def test_same_linkage_in_other_tus_never_replaces_the_local_definition(tmp_path, internal):
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, CannedExecutor(staged, ir={
        "util": _canned_ir([("helper", "f", 3, (), internal),
                           ("copy_field", "copy_field", 13, ("helper",), False)]),
        "net": _canned_ir([("helper", "f", 2, (), internal),
                          ("handle_packet", "handle_packet", 5, ("helper",), False)], "src/net.cpp"),
    }), "ir")
    with _indexed(staged, ir) as db:
        entities = {row["identity"]: json.loads(row["payload_json"]) for row in db.execute("select * from entities")}
        edges = list(db.execute("select * from relations where kind='CALLS'"))
    assert len(edges) == 2
    for edge in edges:
        assert entities[edge["source_id"]]["compile_unit_id"] == entities[edge["target_id"]]["compile_unit_id"]
    result = ir["projects"][sc.CASE]
    assert result["seeded"]["neighborhood_function_count"] == 4
    assert len(result["handoff"]["ranges"]) == 4


@pytest.mark.parametrize("internal", [False, True])
def test_unresolved_cross_tu_linkage_never_guesses_a_definition(tmp_path, internal):
    other = next(stem for stem in sc.SOURCES if stem not in {"net", "util"})
    staged = sc.stage(tmp_path, observations=[sc.observation(f"proj/src/{stem}.cpp", 6)
                                             for stem in ("net", "util", other)])
    modules = {stem: _canned_ir([("helper", "f", 5, (), internal)], f"src/{stem}.cpp")
               for stem in ("util", other)}
    modules["net"] = _canned_ir([("caller", "caller", 5, ("helper",), False)], "src/net.cpp")
    ir, _ = _run(staged, CannedExecutor(staged, ir=modules), "ir")
    with _indexed(staged, ir) as db:
        rows = list(db.execute("select e.payload_json from relations r join entities e "
                               "on r.target_id=e.identity where r.kind='CALLS'"))
    assert len(rows) == 1
    assert json.loads(rows[0][0])["kind"] == "declaration"
    if not internal:
        assert any("ambiguous cross-translation-unit" in gap for gap in ir["projects"][sc.CASE]["gaps"])


def test_seeded_ast_filters_overloads_by_mangled_identity_not_the_display_filter(tmp_path):
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 12)])
    ir_text = _canned_ir([
        ("_Z1fd", "f", 3, (), False), ("_Z1fi", "f", 8, (), False),
        ("caller", "copy_field", 11, ("_Z1fi",), False),
    ])
    ast_text = "\n".join(json.dumps({
        "id": linkage, "kind": "FunctionDecl", "name": name, "mangledName": linkage,
        "loc": {"file": "/scratch/source/src/util.cpp", "line": line, "col": 1},
        "inner": [{"id": linkage + "-param", "kind": "ParmVarDecl", "name": linkage + "-param",
                   "loc": {"line": line, "col": 1}}],
    }) for linkage, name, line in [("_Z1fd", "f", 3), ("_Z1fi", "f", 8), ("caller", "copy_field", 11)])
    ir, ast = _pair(staged, CannedExecutor(staged, ir={"util": ir_text}, ast=ast_text))
    payloads = [json.loads(row[5]) for row in _rows(staged, ast)]
    assert {item["mangled_name"] for item in payloads if item["kind"] == "FunctionDecl"} == {"_Z1fi", "caller"}
    assert {row[3] for row in _rows(staged, ast) if json.loads(row[5])["kind"] == "ParmVarDecl"} == {
        "_Z1fi-param", "caller-param"}
    assert ir["projects"][sc.CASE]["seeded"]["neighborhood_function_count"] == 2


def test_equal_source_ranges_do_not_arbitrarily_resolve_an_overload_seed(tmp_path):
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 12)])
    text = _canned_ir([("_Z1fd", "f", 11, (), False), ("_Z1fi", "f", 11, (), False)])
    ir, _ = _run(staged, CannedExecutor(staged, ir={"util": text}), "ir")
    result = ir["projects"][sc.CASE]
    assert result["seeded"]["resolved_seed_count"] == 0
    assert result["entity_count"] == 0
    assert any("seed_function_ambiguous" in gap for gap in result["gaps"])


def test_missing_ir_definition_line_keeps_linkage_without_an_exact_line_one(tmp_path):
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 12)])
    text = _canned_ir([("callee", "f", 0, (), False), ("caller", "copy_field", 11, ("callee",), False)])
    ir, _ = _run(staged, CannedExecutor(staged, ir={"util": text}), "ir")
    with _indexed(staged, ir) as db:
        rows = list(db.execute("select e.payload_json, l.start_line from entities e "
                               "left join locations l on e.identity=l.entity_id"))
    assert next(row["start_line"] for row in rows if json.loads(row["payload_json"])["linkage_name"] == "callee") is None
    result = ir["projects"][sc.CASE]
    assert len(result["handoff"]["ranges"]) == 1
    assert any("ir_location_unresolved" in gap for gap in result["gaps"])


def test_recorded_ast_header_and_expression_locations_keep_their_source_bytes(tmp_path):
    staged = sc.stage(tmp_path)
    _, ast = _pair(staged, sc.FixtureExecutor(staged.run_root))
    with _indexed(staged, ast) as db:
        rows = list(db.execute("select e.name, e.payload_json, l.* from entities e "
                               "join locations l on e.identity=l.entity_id"))
    declarations = [row for row in rows if row["name"] == "copy_field" and
                    json.loads(row["payload_json"])["kind"] == "FunctionDecl"]
    assert {(row["path"], row["start_line"]) for row in declarations} == {
        ("proj/include/util.h", 3), ("proj/src/util.cpp", 11)}
    for row in declarations:
        data = (staged.target / row["path"]).read_bytes()
        assert row["file_sha256"] == hashlib.sha256(data).hexdigest()
        assert data[row["start_byte"]:row["end_byte"]] == b"copy_field"
    call = next(row for row in rows if row["name"] == "checked_len" and
                json.loads(row["payload_json"])["kind"] == "CallExpr")
    assert call["path"] == "proj/src/util.cpp" and call["start_line"] == 12
    data = (staged.target / call["path"]).read_bytes()
    assert data[call["start_byte"]:call["end_byte"]] == b"checked_len"
    header_param = next(row for row in rows if row["name"] == "dst" and row["path"] == "proj/include/util.h")
    assert header_param["start_line"] == 3
    data = (staged.target / header_param["path"]).read_bytes()
    assert data[header_param["start_byte"]:header_param["end_byte"]] == b"dst"


@pytest.mark.parametrize("coordinates", ["offset", "line-column", "range"])
def test_ast_positions_preserve_utf8_and_crlf_bytes(tmp_path, coordinates):
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 14)])
    data = "// π\r\nint f();\r\n".encode("utf-8")
    header = staged.target / "proj/include/util.h"
    header.write_bytes(data)
    record = next(row for row in staged.mapping["files"] if row["target_path"] == "proj/include/util.h")
    record["sha256"] = hashlib.sha256(data).hexdigest()
    offset = data.index(b"f")
    point = {"file": "/scratch/source/include/util.h", "tokLen": 1}
    point.update({"line": 2, "col": 5} if coordinates == "line-column" else {"offset": offset})
    node = {"id": "0x1", "kind": "VarDecl", "name": "f"}
    node.update({"range": {"begin": point}} if coordinates == "range" else {"loc": point})
    _, ast = _pair(staged, CannedExecutor(staged, ast=json.dumps(node)))
    with _indexed(staged, ast) as db:
        location = db.execute("select * from locations").fetchone()
    assert location["path"] == "proj/include/util.h"
    assert (location["start_line"], location["start_column"]) == (2, 5)
    assert (location["start_byte"], location["end_byte"]) == (offset, offset + 1)
    assert location["file_sha256"] == hashlib.sha256(data).hexdigest()
    assert header.read_bytes() == data


@pytest.mark.parametrize("invalid", ["changed-bytes", "duplicate-mapping"])
def test_ast_location_requires_unique_accepted_file_bytes(tmp_path, invalid):
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 14)])
    if invalid == "changed-bytes":
        (staged.target / "proj/include/util.h").write_bytes(b"changed\n")
    else:
        row = next(row for row in staged.mapping["files"] if row["target_path"] == "proj/include/util.h")
        staged.mapping["files"].append(dict(row))
    node = {"id": "0x1", "kind": "VarDecl", "name": "f",
            "loc": {"file": "/scratch/source/include/util.h", "offset": 0, "tokLen": 1}}
    _, ast = _pair(staged, CannedExecutor(staged, ast=json.dumps(node)))
    with _indexed(staged, ast) as db:
        assert db.execute("select count(*) from locations").fetchone()[0] == 0
    assert any("ast_location_unresolved" in gap for gap in ast["projects"][sc.CASE]["gaps"])


@pytest.mark.parametrize("location", [
    {}, {"line": 2, "col": 1}, {"file": "/foreign/util.h", "line": 2, "col": 1},
    {"file": "/scratch/source/include/util.h", "offset": 999999, "line": 2, "col": 1},
    {"spellingLoc": {"file": "/scratch/source/include/util.h", "offset": 17, "tokLen": 3},
     "expansionLoc": {"file": "/scratch/source/src/util.cpp", "offset": 0, "tokLen": 1}},
])
def test_absent_or_ambiguous_ast_metadata_never_fabricates_an_exact_tu_location(tmp_path, location):
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 14)])
    text = json.dumps({"id": "0x1", "kind": "FunctionDecl", "name": "copy_field",
                       "mangledName": "_Z10copy_fieldPcPKci", "loc": location})
    _, ast = _pair(staged, CannedExecutor(staged, ast=text))
    with _indexed(staged, ast) as db:
        assert db.execute("select count(*) from entities").fetchone()[0] == 1
        assert db.execute("select count(*) from locations where confidence=1 and ambiguous=0").fetchone()[0] == 0
    assert any("ast_location" in gap for gap in ast["projects"][sc.CASE]["gaps"])


def test_only_the_seeded_units_are_replayed_never_the_whole_program(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root)
    assert len(staged.rows) == 12
    _pair(staged, executor)
    assert executor.calls == [("ir", REPLAYED), ("cfg", REPLAYED), ("ast", REPLAYED)]
    assert not any(len(units) > 2 for _, units in executor.calls)


def test_seeded_ir_publishes_the_neighborhood_with_flow_and_calls(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir")
    result = ir["projects"][sc.CASE]
    handoff = result["handoff"]
    assert {handoff["functions"][key]["name"]: distance for key, distance in handoff["neighborhood"].items()} == {
        "copy_field": 0, "handle_packet": 0, "checked_len": 1, "log_event": 1, "clamp_len": 2}
    assert all(key == f"{fn['compile_unit_id']}:{fn['linkage_name']}" for key, fn in handoff["functions"].items())
    assert result["call_edge_count"] == 4 and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    record = result["index_identity"]["producer"]["seeded"]
    assert record["resolved_seed_count"] == 2 and record["status_counts"] == {"resolved": 2}
    assert [name for _, status, _ in [row for row in _coverage(staged, ir)] for name in [status]] == ["partial"]
    flows = [json.loads(row[5]) for row in _rows(staged, ir)]
    function = next(item for item in flows if item.get("linkage_name", "").startswith("_Z10copy_field"))
    assert function["flow"]["blocks"] and function["flow"]["dominators"] and function["seeded"] is True


def _payloads(staged, output: dict) -> dict[str, dict]:
    return {row[3]: json.loads(row[5]) for row in _rows(staged, output)}


def test_source_cfg_is_attached_to_the_neighborhood_functions_with_a_named_line_gap(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir")
    result = ir["projects"][sc.CASE]
    payloads = _payloads(staged, ir)
    cfg = payloads["copy_field"]["source_cfg"]
    assert cfg["producer"] == "clang-cfg" and cfg["entry"] and cfg["exit"] and cfg["branches"] == 1
    branch = next(block for block in cfg["blocks"] if block["terminator"] == "if")
    assert branch["condition"] == "src == nullptr" and len(branch["successors"]) == 2
    assert any(call == "memcpy(dst, src, n)" for block in cfg["blocks"] for call in block["calls"])
    assert result["source_cfg_count"] == 5
    assert set(payloads) == {"copy_field", "handle_packet", "checked_len", "log_event", "clamp_len"}
    assert all("source_cfg" in value for value in payloads.values())
    assert any(gap.startswith("source_cfg_no_block_lines") for gap in result["gaps"])
    assert {status for _, status, _ in _coverage(staged, ir)} == {"partial"}


def test_a_failed_cfg_replay_keeps_the_ir_flow_and_names_the_gap(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root, fail=(("cfg", "util"),))
    ir, _ = _run(staged, executor, "ir")
    result = ir["projects"][sc.CASE]
    payloads = _payloads(staged, ir)
    assert any(gap.startswith("source_cfg_unavailable") and "proj/src/util.cpp" in gap for gap in result["gaps"])
    assert "source_cfg" not in payloads["copy_field"] and "flow" in payloads["copy_field"]
    assert "source_cfg" in payloads["handle_packet"]
    assert any(gap.startswith("source_cfg_unmatched") and "copy_field" in gap for gap in result["gaps"])
    assert {status for _, status, _ in _coverage(staged, ir)} == {"partial"}


def test_zero_seeds_is_a_clean_skip_with_a_named_gap_and_partial_coverage(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path, observations=[])
    executor = sc.FixtureExecutor(staged.run_root)
    ir, ast = _pair(staged, executor)
    assert executor.calls == []
    for output in (ir, ast):
        result = output["projects"][sc.CASE]
        assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and output["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert result["gaps"][0] == seeding.NO_SEEDS_GAP and result["entity_count"] == 0
        assert result["index_identity"]["producer"]["seeded"]["skipped"] is True
        assert {status for _, status, _ in _coverage(staged, output)} == {"partial"}


def test_a_failed_replay_is_a_gap_on_the_seeds_it_carried_and_never_raises_coverage(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root, fail=(("ir", "util"),))
    ir, ast = _pair(staged, executor)
    result = ir["projects"][sc.CASE]
    assert any("proj/src/util.cpp" in gap and "failed" in gap for gap in result["gaps"])
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    by_path = {entry["path"]: entry for entry in ledger}
    assert by_path["src/util.cpp"]["status"] == "unresolved" and by_path["src/util.cpp"]["reason"] == "producer_failed"
    assert by_path["src/net.cpp"]["status"] == "resolved"
    assert {status for _, status, _ in _coverage(staged, ir)} == {"partial"}
    assert result["checkpointable"] is False
    # The AST is anchored to the IR neighborhood: the failed unit is not replayed for it either.
    assert ("ast", REPLAYED[:1]) == executor.calls[-1] or all("util" not in unit for unit in executor.calls[-1][1])


def test_a_total_replay_failure_is_unavailable_coverage(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root, exit_code=9)
    ir, ast = _pair(staged, executor)
    result = ir["projects"][sc.CASE]
    assert {status for _, status, _ in _coverage(staged, ir)} == {"unavailable"}
    assert result["entity_count"] == 0 and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    # No IR neighborhood means no AST replay at all, and the seeds say why.
    assert [call for call in executor.calls if call[0] == "ast"] == []
    ast_result = ast["projects"][sc.CASE]
    assert any(gap.startswith("ast_without_neighborhood") for gap in ast_result["gaps"])
    ledger = json.loads((staged.run_root / ast_result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    assert {entry["reason"] for entry in ledger} == {"not_run"}


def test_a_seed_in_no_translation_unit_is_a_named_gap(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/include/orphan.h", 3),
                                              sc.observation("proj/src/util.cpp", 14)])
    # The file is in the mapping (a header nothing includes) but belongs to no replayed unit.
    (staged.target / "proj" / "include" / "orphan.h").write_text("int orphan();\n")
    staged.mapping["files"].append({"target_path": "proj/include/orphan.h", "scratch_path": "source/include/orphan.h",
                                    "sha256": "d" * 64})
    executor = sc.FixtureExecutor(staged.run_root)
    ir, _ = _run(staged, executor, "ir")
    result = ir["projects"][sc.CASE]
    assert any(gap.startswith("seed_without_translation_unit") for gap in result["gaps"])
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    assert {entry["path"]: entry.get("reason") for entry in ledger}["include/orphan.h"] == "no_translation_unit"
    assert executor.calls == [("ir", ("proj/src/util.cpp",)), ("cfg", ("proj/src/util.cpp",))]


@pytest.mark.parametrize("override, expected", [
    ({"function_limit": 2}, "limit_reached"),
    ({"depth": 1}, "depth_reached"),
    ({"block_limit": 1}, "export_truncated"),
    ({"unit_limit": 1}, "unit_limit_reached"),
])
def test_named_bounds_produce_named_gaps(tmp_path: Path, override: dict, expected: str) -> None:
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir", seeded_settings={**sc.SEEDED, **override})
    assert any(gap.startswith(expected) for gap in ir["projects"][sc.CASE]["gaps"]), ir["projects"][sc.CASE]["gaps"]


def test_every_ir_neighborhood_carries_a_frontier_gap_for_unreplayed_callers(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir")
    assert any(gap.startswith("frontier") for gap in ir["projects"][sc.CASE]["gaps"])


def test_ast_call_expressions_name_their_callee(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    _, ast = _pair(staged, sc.FixtureExecutor(staged.run_root))
    calls = [json.loads(row[5]) for row in _rows(staged, ast) if json.loads(row[5])["kind"] == "CallExpr"]
    callees = {item["referenced_decl"]["name"] for item in calls if item["referenced_decl"]}
    assert {"checked_len", "copy_field", "clamp_len"} <= callees


def test_resume_identity_is_per_producer(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root)
    ir, ast = _pair(staged, executor)
    assert len(executor.calls) == 3
    # Unchanged settings and seed set: both producers reuse their checkpoints, nothing is replayed.
    again_ir, again_ast = _pair(staged, executor)
    assert len(executor.calls) == 3
    assert again_ir["projects"][sc.CASE]["checkpoint_reused"] and again_ast["projects"][sc.CASE]["checkpoint_reused"]
    # A different depth changes both seeded producers' identity: both run again.
    _pair(staged, executor, seeded_settings={**sc.SEEDED, "depth": 2})
    assert [mode for mode, _ in executor.calls[3:]] == ["ir", "cfg", "ast"]
    # A different mode (whole program) is a different identity again, and replays every unit.
    whole = sc.FixtureExecutor(staged.run_root)
    _run(staged, whole, "ir", seeded_settings=None)
    assert len(whole.calls[0][1]) == 12


def test_a_changed_seed_set_reruns_the_ir_and_the_ast(tmp_path: Path) -> None:
    staged = sc.stage(tmp_path)
    executor = sc.FixtureExecutor(staged.run_root)
    _pair(staged, executor)
    changed = sc.stage(tmp_path / "other", observations=[sc.observation("proj/src/util.cpp", 14)])
    # Same case root layout, different seed set: the checkpoint identity differs, so nothing is reused.
    other = sc.FixtureExecutor(changed.run_root)
    ir, _ = _pair(changed, other)
    assert not ir["projects"][sc.CASE].get("checkpoint_reused") and other.calls[0] == ("ir", REPLAYED[1:])


def test_shards_and_records_are_byte_identical_across_runs(tmp_path: Path) -> None:
    outputs = []
    for name in ("a", "b"):
        staged = sc.stage(tmp_path / name)
        ir, ast = _pair(staged, sc.FixtureExecutor(staged.run_root))
        outputs.append([(item["projects"][sc.CASE]["index_identity"]["sha256"],
                         item["projects"][sc.CASE]["index_identity"]["producer"]["seeded"],
                         item["projects"][sc.CASE]["ledger"]["sha256"]) for item in (ir, ast)])
    assert outputs[0] == outputs[1]


def test_seeded_helpers_and_failure_branches(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from appsec_review.jobs.job_cpp_compiled_analysis import clang_cfg, llvm_ir

    # settings_of with whole_program seeded settings and _function_path rejections.
    bare = SimpleNamespace(job=SimpleNamespace(config=SimpleNamespace(settings={"seeded": {"mode": "whole_program"}})))
    assert seeded.settings_of(bare).seeded is False
    dummy_fn = lambda p: llvm_ir.IrFunction("f", "f", p, 1, 2, False, (), {}, {}, (), (), 0, ())
    assert seeded._function_path("proj", dummy_fn("")) is None
    assert seeded._function_path("proj", dummy_fn("/usr/include/stdio.h")) is None
    assert seeded._function_path("proj", dummy_fn("../escape.h")) is None
    assert seeded._function_path("proj", dummy_fn("src/a.cpp")) == "proj/src/a.cpp"

    # _match_cfgs: missing unit, overloaded ambiguity, and unmatched function.
    fn_a1 = dummy_fn("src/a.cpp")
    fn_a2 = llvm_ir.IrFunction("ns::f", "_ZN2ns1fEd", "src/a.cpp", 5, 6, False, (), {}, {}, (), (), 0, ())
    fn_b = llvm_ir.IrFunction("missing_fn", "missing_fn", "src/a.cpp", 9, 10, False, (), {}, {}, (), (), 0, ())
    fn_c = llvm_ir.IrFunction("other_tu", "other_tu", "src/b.cpp", 1, 2, False, (), {}, {}, (), (), 0, ())
    cfg_dup = clang_cfg.SourceCfg("void f()", "f", "f", 0, (), ())
    matched, ambig, miss = seeded._match_cfgs(
        [(0, fn_a1), (0, fn_a2), (0, fn_b), (1, fn_c)],
        {(0, "f"), (0, "_ZN2ns1fEd"), (0, "missing_fn"), (1, "other_tu")},
        {0: [cfg_dup, cfg_dup]},
    )
    assert matched == {}
    assert ambig == ["f", "ns::f"]
    assert miss == ["missing_fn", "other_tu"]

    # _source_cfgs: timed_out, oom_killed, unusable receipt, missing .cfg.txt, and module.gaps.
    staged = sc.stage(tmp_path / "cfg_edges")
    unit = staged.unit("ir.projects")
    root = staged.run_root / "data" / "cpp" / "projects" / sc.CASE
    subset = staged.cataloged["compile_commands"][:1]
    settings = seeded.settings_of(unit)

    def _exec_result(*, timed_out=False, oom_killed=False, write_receipt=True, write_cfg=None):
        def factory(_u):
            class E:
                def execute(self, req):
                    (req.scratch_root / "raw").mkdir(parents=True, exist_ok=True)
                    (req.scratch_root / "raw" / "stdout.bin").write_bytes(b"")
                    (req.scratch_root / "raw" / "stderr.bin").write_bytes(b"")
                    (req.scratch_root / "execution.json").write_text("{}", encoding="utf-8")
                    dest = req.scratch_root / "analysis" / req.argv[1]
                    dest.mkdir(parents=True, exist_ok=True)
                    if write_receipt:
                        (dest / "receipt.json").write_text(json.dumps([{"index": 0, "exit_code": 0}]))
                    if write_cfg is not None:
                        (dest / "tu-0000.cfg.txt").write_text(write_cfg, encoding="utf-8")
                    rel = lambda p: p.relative_to(staged.run_root).as_posix()
                    from appsec_review.container_runtime.executor import ExecutionResult
                    return ExecutionResult("appsec-review/container-execution/1", req.tool_id,
                                           "img", sc.DIGEST, sc.DIGEST, "argv", (), {}, "s", "e",
                                           0, timed_out, oom_killed, False, False,
                                           rel(req.scratch_root / "raw" / "stdout.bin"),
                                           rel(req.scratch_root / "raw" / "stderr.bin"),
                                           rel(req.scratch_root / "execution.json"))
            return E()
        return factory

    gaps: list[str] = []
    seeded._source_cfgs(unit, sc.CASE, root, subset, settings, _exec_result(timed_out=True), gaps)
    assert any("timed out" in g for g in gaps)
    gaps.clear()
    seeded._source_cfgs(unit, sc.CASE, root, subset, settings, _exec_result(oom_killed=True), gaps)
    assert any("ran out of memory" in g for g in gaps)
    gaps.clear()
    seeded._source_cfgs(unit, sc.CASE, root, subset, settings, _exec_result(write_receipt=False), gaps)
    assert any("receipt unusable" in g for g in gaps)
    gaps.clear()
    seeded._source_cfgs(unit, sc.CASE, root, subset, settings, _exec_result(write_cfg=None), gaps)
    assert any("CFG text unavailable or over bound" in g for g in gaps)
    gaps.clear()
    seeded._source_cfgs(unit, sc.CASE, root, subset, settings,
                        _exec_result(write_cfg="bad_head\n [B1]\n   1: x\n"), gaps)
    assert any("source_cfg_unparsed" in g for g in gaps)


def test_seeded_ir_and_ast_unusual_replay_and_neighborhood_branches(tmp_path: Path) -> None:
    # 1. ast_without_neighborhood when IR output has no handoff.
    staged = sc.stage(tmp_path / "no_hood")
    ast_out, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ast",
                      ir={"projects": {sc.CASE: {"terminal_status": "COMPLETED_WITH_GAPS", "gaps": []}}})
    assert any("ast_without_neighborhood" in g for g in ast_out["projects"][sc.CASE]["gaps"])

    # 2. Custom IR with: declared external function in neighborhood, unparsed function without !dbg,
    #    overloaded cross-TU callee ambiguity, and missing second .ll file.
    staged2 = sc.stage(tmp_path / "custom_ir")
    ir_text_0 = "\n".join([
        'define i32 @handle_packet(ptr %p, i32 %n) !dbg !10 {',
        'entry:',
        '  call void @external_sink(i32 %n), !dbg !11',
        '  call void @dup_callee(), !dbg !11',
        '  ret i32 0, !dbg !11',
        '}',
        'define void @no_dbg_fn() {',
        '  ret void',
        '}',
        'define void @dup_callee() !dbg !12 {',
        '  ret void, !dbg !13',
        '}',
        '!10 = distinct !DISubprogram(name: "handle_packet", file: !20, line: 5)',
        '!11 = !DILocation(line: 6, column: 3, scope: !10)',
        '!12 = distinct !DISubprogram(name: "dup_callee", file: !20, line: 10)',
        '!13 = !DILocation(line: 11, column: 3, scope: !12)',
        '!20 = !DIFile(filename: "src/net.cpp", directory: "/scratch/source")',
    ])
    ir_text_1 = "\n".join([
        'define void @dup_callee() !dbg !10 {',
        '  ret void, !dbg !11',
        '}',
        '!10 = distinct !DISubprogram(name: "dup_callee", file: !20, line: 12)',
        '!11 = !DILocation(line: 14, column: 3, scope: !10)',
        '!20 = !DIFile(filename: "src/util.cpp", directory: "/scratch/source")',
    ])

    class CustomIrExecutor:
        def execute(self, req):
            root, mode = req.scratch_root, req.argv[1]
            rows = json.loads((root / f"replay-{mode}.json").read_text())
            dest = root / "analysis" / mode
            dest.mkdir(parents=True, exist_ok=True)
            if mode == "ir":
                (dest / "tu-0000.ll").write_text(ir_text_0, encoding="utf-8")
                (dest / "tu-0001.ll").write_text(ir_text_1, encoding="utf-8")
            elif mode == "cfg":
                # Empty CFG dump -> triggers source_cfg_unmatched on neighborhood functions.
                for idx in range(len(rows)):
                    (dest / f"tu-{idx:04d}.cfg.txt").write_text("void unrelated()\n [B1]\n   1: 0\n", encoding="utf-8")
            else:
                # AST partial failure: unit 0 succeeds, unit 1 fails with exit 2.
                (dest / "tu-0000.json").write_text(json.dumps({
                    "kind": "TranslationUnitDecl",
                    "inner": [{"id": "0x1", "kind": "FunctionDecl", "name": "handle_packet", "loc": {"line": 5, "col": 1}}],
                }), encoding="utf-8")
                (dest / "receipt.json").write_text(json.dumps([
                    {"index": 0, "exit_code": 0},
                    {"index": 1, "exit_code": 1, "stderr": "error: unit 1 failed"},
                ]))
                (root / "raw").mkdir(exist_ok=True)
                (root / "raw" / "stdout.bin").write_bytes(b"")
                (root / "raw" / "stderr.bin").write_bytes(b"")
                (root / "execution.json").write_text("{}", encoding="utf-8")
                rel = lambda p: p.relative_to(staged2.run_root).as_posix()
                from appsec_review.container_runtime.executor import ExecutionResult
                return ExecutionResult("appsec-review/container-execution/1", req.tool_id,
                                       "img", sc.DIGEST, sc.DIGEST, "argv", (), {}, "s", "e",
                                       2, False, False, False, False,
                                       rel(root / "raw" / "stdout.bin"),
                                       rel(root / "raw" / "stderr.bin"),
                                       rel(root / "execution.json"))
            (dest / "receipt.json").write_text(json.dumps([{"index": i, "exit_code": 0} for i in range(len(rows))]))
            (root / "raw").mkdir(exist_ok=True)
            (root / "raw" / "stdout.bin").write_bytes(b"")
            (root / "raw" / "stderr.bin").write_bytes(b"")
            (root / "execution.json").write_text("{}", encoding="utf-8")
            rel = lambda p: p.relative_to(staged2.run_root).as_posix()
            from appsec_review.container_runtime.executor import ExecutionResult
            return ExecutionResult("appsec-review/container-execution/1", req.tool_id,
                                   "img", sc.DIGEST, sc.DIGEST, "argv", (), {}, "s", "e",
                                   0, False, False, False, False,
                                   rel(root / "raw" / "stdout.bin"),
                                   rel(root / "raw" / "stderr.bin"),
                                   rel(root / "execution.json"))

    # Note: dup_callee is defined in two TUs without a local def in TU 2 -> test declared external + unparsed + unmatched CFG.
    ir_res, _ = _run(staged2, CustomIrExecutor(), "ir")
    ir_proj = ir_res["projects"][sc.CASE]
    assert any("carry no debug subprogram" in g for g in ir_proj["gaps"])
    assert any("source_cfg_unmatched" in g for g in ir_proj["gaps"])
    payloads = [json.loads(row[5]) for row in _rows(staged2, ir_res)]
    assert any(p.get("kind") == "declaration" for p in payloads)

    ast_res, _ = _run(staged2, CustomIrExecutor(), "ast", ir=ir_res)
    assert ast_res["projects"][sc.CASE]["entity_count"] >= 1

    # 3. Unusable receipt (exit 0, no receipt.json) and hard exit!=0 failure in AST & IR.
    staged3 = sc.stage(tmp_path / "unusable")

    class NoReceiptExecutor:
        def __init__(self, code: int = 0, write_failed_receipt: bool = False):
            self.code = code
            self.write_failed_receipt = write_failed_receipt

        def execute(self, req):
            root, mode = req.scratch_root, req.argv[1]
            rows = json.loads((root / f"replay-{mode}.json").read_text())
            dest = root / "analysis" / mode
            dest.mkdir(parents=True, exist_ok=True)
            if self.write_failed_receipt:
                (dest / "receipt.json").write_text(json.dumps(
                    [{"index": i, "exit_code": 1, "stderr": "error: boom"} for i in range(len(rows))]
                ))
            (root / "raw").mkdir(exist_ok=True)
            (root / "raw" / "stdout.bin").write_bytes(b"")
            (root / "raw" / "stderr.bin").write_bytes(b"")
            (root / "execution.json").write_text("{}", encoding="utf-8")
            rel = lambda p: p.relative_to(staged3.run_root).as_posix()
            from appsec_review.container_runtime.executor import ExecutionResult
            return ExecutionResult("appsec-review/container-execution/1", req.tool_id,
                                   "img", sc.DIGEST, sc.DIGEST, "argv", (), {}, "s", "e",
                                   self.code, False, False, False, False,
                                   rel(root / "raw" / "stdout.bin"),
                                   rel(root / "raw" / "stderr.bin"),
                                   rel(root / "execution.json"))

    ir_unusable, _ = _run(staged3, NoReceiptExecutor(0), "ir")
    assert any("ir replay receipt unusable" in g for g in ir_unusable["projects"][sc.CASE]["gaps"])
    ir_hard_fail, _ = _run(staged3, NoReceiptExecutor(9, write_failed_receipt=True), "ir")
    assert any("ir failed with exit 9" in g and "error: boom" in g for g in ir_hard_fail["projects"][sc.CASE]["gaps"])
    ast_unusable, _ = _run(staged3, NoReceiptExecutor(0), "ast", ir=ir_res)
    assert any("ast replay receipt unusable" in g for g in ast_unusable["projects"][sc.CASE]["gaps"])
    ast_hard_fail, _ = _run(staged3, NoReceiptExecutor(9, write_failed_receipt=True), "ast", ir=ir_res)
    assert any("ast failed with exit 9" in g and "error: boom" in g for g in ast_hard_fail["projects"][sc.CASE]["gaps"])

    # 4. Seed with no matching translation unit, missing .ll file, and AST unit_limit=1 cap.
    staged4 = sc.stage(tmp_path / "no_tu", observations=[sc.observation(f"{sc.ROOT}/src/uncompiled_only.cpp", 1)])
    (staged4.target / sc.ROOT / "src" / "uncompiled_only.cpp").write_text("int orphan() { return 0; }\n", encoding="utf-8")
    ir_no_tu, _ = _run(staged4, NoReceiptExecutor(0), "ir")
    assert ir_no_tu["projects"][sc.CASE]["entity_count"] == 0

    class MissingLlExecutor:
        def execute(self, req):
            root, mode = req.scratch_root, req.argv[1]
            rows = json.loads((root / f"replay-{mode}.json").read_text())
            dest = root / "analysis" / mode
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "receipt.json").write_text(json.dumps([{"index": i, "exit_code": 0} for i in range(len(rows))]))
            (root / "raw").mkdir(exist_ok=True)
            (root / "raw" / "stdout.bin").write_bytes(b"")
            (root / "raw" / "stderr.bin").write_bytes(b"")
            (root / "execution.json").write_text("{}", encoding="utf-8")
            rel = lambda p: p.relative_to(staged3.run_root).as_posix()
            from appsec_review.container_runtime.executor import ExecutionResult
            return ExecutionResult("appsec-review/container-execution/1", req.tool_id,
                                   "img", sc.DIGEST, sc.DIGEST, "argv", (), {}, "s", "e",
                                   0, False, False, False, False,
                                   rel(root / "raw" / "stdout.bin"),
                                   rel(root / "raw" / "stderr.bin"),
                                   rel(root / "execution.json"))

    ir_missing_ll, _ = _run(staged3, MissingLlExecutor(), "ir")
    assert any("LLVM IR output unavailable or over bound" in g for g in ir_missing_ll["projects"][sc.CASE]["gaps"])

    two_unit_ir = {
        "projects": {
            sc.CASE: {
                "handoff": {
                    "function_units": {"fn_a": [0], "fn_b": [1]},
                    "neighborhood": {"fn_a": 0, "fn_b": 1},
                    "seed_functions": [],
                },
                "handoff_sha256": "h" * 64,
            }
        }
    }
    ast_unit_cap, _ = _run(staged3, MissingLlExecutor(), "ast", seeded_settings={**sc.SEEDED, "unit_limit": 1}, ir=two_unit_ir)
    assert any("unit_limit 1 reached" in g for g in ast_unit_cap["projects"][sc.CASE]["gaps"])
    assert seeded is not None
