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


class DamagedExecutor(sc.FixtureExecutor):
    def __init__(self, staged, mode, damage):
        super().__init__(staged.run_root)
        self.mode, self.damage = mode, damage

    def execute(self, request):
        result = super().execute(request)
        if request.argv[1] == self.mode:
            destination = request.scratch_root / "analysis" / self.mode
            if self.damage == "receipt":
                (destination / "receipt.json").unlink()
            else:
                suffix = {"ir": "ll", "ast": "json", "cfg": "cfg.txt"}[self.mode]
                for path in destination.glob(f"tu-*.{suffix}"):
                    path.write_text(self.damage, encoding="utf-8")
        return result


@pytest.mark.parametrize("damage", ["{broken", "{}", "[]"])
def test_ast_parse_failure_does_not_resolve_seeds_or_survive_retry(tmp_path, damage):
    staged = sc.stage(tmp_path)
    ir, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir")
    ast, _ = _run(staged, DamagedExecutor(staged, "ast", damage), "ast", ir=ir)
    failed = ast["projects"][sc.CASE]
    assert failed["seeded"]["resolved_seed_count"] == 0
    assert failed["checkpointable"] is False
    ledger_path = staged.run_root / failed["ledger"]["path"]
    ledger_bytes = ledger_path.read_bytes()
    ledger = json.loads(ledger_bytes)["seeded"]["seeds"]
    assert {row["reason"] for row in ledger} == {"producer_failed"}
    executor = sc.FixtureExecutor(staged.run_root)
    repaired, _ = _run(staged, executor, "ast", ir=ir)
    assert executor.calls and not repaired["projects"][sc.CASE].get("checkpoint_reused")
    assert repaired["projects"][sc.CASE]["seeded"]["resolved_seed_count"] == 2
    assert ledger_path.read_bytes() == ledger_bytes
    assert repaired["projects"][sc.CASE]["artifact"] != failed["artifact"]
    assert len(_rows(staged, repaired)) > 0


@pytest.mark.parametrize("mode,damage", [
    ("cfg", "receipt"), ("cfg", "malformed CFG"),
    ("ir", "not LLVM IR"),
    ("ir", "define void @missing_debug() {\nentry:\n  ret void\n}\n"),
], ids=["cfg-receipt", "cfg-malformed", "ir-malformed", "ir-no-debug"])
def test_failed_or_unparsed_replay_is_retried_without_reusing_old_shards(tmp_path, mode, damage):
    staged = sc.stage(tmp_path)
    first, _ = _run(staged, DamagedExecutor(staged, mode, damage), "ir")
    failed = first["projects"][sc.CASE]
    assert failed["checkpointable"] is False
    assert failed["gaps"]
    old_path = staged.run_root / failed["artifact"]["path"]
    old_bytes = old_path.read_bytes()
    executor = sc.FixtureExecutor(staged.run_root)
    repaired, _ = _run(staged, executor, "ir")
    assert executor.calls and not repaired["projects"][sc.CASE].get("checkpoint_reused")
    assert repaired["projects"][sc.CASE]["source_cfg_count"] == 5
    assert old_path.read_bytes() == old_bytes
    assert repaired["projects"][sc.CASE]["artifact"] != failed["artifact"]


@pytest.mark.parametrize("mode", ["ir", "ast"])
def test_whole_program_requires_usable_replay_receipt_and_retries(tmp_path, mode):
    staged = sc.stage(tmp_path)
    first, _ = _run(staged, DamagedExecutor(staged, mode, "receipt"), mode, seeded_settings=None)
    failed = first["projects"][sc.CASE]
    assert failed["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("receipt" in gap for gap in failed["gaps"])
    assert not failed.get("checkpointable")
    assert {status for _, status, _ in _coverage(staged, first)} == {"unavailable"}
    executor = sc.FixtureExecutor(staged.run_root)
    repaired, _ = _run(staged, executor, mode, seeded_settings=None)
    assert executor.calls and not repaired["projects"][sc.CASE].get("checkpoint_reused")
    assert repaired["projects"][sc.CASE]["entity_count"] > 0


def test_whole_program_ir_publishes_flow_source_cfg_and_debug_location(tmp_path):
    staged = sc.stage(tmp_path)
    output, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir", seeded_settings=None)
    with _indexed(staged, output) as db:
        rows = list(db.execute("select e.name, e.payload_json, l.path, l.start_line from entities e "
                               "left join locations l on e.identity=l.entity_id"))
    copy = next(row for row in rows if row["name"] == "copy_field")
    payload = json.loads(copy["payload_json"])
    assert payload["flow"]["blocks"] and payload["flow"]["dominators"]
    assert payload["source_cfg"]["blocks"]
    assert (copy["path"], copy["start_line"]) == ("proj/src/util.cpp", 11)
    assert any("source_cfg_no_block_lines" in gap for gap in output["gaps"])


@pytest.mark.parametrize("mode", ["ir", "ast"])
def test_whole_program_valid_empty_output_is_not_a_parse_failure(tmp_path, mode):
    class EmptyExecutor(sc.FixtureExecutor):
        def execute(self, request):
            result = super().execute(request)
            kind = request.argv[1]
            suffix, text = {
                "ast": ("json", '{"kind":"TranslationUnitDecl","inner":[]}'),
                "ir": ("ll", '; ModuleID = "empty"\nsource_filename = "empty.cpp"\n'),
                "cfg": ("cfg.txt", ""),
            }[kind]
            for path in (request.scratch_root / "analysis" / kind).glob(f"tu-*.{suffix}"):
                path.write_text(text)
            return result
    staged = sc.stage(tmp_path)
    executor = EmptyExecutor(staged.run_root)
    output, _ = _run(staged, executor, mode, seeded_settings=None)
    result = output["projects"][sc.CASE]
    assert result["entity_count"] == 0 and result["terminal_status"] == "SUCCEEDED"
    assert result["gaps"] == [] and result["checkpointable"]
    calls = len(executor.calls)
    repeated, _ = _run(staged, executor, mode, seeded_settings=None)
    assert repeated["projects"][sc.CASE]["checkpoint_reused"] and len(executor.calls) == calls


def test_same_case_compile_context_change_replays_and_keeps_old_evidence(tmp_path):
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    from appsec_review.storage import canonical_json
    staged = sc.stage(tmp_path)
    first, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ir")
    old = first["projects"][sc.CASE]
    saved = {item["path"]: (staged.run_root / item["path"]).read_bytes()
             for item in [old["artifact"], old["ledger"], *old["evidence"]]}
    for row in staged.rows:
        row["directory"] = "/scratch/source/src"
        row["command_sha256"] = hashlib.sha256(canonical_json({
            "arguments": row["arguments"], "directory": row["directory"]})).hexdigest()
        row["compile_unit_id"] = job._tu_identity(staged.mapping, row)
    database = staged.case_root / "normalized-compile-commands.json"
    database.write_text(json.dumps(staged.rows))
    staged.cataloged["compile_database"] = job._artifact(staged.run_root, database)
    executor = sc.FixtureExecutor(staged.run_root)
    second, _ = _run(staged, executor, "ir")
    assert executor.calls and not second["projects"][sc.CASE].get("checkpoint_reused")
    assert old["artifact"] != second["projects"][sc.CASE]["artifact"]
    assert all((staged.run_root / path).read_bytes() == data for path, data in saved.items())


def test_ast_node_bound_names_the_lost_detail(tmp_path, monkeypatch):
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    staged = sc.stage(tmp_path)
    monkeypatch.setattr(job, "AST_NODE_LIMIT", 3)
    output, _ = _run(staged, sc.FixtureExecutor(staged.run_root), "ast", seeded_settings=None)
    assert output["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("ast_truncated" in gap and "3" in gap for gap in output["gaps"])


def test_whole_ast_source_admission_precedes_the_detail_limit(tmp_path, monkeypatch):
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    staged = sc.stage(tmp_path)
    monkeypatch.setattr(job, "AST_NODE_LIMIT", 2)
    nodes = [{"kind": "FunctionDecl", "name": f"foreign{i}", "id": f"foreign{i}",
              "loc": {"file": "/foreign/include/util.h", "line": 1, "col": 1}} for i in range(4)]
    nodes += [{"kind": "FunctionDecl", "name": f"accepted{i}", "id": f"accepted{i}",
               "loc": {"file": "/scratch/source/include/util.h", "line": 3, "col": 1}} for i in range(3)]
    output, _ = _run(staged, DamagedExecutor(staged, "ast", json.dumps({
        "kind": "TranslationUnitDecl", "inner": nodes})), "ast", seeded_settings=None)
    with _indexed(staged, output) as db:
        assert {row[0] for row in db.execute("select distinct name from entities")} == {"accepted0", "accepted1"}
    assert any("ast_source_filtered" in gap for gap in output["gaps"])
    assert any("ast_truncated" in gap for gap in output["gaps"])


class _Clang18LocationFixture:
    """Schema-derived fixtures, NOT compiler recordings.

    llvmorg-18.1.3 clang/lib/AST/JSONNodeDumper.cpp writes bare locations with shared
    filename/line elision, spelling then expansion, and loc then range begin/end.
    """

    def __init__(self, sources, foreign, included_from):
        self.sources, self.foreign, self.included_from = sources, foreign, included_from
        self.file = self.line = None

    def point(self, path, offset, length):
        data = self.sources[path]
        line = data.count(b"\n", 0, offset) + 1
        point = {"offset": offset}
        if path != self.file:
            point.update(file=path, line=line)
        elif line != self.line:
            point["line"] = line
        point.update(col=offset - data.rfind(b"\n", 0, offset), tokLen=length)
        self.file, self.line = path, line
        if path == self.foreign:
            point["includedFrom"] = {"file": self.included_from}
        return point

    def macro(self, spelling, expansion, *, begin=False, declaration=True):
        token = b"int" if begin and declaration else b"macro_generated"
        return {
            "spellingLoc": self.point(spelling, self.sources[spelling].index(token), len(token)),
            "expansionLoc": self.point(expansion, self.sources[expansion].rindex(b"DECL"), 4),
        }

    def declaration(self, path, name):
        offset = self.sources[path].index(name.encode())
        return {
            "id": "0x-" + name, "kind": "VarDecl", "name": name, "type": {"qualType": "int"},
            "loc": self.point(path, offset, len(name)),
            "range": {
                "begin": self.point(path, self.sources[path].rfind(b"int ", 0, offset), 3),
                "end": self.point(path, offset, len(name)),
            },
        }


@pytest.mark.parametrize("transition,form,limit,relative,integrity", [
    ("foreign", "loc", 2, False, "intact"),
    ("foreign", "range", 2, True, "intact"),
    ("accepted", "loc", 2, False, "intact"),
    ("same-file", "loc", 2, False, "intact"),
    ("foreign", "loc", 1, False, "intact"),
    ("accepted", "range", 1, True, "intact"),
    ("accepted", "range", 2, True, "intact"),
    ("same-file", "loc", 2, False, "changed-bytes"),
    ("same-file", "loc", 2, False, "symlink"),
], ids=["foreign-loc", "foreign-range-relative", "accepted-loc", "elided-expansion",
        "foreign-budget", "accepted-range-budget", "accepted-range-relative",
        "accepted-hash-mismatch", "accepted-custody"])
def test_macro_emitter_state_filters_elided_foreign_nodes_without_crowding_accepted_source(
        tmp_path, monkeypatch, transition, form, limit, relative, integrity):
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    from appsec_review.storage import canonical_json

    staged = sc.stage(tmp_path)
    accepted = "../include/util.h" if relative else "/scratch/source/include/util.h"
    foreign = "/foreign/vendor.h"
    declaration = form == "loc"
    definition = b"#define DECL " + (b"int " if declaration else b"") + b"macro_generated\n"
    expansion = b"DECL;\n" if declaration else b"int generated = DECL;\n"
    foreign_decls = b"".join(f"int foreign{i};\n".encode() for i in range(4))
    sources = {
        accepted: (definition if transition != "accepted" else b"") +
                  (expansion if transition != "foreign" else b"") + b"int accepted_after;\n",
        foreign: (definition if transition == "accepted" else b"") +
                 (expansion if transition == "foreign" else b"") + foreign_decls,
    }
    for path in (staged.target / "proj/include/util.h", staged.case_root / "source/include/util.h"):
        path.write_bytes(sources[accepted])
    source = next(row for row in staged.mapping["files"] if row["target_path"] == "proj/include/util.h")
    source["sha256"] = hashlib.sha256(sources[accepted]).hexdigest()
    staged.mapping["case_snapshot"] = hashlib.sha256(canonical_json(staged.mapping["files"])).hexdigest()
    command = next(row for row in staged.rows if row["target_path"] == "proj/src/util.cpp")
    if relative:
        command["directory"] = "/scratch/source/src"
    command["compile_unit_id"] = job._tu_identity(staged.mapping, command)
    staged.rows[:] = [command]
    database = staged.case_root / "normalized-compile-commands.json"
    database.write_text(json.dumps(staged.rows))
    staged.cataloged["compile_database"] = job._artifact(staged.run_root, database)

    emitter = _Clang18LocationFixture(sources, foreign, accepted)
    nodes = [emitter.declaration(foreign, "foreign0")]
    spelling = foreign if transition == "accepted" else accepted
    expanded = foreign if transition == "foreign" else accepted
    macro = {"id": "0x-macro", "kind": "VarDecl" if declaration else "DeclRefExpr"}
    if declaration:
        macro.update(name="macro_generated", loc=emitter.macro(spelling, expanded))
    else:
        macro["referencedDecl"] = {"id": "0x-ref", "kind": "VarDecl", "name": "macro_generated"}
    macro["range"] = {
        "begin": emitter.macro(spelling, expanded, begin=True, declaration=declaration),
        "end": emitter.macro(spelling, expanded, declaration=declaration),
    }
    nodes.append(macro)
    if transition == "foreign":
        followers = [emitter.declaration(foreign, f"foreign{i}") for i in range(1, 4)]
        assert all("file" not in node["loc"] for node in followers)
        nodes.extend(followers)
        nodes.append(emitter.declaration(accepted, "accepted_after"))
    else:
        following = emitter.declaration(accepted, "accepted_after")
        assert "file" not in following["loc"]
        if transition == "same-file":
            assert "file" in macro["loc"]["spellingLoc"]
            assert "file" not in macro["loc"]["expansionLoc"]
        nodes.append(following)
        nodes.extend(emitter.declaration(foreign, f"foreign{i}") for i in range(1, 4))
    target_file = staged.target / "proj/include/util.h"
    if integrity == "changed-bytes":
        target_file.write_bytes(sources[accepted] + b"// changed after admission\n")
    elif integrity == "symlink":
        outside = tmp_path / "outside-target.h"
        target_file.rename(outside)
        target_file.symlink_to(outside)
    monkeypatch.setattr(job, "AST_NODE_LIMIT", limit)
    output, _ = _run(staged, DamagedExecutor(staged, "ast", json.dumps({
        "kind": "TranslationUnitDecl", "inner": nodes})), "ast", seeded_settings=None)
    with _indexed(staged, output) as db:
        rows = {row["name"]: row for row in db.execute(
            "select e.name, e.payload_json, l.* from entities e left join locations l on e.identity=l.entity_id")}
    assert set(rows) == ({"macro_generated", "accepted_after"} if limit == 2 else {"macro_generated"})
    macro_row = rows["macro_generated"]
    assert macro_row["path"] is None
    assert "macro spelling/expansion" in json.loads(macro_row["payload_json"])["location_gap"]
    assert json.loads(macro_row["payload_json"])["clang_location"]["range"] == macro["range"]
    if limit == 2:
        location = rows["accepted_after"]
        if integrity == "intact":
            assert location["path"] == "proj/include/util.h"
            assert location["file_sha256"] == hashlib.sha256(sources[accepted]).hexdigest()
            assert sources[accepted][location["start_byte"]:location["end_byte"]] == b"accepted_after"
            assert location["confidence"] == 1.0 and not location["ambiguous"]
        else:
            assert location["path"] is None
            assert "accepted bytes changed" in json.loads(location["payload_json"])["location_gap"]
    assert any("ast_source_filtered" in gap for gap in output["gaps"])
    assert any("ast_truncated" in gap for gap in output["gaps"]) is (limit == 1)


@pytest.mark.parametrize("case", [
    "explicit", "elided", "range", "mixed-spelling", "mixed-expansion", "unknown-initial",
    "missing-expansion", "empty-spelling", "empty-expansion", "invalid-name", "invalid-position",
    "missing-end", "parent",
])
def test_macro_node_is_filtered_only_when_all_emitted_provenance_is_known_foreign(tmp_path, monkeypatch, case):
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    from appsec_review.storage import canonical_json

    staged = sc.stage(tmp_path)
    accepted, spelling, expansion = "/scratch/source/include/util.h", "/foreign/definition.h", "/foreign/use.h"
    definition = b"#define DECL int macro_generated\nDECL;\n"
    sources = {
        accepted: definition + b"int accepted_after;\nint accepted_child;\n",
        spelling: definition + b"int foreign_prime;\n",
        expansion: definition + b"int foreign_after;\n",
    }
    for path in (staged.target / "proj/include/util.h", staged.case_root / "source/include/util.h"):
        path.write_bytes(sources[accepted])
    source = next(row for row in staged.mapping["files"] if row["target_path"] == "proj/include/util.h")
    source["sha256"] = hashlib.sha256(sources[accepted]).hexdigest()
    staged.mapping["case_snapshot"] = hashlib.sha256(canonical_json(staged.mapping["files"])).hexdigest()
    command = next(row for row in staged.rows if row["target_path"] == "proj/src/util.cpp")
    command["compile_unit_id"] = job._tu_identity(staged.mapping, command)
    staged.rows[:] = [command]
    database = staged.case_root / "normalized-compile-commands.json"
    database.write_text(json.dumps(staged.rows))
    staged.cataloged["compile_database"] = job._artifact(staged.run_root, database)

    # These are schema-derived location streams, not newly captured compiler output.
    emitter = _Clang18LocationFixture(sources, spelling, accepted)
    nodes = []
    if case == "elided":
        spelling = expansion
        nodes.append(emitter.declaration(expansion, "foreign_after"))
    macro = {"id": "0x100", "kind": "VarDecl", "name": "macro_generated"}
    if case == "range":
        macro.update(kind="DeclRefExpr", referencedDecl={
            "id": "0x101", "kind": "VarDecl", "name": "macro_generated"})
        macro.pop("name")
    else:
        macro["loc"] = emitter.macro(spelling, expansion)
    macro["range"] = {
        "begin": emitter.macro(spelling, accepted if case == "mixed-expansion" else expansion),
        "end": emitter.macro(accepted if case == "mixed-spelling" else spelling, expansion),
    }
    if case == "elided":
        assert all("file" not in bare for point in [macro["loc"], *macro["range"].values()]
                   for bare in point.values())
    elif case == "unknown-initial":
        del macro["loc"]["spellingLoc"]["file"]
    elif case == "missing-expansion":
        del macro["loc"]["expansionLoc"]
    elif case == "empty-spelling":
        macro["loc"]["spellingLoc"] = {}
    elif case == "empty-expansion":
        macro["loc"]["expansionLoc"] = {}
    elif case == "invalid-name":
        macro["loc"]["spellingLoc"]["file"] = None
    elif case == "invalid-position":
        macro["loc"]["spellingLoc"]["offset"] = -1
    elif case == "missing-end":
        del macro["range"]["end"]
    if case == "parent":
        macro.update(kind="FunctionDecl", mangledName="macro_generated")
        first = emitter.declaration(accepted, "accepted_after")
        second = emitter.declaration(accepted, "accepted_child")
        assert "file" not in second["loc"]
        macro["inner"] = [{"kind": "CompoundStmt", "inner": [first, second]}]
        nodes.extend([macro, emitter.declaration(expansion, "foreign_after")])
    else:
        nodes.extend([macro, emitter.declaration(accepted, "accepted_after")])
    monkeypatch.setattr(job, "AST_NODE_LIMIT", 2 if case == "parent" else 1)
    output, _ = _run(staged, DamagedExecutor(staged, "ast", json.dumps({
        "kind": "TranslationUnitDecl", "inner": nodes})), "ast", seeded_settings=None)
    with _indexed(staged, output) as db:
        rows = {row["name"]: row for row in db.execute(
            "select e.name, e.payload_json, l.* from entities e left join locations l on e.identity=l.entity_id")}
    wholly_foreign = case in {"explicit", "elided", "range", "parent"}
    if wholly_foreign:
        expected = {"accepted_after", "accepted_child"} if case == "parent" else {"accepted_after"}
        assert set(rows) == expected
        for name, location in rows.items():
            assert location["path"] == "proj/include/util.h"
            assert location["file_sha256"] == source["sha256"]
            assert sources[accepted][location["start_byte"]:location["end_byte"]] == name.encode()
        assert any("ast_source_filtered" in gap for gap in output["gaps"])
        assert not any("ast_truncated" in gap for gap in output["gaps"])
    else:
        assert set(rows) == {"macro_generated"}
        assert rows["macro_generated"]["path"] is None
        payload = json.loads(rows["macro_generated"]["payload_json"])
        assert "macro spelling/expansion" in payload["location_gap"]
        assert payload["clang_location"]["loc"] == macro["loc"]
        assert payload["clang_location"]["range"] == macro["range"]
        assert any("ast_truncated" in gap for gap in output["gaps"])


@pytest.mark.parametrize("mode", ["ir", "ast"])
def test_whole_program_missing_or_malformed_payload_cannot_be_cached(tmp_path, mode):
    staged = sc.stage(tmp_path)
    output, _ = _run(staged, DamagedExecutor(staged, mode, "not a compiler document"),
                     mode, seeded_settings=None)
    result = output["projects"][sc.CASE]
    assert result["checkpointable"] is False
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and result["gaps"]
    assert result["entity_count"] == 0
    executor = sc.FixtureExecutor(staged.run_root)
    second, _ = _run(staged, executor, mode, seeded_settings=None)
    assert executor.calls and not second["projects"][sc.CASE].get("checkpoint_reused")


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


@pytest.mark.parametrize("kind,name,body,linkage,return_type,returned", [
    ("CXXConversionDecl", "operator bool", "operator bool() const { return true; }", "_ZNK1XcvbEv", "i1", " true"),
    ("CXXConstructorDecl", "X", "X() {}", "_ZN1XC1Ev", "void", ""),
    ("CXXDestructorDecl", "~X", "~X() {}", "_ZN1XD1Ev", "void", ""),
], ids=["conversion", "constructor", "destructor"])
def test_seeded_cpp_callable_kinds_keep_exact_linkage_and_reuse(
        tmp_path, kind, name, body, linkage, return_type, returned):
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 2)])
    data = f"struct X {{\n  {body}\n}};\n".encode()
    for path in (staged.target / "proj/src/util.cpp", staged.case_root / "source/src/util.cpp"):
        path.write_bytes(data)
    source = next(row for row in staged.mapping["files"] if row["target_path"] == "proj/src/util.cpp")
    source["sha256"] = hashlib.sha256(data).hexdigest()
    command = next(row for row in staged.rows if row["target_path"] == "proj/src/util.cpp")
    command["source_sha256"] = source["sha256"]
    command["compile_unit_id"] = job._tu_identity(staged.mapping, command)
    database = staged.case_root / "normalized-compile-commands.json"
    database.write_text(json.dumps(staged.rows))
    staged.cataloged["compile_database"] = job._artifact(staged.run_root, database)
    ir_text = f"""
define {return_type} @{linkage}(ptr %this) !dbg !1 {{
entry:
  ret {return_type}{returned}, !dbg !2
}}
!1 = distinct !DISubprogram(name: "{name}", scope: !3, file: !4, line: 2)
!2 = !DILocation(line: 2, column: 3, scope: !1)
!3 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "X")
!4 = !DIFile(filename: "src/util.cpp", directory: "/scratch/source")
"""
    ast_text = json.dumps({"id": "0xcallable", "kind": kind, "name": name, "mangledName": linkage,
                           "loc": {"file": "/scratch/source/src/util.cpp", "line": 2, "col": 3},
                           "inner": [{"kind": "CompoundStmt", "inner": []}]})

    class CallableExecutor(CannedExecutor):
        def execute(self, request):
            result = super().execute(request)
            if request.argv[1] == "cfg":
                (request.scratch_root / "analysis/cfg/tu-0000.cfg.txt").write_text(
                    f"X::{name}()\n [B1 (ENTRY)]\n   Succs (1): B0\n [B0 (EXIT)]\n   Preds (1): B1\n")
            return result

    executor = CallableExecutor(staged, ir={"util": ir_text}, ast=ast_text)
    ir, ast = _pair(staged, executor)
    result = ast["projects"][sc.CASE]
    assert result["seeded"]["resolved_seed_count"] == 1
    assert result["checkpointable"]
    with _indexed(staged, ast) as db:
        rows = [json.loads(row[0]) for row in db.execute("select payload_json from entities")]
    assert len(rows) == 1 and rows[0]["kind"] == kind
    assert rows[0]["mangled_name"] == linkage
    assert rows[0]["compile_unit_id"] == command["compile_unit_id"]
    repeated = _pair(staged, executor)
    assert len(executor.calls) == 3
    assert all(output["projects"][sc.CASE]["checkpoint_reused"] for output in repeated)


def test_cpp_constructor_abi_variants_are_not_joined_by_display_name(tmp_path):
    staged = sc.stage(tmp_path, observations=[sc.observation("proj/src/util.cpp", 4)])
    ir_text = _canned_ir([("_ZN1XC2Ev", "X", 3, (), False)])
    ast_text = json.dumps({"kind": "CXXConstructorDecl", "name": "X", "mangledName": "_ZN1XC1Ev",
                           "loc": {"file": "/scratch/source/src/util.cpp", "line": 3, "col": 1}})
    _, ast = _pair(staged, CannedExecutor(staged, ir={"util": ir_text}, ast=ast_text))
    result = ast["projects"][sc.CASE]
    assert result["seeded"]["resolved_seed_count"] == 0
    assert result["entity_count"] == 0 and result["checkpointable"] is False
    assert any("ast_function_unavailable" in gap and "_ZN1XC2Ev" in gap for gap in result["gaps"])


@pytest.mark.parametrize("has_second", [True, False], ids=["bounded-second", "missing-second"])
def test_ast_detail_bound_is_reusable_but_true_callable_absence_is_not(tmp_path, monkeypatch, has_second):
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    staged = sc.stage(tmp_path, observations=[
        sc.observation("proj/src/util.cpp", 4), sc.observation("proj/src/util.cpp", 8)])
    ir_text = _canned_ir([("first", "first", 3, (), False), ("second", "second", 7, (), False)])
    functions = [("first", 3), ("second", 7)] if has_second else [("first", 3)]
    ast_text = "\n".join(json.dumps({
        "id": name, "kind": "FunctionDecl", "name": name, "mangledName": name,
        "loc": {"file": "/scratch/source/src/util.cpp", "line": line, "col": 1},
    }) for name, line in functions)
    ir, _ = _run(staged, CannedExecutor(staged, ir={"util": ir_text}), "ir")
    monkeypatch.setattr(job, "AST_NODE_LIMIT", 1)
    executor = CannedExecutor(staged, ast=ast_text)
    ast, _ = _run(staged, executor, "ast", ir=ir)
    result = ast["projects"][sc.CASE]
    assert result["seeded"]["resolved_seed_count"] == 1
    assert result["seeded"]["neighborhood_function_count"] == 1
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    unresolved = next(row for row in ledger if row["start_line"] == 8)
    assert unresolved["reason"] == ("ast_detail_limit" if has_second else "producer_failed")
    assert result["checkpointable"] is has_second
    assert any("ast_truncated" in gap for gap in result["gaps"]) is has_second
    repeated, _ = _run(staged, executor, "ast", ir=ir)
    assert len(executor.calls) == (1 if has_second else 2)
    assert bool(repeated["projects"][sc.CASE].get("checkpoint_reused")) is has_second
    if has_second:
        monkeypatch.setattr(job, "AST_NODE_LIMIT", 2)
        expanded, _ = _run(staged, executor, "ast", ir=ir)
        assert len(executor.calls) == 2
        assert not expanded["projects"][sc.CASE].get("checkpoint_reused")
        assert expanded["projects"][sc.CASE]["seeded"]["resolved_seed_count"] == 2


@pytest.mark.parametrize("missing_first", [True, False], ids=["missing-first", "bounded-first"])
def test_same_seed_missing_linkage_cannot_be_hidden_by_a_later_bound(tmp_path, monkeypatch, missing_first):
    from appsec_review.jobs.job_cpp_compiled_analysis import job
    from appsec_review.storage import canonical_json

    staged = sc.stage(tmp_path, observations=[sc.observation("proj/include/util.h", 3)])
    data = (b"#pragma once\nint missing_marker, bounded_marker;\n"
            b'extern "C" inline int missing() { return 1; } '
            b'extern "C" inline int bounded() { return 2; }\n// end\n')
    for path in (staged.target / "proj/include/util.h", staged.case_root / "source/include/util.h"):
        path.write_bytes(data)
    source = next(row for row in staged.mapping["files"] if row["target_path"] == "proj/include/util.h")
    source["sha256"] = hashlib.sha256(data).hexdigest()
    ir, _ = _run(staged, CannedExecutor(staged, ir={
        "net": _canned_ir([("missing", "missing", 3, (), False)], "include/util.h"),
        "util": _canned_ir([("bounded", "bounded", 3, (), False)], "include/util.h"),
    }), "ir")
    handoff = ir["projects"][sc.CASE]["handoff"]
    assert len(handoff["seed_functions"]) == 2
    assert {tuple(row[:3]) for row in handoff["seed_functions"]} == {("include/util.h", 3, 3)}
    # Permute the real producer's two function records, without changing either linkage or TU.
    handoff["seed_functions"].sort(key=lambda row: (
        handoff["functions"][row[3]]["name"] != ("missing" if missing_first else "bounded")))
    ir["projects"][sc.CASE]["handoff_sha256"] = hashlib.sha256(canonical_json(handoff)).hexdigest()

    class MixedExecutor(sc.FixtureExecutor):
        def execute(self, request):
            result = super().execute(request)
            rows = json.loads((request.scratch_root / "replay-ast.json").read_text())
            for index, row in enumerate(rows):
                name = "missing" if row["target_path"].endswith("/net.cpp") else "bounded"
                nodes = [{"kind": "VarDecl", "id": name + "-marker", "name": name + "_marker",
                          "loc": {"file": "/scratch/source/include/util.h", "line": 2,
                                  "col": data.splitlines()[1].index((name + "_marker").encode()) + 1}}]
                if name == "bounded":
                    nodes.append({"kind": "FunctionDecl", "id": name, "name": name, "mangledName": name,
                                  "loc": {"file": "/scratch/source/include/util.h", "line": 3,
                                          "col": data.splitlines()[2].index(name.encode()) + 1}})
                (request.scratch_root / "analysis/ast" / f"tu-{index:04d}.json").write_text(json.dumps({
                    "kind": "TranslationUnitDecl", "inner": nodes}))
            return result

    monkeypatch.setattr(job, "AST_NODE_LIMIT", 1)
    executor = MixedExecutor(staged.run_root)
    ast, _ = _run(staged, executor, "ast", ir=ir)
    result = ast["projects"][sc.CASE]
    assert any("ast_function_unavailable" in gap and "missing" in gap for gap in result["gaps"])
    assert any("ast_function_bounded" in gap and "bounded" in gap for gap in result["gaps"])
    assert result["seeded"]["resolved_seed_count"] == 0
    assert result["checkpointable"] is False
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_text())["seeded"]["seeds"]
    assert len(ledger) == 1 and ledger[0]["reason"] == "producer_failed"
    repeated, _ = _run(staged, executor, "ast", ir=ir)
    assert len(executor.calls) == 2
    assert not repeated["projects"][sc.CASE].get("checkpoint_reused")


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
    assert result["checkpointable"] is False
    healthy = sc.FixtureExecutor(staged.run_root)
    repeated, _ = _run(staged, healthy, "ir")
    assert healthy.calls and not repeated["projects"][sc.CASE].get("checkpoint_reused")
    assert repeated["projects"][sc.CASE]["source_cfg_count"] == 5


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


def test_priority_only_change_reruns_ir_and_ast_in_the_same_prepared_case(tmp_path: Path) -> None:
    from appsec_review.retrieval import write_manifest
    from appsec_review.storage import file_sha256

    observations = [sc.observation("proj/src/net.cpp", 6, severity="HIGH"),
                    sc.observation("proj/src/util.cpp", 14, severity="LOW")]
    staged = sc.stage(tmp_path, observations=observations)
    settings = {**sc.SEEDED, "unit_limit": 1}
    executor = sc.FixtureExecutor(staged.run_root)
    unit = staged.unit("ir.projects", seeded=settings)
    original_plan = seeded.plan_for(unit, {sc.CASE: staged.cataloged}, seeded.settings_of(unit))
    original = _pair(staged, executor, seeded_settings=settings)
    unchanged = _pair(staged, executor, seeded_settings=settings)
    assert [mode for mode, _ in executor.calls] == ["ir", "cfg", "ast"]
    assert all(output["projects"][sc.CASE]["checkpoint_reused"] for output in unchanged)
    compile_identity = dict(staged.cataloged["compile_database"])
    source_identity = staged.mapping["case_snapshot"]

    changed_observations = [{**item, "severity": "LOW" if item["severity"] == "HIGH" else "HIGH"}
                            for item in observations]
    changed_shard = sc._observation_shard(staged.run_root, "priority-only", changed_observations)
    staged.manifest_path = staged.manifest_path.with_name("priority-only.json")
    write_manifest(staged.manifest_path, run_id="run", target_snapshot=sc.SNAPSHOT,
                   target_root=staged.target, indexes=[changed_shard])
    staged.manifest_sha = file_sha256(staged.manifest_path)
    unit = staged.unit("ir.projects", seeded=settings)
    changed_plan = seeded.plan_for(unit, {sc.CASE: staged.cataloged}, seeded.settings_of(unit))
    before, after = original_plan.for_scope(sc.CASE), changed_plan.for_scope(sc.CASE)
    assert before.rows == after.rows
    assert [seed.rank for seed in before.seeds] != [seed.rank for seed in after.seeds]
    assert staged.cataloged["compile_database"] == compile_identity
    assert staged.mapping["case_snapshot"] == source_identity

    changed = _pair(staged, executor, seeded_settings=settings)
    assert [mode for mode, _ in executor.calls[3:]] == ["ir", "cfg", "ast"]
    for previous, current in zip(original, changed):
        assert not current["projects"][sc.CASE].get("checkpoint_reused")
        assert current["projects"][sc.CASE]["artifact"] != previous["projects"][sc.CASE]["artifact"]
    repeated = _pair(staged, executor, seeded_settings=settings)
    assert len(executor.calls) == 6
    assert all(output["projects"][sc.CASE]["checkpoint_reused"] for output in repeated)


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
    assert any("no debug subprogram" in g for g in ir_proj["gaps"])
    assert ir_proj["checkpointable"] is False
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
