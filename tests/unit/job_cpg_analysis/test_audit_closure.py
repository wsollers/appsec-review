"""CPG audit regressions using CSVs and real publication; only the engine is replaced."""
from __future__ import annotations

import csv
from dataclasses import asdict, replace
import json
from pathlib import Path
import re

import pytest

from appsec_review import seeding
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs import cpp_seeded
from appsec_review.jobs.cpp_index_scopes import CheckpointIntegrityError
from appsec_review.jobs.job_code_graph_index import producers
from appsec_review.jobs.job_cpg_analysis import export, job, seeded
from appsec_review.retrieval import EntityKind, IndexBuilder
from appsec_review.storage import atomic_json, file_sha256
from tests import seeded_clang_support as sc
from tests.test_seeded_cpg import _run
from .test_handlers import _fake_execution, _make_scope_and_unit


def table(directory, kind, label, columns, rows):
    directory.mkdir(parents=True, exist_ok=True)
    for suffix, values in (("header", [columns]), ("data", rows)):
        with (directory / f"{kind}_{label}_{suffix}.csv").open("w", newline="") as stream:
            csv.writer(stream).writerows(values)


def methods(directory, rows=None):
    table(directory, "nodes", "METHOD",
          [":ID", "NAME:string", "FULL_NAME:string", "SIGNATURE:string", "FILENAME:string",
           "LINE_NUMBER:int", "IS_EXTERNAL:boolean", "CODE:string"],
          rows or [["m", "f", "f:int()", "int()", "a.cpp", 1, "false", "int f() {}"]])


def _identity_export(directory, variant, offset):
    native = lambda n: str(n + offset)
    specs = [["ns::f", "int(int)", 1], ["ns::f", "int(double)", 1]]
    if variant == "clipped":
        prefix = "ns::f<" + "T" * 220
        specs = [[prefix + "A>", "int()", 1], [prefix + "B>", "int()", 1]]
    elif variant == "location":
        specs = [["ns::f", "int()", 1], ["ns::f", "int()", 2]]
    elif variant == "ambiguous":
        specs = [["ns::f", "int()", 1], ["ns::f", "int()", 1]]
    elif variant == "unknown":
        specs = [["ns::f", "", 1], ["ns::g", "", 1]]
    rows = [[native(i + 1), "f", full, signature, "a.cpp", line, "false", "{}"]
            for i, (full, signature, line) in enumerate(specs)]
    methods(directory, list(reversed(rows)) if offset else rows)
    calls, branches, identifiers, ast, conditions, reaching = [], [], [], [], [], []
    for i in range(2):
        method = native(i + 1)
        call, branch, condition = (native(i * 10 + n) for n in (3, 4, 5))
        calls.append([call, f"callee{i}", "callee()", 1, "callee:void()"])
        branches.append([branch, "IF", "if (ok)", 1])
        identifiers.append([condition, "ok"])
        ast.extend([[method, call], [method, branch], [branch, condition]])
        conditions.append([branch, condition])
        reaching.append([condition, call])
    tables = [
        ("nodes", "CALL", [":ID", "NAME:string", "CODE:string", "LINE_NUMBER:int", "METHOD_FULL_NAME:string"], calls),
        ("nodes", "CONTROL_STRUCTURE", [":ID", "CONTROL_STRUCTURE_TYPE:string", "CODE:string", "LINE_NUMBER:int"], branches),
        ("nodes", "IDENTIFIER", [":ID", "CODE:string"], identifiers),
        ("edges", "AST", [":START_ID", ":END_ID"], ast),
        ("edges", "CONDITION", [":START_ID", ":END_ID"], conditions),
        ("edges", "REACHING_DEF", [":START_ID", ":END_ID"], reaching),
    ]
    for kind, label, columns, values in tables:
        table(directory, kind, label, columns, list(reversed(values)) if offset else values)
    return export.read_export(directory)


def _identity_shard(base, parsed, monkeypatch):
    root, scope, unit = _make_scope_and_unit(base)
    unit.job.repository_root = base / "private-repository"
    unit.job.repository_root.mkdir()
    original = Path.read_bytes

    def no_host_feeds(path):
        assert not path.is_relative_to(Path(__file__).resolve().parents[3] / "data")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", no_host_feeds)
    record = root / "data" / "cpg-export.json"
    atomic_json(record, parsed.as_dict())
    reference = job.artifact(root, record)
    index = job._publish_shard(
        unit, scope, artifacts=[dict(scope.compile_database), reference], tool={"tool": "inert-fixture"},
        gaps=parsed.gaps, cpg=None, cpg_manifest=None, resource_limit=None, compact=None,
        seeded_identity=None, exported={**parsed.as_dict(), "artifact": reference})
    shards = [asdict(index)]
    return list(ShardSet(root, shards).entities(shards, kinds=(EntityKind.AST_NODE.value,)))


@pytest.mark.parametrize("variant", ["overload", "clipped", "location"])
def test_semantic_function_identity_survives_consistent_node_edge_renumbering(tmp_path, monkeypatch, variant):
    first = _identity_export(tmp_path / "first", variant, 0)
    second = _identity_export(tmp_path / "second", variant, 9000)
    assert len(first.functions) == len(second.functions) == 2
    assert {fn.function_id for fn in first.functions} == {fn.function_id for fn in second.functions}
    assert len({fn.function_id for fn in first.functions}) == 2
    for parsed in (first, second):
        assert {fn.identity_status for fn in parsed.functions} == {"semantic"}
        assert sorted(call.name for fn in parsed.functions for call in fn.calls) == ["callee0", "callee1"]
        assert all(len(fn.branches) == 1 and fn.branches[0].condition == "ok"
                   and fn.reaching_def_edges == 1 for fn in parsed.functions)
    assert {fn.export_node_id for fn in first.functions}.isdisjoint(
        fn.export_node_id for fn in second.functions)
    normalize = lambda parsed: {fn.function_id: {k: v for k, v in fn.as_dict().items() if k != "export_node_id"}
                                for fn in parsed.functions}
    assert normalize(first) == normalize(second)
    before = _identity_shard(tmp_path / "run1", first, monkeypatch)
    after = _identity_shard(tmp_path / "run2", second, monkeypatch)
    assert {row["identity"] for row in before} == {row["identity"] for row in after}


@pytest.mark.parametrize("variant", ["ambiguous", "unknown"])
def test_unestablished_method_identities_remain_distinct_export_local_records(tmp_path, monkeypatch, variant):
    identities = []
    for offset in (0, 9000):
        parsed = _identity_export(tmp_path / f"export{offset}", variant, offset)
        assert len(parsed.functions) == 2
        assert all(fn.function_id is None for fn in parsed.functions)
        assert {fn.identity_status for fn in parsed.functions} == {variant}
        assert any(f"cpg_function_identity_{variant}:" in gap for gap in parsed.gaps)
        rows = _identity_shard(tmp_path / f"run{offset}", parsed, monkeypatch)
        assert len(rows) == 2 and len({row["identity"] for row in rows}) == 2
        assert sorted(call["name"] for row in rows for call in row["payload"]["calls"]) == ["callee0", "callee1"]
        assert all(row["payload"]["function_id"] is None
                   and row["payload"]["identity_status"] == variant for row in rows)
        identities.append({row["identity"] for row in rows})
    assert identities[0].isdisjoint(identities[1])


def test_conflicting_native_method_ids_are_not_resolved_by_row_order(tmp_path, monkeypatch):
    records = [["1", "f", "ns::f", "int()", "a.cpp", 1, "false", "{}"],
               ["1", "g", "ns::g", "void()", "a.cpp", 2, "false", "{}"],
               ["2", "valid", "ns::valid", "int()", "a.cpp", 3, "false", "{}"]]
    results = []
    for ordinal, rows in enumerate((records, list(reversed(records)))):
        directory = tmp_path / f"export{ordinal}"
        methods(directory, rows)
        parsed = export.read_export(directory)
        assert [fn.name for fn in parsed.functions] == ["valid"]
        assert any("cpg_export_duplicate_method_id:" in gap for gap in parsed.gaps)
        published = _identity_shard(tmp_path / f"publication{ordinal}", parsed, monkeypatch)
        assert len(published) == 1 and published[0]["name"] == "valid"
        results.append(parsed.as_dict())
    assert results[0] == results[1]


def test_incomplete_method_table_cannot_establish_unique_semantic_identity(tmp_path, monkeypatch):
    methods(tmp_path, [["1", "f", "ns::f", "int()", "a.cpp", 1, "false", "{}"],
                       ["2", "f", "ns::f", "int()", "a.cpp", 1, "false", "{}"]])
    monkeypatch.setattr(export, "MAX_ROWS", 1)
    parsed = export.read_export(tmp_path)
    assert len(parsed.functions) == 1
    assert parsed.functions[0].function_id is None and parsed.functions[0].identity_status == "unknown"
    assert any("was cut at 1 rows" in gap for gap in parsed.gaps)
    rows = _identity_shard(tmp_path / "publication", parsed, monkeypatch)
    assert len(rows) == 1 and rows[0]["payload"]["function_id"] is None


def test_selected_source_predicate_matches_identities_not_suffixes():
    regex = seeded.exclude_regex(["src/a.cpp", "a[1].c"])
    for prefix in ("", "/target/source/", "/scratch/source/"):
        assert not re.fullmatch(regex, prefix + "src/a.cpp")
        assert not re.fullmatch(regex, prefix + "a[1].c")
        for path in ("vendor/src/a.cpp", "not-src/a.cpp", "src/b.cpp", "a1.c", "x.h",
                     "src/a.CPP", "x.mm", "x.ii"):
            assert re.fullmatch(regex, prefix + path)
    assert re.fullmatch(regex, "/foreign/src/a.cpp")
    assert re.fullmatch(seeded.exclude_regex([]), "/target/source/a.cpp")


def test_ast_depth_is_order_independent_and_reports_unresolved_ownership(tmp_path):
    methods(tmp_path)
    table(tmp_path, "edges", "AST", [":START_ID", ":END_ID"],
          [["m" if i == 0 else f"n{i-1}", f"n{i}"] for i in range(export.MAX_AST_DEPTH + 3)]
          + [["cycle1", "cycle2"], ["cycle2", "cycle1"]])
    outputs = []
    for order in ((export.MAX_AST_DEPTH + 2, 20), (20, export.MAX_AST_DEPTH + 2)):
        table(tmp_path, "nodes", "CALL", [":ID", "NAME:string"],
              [[f"n{i}", f"call{i}"] for i in order] + [["orphan", "lost"], ["cycle1", "cyclic"]])
        parsed = export.read_export(tmp_path)
        assert [call.name for call in parsed.functions[0].calls] == ["call20"]
        assert any("cpg_ast_depth_limit" in gap for gap in parsed.gaps)
        assert any("cpg_ast_cycle" in gap for gap in parsed.gaps)
        assert any("cpg_ast_orphan" in gap for gap in parsed.gaps)
        outputs.append(parsed.as_dict())
    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("damage", ["missing_ast", "missing_id", "missing_half", "width", "quoted",
                                    "field_limit", "header_limit", "bad_encoding"])
def test_incomplete_or_malformed_csv_is_a_scoped_gap(tmp_path, monkeypatch, damage):
    methods(tmp_path)
    table(tmp_path, "edges", "AST", [":START_ID", ":END_ID"], [["m", "c"]])
    table(tmp_path, "nodes", "CALL", [":ID", "NAME:string", "CODE:string"], [["c", "g", "g()"]])
    data = tmp_path / "nodes_CALL_data.csv"
    if damage == "missing_ast":
        for path in tmp_path.glob("edges_AST*"):
            path.unlink()
    elif damage == "missing_id":
        (tmp_path / "nodes_METHOD_header.csv").write_text("NAME:string,FILENAME:string\n")
    elif damage == "missing_half":
        data.unlink()
    elif damage == "width":
        data.write_text("c,g,g(),extra\n")
    elif damage == "quoted":
        data.write_text('c,g,"unclosed\n')
    elif damage == "field_limit":
        table(tmp_path, "nodes", "CALL", [":ID", "NAME:string", "CODE:string"],
              [["c", "g", "x" * ((1 << 20) + 1)]])
    elif damage == "header_limit":
        monkeypatch.setattr(export, "MAX_FILE_BYTES", 256)
        (tmp_path / "nodes_CALL_header.csv").write_text("x" * 257)
    else:
        data.write_bytes(b"c,g,\xff\n")
    before = csv.field_size_limit()
    parsed = export.read_export(tmp_path)
    assert csv.field_size_limit() == before
    assert any(gap.startswith(("cpg_export_invalid:", "cpg_export_incomplete:", "cpg_export_limit:"))
               for gap in parsed.gaps)
    assert not parsed.functions or not parsed.functions[0].calls


def test_full_method_identity_survives_normalization_publication_and_consumer(tmp_path, monkeypatch):
    directory = tmp_path / "export"
    prefix = "ns::f<" + "T" * 220
    methods(directory, [["m1", "f", prefix + "A>", "int()", "a.cpp", 1, "false", "{}"],
                        ["m2", "f", prefix + "B>", "void()", "a.cpp", 1, "false", "{}"]])
    parsed = export.read_export(directory)
    root, scope, unit = _make_scope_and_unit(tmp_path / "case")
    unit.job.repository_root = tmp_path / "repository"
    unit.job.repository_root.mkdir()
    original = Path.read_bytes

    def no_host_feeds(path):
        assert not path.is_relative_to(Path(__file__).resolve().parents[3] / "data")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", no_host_feeds)
    identity = job._publish_shard(
        unit, scope, artifacts=[dict(scope.compile_database)], tool={"tool": "fixture"},
        gaps=parsed.gaps, cpg=None, cpg_manifest=None, resource_limit=None,
        compact=None, seeded_identity=None, exported=parsed.as_dict())
    shards = [asdict(identity)]
    source = list(ShardSet(root, shards).entities(shards, kinds=(EntityKind.AST_NODE.value,)))
    assert len(source) == 2 and len({row["identity"] for row in source}) == 2
    out = producers.ProducerRows()
    producers._cpg_rows(ShardSet(root, shards), shards,
                        {"scope_id": "codeql-scope", "language": "cpp", "build_unit_id": "unit"}, sc.SNAPSHOT, out)
    assert len({entity.identity.value for entity in out.entities}) == 2
    assert {entity.payload["source_identity"] for entity in out.entities} == {row["identity"] for row in source}
    builder = IndexBuilder(root / "graph.sqlite", name="graph", fingerprint="c" * 64,
                           target_snapshot=sc.SNAPSHOT, shard_id="fixture")
    for entity in out.entities:
        builder.add_entity(entity)
    assert builder.build()


def test_failed_export_retries_and_preserves_prior_evidence(tmp_path):
    staged = sc.stage(tmp_path)
    engine = sc.CpgExecutor(staged.run_root, export_exit_code=4)
    first, _ = _run(staged, engine)
    retained = {key: (staged.run_root / first[key]["path"]).read_bytes()
                for key in ("cpg", "cpg_manifest", "ledger")}
    engine.export_exit_code = 0
    second, _ = _run(staged, engine)
    assert second["cpg_export"] is not None
    assert len(engine.exports) == 2
    assert first["cpg"]["path"] != second["cpg"]["path"]
    for key, data in retained.items():
        assert (staged.run_root / first[key]["path"]).read_bytes() == data
    third, _ = _run(staged, engine)
    assert third["checkpoint_reused"] and len(engine.exports) == 2


@pytest.mark.parametrize("name", ["execution.json", "compile_commands.json", "raw/stdout.bin", "raw/stderr.bin"])
@pytest.mark.parametrize("mutation", ["remove", "change"])
def test_reuse_verifies_every_export_invocation_artifact(tmp_path, name, mutation):
    staged = sc.stage(tmp_path)
    engine = sc.CpgExecutor(staged.run_root)
    result, _ = _run(staged, engine)
    exports = list((staged.run_root / "data/code-index/joern").rglob("export-run"))
    assert len(exports) == 1
    path = exports[0] / name
    if mutation == "remove":
        path.unlink()
    else:
        path.write_bytes(b"changed")
    with pytest.raises(CheckpointIntegrityError):
        _run(staged, engine)
    assert len(engine.exports) == 1 and result["cpg_export_function_count"] > 0


@pytest.mark.parametrize("change", ["population", "source"])
def test_ledger_population_and_sources_invalidate_reuse(tmp_path, change):
    staged = sc.stage(tmp_path)
    engine = sc.CpgExecutor(staged.run_root)
    unit = staged.unit("generate.scopes", job_id=job.JOB_ID)
    unit.job.config.settings.update(sc.CPG_SETTINGS)
    scope = sc.index_scope(staged)
    settings = cpp_seeded.settings_of(unit)
    plan = cpp_seeded.plan_for(unit, [scope], settings)
    seeds = plan.for_scope(scope.case_id)
    first = job._generate(unit, scope, lambda _u: engine, seeded.Run(settings, plan, seeds))
    if change == "population":
        seeds = replace(seeds, total=12, dropped=10)
        plan = replace(plan, scopes={scope.case_id: seeds}, not_in_database=3, unlocated=2)
    else:
        seeds = replace(seeds, seeds=tuple(replace(seed, sources=(
            seeding.ledger.SeedSource("other-scanner", "other-rule", "HIGH", "other-observation"),))
                                           for seed in seeds.seeds))
        plan = replace(plan, scopes={scope.case_id: seeds})
    result = job._generate(unit, scope, lambda _u: engine, seeded.Run(settings, plan, seeds))
    assert not result.get("checkpoint_reused")
    ledger = json.loads((staged.run_root / result["ledger"]["path"]).read_bytes())["seeded"]
    if change == "population":
        assert ledger["status_counts"]["over_limit"] == 10
        assert any("3 finding locations" in gap for gap in result["gaps"])
        assert any("2 source findings" in gap for gap in result["gaps"])
    else:
        assert ledger["seeds"][0]["sources"][0]["observation_id"] == "other-observation"
    assert (staged.run_root / first["ledger"]["path"]).is_file()
    assert file_sha256(staged.run_root / first["ledger"]["path"]) == first["ledger"]["sha256"]
    reordered = replace(seeds, seeds=tuple(reversed(seeds.seeds)))
    reused = job._generate(unit, scope, lambda _u: engine,
                           seeded.Run(settings, replace(plan, scopes={scope.case_id: reordered}), reordered))
    assert reused["checkpoint_reused"] and len(engine.exports) == 2


def test_directory_shaped_cpg_is_a_gap_without_deleting_target(tmp_path, monkeypatch):
    root, scope, unit = _make_scope_and_unit(tmp_path)
    target_file = unit.job.target_root / "keep"
    target_file.write_bytes(b"target")

    def execute(_u, _s, _t, _argv, scratch, _ef, **kw):
        execution = _fake_execution(root, scratch, cpg_bytes=None)
        (scratch / "cpg.bin").mkdir()
        (scratch / "cpg.bin" / "link").symlink_to(target_file)
        return execution

    monkeypatch.setattr(job, "execute_scope_tool", execute)
    result = job._generate(unit, scope, lambda _: None)
    assert result["cpg"] is None
    assert "Joern c2cpg produced no CPG" in result["gaps"]
    assert target_file.read_bytes() == b"target"
    assert not list((root / "data/code-index/joern").rglob("cpg.bin"))


def test_unsupported_whole_program_scope_does_not_dispatch_and_publishes_applicability(tmp_path):
    staged = sc.stage(tmp_path)
    staged.rows = [{**staged.rows[0], "target_path": "proj/start.S", "file": "/scratch/source/start.S"}]
    engine = sc.CpgExecutor(staged.run_root)
    result, _ = _run(staged, engine, seeded_settings=None)
    assert not engine.calls and not engine.exports
    assert result["terminal_status"] == "NOT_APPLICABLE"
    assert result["not_applicable_inputs"]["count"] == 1
    assert not result["gaps"]
    shards = [result["index_identity"]]
    assert not list(ShardSet(staged.run_root, shards).entities(shards, kinds=(EntityKind.AST_NODE.value,)))


def test_unsupported_scope_survives_generate_and_summary(tmp_path, monkeypatch):
    root, scope, load_unit = _make_scope_and_unit(
        tmp_path, unit_id="load.accepted_cpp", settings_override={"seeded": {"mode": "whole_program"}})
    scope = replace(scope, compile_commands=({"target_path": "native/start.S", "arguments": ["as", "start.S"]},))
    accepted = {"handoff": {"source_fingerprint": load_unit.job.source_fingerprint},
                "handoff_sha256": "a" * 64,
                "manifest": {"path": load_unit.job.input_manifest_path.relative_to(root).as_posix(),
                             "sha256": load_unit.job.input_manifest_sha256}}
    monkeypatch.setattr(job, "accepted_cpp_scopes", lambda _: (accepted, [scope], {}))

    def never(_):
        pytest.fail("unsupported scope dispatched a tool")

    outputs = {}
    for spec in job.build_job(executor_factory=never).units:
        unit = type(load_unit)(**vars(load_unit))
        unit.unit_id = spec.unit_id
        unit.unit_root = load_unit.job.attempt_root / spec.unit_id
        unit.unit_root.mkdir(parents=True, exist_ok=True)
        unit.output = outputs.__getitem__
        outputs[spec.unit_id] = spec.handler(unit)
    result = outputs["acceptance.publish_handoff"]
    assert result["terminal_status"] == "NOT_APPLICABLE"
    summary = json.loads((root / result["artifact"]["path"]).read_bytes())
    assert summary["counts"]["cpgs_generated"] == 0
    assert summary["scopes"][0]["not_applicable_inputs"]["count"] == 1
    assert summary["retirement"]["retired"] is True
    assert not summary["gaps"]


def test_cleanup_refuses_referenced_native_output(tmp_path, monkeypatch):
    root, scope, unit = _make_scope_and_unit(tmp_path)
    evidence = root / "data/code-index/joern" / scope.scope_id
    source = scope.case_root / "cpg.bin"
    source.write_bytes(b"accepted input")

    def execute(_u, _s, _t, _argv, scratch, _ef, **kw):
        execution = _fake_execution(root, scratch, exit_code=9)
        native = scratch / "export" / "native.bin"
        native.parent.mkdir()
        native.write_bytes(b"retained native output")
        execution["stdout_path"] = native.relative_to(root).as_posix()
        return execution

    monkeypatch.setattr(job, "execute_scope_tool", execute)
    with pytest.raises(CheckpointIntegrityError, match="overlaps retained execution evidence"):
        job._export(unit, scope, evidence, source, lambda _: None)
    assert (evidence / "export-run/export/native.bin").read_bytes() == b"retained native output"
    assert source.read_bytes() == b"accepted input"


def test_symlinked_scope_root_cannot_launch_or_clean_foreign_paths(tmp_path, monkeypatch):
    root, scope, unit = _make_scope_and_unit(tmp_path)
    evidence = root / "data/code-index/joern" / scope.scope_id
    evidence.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_bytes(b"prior evidence")
    evidence.symlink_to(outside, target_is_directory=True)

    def never(*args, **kwargs):
        pytest.fail("symlinked evidence root reached execution")

    monkeypatch.setattr(job, "execute_scope_tool", never)
    with pytest.raises(CheckpointIntegrityError, match="not its owned path"):
        job._generate(unit, scope, lambda _: None)
    assert (outside / "keep").read_bytes() == b"prior evidence"


@pytest.mark.parametrize("outcome", ["exit", "limit", "timeout", "oom", "malformed", "symlink", "empty"])
def test_export_cleanup_is_own_disposable_only(tmp_path, monkeypatch, outcome):
    root, scope, unit = _make_scope_and_unit(tmp_path)
    evidence = root / "data/code-index/joern" / scope.scope_id
    protected = root / "data" / "native-evidence"
    protected.mkdir()
    (protected / "keep").write_bytes(b"native")
    source = scope.case_root / "cpg.bin"
    source.write_bytes(b"accepted input")

    def execute(_u, _s, _t, _argv, scratch, _ef, **kw):
        execution = _fake_execution(root, scratch,
                                    exit_code=9 if outcome == "exit" else 0,
                                    limit_reached=outcome == "limit", timed_out=outcome == "timeout",
                                    oom_killed=outcome == "oom")
        directory = scratch / "export"
        if outcome == "symlink":
            directory.symlink_to(protected, target_is_directory=True)
        else:
            directory.mkdir()
            (directory / "native-link").symlink_to(protected, target_is_directory=True)
            if outcome == "malformed":
                table(directory, "nodes", "METHOD", ["NAME:string"], [["f"]])
            else:
                (directory / "partial.csv").write_bytes(b"partial")
        return execution

    monkeypatch.setattr(job, "execute_scope_tool", execute)
    record, artifacts, gaps = job._export(unit, scope, evidence, source, lambda _: None)
    assert record is None and gaps
    assert not (evidence / "export-run/export").exists()
    assert not (evidence / "export-run/export").is_symlink()
    assert not (evidence / "export-run/cpg.bin").exists()
    assert (protected / "keep").read_bytes() == b"native"
    assert source.read_bytes() == b"accepted input"
    for item in artifacts:
        assert file_sha256(root / item["path"]) == item["sha256"]
