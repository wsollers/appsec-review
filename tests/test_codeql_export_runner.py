"""Offline tests for the C1 code-graph export pack, catalog, runner action and recordings."""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import random
import re
import shutil
from types import SimpleNamespace

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
import pytest

from appsec_review.codeql.runtime import (
    CodeQLExecutor,
    CodeQLImage,
    GraphExportIntegrityError,
    action_timeout,
    graph_compile_arguments,
    graph_export_arguments,
    load_asset_lock,
    load_graph_exports,
)
from appsec_review.graph import contract

ROOT = Path(__file__).parents[1]
PACK_ROOT = ROOT / "rules" / "codeql-graph-export"
FIXTURES = ROOT / "tests" / "fixtures" / "graph" / "codeql_export"
IMAGE = "sha256:" + "1" * 64


def _runner():
    spec = importlib.util.spec_from_file_location(
        "appsec_review_codeql_export_runner", ROOT / "containers" / "tools" / "codeql" / "codeql_runner.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = _runner()
COLUMNS = json.loads((PACK_ROOT / "columns.json").read_text(encoding="utf-8"))
QUERIES = COLUMNS["languages"]["cpp"]["queries"]
QUERY_IDS = [query["query_id"] for query in QUERIES]
SCOPE_REPORT_QUERIES = {"seed_functions", "neighborhood"}  # seeded-mode reports, outside every graph family
CATALOG = json.loads((PACK_ROOT / "catalog.json").read_text(encoding="utf-8"))
LOCK_ENTRY = load_asset_lock(ROOT)["export_query_packs"]["cpp"]


def _fixture_exports(name: str) -> dict[str, dict]:
    return load_graph_exports(FIXTURES / name / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)


# --------------------------------------------------------------------------- runner action


class FakeCodeQL:
    """Stands in for the CodeQL CLI: records argv and serves recorded rows as BQRS results."""

    def __init__(self, rows: dict[str, list[list]], *, drop_result_set: str | None = None) -> None:
        self.rows = rows
        self.calls: list[list[str]] = []
        self.drop_result_set = drop_result_set
        self.bqrs_files: dict[str, str] = {}

    def run(self, argv: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
        self.calls.append(list(argv))
        assert argv[0] == RUNNER.CODEQL and cwd.is_dir() and environment["TZ"] == "UTC"
        if argv[1:3] == ["database", "run-queries"]:
            database = Path(argv[argv.index("--") + 1])
            results = database / "results" / "appsec-review" / "graph-export-cpp"
            results.mkdir(parents=True, exist_ok=True)
            for query in QUERIES:
                path = results / Path(query["query_file"]).with_suffix(".bqrs")
                path.write_bytes(f"bqrs {query['query_file']}".encode())
                for item in QUERIES:
                    if item["query_file"] == query["query_file"]:
                        self.bqrs_files[item["result_set"]] = str(path)
            return
        assert argv[1:4] == ["bqrs", "decode", "--format=json"]
        result_set = argv[argv.index("--result-set") + 1]
        limit = int(argv[argv.index("--rows") + 1])
        rows = list(self.rows[result_set])
        random.Random(result_set).shuffle(rows)
        Path(argv[argv.index("--output") + 1]).write_text(json.dumps(
            {result_set: {"columns": [], "tuples": rows[:limit]}}), encoding="utf-8")

    def compile(self, argv: list[str], *, cwd: Path, environment: dict[str, str]) -> dict[str, float]:
        self.calls.append(list(argv))
        assert argv[1:3] == ["query", "compile"] and cwd.is_dir()
        return {Path(value).name: 1.5 for value in argv[argv.index("--") + 1:]}

    def capture(self, argv: list[str], *, cwd: Path, environment: dict[str, str]) -> bytes:
        self.calls.append(list(argv))
        assert argv[1:4] == ["bqrs", "info", "--format=json"]
        path = argv[argv.index("--") + 1]
        sets = [{"name": item["result_set"], "rows": len(self.rows[item["result_set"]]),
                 "columns": [{"name": column["name"]} for column in item["columns"]]}
                for item in QUERIES if self.bqrs_files.get(item["result_set"]) == path
                and item["result_set"] != self.drop_result_set]
        return json.dumps({"result-sets": sets}).encode()


def _stage(tmp_path: Path) -> Path:
    scratch = tmp_path / "scratch"
    (scratch / "query-database").mkdir(parents=True)
    shutil.copytree(PACK_ROOT / "cpp", scratch / "export-pack")
    shutil.copyfile(PACK_ROOT / "columns.json", scratch / "export-columns.json")
    shutil.copyfile(ROOT / "containers" / "tools" / "codeql" / "assets.lock.json", scratch / "assets.lock.json")
    (scratch / "scope.csv").write_text("whole_program,0\n", encoding="utf-8")
    (scratch / "seeds.csv").write_text("", encoding="utf-8")
    return scratch


def _args(**overrides) -> argparse.Namespace:
    argv = graph_export_arguments(
        database="query-database", pack="export-pack", columns="export-columns.json",
        asset_lock="assets.lock.json", language="cpp", output_dir="exports",
        scope_file=overrides.pop("scope_file", "scope.csv"), seeds_file=overrides.pop("seeds_file", "seeds.csv"),
        row_limit=overrides.pop("row_limit", 1000), max_bytes=overrides.pop("max_bytes", 1 << 24),
        threads=2, ram_mb=2048)
    return RUNNER.parser().parse_args(["export", *argv])


def _fake(monkeypatch: pytest.MonkeyPatch, fake: FakeCodeQL) -> None:
    monkeypatch.setattr(RUNNER, "_run", fake.run)
    monkeypatch.setattr(RUNNER, "_run_compile", fake.compile)
    monkeypatch.setattr(RUNNER, "_capture", fake.capture)
    monkeypatch.setattr(RUNNER, "_environment", lambda: {"TZ": "UTC", "HOME": "/tmp/codeql-home"})


def _synthetic_rows() -> dict[str, list[list]]:
    return {query_id: document["rows"] for query_id, document in _fixture_exports("synthetic").items()}


def test_export_argv_runs_queries_then_bounded_decode_per_result_set(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = _stage(tmp_path)
    fake = FakeCodeQL(_synthetic_rows())
    _fake(monkeypatch, fake)

    RUNNER.export(_args(), scratch=scratch)

    database, pack = str(scratch / "query-database"), str(scratch / "export-pack")
    files = list(dict.fromkeys(query["query_file"] for query in QUERIES))
    assert fake.calls[0] == [RUNNER.CODEQL, "query", "compile", "--threads", "2", "--ram", "2048", "--",
                             *(f"{pack}/{file}" for file in files)]
    assert fake.calls[1:1 + len(files)] == [
        [RUNNER.CODEQL, "database", "run-queries", "--threads", "2", "--ram", "2048",
         f"--external=exportScope={scratch / 'scope.csv'}", f"--external=exportSeed={scratch / 'seeds.csv'}",
         "--", database, f"{pack}/{file}"] for file in files]
    expected = []
    for query in QUERIES:
        bqrs = fake.bqrs_files[query["result_set"]]
        expected.append([RUNNER.CODEQL, "bqrs", "info", "--format=json", "--", bqrs])
        expected.append([RUNNER.CODEQL, "bqrs", "decode", "--format=json", "--result-set", query["result_set"],
                         "--rows", "1000", "--output", str(scratch / "exports" / f".{query['query_id']}.decoded.json"),
                         "--", bqrs])
    assert fake.calls[1 + len(files):] == expected
    # Offline: no CLI call can download packs or reach the network.
    assert not any(re.search(r"download|https?:|registry", value) for call in fake.calls for value in call)
    exports = load_graph_exports(scratch / "exports", bytes_limit=1 << 24)
    recorded = _fixture_exports("synthetic")
    assert list(exports) == sorted(QUERY_IDS)
    for query_id, document in exports.items():
        contract.validate_export(document)
        assert {key: document[key] for key in ("columns", "rows", "row_count", "truncated")} == {
            key: recorded[query_id][key] for key in ("columns", "rows", "row_count", "truncated")}
    manifest = json.loads((scratch / "exports" / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["pack"]["tree_sha256"] == LOCK_ENTRY["tree_sha256"]
    assert manifest["row_limit"] == 1000 and all(not item["truncated"] for item in manifest["exports"])
    assert isinstance(manifest["compile_ms"], int)
    assert manifest["scope"] == {"mode": "whole_program", "depth": 0, "seed_count": 0}
    assert all(item["evaluate_ms"] >= 0 and item["compile_s"] == 1.5 for item in manifest["exports"])


def test_seeded_scope_is_bound_to_every_evaluation_and_recorded_in_the_manifest(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = _stage(tmp_path)
    (scratch / "scope.csv").write_text("seeded,3\n", encoding="utf-8")
    (scratch / "seeds.csv").write_text('src/a.cpp,10,12\nsrc/a.cpp,10,12\n"src/b,c.cpp",5,5\n', encoding="utf-8")
    fake = FakeCodeQL(_synthetic_rows())
    _fake(monkeypatch, fake)

    RUNNER.export(_args(), scratch=scratch)

    evaluations = [call for call in fake.calls if call[1:3] == ["database", "run-queries"]]
    assert len(evaluations) == len({query["query_file"] for query in QUERIES})
    for call in evaluations:
        assert call.count(f"--external=exportScope={scratch / 'scope.csv'}") == 1
        assert call.count(f"--external=exportSeed={scratch / 'seeds.csv'}") == 1
        assert call.index("--") > call.index(f"--external=exportSeed={scratch / 'seeds.csv'}")
    assert not any("--external" in value for call in fake.calls if call[1:3] == ["query", "compile"]
                   for value in call), "the compile step must not depend on the scope"
    manifest = json.loads((scratch / "exports" / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["scope"] == {"mode": "seeded", "depth": 3, "seed_count": 2}
    load_graph_exports(scratch / "exports", bytes_limit=1 << 24)  # extra manifest keys stay tolerated


@pytest.mark.parametrize(("scope", "seeds", "message"), [
    ("seeded\n", "", "<mode>,<depth>"),
    ("seeded,3\nseeded,4\n", "", "<mode>,<depth>"),
    ("whole,0\n", "", "unsupported mode"),
    ("seeded,-1\n", "", "unsupported mode or depth"),
    ("seeded,2\n", "a.cpp,10\n", "<path>,<start_line>,<end_line>"),
    ("seeded,2\n", "a.cpp,12,10\n", "<path>,<start_line>,<end_line>"),
    ("seeded,2\n", "a.cpp,x,10\n", "<path>,<start_line>,<end_line>"),
    ("whole_program,0\n", "a.cpp,1,2\n", "empty in whole_program"),
])
def test_export_rejects_a_malformed_scope_or_seeds_file_before_running_codeql(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: str, seeds: str, message: str) -> None:
    scratch = _stage(tmp_path)
    (scratch / "scope.csv").write_text(scope, encoding="utf-8")
    (scratch / "seeds.csv").write_text(seeds, encoding="utf-8")
    fake = FakeCodeQL(_synthetic_rows())
    _fake(monkeypatch, fake)
    with pytest.raises(ValueError, match=re.escape(message)):
        RUNNER.export(_args(), scratch=scratch)
    assert fake.calls == []


def test_export_requires_both_scope_arguments_and_scratch_relative_paths() -> None:
    complete = graph_export_arguments(
        database="d", pack="p", columns="c", asset_lock="l", language="cpp", output_dir="o",
        scope_file="export/scope.csv", seeds_file="export/seeds.csv", row_limit=1, max_bytes=1, threads=1, ram_mb=1)
    assert complete[complete.index("--scope-file"):complete.index("--scope-file") + 4] == (
        "--scope-file", "export/scope.csv", "--seeds-file", "export/seeds.csv")
    parsed = RUNNER.parser().parse_args(["export", *complete])
    assert (parsed.scope_file, parsed.seeds_file) == ("export/scope.csv", "export/seeds.csv")
    for option in ("--scope-file", "--seeds-file"):
        trimmed = list(complete)
        at = trimmed.index(option)
        del trimmed[at:at + 2]
        with pytest.raises(SystemExit):
            RUNNER.parser().parse_args(["export", *trimmed])
    for bad in ({"scope_file": "../scope.csv"}, {"seeds_file": "/abs/seeds.csv"}):
        with pytest.raises(ValueError, match="scratch-relative"):
            graph_export_arguments(
                database="d", pack="p", columns="c", asset_lock="l", language="cpp", output_dir="o",
                **{"scope_file": "s", "seeds_file": "e", **bad}, row_limit=1, max_bytes=1, threads=1, ram_mb=1)


def test_row_bound_truncates_and_keeps_the_true_row_count(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = _stage(tmp_path)
    rows = _synthetic_rows()
    _fake(monkeypatch, FakeCodeQL(rows))

    RUNNER.export(_args(row_limit=2), scratch=scratch)

    exports = load_graph_exports(scratch / "exports", bytes_limit=1 << 24)
    call_sites = exports["call_sites"]
    assert call_sites["truncated"] is True and call_sites["row_count"] == len(rows["call_sites"])
    assert len(call_sites["rows"]) == 2
    assert exports["path_sanitizers"]["truncated"] is False and exports["path_sanitizers"]["row_count"] == 0
    for document in exports.values():
        contract.validate_export(document)


def test_export_does_not_fingerprint_supplied_pack(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = _stage(tmp_path)
    fake = FakeCodeQL(_synthetic_rows())
    _fake(monkeypatch, fake)
    guards = scratch / "export-pack" / "Guards.ql"
    guards.write_text(guards.read_text(encoding="utf-8") + "\n// changed\n", encoding="utf-8")

    original = RUNNER._sha256
    def target_evidence_only(path):
        assert scratch / "export-pack" not in path.parents
        return original(path)
    monkeypatch.setattr(RUNNER, "_sha256", target_evidence_only)
    RUNNER.export(_args(), scratch=scratch)
    assert fake.calls


def test_export_byte_bound_and_result_set_contract_fail_the_action(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = _stage(tmp_path)
    _fake(monkeypatch, FakeCodeQL(_synthetic_rows()))
    with pytest.raises(ValueError, match="byte bound"):
        RUNNER.export(_args(max_bytes=4096), scratch=scratch)

    scratch = _stage(tmp_path / "missing")
    _fake(monkeypatch, FakeCodeQL(_synthetic_rows(), drop_result_set="guards"))
    with pytest.raises(ValueError, match="result set guards differs"):
        RUNNER.export(_args(), scratch=scratch)


def test_export_paths_must_stay_in_scratch() -> None:
    with pytest.raises(ValueError, match="scratch-relative"):
        graph_export_arguments(database="../db", pack="p", columns="c", asset_lock="l", language="cpp",
                               output_dir="o", scope_file="s", seeds_file="e", row_limit=1, max_bytes=1,
                               threads=1, ram_mb=1)
    with pytest.raises(ValueError, match="positive"):
        graph_export_arguments(database="db", pack="p", columns="c", asset_lock="l", language="cpp",
                               output_dir="o", scope_file="s", seeds_file="e", row_limit=0, max_bytes=1,
                               threads=1, ram_mb=1)


def test_decode_of_recorded_bqrs_json_yields_the_export_object() -> None:
    raw = FIXTURES / "synthetic" / "bqrs"
    decoded = json.loads((raw / "call_sites.decoded.json").read_text(encoding="utf-8"))
    info = json.loads((raw / "CallSites.info.json").read_text(encoding="utf-8"))
    query = next(item for item in QUERIES if item["query_id"] == "call_sites")
    total = info["result-sets"][0]["rows"]
    tuples = RUNNER.decoded_tuples(decoded, "call_sites")
    assert tuples != sorted(tuples, key=lambda row: tuple(map(str, row))), "recording must be unsorted"

    document = RUNNER.export_document(query, tuples, total_rows=total, row_limit=1000, bqrs_sha256="b" * 64)
    contract.validate_export(document)
    recorded = _fixture_exports("synthetic")["call_sites"]
    assert document == {**recorded, "bqrs_sha256": "b" * 64}

    bounded = RUNNER.export_document(query, tuples[:3], total_rows=total, row_limit=3, bqrs_sha256="b" * 64)
    contract.validate_export(bounded)
    assert bounded["truncated"] is True and bounded["row_count"] == total and len(bounded["rows"]) == 3


@pytest.mark.parametrize("cell", [{"id": 1234, "label": "call to memcpy"}, ["x"], True, 1.5])
def test_export_document_rejects_entity_and_non_primitive_cells(cell) -> None:
    query = next(item for item in QUERIES if item["query_id"] == "call_sites")
    row = list(_fixture_exports("synthetic")["call_sites"]["rows"][0])
    row[0] = cell
    with pytest.raises(ValueError, match="primitive"):
        RUNNER.export_document(query, [row], total_rows=1, row_limit=10, bqrs_sha256="b" * 64)
    with pytest.raises(ValueError, match="columns"):
        RUNNER.export_document(query, [row[:-1]], total_rows=1, row_limit=10, bqrs_sha256="b" * 64)


def test_executor_export_action_runs_without_network_and_with_export_timeout(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[tuple[str, ...], int]] = []

    def runner(argv, timeout):
        calls.append((tuple(argv), timeout))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, (IMAGE + "\n").encode(), b"", False
        return 0, b"ok", b"", False

    image = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, IMAGE, IMAGE, "build:local", IMAGE,
                        "codeql:local", "10001:10001", "b" * 64, "c" * 64, False, "manifest.json")
    settings = SimpleNamespace(inventory_timeout_seconds=30, database_timeout_seconds=30,
                               query_timeout_seconds=30, output_bytes=1024, threads=2, ram_mb=1024)
    scratch = tmp_path / "scratch"
    (scratch / "export").mkdir(parents=True)
    query_sibling = scratch / "queries" / "busy" / "query-database" / "transient"
    query_sibling.mkdir(parents=True)
    original_is_symlink = Path.is_symlink

    def guarded_is_symlink(path: Path) -> bool:
        if query_sibling == path or query_sibling in path.parents:
            raise AssertionError("export must not traverse a concurrent query scratch tree")
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", guarded_is_symlink)
    result = CodeQLExecutor(image=image, run_root=tmp_path, settings=settings, runner=runner).execute(
        "export", ("--language", "cpp"), scratch_root=scratch)
    command, timeout = next(call for call in calls
                            if call[0][:2] == ("docker", "run") and "/opt/appsec/codeql_runner.py" in call[0])
    assert any(value.startswith("type=volume,src=appsec-codeql-compile-") and value.endswith(",dst=/codeql-cache")
               for value in command) and result.limits["compile_cache"] == "persistent-docker-volume"
    assert not any(call[0][:3] == ("docker", "volume", "rm") for call in calls)
    expected_user = (f"{os.geteuid()}:{os.getegid()}" if hasattr(os, "geteuid") and
                     os.geteuid() > 0 and os.getegid() > 0 else image.runtime_user)
    assert command[command.index("--user") + 1] == expected_user
    assert result.limits["user"] == expected_user
    assert command[command.index("--network") + 1] == "none" and result.limits["network"] == "none"
    assert command[-3:] == ("export", "--language", "cpp")
    assert timeout == contract.GraphSettings().export_timeout_seconds
    assert action_timeout(SimpleNamespace(**vars(settings), export_timeout_seconds=7), "export") == 7
    assert action_timeout(settings, "query") == 30
    with pytest.raises(ValueError):
        CodeQLExecutor(image=image, run_root=tmp_path, settings=settings, runner=runner).execute(
            "analyze", (), scratch_root=tmp_path / "scratch")


# --------------------------------------------------------------------------- lock and QL contract


def test_supplied_pack_availability_uses_no_payload_hashes(monkeypatch) -> None:
    def forbidden(path):
        raise AssertionError("supplied pack must not be hashed")
    monkeypatch.setattr(RUNNER, "_sha256", forbidden)
    RUNNER._verify_export_pack(LOCK_ENTRY, PACK_ROOT / "cpp", ROOT / LOCK_ENTRY["columns_path"])
    assert ROOT / LOCK_ENTRY["source_path"] == PACK_ROOT / "cpp"
    qlpack = (PACK_ROOT / "cpp" / "qlpack.yml").read_text(encoding="utf-8")
    assert f"name: {LOCK_ENTRY['query_pack']}\n" in qlpack
    assert f"version: {LOCK_ENTRY['query_pack_version']}\n" in qlpack
    assert COLUMNS["languages"]["cpp"]["query_pack"] == LOCK_ENTRY["query_pack"] == CATALOG["languages"]["cpp"][
        "export_pack"]


def test_supplied_pack_availability_is_location_independent(tmp_path: Path) -> None:
    for root in (tmp_path / "one", tmp_path / "two" / "nested"):
        shutil.copytree(PACK_ROOT / "cpp", root)
        RUNNER._verify_export_pack(LOCK_ENTRY, root, ROOT / LOCK_ENTRY["columns_path"])
    (tmp_path / "one" / "extra.ql").write_text("", encoding="utf-8")
    RUNNER._verify_export_pack(LOCK_ENTRY, tmp_path / "one", ROOT / LOCK_ENTRY["columns_path"])


def _query_predicates() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    found = {}
    for path in sorted((PACK_ROOT / "cpp").glob("*.ql")):
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", path.read_text(encoding="utf-8")):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    return found


def test_columns_contract_is_closed_and_equals_the_ql_query_predicates() -> None:
    assert set(COLUMNS) == {"schema", "export_schema", "languages"} and set(COLUMNS["languages"]) == {"cpp"}
    assert COLUMNS["export_schema"] == contract.EXPORT_SCHEMA
    assert RUNNER.export_queries(COLUMNS, "cpp") == QUERIES
    predicates = _query_predicates()
    assert sorted(predicates) == sorted(QUERY_IDS)
    for query in QUERIES:
        reports = query["query_id"] in SCOPE_REPORT_QUERIES
        assert set(query) == {"query_id", "query_file", "result_set", "description", "columns"} | (
            set() if reports else {"family"})
        assert query["result_set"] == query["query_id"]
        if not reports:
            contract.Family(query["family"])
        assert all(set(column) == {"name", "type", "meaning"} and column["meaning"] for column in query["columns"])
        assert predicates[query["query_id"]] == (
            query["query_file"], [(column["type"], column["name"]) for column in query["columns"]])
    assert {query["family"] for query in QUERIES if "family" in query} == {family.value for family in contract.Family}
    suite = (PACK_ROOT / "cpp" / "graph-export.qls").read_text(encoding="utf-8")
    assert sorted(re.findall(r"- query: (\S+)", suite)) == sorted({query["query_file"] for query in QUERIES})
    for path in (PACK_ROOT / "cpp").glob("*.ql"):
        text = path.read_text(encoding="utf-8")
        assert "LIVE-UNVERIFIED" in text and "@kind table" in text and "select " not in text


def test_seeded_scope_report_queries_are_outside_every_graph_family() -> None:
    from appsec_review.graph.normalize import FAMILY_QUERIES, export_columns

    in_families = {query_id for queries in FAMILY_QUERIES.values() for query_id in queries}
    assert SCOPE_REPORT_QUERIES == {"seed_functions", "neighborhood"} and not SCOPE_REPORT_QUERIES & in_families
    assert in_families | SCOPE_REPORT_QUERIES == set(QUERY_IDS) == set(export_columns("cpp"))
    by_id = {query["query_id"]: query for query in QUERIES}
    assert [column["name"] for column in by_id["seed_functions"]["columns"]] == [
        "seed_path", "seed_start_line", "seed_end_line", "function_name", "function_path",
        "function_start_line", "function_start_column"]
    assert [column["name"] for column in by_id["neighborhood"]["columns"]] == [
        "function_name", "function_path", "function_start_line", "function_start_column", "depth"]
    assert (by_id["seed_functions"]["query_file"], by_id["neighborhood"]["query_file"]) == (
        "Seeds.ql", "Neighborhood.ql")


def test_pack_declares_the_scope_externals_and_restricts_every_query_by_exported() -> None:
    library = (PACK_ROOT / "cpp" / "GraphExport.qll").read_text(encoding="utf-8")
    assert "external predicate exportScope(string mode, int depth);" in library
    assert "external predicate exportSeed(string path, int startLine, int endLine);" in library
    for name in ("seedFunction", "near", "exported", "wholeProgram"):
        assert re.search(rf"\bpredicate {name}\(", library), name
    # sink() and source() carry the scope restriction for SinkSites, Guards, Ranges, Paths and
    # SourceSites; the other queries apply it to their own function.
    assert "exportedExpr(sinkExpr)" in library and "exportedNode(n)" in library
    for name in ("CallSites.ql", "FlowSummaries.ql"):
        assert "GraphExport::exported(" in (PACK_ROOT / "cpp" / name).read_text(encoding="utf-8"), name
    assert "GraphExport::exportedNode(n)" in (PACK_ROOT / "cpp" / "Paths.ql").read_text(encoding="utf-8")
    for name in ("Seeds.ql", "Neighborhood.ql"):
        assert "not GraphExport::wholeProgram()" in (PACK_ROOT / "cpp" / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- catalog


def _ql_pairs(predicate: str) -> set[tuple[str, int]]:
    text = (PACK_ROOT / "cpp" / "GraphExport.qll").read_text(encoding="utf-8")
    body = text.split(f"predicate {predicate}(", 1)[1].split("\n  }\n", 1)[0]
    return {(name, int(index)) for name, index in re.findall(r'name = "(\w+)" and arg = (-?\d+)', body)}


def _rules(kind: str) -> list[dict]:
    return CATALOG["languages"]["cpp"][kind]


def test_catalog_validates_against_its_schema_and_the_closed_vocabularies() -> None:
    schema = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(CATALOG)
    assert CATALOG["schema"] == contract.CATALOG_SCHEMA
    sink_classes = {value.value for value in contract.SinkClass} - {"unclassified"}
    source_classes = {value.value for value in contract.SourceClass} - {"unclassified"}
    assert set(schema["$defs"]["sink_class"]["enum"]) == sink_classes
    assert set(schema["$defs"]["source_class"]["enum"]) == source_classes
    assert {rule["sink_class"] for rule in _rules("sinks")} <= sink_classes
    assert {rule["source_class"] for rule in _rules("sources")} <= source_classes
    assert set(CATALOG["attacker_reachable_sources"]) == {value.value for value in contract.ATTACKER_REACHABLE_SOURCES}
    rule_ids = [rule["rule_id"] for kind in ("sinks", "sources", "sanitizers") for rule in _rules(kind)]
    assert len(rule_ids) == len(set(rule_ids))
    for kind in ("sinks", "sources"):
        for rule in _rules(kind):
            match = rule["match"]
            assert ("model" in match) != ("api" in match)
            assert "model" in match or match["declared_in"]
        matches = [json.dumps(rule["match"], sort_keys=True) for rule in _rules(kind)]
        assert len(matches) == len(set(matches)), f"duplicate {kind} match"
        api_keys = [rule["match"]["api"] for rule in _rules(kind) if "api" in rule["match"]]
        assert len(api_keys) == len(set(api_keys))


@pytest.mark.parametrize("mutate", [
    lambda doc: doc["languages"]["cpp"]["sinks"][0].update(sink_class="unclassified"),
    lambda doc: doc["languages"]["cpp"]["sinks"][0]["match"].pop("declared_in"),
    lambda doc: doc["languages"]["cpp"]["sources"][0].update(source_class="attacker"),
    lambda doc: doc["languages"]["cpp"]["sinks"][-1]["match"].update(model="SomethingElse"),
    lambda doc: doc["languages"]["cpp"]["sinks"][0].update(cwe_family="787"),
    lambda doc: doc.update(extra=True),
])
def test_catalog_schema_rejects_open_vocabulary_or_unfiltered_api_rules(mutate) -> None:
    schema = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
    document = copy.deepcopy(CATALOG)
    mutate(document)
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(document)


def test_catalog_api_and_model_rules_equal_what_the_queries_can_emit() -> None:
    sink_api = {(rule["match"]["api"], rule["match"]["argument_index"]) for rule in _rules("sinks")
                if "api" in rule["match"]}
    source_api = {(rule["match"]["api"], rule["match"]["index"]) for rule in _rules("sources")
                  if "api" in rule["match"]}
    assert sink_api == _ql_pairs("apiSinkArgument")
    assert source_api == _ql_pairs("apiSourceArgument")
    library = (PACK_ROOT / "cpp" / "GraphExport.qll").read_text(encoding="utf-8")
    sanitizers = set(re.findall(r'"(\w+)"', library.split("predicate sanitizerApi(", 1)[1].split("}", 1)[0]))
    assert sanitizers == {rule["api"] for rule in _rules("sanitizers")}
    emitted_sink_models = set(re.findall(r'model = "([\w.]+)"', library)) - {"api"}
    assert {rule["match"]["model"] for rule in _rules("sinks") if "model" in rule["match"]} < emitted_sink_models
    assert "RemoteFlowSinkFunction" in emitted_sink_models - {
        rule["match"]["model"] for rule in _rules("sinks") if "model" in rule["match"]}


def test_guard_columns_are_facts_and_the_destination_apis_are_catalog_memory_writes() -> None:
    guards = next(query for query in QUERIES if query["query_id"] == "guards")
    names = [column["name"] for column in guards["columns"]]
    assert names[18:] == [f"{role}_{part}" for role in ("lhs", "rhs") for part in (
        "path", "start_line", "start_column", "end_line", "end_column", "kind", "value")] + [
        "destination_object_bytes"]
    assert not [name for name in names if "relation" in name or "capacity" in name or "adequa" in name]
    library = (PACK_ROOT / "cpp" / "GraphExport.qll").read_text(encoding="utf-8")
    body = library.split("predicate destinationApi(string name) {", 1)[1].split("}", 1)[0]
    destination_apis = set(re.findall(r'"(\w+)"', body))
    memory_write = {rule["match"]["api"] for rule in _rules("sinks")
                    if "api" in rule["match"] and rule["sink_class"] == "memory_write"}
    assert destination_apis == {"memcpy", "memmove", "memset", "strcpy", "strcat", "strncpy", "strncat"}
    assert destination_apis <= memory_write


def _classify(kind: str, row: dict) -> str:
    """Test-local reading of README tier order (C3 owns the production classifier)."""
    rules = _rules(kind)
    declared = set(filter(None, row.get("declared_in", "").split(",")))
    index_key = "argument_index" if kind == "sinks" else "index"
    class_key = "sink_class" if kind == "sinks" else "source_class"
    tiers = [
        [rule for rule in rules if rule["match"].get("api") == row["api"] and row["api"]
         and rule["match"][index_key] == row[index_key] and declared & set(rule["match"]["declared_in"])],
        [rule for rule in rules if "source_type" in rule["match"] and rule["match"]["model"] == row["model"]
         and rule["match"]["source_type"] == row.get("source_type")],
        [rule for rule in rules if set(rule["match"]) == {"model"} and rule["match"]["model"] == row["model"]],
    ]
    return next((tier[0][class_key] for tier in tiers if tier), "unclassified")


# --------------------------------------------------------------------------- recordings


@pytest.mark.parametrize("name", ["synthetic", "native"])
def test_recorded_exports_satisfy_the_contract_and_resolve_against_their_sources(name: str) -> None:
    exports = _fixture_exports(name)
    provenance = json.loads((FIXTURES / name / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["recording"] in {"hand-authored", "live"}
    source_root = (FIXTURES / name / provenance["source_root"]).resolve()
    assert sorted(exports) == sorted(QUERY_IDS)
    by_id = {query["query_id"]: query for query in QUERIES}
    for query_id, document in exports.items():
        assert document["columns"] == [column["name"] for column in by_id[query_id]["columns"]]
        names = document["columns"]
        for row in document["rows"]:
            for prefix in {name[:-5] for name in names if name.endswith("_path")}:
                path = row[names.index(f"{prefix}_path")]
                line = row[names.index(f"{prefix}_start_line")]
                if path == "":
                    assert line == 0
                    continue
                lines = (source_root / path).read_text(encoding="utf-8").split("\n")
                column = row[names.index(f"{prefix}_start_column")]
                assert 1 <= line <= len(lines) and 1 <= column <= len(lines[line - 1]), (query_id, prefix, row)
                if f"{prefix}_end_line" in names:
                    end_line, end_column = row[names.index(f"{prefix}_end_line")], row[names.index(f"{prefix}_end_column")]
                    assert (end_line, end_column) >= (line, column) and end_column <= len(lines[end_line - 1])


def _rows(document: dict) -> list[dict]:
    return [dict(zip(document["columns"], row)) for row in document["rows"]]


def test_synthetic_recording_covers_every_c1_case() -> None:
    exports = {query_id: _rows(document) for query_id, document in _fixture_exports("synthetic").items()}
    calls = exports["call_sites"]
    assert any(row["dispatch"] == "unresolved_indirect" and row["candidate_count"] == 0 for row in calls)
    virtual = [row for row in calls if row["dispatch"] == "virtual_resolved"]
    assert len(virtual) == 2 and {row["candidate_count"] for row in virtual} == {2}
    assert len({(row["call_start_line"], row["call_start_column"]) for row in virtual}) == 1

    sink_key = ("sink_path", "sink_start_line", "sink_start_column", "sink_end_line", "sink_end_column",
                "argument_index")
    source_key = ("source_path", "source_start_line", "source_start_column", "source_end_line", "source_end_column")
    flows: dict[tuple, set] = {}
    for row in exports["path_flows"]:
        flows.setdefault(tuple(row[key] for key in sink_key), set()).add(tuple(row[key] for key in source_key))
    assert any(len(sources) == 2 for sources in flows.values()), "two paths to one sink"
    for row in exports["path_edges"]:
        assert tuple(row[key] for key in sink_key) in flows

    guards = exports["guards"]
    states = {row["guard_state"] for row in guards}
    assert {"dominating", "non_dominating", "none"} <= states
    assert any(row["guard_state"] == "dominating" and row["polarity"] == "true_branch"
               and row["constrains_sink_operand"] == "true" for row in guards)
    assert any(row["in_macro"] == "true" and row["guard_state"] == "dominating" for row in guards)
    assert all(row["condition_path"] == "" for row in guards if row["guard_state"] == "none")

    assert any(row["lower"] == "unknown" and row["upper"] == "unknown" for row in exports["ranges"])
    assert any(row["kind"] == "sign_change" for row in exports["range_conversions"])

    sinks = exports["sink_sites"]
    classes = {row["api"] or row["model"]: _classify("sinks", row) for row in sinks}
    assert classes["send"] == "unclassified" and classes["memcpy"] == "memory_write"
    assert classes["printf"] == "format_string" and classes["ArrayExprWrite"] == "memory_write"
    sources = {row["api"] or row["source_type"]: _classify("sources", row) for row in exports["source_sites"]}
    assert sources == {"getenv": "environment", "a command-line argument": "argv"}


def test_one_flipped_byte_in_a_recorded_export_fails_the_manifest_check(tmp_path: Path) -> None:
    exports = tmp_path / "exports"
    shutil.copytree(FIXTURES / "synthetic" / "exports", exports)
    load_graph_exports(exports, bytes_limit=1 << 24)
    target = exports / "guards.json"
    data = bytearray(target.read_bytes())
    index = data.index(b'"dominating"') + 2
    data[index] ^= 0x01
    target.write_bytes(bytes(data))
    with pytest.raises(GraphExportIntegrityError, match="hash differs"):
        load_graph_exports(exports, bytes_limit=1 << 24)


def test_manifest_check_rejects_unlisted_files_bounds_and_rows_that_disagree(tmp_path: Path) -> None:
    exports = tmp_path / "exports"
    shutil.copytree(FIXTURES / "synthetic" / "exports", exports)
    with pytest.raises(GraphExportIntegrityError, match="exceeds its bound"):
        load_graph_exports(exports, bytes_limit=1024)
    (exports / "stray.json").write_text("{}", encoding="utf-8")
    with pytest.raises(GraphExportIntegrityError, match="unlisted"):
        load_graph_exports(exports, bytes_limit=1 << 24)
    (exports / "stray.json").unlink()
    manifest_path = exports / "export-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["exports"][0]["row_count"] += 1
    manifest_path.write_bytes(RUNNER._canonical(manifest))
    with pytest.raises(GraphExportIntegrityError, match="differs from its manifest row"):
        load_graph_exports(exports, bytes_limit=1 << 24)


def test_compile_action_compiles_the_verified_pack_once_without_a_database(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    scratch = _stage(tmp_path)
    shutil.rmtree(scratch / "query-database")
    fake = FakeCodeQL(_synthetic_rows())
    _fake(monkeypatch, fake)
    argv = graph_compile_arguments(pack="export-pack", columns="export-columns.json",
                                   asset_lock="assets.lock.json", language="cpp", threads=8, ram_mb=8192)

    RUNNER.compile_export(RUNNER.parser().parse_args(["compile", *argv]), scratch=scratch)

    files = list(dict.fromkeys(query["query_file"] for query in QUERIES))
    assert fake.calls == [[RUNNER.CODEQL, "query", "compile", "--threads", "8", "--ram", "8192", "--",
                           *(f"{scratch / 'export-pack'}/{file}" for file in files)]]
    report = json.loads(capsys.readouterr().out)
    assert report["schema"] == "appsec-review/codeql-compile/1" and report["query_count"] == len(files)
    assert set(report["compile_s"]) == set(files)


def test_compile_action_does_not_verify_supplied_payload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch = _stage(tmp_path)
    (scratch / "export-pack" / "CallSites.ql").write_text("// tampered\n", encoding="utf-8")
    fake = FakeCodeQL(_synthetic_rows())
    _fake(monkeypatch, fake)
    argv = graph_compile_arguments(pack="export-pack", columns="export-columns.json",
                                   asset_lock="assets.lock.json", language="cpp", threads=2, ram_mb=2048)
    def forbidden(path):
        raise AssertionError("supplied pack must not be hashed")
    monkeypatch.setattr(RUNNER, "_sha256", forbidden)
    RUNNER.compile_export(RUNNER.parser().parse_args(["compile", *argv]), scratch=scratch)
    assert fake.calls


def test_executor_compile_action_has_its_own_timeout_resources_and_a_run_private_declared_cache(
        tmp_path: Path) -> None:
    settings = SimpleNamespace(inventory_timeout_seconds=30, database_timeout_seconds=30,
                               query_timeout_seconds=30, output_bytes=1024, threads=2, ram_mb=1024,
                               export_timeout_seconds=7, compile_timeout_seconds=99, compile_threads=6,
                               compile_ram_mb=5000)
    assert action_timeout(settings, "compile") == 99
    scratch = tmp_path / "scratch"
    (scratch / "export").mkdir(parents=True)
    volumes = set()
    for derived in (IMAGE, "sha256:" + "b" * 64):
        calls: list[tuple[tuple[str, ...], int]] = []

        def runner(argv, timeout, derived=derived, calls=calls):
            calls.append((tuple(argv), timeout))
            if argv[:3] == ("docker", "image", "inspect"):
                return 0, (derived + "\n").encode(), b"", False
            return 0, b"ok", b"", False

        image = CodeQLImage("appsec-review/codeql-derived-image/2", "a" * 64, "sha256:" + "5" * 64, IMAGE,
                            "build:local", derived, "codeql:local", "10001:10001", "b" * 64, "c" * 64,
                            False, "manifest.json")
        CodeQLExecutor(image=image, run_root=tmp_path, settings=settings, runner=runner).execute(
            "compile", ("--language", "cpp"), scratch_root=scratch)
        command, timeout = next(call for call in calls
                                if call[0][:2] == ("docker", "run") and "/opt/appsec/codeql_runner.py" in call[0])
        assert timeout == 99
        assert command[command.index("--cpus") + 1] == "6" and command[command.index("--memory") + 1] == "6024m"
        assert command[command.index("--network") + 1] == "none"
        assert command[-3:] == ("compile", "--language", "cpp")
        volumes.update(value for value in command if value.startswith("type=volume,src=appsec-codeql-compile-"))
    assert len(volumes) == 1, "derived images within one run and declared release share one compile cache"
