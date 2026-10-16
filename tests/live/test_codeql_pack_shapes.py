"""Query-pack output shape against a recorded CodeQL database of a multivuln C++ project.

``tests/fixtures/codeql/linux-calibration/database.tar.gz`` is a real CodeQL database built from
``targets/appsec-multi-vuln/projects/native/linux-calibration`` (CMake, C and C++). Building it is
slow, so the tests restore it and run every enabled CodeQL pack against it: the graph-export pack
through the runner ``export`` action, and the default, extended and CERT C++ suites through the
``query`` action. The assertions are about shape, not rule semantics: the export has exactly the
declared tables and columns, and every SARIF result names a rule the run declares and a real source
location. Rule semantics are asserted by the pack's own ``codeql test`` fixtures.

Skipped without the pinned CodeQL image. To rebuild the fixture from the corpus:

    APPSEC_REVIEW_REFRESH_CODEQL_FIXTURE=1 python -m pytest tests/live/test_codeql_pack_shapes.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

import pytest

from appsec_review.codeql.runtime import CodeQLExecutor, graph_export_arguments, load_graph_exports, load_sarif, tree_manifest
from appsec_review.graph import contract
from tests.test_live_codeql_toolchains import _write_replay, live_codeql_runtime  # noqa: F401

ROOT = Path(__file__).parents[2]
PROJECT = ROOT / "targets" / "appsec-multi-vuln" / "projects" / "native" / "linux-calibration"
FIXTURE = ROOT / "tests" / "fixtures" / "codeql" / "linux-calibration"
ARCHIVE, PROVENANCE = FIXTURE / "database.tar.gz", FIXTURE / "provenance.json"
COMMANDS = ((".", ("cmake", "-S", ".", "-B", "codeql-build"), {}), (".", ("cmake", "--build", "codeql-build"), {}))
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}


def _extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter="data")


@pytest.fixture(scope="module")
def database(live_codeql_runtime):  # noqa: F811
    settings, run_root, image_for = live_codeql_runtime
    scratch = run_root / "pack-shapes"
    scratch.mkdir()
    executor = CodeQLExecutor(image=image_for("native"), run_root=run_root, settings=settings)
    if os.environ.get("APPSEC_REVIEW_REFRESH_CODEQL_FIXTURE") or not ARCHIVE.is_file():
        if not PROJECT.is_dir():
            pytest.skip("the appsec-multi-vuln corpus is not checked out and no recorded database exists")
        shutil.copytree(PROJECT, scratch / "workspace")
        _write_replay(scratch / "replay.json", run_root, image_for("native").build_image_id, COMMANDS)
        build = executor.execute("database", (
            "--mode", "manual", "--language", "cpp", "--replay", "replay.json", "--workspace", "workspace",
            "--source-subroot", ".", "--database", "built", "--threads", str(settings.threads),
            "--ram", str(settings.ram_mb)), scratch_root=scratch)
        assert not build.timed_out and build.exit_code == 0, (run_root / build.stderr_path).read_text()[-8000:]
        FIXTURE.mkdir(parents=True, exist_ok=True)
        with tarfile.open(ARCHIVE, "w:gz") as bundle:
            bundle.add(scratch / "built", arcname="database")
        manifest = tree_manifest(scratch / "built", file_limit=settings.database_file_limit,
                                 bytes_limit=settings.database_bytes_limit)
        PROVENANCE.write_text(json.dumps({
            "schema": "appsec-review/codeql-database-fixture/1", "language": "cpp",
            "source": "targets/appsec-multi-vuln/projects/native/linux-calibration",
            "corpus_commit": os.popen(f"git -C {ROOT / 'targets/appsec-multi-vuln'} rev-parse HEAD").read().strip(),
            "build_commands": [list(item[1]) for item in COMMANDS],
            "database_tree_sha256": manifest["tree_sha256"], "database_file_count": manifest["file_count"]},
            indent=2) + "\n", encoding="utf-8")
    _extract(ARCHIVE, scratch)
    return executor, settings, run_root, scratch


def test_recorded_database_matches_its_provenance(database) -> None:
    _, settings, _, scratch = database
    provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    manifest = tree_manifest(scratch / "database", file_limit=settings.database_file_limit,
                             bytes_limit=settings.database_bytes_limit)
    assert manifest["tree_sha256"] == provenance["database_tree_sha256"]
    assert manifest["file_count"] == provenance["database_file_count"] > 0


def _export(database, name: str, *, mode: str, depth: int = 0, seeds: tuple[tuple[str, int, int], ...] = ()):
    """Run the export action on a fresh disposable copy of the database; return (exports, seconds, manifest)."""
    executor, settings, run_root, scratch = database
    root = scratch / f"export-{name}"  # one execution scratch per export; the runner reads ``export/`` in it
    staging = root / "export"  # the layout job_codeql_analysis._stage_export builds
    staging.mkdir(parents=True)
    shutil.copytree(scratch / "database", staging / "database")
    shutil.copytree(ROOT / "rules" / "codeql-graph-export" / "cpp", staging / "pack")
    shutil.copyfile(ROOT / "rules" / "codeql-graph-export" / "columns.json", staging / "columns.json")
    shutil.copyfile(ROOT / "containers" / "tools" / "codeql" / "assets.lock.json", staging / "assets.lock.json")
    (staging / "scope.csv").write_text(f"{mode},{depth}\n", encoding="utf-8")
    (staging / "seeds.csv").write_text("".join(f"{path},{start},{end}\n" for path, start, end in seeds),
                                       encoding="utf-8")
    subprocess.run(["chmod", "-R", "a+rwX", str(staging)], check=True)
    bounds = contract.GraphSettings()
    started = time.monotonic()
    export = executor.execute("export", graph_export_arguments(
        database="export/database", pack="export/pack", columns="export/columns.json",
        asset_lock="export/assets.lock.json", language="cpp", output_dir="exports",
        scope_file="export/scope.csv", seeds_file="export/seeds.csv",
        row_limit=bounds.max_facts_per_family_per_scope, max_bytes=bounds.max_export_bytes,
        threads=settings.threads, ram_mb=settings.ram_mb), scratch_root=root)
    seconds = time.monotonic() - started
    assert not export.timed_out and export.exit_code == 0, (run_root / export.stderr_path).read_text()[-8000:]
    exports = load_graph_exports(root / "exports", bytes_limit=bounds.max_export_bytes)
    manifest = json.loads((root / "exports" / "export-manifest.json").read_text(encoding="utf-8"))
    shutil.rmtree(staging / "database")
    return exports, seconds, manifest


@pytest.fixture(scope="module")
def whole_program(database):
    return _export(database, "whole-program", mode="whole_program")


def test_graph_export_pack_emits_exactly_the_declared_tables_and_columns(database, whole_program) -> None:
    exports, _, manifest = whole_program
    assert manifest["scope"] == {"mode": "whole_program", "depth": 0, "seed_count": 0}
    declared = {item["query_id"]: item for item in
                json.loads((ROOT / "rules/codeql-graph-export/columns.json").read_text())["languages"]["cpp"]["queries"]}
    assert set(exports) == set(declared)
    for query_id, document in exports.items():
        names = [column["name"] for column in declared[query_id]["columns"]]
        assert [column["name"] if isinstance(column, dict) else column for column in document["columns"]] == names
        assert document["row_count"] >= len(document["rows"]) and all(len(row) == len(names) for row in document["rows"])
        assert document["truncated"] == (document["row_count"] > len(document["rows"]))
    assert exports["call_sites"]["rows"], "a C++ project with functions and calls produced no call sites"
    # The seeded-scope reports are empty in whole_program mode.
    assert exports["seed_functions"]["rows"] == [] and exports["neighborhood"]["rows"] == []


def _rows(document) -> list[dict]:
    return [dict(zip(document["columns"], row)) for row in document["rows"]]


def test_seeded_export_is_a_strict_subset_around_the_seed_functions(database, whole_program) -> None:
    whole, whole_seconds, _ = whole_program
    callers = {}
    for row in _rows(whole["call_sites"]):
        if row["call_path"] and row["call_start_line"] > row["caller_start_line"]:
            callers.setdefault((row["caller_path"], row["caller_name"]), row)
    assert len(callers) >= 2, "the calibration database needs at least two functions that make calls"
    # Seed lines taken from real calls inside two different functions (the last call line of each).
    picked = sorted(callers.items())[:2]
    seeds = tuple(sorted({(row["call_path"], row["call_start_line"], row["call_end_line"]) for _, row in picked}))
    exports, seconds, manifest = _export(database, "seeded", mode="seeded", depth=1, seeds=seeds)
    print("whole_program row counts:", {key: value["row_count"] for key, value in sorted(whole.items())})
    print("seeded row counts:", {key: value["row_count"] for key, value in sorted(exports.items())})
    print(f"export wall time: whole_program={whole_seconds:.1f}s seeded(depth=1,seeds={len(seeds)})={seconds:.1f}s")
    assert manifest["scope"] == {"mode": "seeded", "depth": 1, "seed_count": len(seeds)}

    seed_rows = _rows(exports["seed_functions"])
    resolved = {(row["function_path"], row["function_name"], row["function_start_line"]) for row in seed_rows}
    assert {(path, name) for (path, name), _ in picked} <= {(path, name) for path, name, _ in resolved}
    assert {(row["seed_path"], row["seed_start_line"], row["seed_end_line"]) for row in seed_rows} <= set(seeds)
    print("seeds:", seeds, "seed_functions:", sorted(resolved))
    neighborhood = {(row["function_path"], row["function_name"], row["function_start_line"]): row["depth"]
                    for row in _rows(exports["neighborhood"])}
    assert all(neighborhood.get(function) == 0 for function in resolved), "each seed function is at depth 0"
    assert set(neighborhood.values()) <= {0, 1}

    for query_id, document in exports.items():
        if query_id in {"seed_functions", "neighborhood"}:
            continue
        assert {tuple(map(str, row)) for row in document["rows"]} <= {tuple(map(str, row)) for row in whole[query_id]["rows"]}, query_id
    seeded_calls = _rows(exports["call_sites"])
    assert 0 < len(seeded_calls) < len(whole["call_sites"]["rows"])
    exported = {(row["function_path"], row["function_name"], row["function_start_line"]) for row in _rows(exports["neighborhood"])}
    assert {(row["caller_path"], row["caller_name"], row["caller_start_line"]) for row in seeded_calls} <= exported


def _suites(settings):
    configured = settings.languages["cpp"]
    return [("default", ("--pack", configured.query_pack, "--pack-version", configured.query_pack_version,
                         "--suite", configured.query_suite)),
            *((item.query_id, ("--pack", configured.query_pack, "--pack-version", configured.query_pack_version,
                               "--suite", item.query_suite)) for item in configured.additional_queries),
            *((item.query_id, ("--suite-path", f"{item.root}/{item.query_suite}")) for item in configured.custom_queries)]


def test_every_query_suite_emits_well_formed_located_sarif(database) -> None:
    executor, settings, run_root, scratch = database
    sources = {path.relative_to(PROJECT).as_posix() for path in PROJECT.rglob("*") if path.suffix in SOURCE_SUFFIXES} \
        if PROJECT.is_dir() else None
    suites = _suites(settings)
    assert {name for name, _ in suites} >= {"default", "cert-cpp"}
    for name, selection in suites:
        output = f"queries/{name}.sarif"
        query = executor.execute("query", ("--database", "database", "--output", output, *selection,
                                           "--threads", str(settings.threads), "--ram", str(settings.ram_mb),
                                           "--max-paths", str(settings.max_paths)), scratch_root=scratch)
        assert not query.timed_out and query.exit_code == 0, (name, (run_root / query.stderr_path).read_text()[-8000:])
        sarif = load_sarif(scratch / output, bytes_limit=settings.sarif_bytes_limit, result_limit=settings.result_limit)
        assert sarif["version"] == "2.1.0" and len(sarif["runs"]) >= 1
        for run in sarif["runs"]:
            assert run["tool"]["driver"]["name"] == "CodeQL"
            declared = {rule["id"] for rule in run["tool"]["driver"].get("rules", ())}
            for result in run.get("results", ()):
                assert result["ruleId"] in declared and result["message"]["text"], (name, result)
                location = result["locations"][0]["physicalLocation"]
                assert location["region"]["startLine"] >= 1
                if sources is not None:
                    assert location["artifactLocation"]["uri"] in sources, (name, location["artifactLocation"])
