"""Live tier for the C/C++ code-graph export pack (skipped without the pinned CodeQL image).

It builds a real database for tests/fixtures/build_toolchains/native, runs the hash-pinned export
pack through the runner `export` action, and compares the decoded rows with the recording under
tests/fixtures/graph/codeql_export/native/exports. This is how that recording is refreshed: the
test prints the difference and fails until the recording is updated in the same change as the
pack (bqrs_sha256 is a BQRS file identity, not a row contract, and is not compared).

It also compiles tests/fixtures/graph/codeql_export/synthetic/source/synthetic.cpp, whose recording is
hand-authored and not refreshable, and requires the live export to satisfy every semantic expectation
in that fixture's expected-facts.json (paths, guards, ranges, conversions, dispatch). The native
fixture has no sources or sinks, so this is the tier that proves the dataflow families.
"""
from __future__ import annotations

import difflib
import json
from pathlib import Path
import shutil

from appsec_review.codeql.runtime import CodeQLExecutor, graph_export_arguments, load_graph_exports
from appsec_review.graph import contract
from tests.fixtures.graph.expectations import SYNTHETIC, load_expectations, unmet
from tests.test_live_codeql_toolchains import LIVE_SCOPES, _write_replay, live_codeql_runtime  # noqa: F401

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "build_toolchains"
RECORDING = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "native" / "exports"
COMPARED = ("columns", "rows", "row_count", "truncated")


def _export(settings, run_root: Path, image_for, name: str, workspace: Path, profile: str, mode: str,
            source_subroot: str, commands, *, language: str = "cpp") -> Path:
    """Build a ``language`` database for ``workspace`` and run that language's hash-pinned export pack."""
    scratch = run_root / f"graph-export-{name}"
    shutil.copytree(workspace, scratch / "workspace")
    codeql_image = image_for(profile)
    # Like the job, only a manual (build-mode) scope replays accepted build commands.
    replay: tuple[str, ...] = ()
    if commands:
        _write_replay(scratch / "replay.json", run_root, codeql_image.build_image_id, commands)
        replay = ("--replay", "replay.json")
    executor = CodeQLExecutor(image=codeql_image, run_root=run_root, settings=settings)
    database = executor.execute("database", (
        "--mode", mode, "--language", language, *replay, "--workspace", "workspace",
        "--source-subroot", source_subroot, "--database", "database",
        "--threads", str(settings.threads), "--ram", str(settings.ram_mb),
    ), scratch_root=scratch)
    detail = (run_root / database.stderr_path).read_text(encoding="utf-8", errors="replace")
    assert not database.timed_out and database.exit_code == 0, detail[-12000:]

    # The executor's export action reads only the staged ``export`` tree, exactly as the job stages it.
    staged = scratch / "export"
    shutil.copytree(scratch / "database", staged / "database")
    shutil.copytree(ROOT / "rules" / "codeql-graph-export" / language, staged / "pack")
    shutil.copyfile(ROOT / "rules" / "codeql-graph-export" / "columns.json", staged / "columns.json")
    shutil.copyfile(ROOT / "containers" / "tools" / "codeql" / "assets.lock.json", staged / "assets.lock.json")
    (staged / "scope.csv").write_text("whole_program,0\n", encoding="utf-8")
    (staged / "seeds.csv").write_text("", encoding="utf-8")
    bounds = contract.GraphSettings()
    export = executor.execute("export", graph_export_arguments(
        database="export/database", pack="export/pack", columns="export/columns.json",
        asset_lock="export/assets.lock.json", language=language, output_dir="exports",
        scope_file="export/scope.csv", seeds_file="export/seeds.csv",
        row_limit=bounds.max_facts_per_family_per_scope, max_bytes=bounds.max_export_bytes,
        threads=settings.threads, ram_mb=settings.ram_mb), scratch_root=scratch)
    detail = (run_root / export.stderr_path).read_text(encoding="utf-8", errors="replace")
    assert not export.timed_out and export.exit_code == 0, detail[-12000:]
    shutil.rmtree(staged)
    return scratch


def test_live_graph_export_pack_compiles_runs_and_matches_the_native_recording(live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    _language, profile, mode, source_subroot, commands = next(item for item in LIVE_SCOPES if item[0] == "cpp")
    scratch = _export(settings, run_root, image_for, "native", FIXTURE, profile, mode, source_subroot, commands)
    bounds = contract.GraphSettings()
    live = load_graph_exports(scratch / "exports", bytes_limit=bounds.max_export_bytes)
    recorded = load_graph_exports(RECORDING, bytes_limit=bounds.max_export_bytes)
    assert sorted(live) == sorted(recorded)
    differences = []
    for query_id in sorted(live):
        actual = json.dumps({key: live[query_id][key] for key in COMPARED}, indent=1).splitlines()
        expected = json.dumps({key: recorded[query_id][key] for key in COMPARED}, indent=1).splitlines()
        differences.extend(difflib.unified_diff(expected, actual, f"recorded/{query_id}", f"live/{query_id}",
                                                lineterm=""))
    if differences:
        print("\n".join(differences))
    assert not differences, "refresh tests/fixtures/graph/codeql_export/native from this live export"


def test_live_graph_export_pack_meets_the_synthetic_dataflow_expectations(live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    _language, profile, mode, _subroot, _commands = next(item for item in LIVE_SCOPES if item[0] == "cpp")
    commands = (("synthetic", ("c++", "-std=c++17", "-c", "synthetic.cpp", "-o", "synthetic.o"), {}),)
    workspace = run_root / "synthetic-workspace"
    shutil.copytree(SYNTHETIC / "source", workspace / "synthetic")
    scratch = _export(settings, run_root, image_for, "synthetic", workspace, profile, mode, "synthetic", commands)
    live = load_graph_exports(scratch / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)
    assert not [query_id for query_id, document in live.items() if document["truncated"]]
    failures = unmet(live, load_expectations())
    assert not failures, "\n".join(failures)
