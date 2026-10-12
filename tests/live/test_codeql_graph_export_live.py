"""Live tier for the C/C++ code-graph export pack (skipped without the pinned CodeQL image).

It builds a real database for tests/fixtures/build_toolchains/native, runs the hash-pinned export
pack through the runner `export` action, and compares the decoded rows with the recording under
tests/fixtures/graph/codeql_export/native/exports. This is how that recording is refreshed: the
test prints the difference and fails until the recording is updated in the same change as the
pack (bqrs_sha256 is a BQRS file identity, not a row contract, and is not compared).
"""
from __future__ import annotations

import difflib
import json
from pathlib import Path
import shutil

from appsec_review.codeql.runtime import CodeQLExecutor, graph_export_arguments, load_graph_exports
from appsec_review.graph import contract
from tests.test_live_codeql_toolchains import LIVE_SCOPES, _write_replay, live_codeql_runtime  # noqa: F401

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "build_toolchains"
RECORDING = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "native" / "exports"
COMPARED = ("columns", "rows", "row_count", "truncated")


def test_live_graph_export_pack_compiles_runs_and_matches_the_native_recording(live_codeql_runtime) -> None:
    settings, run_root, image_for = live_codeql_runtime
    language, profile, mode, source_subroot, commands = next(item for item in LIVE_SCOPES if item[0] == "cpp")
    scratch = run_root / "graph-export-cpp"
    shutil.copytree(FIXTURE, scratch / "workspace")
    codeql_image = image_for(profile)
    _write_replay(scratch / "replay.json", run_root, codeql_image.build_image_id, commands)
    executor = CodeQLExecutor(image=codeql_image, run_root=run_root, settings=settings)
    database = executor.execute("database", (
        "--mode", mode, "--language", language, "--replay", "replay.json", "--workspace", "workspace",
        "--source-subroot", source_subroot, "--database", "database",
        "--threads", str(settings.threads), "--ram", str(settings.ram_mb),
    ), scratch_root=scratch)
    detail = (run_root / database.stderr_path).read_text(encoding="utf-8", errors="replace")
    assert not database.timed_out and database.exit_code == 0, detail[-12000:]

    shutil.copytree(scratch / "database", scratch / "query-database")
    shutil.copytree(ROOT / "rules" / "codeql-graph-export" / "cpp", scratch / "export-pack")
    shutil.copyfile(ROOT / "rules" / "codeql-graph-export" / "columns.json", scratch / "export-columns.json")
    shutil.copyfile(ROOT / "containers" / "tools" / "codeql" / "assets.lock.json", scratch / "assets.lock.json")
    bounds = contract.GraphSettings()
    export = executor.execute("export", graph_export_arguments(
        database="query-database", pack="export-pack", columns="export-columns.json",
        asset_lock="assets.lock.json", language="cpp", output_dir="exports",
        row_limit=bounds.max_facts_per_family_per_scope, max_bytes=bounds.max_export_bytes,
        threads=settings.threads, ram_mb=settings.ram_mb), scratch_root=scratch)
    detail = (run_root / export.stderr_path).read_text(encoding="utf-8", errors="replace")
    assert not export.timed_out and export.exit_code == 0, detail[-12000:]

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
    shutil.rmtree(scratch / "query-database")
