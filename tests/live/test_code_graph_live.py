"""Live tier for code-graph acceptance (code-graph-precomputation.md section 10, C9; operator-run).

Skipped without the licensed pinned CodeQL image (``live_codeql_runtime``). With it, for every scope
it can build (the native fixture always; the ``appsec-multi-vuln`` C/C++ workspace when the operator
names it in ``APPSEC_MULTI_VULN_WORKSPACE``), the test:

1. builds a real database and runs the hash-pinned export pack through the runner ``export`` action;
2. compares the native export with its recording (``test_codeql_graph_export_live.py`` owns the diff);
3. normalizes the export with the real ``graph.normalize.normalize_scope`` and publishes one ``graph``
   shard per family with the real ``job_code_graph_index`` publisher into a fresh accepted manifest;
4. answers every ``query_code_graph`` mode over that manifest through ``RetrievalCore``;
5. for the multi-vuln scope, requires at least one ``dataflow_path`` with two or more steps and a
   ``guard_fact``.

Per-scope export and gap counts are written to ``code-graph-acceptance.json`` in the run, and copied
to ``APPSEC_CODE_GRAPH_VERIFICATION`` when the operator sets it (for example
``deploy/dagster/verification/code-graph-acceptance.json``). The offline suite never writes it.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
from typing import Any

from appsec_review.codeql.runtime import CodeQLExecutor, graph_export_arguments, load_graph_exports
from appsec_review.graph import contract
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import EXPORT_UPSTREAM_INDEX, normalize_scope
from appsec_review.jobs.job_code_graph_index import scopes as graph_scopes
from appsec_review.retrieval import IndexIdentity, RetrievalCore, write_manifest
from appsec_review.storage import atomic_json, file_sha256
from tests.test_live_codeql_toolchains import LIVE_SCOPES, _write_replay, live_codeql_runtime  # noqa: F401

ROOT = Path(__file__).parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "build_toolchains"
RECORDING = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "native" / "exports"
RUN_ID = "2026-10-12-0099"
SNAPSHOT = "target-sha256:" + "9" * 64
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def _export(settings, run_root: Path, image, workspace: Path, name: str, commands, subroot: str) -> Path:
    scratch = run_root / f"graph-{name}"
    shutil.copytree(workspace, scratch / "workspace")
    _write_replay(scratch / "replay.json", run_root, image.build_image_id, commands)
    executor = CodeQLExecutor(image=image, run_root=run_root, settings=settings)
    database = executor.execute("database", (
        "--mode", "manual", "--language", "cpp", "--replay", "replay.json", "--workspace", "workspace",
        "--source-subroot", subroot, "--database", "database", "--threads", str(settings.threads),
        "--ram", str(settings.ram_mb)), scratch_root=scratch)
    assert not database.timed_out and database.exit_code == 0, (
        run_root / database.stderr_path).read_text(encoding="utf-8", errors="replace")[-12000:]
    # The executor's export action reads only the staged ``export`` tree, exactly as the job stages it.
    staged = scratch / "export"
    shutil.copytree(scratch / "database", staged / "database")
    shutil.copytree(ROOT / "rules" / "codeql-graph-export" / "cpp", staged / "pack")
    shutil.copyfile(ROOT / "rules" / "codeql-graph-export" / "columns.json", staged / "columns.json")
    shutil.copyfile(ROOT / "containers" / "tools" / "codeql" / "assets.lock.json", staged / "assets.lock.json")
    (staged / "scope.csv").write_text("whole_program,0\n", encoding="utf-8")
    (staged / "seeds.csv").write_text("", encoding="utf-8")
    bounds = contract.GraphSettings()
    export = executor.execute("export", graph_export_arguments(
        database="export/database", pack="export/pack", columns="export/columns.json",
        asset_lock="export/assets.lock.json", language="cpp", output_dir="exports",
        scope_file="export/scope.csv", seeds_file="export/seeds.csv", row_limit=bounds.max_facts_per_family_per_scope,
        max_bytes=bounds.max_export_bytes, threads=settings.threads, ram_mb=settings.ram_mb),
        scratch_root=scratch)
    assert not export.timed_out and export.exit_code == 0, (
        run_root / export.stderr_path).read_text(encoding="utf-8", errors="replace")[-12000:]
    return scratch


def _publish(run_root: Path, target: Path, scopes: list[dict[str, Any]]) -> RetrievalCore:
    catalog = load_catalog()
    indexes = []
    for scope in scopes:
        manifest_path = scope["scratch"] / "exports" / "export-manifest.json"
        exports = load_graph_exports(manifest_path.parent, bytes_limit=contract.GraphSettings().max_export_bytes)
        sources = {item["path"]: SourceFile.from_bytes((target / item["path"]).read_bytes()) for item in scope["files"]}
        block = {"scope_id": scope["scope_id"], "language": "cpp", "build_unit_id": None, "component_id": None}
        result = normalize_scope(
            exports, scope={**block, "root": scope["root"], "files": scope["files"]}, target_snapshot=SNAPSHOT,
            sources=sources, catalog=catalog, tool_version="live",
            export_pack_sha256=json.loads(manifest_path.read_text(encoding="utf-8"))["pack"]["tree_sha256"],
            upstream=[{"index": EXPORT_UPSTREAM_INDEX, "shard_id": f"{scope['scope_id']}:export-manifest",
                       "sha256": file_sha256(manifest_path)}])
        scope["result"] = result
        record = {**block, "root": scope["root"], "export_status": "SUCCEEDED"}
        shards = graph_scopes.publish_scope(
            run_root, scope=record, snapshot=SNAPSHOT, identity=hashlib.sha256(scope["scope_id"].encode()).hexdigest(),
            facts=result.facts, symbols=result.symbols, relations=result.relations, coverage=result.coverage,
            catalog_sha256=catalog.sha256, unit_id="live")
        indexes.extend(IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in shards)
    manifest = run_root / "data" / "indices" / "manifests" / "live-graph.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=indexes)
    artifact = {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest)}
    handoff = run_root / "data" / "jobs" / "live" / "attempts" / "attempt_0001" / "handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "job_id": "live", "status": "ACCEPTED",
                          "artifacts": [artifact], "outputs": {"publish": {"index_manifest": artifact}},
                          "source_fingerprint": SNAPSHOT})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": artifact["path"], "manifest_sha256": artifact["sha256"]})
    return RetrievalCore(run_root.parent, RUN_ID)


def _files(target: Path, root: str) -> list[dict[str, str]]:
    base = target if root == "." else target / root
    return [{"path": path.relative_to(target).as_posix(), "sha256": file_sha256(path)}
            for path in sorted(base.rglob("*")) if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES]


def test_live_code_graph_acceptance(live_codeql_runtime, tmp_path: Path) -> None:
    settings, run_root, image_for = live_codeql_runtime
    _language, profile, _mode, subroot, commands = next(item for item in LIVE_SCOPES if item[0] == "cpp")
    image = image_for(profile)
    graph_run = tmp_path / "runs" / RUN_ID
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    scopes = [{"name": "native", "scope_id": "codeql-unit-live-native", "root": subroot,
               "scratch": _export(settings, run_root, image, FIXTURE, "native", commands, subroot),
               "files": _files(target, subroot)}]
    multi_vuln = os.environ.get("APPSEC_MULTI_VULN_WORKSPACE")
    if multi_vuln:
        workspace = Path(multi_vuln).resolve()
        shutil.copytree(workspace, target / "multi-vuln")
        build = (("multi-vuln", ("cmake", "-S", ".", "-B", "codeql-build"), {}),
                 ("multi-vuln", ("cmake", "--build", "codeql-build"), {}))
        scopes.append({"name": "multi-vuln", "scope_id": "codeql-unit-live-multi-vuln", "root": "multi-vuln",
                       "scratch": _export(settings, run_root, image, target, "multi-vuln", build, "multi-vuln"),
                       "files": _files(target, "multi-vuln")})

    live = load_graph_exports(scopes[0]["scratch"] / "exports", bytes_limit=contract.GraphSettings().max_export_bytes)
    recorded = load_graph_exports(RECORDING, bytes_limit=contract.GraphSettings().max_export_bytes)
    assert sorted(live) == sorted(recorded)

    core = _publish(graph_run, target, scopes)
    report: dict[str, Any] = {"schema": "appsec-review/code-graph-live-acceptance/1", "scopes": []}
    for scope in scopes:
        result = scope["result"]
        by_family = {family.value: [fact for fact in result.facts if fact.family is family]
                     for family in contract.Family}
        symbols = [item.identity.value for item in result.symbols]
        sinks = [fact.identity.value for fact in by_family["sink_site"]]
        subjects = {"callers": symbols[:1], "callees": symbols[:1], "summary": symbols[:1],
                    "sinks": symbols[:1], "entry_points": symbols[:1], "paths": sinks[:1],
                    "guards": sinks[:1], "ranges": sinks[:1]}
        answered = {}
        for mode, values in subjects.items():
            for subject in values:
                response = core.query_code_graph(mode=mode, subject=subject)
                assert response["index_manifest"]["sha256"] == core.manifest_sha256
                answered[mode] = {"rows": len(response["results"]), "gaps": len(response["coverage_gaps"])}
        report["scopes"].append({
            "scope": scope["name"], "facts": {family: len(values) for family, values in by_family.items()},
            "coverage": [row.as_dict() for row in result.coverage], "modes": answered})
        if scope["name"] == "multi-vuln":
            assert any(len(fact.payload["result"]["steps"]) >= 2 for fact in by_family["dataflow_path"])
            assert by_family["guard_fact"]
    destination = graph_run / "code-graph-acceptance.json"
    atomic_json(destination, report)
    if os.environ.get("APPSEC_CODE_GRAPH_VERIFICATION"):
        shutil.copyfile(destination, Path(os.environ["APPSEC_CODE_GRAPH_VERIFICATION"]))
