"""Stage a seeded multi-producer run for ``job_code_graph_index`` over the 12-translation-unit fixture.

The run holds what the producing jobs publish, in the shapes they publish it:

* a seeded ``job_codeql_analysis`` handoff for one scope (root ``proj``): the seed ledger, and an export
  directory whose call graph, sink and seed rows are derived from the project sources, with the manifest
  bound to the handoff;
* the real seeded ``job_cpp_compiled_analysis`` IR and AST branch handlers and the real seeded
  ``job_clang_static_analysis`` scope handler, run on the recorded Clang output through injected executors,
  and published in their own accepted handoffs;
* a clangd shard over the project (production clangd is whole-program), optionally with one edge that
  contradicts CodeQL;
* the evidence observation shard that supplies the two seeds.

Nothing here runs CodeQL, Clang, Joern or a container.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
from typing import Any, Mapping, Sequence

from appsec_review.config import load_config
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.jobs.job_clang_static_analysis import job as static_job
from appsec_review.jobs.job_clang_static_analysis import seeded as static_seeded
from appsec_review.jobs.job_codeql_analysis.job import GRAPH_EXPORTS_SCHEMA
from appsec_review.jobs.job_cpp_compiled_analysis import build_job as build_compiled_job
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256
from tests import seeded_clang_support as sc

ROOT = Path(__file__).resolve().parents[1]
COLUMNS = json.loads((ROOT / "rules" / "codeql-graph-export" / "columns.json").read_text(encoding="utf-8"))
SYNTHETIC_MANIFEST = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "synthetic" / "exports" / "export-manifest.json"
CODEQL = "job_codeql_analysis"
SCOPE = "codeql-unit-" + "e" * 24
SNAPSHOT = sc.SNAPSHOT

# function -> (file, definition line) in the fixture project; the column is the position of the name.
FUNCTIONS = {"copy_field": ("src/util.cpp", 11), "checked_len": ("src/util.cpp", 8), "clamp_len": ("src/util.cpp", 3),
             "handle_packet": ("src/net.cpp", 3), "log_event": ("src/net.cpp", 2), "main": ("src/main.cpp", 3),
             "parse_record": ("src/parse.cpp", 3), "helper_a": ("src/mod_a.cpp", 1)}
# (caller, callee, line in the caller's file) -- every call of the neighborhood in the fixture sources.
CALLS = (("copy_field", "checked_len", 12), ("copy_field", "memcpy", 14), ("checked_len", "clamp_len", 9),
         ("handle_packet", "log_event", 5), ("handle_packet", "copy_field", 6), ("main", "handle_packet", 5),
         ("main", "parse_record", 5), ("parse_record", "copy_field", 5), ("parse_record", "helper_a", 6))
# CodeQL's call-graph neighborhood of the two seeds, both directions, depth 3.
NEIGHBORHOOD = {"copy_field": 0, "handle_packet": 0, "checked_len": 1, "log_event": 1, "main": 1, "parse_record": 1,
                "clamp_len": 2, "helper_a": 2}
SEED_FUNCTIONS = (("src/util.cpp", 14, "copy_field"), ("src/net.cpp", 6, "handle_packet"))


@dataclass
class Pipeline:
    config: Any
    run_id: str
    run_root: Path
    target: Path
    staged: Any
    executors: dict[str, Any]
    clang: dict[str, Any] = field(default_factory=dict)
    ids: dict[str, str] = field(default_factory=dict)

    @property
    def runs(self) -> Path:
        return self.config.runtime.runs_dir


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _source(path: str) -> list[str]:
    return (sc.PROJECT / path).read_text(encoding="utf-8").splitlines()


def definition(name: str) -> tuple[str, int, int]:
    path, line = FUNCTIONS[name]
    return path, line, _source(path)[line - 1].index(name) + 1


def call_span(caller: str, callee: str, line: int) -> tuple[int, int, int]:
    """(line, first column, last column) of ``callee(...)`` on ``line`` of the caller's file; inclusive, 1-based."""
    text = _source(FUNCTIONS[caller][0])[line - 1]
    start = re.search(rf"\b{re.escape(callee)}\(", text).start()
    depth, end = 0, start
    for end in range(start + len(callee), len(text)):
        depth += {"(": 1, ")": -1}.get(text[end], 0)
        if depth == 0:
            break
    return line, start + 1, end + 1


def _rows(query_id: str) -> list[list[Any]]:
    caller_rows = []
    if query_id == "call_sites":
        for caller, callee, line in CALLS:
            path, c_line, c_col = definition(caller)
            span = call_span(caller, callee, line)
            if callee in FUNCTIONS:
                p, l, c = definition(callee)
                resolved = [p, l, c, "direct"]
                declared = {"copy_field": "util.h", "checked_len": "util.h"}.get(callee, Path(p).name)
            else:
                resolved, declared = ["", 0, 0, "external_undefined"], "string.h"
            caller_rows.append([caller, path, c_line, c_col, path, span[0], span[1], span[0], span[2], callee,
                                declared, *resolved, 1, 3 if callee == "memcpy" else 2, "false"])
        return caller_rows
    if query_id == "sink_sites":
        path, c_line, c_col = definition("copy_field")
        line, start, end = call_span("copy_field", "memcpy", 14)
        operand = _source(path)[13].rindex("n") + 1
        return [[path, line, start, line, end, 2, path, line, operand, line, operand, "api", "memcpy", "string.h",
                 "call to memcpy", "copy_field", path, c_line, c_col, 0]]
    if query_id == "seed_functions":
        return [[path, line, line, name, *definition(name)] for path, line, name in SEED_FUNCTIONS]
    if query_id == "neighborhood":
        return [[name, *definition(name), depth] for name, depth in NEIGHBORHOOD.items()]
    return []


def write_codeql_export(exports: Path) -> None:
    template = json.loads(SYNTHETIC_MANIFEST.read_text(encoding="utf-8"))
    entries = []
    for query in COLUMNS["languages"]["cpp"]["queries"]:
        rows = sorted(_rows(query["query_id"]), key=lambda row: tuple(str(value) for value in row))
        document = {"bqrs_sha256": hashlib.sha256(query["query_id"].encode()).hexdigest(),
                    "columns": [column["name"] for column in query["columns"]], "query_id": query["query_id"],
                    "row_count": len(rows), "rows": rows, "schema": "appsec-review/codeql-graph-export/1",
                    "truncated": False}
        path = exports / f"{query['query_id']}.json"
        exports.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        entries.append({"bqrs_sha256": document["bqrs_sha256"], "bytes": path.stat().st_size, "decode_ms": 0,
                        "exported_rows": len(rows), "path": path.name, "query_file": query["query_file"],
                        "query_id": query["query_id"], "row_count": len(rows), "sha256": file_sha256(path),
                        "truncated": False})
    manifest = {**template, "exports": sorted(entries, key=lambda item: item["query_id"]),
                "scope": {"depth": 3, "mode": "seeded", "seed_count": len(SEED_FUNCTIONS)}}
    (exports / "export-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                                                  encoding="utf-8")


def _handoff(run_root: Path, job_id: str, outputs: Mapping[str, Any], artifacts: Sequence[Mapping[str, Any]],
             *, completion: str = "SUCCEEDED") -> dict[str, Any]:
    from tests.handoff_fixture import write_fixture_handoff
    attempt = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001"
    path = attempt / "handoff.json"
    write_fixture_handoff(run_root, path, {"job_id": job_id, "attempt_id": "attempt_0001",
                       "status": "ACCEPTED", "completion_status": completion, "outputs": dict(outputs),
                       "artifacts": list(artifacts), "source_fingerprint": SNAPSHOT,
                       "resolving_paths": {"attempt": attempt.relative_to(run_root).as_posix()}})
    identity = _artifact(run_root, path)
    atomic_json(attempt.parent.parent / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001", "handoff_path": identity["path"],
        "handoff_sha256": identity["sha256"]})
    return identity


def _manifest(run_root: Path, target: Path, run_id: str, name: str, identities: Sequence[IndexIdentity]) -> dict[str, Any]:
    path = run_root / "data" / "indices" / "manifests" / f"{name}.json"
    write_manifest(path, run_id=run_id, target_snapshot=SNAPSHOT, target_root=target, indexes=list(identities))
    return _artifact(run_root, path)


def _identity(value: Mapping[str, Any]) -> IndexIdentity:
    return IndexIdentity(**{**value, "gaps": tuple(value.get("gaps", ()))})


def _location(target: Path, path: str, line: int, column: int, end_line: int, end_column: int) -> SourceLocation:
    data = (target / path).read_bytes()
    source = SourceFile.from_bytes(data)
    return SourceLocation(SNAPSHOT, path, file_sha256(target / path), source.offset(line, column),
                          source.offset(end_line, end_column), line, end_line, column, end_column, {},
                          "clangd-uri-exact-path", 1.0)


def clangd_shard(run_root: Path, target: Path, *, contradict: bool) -> IndexIdentity:
    """Whole-program clangd symbols over the project; ``contradict`` adds one edge that disagrees with CodeQL."""
    ids: dict[str, str] = {}
    entities = []
    for name in FUNCTIONS:
        path, line, column = definition(name)
        ids[name] = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"producer": "clangd", "clangd_id": name}).value
        entities.append(EntityRecord(
            LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"producer": "clangd", "clangd_id": name}),
            f"clangd:{name}", name, f"Function {name}", {
                "producer": "clangd", "kind": "Function",
                "definition": {"path": f"{sc.ROOT}/{path}", "line": line, "column": column, "end_line": line,
                               "end_column": column + len(name)}},
            _location(target, f"{sc.ROOT}/{path}", line, column, line, column + len(name))))
    relations = []
    edges = [(caller, callee, call_span(caller, callee, line)) for caller, callee, line in CALLS if callee in FUNCTIONS]
    if contradict:
        # CodeQL has handle_packet -> copy_field at net.cpp:6; clangd names checked_len at the same reference.
        edges = [edge for edge in edges if edge[:2] != ("handle_packet", "copy_field")]
        edges.append(("handle_packet", "checked_len", call_span("handle_packet", "copy_field", 6)))
    for caller, callee, (line, column, _end) in edges:
        path = f"{sc.ROOT}/{FUNCTIONS[caller][0]}"
        relations.append(RelationRecord(RelationKind.CALLS, ids[caller], ids[callee], True, 1.0, None, {
            "producer": "clangd", "occurrences": 1,
            "locations": [{"path": path, "line": line, "column": column, "ref_kind": 28}]}))
    shard_id = "clangd-cpp-scope-proj"
    producer = {"job": "job_cpp_symbol_index", "unit": "index.scopes", "scope_id": "cpp-scope-proj"}
    fingerprint = index_fingerprint(name="analysis", target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id, "c": contradict}],
                                    tool_identity=producer, parser_identity="e2e/1", normalizer_identity="e2e/1",
                                    mapping_identity="e2e/1")
    path = run_root / "data" / "indices" / "analysis" / shard_id / f"{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
    for entity in entities:
        builder.add_entity(entity)
    for relation in relations:
        builder.add_relation(relation)
    builder.add_coverage(shard_id, "complete")
    return IndexIdentity("analysis", "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                         path.relative_to(run_root).as_posix(), producer, (), shard_id)


def seeded_ledger() -> dict[str, Any]:
    seeds = [{"path": f"src/{Path(path).name}", "start_line": line, "end_line": line, "status": "resolved",
              "functions": [name], "sources": [{"scanner": "cppcheck", "rule": "r1", "severity": "high"}]}
             for path, line, name in SEED_FUNCTIONS]
    return {"mode": "seeded", "depth": 3, "seed_limit": 200, "seed_count": 2, "resolved_seed_count": 2,
            "neighborhood_function_count": len(NEIGHBORHOOD), "depth_histogram": {"0": 2, "1": 4, "2": 2},
            "seeds": seeds, "gaps": []}


def _seeded_cpg(staged: Any, scope: Any) -> dict[str, Any]:
    """The real seeded Joern producer on the recorded c2cpg and joern-export output."""
    from appsec_review.jobs import cpp_seeded
    from appsec_review.jobs.job_cpg_analysis import job as cpg_job
    from appsec_review.jobs.job_cpg_analysis import seeded as cpg_seeded

    unit = staged.unit("generate.scopes", {}, seeded=sc.SEEDED, job_id="job_cpg_analysis")
    unit.job.config.settings.update(sc.CPG_SETTINGS)
    settings = cpp_seeded.settings_of(unit)
    plan = cpp_seeded.plan_for(unit, [scope], settings)
    run = cpg_seeded.Run(settings, plan, plan.for_scope(sc.CASE))
    executor = sc.CpgExecutor(staged.run_root)
    return cpg_job._generate(unit, scope, lambda _u: executor, run)


def stage_pipeline(tmp_path: Path, *, contradict: bool = False, cpg: bool = False) -> Pipeline:
    base = load_config(ROOT / "appsec-review.toml")
    from dataclasses import replace

    runs = tmp_path / "runs"
    config = replace(base, runtime=replace(base.runtime, runs_dir=runs, data_dir=tmp_path / "data",
                                           metadata_dir=runs / "metadata"))
    runner = JobRunner(config)
    run_id, run_root = runner.runs.create(datetime(2026, 10, 12, tzinfo=timezone.utc))
    runner._bind_configuration(run_root)
    target = tmp_path / "target"
    staged = sc.stage(tmp_path, run_root=run_root, target=target)
    pipeline = Pipeline(config, run_id, run_root, target, staged, {})

    # -- the real seeded Clang producers on the recorded output -----------------------------------
    ir_executor, static_executor = sc.FixtureExecutor(run_root), sc.StaticExecutor(run_root)
    handlers = {unit.unit_id: unit for unit in build_compiled_job(executor_factory=lambda _u: ir_executor).units}
    outputs = {"catalog.projects": {"projects": {sc.CASE: staged.cataloged}}}
    ir = handlers["ir.projects"].handler(staged.unit("ir.projects", outputs))
    ast = handlers["ast.projects"].handler(staged.unit("ast.projects", {**outputs, "ir.projects": ir}))
    unit = staged.unit("analyze.scopes", {}, job_id="job_clang_static_analysis")
    unit.job.config.settings.update(sc.STATIC_SETTINGS)
    scope = sc.index_scope(staged)
    settings = static_seeded.settings_of(unit)
    plan = static_seeded.plan_for(unit, [scope], settings)
    run = static_seeded.Run(settings, plan, plan.for_scope(sc.CASE),
                            static_seeded.neighborhood_of({"result": {"outputs": {"ir.projects": ir}}}, sc.CASE))
    static = static_job._analyze_scope(unit, scope, lambda _u: static_executor, run)
    shutil.rmtree(run_root / "data" / "units")   # unit scratch of the handlers run directly; real jobs keep it under attempts/
    pipeline.executors = {"ir": ir_executor, "static": static_executor}
    pipeline.clang = {"ir": ir["projects"][sc.CASE], "ast": ast["projects"][sc.CASE], "static": static}

    compiled = _manifest(run_root, target, run_id, "cpp-compiled-attempt_0001",
                         [_identity(pipeline.clang["ir"]["index_identity"]), _identity(pipeline.clang["ast"]["index_identity"])])
    _handoff(run_root, "job_cpp_compiled_analysis", {"acceptance.publish_handoff": {"index_manifest": compiled}},
             [compiled], completion="COMPLETED_WITH_GAPS")
    analyzers = _manifest(run_root, target, run_id, "clang-static-attempt_0001", [_identity(static["index_identity"])])
    _handoff(run_root, "job_clang_static_analysis", {"acceptance.publish_handoff": {"index_manifest": analyzers}},
             [analyzers], completion="COMPLETED_WITH_GAPS")
    if cpg:
        cpg_result = _seeded_cpg(staged, scope)
        pipeline.clang["cpg"] = cpg_result
        shutil.rmtree(run_root / "data" / "units", ignore_errors=True)
        joern = _manifest(run_root, target, run_id, "joern-attempt_0001", [_identity(cpg_result["index_identity"])])
        _handoff(run_root, "job_cpg_analysis", {"acceptance.publish_handoff": {"index_manifest": joern}},
                 [joern], completion="COMPLETED_WITH_GAPS")
    symbols = _manifest(run_root, target, run_id, "symbols-attempt_0001", [clangd_shard(run_root, target, contradict=contradict)])
    _handoff(run_root, "job_cpp_symbol_index", {"acceptance.publish_handoff": {"index_manifest": symbols}}, [symbols])

    # -- the seeded CodeQL handoff -----------------------------------------------------------------
    files = [{"path": f"{sc.ROOT}/{path.relative_to(sc.PROJECT).as_posix()}",
              "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
             for path in sorted(sc.PROJECT.rglob("*")) if path.is_file()]
    attempt = run_root / "data" / "jobs" / CODEQL / "attempts" / "attempt_0001"
    plan_path = attempt / "artifacts" / "codeql" / "plan.json"
    atomic_json(plan_path, {"schema": "appsec-review/codeql-plan/1", "source_fingerprint": SNAPSHOT, "scopes": [
        {"scope_id": SCOPE, "language": "cpp", "root": sc.ROOT, "build_unit_id": "build-unit-proj", "files": files}]})
    exports = run_root / "data" / "codeql" / "scopes" / SCOPE / "exports"
    write_codeql_export(exports)
    atomic_json(exports.parent / "export-checkpoint.json", {"schema": "appsec-review/codeql-export-checkpoint/1", "identity": "e" * 64})
    manifest = json.loads((exports / "export-manifest.json").read_text(encoding="utf-8"))
    record = {"scope_id": SCOPE, "language": "cpp", "root": sc.ROOT, "build_unit_id": "build-unit-proj",
              "database_identity": hashlib.sha256(SCOPE.encode()).hexdigest(), "export_identity": "f" * 64,
              "export_reused": False, "export_status": "SUCCEEDED", "export_pack": dict(manifest["pack"]),
              "export_manifest": _artifact(run_root, exports / "export-manifest.json"),
              "export_files": [{"query_id": item["query_id"], **_artifact(run_root, exports / item["path"])}
                               for item in manifest["exports"]],
              "export_count": len(manifest["exports"]), "truncated_queries": [], "gaps": [], "seeded": seeded_ledger()}
    index_path = attempt / "artifacts" / "codeql" / "graph-exports.json"
    atomic_json(index_path, {"schema": GRAPH_EXPORTS_SCHEMA, "settings": {}, "exports": [record]})
    evidence = json.loads(staged.manifest_path.read_text(encoding="utf-8"))["indexes"]
    codeql_manifest = _manifest(run_root, target, run_id, "codeql-attempt_0001", [_identity(item) for item in evidence])
    result_path = attempt / "result.json"
    atomic_json(result_path, {"schema": "appsec-review/unit-execution/2", "status": "SUCCEEDED", "outputs": {
        "plan.inventory": {"plan": _artifact(run_root, plan_path)},
        "export.scopes": {"schema": GRAPH_EXPORTS_SCHEMA, "artifact": _artifact(run_root, index_path),
                          "exports": [record], "gaps": []},
        "acceptance.publish_handoff": {"index_manifest": codeql_manifest, "gaps": []}}})
    artifacts = [_artifact(run_root, result_path), _artifact(run_root, plan_path), _artifact(run_root, index_path),
                 codeql_manifest, record["export_manifest"],
                 *({key: value for key, value in item.items() if key != "query_id"} for item in record["export_files"])]
    handoff = _handoff(run_root, CODEQL, {
        "export.scopes": {"schema": GRAPH_EXPORTS_SCHEMA, "artifact": _artifact(run_root, index_path), "gaps": []},
        "acceptance.publish_handoff": {"index_manifest": codeql_manifest, "gaps": []}}, artifacts)
    handoff_path = run_root / handoff["path"]
    document = json.loads(handoff_path.read_text(encoding="utf-8"))
    document["resolving_paths"]["result"] = result_path.relative_to(run_root).as_posix()
    atomic_json(handoff_path, document)
    handoff = _artifact(run_root, handoff_path)
    atomic_json(run_root / "data" / "jobs" / CODEQL / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001", "handoff_path": handoff["path"],
        "handoff_sha256": handoff["sha256"]})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id, "handoff_path": handoff["path"],
        "handoff_sha256": handoff["sha256"], "manifest_path": codeql_manifest["path"],
        "manifest_sha256": codeql_manifest["sha256"]})
    return pipeline
