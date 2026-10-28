"""Stage a fake accepted run for ``job_code_graph_index`` (code-graph chunk C5).

The run holds, exactly in the shapes the producing jobs publish:

* an accepted ``job_codeql_analysis`` handoff: ``execution.scopes`` graph export artifact
  (``appsec-review/codeql-graph-exports/1``), result, plan and, per succeeded scope, the C1 recorded
  export directory under ``data/codeql/scopes/<scope>/exports`` with its manifest bound to the handoff;
* four CodeQL scopes: the synthetic recording (root ``src``), the native recording (root ``native``),
  a C/C++ scope whose database failed (``SKIPPED``) and a Go scope without an export pack
  (``NOT_APPLICABLE``);
* accepted secondary shards built with the real ``IndexBuilder`` (the
  ``tests/fixtures/graph/secondary/builder.py`` pattern): a clangd shard over the synthetic source
  (one agreeing edge, one contradicting edge, one reference outside every CodeQL call span), CodeQL
  observations with a bridged and a broken path-problem flow, and a prioritization shard whose
  semantic path maps onto the bridged flow;
* an accepted index manifest composing all of them, pointed to by ``data/indices/accepted.json``.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Mapping, Sequence

from appsec_review.config import load_config
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.jobs.job_codeql_analysis.job import GRAPH_EXPORTS_SCHEMA
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256

ROOT = Path(__file__).resolve().parents[4]
EXPORTS = ROOT / "tests" / "fixtures" / "graph" / "codeql_export"
NATIVE_SOURCES = ROOT / "tests" / "fixtures" / "build_toolchains" / "native"
SNAPSHOT = "target-sha256:" + "6" * 64
CODEQL = "job_codeql_analysis"
SYNTHETIC = "codeql-unit-" + "a" * 24
NATIVE = "codeql-unit-" + "b" * 24
FAILED = "codeql-unit-" + "c" * 24
GO = "codeql-unit-" + "d" * 24
SYNTHETIC_PATH = "src/synthetic.cpp"
# clangd symbols over the synthetic source: name -> (line, column) of the defining name.
CLANGD_SYMBOLS = {"main": (52, 5), "copy_checked": (32, 6), "copy_unchecked": (41, 6), "dispatch": (24, 6),
                  "forward": (48, 6)}
# (caller, callee) -> reference point. 56:3 agrees with CodeQL; 60:3 lies in CodeQL's main -> dispatch
# call span but names forward (a contradiction); 53:3 lies in no CodeQL call span (secondary_only).
CLANGD_CALLS = {("main", "copy_checked"): (56, 3), ("main", "forward"): (60, 3),
                ("main", "copy_unchecked"): (53, 3)}


def configured(tmp_path: Path):
    from appsec_review.config.assurance import ComponentReleases
    base = load_config(ROOT / "appsec-review.toml")
    runs = tmp_path / "runs"
    policy = replace(base.review_policy, releases=ComponentReleases({
        key: "fixture-1" for key in ("platform", "validation", "graph_catalog", "graph_columns", "graph_normalizer")}))
    resolved = json.loads(base.resolved_json)
    resolved["review_policy"] = policy.view()
    payload = json.dumps(resolved, sort_keys=True, separators=(",", ":")).encode()
    return replace(base, review_policy=policy, resolved_json=payload,
                   resolved_sha256=hashlib.sha256(payload).hexdigest(),
                   runtime=replace(base.runtime, runs_dir=runs, data_dir=tmp_path / "data",
                                         metadata_dir=runs / "metadata"))


@dataclass
class Staged:
    config: Any
    run_id: str
    run_root: Path
    target: Path
    ids: dict[str, str] = field(default_factory=dict)
    upstream_shards: list[dict[str, Any]] = field(default_factory=list)

    @property
    def runs(self) -> Path:
        return self.config.runtime.runs_dir

    def export_dir(self, scope_id: str) -> Path:
        return self.run_root / "data" / "codeql" / "scopes" / scope_id / "exports"


def _sha(path: Path) -> str:
    return file_sha256(path)


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _span(source: SourceFile, path: str, line: int, column: int, end_line: int, end_column: int,
          method: str = "fixture-exact") -> SourceLocation:
    start, end = source.offset(line, column), source.offset(end_line, end_column)
    assert start is not None and end is not None
    return SourceLocation(SNAPSHOT, path, source.sha256, start, end, line, end_line, column, end_column, {},
                          method, 1.0)


def _line(source: SourceFile, path: str, line: int) -> SourceLocation:
    starts = source.line_starts
    end = starts[line] - 1 if line < len(starts) else source.size
    return SourceLocation(SNAPSHOT, path, source.sha256, starts[line - 1], end, line, line, 1, 1, {},
                          "codeql-sarif-flow-step", 1.0)


def sarif_step(source: SourceFile, ordinal: int, line: int, column: int, end_line: int, end_column: int,
               *, code_flow: int = 0) -> dict[str, Any]:
    """One normalized SARIF flow step as ``sarif.py`` stores it (end column exclusive)."""
    return {"ordinal": ordinal, "code_flow": code_flow, "thread_flow": 0, "message": "step",
            "location": {"path": SYNTHETIC_PATH, "file_sha256": source.sha256, "start_line": line,
                         "end_line": end_line, "start_column": column, "end_column": end_column,
                         "confidence": 1.0, "ambiguous": False}}


# getenv(...) -> atoi(...) -> m -> len parameter -> memcpy sink (test_normalize's bridged flow).
BRIDGED_FLOW = ((55, 16, 55, 35), (55, 11, 55, 36), (58, 32, 58, 33), (41, 49, 41, 56), (45, 3, 45, 24))
# The len parameter is no entry point, so no path joins this flow to the memcpy sink.
BROKEN_FLOW = ((41, 49, 41, 56), (45, 3, 45, 24))


def stage_run(tmp_path: Path, *, with_priority: bool = True, legacy_codeql: bool = False) -> Staged:
    config = configured(tmp_path)
    runner = JobRunner(config)
    run_id, run_root = runner.runs.create(datetime(2026, 10, 12, tzinfo=timezone.utc))
    runner._bind_configuration(run_root)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    shutil.copyfile(EXPORTS / "synthetic" / "source" / "synthetic.cpp", target / SYNTHETIC_PATH)
    (target / "native").mkdir()
    for name in ("main.cpp", "helper.c"):
        shutil.copyfile(NATIVE_SOURCES / name, target / "native" / name)
    (target / "broken").mkdir()
    (target / "broken" / "x.cpp").write_text("int x(void) { return 0; }\n", encoding="utf-8")
    (target / "svc").mkdir()
    (target / "svc" / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    staged = Staged(config, run_id, run_root, target)
    source = SourceFile.from_bytes((target / SYNTHETIC_PATH).read_bytes())

    def files(*paths: str) -> list[dict[str, Any]]:
        return [{"path": path, "sha256": _sha(target / path), "size_bytes": (target / path).stat().st_size}
                for path in paths]

    plan_scopes = [
        {"scope_id": SYNTHETIC, "language": "cpp", "root": "src", "build_unit_id": "build-unit-synthetic",
         "files": files(SYNTHETIC_PATH)},
        {"scope_id": NATIVE, "language": "cpp", "root": "native", "build_unit_id": "build-unit-native",
         "files": files("native/helper.c", "native/main.cpp")},
        {"scope_id": FAILED, "language": "cpp", "root": "broken", "build_unit_id": "build-unit-broken",
         "files": files("broken/x.cpp")},
        {"scope_id": GO, "language": "go", "root": "svc", "build_unit_id": "build-unit-go",
         "files": files("svc/main.go")},
    ]
    attempt = run_root / "data" / "jobs" / CODEQL / "attempts" / "attempt_0001"
    artifacts: list[dict[str, Any]] = []
    plan_path = attempt / "artifacts" / "codeql" / "plan.json"
    atomic_json(plan_path, {"schema": "appsec-review/codeql-plan/1", "source_fingerprint": SNAPSHOT,
                            "scopes": plan_scopes})
    plan = _artifact(run_root, plan_path)

    records = []
    for scope, recording in ((plan_scopes[0], "synthetic"), (plan_scopes[1], "native")):
        exports = staged.export_dir(scope["scope_id"])
        shutil.copytree(EXPORTS / recording / "exports", exports)
        atomic_json(exports.parent / "export-checkpoint.json", {"schema": "appsec-review/codeql-export-checkpoint/1",
                                                                "identity": "e" * 64})
        manifest = json.loads((exports / "export-manifest.json").read_text(encoding="utf-8"))
        records.append({
            "scope_id": scope["scope_id"], "language": "cpp", "root": scope["root"],
            "build_unit_id": scope["build_unit_id"], "database_identity": hashlib.sha256(
                scope["scope_id"].encode()).hexdigest(), "export_identity": "f" * 64, "export_reused": False,
            "export_status": "SUCCEEDED", "export_pack": dict(manifest["pack"]),
            "export_manifest": _artifact(run_root, exports / "export-manifest.json"),
            "export_files": [{"query_id": item["query_id"], **_artifact(run_root, exports / item["path"])}
                             for item in manifest["exports"]],
            "export_count": len(manifest["exports"]), "truncated_queries": [], "gaps": []})
    records.append({"scope_id": FAILED, "language": "cpp", "root": "broken", "build_unit_id": "build-unit-broken",
                    "database_identity": None, "export_identity": None, "export_reused": False,
                    "export_status": "SKIPPED",
                    "gaps": ["CodeQL graph export skipped because database creation failed"]})
    records.append({"scope_id": GO, "language": "go", "root": "svc", "build_unit_id": "build-unit-go",
                    "database_identity": "9" * 64, "export_identity": None, "export_reused": False,
                    "export_status": "NOT_APPLICABLE", "reason": "no hash-pinned CodeQL graph export pack for go",
                    "gaps": []})
    index_path = attempt / "artifacts" / "codeql" / "graph-exports.json"
    atomic_json(index_path, {"schema": GRAPH_EXPORTS_SCHEMA, "settings": {}, "exports": records})
    index = _artifact(run_root, index_path)

    # -- accepted secondary, observation and prioritization shards --------------------------------
    identities: list[IndexIdentity] = []

    def shard(name: str, shard_id: str, producer: Mapping[str, Any], entities: Sequence[EntityRecord],
              relations: Sequence[RelationRecord] = ()) -> None:
        fingerprint = index_fingerprint(name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"shard": shard_id}],
                                        tool_identity=dict(producer), parser_identity="fixture/1",
                                        normalizer_identity="fixture/1", mapping_identity="fixture/1")
        path = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(shard_id, "complete")
        identities.append(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                                        path.relative_to(run_root).as_posix(), dict(producer), (), shard_id))

    clangd: dict[str, str] = {}
    entities = []
    for name, (line, column) in CLANGD_SYMBOLS.items():
        identity = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"producer": "clangd", "clangd_id": name})
        clangd[name] = identity.value
        entities.append(EntityRecord(identity, name.upper(), name, f"Function {name}", {
            "producer": "clangd", "kind": "Function",
            "definition": {"path": SYNTHETIC_PATH, "line": line, "column": column, "end_line": line,
                           "end_column": column + len(name)}},
            _span(source, SYNTHETIC_PATH, line, column, line, column + len(name), "clangd-uri-exact-path")))
    relations = [RelationRecord(RelationKind.CALLS, clangd[caller], clangd[callee], True, 1.0, None, {
        "producer": "clangd", "occurrences": 1,
        "locations": [{"path": SYNTHETIC_PATH, "line": line, "column": column, "ref_kind": 28}]})
        for (caller, callee), (line, column) in CLANGD_CALLS.items()]
    shard("analysis", "clangd-cpp-scope-synthetic", {"job": "job_cpp_symbol_index", "unit": "index.scopes",
                                                     "scope_id": "cpp-scope-synthetic"}, entities, relations)
    staged.ids.update({f"clangd:{name}": value for name, value in clangd.items()})

    observations = []
    for key, flow in (("bridged", BRIDGED_FLOW), ("broken", BROKEN_FLOW)):
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"codeql": key})
        staged.ids[f"obs:{key}"] = identity.value
        steps = [sarif_step(source, ordinal, *span) for ordinal, span in enumerate(flow)]
        observations.append(EntityRecord(identity, key, "cpp/overflow", f"{key} flow", {
            "producer": "codeql", "rule_id": "cpp/overflow", "flows": steps}, _line(source, SYNTHETIC_PATH, 45)))
    shard("observations", f"codeql-cpp-{SYNTHETIC}-default", {"job": CODEQL, "unit": "normalize.scopes",
                                                             "language": "cpp", "query_profile": "default"},
          observations)

    if with_priority:
        signal = LogicalIdentity.derive(EntityKind.REVIEW_SIGNAL, SNAPSHOT, {"signal_id": "path-bridged"})
        staged.ids["signal"] = signal.value
        priority_entities = [EntityRecord(signal, "path-bridged", "cpp/overflow", "semantic_path", {
            "category": "semantic_path", "path_id": "path-bridged", "observation": staged.ids["obs:bridged"],
            "code_flow": 0, "thread_flow": 0, "steps": len(BRIDGED_FLOW)}, _line(source, SYNTHETIC_PATH, 45))]
        priority_relations = []
        for ordinal, (line, *_rest) in enumerate(BRIDGED_FLOW):
            step = LogicalIdentity.derive(EntityKind.REVIEW_FLOW_STEP, SNAPSHOT, {"path_id": "path-bridged",
                                                                                 "ordinal": ordinal})
            staged.ids[f"step:{ordinal}"] = step.value
            priority_entities.append(EntityRecord(step, f"path-bridged:{ordinal}", f"flow step {ordinal}", "step", {
                "path_id": "path-bridged", "ordinal": ordinal, "producer": "codeql"},
                _line(source, SYNTHETIC_PATH, line)))
            priority_relations.append(RelationRecord(RelationKind.CONTAINS, signal.value, step.value, True, 1.0))
        shard("priority", "review-priority", {"job": "job_review_prioritization", "unit": "publish.index_priority"},
              priority_entities, priority_relations)

    manifest_path = run_root / "data" / "indices" / "manifests" / f"codeql-{attempt.name}.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    manifest = _artifact(run_root, manifest_path)
    staged.upstream_shards = json.loads(manifest_path.read_text(encoding="utf-8"))["indexes"]

    result_path = attempt / "result.json"
    export_unit = "export.scopes" if legacy_codeql else "execution.scopes"
    artifact_key = "artifact" if legacy_codeql else "graph_export_artifact"
    export_output = {"schema": GRAPH_EXPORTS_SCHEMA, artifact_key: index, "exports": records, "gaps": []}
    atomic_json(result_path, {"schema": "appsec-review/unit-execution/2", "status": "SUCCEEDED", "outputs": {
        "plan.inventory": {"plan": plan},
        export_unit: export_output,
        "acceptance.publish_handoff": {"index_manifest": manifest, "gaps": []}}})
    artifacts = [_artifact(run_root, result_path), plan, index, manifest]
    for record in records:
        if record["export_status"] == "SUCCEEDED":
            artifacts.append(record["export_manifest"])
            artifacts.extend({key: value for key, value in item.items() if key != "query_id"}
                             for item in record["export_files"])
    handoff_path = attempt / "handoff.json"
    from tests.handoff_fixture import write_fixture_handoff
    write_fixture_handoff(run_root, handoff_path, {
        "job_id": CODEQL, "attempt_id": attempt.name, "status": "ACCEPTED",
        "completion_status": "COMPLETED_WITH_GAPS", "source_fingerprint": SNAPSHOT,
        "outputs": {export_unit: export_output,
                    "acceptance.publish_handoff": {"index_manifest": manifest, "gaps": []}},
        "artifacts": artifacts,
        "resolving_paths": {"attempt": attempt.relative_to(run_root).as_posix(),
                            "result": result_path.relative_to(run_root).as_posix()}})
    handoff = _artifact(run_root, handoff_path)
    atomic_json(run_root / "data" / "jobs" / CODEQL / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": attempt.name, "handoff_path": handoff["path"],
        "handoff_sha256": handoff["sha256"]})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id, "handoff_path": handoff["path"],
        "handoff_sha256": handoff["sha256"], "manifest_path": manifest["path"], "manifest_sha256": manifest["sha256"]})
    return staged
