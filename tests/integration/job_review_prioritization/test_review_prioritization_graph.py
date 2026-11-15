"""Graph-level and optional host-toolchain tests for job_review_prioritization."""

from __future__ import annotations

from dataclasses import replace
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_review_prioritization import build_job, load_accepted_prioritization
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_tree_sitter_ast import build_job as build_tree_sitter
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore, SourceLocation,
    write_manifest,
)
from appsec_review.runtime import GraphRunner
from appsec_review.storage import atomic_json, file_sha256
from tests.container_fixture import copy_containers


pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "tests" / "fixtures" / "review_prioritization"
TARGET = FIXTURE / "target"
GOLDEN = json.loads(gzip.decompress((FIXTURE / "ast-golden.json.gz").read_bytes()))


def test_ast_golden_regenerates_identically_with_the_pinned_parser() -> None:
    from importlib.metadata import PackageNotFoundError, version
    try:
        installed = version("tree-sitter-language-pack")
    except PackageNotFoundError:
        pytest.skip("pinned tree-sitter-language-pack is not installed")
    if installed != GOLDEN["tool"]["language_pack"]:
        pytest.skip("installed tree-sitter-language-pack does not match the locked version")
    spec = importlib.util.spec_from_file_location("generate_ast", FIXTURE / "generate_ast.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert module.parse_records() == GOLDEN


class GoldenTreeSitter:
    """Replay the locked Tree-sitter container output for fixture files without Docker."""

    image_id = "sha256:" + "7" * 64

    def __init__(self, run_root: Path):
        self.run_root = run_root

    def resolve_image(self, _tool) -> str:
        return self.image_id

    def execute(self, request) -> ExecutionResult:
        payload = json.loads((request.scratch_root / "request.json").read_text(encoding="utf-8"))
        lock = json.loads((ROOT / "containers" / "tools" / "tree-sitter" / "assets.lock.json").read_text())
        records, scope_nodes = [], 0
        for item in payload["files"]:
            golden = GOLDEN["files"][item["path"]]
            assert golden["sha256"] == item["sha256"]
            if (TARGET / item["path"]).stat().st_size > payload["max_file_bytes"]:
                records.append({"kind": "file", "path": item["path"], "status": "TRUNCATED", "reason": "file_byte_limit",
                                "sha256": item["sha256"], "bytes": 0})
                continue
            limit = min(payload["max_nodes"], payload["max_scope_nodes"] - scope_nodes)
            nodes = golden["nodes"][:max(0, limit)]
            truncated = len(nodes) < len(golden["nodes"])
            scope_nodes += len(nodes)
            records.append({"kind": "file", "path": item["path"], "status": "PARTIAL" if truncated else "SUCCEEDED",
                            "sha256": item["sha256"], "bytes": (TARGET / item["path"]).stat().st_size,
                            "grammar": golden["grammar"], "root_has_error": golden["root_has_error"],
                            "node_count": len(nodes), "truncated": truncated, "nodes": nodes})
        output = {"schema": "appsec-review/tree-sitter-container-output/1",
                  "tool": {"id": "tool-tree-sitter", "version": lock["tool_version"],
                           "tree_sitter": lock["tree_sitter"]["version"], "language_pack": lock["language_pack"]["version"],
                           "normalizer_schema": lock["normalizer_schema"], "architecture": "x86_64"},
                  "scope_id": payload["scope_id"], "language": payload["language"], "records": records}
        (request.scratch_root / "output.json").write_text(json.dumps(output), encoding="utf-8")
        now = "2026-10-10T00:00:00+00:00"
        return ExecutionResult("appsec-review/container-execution/1", "tool-tree-sitter", "tool-tree-sitter:test",
                               self.image_id, self.image_id, "golden", (), {}, now, now, 0, False, False, False, False,
                               "", "", "")


def configured(tmp_path: Path, *, max_nodes: int | None = None, file_top_count: int | None = None,
               extra: str = ""):
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if max_nodes is not None:
        text = text.replace("max_nodes_per_file = 20000", f"max_nodes_per_file = {max_nodes}")
    if file_top_count is not None:
        text = text.replace("file_top_count = 0", f"file_top_count = {file_top_count}")
    text += extra
    (tmp_path / "appsec-review.toml").write_text(text, encoding="utf-8")
    copy_containers(ROOT, tmp_path)
    shutil.copytree(ROOT / "rules" / "semgrep", tmp_path / "rules" / "semgrep")
    base = load_config(tmp_path / "appsec-review.toml")
    return replace(base, runtime=replace(base.runtime, runs_dir=tmp_path / "runs", data_dir=tmp_path / "data",
                                         metadata_dir=tmp_path / "metadata"),
                   review_policy=replace(base.review_policy, releases=ComponentReleases({
                       **base.review_policy.releases.values, "platform": "test-platform",
                       "validation": "test-validation"})))


def target_copy(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    shutil.copytree(TARGET, target)
    return target


def run_graph(config, target: Path, *, run_id: str | None = None, prioritize: bool = True):
    jobs = [build_intake(), build_catalog(),
            build_tree_sitter(executor_factory=lambda unit: GoldenTreeSitter(unit.job.run_root))]
    if prioritize:
        jobs.append(build_job())
    return GraphRunner(config, jobs).run(target_root=target, source_fingerprint=source_fingerprint(target),
                                         run_id=run_id)


def published(outcome) -> dict[str, Any]:
    return outcome["jobs"]["job_review_prioritization"]["result"]["outputs"]["publish.publish_handoff"]


def test_job_ranks_indexes_and_names_every_missing_producer(tmp_path: Path) -> None:
    config = configured(tmp_path, file_top_count=12)
    target = target_copy(tmp_path)
    outcome = run_graph(config, target)
    output = published(outcome)
    assert output["terminal_status"] == "PARTIAL"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    document = load_accepted_prioritization(run_root)
    assert document is not None and document["sources"] == {
        "tree_sitter": "PARTIAL", "semgrep": "UNAVAILABLE", "codeql": "UNAVAILABLE", "history": "UNAVAILABLE"}
    gaps = "\n".join(document["gaps"])
    for expected in ("semantic_paths_unavailable", "semgrep_review_signals_unavailable",
                     "history_hotspots_unavailable", "web/src/broken.js: parse_errors",
                     "native/src/codec.c: unresolved_or_dynamic_imports: missing/config.h",
                     "web/src/server.js: unresolved_or_dynamic_imports: None (non_literal_specifier)"):
        assert expected in gaps
    assert document["summary"]["by_language"]["Go"]["function_count"] == 5
    assert document["summary"]["by_language"]["Ruby"]["function_count"] == 6
    ranking = json.loads((run_root / document["artifacts"]["ranking"]["path"]).read_text())
    first = ranking["functions"][0]
    assert set(first["features"]) >= {"cyclomatic", "cognitive", "semantic_path", "history_hotspot", "sink"}
    assert first["features"]["semantic_path"] is None and "semantic_path" in first["missing_features"]
    assert first["feature_coverage"] < 1.0 and first["evidence"]
    top = {item["name"] for item in document["top_functions"]}
    assert "UserController.importUsers" in top or "Register.<callback:mux.HandleFunc>" in top

    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    found = core.find(kind="priority_item", path="java/src/main/java/com/example/web/UserController.java",
                      indexes=("priority",))["results"]
    assert found and found[0]["payload"]["authority"].startswith("review-first")
    assert core.find(kind="priority_item", path="ruby/lib/processor.rb", indexes=("priority",))["results"]
    assert not core.find(kind="priority_item", path="php/src/Support/Helpers.php", indexes=("priority",))["results"]
    function_hit = next(item for item in core.search(query="priority function", indexes=("priority",),
                                                     kinds=("priority_item",), limit=50)["results"]
                        if item["payload"]["scope"] == "function")
    assert function_hit["location"]["mapping_method"] == "tree-sitter-byte-and-point-exact"
    traced = core.trace(identity=function_hit["identity"], relations=("DERIVED_FROM",), depth=1)
    assert any(row["kind"] == "DERIVED_FROM" and row["target_id"].startswith("asr:review_signal:")
               for row in traced["results"])
    coverage = {(row["area"], row["status"]) for item in core.coverage(indexes=("priority",))["results"]
                for row in item["coverage"]}
    assert ("codeql-semantic-paths", "unavailable") in coverage
    assert ("history-hotspots", "unavailable") in coverage
    assert ("semgrep-review-signals", "unavailable") in coverage
    assert ("complexity", "partial") in coverage

    resumed = run_graph(config, target, run_id=outcome["run_id"])
    assert [item["action"] for item in resumed["decisions"]] == ["REUSE"] * 4


def test_truncated_ast_is_a_named_gap_not_a_clean_file(tmp_path: Path) -> None:
    config = configured(tmp_path, max_nodes=400)
    target = target_copy(tmp_path)
    outcome = run_graph(config, target)
    document = load_accepted_prioritization(config.runtime.runs_dir / outcome["run_id"])
    assert document is not None
    assert any(gap.startswith("java/src/main/java/com/example/web/UserController.java: ast_truncated")
               for gap in document["gaps"])
    names = {item["path"] for item in document["top_files"]}
    assert "java/src/main/java/com/example/web/UserController.java" not in names


def test_priority_index_shard_names_its_publication_unit_and_satisfies_required_output(tmp_path: Path) -> None:
    config = configured(tmp_path)
    target = tmp_path / "target"
    for relative in ("ruby/lib/support.rb", "ruby/lib/processor.rb"):
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(TARGET / relative, target / relative)
    outcome = run_graph(config, target)
    output = published(outcome)
    run_root = config.runtime.runs_dir / outcome["run_id"]
    manifest = json.loads((run_root / output["index_manifest"]["path"]).read_text(encoding="utf-8"))
    shards = [item for item in manifest["indexes"] if item["name"] == "priority"]
    assert [item["producer"] for item in shards] == [
        {"job": "job_review_prioritization", "unit": "publish.index_priority"}]
    assert load_accepted_prioritization(run_root) is not None


def _publish_handoff(run_root: Path, job_id: str, outputs: dict[str, Any]) -> None:
    from tests.handoff_fixture import write_fixture_handoff
    attempt = run_root / "data" / "jobs" / job_id / "attempts" / "fixture"
    attempt.mkdir(parents=True, exist_ok=True)
    handoff = attempt / "handoff.json"
    write_fixture_handoff(run_root, handoff, {"status": "ACCEPTED", "job_id": job_id,
                          "outputs": outputs})
    atomic_json(run_root / "data" / "jobs" / job_id / "latest.json",
                {"handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff)})


def _artifact(run_root: Path, path: Path, value: Any) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, value)
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}


def _shard(run_root: Path, snapshot: str, target: Path, name: str, producer: dict[str, str],
           entities: list[tuple[dict[str, Any], dict[str, Any] | None]]) -> dict[str, Any]:
    fingerprint = hashlib.sha256(json.dumps([name, producer, len(entities)]).encode()).hexdigest()
    path = run_root / "data" / "indices" / name / f"fixture-{producer.get('producer', producer['job'])}.sqlite"
    builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=snapshot, shard_id=path.stem)
    for index, (payload, location) in enumerate(entities):
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"fixture": producer, "index": index})
        source = None
        if location is not None:
            data = (target / location["path"]).read_bytes()
            source = SourceLocation(snapshot, location["path"], hashlib.sha256(data).hexdigest(), 0, len(data),
                                    location["start_line"], location["start_line"], 1, 1, {}, "fixture", 1.0)
        builder.add_entity(EntityRecord(identity, str(index), "fixture", "fixture", payload, source))
    builder.build()
    identity = IndexIdentity(name, "appsec-review/retrieval-index/2", file_sha256(path), fingerprint,
                             path.relative_to(run_root).as_posix(), producer, (), path.stem)
    manifest = run_root / "data" / "indices" / "manifests" / f"fixture-{path.stem}.json"
    write_manifest(manifest, run_id=run_root.name, target_snapshot=snapshot, target_root=target, indexes=[identity])
    return {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest)}


def _step(path: str, line: int, column: int, target: Path, code_flow: int, ordinal: int) -> dict[str, Any]:
    digest = hashlib.sha256((target / path).read_bytes()).hexdigest()
    return {"ordinal": ordinal, "code_flow": code_flow, "thread_flow": 0, "message": "step",
            "location": {"path": path, "file_sha256": digest, "start_line": line, "end_line": line,
                         "start_column": column, "end_column": column + 1}}


def test_semantic_paths_semgrep_patterns_and_history_hotspots_feed_the_score(tmp_path: Path) -> None:
    config = configured(tmp_path)
    target = target_copy(tmp_path)
    first = run_graph(config, target, prioritize=False)
    run_root = config.runtime.runs_dir / first["run_id"]
    snapshot = source_fingerprint(target)
    handler = "go/server/handler.go"
    long_flow = [_step(handler, 18, 32, target, 0, 1), _step(handler, 19, 3, target, 0, 2),
                 _step(handler, 22, 3, target, 0, 3), _step(handler, 22, 15, target, 0, 4)]
    short_flow = [_step(handler, 18, 32, target, 1, 5), _step("go/store/store.go", 15, 3, target, 1, 6),
                  _step(handler, 22, 15, target, 1, 7)]
    codeql_manifest = _shard(run_root, snapshot, target, "observations", {"job": "job_codeql_analysis"}, [
        ({"producer": "codeql", "rule_id": "go/command-injection", "query_identity": "q" * 64, "language": "go",
          "message": "Command built from user input", "flows": [*long_flow, *short_flow]}, {"path": handler,
                                                                                            "start_line": 22}),
        ({"producer": "codeql", "rule_id": "go/no-flow", "query_identity": "q" * 64, "language": "go",
          "message": "single location", "flows": []}, {"path": handler, "start_line": 13}),
    ])
    summary = _artifact(run_root, run_root / "fixture" / "codeql-summary.json", {
        "schema": "appsec-review/codeql-analysis-handoff/1",
        "scopes": [{"language": "go", "terminal_status": "SUCCEEDED"}, {"language": "java", "terminal_status": "FAILED"}]})
    _publish_handoff(run_root, "job_codeql_analysis", {"acceptance.publish_handoff": {
        "artifact": summary, "index_manifest": codeql_manifest}})
    java = "java/src/main/java/com/example/web/UserController.java"
    semgrep_manifest = _shard(run_root, snapshot, target, "observations",
                              {"job": "job_evidence_collection", "producer": "tool-semgrep"}, [
        ({"tool_id": "tool-semgrep", "evidence_id": "evidence-1",
          "native_rule_id": "rules.appsec-review.review-signal.privilege_shift.spring-permit-all",
          "message": "anonymous access", "location": {"path": java, "start_line": 19, "end_line": 19}},
         {"path": java, "start_line": 19}),
        ({"tool_id": "tool-semgrep", "evidence_id": "evidence-2", "native_rule_id": "appsec-review.python-dangerous-eval",
          "message": "baseline rule", "location": {"path": java, "start_line": 20, "end_line": 20}},
         {"path": java, "start_line": 20}),
    ])
    evidence = _artifact(run_root, run_root / "fixture" / "evidence.json", {
        "schema": "appsec-review/evidence-collection-handoff/1",
        "dispositions": [{"tool_id": "tool-semgrep", "terminal_status": "SUCCEEDED", "gaps": []}]})
    _publish_handoff(run_root, "job_evidence_collection", {"evidence_publication.publish_handoff": {
        "artifact": evidence, "index_manifest": semgrep_manifest}})
    signals = _artifact(run_root, run_root / "fixture" / "history-signals.json", {
        "schema": "appsec-review/source-history-signals/2", "symbols": {}, "files": {
            "go/store/store.go": {"sii": {"rank": 1, "tier": 1, "score": 90.0}},
            "web/src/util.js": {"sii": {"rank": 2, "tier": 2, "score": 40.0}}}})
    history = _artifact(run_root, run_root / "fixture" / "source-history.json", {
        "schema": "appsec-review/source-history-analysis/2", "decision": "SUCCEEDED", "binding": "exact",
        "ranking": {"signals": signals}, "gaps": []})
    _publish_handoff(run_root, "job_source_history_analysis", {"publish.publish_handoff": {"artifact": history}})

    outcome = run_graph(config, target, run_id=first["run_id"])
    document = load_accepted_prioritization(run_root)
    assert document is not None
    assert document["sources"]["codeql"] == "PARTIAL" and document["sources"]["semgrep"] == "SUCCEEDED"
    assert document["sources"]["history"] == "EXACT"
    assert any("CodeQL java scope FAILED" in gap for gap in document["gaps"])
    semantic = json.loads((run_root / document["artifacts"]["semantic"]["path"]).read_text())
    [path] = semantic["semantic_paths"]
    assert path["steps"] == 3 and path["basis"] == "verified_semantic_path"
    assert [step["location"]["start_line"] for step in path["flow_steps"]] == [18, 15, 22]
    assert path["flow_steps"][1]["location"]["path"] == "go/store/store.go"
    assert path["source_function"].endswith("Register.<callback:mux.HandleFunc>@16:25")
    [pattern] = semantic["semgrep_signals"]
    assert pattern["category"] == "privilege_shift" and pattern["producer"] == "semgrep"
    assert pattern["function_id"].endswith("#UserController.importUsers@15:5")
    ranking = json.loads((run_root / document["artifacts"]["ranking"]["path"]).read_text())
    functions = {item["name"]: item for item in ranking["functions"]}
    handler_item = functions["Register.<callback:mux.HandleFunc>"]
    assert handler_item["features"]["semantic_path"] == 1 and path["signal_id"] in handler_item["evidence"]
    assert functions["DB.Save"]["features"]["semantic_path"] == 1
    assert functions["UserController.importUsers"]["features"]["semantic_path"] is None
    assert functions["UserController.importUsers"]["features"]["privilege_shift"] == 2
    files = {item["path"]: item for item in ranking["files"]}
    assert files["go/store/store.go"]["features"]["history_hotspot"] == 90.0
    assert files["go/store/store.go"]["features"]["semantic_path"] == 1
    assert files["native/src/codec.c"]["features"]["history_hotspot"] is None
    assert handler_item["percentiles"]["semantic_path"] == 0.8
    weights = ranking["weights"]
    expected = sum(weights[name] * value for name, value in handler_item["percentiles"].items()) / sum(
        weights[name] for name in handler_item["percentiles"])
    assert handler_item["score"] == round(expected, 6)
    go_functions = [item for item in ranking["functions"] if item["language"] == "Go"]
    assert min(go_functions, key=lambda item: item["rank"]) is handler_item
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    hits = core.search(query="semantic_path", indexes=("priority",), kinds=("review_signal",))["results"]
    assert hits and hits[0]["payload"]["basis"] == "verified_semantic_path"
    steps = core.find(kind="review_flow_step", indexes=("priority",))["results"]
    assert len(steps) == 3
    assert core.find(kind="review_context_file", indexes=("priority",))["results"]
    graph = core.trace(identity=hits[0]["identity"], relations=("CONTAINS", "FLOWS_TO"), depth=3)["results"]
    assert sum(edge["kind"] == "FLOWS_TO" for edge in graph) >= 2
