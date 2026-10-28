"""Fixture-only generated source pipeline: no parser, Docker, tools or model execution."""
import hashlib
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import ExecutionResult
from appsec_review.jobs.job_tree_sitter_ast import job as ast
from appsec_review.jobs.job_tree_sitter_ast.generated_sources import load_generated_sources
from appsec_review.jobs.job_tree_sitter_ast.model import GrammarLock
from appsec_review.jobs.job_tree_sitter_ast.normalize import NORMALIZER_SCHEMA
from appsec_review.jobs.job_review_prioritization import job as priority
from appsec_review.orchestration.topology import WAVE1_REQUIRED, wave1_dependencies
from appsec_review.retrieval import IndexBuilder, IndexIdentity, RetrievalCore, write_manifest
from appsec_review.retrieval.source_resolution import (
    backing_reference, read_source_bytes, source_native,
)
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import immutable_bytes


ROOT = Path(__file__).parents[1]
SNAPSHOT = "a" * 64
IMAGE = "sha256:" + "d" * 64
LOCK = GrammarLock("JavaScript", "javascript", "https://example.invalid/grammar",
                   "b" * 40, "MIT", "fixture-grammar", "c" * 64)
ASSETS = {"tool_version": "fixture", "tree_sitter": {"version": "fixture"},
          "language_pack": {"version": "fixture"}, "normalizer_schema": NORMALIZER_SCHEMA}


def _json(run, relative, document):
    path = run / relative
    atomic_json(path, document)
    return {"path": relative, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _accepted(run, name, outputs):
    from tests.handoff_fixture import write_fixture_handoff
    artifacts = [value[key] for value in outputs.values()
                 for key in ("artifact", "index_manifest") if key in value]
    relative = f"data/jobs/{name}/attempts/fixture/handoff.json"
    path = write_fixture_handoff(run, run / relative, {
        "source_fingerprint": SNAPSHOT, "status": "ACCEPTED", "job_id": name,
        "outputs": outputs, "artifacts": artifacts,
    })
    reference = {"path": relative, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
    _json(run, f"data/jobs/{name}/latest.json", {
        "handoff_path": reference["path"], "handoff_sha256": reference["sha256"],
    })
    return reference


def _fixture(tmp_path, *, build=True, target_source=False):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text())
    config = load_config(config_path)
    run = tmp_path / "runs/2026-10-24-0001"
    run.mkdir(parents=True)
    target = tmp_path / "target"
    target.mkdir()
    files = []
    if target_source:
        source = target / "app.js"
        source.write_text("const original = 1;\n")
        files = [{"path": "app.js", "sha256": file_sha256(source), "size_bytes": source.stat().st_size,
                  "language": "JavaScript", "generated": False, "scope_role": "target_source"}]
    intake = _json(run, "fixture/intake.json", {
        "schema": "appsec-review/review-intake/1", "fingerprint": {"sha256": SNAPSHOT},
    })
    _accepted(run, "job_review_intake", {"publish_intake.publish_handoff": {"artifact": intake}})
    partition = _json(run, "fixture/partition.json", {"files": files, "gaps": []})
    components = _json(run, "fixture/components.json", {
        "components": [{"component_id": "fixture-component", "root": "."}],
    })
    builds = _json(run, "fixture/builds.json", {
        "targets": [{"build_unit_id": "fixture-build", "root": "."}] if build else [],
    })
    catalog = _json(run, "fixture/catalog.json", {
        "schema": "appsec-review/target-catalog/1", "source_fingerprint": SNAPSHOT,
        "artifacts": {"repository_discovery.partition_repository": partition,
                      "component_discovery.catalog_components": components,
                      "build_discovery.catalog_build_targets": builds},
    })
    index = run / "data/indices/source/fixture.sqlite"
    builder = IndexBuilder(index, name="source", fingerprint="e" * 64, target_snapshot=SNAPSHOT)
    builder.add_coverage("fixture", "complete", None)
    digest = builder.build()
    identity = IndexIdentity("source", "appsec-review/retrieval-index/2", digest, "e" * 64,
                             index.relative_to(run).as_posix(), {"job": "job_target_catalog"}, ())
    manifest = run / "data/indices/manifests/fixture.json"
    write_manifest(manifest, run_id=run.name, target_snapshot=SNAPSHOT, target_root=target, indexes=[identity])
    manifest_ref = {"path": manifest.relative_to(run).as_posix(), "sha256": file_sha256(manifest),
                    "size_bytes": manifest.stat().st_size}
    _accepted(run, "job_target_catalog", {
        "publish_catalog.publish_handoff": {"artifact": catalog, "index_manifest": manifest_ref},
    })
    workspace = run / "data/build/node/fixture/workspace"
    if build:
        artifacts, manifest_files = [], {}
        for relative, role in (("dist/generated/app.js", "deliverable"),
                               ("dist/node_modules/sdk/index.js", "shipped_dependency"),
                               ("dist/unknown.js", "unknown")):
            path = workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("const generated = 1;\n")
            digest = file_sha256(path)
            manifest_files[relative] = digest
            artifacts.append({
                "path": path.relative_to(run).as_posix(), "workspace_path": relative, "sha256": digest,
                "size_bytes": path.stat().st_size, "kind": "generated-code", "scope_role": role,
                "artifact_origin": "build-output", "build_unit_id": "fixture-build",
                "mapping": "exact-workspace-path", "mapping_confidence": 1.0,
            })
        artifacts.append({"path": "platform/must-not-exist.js", "workspace_path": "platform/tool.js",
                          "kind": "generated-code", "scope_role": "supplied_platform", "sha256": "f" * 64,
                          "size_bytes": 10, "artifact_origin": "build-output"})
        workspace_ref = _json(run, "fixture/workspace.json", {
            "schema": "appsec-review/build-workspace-manifest/1",
            "build_unit_id": "fixture-build", "files": manifest_files,
        })
        receipt = {"schema": "appsec-review/language-build-receipt/1", "family": "node",
                   "build_unit_id": "fixture-build", "root": ".", "source_fingerprint": SNAPSHOT,
                   "terminal_status": "SUCCEEDED", "workspace": workspace.relative_to(run).as_posix(),
                   "workspace_manifest": workspace_ref, "artifacts": artifacts, "tool_invocations": [], "gaps": []}
        document = _json(run, "fixture/language.json", {
            "schema": "appsec-review/language-build-handoff/1",
            "source_fingerprint": SNAPSHOT, "receipts": [receipt], "gaps": [],
        })
        _accepted(run, "job_language_build", {"acceptance.publish_handoff": {"artifact": document}})
    return config, run, target, workspace, manifest_ref


class FakeParser:
    def resolve_image(self, tool):
        return IMAGE

    def execute(self, request):
        document = json.loads((request.scratch_root / "request.json").read_text())
        records = []
        for item in document["files"]:
            source = request.target_root / item["path"]
            if item["path"].startswith("@generated/"):
                assert not request.target_root.is_relative_to(request.scratch_root)
            data = source.read_bytes()
            assert hashlib.sha256(data).hexdigest() == item["sha256"]
            records.append({
                "path": item["path"], "sha256": item["sha256"], "grammar": "javascript",
                "status": "SUCCEEDED", "bytes": len(data), "root_has_error": False, "truncated": False,
                "nodes": [{"ordinal_path": [], "field": None, "type": "program", "named": True,
                           "start_byte": 0, "end_byte": len(data), "start_point": [0, 0],
                           "end_point": [data.count(b"\n"), 0]}],
            })
        atomic_json(request.scratch_root / "output.json", {
            "schema": "appsec-review/tree-sitter-container-output/1",
            "scope_id": document["scope_id"], "language": document["language"], "records": records,
            "tool": {"id": "tool-tree-sitter", "version": "fixture", "tree_sitter": "fixture",
                     "language_pack": "fixture", "normalizer_schema": NORMALIZER_SCHEMA, "architecture": "x86_64"},
        })
        return ExecutionResult("appsec-review/container-execution/1", "tool-tree-sitter", "fixture",
                               IMAGE, IMAGE, "fixture", (), {}, "fixture", "fixture", 0,
                               False, False, False, False, "", "", "")


def _execute_units(config, run, target, job, *, initial=None):
    outputs = dict(initial or {})
    context = SimpleNamespace(
        config=config.job(job.job_id), run_root=run, run_id=run.name, target_root=target,
        source_fingerprint=SNAPSHOT, repository_root=config.runtime.repository_root, attempt_id="fixture",
        tools=config.tools, events=SimpleNamespace(write=lambda *args, **kwargs: None),
        review_policy=config.review_policy, metadata_root=run.parent / "metadata",
    )
    for task in job.units:
        root = run / f"data/jobs/{job.job_id}/attempts/fixture/units/{task.unit_id}"
        root.mkdir(parents=True, exist_ok=True)
        unit = SimpleNamespace(job=context, unit_id=task.unit_id, unit_root=root, output=lambda key: outputs[key])
        outputs[task.unit_id] = task.handler(unit)
    return outputs


def _ast_pipeline(tmp_path, monkeypatch, **options):
    config, run, target, workspace, manifest = _fixture(tmp_path, **options)
    monkeypatch.setattr(ast, "_grammar_locks", lambda _: ({"JavaScript": LOCK}, ASSETS))
    monkeypatch.setattr(ast, "load_catalog", lambda _: SimpleNamespace(tool=lambda _: object()))
    monkeypatch.setattr(ast, "resolve_context_manifest", lambda _: (run / manifest["path"], manifest["sha256"]))
    outputs = _execute_units(config, run, target, ast.build_job(executor_factory=lambda _: FakeParser()))
    _accepted(run, "job_tree_sitter_ast", {
        "acceptance.publish_handoff": outputs["acceptance.publish_handoff"],
    })
    return config, run, target, workspace, outputs


def test_generated_only_source_reaches_ast_priority_and_resolving_excerpts(tmp_path, monkeypatch):
    config, run, target, workspace, outputs = _ast_pipeline(tmp_path, monkeypatch)
    generated = outputs["load.accepted_inputs"]["accepted"]["generated_sources"]
    assert len(generated) == 3
    assert {row["scope_role"] for row in generated} == {"deliverable", "shipped_dependency", "unknown"}
    assert all(row["canonical_artifact_identity"] and row["build_unit_id"] == "fixture-build" for row in generated)
    assert any("delivery status is unknown" in gap for gap in outputs["parse.dynamic_scopes"]["gaps"])
    assert not any(target.rglob("*.js"))
    shutil.rmtree(workspace)
    manifest = outputs["acceptance.publish_handoff"]["index_manifest"]
    core = RetrievalCore(run.parent, run.name, manifest_path=run / manifest["path"])
    nodes = core.find(kind="ast_node", indexes=("analysis",))["results"]
    assert len(nodes) == 3
    for node in nodes:
        assert node["location"]["producer_location"]["source_domain"] == "generated"
        assert core.read_excerpt(identity=node["identity"])["results"][0]["excerpt"] == "const generated = 1;"
        source, gap = core.read_source_lines(identity=node["identity"])
        assert gap is None and source["lines"] == ["const generated = 1;"]
    closures = core.find(kind="source_file", indexes=("analysis",))["results"]
    assert len(closures) == 3 and all(row.get("location") for row in closures)
    monkeypatch.setattr(priority, "resolve_context_manifest", lambda _: (run / manifest["path"], manifest["sha256"]))
    prioritized = _execute_units(config, run, target, priority.build_job())
    assert prioritized["extract.syntax_metrics"]["file_count"] == 3
    priority_manifest = prioritized["publish.index_priority"]["manifest"]
    priority_core = RetrievalCore(run.parent, run.name, manifest_path=run / priority_manifest["path"])
    items = priority_core.find(kind="priority_item", indexes=("priority",))["results"]
    assert items
    for item in items:
        assert item["location"]["producer_location"]["source_domain"] == "generated"
        assert priority_core.read_source_lines(identity=item["identity"])[1] is None


def test_source_only_pipeline_keeps_target_routing_without_build(tmp_path, monkeypatch):
    _, run, _, _, outputs = _ast_pipeline(tmp_path, monkeypatch, build=False, target_source=True)
    assert outputs["load.accepted_inputs"]["accepted"]["generated_sources"] == []
    assert outputs["load.accepted_inputs"]["accepted"]["generated_source_gaps"] == []
    assert outputs["plan.route_scopes"]["scopes"][0]["files"][0]["path"] == "app.js"
    manifest = outputs["acceptance.publish_handoff"]["index_manifest"]
    core = RetrievalCore(run.parent, run.name, manifest_path=run / manifest["path"])
    [node] = core.find(kind="ast_node", indexes=("analysis",))["results"]
    assert core.read_source_lines(identity=node["identity"])[0]["lines"] == ["const original = 1;"]


@pytest.mark.parametrize("mutation", ["object", "reference", "cross_run", "snapshot", "logical_path", "origin", "symlink"])
def test_generated_backing_rejects_mutations_and_cross_run_replay(tmp_path, mutation):
    _, run, target, _, _ = _fixture(tmp_path)
    rows, _, _ = load_generated_sources(run, target_snapshot=SNAPSHOT, relevant=True,
                                       max_files=10, max_file_bytes=4096, max_total_bytes=16384)
    row = rows[0]
    native = source_native(row)
    snapshot, path = SNAPSHOT, row["path"]
    if mutation == "object":
        document = json.loads((run / row["source_backing"]["path"]).read_text())
        obj = run / document["source"]["path"]
        obj.chmod(0o644)
        obj.write_bytes(b"x" * row["size_bytes"])
    elif mutation == "reference":
        native = {"source_domain": "generated", "source_backing": {
            **row["source_backing"], "path": "../source.js"}}
    elif mutation == "cross_run":
        copied = tmp_path / "other/2026-10-24-0001"
        shutil.copytree(run, copied)
        run = copied
    elif mutation == "snapshot":
        snapshot = "f" * 64
    elif mutation == "logical_path":
        path = "@generated/wrong.js"
    elif mutation == "symlink":
        document = json.loads((run / row["source_backing"]["path"]).read_text())
        obj = run / document["source"]["path"]
        outside = tmp_path / "outside-source"
        outside.write_bytes(obj.read_bytes())
        obj.unlink()
        obj.symlink_to(outside)
    else:
        document = json.loads((run / row["source_backing"]["path"]).read_text())
        document["artifact_origin"] = "supplied-platform"
        payload = canonical_json(document)
        digest = hashlib.sha256(payload).hexdigest()
        native = {"source_domain": "generated", "source_backing": immutable_bytes(
            run, f"data/treesitter/sources/{digest}.json", payload)}
    with pytest.raises(ValueError):
        read_source_bytes(run, target, target_snapshot=snapshot, path=path, sha256=row["sha256"], native=native)


def test_generated_lane_reports_missing_producer_and_bounds(tmp_path):
    _, run, _, _, _ = _fixture(tmp_path)
    rows, gaps, _ = load_generated_sources(run, target_snapshot=SNAPSHOT, relevant=True,
                                         max_files=1, max_file_bytes=4096, max_total_bytes=4096)
    assert len(rows) == 1 and any(row["reason"] == "generated_source_lane_bound" for row in gaps)
    (run / "data/jobs/job_language_build/latest.json").unlink()
    rows, gaps, producer = load_generated_sources(run, target_snapshot=SNAPSHOT, relevant=True,
                                                  max_files=10, max_file_bytes=4096, max_total_bytes=4096)
    assert rows == [] and producer is None
    assert gaps == [{"path": "@generated", "reason": "generated_source_producer_unavailable"}]


def test_source_backing_does_not_accept_an_origin_string_or_arbitrary_native_path(tmp_path):
    with pytest.raises(ValueError, match="incomplete"):
        read_source_bytes(tmp_path, tmp_path, target_snapshot=SNAPSHOT, path="app.js", sha256="f" * 64,
                          native={"source_domain": "generated"})
    with pytest.raises(ValueError):
        backing_reference({"path": "containers/tools/tool.py", "sha256": "f" * 64, "size_bytes": 1})


@pytest.mark.parametrize("native", [[], "generated", {"source_domain": []}])
def test_source_backing_rejects_malformed_provenance(tmp_path, native):
    with pytest.raises(ValueError):
        read_source_bytes(tmp_path, tmp_path, target_snapshot=SNAPSHOT, path="app.js",
                          sha256="f" * 64, native=native)


@pytest.mark.parametrize("enabled", [False, True])
def test_ast_topology_waits_only_for_enabled_language_build(enabled):
    registered = {*WAVE1_REQUIRED, "job_tree_sitter_ast"}
    if enabled:
        registered.update({"job_project_build", "job_language_build"})
    dependencies = wave1_dependencies(registered)
    assert dependencies["job_tree_sitter_ast"] == (
        ("job_language_build",) if enabled else ("job_target_analysis_plan",))
    seen = set()
    for job, upstream in dependencies.items():
        assert set(upstream) <= seen
        seen.add(job)
