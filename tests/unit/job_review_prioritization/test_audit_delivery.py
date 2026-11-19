"""T-5177/T-5178: real offline priority publication, reuse and bounded delivery."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_review_prioritization import build_job
from appsec_review.jobs.job_review_prioritization.dependencies import GraphBuilder
from appsec_review.jobs.job_review_prioritization.inputs import read_json
from appsec_review.jobs.job_review_prioritization.semantic import codeql_paths
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation, write_manifest,
)
from appsec_review.review.lead_families import LeadCollection
from appsec_review.review.packages import PackageSettings, assemble_packages, rank_hunt_candidates
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import atomic_json, file_sha256
from tests.unit.job_review_prioritization.test_contract import (
    BASE_CONFIG, GOLDEN, JOB_ID, _artifact_ref, _job_context, _publish_handoff, _seed_upstream_run,
)
from tests.unit.job_review_prioritization.test_signals_and_rewiring import _seed_polyglot_run, _sources


def _codeql(run: Path, target: Path, snapshot: str, scopes: list[dict], *, gaps=(), flows=()) -> str:
    shard = run / "data/indices/observations/codeql/empty.sqlite"
    builder = IndexBuilder(shard, name="observations", fingerprint="b" * 64,
                           target_snapshot=snapshot, shard_id="codeql")
    builder.add_coverage("codeql", "partial" if gaps else "complete")
    for ordinal, points in enumerate(flows):
        steps = []
        for number, (path, line) in enumerate(points):
            steps.append({"ordinal": number, "code_flow": 0, "thread_flow": 0, "location": {
                "path": path, "file_sha256": file_sha256(target / path) if (target / path).is_file() else None,
                "start_line": line, "end_line": line, "start_column": 1, "end_column": 2}})
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"flow": ordinal})
        builder.add_entity(EntityRecord(identity, str(ordinal), "flow", "flow", {
            "rule_id": f"rule-{ordinal}", "language": "go", "query_identity": "q", "flows": steps}, None))
    builder.build()
    manifest = run / "fixture/codeql-manifest.json"
    write_manifest(manifest, run_id=run.name, target_snapshot=snapshot, target_root=target, indexes=[
        IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(shard), "b" * 64,
                      shard.relative_to(run).as_posix(), {"job": "job_codeql_analysis"}, (), "codeql")])
    ref = _artifact_ref(run, run / "fixture/codeql.json", {
        "schema": "appsec-review/codeql-analysis-handoff/1", "target_snapshot": snapshot,
        "scopes": scopes, "gaps": list(gaps)})
    return _publish_handoff(run, "job_codeql_analysis", {"acceptance.publish_handoff": {
        "artifact": ref, "index_manifest": _artifact_ref(run, manifest)}})


def test_failed_codeql_scope_never_becomes_observed_zero(tmp_path: Path) -> None:
    run, target, snapshot, pins = _seed_upstream_run(
        tmp_path, golden_paths=("go/server/handler.go", "go/store/store.go"))
    scopes = [
        {"scope_id": "ok", "root": "go/server", "language": "go", "build_unit_id": None,
         "query_profile": "security", "terminal_status": "SUCCEEDED", "gaps": []},
        {"scope_id": "bad", "root": "go/store", "language": "go", "build_unit_id": None,
         "query_profile": "security", "terminal_status": "FAILED", "gaps": ["query timeout"]},
    ]
    pins["job_codeql_analysis"] = _codeql(run, target, snapshot, scopes, gaps=["query timeout"])
    semantic = codeql_paths(run, limit=10)
    assert semantic["status"] == "PARTIAL"
    assert semantic["scopes"] == scopes
    assert semantic["languages"] == {"go": "PARTIAL"}
    assert any("bad" in gap and "security" in gap and "FAILED" in gap for gap in semantic["gaps"])
    result = build_job().execute(_job_context(
        tmp_path, run, target, snapshot, pins, settings_override={"sources": _sources("codeql")}))
    ranking = read_json(run, result["outputs"]["prioritize.score"]["artifact"])
    files = {item["path"]: item for item in ranking["files"]}
    assert files["go/server/handler.go"]["features"]["semantic_path"] == 0
    assert files["go/store/store.go"]["features"]["semantic_path"] is None
    assert "semantic_path" in files["go/store/store.go"]["missing_features"]
    assert any("bad" in gap for gap in files["go/store/store.go"]["gaps"])
    for item in ranking["functions"]:
        if item["path"] == "go/store/store.go":
            assert item["features"]["semantic_path"] is None


@pytest.mark.parametrize("case", [
    "complete", "path-cap", "step-cap", "unbound", "missing-scopes", "partial-profile", "outside-scope",
])
def test_semantic_counts_preserve_positive_evidence_and_qualify_omissions(tmp_path: Path, case: str) -> None:
    run, target, snapshot, pins = _seed_upstream_run(
        tmp_path, golden_paths=("go/server/handler.go", "go/store/store.go"))
    scopes = [{"scope_id": "go", "root": "go", "language": "go", "query_profile": "security",
               "terminal_status": "SUCCEEDED", "gaps": []}]
    if case == "missing-scopes":
        scopes = []
    if case == "outside-scope":
        scopes[0]["root"] = "go/server"
    if case == "partial-profile":
        scopes.append({**scopes[0], "query_profile": "extended", "terminal_status": "PARTIAL", "gaps": ["timeout"]})
    flows = [[("go/server/handler.go", 10), ("go/server/handler.go", 22)]]
    if case in {"path-cap", "step-cap", "unbound"}:
        flows.append([("go/store/store.go", 1), ("go/store/store.go", 2)])
    if case == "step-cap":
        flows[-1].append(("go/store/store.go", 3))
    if case == "unbound":
        flows[-1][0] = ("not-in-catalog.go", 1)
    pins["job_codeql_analysis"] = _codeql(run, target, snapshot, scopes, flows=flows)
    result = build_job().execute(_job_context(tmp_path, run, target, snapshot, pins, settings_override={
        "sources": _sources("codeql"), "max_semantic_paths": 1 if case == "path-cap" else 10,
        "max_flow_steps_per_path": 2 if case == "step-cap" else 10}))
    ranking = read_json(run, result["outputs"]["prioritize.score"]["artifact"])
    files = {item["path"]: item for item in ranking["files"]}
    assert files["go/server/handler.go"]["features"]["semantic_path"] == 1
    assert files["go/store/store.go"]["features"]["semantic_path"] == (0 if case == "complete" else None)
    assert files["go/store/store.go"]["semantic_path_lower_bound"] is (case != "complete")
    semantic = result["outputs"]["extract.semantic_evidence"]
    assert semantic["path_count"] == 1
    assert semantic["codeql_status"] == ("SUCCEEDED" if case == "complete" else "PARTIAL")


@pytest.mark.parametrize("mode", ["budget", "excluded", "module"])
def test_omitted_imports_qualify_shared_coupling(mode: str) -> None:
    if mode == "module":
        files = {
            "p/a.go": {"grammar": "go", "imports": [{"kind": "unsupported", "specifier": "x", "line": 1}]},
            "p/b.go": {"grammar": "go", "imports": []},
        }
        graph = GraphBuilder(files, files, lambda _: b"", min_confidence=.8, max_records=5).build({})
        assert all(item["coupling_lower_bound"] for item in graph["files"].values())
        return
    files = {
        "a.c": {"grammar": "c", "imports": [{"kind": "include", "specifier": "b.h", "line": 1}]},
        "b.h": {"grammar": "c", "imports": [{"kind": "include", "specifier": "c.h", "line": 1}]},
        "c.h": {"grammar": "c", "imports": []},
    }
    active = files if mode == "budget" else {"a.c": files["a.c"]}
    graph = GraphBuilder(active, files, lambda _: b"", min_confidence=.8,
                         max_records=1 if mode == "budget" else 5).build({})
    path = "b.h" if mode == "budget" else "a.c"
    value = graph["files"][path]
    assert value["coupling_lower_bound"] is True
    assert value["omitted_import_count"] == (1 if mode == "budget" else 0)
    assert value["excluded_target_count"] == (1 if mode == "excluded" else 0)
    assert value["coupling_gaps"]
    assert graph["modules"][value["module"]]["coupling_lower_bound"] is True
    assert value["instability"] is None


@pytest.mark.parametrize("damage", ["shard", "checkpoint", "missing-checkpoint"])
def test_cached_priority_keeps_local_gaps_and_rejects_tamper(tmp_path: Path, monkeypatch, damage: str) -> None:
    run, target, snapshot, pins = _seed_upstream_run(tmp_path, golden_paths=tuple(sorted(GOLDEN["files"])))
    ctx = _job_context(tmp_path, run, target, snapshot, pins, settings_override={
        "sources": _sources(),
        "index": {**BASE_CONFIG.job(JOB_ID).settings["index"],
                  "file_top_count": 2, "function_top_count": 1, "max_graph_neighbors": 1}})
    job = build_job()
    first = job.execute(ctx)["outputs"]["publish.index_priority"]
    assert "dependency_graph_context_bound_reached" in first["gaps"]
    with monkeypatch.context() as patch:
        patch.setattr(IndexBuilder, "build", lambda _: pytest.fail("a checkpointed shard must be reused"))
        second = job.execute(ctx)["outputs"]["publish.index_priority"]
    assert second["gaps"] == first["gaps"]
    assert second["aggregated_gaps"] == first["aggregated_gaps"]
    assert second["index_identity"] == first["index_identity"]
    checkpoint_path = run / first["checkpoint"]["path"]
    if damage == "shard":
        shard = run / first["index_identity"]["relative_path"]
        with shard.open("ab") as stream:
            stream.write(b"tampered")
    elif damage == "checkpoint":
        checkpoint = json.loads(checkpoint_path.read_text())
        checkpoint["gaps"] = []
        atomic_json(checkpoint_path, checkpoint)
    else:
        checkpoint_path.unlink()
        recovered = job.execute(ctx)["outputs"]["publish.index_priority"]
        assert recovered["index_identity"] == first["index_identity"]
        assert recovered["gaps"] == first["gaps"]
        assert recovered["checkpoint"] == first["checkpoint"]
        return
    rejected = job.execute(ctx)
    assert rejected["status"] == "FAILED"
    assert rejected["failed_units"] == ["publish.index_priority"]
    assert "differ" in rejected["units"]["publish.index_priority"]["error"]["message"]
    assert "publish.publish_handoff" not in rejected["outputs"]


def test_suppression_only_bound_preserves_count_and_names_loss(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    code = b"// nosemgrep\n// nosemgrep\n"
    (target / "comments.js").write_bytes(code)
    run = tmp_path / "runs/2026-01-01-0001"
    rows = []
    width = len(code.splitlines(keepends=True)[0])
    for ordinal, (kind, start, end, line, end_line) in enumerate([
        ("program", 0, len(code), 1, 3), ("comment", 0, width - 1, 1, 1),
        ("comment", width, len(code) - 1, 2, 2),
    ]):
        rows.append({
            "path": "comments.js", "file_sha256": file_sha256(target / "comments.js"),
            "grammar_native_type": kind, "named": True, "field": None, "error": False, "missing": False,
            "location": {"producer_location": {"grammar": "javascript",
                                                 "ordinal_path": [] if ordinal == 0 else [ordinal - 1]},
                         "start_byte": start, "end_byte": end, "start_line": line, "end_line": end_line,
                         "start_column": 1, "end_column": 12}})
    shard = run / "fixture/comments.jsonl"
    shard.parent.mkdir(parents=True)
    shard.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    run, target, snapshot, pins = _seed_upstream_run(
        tmp_path, golden_paths=(), extra_catalog_files=[{
            "path": "comments.js", "sha256": file_sha256(target / "comments.js"),
            "size_bytes": len(code), "language": "JavaScript", "generated": False,
            "delivery_role": "production", "first_party": True, "vendored": False}],
        extra_dispositions=[{"language": "JavaScript", "terminal_status": "SUCCEEDED",
                             "artifact": _artifact_ref(run, shard), "gaps": []}])
    result = build_job().execute(_job_context(tmp_path, run, target, snapshot, pins, settings_override={
        "sources": _sources(), "max_signals_per_file": 1}))
    syntax = result["outputs"]["extract.syntax_metrics"]
    record = read_json(run, syntax["artifact"])["files"]["comments.js"]
    assert record["signal_counts"] == {}
    assert record["suppression_count"] == 2 and len(record["suppressions"]) == 1
    assert "suppressions_truncated:1" in record["gaps"]
    assert "comments.js: suppressions_truncated:1" in syntax["gaps"]


def _delivery_run(tmp_path: Path):
    run, target, snapshot, pins = _seed_polyglot_run(tmp_path)
    catalog = read_json(run, {"path": "fixture/catalog.json",
                             "sha256": file_sha256(run / "fixture/catalog.json")})
    files = read_json(run, catalog["artifacts"]["repository_discovery.partition_repository"])["files"]
    source_path = run / "data/indices/source/catalog.sqlite"
    source = IndexBuilder(source_path, name="source", fingerprint="c" * 64,
                          target_snapshot=snapshot, shard_id="source")
    for item in files:
        identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, item)
        location = SourceLocation(snapshot, item["path"], item["sha256"], 0, item["size_bytes"], 1,
                                  len((target / item["path"]).read_bytes().splitlines()), 1, 1, {}, "exact", 1)
        source.add_entity(EntityRecord(identity, item["path"], item["path"], item["path"], item, location))
    source.build()
    manifest = run / "data/indices/manifests/source.json"
    write_manifest(manifest, run_id=run.name, target_snapshot=snapshot, target_root=target, indexes=[
        IndexIdentity("source", "appsec-review/retrieval-index/2", file_sha256(source_path), "c" * 64,
                      source_path.relative_to(run).as_posix(), {"job": "job_target_catalog"}, (), "source")])
    # The test context's input manifest is the real accepted catalog source index.
    atomic_json(run / "data/indices/manifests/catalog.json", read_json(run, _artifact_ref(run, manifest)))
    pins["job_target_catalog"] = _publish_handoff(run, "job_target_catalog", {
        "publish_catalog.publish_handoff": {
            "artifact": _artifact_ref(run, run / "fixture/catalog.json"),
            "index_manifest": _artifact_ref(run, run / "data/indices/manifests/catalog.json")}}, attempt_id="source")
    ci_ref = _artifact_ref(run, run / "fixture/ci.json", {
        "schema": "appsec-review/ci-configuration-analysis-handoff/1",
        "security_findings": [{"lead_candidate": True, "path": "go/server/handler.go", "line": 1,
                               "rule_id": "ci-test", "severity": "high", "message": "provisional CI route"}]})
    pins["job_ci_configuration_analysis"] = _publish_handoff(
        run, "job_ci_configuration_analysis", {"ci_coverage.publish_handoff": {"artifact": ci_ref}})
    artifact_path = run / "data/indices/observations/artifact.sqlite"
    artifacts = IndexBuilder(artifact_path, name="observations", fingerprint="d" * 64,
                             target_snapshot=snapshot, shard_id="artifact-security")
    artifact_source = next(item for item in files if item["path"] == "ruby/lib/processor.rb")
    observation = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"artifact": "test"})
    artifacts.add_entity(EntityRecord(observation, "artifact", "artifact", "artifact", {
        "lead_candidate": True, "rule_id": "artifact-test", "severity": "high", "message": "artifact route"},
        SourceLocation(snapshot, artifact_source["path"], artifact_source["sha256"], 0, 10, 1, 1, 1, 10,
                       {}, "exact", 1)))
    artifacts.build()
    artifact_manifest = run / "fixture/artifact-manifest.json"
    write_manifest(artifact_manifest, run_id=run.name, target_snapshot=snapshot, target_root=target, indexes=[
        IndexIdentity("observations", "appsec-review/retrieval-index/2", file_sha256(artifact_path), "d" * 64,
                      artifact_path.relative_to(run).as_posix(), {"job": "job_artifact_security_analysis"},
                      (), "artifact-security")])
    pins["job_artifact_security_analysis"] = _publish_handoff(
        run, "job_artifact_security_analysis", {"acceptance.publish_handoff": {
            "index_manifest": _artifact_ref(run, artifact_manifest)}})
    sca = _artifact_ref(run, run / "fixture/sca.json", {
        "schema": "appsec-review/sca-reachability/1",
        "advisories": [{"advisory_id": "CVE-2026-1234", "package_name": "ffi-lib", "package_version": "1.2",
                        "ecosystem": "crates.io", "purl": "pkg:cargo/ffi-lib@1.2", "dependency_ids": ["dep-1"],
                        "reachability": "symbol_reachable", "severity": "high", "ffi_mechanisms": ["extern"],
                        "call_sites": [{"path": "rust/src/lib.rs", "line": 1,
                                        "kind": "ffi_boundary", "ffi_mechanism": "extern"}]}]})
    dependency = _artifact_ref(run, run / "fixture/dependency.json", {
        "schema": "appsec-review/dependency-intelligence-handoff/1",
        "target_snapshot": snapshot, "sca_reachability": sca})
    pins["job_dependency_intelligence"] = _publish_handoff(
        run, "job_dependency_intelligence", {"acceptance.publish_handoff": {"artifact": dependency}})
    result = build_job().execute(_job_context(tmp_path, run, target, snapshot, pins, settings_override={
        "sources": _sources("ci_configuration", "artifact_security", "dependency_intelligence", "sast_silence_hunt"),
        "index": {**BASE_CONFIG.job(JOB_ID).settings["index"], "max_indexed_items": 1, "file_top_count": 1}}))
    manifest = result["outputs"]["publish.publish_handoff"]["index_manifest"]
    scope = accept_manifest(run, manifest_path=run / manifest["path"], manifest_sha256=manifest["sha256"])
    return run, target, result, scope


def test_full_routing_population_reaches_real_bounded_packages(tmp_path: Path) -> None:
    run, _, result, scope = _delivery_run(tmp_path)
    ranking = read_json(run, result["outputs"]["prioritize.score"]["artifact"])
    routes = [row for row in scope.store.entities(scope.producer("review_prioritization").shards,
                                                  kinds=("review_signal",))
              if row["payload"].get("routing_kind")]
    hunts = sorted((row for row in routes if row["payload"]["routing_kind"] == "hunt_candidate"),
                   key=lambda row: row["payload"]["routing_ordinal"])
    assert [row["payload"]["item_id"] for row in hunts] == [item["item_id"] for item in ranking["hunt_queue"]]
    assert len(hunts) > 1
    promoted = [row for row in routes if row["payload"]["routing_kind"] == "promoted_lead"]
    assert len(promoted) == len(ranking["promoted_leads"]) == 3
    leads = {row["payload"]["lead_source"]: row["payload"] for row in promoted}
    assert set(leads) == {"ci_configuration", "artifact_security", "sca_reachable"}
    assert leads["ci_configuration"]["upstream"]["producer"] == "job_ci_configuration_analysis"
    assert len(leads["ci_configuration"]["upstream"]["handoff_sha256"]) == 64
    assert leads["artifact_security"]["observation_identity"].startswith("asr:tool_observation:")
    assert leads["sca_reachable"]["subject"] == "pkg:cargo/ffi-lib@1.2"
    assert leads["sca_reachable"]["attack_class"] == "native_ffi_vulnerable_dependency"
    collection = LeadCollection((), (), {}, None)
    settings = PackageSettings(hunt_max_units=20, unit_max_files=1)
    candidates = rank_hunt_candidates(scope, settings, collection)
    entries = {entry.id for item in candidates.ranked for entry in item.unit.context}
    assert {row["identity"] for row in routes} <= entries
    for ranked in candidates.ranked:
        hunt_scores = [row["payload"]["score"] for row in hunts if row["payload"]["path"] in ranked.unit.paths]
        if hunt_scores:
            lps = next(signal.value for signal in ranked.unit.signals if signal.signal == "lps")
            assert lps >= round(max(hunt_scores) * settings.rank_weights.lps)
    assembly = assemble_packages(scope, settings, collection=collection)
    delivered = {entry["id"] for package in assembly.packages for entry in package.resolved()["context"]}
    assert {row["identity"] for row in routes} <= delivered
    assert all(row["payload"]["authority"] == "provisional_navigation_lead" for row in routes)
    assert not any(package.kind == "finding_lead" for package in assembly.packages)
    bounded = assemble_packages(scope, replace(settings, hunt_max_units=1, max_context_entries=1),
                                collection=collection)
    delivered = {entry["id"] for package in bounded.packages for entry in package.resolved()["context"]}
    omitted = {row["identity"] for row in routes} - delivered
    gaps = [gap for gap in bounded.gaps if gap.producer == JOB_ID and gap.state == "truncated"]
    assert omitted and {gap.scope for gap in gaps} == omitted


@pytest.mark.parametrize("denied", [False, True], ids=["admitted", "permission-removed"])
def test_routing_reads_require_actual_priority_dataset(tmp_path: Path, denied: bool) -> None:
    from appsec_review.interchange import UNIT_OUTPUT_KEYS
    from appsec_review.jobs.job_review_package_assembly.datasets import CONTRACT as PACKAGE_CONTRACT
    from appsec_review.jobs.job_review_prioritization.datasets import DATASETS
    from appsec_review.runtime.datasets import dataset_contract
    from appsec_review.runtime.handoff import collect_artifacts
    from appsec_review.runtime.inputs import input_read_scope
    from tests.handoff_fixture import write_fixture_handoff

    run, _, result, scope = _delivery_run(tmp_path)
    attempt = run / "data/jobs" / JOB_ID / "attempts/attempt_0001"
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(JOB_ID, ("load", "extract", "prioritize", "publish"), DATASETS)})
    # Use the production closed projection, not the unprojected unit result.
    outputs = {unit: {key: value[key] for key in UNIT_OUTPUT_KEYS if key in value}
               for unit, value in result["outputs"].items()}
    shard = scope.producer("review_prioritization").shards[0]
    handoff = write_fixture_handoff(run, attempt / "handoff.json", {
        "job_id": JOB_ID, "attempt_id": "attempt_0001", "outputs": outputs,
        "artifacts": [*collect_artifacts(run, result),
                      _artifact_ref(run, run / shard["relative_path"])],
        "completion_status": result["status"]}, target_snapshot=scope.target_snapshot)
    contract = replace(PACKAGE_CONTRACT, inputs=tuple(
        item for item in PACKAGE_CONTRACT.inputs
        if not (denied and item.producer == JOB_ID and item.output_kind == "priority_items")))
    context = SimpleNamespace(
        run_root=run, config=SimpleNamespace(job_id="job_review_package_assembly"),
        upstream_handoffs={JOB_ID: file_sha256(handoff)}, contract=contract)
    if denied:
        with pytest.raises(ValueError, match="undeclared consumption.*priority_items"), input_read_scope(context):
            rank_hunt_candidates(scope, PackageSettings(), LeadCollection((), (), {}, None))
    else:
        with input_read_scope(context) as reads:
            candidates = rank_hunt_candidates(scope, PackageSettings(), LeadCollection((), (), {}, None))
        assert candidates.ranked
        receipt = next(row for row in reads.document()["reads"] if row["output_kind"] == "priority_items")
        assert receipt["sha256"] == shard["sha256"]
        assert receipt["handoff_sha256"] == file_sha256(handoff)
        assert receipt["target_snapshot"] == scope.target_snapshot
        assert receipt["authority"] == "routing_context"


def test_routing_tamper_cannot_publish_packages(tmp_path: Path) -> None:
    from appsec_review.review.models import IntegrityError
    run, _, _, scope = _delivery_run(tmp_path)
    shard = scope.producer("review_prioritization").shards[0]
    with (run / shard["relative_path"]).open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(IntegrityError, match="accepted shard changed"):
        assemble_packages(scope, collection=LeadCollection((), (), {}, None))
