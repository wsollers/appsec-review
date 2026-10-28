"""Full dependency job with recorded compiler/SBOM and bounded HTTP boundaries."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.jobs.job_artifact_indexing import build_job as artifact_job
from appsec_review.jobs.job_dependency_intelligence import (
    HttpResponse, build_job as dependency_job, load_accepted_dependency_intelligence,
)
from appsec_review.jobs.job_review_intake import build_job as intake_job
from appsec_review.jobs.job_target_catalog import build_job as catalog_job
from appsec_review.retrieval import IndexBuilder, IndexIdentity, index_fingerprint, write_manifest
from appsec_review.runtime import GraphRunner, Job, JobRunner, Unit, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from tests.integration.test_signal_job_acceptance import _available
from tests.test_artifact_indexing import RUN_ID, _identity, _publish_changed_language_receipts, _seed


REPOSITORY = "https://github.com/example/tiny-native"
SCORECARD = b'{"score":7.4,"date":"2026-01-01","checks":[{"name":"Maintained","score":8}]}'


def _recorded_empty_sbom_job() -> Job:
    def publish(unit):
        root = unit.job.run_root
        fingerprint = index_fingerprint(
            name="observations", target_snapshot=unit.job.source_fingerprint,
            producer_artifacts=[{"recorded_sbom": "no-packages"}],
            tool_identity={"fixture": "recorded-syft"}, parser_identity="fixture/1",
            normalizer_identity="fixture/1", mapping_identity="fixture/1")
        path = root / "data" / "indices" / "observations" / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint, shard_id="recorded-syft")
        builder.add_coverage("recorded-syft", "complete")
        identity = IndexIdentity(
            "observations", "appsec-review/retrieval-index/2", builder.build(), fingerprint,
            path.relative_to(root).as_posix(), {"producer": "tool-syft"}, (), "recorded-syft")
        manifest = root / "data" / "indices" / "manifests" / "recorded-syft.json"
        write_manifest(manifest, run_id=unit.job.run_id,
                       target_snapshot=unit.job.source_fingerprint, target_root=unit.job.target_root,
                       indexes=(identity,))
        return {"index_manifest": _identity(root, manifest), "terminal_status": "SUCCEEDED"}

    units = (Unit("evidence_publication.publish_handoff", publish),)
    return Job("job_evidence_collection", "evidence_collection", UnitExecutor(units).execute,
               units=units)


def _prepare(workspace: LaneWorkspace):
    base = workspace.root / "fixture"
    base.mkdir()
    config, target, snapshot, root, receipts, accepted, handoff, latest = _seed(base)
    settings = config.job("job_dependency_intelligence").settings["scorecard"]
    cache_root = config.runtime.repository_root / settings["cache_root"]
    workspace.require_owned_path(cache_root)
    native = receipts[0]
    build_root = root / native["workspace"]
    manifest_path = root / native["workspace_manifest"]["path"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name in ("tiny", "tiny-alias"):
        relative = f"lib/pkgconfig/{name}.pc"
        path = build_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Name: {name}\nVersion: 1.0\nURL: {REPOSITORY}\n", encoding="utf-8")
        manifest["files"][relative] = file_sha256(path)
    commands = [
        {"command_id": "recorded-debug-link", "argv": ["clang", "-g", "main.o", "-ltiny"]},
        {"command_id": "recorded-qa-link", "argv": ["clang", "main.o", "-ltiny-alias"],
         "configuration": "integration-test"},
    ]
    for command in commands:
        command["argv_sha256"] = hashlib.sha256(canonical_json(command["argv"])).hexdigest()
    protected = build_root.parent / "protected-compile-commands.json"
    atomic_json(protected, {"schema": "appsec-review/protected-compile-commands/1",
                            "rows": commands})
    native["protected_compile_commands"] = _identity(root, protected)
    native["artifacts"][1]["loader_dependencies"] = ["libtiny.so.1"]
    atomic_json(manifest_path, manifest)
    native["workspace_manifest"] = _identity(root, manifest_path)
    _publish_changed_language_receipts(root, receipts, accepted, handoff, latest)
    GraphRunner(config, [intake_job(check_models=_available), catalog_job(),
                         _recorded_empty_sbom_job(), artifact_job()]).run(
        run_id=RUN_ID, target_root=target, source_fingerprint=snapshot)
    return config, target, snapshot, root, cache_root


def test_dependency_job_deduplicates_requests_and_publishes_bound_exposure_and_cache_context(
        acceptance_workspace: LaneWorkspace) -> None:
    workspace = LaneWorkspace.create(acceptance_workspace.root, "dependency-jobs")
    started = time.monotonic()
    calls = []

    def transport(url, **kwargs):
        calls.append((url, kwargs))
        return HttpResponse(200, SCORECARD, {})

    with workspace.span("acceptance.dependency_jobs"):
        config, target, snapshot, root, cache_root = _prepare(workspace)
        runner = JobRunner(config)
        job = dependency_job(scorecard_transport=transport)
        runner.run(job, run_id=RUN_ID, target_root=target, source_fingerprint=snapshot)
        first = load_accepted_dependency_intelligence(root)
        assert len(calls) == 1
        assert calls[0][0].endswith("/projects/github.com/example/tiny-native")
        assert first["scorecard_metrics"] == {
            "request_count": 1, "repository_count": 1, "cache_hit_count": 0}
        assert {item["name"] for item in first["dependencies"]} == {"tiny", "tiny-alias"}
        tiny = next(item for item in first["dependencies"] if item["name"] == "tiny")
        assert tiny["maximal_exposure"] == "PROD"
        assert {item["exposure"] for item in tiny["exposure_evidence"]} == {"DEBUG", "PROD"}
        assert all(item["evidence_id"] for item in tiny["exposure_evidence"])
        alias = next(item for item in first["dependencies"] if item["name"] == "tiny-alias")
        assert alias["maximal_exposure"] == "QA"
        assert len(first["repositories"]) == 1 and len(first["repositories"][0]["dependency_ids"]) == 2
        assert len(first["scorecards"]) == 2
        assert all(item["context_only"] is True and item["security_finding"] is False
                   for item in first["scorecards"])
        response = first["scorecards"][0]["response_artifact"]
        assert (root / response["path"]).read_bytes() == SCORECARD
        assert response["sha256"] == hashlib.sha256(SCORECARD).hexdigest()
        assert first["security_findings"] == []
        index_path = root / first["index_identity"]["relative_path"]
        with sqlite3.connect(index_path) as database:
            packages = [json.loads(row[0]) for row in database.execute(
                "SELECT payload_json FROM entities WHERE kind = 'dependency_package'")]
            signals = [json.loads(row[0]) for row in database.execute(
                "SELECT payload_json FROM entities WHERE kind = 'review_signal'")]
        assert {item["name"]: item["maximal_exposure"] for item in packages} == {
            "tiny": "PROD", "tiny-alias": "QA"}
        assert len(signals) == 2 and all(item["response_artifact"] == response for item in signals)
        assert any(cache_root.rglob("*.json"))
        first_handoff = first["handoff_sha256"]
        runner.run(job, run_id=RUN_ID, target_root=target, source_fingerprint=snapshot)
        second = load_accepted_dependency_intelligence(root)
        assert second["handoff_sha256"] != first_handoff
        assert len(calls) == 1, "fresh cache must avoid a second HTTP request"
        assert second["scorecard_metrics"] == {
            "request_count": 0, "repository_count": 1, "cache_hit_count": 1}
        assert all(item["cache"]["status"] == "hit" for item in second["scorecards"])
        assert (root / second["scorecards"][0]["response_artifact"]["path"]).read_bytes() == SCORECARD
        assert second["index_identity"]["relative_path"] != first["index_identity"]["relative_path"]
        assert file_sha256(index_path) == first["index_identity"]["sha256"]
        with sqlite3.connect(root / second["index_identity"]["relative_path"]) as database:
            cached_signals = [json.loads(row[0]) for row in database.execute(
                "SELECT payload_json FROM entities WHERE kind = 'review_signal'")]
        assert len(cached_signals) == 2 and all(item["cache"]["status"] == "hit" for item in cached_signals)
        assert (root / "data" / "logs" / "pipeline.jsonl").is_relative_to(workspace.root)
    elapsed = time.monotonic() - started
    workspace.emit("ACCEPTANCE_CASE_COMPLETED", duration_ms=elapsed * 1000, outcome="passed",
                   http_request_count=len(calls), cache_root=str(cache_root))
    assert elapsed < 120, f"dependency lane exceeded 120 seconds: {elapsed:.3f}s; {workspace.root}"
