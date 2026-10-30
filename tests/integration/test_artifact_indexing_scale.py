"""Integration: a multi-unit receipt with ~5k produced artifacts through the full artifact-indexing job.

Exercises the per-build-unit batched layout end to end: GraphRunner publication, the accepted
handoff loader, RetrievalCore GENERATED_FROM/LINKS_INTO traces across batch shards, and the
downstream loaders of job_debug_symbol_indexing and job_artifact_security_analysis.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from appsec_review.jobs.job_artifact_indexing import build_job, canonical_artifact_identity
from appsec_review.jobs.job_artifact_indexing import job as job_module
from appsec_review.jobs.job_artifact_indexing.job import load_accepted_artifact_index
from appsec_review.jobs.job_artifact_security_analysis import job as security_job
from appsec_review.jobs.job_debug_symbol_indexing import job as debug_job
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from tests.test_artifact_indexing import RUN_ID
from tests.test_artifact_indexing_throughput import _scaled_native_run

OBJECTS = 5_000
BATCH = 2_000


def test_multi_unit_scale_publication_traces_and_downstream_loaders(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(job_module, "MAX_ARTIFACTS_PER_SHARD", BATCH)
    config, target, snapshot, run_root, _handoff = _scaled_native_run(
        tmp_path / "scale", OBJECTS, build_families=("native", "dotnet", "wasm", "python"))
    outcome = GraphRunner(config, [build_job()]).run(
        target_root=target, source_fingerprint=snapshot, run_id=RUN_ID)
    assert outcome["jobs"]["job_artifact_indexing"]["status"]["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}

    receipts = load_accepted_language_build(run_root)["receipts"]
    native = next(item for item in receipts if item["family"] == "native")
    native_unit = native["build_unit_id"]
    accepted = load_accepted_artifact_index(run_root)
    assert accepted["artifact_count"] == (sum(len(item["artifacts"]) for item in receipts)
                                          + len(accepted["target_artifacts"]))

    core = RetrievalCore(config.runtime.runs_dir, RUN_ID)
    shards = [item for item in core.manifest["indexes"] if item["name"] == "artifacts"]
    relations = sorted(item["shard_id"] for item in shards if item["shard_id"].startswith("relations-"))
    expected_batches = -(-(OBJECTS + 1) // BATCH)
    assert [item for item in relations if native_unit in item] == [
        f"relations-{native_unit}-{batch:04d}" for batch in range(expected_batches)]
    assert {item.rsplit("-", 1)[0] for item in relations} == {
        f"relations-{receipt['build_unit_id']}" for receipt in receipts}
    assert accepted["artifact_shard_count"] == len(shards)
    for shard in shards:
        if shard["shard_id"].startswith("relations-") and native_unit in shard["shard_id"]:
            assert shard["producer"]["batch_count"] == expected_batches

    objects = [item for item in native["artifacts"] if item["kind"] == "object"]
    app = next(item for item in native["artifacts"] if item["kind"] == "executable")
    app_identity = canonical_artifact_identity(snapshot, native_unit, app).value
    # RetrievalLimits.max_results bounds a trace, so follow individual objects across batches.
    for artifact in (objects[0], objects[len(objects) // 2], objects[-1]):
        identity = canonical_artifact_identity(snapshot, native_unit, artifact).value
        links = core.trace(identity=identity, relations=("LINKS_INTO",), depth=1)
        assert [(item["source_id"], item["target_id"]) for item in links["results"]] == [
            (identity, app_identity)]
        generated = core.trace(identity=identity, relations=("GENERATED_FROM",), depth=1)
        assert [(item["source_id"], item["exact"]) for item in generated["results"]] == [(identity, 1)]
        action = generated["results"][0]["target_id"]
        producing = core.query_artifacts(artifact_identity=identity, producing_build_action=action)
        assert [item["identity"] for item in producing["results"]] == [identity]
    assert len({item["shard_id"] for artifact in (objects[0], objects[-1]) for item in core.trace(
        identity=canonical_artifact_identity(snapshot, native_unit, artifact).value,
        relations=("GENERATED_FROM",), depth=1)["results"]}) == 2

    security = security_job._accepted_artifacts(run_root)
    assert len(security["artifacts"]) == accepted["artifact_count"]
    assert security["artifact_index"]["handoff_sha256"] == accepted["handoff_sha256"]

    debug_unit = SimpleNamespace(job=SimpleNamespace(
        run_root=run_root, run_id=RUN_ID, source_fingerprint=snapshot))
    debug = debug_job._accepted_inputs(debug_unit, {"max_artifacts": OBJECTS + 10})
    debug_identities = {item["artifact_identity"] for item in debug["artifacts"]}
    assert app_identity in debug_identities
    assert len(debug_identities) >= OBJECTS + 1
    assert debug["artifact_handoff_sha256"] == accepted["handoff_sha256"]


def test_rerun_reuses_every_batch_shard(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(job_module, "MAX_ARTIFACTS_PER_SHARD", BATCH)
    config, target, snapshot, run_root, _handoff = _scaled_native_run(tmp_path / "rerun", OBJECTS)
    runner = GraphRunner(config, [build_job()])
    runner.run(target_root=target, source_fingerprint=snapshot, run_id=RUN_ID)
    first = {item["shard_id"]: item["sha256"] for item in RetrievalCore(
        config.runtime.runs_dir, RUN_ID).manifest["indexes"] if item["name"] == "artifacts"}
    runner.run(target_root=target, source_fingerprint=snapshot, run_id=RUN_ID,
               force_from="job_artifact_indexing")
    second = {item["shard_id"]: item["sha256"] for item in RetrievalCore(
        config.runtime.runs_dir, RUN_ID).manifest["indexes"] if item["name"] == "artifacts"}
    assert second == first
    accepted = load_accepted_artifact_index(run_root)
    assert accepted["reused_shard_count"] == accepted["artifact_shard_count"] == len(first)
