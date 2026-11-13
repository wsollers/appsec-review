"""``acceptance.publish_handoff`` joins the two lanes: exactly one selected shard, the upstream
manifest carried forward with the symbol shard added, and a hash-bound summary inside its glob."""
from __future__ import annotations

import json

import pytest

from appsec_review.debug_symbols.contract import INDEX_NAME
from appsec_review.jobs.job_debug_symbol_indexing.job import SCHEMA, FrameworkIntegrityError
from appsec_review.retrieval import INDEX_SCHEMA, IndexBuilder, IndexIdentity
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.storage import file_sha256
from tests.unit.job_debug_symbol_indexing.support import (
    ELF, HANDOFF_SHA, SNAPSHOT, accepted_inputs, artifact, build_job, catalog_shard, decide, events, extract_output,
    extractor, handlers, job_context, manifest, unit,
)


def _stale_symbol_shard(run_root):
    path = run_root / "data" / "indices" / INDEX_NAME / "stale.sqlite"
    builder = IndexBuilder(path, name=INDEX_NAME, fingerprint="9" * 64, target_snapshot=SNAPSHOT, shard_id="symbols-old")
    builder.add_coverage("old", "complete")
    return IndexIdentity(INDEX_NAME, INDEX_SCHEMA, builder.build(), "9" * 64, path.relative_to(run_root).as_posix(),
                         {"job_id": "job_debug_symbol_indexing"}, (), "symbols-old")


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    """Decision and real extraction of one binary, plus the real catalog shard in the upstream manifest."""
    context = job_context(tmp_path)
    run_root = context.run_root
    binary = artifact(run_root, "bin/program", ELF)
    catalog = catalog_shard(run_root, [binary])
    stale = _stale_symbol_shard(run_root)
    upstream = manifest(run_root, [catalog, stale])
    job = build_job(extractor=extractor())
    decision = decide(monkeypatch, job, context, accepted_inputs([binary], upstream, gaps=["catalog gap"]))
    selected = handlers(job)["extract.clang_dwarf"](unit(context, "extract.clang_dwarf", {"decide.target": decision}))
    skipped = handlers(job)["extract.msvc_pdb"](unit(context, "extract.msvc_pdb", {"decide.target": decision}))
    return context, job, decision, selected, skipped, catalog, stale


def _publish(pipeline, **overrides):
    context, job, decision, selected, skipped, *_ = pipeline
    outputs = {"decide.target": decision, "extract.clang_dwarf": selected, "extract.msvc_pdb": skipped, **overrides}
    return handlers(job)["acceptance.publish_handoff"](unit(context, "acceptance.publish_handoff", outputs))


def test_publication_merges_the_symbol_shard_into_the_upstream_manifest_and_binds_the_summary(pipeline):
    context, job, decision, selected, skipped, catalog, stale = pipeline
    result = _publish(pipeline)
    assert result["schema"] == SCHEMA and result["item_count"] == 3
    assert result["gaps"] == ["catalog gap"] and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    manifest_path = context.run_root / result["index_manifest"]["path"]
    assert result["index_manifest"]["path"] == "data/indices/manifests/debug-symbol-indexing-attempt_0001.json"
    document, _ = load_verified_manifest(context.run_root, manifest_path, result["index_manifest"]["sha256"])
    assert [(item["name"], item["shard_id"]) for item in document["indexes"]] == [
        ("artifacts", "catalog-fixture"), (INDEX_NAME, "symbols-clang_dwarf")], "a prior symbol shard is replaced"
    assert document["indexes"][0]["sha256"] == catalog.sha256
    assert document["indexes"][1] == {**selected["indexes"][0], "gaps": ["catalog gap"]}
    assert document["upstream_manifests"] == [decision_document(context)["upstream_manifest"]]
    assert document["run_id"] == context.run_id and document["target_snapshot"] == SNAPSHOT
    summary_path = context.run_root / result["artifact"]["path"]
    assert result["artifact"]["path"].endswith("attempts/attempt_0001/artifacts/debug-symbols/accepted-index.json")
    assert file_sha256(summary_path) == result["artifact"]["sha256"]
    summary = json.loads(summary_path.read_text())
    assert summary == {
        "schema": SCHEMA, "source_fingerprint": SNAPSHOT, "compiler_target": "clang", "selected_lane": "clang_dwarf",
        "decision": decision["artifact"], "reader_evidence": selected["artifact"],
        "input_fingerprint": selected["input_fingerprint"], "artifact_handoff_sha256": HANDOFF_SHA,
        "record_count": 3, "artifact_count": 1, "gaps": ["catalog gap"], "index_manifest": result["index_manifest"]}
    completed = [event for event in events(context) if event["event"] == "DEBUG_SYMBOL_INDEX_COMPLETED"]
    assert len(completed) == 1
    assert {key: completed[0][key] for key in ("unit_id", "compiler_target", "lane", "record_count", "artifact_count", "gap_count")} == {
        "unit_id": "acceptance.publish_handoff", "compiler_target": "clang", "lane": "clang_dwarf",
        "record_count": 3, "artifact_count": 1, "gap_count": 1}
    assert completed[0]["duration_ms"] >= selected["duration_ms"]


def decision_document(context):
    return json.loads((context.attempt_root / "artifacts" / "debug-symbols" / "decision.json").read_text())


def test_publication_without_gaps_succeeds(pipeline, monkeypatch):
    context, job, decision, selected, skipped, *_ = pipeline
    result = _publish(pipeline, **{"extract.clang_dwarf": {**selected, "gaps": []}})
    assert result["terminal_status"] == "SUCCEEDED" and result["gaps"] == []


@pytest.mark.parametrize("case", ["other-not-skipped", "other-has-indexes", "selected-has-no-indexes"])
def test_publication_requires_exactly_one_selected_lane(pipeline, case):
    context, job, decision, selected, skipped, *_ = pipeline
    overrides = {
        "other-not-skipped": {"extract.msvc_pdb": {**skipped, "status": "COMPLETED"}},
        "other-has-indexes": {"extract.msvc_pdb": {**skipped, "indexes": selected["indexes"]}},
        "selected-has-no-indexes": {"extract.clang_dwarf": {**selected, "indexes": []}},
    }[case]
    with pytest.raises(ValueError, match="exactly one selected lane"):
        _publish(pipeline, **overrides)
    assert not (context.attempt_root / "artifacts" / "debug-symbols" / "accepted-index.json").exists()


def test_publication_refuses_a_selected_shard_whose_bytes_moved(pipeline):
    context, job, decision, selected, skipped, *_ = pipeline
    (context.run_root / selected["indexes"][0]["relative_path"]).write_bytes(b"corrupt")
    with pytest.raises(ValueError):
        _publish(pipeline)
    assert not (context.attempt_root / "artifacts" / "debug-symbols" / "accepted-index.json").exists()


def test_publication_refuses_an_upstream_manifest_whose_bytes_moved(pipeline):
    context, job, decision, *_ = pipeline
    upstream = decision_document(context)["upstream_manifest"]
    (context.run_root / upstream["path"]).write_text("{}")
    with pytest.raises(ValueError):
        _publish(pipeline)


def test_publication_re_reads_the_decision_before_trusting_lane_outputs(pipeline):
    context, job, decision, *_ = pipeline
    (context.run_root / decision["artifact"]["path"]).write_text("{}")
    with pytest.raises(FrameworkIntegrityError, match="decision"):
        _publish(pipeline)


def test_canned_lane_outputs_of_the_other_lane_are_accepted_when_skipped(pipeline):
    context, job, decision, selected, skipped, *_ = pipeline
    result = _publish(pipeline, **{"extract.msvc_pdb": extract_output(skipped=True)})
    assert result["item_count"] == 3
