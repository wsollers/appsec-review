"""Real declared producers, immutable handoffs, admission and observed debug payload reads."""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib

import pytest

from appsec_review.debug_symbols.contract import SourceSpan
from appsec_review.jobs.job_artifact_indexing.datasets import DATASETS as ARTIFACT_DATASETS
from appsec_review.jobs.job_artifact_indexing import canonical_artifact_identity
from appsec_review.jobs.job_language_build.datasets import DATASETS as LANGUAGE_DATASETS
from appsec_review.jobs.job_debug_symbol_indexing.datasets import CONTRACT, DATASETS
from appsec_review.jobs.job_debug_symbol_indexing.job import _Sources, _accepted_inputs, load_accepted_debug_symbols
from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.retrieval import INDEX_SCHEMA, IndexBuilder, IndexIdentity
from appsec_review.runtime.inputs import admit_inputs, input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_debug_symbol_indexing.support import (
    ELF, SNAPSHOT, artifact, build_job, catalog_shard, extractor, job_context,
    manifest, ref, source_shard, unit,
)

CONTENT = b"int main() { return 0; }\n"


def publish(context, job_id, datasets, outputs, artifacts=(), *, snapshot=SNAPSHOT, pins=None):
    root = context.run_root
    attempt = root / "data" / "jobs" / job_id / "attempts" / "attempt_0001"
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(job_id, sorted({item.step for item in datasets}), datasets)})
    path = write_fixture_handoff(root, attempt / "handoff.json", {
        "job_id": job_id, "outputs": outputs, "artifacts": list(artifacts),
        "upstream_handoff_sha256": pins or {},
    }, target_snapshot=snapshot)
    return file_sha256(path)


def prepared(tmp_path, *, build_status=None):
    context = replace(job_context(tmp_path), contract=CONTRACT, evidence_target_snapshot=SNAPSHOT)
    root = context.run_root
    binary = artifact(root, "bin/program", ELF)
    language_pin = None
    if build_status is not None:
        binary["reference"]["artifact_origin"] = "build"
        binary["artifact_identity"] = canonical_artifact_identity(SNAPSHOT, "unit-1", binary["reference"]).value
        binary["reference"]["canonical_identity"] = binary["artifact_identity"]
        receipt = {"build_unit_id": "unit-1", "build_outcome": "built", "terminal_status": build_status,
                   "source_fingerprint": SNAPSHOT, "artifacts": [binary["reference"]],
                   "image": {"image_id": "sha256:" + "d" * 64, "user": "10001:10001"},
                   "gaps": ["provenance unavailable"] if build_status == "COMPLETED_WITH_GAPS" else []}
        path = root / "data/jobs/job_language_build/attempts/attempt_0001/artifacts/language-build/receipts.json"
        atomic_json(path, {"schema": "appsec-review/language-build-handoff/2", "source_fingerprint": SNAPSHOT,
                           "receipts": [receipt]})
        language_pin = publish(context, "job_language_build", LANGUAGE_DATASETS,
                               {"acceptance.publish_handoff": {"artifact": ref(root, path)}})
    source = replace(source_shard(root, CONTENT), producer={
        "job": "job_target_catalog", "unit": "retrieval_indexes.build_path_index"})
    catalog = replace(catalog_shard(root, [binary]), producer={"job": "job_artifact_indexing"})
    source_indexes = [source]
    source_outputs = {"retrieval_indexes.build_path_index": {
        "artifact": ref(root, root / source.relative_path), "index_identity": asdict(source)}}
    for name, task in (("analysis", "retrieval_indexes.build_symbol_index"),
                       ("components", "retrieval_indexes.build_component_index"),
                       ("documents", "retrieval_indexes.build_target_documents"),
                       ("build", "publish_catalog.publish_handoff")):
        path = root / "data" / "indices" / name / "catalog.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint="b" * 64, target_snapshot=SNAPSHOT)
        builder.add_coverage("fixture", "complete")
        identity = IndexIdentity(name, INDEX_SCHEMA, builder.build(), "b" * 64,
                                 path.relative_to(root).as_posix(), {"job": "job_target_catalog", "unit": task})
        source_indexes.append(identity)
        source_outputs[task] = {"artifact": ref(root, path), "index_identity": asdict(identity)}
    source_manifest = manifest(root, source_indexes, name="source.json")
    source_outputs["publish_catalog.publish_handoff"]["index_manifest"] = source_manifest
    source_pin = publish(context, "job_target_catalog", CATALOG_DATASETS,
                         source_outputs)
    upstream = manifest(root, [source, catalog])
    summary = root / "data/jobs/job_artifact_indexing/attempts/attempt_0001/artifacts/artifact-indexing/accepted-index.json"
    atomic_json(summary, {"schema": "appsec-review/artifact-indexing/1", "source_fingerprint": SNAPSHOT,
                          "target_artifacts": [] if language_pin else [binary["reference"]],
                          "language_build_handoff_sha256": language_pin, "index_manifest": upstream, "gaps": []})
    artifact_pin = publish(context, "job_artifact_indexing", ARTIFACT_DATASETS,
                           {"acceptance.publish_handoff": {"artifact": ref(root, summary), "index_manifest": upstream}},
                           [ref(root, root / catalog.relative_path)], pins={"job_target_catalog": source_pin})
    context = replace(context, upstream_handoffs={
        "job_target_catalog": source_pin, "job_artifact_indexing": artifact_pin,
        **({"job_language_build": language_pin} if language_pin else {})})
    decision = {"upstream_manifest": upstream, "settings": context.config.settings}
    return context, decision, source, catalog


def test_source_and_catalog_reads_require_exact_payloads_and_record_actual_receipts(tmp_path):
    context, decision, source, catalog = prepared(tmp_path)
    admitted = admit_inputs(context, set(context.upstream_handoffs))
    assert any(row["output_kind"] == "source_files" and row["supplied"] and not row["read"]
               for row in admitted["requirements"])
    with input_read_scope(context) as reads:
        selected = _accepted_inputs(unit(context, "decide.target"), context.config.settings)
        sources = _Sources(unit(context, "extract.clang_dwarf"), decision)
        location, gap = sources.resolve(SourceSpan("src/main.cc", 1, 0,
                                                   hashlib.sha256(CONTENT).hexdigest(), "sha256"))
        assert gap is None and location["path"] == "src/main.cc" and selected["artifacts"]
    records = reads.document()["reads"]
    for output, shard in (("source_files", source), ("artifact_catalog", catalog)):
        observed, = [row for row in records if row["output_kind"] == output]
        assert observed["sha256"] == shard.sha256 and observed["path"] == shard.relative_path
        assert observed["handoff_sha256"] == context.upstream_handoffs[shard.producer["job"]]
        assert observed["attempt_id"] == "attempt_0001" and observed["target_snapshot"] == SNAPSHOT
        assert observed["read"] is True and observed["cited"] is None
    assert any(row["output_kind"] == "artifact_index_summary" for row in records)


@pytest.mark.parametrize("status", ["SUCCEEDED", "COMPLETED_WITH_GAPS"])
def test_real_accepted_built_receipt_retains_exact_image_and_payload_receipt(tmp_path, status):
    context, _, _, _ = prepared(tmp_path, build_status=status)
    admit_inputs(context, set(context.upstream_handoffs))
    with input_read_scope(context) as reads:
        selected = _accepted_inputs(unit(context, "decide.target"), context.config.settings)
    artifact, = selected["artifacts"]
    assert artifact["build_image"] == {"image_id": "sha256:" + "d" * 64, "user": "10001:10001"}
    assert artifact["reference"]["canonical_identity"] == artifact["artifact_identity"]
    receipt, = [row for row in reads.document()["reads"] if row["output_kind"] == "language_build_receipts"]
    assert receipt["handoff_sha256"] == selected["language_build_handoff_sha256"]
    assert receipt["attempt_id"] == "attempt_0001" and receipt["target_snapshot"] == SNAPSHOT


@pytest.mark.parametrize("defect", ["unsupplied", "undeclared", "schema", "authority", "changed-bytes"])
def test_source_payload_refuses_missing_or_changed_admission(tmp_path, defect):
    from appsec_review.runtime.contracts import EvidenceAuthority
    context, decision, source, _ = prepared(tmp_path)
    if defect == "unsupplied":
        context = replace(context, upstream_handoffs={key: value for key, value in context.upstream_handoffs.items()
                                                     if key != "job_target_catalog"})
    elif defect == "undeclared":
        context = replace(context, contract=replace(CONTRACT, inputs=tuple(item for item in CONTRACT.inputs
                                                         if item.output_kind != "source_files")))
    elif defect in {"schema", "authority"}:
        changes = ({"schema": "appsec-review/retrieval-index/999"} if defect == "schema"
                   else {"authority": EvidenceAuthority.REFERENCE})
        context = replace(context, contract=replace(
            CONTRACT, inputs=tuple(replace(item, **changes) if item.output_kind == "source_files"
                                   else item for item in CONTRACT.inputs)))
    else:
        path = context.run_root / source.relative_path
        path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(ValueError):
        with input_read_scope(context):
            _Sources(unit(context, "extract.clang_dwarf"), decision)


def test_debug_loader_observes_only_its_declared_summary_decision_and_raw_evidence(tmp_path):
    from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT as CONSUMER_CONTRACT
    context, _, _, _ = prepared(tmp_path)
    job = build_job(extractor=extractor())
    admit_inputs(context, set(context.upstream_handoffs))
    outputs = {}
    with input_read_scope(context):
        for item in job.units:
            outputs[item.unit_id] = item.handler(unit(context, item.unit_id, outputs))
    refs = [ref(context.run_root, path) for path in (context.attempt_root / "artifacts").rglob("*.json")]
    refs += [ref(context.run_root, context.run_root / item["relative_path"])
             for item in outputs["extract.clang_dwarf"]["indexes"]]
    pin = publish(context, job.job_id, DATASETS, outputs, refs, pins=context.upstream_handoffs)
    context = replace(context, contract=CONSUMER_CONTRACT,
                      config=replace(context.config, job_id="job_review_data_indexing"),
                      upstream_handoffs={job.job_id: pin})
    admit_inputs(context, {job.job_id})
    with input_read_scope(context) as reads:
        result = load_accepted_debug_symbols(context.run_root)
    assert result["record_count"] == 3
    assert {row["output_kind"] for row in reads.document()["reads"]} == {
        "handoff", "debug_symbol_summary", "target_decision", "raw_artifact_refs"}
