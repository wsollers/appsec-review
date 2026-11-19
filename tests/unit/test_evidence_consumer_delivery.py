"""Real publication, canonical runner projection and bounded downstream readers."""

from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_document_issue_analysis import job as documents
from appsec_review.jobs.job_document_issue_analysis.datasets import CONTRACT as DOCUMENT_CONTRACT, DATASETS as DOCUMENT_DATASETS
from appsec_review.jobs.job_inference_security_review import job as inference
from appsec_review.jobs.job_inference_security_review.datasets import CONTRACT as INFERENCE_CONTRACT
from appsec_review.jobs.job_evidence_collection import job as scanners
from appsec_review.jobs.job_evidence_collection.datasets import CONTRACT as SCANNER_CONTRACT, DATASETS
from appsec_review.jobs.job_evidence_collection.evidence import corroborate_sast_records
from appsec_review.jobs.job_review_prioritization.composite import _collect_sast_spans
from appsec_review.jobs.job_review_prioritization.datasets import CONTRACT as PRIORITY_CONTRACT
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore, SourceLocation, write_manifest,
)
from appsec_review.retrieval.core import materialize_attempt_input_manifest
from appsec_review.review.packages import PackageSettings, assemble_packages
from appsec_review.review.package_view import ViewLimits, build_view
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime import UnitContext
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import reference
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_document_issue_analysis.test_handlers import (
    _make_job_context, _seed_document_hunt_run,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIG = load_config(ROOT / "appsec-review.toml")


def canonical_handoff(context, outputs, datasets, contract, artifacts=()):
    """Use the runner's actual closed control projection, not a copied field allowlist."""
    root, attempt = context.run_root, context.attempt_root
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(context.config.job_id, tuple(context.config.steps), datasets,
                                             job_contract=contract.document()),
    })
    path = attempt / "handoff.json"
    write_fixture_handoff(root, path, {
        "job_id": context.config.job_id, "attempt_id": context.attempt_id,
        "outputs": outputs, "target_snapshot": context.source_fingerprint, "artifacts": list(artifacts),
        "completion_status": "COMPLETED_WITH_GAPS",
    })
    prior = json.loads(path.read_text())
    claim = json.loads((attempt / "claim.json").read_text())
    claim.update(component_identities={"implementation": "unit/1", "schema": "unit/1", "validation": "unit/1"},
                 started_at=prior["started_at"], job_config_sha256=prior["job_config_sha256"])
    result = {"status": "COMPLETED_WITH_GAPS", "outputs": outputs}
    handoff = JobRunner(CONFIG)._handoff_document(
        context, claim, result, json.loads((attempt / "outcomes.json").read_text()), prior["outcomes"],
        accepted=True, completed=prior["completed_at"], artifacts=prior["artifacts"])
    atomic_json(path, handoff)
    pin = reference(root, path)
    atomic_json(attempt.parent.parent / "latest.json",
                {"handoff_path": pin["path"], "handoff_sha256": pin["sha256"]})
    return handoff, pin


def scanner_publication(tmp_path, *, partial=False, missing=False, observation=False, missing_domain=False):
    root = tmp_path / "runs" / "2026-11-19-5135"
    job = scanners.build_job()
    attempt = root / "data/jobs/job_evidence_collection/attempts/attempt_0001"
    context = SimpleNamespace(run_root=root, run_id=root.name, attempt_id="attempt_0001",
                              attempt_root=attempt, config=CONFIG.job(job.job_id),
                              source_fingerprint="target-sha256:" + "8" * 64)
    document = corroborate_sast_records({"tool-semgrep": {"records": [{
        "category": "source_sast", "native_rule_id": "unsafe-call", "severity": "HIGH",
        "message": "untrusted input", "location": {
            "path": "app.py", "start_line": 4, "end_line": 6, "file_sha256": "a" * 64},
    }]}}, target_fingerprint=context.source_fingerprint)
    path = attempt / "steps/evidence_publication/tasks/assemble_manifest/corroborated-sast-evidence.json"
    atomic_json(path, document)
    corr = reference(root, path)
    identities = []
    if observation:
        shard_path = root / "data/indices/observations/semgrep/fixture.sqlite"
        builder = IndexBuilder(shard_path, name="observations", shard_id="semgrep",
                               fingerprint="f" * 64, target_snapshot=context.source_fingerprint)
        if observation != "empty":
            builder.add_entity(EntityRecord(
                LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, context.source_fingerprint, {"rule": "fallback"}),
                "fallback", "fallback", "fallback", {"category": "source_sast", "severity": "HIGH"},
                SourceLocation(context.source_fingerprint, "fallback.py", "b" * 64,
                               0, 10, 2, 2, 1, 5, {}, "exact", 1.0)))
        builder.add_coverage("semgrep", "complete", None)
        sha = builder.build()
        identities.append(IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, "f" * 64,
                                        shard_path.relative_to(root).as_posix(),
                                        {"job": job.job_id, "producer": "tool-semgrep"}, (), "semgrep"))
    manifest = attempt / "indices.json"
    write_manifest(manifest, run_id=root.name, target_snapshot=context.source_fingerprint,
                   target_root=tmp_path, indexes=identities)
    output = {"shards": [asdict(item) for item in identities], "dispositions": [
        {"tool_id": "tool-semgrep", "terminal_status": "PARTIAL" if partial else "SUCCEEDED"}],
        "gaps": ["native scanner coverage incomplete"] if partial else [],
        "corroborated_sast_evidence": None if missing else corr, "telemetry": document["telemetry"],
        "item_count": 1, "index_manifest": reference(root, manifest)}
    unit_id = "evidence_publication.publish_handoff"
    unit = UnitContext(context, unit_id, "evidence_publication", "publish_handoff",
                       attempt / "steps/evidence_publication/tasks/publish_handoff",
                       {"evidence_publication.assemble_manifest": output})
    published = next(item for item in job.units if item.unit_id == unit_id).handler(unit)
    if missing_domain:
        published = {key: value for key, value in published.items() if key != "artifact"}
    handoff, pin = canonical_handoff(context, {
        "evidence_publication.assemble_manifest": output, unit_id: published,
    }, DATASETS, SCANNER_CONTRACT,
        [reference(root, root / item.relative_path) for item in identities])
    consumer = SimpleNamespace(run_root=root, config=CONFIG.job("job_review_prioritization"),
                               contract=PRIORITY_CONTRACT,
                               upstream_handoffs={job.job_id: pin["sha256"]})
    return context, consumer, published, handoff, corr


@pytest.mark.parametrize("partial", [False, True])
def test_scanner_corroboration_survives_real_control_projection(tmp_path, partial):
    context, consumer, published, handoff, corr = scanner_publication(tmp_path, partial=partial)
    assert "corroborated_sast_evidence" not in handoff["outputs"]["evidence_publication.publish_handoff"]
    with input_read_scope(consumer) as reads:
        spans = _collect_sast_spans(context.run_root, {}, {"semgrep": True})
    assert spans == {"app.py": [(4, 6)]}
    receipts = reads.document()["reads"]
    for kind, artifact in (("static_tool_evidence", published["artifact"]), ("corroborated_sast_evidence", corr)):
        assert any(row["output_kind"] == kind and row["sha256"] == artifact["sha256"]
                   and row["read"] and row["handoff_sha256"] == consumer.upstream_handoffs["job_evidence_collection"]
                   for row in receipts)


@pytest.mark.parametrize("artifact_kind", ["domain", "corroboration"])
def test_scanner_payload_tampering_is_not_silently_dropped(tmp_path, artifact_kind):
    context, consumer, published, _handoff, corr = scanner_publication(tmp_path)
    artifact = published["artifact"] if artifact_kind == "domain" else corr
    (context.run_root / artifact["path"]).write_text("{}")
    with pytest.raises(ValueError), input_read_scope(consumer):
        _collect_sast_spans(context.run_root, {}, {"semgrep": True})


@pytest.mark.parametrize("observation", ["populated", "empty"])
def test_missing_corroboration_keeps_observation_fallback_and_receipts(tmp_path, observation):
    context, consumer, _published, _handoff, _corr = scanner_publication(tmp_path, missing=True, observation=observation)
    with input_read_scope(consumer) as reads:
        assert _collect_sast_spans(context.run_root, {}, {"semgrep": True}) == (
            {} if observation == "empty" else {"fallback.py": [(2, 2)]})
    assert any(row["output_kind"] == "static_tool_observations" and row["read"]
               for row in reads.document()["reads"])


def document_publication(tmp_path, *, max_records=20000):
    root, target, snapshot, manifest, sha, _packages, _pin = _seed_document_hunt_run(tmp_path)
    context = _make_job_context(root, target, source_fingerprint=snapshot, manifest_path=manifest,
                                manifest_sha=sha, max_source_files=max_records)
    result = documents.build_job().handler(context)
    output = result["outputs"]["analysis.map_and_adjudicate"]
    handoff, pin = canonical_handoff(context, result["outputs"], DOCUMENT_DATASETS, DOCUMENT_CONTRACT)
    upstream = {documents.JOB_ID: pin["sha256"]}
    original = json.loads(manifest.read_text())
    from appsec_review.jobs.job_target_catalog.datasets import DATASETS as CATALOG_DATASETS, CONTRACT as CATALOG_CONTRACT
    from appsec_review.jobs.job_review_data_indexing.datasets import DATASETS as INDEX_DATASETS, CONTRACT as INDEX_CONTRACT
    for job_id, datasets, contract in (
        ("job_target_catalog", CATALOG_DATASETS, CATALOG_CONTRACT),
        ("job_review_data_indexing", INDEX_DATASETS, INDEX_CONTRACT),
    ):
        ctx = replace(context, config=CONFIG.job(job_id),
                      attempt_root=root / "data/jobs" / job_id / "attempts/attempt_0001")
        artifacts = [reference(root, root / row["relative_path"]) for row in original["indexes"]
                     if row["producer"]["job"] == job_id]
        _, upstream_pin = canonical_handoff(ctx, {"publication.fixture": {}}, datasets, contract, artifacts)
        upstream[job_id] = upstream_pin["sha256"]
    return context, output, handoff, upstream


def test_document_producer_publishes_queryable_late_input(tmp_path):
    context, output, handoff, pins = document_publication(tmp_path)
    root = context.run_root
    assert "drift_artifact" not in handoff["outputs"]["analysis.map_and_adjudicate"]
    published = output["index_manifest"]
    consumer = replace(context, config=CONFIG.job(inference.JOB_ID), contract=INFERENCE_CONTRACT,
                       attempt_root=root / "data/jobs" / inference.JOB_ID / "attempts/attempt_0001",
                       upstream_handoffs=pins)
    path, sha = materialize_attempt_input_manifest(
        run_root=root, attempt_root=consumer.attempt_root, run_id=root.name,
        target_snapshot=context.source_fingerprint, target_root=context.target_root, upstream_handoffs=pins)
    assert path == root / published["path"]
    consumer = replace(consumer, input_manifest_path=path, input_manifest_sha256=sha)
    with input_read_scope(consumer) as reads:
        core = RetrievalCore(root.parent, root.name, manifest_path=path, manifest_sha256=sha)
        response = core.query_doc_drift(path="backend/orders.ts")
        scope_unit = next(unit for unit in inference.build_job().units if unit.unit_id == "scope.accept_manifest")
        unit = UnitContext(consumer, scope_unit.unit_id, "scope", "accept_manifest",
                           consumer.attempt_root / "steps/scope/tasks/accept_manifest", {})
        admitted = scope_unit.handler(unit)
        scope = accept_manifest(root, manifest_path=path, manifest_sha256=sha)
        assembly = assemble_packages(scope, PackageSettings(), document_navigation=True)
    assert len(response["results"]) == 1
    lead = response["results"][0]
    assert lead["drift_kind"] == "missing_auth_middleware"
    assert lead["payload"]["result"]["authority"] == "provisional_navigation_lead"
    assert response["coverage_gaps"]
    result = lead["payload"]["result"]
    assert core.query_doc_drift(subject=result["spec_source_id"])["results"][0]["identity"] == lead["identity"]
    assert result["payload_artifact"]["sha256"] == output["drift_artifact"]["sha256"]
    assert "path" not in result["payload_artifact"]  # existing raw-artifact custody stays closed
    assert result["accepted_manifest_sha256"] == context.input_manifest_sha256
    assert {result["handler_path"], result["spec_path"]} == {"backend/orders.ts", "api/openapi.yaml"}
    assert {core.find(identity=row["identity"], limit=1)["results"][0]["location"]["path"]
            for row in result["source_evidence"]} == {"backend/orders.ts", "api/openapi.yaml"}
    assert all(row["shard_sha256"] and row["location"]["file_sha256"] for row in result["source_evidence"])
    assert admitted["manifest_sha256"] == sha
    assert any(row["output_kind"] == "document_navigation" and row["authority"] == "provisional"
               and row["handoff_sha256"] == pins[documents.JOB_ID] and row["read"]
               for row in reads.document()["reads"])
    hunts = [package for package in assembly.packages if package.kind == "hunt"]
    assert hunts and not any(package.kind == "finding_lead" for package in assembly.packages)
    package = next(package for package in hunts if lead["identity"] in package.resolved()["retrieval"]["entity_ids"])
    assert all(not entry.get("control_assessment") for entry in package.resolved()["context"]
               if entry["id"] == lead["identity"])
    view = build_view(package.resolved(), core, ViewLimits())
    text = json.dumps(view.files)
    assert "provisional_navigation_lead" in text
    assert "missing_auth_middleware" in text
    mappings = [row["payload"]["result"] for row in core.query_precomputed(
        query_set="document_context")["results"] if row["payload"].get("fact_type") == "document_mapping"]
    assert mappings and all(row["state"] == "insufficient_evidence" for row in mappings)
    assert any(row["document_evidence"] and row["source_evidence"] for row in mappings)
    bounded = assemble_packages(scope, replace(PackageSettings(), max_context_entries=1), document_navigation=True)
    assert any("provisional document records not admitted" in gap.reason for gap in bounded.gaps)


@pytest.mark.parametrize("missing", [False, True])
def test_indexing_reads_domain_dispositions_not_stripped_assembly_fields(tmp_path, missing):
    from appsec_review.jobs.job_review_data_indexing import job as indexing
    from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT as INDEX_CONTRACT, DATASETS as INDEX_DATASETS
    from appsec_review.retrieval.index import load_verified_manifest
    context, _consumer, published, handoff, _corr = scanner_publication(
        tmp_path, partial=True, observation=True, missing_domain=missing)
    assert "dispositions" not in handoff["outputs"]["evidence_publication.assemble_manifest"]
    config = CONFIG.job(indexing.JOB_ID)
    base = _make_job_context(
        context.run_root, tmp_path, source_fingerprint=context.source_fingerprint,
        manifest_path=context.run_root / published["index_manifest"]["path"],
        manifest_sha=published["index_manifest"]["sha256"])
    attempt = context.run_root / "data/jobs" / indexing.JOB_ID / "attempts/attempt_0001"
    pin = file_sha256(context.attempt_root / "handoff.json")
    consumer = replace(base, config=config, contract=INDEX_CONTRACT, attempt_root=attempt, repository_root=tmp_path,
                       upstream_handoffs={"job_evidence_collection": pin})
    atomic_json(attempt / "claim.json", {
        "schema": "appsec-review/attempt-claim/1", "run_id": consumer.run_id,
        "job_id": indexing.JOB_ID, "attempt_id": consumer.attempt_id,
        "orchestration": dict(consumer.orchestration),
        "attempt_path": attempt.relative_to(context.run_root).as_posix(),
        "dataset_contract": dataset_contract(indexing.JOB_ID, tuple(config.steps), INDEX_DATASETS),
    })
    job = indexing.build_job()
    manifest, _ = load_verified_manifest(
        context.run_root, context.run_root / published["index_manifest"]["path"],
        published["index_manifest"]["sha256"])
    inputs = attempt / "steps/load/tasks/accepted_inputs/accepted-inputs.json"
    atomic_json(inputs, {
        "schema": "appsec-review/review-data-indexing-inputs/2",
        "target_snapshot": manifest["target_snapshot"], "accepted_manifest": published["index_manifest"],
        "shards": manifest["indexes"], "restored_shards": [], "feeds": {}, "owasp": {},
    })
    # Scanner correlation needs these verified observations, not repository-wide feed discovery or link products.
    outputs = {"load.accepted_inputs": {"artifact": reference(context.run_root, inputs)},
               "links.cross_domain": {"links": []}}
    unit_id = "precompute.scanner_correlation"
    unit = UnitContext(consumer, unit_id, "precompute", "scanner_correlation",
                       attempt / "steps/precompute/tasks/scanner_correlation", outputs)
    with input_read_scope(consumer) as reads:
        output = next(item for item in job.units if item.unit_id == unit_id).handler(unit)
    assert output["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert output["counts"]["source_sast_observations"] == output["counts"]["lead_facts"] == 1
    receipts = reads.document()["reads"]
    assert any(row["output_kind"] == "static_tool_observations" and row["read"]
               and row["sha256"] == manifest["indexes"][0]["sha256"]
               and row["handoff_sha256"] == pin for row in receipts)
    if missing:
        assert any("scanner dispositions are unknown" in gap for gap in output["gaps"])
        assert not any(row["output_kind"] == "static_tool_evidence" for row in receipts)
    else:
        assert any("scanner tool-semgrep: PARTIAL" in gap for gap in output["gaps"])
        assert "native scanner coverage incomplete" in output["gaps"]
        assert any(row["output_kind"] == "static_tool_evidence"
                   and row["sha256"] == published["artifact"]["sha256"]
                   and row["read"] and row["handoff_sha256"] == pin for row in receipts)


def test_document_context_without_drift_is_an_explicit_coverage_gap(tmp_path):
    root, _target, _snapshot, manifest, sha, _packages, _pin = _seed_document_hunt_run(tmp_path)
    core = RetrievalCore(root.parent, root.name, manifest_path=manifest, manifest_sha256=sha)
    response = core.query_doc_drift()
    assert response["results"] == []
    assert any("drift projection is unavailable" in gap for gap in response["coverage_gaps"])
    scope = accept_manifest(root, manifest_path=manifest, manifest_sha256=sha)
    assembly = assemble_packages(scope, document_navigation=True)
    assert any(gap.producer == documents.JOB_ID and gap.state == "missing" for gap in assembly.gaps)


def test_document_projection_cap_and_unmapped_gaps_survive(tmp_path):
    context, output, _handoff, _pins = document_publication(tmp_path, max_records=1)
    core = RetrievalCore(context.run_root.parent, context.run_id,
                         manifest_path=context.run_root / output["index_manifest"]["path"],
                         manifest_sha256=output["index_manifest"]["sha256"])
    response = core.query_doc_drift(limit=1)
    assert len(response["results"]) == 1
    assert any("projection truncated" in gap for gap in response["coverage_gaps"])


@pytest.mark.parametrize("artifact_kind", ["shard", "manifest"])
def test_document_projection_tampering_fails_closed(tmp_path, artifact_kind):
    context, output, _handoff, _pins = document_publication(tmp_path)
    path = (output["index_identity"]["relative_path"] if artifact_kind == "shard"
            else output["index_manifest"]["path"])
    (context.run_root / path).write_bytes(b"changed")
    with pytest.raises(ValueError):
        RetrievalCore(context.run_root.parent, context.run_id,
                      manifest_path=context.run_root / output["index_manifest"]["path"],
                      manifest_sha256=output["index_manifest"]["sha256"])
