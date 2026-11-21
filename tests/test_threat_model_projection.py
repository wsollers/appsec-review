"""Canonical handler output, admitted artifacts, immutable index and retrieval."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from appsec_review.indexing.derive import publish_derived
from appsec_review.indexing.products import ProductContext, product_rule
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.job_review_data_indexing.datasets import CONTRACT as INDEX_CONTRACT
from appsec_review.jobs.job_review_data_indexing.job import threat_model_status
from appsec_review.jobs.job_threat_model_generation import build_job
from appsec_review.jobs.job_threat_model_generation.datasets import ARTIFACT_DIRECTORY, DATASETS
from appsec_review.retrieval import EntityKind, IndexIdentity, RetrievalCore, write_manifest
from appsec_review.runtime.consume import UpstreamIntegrityError
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.threat_model.validate import validate_documents
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_threat_model_generation.test_handlers import (
    ATTEMPT_ID, CATALOG, JOB_ID, PUBLISH, ROOT, RUN_ID, SNAPSHOT, SyntheticAttempt, _build_unit, _entity, _syntax_calls,
)


def _published(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "fsync", lambda _: None)
    attempt = SyntheticAttempt(tmp_path)
    component = _entity(EntityKind.COMPONENT, "component-root", {"component_id": "component-root", "root": "."})
    calls = _syntax_calls()
    sources = [_entity(EntityKind.SOURCE_FILE, path, location=next(
        c.location for c in calls if c.location.path == path)) for path in ("client.c", "server.c")]
    catalog = [attempt.shard(CATALOG, index, "default",
                            [_build_unit()] if index == "build" else [component] if index == "components"
                            else sources if index == "source" else ())
               for index in ("analysis", "build", "components", "documents", "source")]
    attempt.accept(CATALOG, catalog)
    syntax = attempt.accept_syntax(calls)
    execution = build_job().handler(attempt.job_context())
    base = attempt.attempt_root / ARTIFACT_DIRECTORY
    docs = [json.loads((base / name).read_bytes())
            for name in ("dfd.json", "threat-model.json", "evidence.json", "result.json")]
    validate_documents(*docs)
    atomic_json(attempt.attempt_root / "claim.json", {"dataset_contract": dataset_contract(
        JOB_ID, sorted({d.step for d in DATASETS}), DATASETS)})
    handoff = attempt.attempt_root / "handoff.json"
    write_fixture_handoff(attempt.run_root, handoff, {
        "job_id": JOB_ID, "source_fingerprint": SNAPSHOT, "outputs": execution["outputs"],
        "artifacts": list(execution["outputs"][PUBLISH]["artifacts"].values())})
    pin = file_sha256(handoff)
    atomic_json(attempt.run_root / "data" / "jobs" / JOB_ID / "latest.json", {
        "handoff_path": handoff.relative_to(attempt.run_root).as_posix(), "handoff_sha256": pin})
    context = SimpleNamespace(run_root=attempt.run_root, config=SimpleNamespace(job_id="job_review_data_indexing"),
                              upstream_handoffs={**attempt.pins, JOB_ID: pin}, contract=INDEX_CONTRACT,
                              external_input_selection=None)
    with input_read_scope(context) as reads:
        state = threat_model_status(attempt.run_root)
    assert {r["output_kind"] for r in reads.document()["reads"]} >= {
        "generated_dfd", "generated_threat_model", "threat_model_documents"}
    return attempt, docs, state, [*catalog, syntax], component, sources, context


def test_canonical_handler_documents_survive_index_publication_and_retrieval(tmp_path: Path, monkeypatch) -> None:
    attempt, (dfd, model, _, _), state, catalog, component, sources, context = _published(tmp_path, monkeypatch)
    shards = ShardSet(attempt.run_root, [asdict(s) for s in catalog])
    rule = product_rule("threat_boundaries")
    selected = rule.select(shards)
    product = ProductContext(attempt.run_root, SNAPSHOT, shards, {}, {}, {}, 100, rule.version, threat_model=state)
    with input_read_scope(context):
        derived = rule.build(product, selected)
    by_id = {row.payload["result"]["boundary_id"]: row for row in derived.entities}
    assert set(by_id) == {boundary["id"] for boundary in dfd["boundaries"]}
    assert model["threats"] and model["entry_points"]
    schema = json.loads((ROOT / "docs/schemas/indexing/threat-boundary-index.schema.json").read_text())
    for boundary in dfd["boundaries"]:
        row = by_id[boundary["id"]]
        result = row.payload["result"]
        jsonschema.validate(result, schema)
        assert result["element_ids"] == boundary["inside"]
        assert result["component_ids"] == ["component-root"]
        expected = {t["id"] for t in model["threats"] if boundary["id"] in t["boundary_ids"]}
        assert {t["threat_id"] for t in result["threats"]} == expected
        assert {e["entry_point_id"] for e in result["entry_points"]} == {
            e["id"] for e in model["entry_points"] if e["process"] in boundary["inside"]}
        assert result["authority"] == "routing_context"
        assert {t["severity"] for t in result["threats"]} <= {"unspecified"}
        assert result["source_paths"]
        targets = {r.target_id for r in derived.relations if r.source_id == row.identity.value}
        assert component.identity.value in targets
        assert any(source.identity.value in targets for source in sources)
    assert not any("unassigned_threat" in gap for gap in derived.gaps)
    published = publish_derived(
        attempt.run_root, index="precomputed", shard_id="precomputed-threat_boundaries",
        job_id="job_review_data_indexing", unit_id="precompute.threat_boundaries",
        rule=rule.query_set, rule_version=rule.version, snapshot=SNAPSHOT,
        producer={"query_set": rule.query_set},
        inputs={"generated": state["handoff_sha256"], "shards": ShardSet.identities(selected)}, build=lambda: derived)
    index = IndexIdentity(**published["index_identity"])
    manifest = attempt.run_root / "data" / "indices" / "manifests" / "threat-projection.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT,
                   target_root=attempt.run_root.parent / "target", indexes=[*catalog, index])
    handoff = attempt.run_root / "data" / "jobs" / "fixture" / "attempts" / ATTEMPT_ID / "handoff.json"
    write_fixture_handoff(attempt.run_root, handoff, {
        "job_id": "fixture", "source_fingerprint": SNAPSHOT,
        "artifacts": [artifact_ref(attempt.run_root, manifest)], "outputs": {}})
    atomic_json(attempt.run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(attempt.run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": manifest.relative_to(attempt.run_root).as_posix(), "manifest_sha256": file_sha256(manifest)})
    core = RetrievalCore(attempt.run_root.parent, RUN_ID)
    for bid, row in by_id.items():
        returned, = core.query_threat_boundaries(boundary_id=bid)["results"]
        assert returned["payload"]["result"] == row.payload["result"]
        assert core.query_threat_boundaries(
            boundary_id=bid, path=row.payload["result"]["source_paths"][0])["results"]
        assert core.query_threat_boundaries(boundary_id=bid, subject=component.identity.value)["results"]


def test_source_ownership_requires_digest_and_citations_require_admitted_shards(tmp_path: Path, monkeypatch) -> None:
    attempt, _, state, catalog, _, sources, context = _published(tmp_path, monkeypatch)
    wrong_sources = [replace(s, location=replace(s.location, file_sha256="d" * 64)) for s in sources]
    replacement = attempt.shard(CATALOG, "source", "default", wrong_sources)
    # Publish a catalog without the original source bytes, and do not supply syntax to indexing.
    retained = [s for s in catalog if s.producer["job"] == CATALOG and s.name != "source"]
    attempt.accept(CATALOG, [*retained, replacement], attempt_id="attempt_0002")
    context.upstream_handoffs = {**context.upstream_handoffs, CATALOG: attempt.pins[CATALOG]}
    shards = ShardSet(attempt.run_root, [asdict(s) for s in (*retained, replacement)])
    rule = product_rule("threat_boundaries")
    product = ProductContext(attempt.run_root, SNAPSHOT, shards, {}, {}, {}, 100, rule.version, threat_model=state)
    with input_read_scope(context):
        derived = rule.build(product, rule.select(shards))
    assert all(row.payload["result"]["source_paths"] for row in derived.entities)
    assert not {s.identity.value for s in wrong_sources} & {r.target_id for r in derived.relations}
    assert not any(r.target_id.startswith("asr:ast_node:") for r in derived.relations)
    assert any("citation_unavailable:" in gap for gap in derived.gaps)


def test_schema_valid_threat_membership_is_retained_in_every_declared_boundary(tmp_path: Path) -> None:
    from tests.test_threat_model_documents import documents, plains

    dfd, model, evidence, result = plains(documents())
    threat = model["threats"][0]
    boundary_ids = sorted(b["id"] for b in dfd["boundaries"])[:2]
    assert len(boundary_ids) == 2
    threat["boundary_ids"] = boundary_ids
    validate_documents(dfd, model, evidence, result)
    rule = product_rule("threat_boundaries")
    shards = ShardSet(tmp_path, ())
    context = ProductContext(tmp_path, SNAPSHOT, shards, {}, {}, {}, 100, rule.version,
                             threat_model={"status": "accepted", "dfd": dfd, "threat_model": model})
    derived = rule.build(context, ())
    for boundary_id in boundary_ids:
        row, = [r.payload["result"] for r in derived.entities if r.payload["result"]["boundary_id"] == boundary_id]
        assert threat["id"] in {t["threat_id"] for t in row["threats"]}


def test_admitted_generated_artifact_tampering_is_not_projection_absence(tmp_path: Path, monkeypatch) -> None:
    attempt, _, _, _, _, _, context = _published(tmp_path, monkeypatch)
    path = attempt.attempt_root / ARTIFACT_DIRECTORY / "threat-model.json"
    path.write_bytes(path.read_bytes() + b" ")
    with input_read_scope(context), pytest.raises((UpstreamIntegrityError, ValueError)):
        threat_model_status(attempt.run_root)
