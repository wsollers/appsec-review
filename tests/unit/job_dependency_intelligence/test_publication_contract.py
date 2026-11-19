"""Admission and immutable SCA publication regressions (T-5127/T-5128)."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from appsec_review.jobs.job_dependency_intelligence import build_job
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import UnitContext
from appsec_review.runtime.consume import accepted_upstream
from appsec_review.runtime.inputs import admit_inputs, input_read_scope
from appsec_review.storage import atomic_bytes, canonical_json, file_sha256
from appsec_review.storage.shared import reference
from tests.unit.job_dependency_intelligence.test_job_graph import (
    _framework, _make_job_context, _owner_scope, _seed_upstreams,
)
from tests.unit.job_dependency_intelligence.test_sca_reachability import _build_osv_sqlite, _pin


_REQUIRED = (
    "job_artifact_indexing", "job_evidence_collection", "job_language_build", "job_target_catalog",
)
_PUBLICATIONS = (
    ("job_artifact_indexing", "artifact_index_summary", "acceptance.publish_handoff",
     "artifacts/artifact-indexing/summary.json"),
    ("job_language_build", "language_build_receipts", "acceptance.publish_handoff",
     "artifacts/language-build/receipts.json"),
    ("job_target_catalog", "catalog_documents", "publish_catalog.publish_handoff",
     "artifacts/catalog/catalog.json"),
)


def _context(tmp_path, *, missing_publication=None):
    target = tmp_path / "target"
    ctx, root, _ = _make_job_context(tmp_path, target_root=target)
    ctx = replace(ctx, evidence_target_snapshot=ctx.source_fingerprint,
                  config=replace(ctx.config, settings={
                      **ctx.config.settings,
                      "model": {**ctx.config.settings["model"], "enabled": False},
                      "native_inference": {**ctx.config.settings["native_inference"], "enabled": False},
                  }))
    _seed_upstreams(
        root, target, files={"app.py": b"import demo\nx = demo.unsafe()\n"},
        declared_dependencies=[{
            "name": "demo", "version": "1.0.0", "purl": "pkg:pypi/demo@1.0.0",
            "ecosystem": "pypi", "path": "requirements.txt",
        }],
        observations=[], source_syft=False, language_gaps=["native build unavailable"],
    )
    # Retain fixture payloads under their producer's real dataset publication patterns.
    for producer, kind, output_id, relative in _PUBLICATIONS:
        accepted = accepted_upstream(root, producer)
        outputs = dict(accepted.handoff["outputs"])
        original = outputs[output_id]["artifact"]
        artifacts = [ref for ref in accepted.handoff["artifacts"] if ref != original]
        if kind == missing_publication:
            outputs = {}
        else:
            path = root / "data" / "jobs" / producer / "attempts" / "attempt_0002" / relative
            atomic_bytes(path, (root / original["path"]).read_bytes())
            artifact = reference(root, path)
            outputs[output_id] = {**outputs[output_id], "artifact": artifact}
            artifacts.append(artifact)
        if producer == "job_target_catalog":
            indexes = []
            for name in ("source", "analysis", "components", "documents", "build"):
                path = root / "data" / "indices" / f"catalog-{name}.sqlite"
                builder = IndexBuilder(path, name=name, fingerprint="a" * 64,
                                       target_snapshot=ctx.source_fingerprint)
                unit_id = f"{'publish_catalog' if name == 'build' else 'retrieval_indexes'}.{name}"
                indexes.append(IndexIdentity(
                    name, "appsec-review/retrieval-index/2", builder.build(), "a" * 64,
                    path.relative_to(root).as_posix(), {"job": producer, "unit": unit_id}, ()))
                outputs[unit_id] = {"index_identity": asdict(indexes[-1])}
                artifacts.append(reference(root, path))
            path = root / "data" / "indices" / "catalog-manifest.json"
            write_manifest(path, run_id=ctx.run_id, target_snapshot=ctx.source_fingerprint,
                           target_root=target, indexes=tuple(indexes))
            manifest = reference(root, path)
            artifacts.append(manifest)
            outputs["retrieval_indexes.publish_indexes"] = {"index_manifest": manifest}
        _framework(root, producer, outputs, artifacts, attempt="attempt_0002")
    pins = {producer: accepted_upstream(root, producer).sha256 for producer in _REQUIRED}
    ctx = replace(ctx, upstream_handoffs=pins,
                  tools=replace(ctx.tools, enable_native_advisory_lookup=False))
    return ctx


def _unit(ctx, unit_id, outputs):
    step, task = unit_id.split(".")
    path = ctx.attempt_root / "steps" / step / "tasks" / task
    path.mkdir(parents=True, exist_ok=True)
    return UnitContext(ctx, unit_id, step, task, path, outputs)


@pytest.mark.parametrize("producer", _REQUIRED)
def test_missing_required_envelope_is_rejected_before_loading(tmp_path, producer):
    ctx = _context(tmp_path)
    ctx = replace(ctx, upstream_handoffs={
        name: digest for name, digest in ctx.upstream_handoffs.items() if name != producer
    })
    # An available pointer must not substitute for an unadmitted/disabled prerequisite.
    with pytest.raises(ValueError, match=f"required input unavailable: {producer}/handoff"):
        admit_inputs(ctx, set())


@pytest.mark.parametrize("producer,kind", [(row[0], row[1]) for row in _PUBLICATIONS])
def test_missing_required_publication_is_rejected_before_loading(tmp_path, producer, kind):
    ctx = _context(tmp_path, missing_publication=kind)
    with pytest.raises(ValueError, match=f"required input unavailable: {producer}/{kind}"):
        admit_inputs(ctx, set())


def test_optional_scopes_and_partial_build_allow_catalog_discovery(tmp_path):
    ctx = _context(tmp_path)
    admission = admit_inputs(ctx, set())
    assert all(not row["read"] for row in admission["requirements"])
    job = build_job()
    with _owner_scope(ctx), input_read_scope(ctx) as reads:
        loaded = job.units[0].handler(_unit(ctx, "inputs.load_accepted", {}))
        discovery = job.units[1].handler(_unit(
            ctx, "resolution.detect_dependencies", {"inputs.load_accepted": loaded}))
    envelopes = {row["producer"]: row for row in reads.document()["reads"]
                 if row["output_kind"] == "handoff"}
    assert set(envelopes) == set(_REQUIRED)
    assert all(row["handoff_sha256"] == ctx.upstream_handoffs[name]
               for name, row in envelopes.items())
    assert loaded["receipts"] == [] and loaded["native_artifacts"] == []
    assert loaded["source_syft"] is None
    assert loaded["native_files"][0]["path"] == "app.py"
    assert any(gap["kind"] == "input_missing" for gap in discovery["gaps"])
    assert any("native build unavailable" in gap["detail"] for gap in discovery["gaps"])
    assert discovery["terminal_status"] == "COMPLETED_WITH_GAPS"


def _snapshot(tmp_path, *, matching=True, summary="first"):
    database = tmp_path / "osv.sqlite"
    _build_osv_sqlite(database, [{
        "id": "GHSA-demo-0001", "summary": summary,
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "demo"},
            "versions": ["1.0.0" if matching else "2.0.0"],
            "ecosystem_specific": {"imports": [{"path": "demo", "symbols": ["unsafe"]}]},
        }],
    }])
    return _pin(tmp_path / "feed", database)


def _publish(ctx, outputs, snapshot):
    selection = {"inputs": [{
        "producer": "job_third_party_data_sync", "output_kind": "feed_snapshot",
        "schema": "appsec-review/public-feed-use/1", "status": "available",
        "identity": {key: snapshot[key] for key in ("feed_id", "snapshot_id", "manifest_sha256")},
    }] if snapshot else []}
    ctx = replace(ctx, external_input_selection=selection)
    handler = next(unit.handler for unit in build_job(osv_snapshot=snapshot).units
                   if unit.unit_id == "publication.publish_context")
    with input_read_scope(ctx) as reads:
        result = handler(_unit(ctx, "publication.publish_context", outputs))
    observed = reads.document()["reads"]
    assert any(row["producer"] == "job_evidence_collection" and row["read"] for row in observed)
    if snapshot:
        assert any(row.get("snapshot_id") == snapshot["snapshot_id"]
                   and row.get("manifest_sha256") == snapshot["manifest_sha256"] for row in observed)
    manifest = result["index_manifest"]
    load_verified_manifest(ctx.run_root, ctx.run_root / manifest["path"], manifest["sha256"])
    document = json.loads((ctx.run_root / result["sca_reachability"]["path"]).read_bytes())
    index = ctx.run_root / result["index_identity"]["relative_path"]
    with sqlite3.connect(f"file:{index.as_posix()}?mode=ro&immutable=1", uri=True) as db:
        signals = [json.loads(row[0]) for row in db.execute(
            "SELECT payload_json FROM entities WHERE kind = 'review_signal'")]
    assert sorted(signals, key=canonical_json) == sorted(
        [{"signal_kind": "sca_reachability", **row} for row in document["advisories"]],
        key=canonical_json)
    return result, document


@pytest.mark.parametrize("change", ("advisories", "snapshot", "settings", "reachability", "unavailable"))
def test_inventory_identity_binds_sca_result_snapshot_and_settings(tmp_path, change):
    ctx = _context(tmp_path)
    outputs = {}
    with _owner_scope(ctx):
        for unit in build_job().units:
            if unit.unit_id == "publication.publish_context":
                break
            outputs[unit.unit_id] = unit.handler(_unit(ctx, unit.unit_id, outputs))
    snapshot = _snapshot(tmp_path / "first")
    first, first_doc = _publish(ctx, outputs, snapshot)
    assert first_doc["advisories"][0]["reachability"] == "symbol_reachable"
    assert first_doc["advisories"][0]["call_sites"][0]["file_sha256"] == file_sha256(ctx.target_root / "app.py")
    original = ctx.run_root / first["index_identity"]["relative_path"]
    original_bytes = original.read_bytes()
    repeated, _ = _publish(ctx, outputs, snapshot)
    assert repeated["index_identity"] == first["index_identity"]
    if change in {"advisories", "snapshot"}:
        snapshot = _snapshot(tmp_path / "second", matching=change != "advisories", summary="second")
    elif change == "unavailable":
        snapshot = None
    else:
        settings = {**ctx.config.settings, **(
            {"max_call_sites_per_advisory": 7} if change == "settings" else {"reachability_enabled": False})}
        ctx = replace(ctx, config=replace(ctx.config, settings=settings))
    second, second_doc = _publish(ctx, outputs, snapshot)
    assert second["index_identity"]["fingerprint"] != first["index_identity"]["fingerprint"]
    assert second["index_identity"]["relative_path"] != first["index_identity"]["relative_path"]
    assert original.read_bytes() == original_bytes
    if change == "advisories":
        assert second_doc["advisories"] == []
    elif change == "snapshot":
        assert second_doc["advisories"] == first_doc["advisories"]
        assert second_doc["osv_snapshot"] != first_doc["osv_snapshot"]
    elif change == "settings":
        assert second_doc == first_doc
    elif change == "unavailable":
        assert second_doc["advisories"] == []
        assert "osv_snapshot_not_admitted" in second_doc["gaps"]
        assert second["terminal_status"] == "COMPLETED_WITH_GAPS"
    else:
        assert second_doc["advisories"][0]["reachability"] == "unknown"
        assert second_doc["gaps"]
        assert second["terminal_status"] == "COMPLETED_WITH_GAPS"
    repeated, _ = _publish(ctx, outputs, snapshot)
    assert repeated["index_identity"] == second["index_identity"]
