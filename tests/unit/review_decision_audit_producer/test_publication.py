from dataclasses import replace
import hashlib
import json
import os

import pytest

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.projection import policy_sha256
from appsec_review.review.decision_audit.publication import (
    AuditUnavailable, BoundReader, _write, audit_directory, publish_bundle, publish_descriptor,
)
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json

from .helpers import ATTEMPT, digest, document, fixture, reference


def test_real_publication_and_idempotent_no_replace(tmp_path):
    f = fixture(tmp_path)
    ref = f.publish()
    before = {path: path.read_bytes() for path in (f.root / f.directory).rglob("*") if path.is_file()}
    assert f.publish() == ref
    assert {path: path.read_bytes() for path in (f.root / f.directory).rglob("*") if path.is_file()} == before
    manifest = c.from_document(json.loads((f.root / ref.path).read_bytes()), expected_origin=f.inputs.origin)
    shards = {shard.path: tuple(c.from_document(json.loads(line), expected_origin=f.inputs.origin)
                               for line in (f.root / shard.path).read_bytes().splitlines()) for shard in manifest.shards}
    c.validate_bundle(manifest, shards, expected_origin=f.inputs.origin, manifest_reference=ref)
    assert len(shards) == 3
    assert not list((f.root / f.directory).glob(".audit-*"))


@pytest.mark.parametrize("target", ["handoff", "ledger", "projection", "adjudications", "scores", "triage"])
def test_tampered_accepted_source_fails_loudly(tmp_path, target):
    f = fixture(tmp_path)
    path = f.root / getattr(f.refs, target)["path"]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(IntegrityError):
        f.publish()
    assert not (f.root / f.directory / "manifest.json").exists()


@pytest.mark.parametrize("where", ["file", "parent", "attempt", "root"])
def test_symlink_custody_is_rejected(tmp_path, where):
    f = fixture(tmp_path)
    if where == "file":
        path = f.root / f.refs.triage["path"]
        other = path.with_suffix(".original")
    elif where == "parent":
        path = f.root / "data/indices"
        other = f.root / "data/original-indices"
    elif where == "attempt":
        path, other = f.attempt, f.attempt.with_name("original-attempt")
    else:
        path, other = f.root, f.root.with_name("original-run")
    path.rename(other)
    path.symlink_to(other, target_is_directory=other.is_dir())
    with pytest.raises(IntegrityError):
        f.publish()


@pytest.mark.parametrize("mutation", ["run", "attempt", "snapshot", "scope", "foreign-input"])
def test_foreign_binding_rejected(tmp_path, mutation):
    f = fixture(tmp_path)
    if mutation == "run":
        f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, run_id="run-other"))
    elif mutation == "attempt":
        f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, review_attempt_id="attempt-other"))
    elif mutation == "snapshot":
        f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, target_snapshot="stale"))
    elif mutation == "scope":
        f.scope = replace(f.scope, manifest_sha256=digest("stale"))
    else:
        f.refs = replace(f.refs, adjudications={"path": "foreign/adjudications.json", "sha256": digest("foreign")})
    with pytest.raises(IntegrityError):
        f.publish()


@pytest.mark.parametrize("payload", [b'{"x":1,"x":2}', b'[]', b'not-json', b'\xff'])
def test_malformed_bounded_input_is_not_unavailable(tmp_path, payload):
    path = tmp_path / "input.json"
    path.write_bytes(payload)
    reader = BoundReader(tmp_path, DecisionAuditSettings())
    with pytest.raises(IntegrityError):
        reader.json({"path": path.name, "sha256": hashlib.sha256(payload).hexdigest()})


@pytest.mark.parametrize("path", ["../outside", "/absolute", "a//b", "a/./b", "a\\b", "a:b"])
def test_noncanonical_path_rejected(tmp_path, path):
    with pytest.raises(IntegrityError):
        BoundReader(tmp_path, DecisionAuditSettings()).read({"path": path, "sha256": digest("data")})


def test_input_total_bound_cache_and_size(tmp_path):
    first = document(tmp_path, "first.json", {"data": "x" * 2500})
    second = document(tmp_path, "second.json", {"data": "y" * 2500})
    reader = BoundReader(tmp_path, DecisionAuditSettings(max_input_bytes=4096))
    expected = reader.read(reference(first))
    assert reader.read(reference(first)) == expected
    with pytest.raises(AuditUnavailable, match="max_input_bytes"):
        reader.read(reference(second))
    with pytest.raises(IntegrityError, match="conflicting"):
        reader.read({**reference(first), "sha256": digest("changed")})
    with pytest.raises(IntegrityError, match="size"):
        reader.read({**reference(first), "size_bytes": False})
    with pytest.raises(IntegrityError, match="size"):
        BoundReader(tmp_path, DecisionAuditSettings()).read({**reference(first), "size_bytes": 1})


@pytest.mark.parametrize("ref", [{}, {"path": "file", "sha256": "short"}, {"path": 1, "sha256": "a" * 64}])
def test_malformed_reference(tmp_path, ref):
    with pytest.raises(IntegrityError, match="malformed"):
        BoundReader(tmp_path, DecisionAuditSettings()).read(ref)


def test_fifo_input_does_not_block(tmp_path):
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(IntegrityError, match="regular"):
        BoundReader(tmp_path, DecisionAuditSettings()).read({"path": "fifo", "sha256": digest("data")})


def test_atomic_conflict_preserves_changed_content_and_sibling(tmp_path):
    _write(tmp_path, "audit/one.json", b"one")
    _write(tmp_path, "audit/two.json", b"two")
    _write(tmp_path, "audit/one.json", b"one")
    with pytest.raises(IntegrityError, match="changed immutable"):
        _write(tmp_path, "audit/one.json", b"changed")
    assert (tmp_path / "audit/one.json").read_bytes() == b"one"
    assert (tmp_path / "audit/two.json").read_bytes() == b"two"
    assert not list((tmp_path / "audit").glob(".audit-*"))


def test_bundle_collision_rejected_before_publication(tmp_path):
    f = fixture(tmp_path)
    result = f.project()
    record = result.records[0]
    source = replace(record.context.sources[0], path=f.directory + "/manifest.json")
    record = replace(record, context=replace(record.context, sources=(source,)))
    with pytest.raises(IntegrityError, match="conflicting hash"):
        publish_bundle(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, settings=f.settings,
                       records=(record, *result.records[1:]), coverage=result.coverage, continuations={})
    assert not (f.root / f.directory).exists()


@pytest.mark.parametrize("limit", ["disabled", "max_records", "shard_bytes", "shard_records"])
def test_publication_bounds(tmp_path, limit):
    f = fixture(tmp_path)
    settings = replace(f.settings, **{"disabled": {"enabled": False}, "max_records": {"max_records": 1},
                                     "shard_bytes": {"shard_bytes": 4096},
                                     "shard_records": {"shard_records": 1}}[limit])
    f.settings = settings
    f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, projection_policy_sha256=policy_sha256(settings)))
    if limit == "shard_records":
        result = f.project()
        ref = publish_bundle(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, settings=settings,
                             records=result.records, coverage=result.coverage, continuations={})
        body = json.loads((f.root / ref.path).read_bytes())
        assert all(shard["record_count"] == 1 for shard in body["shards"])
    else:
        with pytest.raises(AuditUnavailable):
            result = f.project()
            publish_bundle(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, settings=settings,
                           records=result.records, coverage=result.coverage, continuations={})


def test_receipt_tampering_is_not_hidden_by_successful_siblings(tmp_path):
    f = fixture(tmp_path)
    cell, receipt = next(iter(f.inputs.receipts.items()))
    path = f.root / receipt.source.path
    path.write_bytes(canonical_json({**receipt.value, "status": "succeeded", "result": {"tampered": True}}))
    with pytest.raises(IntegrityError, match="changed"):
        f.publish()
    assert all((f.root / other.source.path).read_bytes() == canonical_json(other.value)
               for identity, other in f.inputs.receipts.items() if identity != cell)


def test_descriptor_pins_all_files_through_existing_controls(tmp_path):
    from appsec_review.jobs.job_inference_security_review.audit import publish_decision_audit
    f = fixture(tmp_path)
    result = publish_decision_audit(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin,
                                    scope=f.scope, collection=f.inputs.collection, inputs=f.refs, settings=f.settings)
    control = result.unit_output()
    assert set(control) == {"metadata_path", "audit_metadata_artifact", "audit_artifacts", "audit_source_artifacts"}
    refs = [control["audit_metadata_artifact"], *control["audit_artifacts"]]
    assert len({ref["path"] for ref in refs}) == len(refs)
    for ref in refs:
        assert hashlib.sha256((f.root / ref["path"]).read_bytes()).hexdigest() == ref["sha256"]
    assert {path.relative_to(f.root).as_posix() for path in (f.root / f.directory).rglob("*")
            if path.is_file()} == {ref["path"] for ref in refs}


@pytest.mark.parametrize("kind", ["foreign-manifest", "foreign-artifact", "duplicate-artifact", "missing-manifest",
                                 "unavailable-payload", "disabled"])
def test_descriptor_membership_and_unavailability(tmp_path, kind):
    f = fixture(tmp_path)
    ref = c.ManifestRef(f.inputs.origin, f.directory + "/manifest.json", digest("manifest"),
                        "audit-manifest-" + digest("manifest-id"))
    artifacts = ({"path": ref.path, "sha256": ref.sha256},)
    reason = None
    if kind == "foreign-manifest":
        ref = replace(ref, path="foreign/manifest.json")
    elif kind == "foreign-artifact":
        artifacts = ({"path": "foreign/file", "sha256": digest("file")},)
    elif kind == "duplicate-artifact":
        artifacts *= 2
    elif kind == "missing-manifest":
        artifacts = ()
    elif kind == "unavailable-payload":
        ref, reason = None, "capacity_exceeded"
    else:
        f.settings = replace(f.settings, enabled=False)
        f.inputs = replace(f.inputs, origin=replace(f.inputs.origin,
                                                    projection_policy_sha256=policy_sha256(f.settings)))
        ref, reason, artifacts = None, "disabled", ()
    kwargs = dict(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin,
                  settings=f.settings, manifest=ref, artifacts=artifacts, unavailable_reason=reason)
    if kind == "disabled":
        result = publish_descriptor(**kwargs)
        body = json.loads((f.root / result.metadata_artifact["path"]).read_bytes())
        assert body["status"] == "unavailable" and body["unavailable_reason"] == "disabled"
    else:
        with pytest.raises(IntegrityError):
            publish_descriptor(**kwargs)
        assert not (f.root / f.directory / "publication.json").exists()


@pytest.mark.parametrize("kind", ["disabled", "policy", "count", "empty"])
def test_bundle_independent_boundaries(tmp_path, kind):
    f = fixture(tmp_path)
    result = f.project()
    settings, origin = f.settings, f.inputs.origin
    records, coverage = result.records, result.coverage
    if kind == "disabled":
        settings = replace(settings, enabled=False)
    elif kind == "policy":
        origin = replace(origin, projection_policy_sha256=digest("wrong"))
    elif kind == "count":
        settings = replace(settings, max_records=1)
        origin = replace(origin, projection_policy_sha256=policy_sha256(settings))
    else:
        records = ()
        coverage = tuple(c.CoverageCount(population, 0, 0, 0, 0, None) for population in c.Population)
    kwargs = dict(run_root=f.root, attempt_root=f.attempt, origin=origin, settings=settings,
                  records=records, coverage=coverage, continuations={})
    if kind == "empty":
        ref = publish_bundle(**kwargs)
        assert json.loads((f.root / ref.path).read_bytes())["shards"] == []
    else:
        with pytest.raises(IntegrityError if kind == "policy" else AuditUnavailable):
            publish_bundle(**kwargs)


def test_continuation_cannot_publish_outside_owned_subtree(tmp_path):
    f = fixture(tmp_path, relation_count=260)
    result = f.project()
    records, continued = [], {}
    for row in result.records:
        refs = []
        for ref in row.context.continuations:
            path = ref.path.replace("/continuations/", "/foreign/")
            refs.append(replace(ref, path=path))
            continued[path] = result.continuations[ref.path]
        records.append(replace(row, context=replace(row.context, continuations=tuple(refs))))
    # Basis links change with the changed records: use decision rows only for this storage test.
    records = tuple(row for row in records if isinstance(row, c.DecisionRecord))
    declared = {ref.path for row in records for ref in row.context.continuations}
    continued = {path: rows for path, rows in continued.items() if path in declared}
    coverage = tuple(c.CoverageCount(population, len(records) if population == c.Population.DECISIONS else 0,
                                     len(records) if population == c.Population.DECISIONS else 0, 0, 0, None)
                     for population in c.Population)
    with pytest.raises(IntegrityError, match="exact audit directory"):
        publish_bundle(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, settings=f.settings,
                       records=records, coverage=coverage, continuations=continued)
    assert not (f.root / f.directory).exists()


def test_named_source_reads_retain_real_attempt_receipts_including_cached_reads(tmp_path):
    from types import SimpleNamespace
    from appsec_review.runtime.datasets import artifact_only, dataset_contract
    from appsec_review.storage import atomic_json
    from appsec_review.storage import shared
    f = fixture(tmp_path)
    attempt = f.root / "data/jobs/job_fixture/attempts/attempt-2"
    declaration = artifact_only("shared", "work", "inventory", shared.RECEIPT_SCHEMA,
                                "Unit fixture shared receipts", artifacts=("data/jobs/job_fixture/attempts/*/shared/*/*.json",),
                                reason="not accepted evidence")
    claim = {"schema": "appsec-review/attempt-claim/1", "run_id": f.root.name, "job_id": "job_fixture",
             "attempt_id": attempt.name, "attempt_path": attempt.relative_to(f.root).as_posix(),
             "source_fingerprint": "snapshot", "orchestration": {"system": "dagster", "run_id": "fixture"},
             "dataset_contract": dataset_contract("job_fixture", ("work",), (declaration,))}
    atomic_json(attempt / "claim.json", claim)
    owner = shared.SharedArtifacts.for_job(SimpleNamespace(
        run_root=f.root, attempt_root=attempt, run_id=f.root.name, attempt_id=attempt.name,
        orchestration=claim["orchestration"], config=SimpleNamespace(job_id="job_fixture")))
    receipt = next(iter(f.inputs.receipts.values()))
    reader = BoundReader(f.root, f.settings)
    with shared.publication_scope_for_owner(owner):
        data = reader.read(reference(receipt), namespace="review-cell")
        assert reader.read(reference(receipt), namespace="review-cell") == data
    assert list((attempt / "shared").rglob("*.json"))
    assert any((ref["path"], ref["sha256"]) == (receipt.source.path, receipt.source.sha256)
               for ref in shared.attempt_artifacts(f.root, attempt))


def test_output_and_descriptor_bytes_fit_remaining_consumer_budget_before_writes(tmp_path):
    f = fixture(tmp_path)
    result = f.project()
    with pytest.raises(AuditUnavailable, match="verification_bundle"):
        publish_bundle(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, settings=f.settings,
                       records=result.records, coverage=result.coverage, continuations={}, byte_budget=1)
    assert not (f.root / f.directory).exists()


def test_continuation_rows_count_toward_total_capacity(tmp_path):
    f = fixture(tmp_path, relation_count=260)
    result = f.project()
    count = len(result.records) + sum(len(rows) for rows in result.continuations.values())
    f.settings = replace(f.settings, max_records=count - 1)
    f.inputs = replace(f.inputs, origin=replace(f.inputs.origin,
                                              projection_policy_sha256=policy_sha256(f.settings)))
    result = f.project()
    with pytest.raises(AuditUnavailable, match="max_records"):
        publish_bundle(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, settings=f.settings,
                       records=result.records, coverage=result.coverage, continuations=result.continuations)
    assert not (f.root / f.directory).exists()


@pytest.mark.parametrize("detail,reason", [("disabled", "disabled"),
    ("input_unavailable:adjudication", "input_unavailable"), ("max_records", "capacity_exceeded")])
def test_unavailable_reports_closed_metadata_reason(detail, reason):
    assert AuditUnavailable(detail).reason == reason
