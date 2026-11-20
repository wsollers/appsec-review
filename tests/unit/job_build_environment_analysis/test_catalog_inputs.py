"""Preserve accepted catalog admission and reads across the catalog-reader extraction."""
from __future__ import annotations

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_build_environment_analysis import job as environment
from appsec_review.jobs.job_target_analysis_plan import job as planner
from appsec_review.jobs.job_target_catalog import job as catalog
from appsec_review.runtime.consume import UpstreamIntegrityError, UpstreamNotPinnedError
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import admit_inputs, input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import (
    SharedArtifacts, attempt_artifacts, publication_scope_for_owner,
)
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_target_catalog.support import context as catalog_context

CATALOG = "job_target_catalog"
PUBLISH = "publish_catalog.publish_handoff"
PARTITION = "repository_discovery.partition_repository"


def _publish_catalog(tmp_path, *, attempt_id="attempt_0001"):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "setup.sh").write_bytes(b"CC=clang\n")
    outputs = {}
    job = catalog.build_job()
    context = catalog_context(tmp_path, job.units[0].unit_id, outputs)
    context.job.run_id = context.job.run_root.name
    context.job.attempt_id = attempt_id
    context.job.attempt_root = context.job.attempt_root.parent / attempt_id
    context.job.config.job_id = CATALOG
    context.job.orchestration = {}
    root, attempt = context.job.run_root, context.job.attempt_root
    atomic_json(attempt / "claim.json", {
        "dataset_contract": dataset_contract(
            CATALOG, tuple(catalog.TOPOLOGY), job.datasets, job_contract=job.contract.document()),
        "orchestration": {},
    })
    identity = {
        "job_id": CATALOG,
        "source_fingerprint": context.job.source_fingerprint,
        "schema_identity": job.schema_identity,
    }
    # Seed the immutable claim before real writers bind their publication receipts.
    write_fixture_handoff(root, attempt / "handoff.json", identity)
    claim_sha = file_sha256(attempt / "claim.json")
    with publication_scope_for_owner(SharedArtifacts.for_job(context.job)):
        for unit in job.units:
            context.unit_id = unit.unit_id
            outputs[unit.unit_id] = unit.handler(context)
    (attempt / "result.json").unlink()
    handoff = write_fixture_handoff(root, attempt / "handoff.json", {
        **identity,
        "completion_status": "COMPLETED_WITH_GAPS",
        "artifacts": attempt_artifacts(root, attempt),
        "outputs": outputs,
    })
    assert file_sha256(attempt / "claim.json") == claim_sha
    digest = file_sha256(handoff)
    atomic_json(root / "data/jobs" / CATALOG / "latest.json", {
        "handoff_path": handoff.relative_to(root).as_posix(), "handoff_sha256": digest,
    })
    return SimpleNamespace(
        root=root, target=target, source=context.job.source_fingerprint,
        handoff=handoff, digest=digest, outputs=outputs,
    )


@pytest.fixture
def published_catalog(tmp_path):
    return _publish_catalog(tmp_path)


def _consumer(publication, consumer=environment):
    job = consumer.build_job()
    events = []
    launch = environment.environment_contract(SimpleNamespace(jobs={}), {}, {})
    context = SimpleNamespace(
        run_root=publication.root, target_root=publication.target,
        source_fingerprint=publication.source, evidence_target_snapshot=publication.source,
        config=SimpleNamespace(job_id=job.job_id, settings={}), contract=job.contract,
        upstream_handoffs={CATALOG: publication.digest}, optional_prior_handoffs={},
        external_input_selection=None,
        orchestration={"build_environment_contract": json.dumps(launch)},
        events=SimpleNamespace(write=lambda event, **fields: events.append((event, fields))),
    )
    return job.units[0].handler, SimpleNamespace(
        job=context, unit_id=job.units[0].unit_id,
    ), events


@pytest.mark.parametrize("consumer", [environment, planner], ids=["environment", "planner"])
def test_catalog_consumers_keep_admitted_pin_and_observed_receipt_after_latest_moves(
    tmp_path, published_catalog, consumer,
):
    first = published_catalog
    handler, unit, events = _consumer(first, consumer)
    admission = admit_inputs(unit.job, {CATALOG})
    envelope = next(row for row in admission["requirements"]
                    if (row["producer"], row["output_kind"]) == (CATALOG, "handoff"))
    assert envelope["supplied"] is True and envelope["read"] is False
    assert envelope["handoff_sha256"] == first.digest

    (first.target / "README.md").write_bytes(b"newer accepted inventory\n")
    second = _publish_catalog(tmp_path, attempt_id="attempt_0002")
    assert second.digest != first.digest
    with input_read_scope(unit.job) as reads:
        output = handler(unit)
    if consumer is environment:
        value = output["environment"]
        assert [(row["path"], row["name"], row["value"]) for row in value["declarations"]] == [
            ("setup.sh", "CC", "clang")]
        assert value["coverage"] == "complete"
    else:
        value = output["catalog"]
        assert [row["path"] for row in value["files"]] == ["setup.sh"]
        assert output["environment"]["availability"] == "ABSENT"
    assert value["catalog_handoff_sha256"] == first.digest
    assert value["source_fingerprint"] == first.source
    assert events
    observed = reads.document()
    assert observed["citation_observation"] == "not_observed"
    assert len(observed["reads"]) == 1
    assert observed["reads"][0] == {
        "producer": CATALOG, "output_kind": "handoff",
        "schema": "appsec-review/job-handoff/2", "channel": "handoff",
        "authority": "producer_evidence", "read": True, "cited": None,
        "handoff_sha256": first.digest, "attempt_id": "attempt_0001",
        "target_snapshot": first.source,
        "coverage": json.loads(first.handoff.read_bytes())["coverage"],
    }


@pytest.mark.parametrize("defect,error_type,message", [
    ("undeclared", UpstreamNotPinnedError, "undeclared consumption"),
    ("unsupplied", UpstreamNotPinnedError, "not supplied by the attempt claim"),
    ("foreign-root", UpstreamIntegrityError, "foreign run"),
], ids=["undeclared", "unsupplied", "foreign-root"])
def test_catalog_reader_keeps_typed_permission_supply_and_run_boundary(
    published_catalog, defect, error_type, message,
):
    handler, unit, events = _consumer(published_catalog)
    if defect == "undeclared":
        unit.job.contract = replace(unit.job.contract, inputs=())
    elif defect == "unsupplied":
        unit.job.upstream_handoffs = {}
    with pytest.raises(error_type, match=message) as caught:
        with input_read_scope(unit.job) as reads:
            if defect == "foreign-root":
                unit.job = SimpleNamespace(**{
                    **vars(unit.job), "run_root": published_catalog.root / "foreign-run",
                })
            handler(unit)
    assert type(caught.value) is error_type and caught.value.__cause__ is None
    assert reads.document()["reads"] == [] and events == []


def test_catalog_reader_requires_an_accepted_producer_before_target_access(tmp_path):
    publication = SimpleNamespace(
        root=tmp_path / "run", target=None, source="fixture-snapshot", digest="a" * 64,
    )
    handler, unit, events = _consumer(publication)
    unit.job.upstream_handoffs = {}
    with pytest.raises(UpstreamIntegrityError, match="handoff is required") as caught:
        with input_read_scope(unit.job) as reads:
            handler(unit)
    assert type(caught.value) is UpstreamIntegrityError
    assert reads.document()["reads"] == [] and events == []


@pytest.mark.parametrize("defect,error_type,message,read_count", [
    ("handoff-bytes", UpstreamIntegrityError, "handoff changed after it was recorded", 0),
    ("catalog-bytes", ValueError, "accepted upstream artifact identity changed", 1),
    ("partition-bytes", ValueError, "accepted upstream artifact identity changed", 1),
    ("catalog-symlink", ValueError, "symlink", 1),
], ids=["handoff-bytes", "catalog-bytes", "partition-bytes", "catalog-symlink"])
def test_catalog_read_time_integrity_failures_keep_shared_exception_identity(
    published_catalog, defect, error_type, message, read_count,
):
    publication = published_catalog
    handler, unit, events = _consumer(publication)
    admit_inputs(unit.job, {CATALOG})
    if defect == "handoff-bytes":
        path = publication.handoff
    else:
        output = publication.outputs[PARTITION if defect == "partition-bytes" else PUBLISH]
        path = publication.root / output["artifact"]["path"]
    if defect == "catalog-symlink":
        copy = path.with_name("displaced-catalog.json")
        path.rename(copy)
        path.symlink_to(copy.name)
    else:
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(error_type, match=message) as caught:
        with input_read_scope(unit.job) as reads:
            handler(unit)
    assert type(caught.value) is error_type and caught.value.__cause__ is None
    assert len(reads.document()["reads"]) == read_count
    assert events == []


@pytest.mark.parametrize("field,value,message", [
    ("run_id", "foreign-run", "invalid accepted handoff"),
    ("attempt_id", "attempt_9999", "attempt path identity mismatch"),
], ids=["foreign-run", "foreign-attempt"])
def test_catalog_admission_rejects_foreign_run_and_attempt_identity(
    published_catalog, field, value, message,
):
    publication = published_catalog
    document = json.loads(publication.handoff.read_bytes())
    document[field] = value
    atomic_json(publication.handoff, document)
    publication.digest = file_sha256(publication.handoff)
    atomic_json(publication.root / "data/jobs" / CATALOG / "latest.json", {
        "handoff_path": publication.handoff.relative_to(publication.root).as_posix(),
        "handoff_sha256": publication.digest,
    })
    _, unit, events = _consumer(publication)
    with pytest.raises(ValueError, match=message) as caught:
        admit_inputs(unit.job, {CATALOG})
    if field == "run_id":
        assert isinstance(caught.value.__cause__, ValueError)
        assert str(caught.value.__cause__) == "handoff run_id mismatch"
    else:
        assert caught.value.__cause__ is None
    assert events == []
