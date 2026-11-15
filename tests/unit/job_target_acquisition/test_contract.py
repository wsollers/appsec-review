"""Pin every contract field and file boundary, including the published schema."""

from __future__ import annotations

from dataclasses import asdict
from fnmatch import fnmatch
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_target_acquisition import build_job
from appsec_review.jobs.job_target_acquisition import job as acquisition_job
from appsec_review.jobs.job_target_acquisition.datasets import CONSUMES, CONTRACT, DATASETS
from tests.unit.job_target_acquisition.support import (
    ACQUISITION, ATTEMPT, CONFIGURATION, PUBLICATION, SCHEMA, SELECTION, SYSTEM_SCHEMA,
    artifact_document, backend_result, fake_backend, handler, plan, unit_context,
)

PLAN_GLOB = "data/jobs/job_target_acquisition/attempts/*/steps/selection/tasks/resolve_system/target-acquisition-plan.json"
RESULT_GLOB = "data/jobs/job_target_acquisition/attempts/*/steps/acquisition/tasks/acquire_components/target-acquisition-result.json"
MANIFEST_GLOB = "data/jobs/job_target_acquisition/attempts/*/steps/acquisition/tasks/acquire_components/system-manifest.json"
HANDOFF_GLOB = "data/jobs/job_target_acquisition/attempts/*/steps/publication/tasks/publish_handoff/target-acquisition-handoff.json"
QUERY_ROUTE = "query_dataset_inventory (sanitized identity, hash, status and coverage only)"
REASON = "source provenance of the review target; intake binds the composed tree fingerprint"


def _expected_dataset(output_kind: str, step: str, schema: str, description: str, glob: str) -> dict[str, object]:
    return {
        "output_kind": output_kind, "step": step, "family": "configuration",
        "schema": schema, "sensitivity": "internal", "disposition": "artifact_only",
        "description": description, "indexes": (), "shard_prefixes": (), "shard_suffixes": (),
        "artifacts": (glob,), "query_route": QUERY_ROUTE, "reason": REASON,
        "required": False, "store": "retrieval", "authority": "operational",
    }


def test_contract_has_no_input_requirements_and_only_a_scheduling_predecessor():
    assert asdict(CONTRACT) == {
        "inputs": (), "schedule_after": ("job_image_pin_verification",), "dispatch": "review_graph",
        "target_access": "none", "always_execute": True, "propagate_handoff": False,
    }
    assert CONSUMES == CONTRACT.consumes == ()
    job = build_job(environ={})
    assert job.contract is CONTRACT and job.datasets is DATASETS and job.consumes == ()


def test_every_dataset_field_is_pinned_independently_of_the_handler():
    assert tuple(asdict(item) for item in DATASETS) == (
        _expected_dataset(
            "target_acquisition", "publication", SCHEMA,
            "Pinned acquisition or read-only re-verification of every component of the requested review system.",
            HANDOFF_GLOB,
        ),
        _expected_dataset(
            "target_acquisition_plan", "selection", SCHEMA,
            "Frozen configuration and selected component specifications for the requested review system.",
            PLAN_GLOB,
        ),
        _expected_dataset(
            "target_acquisition_result", "acquisition", SCHEMA,
            "Component acquisition or re-verification result, including scoped failures and non-applicability.",
            RESULT_GLOB,
        ),
        _expected_dataset(
            "target_acquisition_system_manifest", "acquisition", SYSTEM_SCHEMA,
            "Exact-byte copy of the verified composed-system acquisition manifest, when available.",
            MANIFEST_GLOB,
        ),
    )
    assert (acquisition_job.PLAN_NAME, acquisition_job.RESULT_NAME,
            acquisition_job.MANIFEST_NAME, acquisition_job.HANDOFF_NAME) == (
        "target-acquisition-plan.json", "target-acquisition-result.json",
        "system-manifest.json", "target-acquisition-handoff.json",
    )


@pytest.mark.parametrize("unit_id", [ACQUISITION, PUBLICATION, SELECTION],
                         ids=["acquisition", "publication", "selection"])
def test_handlers_read_and_write_only_their_named_files_and_declared_globs(tmp_path, monkeypatch, unit_id):
    outputs = {SELECTION: plan(), ACQUISITION: {
        "schema": SCHEMA, "status": "NOT_REQUESTED", "artifact": plan()["artifact"], "gaps": [],
    }}
    unit, _ = unit_context(tmp_path, unit_id, outputs=outputs)
    expected_reads = set()
    expected_writes = set()
    if unit_id == ACQUISITION:
        backend = backend_result()
        data = json.dumps({"schema": SYSTEM_SCHEMA, "system_id": "sys"}).encode()
        backend.update(manifest="acquisition-records/sys/manifest.json",
                       manifest_sha256=hashlib.sha256(data).hexdigest())
        _, records = fake_backend(monkeypatch, unit, backend)
        manifest_path = records / "manifest.json"
        manifest_path.write_bytes(data)
        expected_reads = {unit.job.run_root / CONFIGURATION, manifest_path}
        expected_writes = {unit.unit_root / "target-acquisition-result.json", unit.unit_root / "system-manifest.json"}
    elif unit_id == SELECTION:
        expected_reads = {unit.job.run_root / CONFIGURATION}
        expected_writes = {unit.unit_root / "target-acquisition-plan.json"}
    else:
        expected_writes = {unit.unit_root / "target-acquisition-handoff.json"}
    reads, writes = [], []
    read_bytes, write_bytes, write_json = Path.read_bytes, Path.write_bytes, acquisition_job.write_json

    def observe_read(path):
        reads.append(path)
        return read_bytes(path)

    def observe_bytes(path, data):
        writes.append(path)
        return write_bytes(path, data)

    def observe_json(path, document):
        writes.append(path)
        return write_json(path, document)

    with monkeypatch.context() as spy:
        spy.setattr(Path, "read_bytes", observe_read)
        spy.setattr(Path, "write_bytes", observe_bytes)
        spy.setattr(acquisition_job, "write_json", observe_json)
        result = handler(unit_id, environ={})(unit)
    assert set(reads) == expected_reads
    assert set(writes) == expected_writes
    assert set(unit.unit_root.iterdir()) == expected_writes
    for path in expected_writes:
        relative = path.relative_to(unit.job.run_root).as_posix()
        matching = [decl for decl in DATASETS if any(fnmatch(relative, glob) for glob in decl.artifacts)]
        assert len(matching) == 1
        assert matching[0].step == unit.step_id
        document = json.loads(path.read_bytes())
        assert document["schema"] == matching[0].schema
    assert artifact_document(unit, result["artifact"])["schema"] == SCHEMA
    assert not any(
        fnmatch("data/jobs/another_job/attempts/x/target-acquisition-handoff.json", glob)
        for decl in DATASETS for glob in decl.artifacts
    )
    assert not (tmp_path / "checkouts").exists()


def test_published_handoff_schema_matches_the_declared_dataset(tmp_path):
    acquired = {"schema": SCHEMA, "status": "NOT_REQUESTED", "artifact": plan()["artifact"], "gaps": []}
    unit, _ = unit_context(tmp_path, PUBLICATION, outputs={ACQUISITION: acquired})
    result = handler(PUBLICATION, environ={})(unit)
    document = artifact_document(unit, result["artifact"])
    assert result["artifact"]["path"] == (
        f"{ATTEMPT}/steps/publication/tasks/publish_handoff/target-acquisition-handoff.json"
    )
    assert document["schema"] == DATASETS[0].schema, (
        "target_acquisition publishes a handoff whose schema disagrees with its dataset contract"
    )
