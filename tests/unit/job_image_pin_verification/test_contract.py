"""Pin input authority, dataset declarations and every handler's file/receipt boundary."""

from dataclasses import asdict
from fnmatch import fnmatchcase
from pathlib import Path

import pytest

from appsec_review.jobs.job_image_pin_verification import job as gate
from appsec_review.jobs.job_image_pin_verification.datasets import CONSUMES, CONTRACT, DATASETS
from tests.unit.job_image_pin_verification.support import (
    ATTEMPT, PIN_A, UNITS, artifact, context, matching_runner, pin, write_inputs,
)


def test_inputs_are_empty_and_scheduling_is_not_read_authority():
    assert asdict(CONTRACT) == {
        "inputs": (), "schedule_after": ("job_model_connectivity",),
        "dispatch": "review_graph", "target_access": "none",
        "always_execute": True, "propagate_handoff": False,
    }
    job = gate.build_job(runner=matching_runner)
    assert job.contract is CONTRACT and job.datasets is DATASETS
    assert job.consumes == CONSUMES == ()


def test_output_declaration_pins_all_metadata_and_artifact_globs():
    prefix = "data/jobs/job_image_pin_verification/attempts/*/steps/"
    assert [asdict(item) for item in DATASETS] == [{
        "output_kind": "image_pin_verification", "step": "publication",
        "family": "configuration", "schema": "appsec-review/image-pin-verification/1",
        "sensitivity": "internal", "disposition": "artifact_only",
        "description": "Local resolution of every enabled catalog image and configured image-ID pin for one dispatch.",
        "indexes": (), "shard_prefixes": (), "shard_suffixes": (),
        "artifacts": (
            prefix + "selection/tasks/resolve_pins/image-pin-plan.json",
            prefix + "verification/tasks/inspect_images/image-pin-verification.json",
            prefix + "publication/tasks/publish_handoff/image-pin-verification-handoff.json",
        ),
        "query_route": "query_dataset_inventory (sanitized identity, hash, status and coverage only)",
        "reason": "tool image pin provenance; no target security evidence",
        "required": False, "store": "retrieval", "authority": "operational",
    }]
    assert not any(fnmatchcase("data/jobs/other/attempts/a/image-pin-verification.json", pattern)
                   for pattern in DATASETS[0].artifacts)


@pytest.mark.parametrize(
    ("unit_id", "name", "schema", "receipt"),
    [
        (UNITS[0], "image-pin-plan.json", "appsec-review/image-pin-plan/2", None),
        (UNITS[1], "image-pin-verification.json", "appsec-review/image-pin-verification/1", UNITS[0]),
        (UNITS[2], "image-pin-verification-handoff.json", "appsec-review/image-pin-verification/1", UNITS[1]),
    ],
    ids=["selection", "verification", "publication"],
)
def test_handlers_read_only_declared_files_and_receipts_and_write_claimed_artifacts(
        tmp_path, monkeypatch, unit_id, name, schema, receipt):
    upstream_identity = {"path": "prior.json", "sha256": "c" * 64, "size_bytes": 17}
    images = [{**pin(), "resolved_image_id": PIN_A, "status": "matched"}]
    outputs = {
        UNITS[0]: {"pins": [pin()], "artifact": upstream_identity},
        UNITS[1]: {"images": images, "artifact": upstream_identity, "pin_count": 1},
    }
    unit = context(tmp_path, unit_id, outputs)
    inputs = write_inputs(unit)
    original = Path.read_bytes
    reads = []

    def read_bytes(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)
    handler = {item.unit_id: item.handler for item in gate.build_job(runner=matching_runner).units}[unit_id]
    result = handler(unit)
    assert reads == (list(inputs) if unit_id == UNITS[0] else [])
    assert unit.reads == ([] if receipt is None else [receipt])
    assert sorted(path.relative_to(unit.unit_root).as_posix() for path in unit.unit_root.rglob("*")
                  if path.is_file()) == [name]
    identity, document = artifact(unit, name)
    assert result["artifact"] == identity
    assert result["schema"] == document["schema"] == schema
    assert any(fnmatchcase(identity["path"], pattern) for pattern in DATASETS[0].artifacts)
    assert identity["path"] == f"{ATTEMPT}/steps/{unit_id.replace('.', '/tasks/')}/{name}"
    if unit_id == UNITS[2]:
        assert document == {"schema": DATASETS[0].schema, "artifact": upstream_identity, "images": images}
        assert result["terminal_status"] == "SUCCEEDED" and result["gaps"] == []
