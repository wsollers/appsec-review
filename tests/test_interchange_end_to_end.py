"""Contract integration without Docker, network services, targets, or model calls."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.interchange import HANDOFF_SCHEMA, decode_handoff
from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.provenance import (
    common_metadata, json_selector, retain_native_output, select_native,
    validate_observation_provenance, verify_native_reference,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore, write_manifest,
)
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import atomic_json, file_sha256, shared
from tests.test_job_runtime import write_config


def _config(tmp_path):
    path = write_config(tmp_path)
    with path.open("a", encoding="utf-8") as stream:
        stream.write('\n[review_policy.releases]\nplatform = "fixture/1"\nvalidation = "fixture/1"\n')
    return load_config(path)


def _large_artifact(unit):
    path = unit.unit_root / "dataset.bin"
    path.write_bytes(b"x" * (2 * 1024 * 1024))
    return {"terminal_status": "SUCCEEDED", "item_count": 1_000_000, "artifact": {
        "path": path.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
    }}


@pytest.fixture(autouse=True)
def registered_fixture_job(monkeypatch):
    from appsec_review.runtime import registry
    jobs = registry.builtin_registry()
    jobs.register("job_fixture", lambda: Job(
        "job_fixture", "fixture", _large_artifact, units=(Unit("work.produce", _large_artifact),)))
    monkeypatch.setattr(registry, "builtin_registry", lambda: jobs)


def test_large_dataset_publication_resume_and_metrics_share_one_envelope(tmp_path):
    config = _config(tmp_path)
    job = Job("job_fixture", "fixture", _large_artifact, units=(Unit("work.produce", _large_artifact),))
    outcome = JobRunner(config).run(job, source_fingerprint="fixture-snapshot")
    handoff = decode_handoff(outcome["handoff"], job_id=job.job_id)
    run_root = Path(outcome["attempt_root"]).parents[4]
    assert handoff["schema"] == HANDOFF_SCHEMA
    assert handoff["target_snapshot"] == "fixture-snapshot"
    assert handoff["coverage"] == {"disposition": "complete", "gap_count": 0, "retry_required": False}
    assert len(json.dumps(handoff).encode("utf-8")) < 20_000
    assert handoff["outputs"]["work.produce"]["artifact"]["size_bytes"] == 2 * 1024 * 1024
    assert handoff["outcomes"] in handoff["artifacts"]
    reasons, digest = ResumePlanner(config, run_root, [job], "fixture-snapshot").accepted(job, {})
    assert reasons == () and digest == outcome["handoff_sha256"]
    metrics = aggregate_run_metrics(run_root)
    assert metrics["interchange"]["schema"] == "appsec-review/interchange-metrics/1"
    assert metrics["interchange"]["handoffs"]["accepted"] == 1
    assert metrics["interchange"]["handoffs"]["validated"] == 1
    assert metrics["interchange"]["handoffs"]["units"] == 1
    assert metrics["interchange"]["handoffs"]["accounting_complete"]
    records, torn = PipelineLog(run_root).read()
    assert not torn
    validation = [record for record in records if record["event_type"] == "HANDOFF_VALIDATED"]
    assert len(validation) == 1
    assert validation[0]["details"]["handoff_reference"]["sha256"] == digest
    assert "x" * 100 not in json.dumps(records)


def test_dataset_byte_tamper_invalidates_reuse_without_rewriting_history(tmp_path):
    config = _config(tmp_path)
    job = Job("job_fixture", "fixture", _large_artifact, units=(Unit("work.produce", _large_artifact),))
    outcome = JobRunner(config).run(job, source_fingerprint="fixture-snapshot")
    attempt = Path(outcome["attempt_root"])
    run_root = attempt.parents[4]
    handoff_path = attempt / "handoff.json"
    original = handoff_path.read_bytes()
    reference = outcome["handoff"]["outputs"]["work.produce"]["artifact"]
    (run_root / reference["path"]).write_bytes(b"changed")
    reasons, _ = ResumePlanner(config, run_root, [job], "fixture-snapshot").accepted(job, {})
    assert reasons
    assert handoff_path.read_bytes() == original


def test_failed_job_has_only_a_rejected_diagnostic_and_no_accepted_pointer(tmp_path):
    config = _config(tmp_path)

    def fail(unit):
        raise RuntimeError("fixture producer failed")

    job = Job("job_fixture", "fixture", fail, units=(Unit("work.produce", fail),))
    with pytest.raises(RuntimeError, match="fixture producer failed"):
        JobRunner(config).run(job, source_fingerprint="fixture-snapshot")
    handoff_path = next(config.runtime.runs_dir.glob("*/data/jobs/job_fixture/attempts/*/rejected-handoff.json"))
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    assert decode_handoff(handoff, accepted_only=False)["status"] == "REJECTED"
    assert handoff["execution_status"] == "FAILED"
    assert handoff["coverage"]["disposition"] == "unavailable"
    assert not (handoff_path.parents[2] / "latest.json").exists()
    with pytest.raises(ValueError):
        decode_handoff(handoff)


def test_native_scanner_provenance_survives_publication_indexing_and_bounded_retrieval(tmp_path, monkeypatch):
    config = _config(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    snapshot = "fixture-snapshot"

    def scan(unit):
        root = unit.job.run_root
        native_path = unit.unit_root / "parser-input.json"
        atomic_json(native_path, {"files": {"secret.json": [{"rule": "leak", "Secret": "raw-fixture-value"}]}})
        execution = unit.unit_root / "containers" / "fixture" / "receipt.json"
        atomic_json(execution, {"status": "SUCCEEDED", "exit_code": 0})
        native = retain_native_output(
            root, native_path, parser_identity="fixture-parser/1", complete=True, native_result_count=1,
            execution_reference=shared.reference(root, execution), events=unit.job.events, unit_id=unit.unit_id)
        reference = select_native(native, json_selector("files", "secret.json", 0))
        payload = {"tool_id": "tool-gitleaks", "category": "secret_detection", "rule_id": "leak",
                   "severity": "HIGH", "password": "raw-fixture-value"}
        payload["common"] = common_metadata(
            payload, evidence_refs=[reference.as_dict()], payload_schema="fixture-observation/1")
        proof = validate_observation_provenance(
            root, [payload], parser_identity="fixture-parser/1", events=unit.job.events, unit_id=unit.unit_id)
        shard = root / "data" / "indices" / "observations" / "fixture.sqlite"
        builder = IndexBuilder(shard, name="observations", fingerprint="c" * 64, target_snapshot=snapshot)
        identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"rule_id": "leak"})
        builder.add_entity(EntityRecord(identity, "leak", "scanner observation", "indexed-only", payload))
        digest = builder.build()
        manifest = unit.unit_root / "index-manifest.json"
        write_manifest(manifest, run_id=root.name, target_snapshot=snapshot, target_root=target, indexes=[
            IndexIdentity("observations", "appsec-review/retrieval-index/2", digest, "c" * 64,
                          shard.relative_to(root).as_posix(), {"job": unit.job.config.job_id})])
        native_path.write_bytes(b"mutable scanner scratch was overwritten")
        assert verify_native_reference(root, reference, resolve=True)["rule"] == "leak"
        return {"terminal_status": "SUCCEEDED", "native_output": reference.as_dict(),
                "provenance_receipt": proof, "index_manifest": shared.reference(root, manifest)}

    job = Job("job_fixture", "fixture", scan, units=(Unit("work.produce", scan),))
    outcome = JobRunner(config).run(job, source_fingerprint=snapshot)
    run_root = Path(outcome["attempt_root"]).parents[4]
    output = outcome["handoff"]["outputs"]["work.produce"]
    result = json.loads((Path(outcome["attempt_root"]) / "steps" / "work" / "tasks" / "produce" /
                         "result.json").read_text())
    native = result["native_output"]
    assert native["artifact"] in outcome["handoff"]["artifacts"]
    metrics = aggregate_run_metrics(run_root)["interchange"]
    assert metrics["native_outputs"]["reference_count"] == 1
    assert metrics["native_outputs"]["distinct_artifact_bytes"] == native["artifact"]["size_bytes"]
    assert metrics["observations"]["count"] == 1
    assert metrics["observations"]["provenance_complete_count"] == 1
    assert metrics["accounting_complete"]
    report_path = run_root / native["artifact"]["path"]
    original_open = Path.open

    def forbid_native(path, *args, **kwargs):
        assert path != report_path, "retrieval reopened a retained native scanner report"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", forbid_native)
    core = RetrievalCore(run_root.parent, run_root.name,
                         manifest_path=run_root / output["index_manifest"]["path"])
    response = core.query_observations(observation_class="secret", scanner="tool-gitleaks")
    row, = response["results"]
    assert row["payload"]["common"]["evidence_refs"] == [native]
    assert "raw-fixture-value" not in json.dumps(response)
    assert "not an adjudicated finding" in row["authority"]
