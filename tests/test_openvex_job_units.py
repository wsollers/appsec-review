from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import parse_review_policy
from appsec_review.jobs.job_openvex_export.contracts import (
    ArtifactRef, ExportError, ExportReportState, JOB_ID, OPENVEX_EXPORT_HANDOFF_SCHEMA,
    SizedArtifactRef, VerifiedInputs, canonical_bytes,
)
from appsec_review.jobs.job_openvex_export.job import build_job
from appsec_review.jobs.job_openvex_export.reporting import (
    load_export, read_accepted_export, report_section,
)
from appsec_review.observability import EventLog, PipelineLog
from appsec_review.runtime import JobContext, UnitContext
from tests.openvex_input_support import AcceptedInputDisk
from tests.openvex_support import ROOT
from tests.openvex_support import enabled_settings


class ExportUnits:
    def __init__(self, disk: AcceptedInputDisk):
        self.disk = disk
        manifest_path = disk.root / disk.config_manifest_ref["path"]
        manifest = json.loads(manifest_path.read_bytes())
        manifest["schema"] = "appsec-review/run-configuration/2"
        disk.config_manifest_ref = disk.put(disk.config_manifest_ref["path"], manifest)
        self.job = build_job(repository_root=ROOT)
        config = load_config(ROOT / "appsec-review.toml", profile="dev", overlay="")
        policy = parse_review_policy(disk.resolved.get("review_policy", {}))
        settings = replace(config.job(JOB_ID), settings=disk.settings.to_mapping(), typed_settings=disk.settings)
        attempt = disk.root / "data" / "jobs" / JOB_ID / "attempts" / "unit"
        self.context = JobContext(
            run_id=disk.gate["run_id"], attempt_id="unit", trigger="manual", repository_root=ROOT,
            run_root=disk.root, attempt_root=attempt, metadata_root=disk.root / "metadata",
            orchestration={}, config=settings, review_policy=policy,
            events=EventLog(attempt / "logs" / "events.jsonl", PipelineLog(disk.root), {
                "run_id": disk.gate["run_id"], "job_id": JOB_ID, "attempt_id": "unit",
            }),
        )
        self.implementation_identity = policy.releases.values.get(JOB_ID, policy.releases.values.get("platform"))
        self.release = "undeclared" if self.implementation_identity is None else self.implementation_identity
        disk.put((attempt / "claim.json").relative_to(disk.root).as_posix(), {
            "started_at": datetime.now(timezone.utc).isoformat(),
        })
        self.outputs = {}

    def execute(self, unit_id):
        unit = next(unit for unit in self.job.units if unit.unit_id == unit_id)
        step, task = unit_id.split(".")
        path = self.context.attempt_root / "steps" / step / "tasks" / task
        path.mkdir(parents=True, exist_ok=True)
        result = unit.handler(UnitContext(self.context, unit_id, step, task, path, self.outputs))
        self.outputs[unit_id] = dict(result)
        return result

    def assemble(self):
        self.execute("load.verify_inputs")
        return self.execute("export.assemble")

    def accept(self):
        self.execute("acceptance.publish_handoff")
        artifacts = {}

        def collect(value):
            if isinstance(value, dict):
                if {"path", "sha256"} <= value.keys():
                    artifacts[value["path"]] = dict(value)
                for child in value.values():
                    collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)

        collect(self.outputs)
        outputs = {key: {name: value for name, value in output.items()
                         if name in {"schema", "artifact", "item_count", "gaps", "terminal_status"}}
                   for key, output in self.outputs.items()}
        handoff = self.disk.handoff(JOB_ID, outputs)
        handoff.update({
            "attempt_id": self.context.attempt_id,
            "completion_status": self.outputs["acceptance.publish_handoff"]["terminal_status"],
            "schema_identity": OPENVEX_EXPORT_HANDOFF_SCHEMA, "implementation_identity": self.implementation_identity,
            "resolved_config_sha256": self.disk.config_ref["sha256"],
            "upstream_handoff_sha256": {
                "job_final_publication_gate": self.disk.gate_job_ref["sha256"],
                "job_inference_security_review": self.disk.review_job_ref["sha256"],
            },
            "artifacts": list(artifacts.values()),
        })
        self.reference = ArtifactRef.from_mapping(self.disk.publish(JOB_ID, handoff))
        return handoff

    def view(self, **overrides):
        return load_export(self.disk.root, self.disk.settings, ROOT,
                           exporter_release=overrides.get("release", self.release),
                           gate_handoff=overrides.get("gate", self.disk.gate_job_ref))

    def result(self):
        reference = self.outputs["export.assemble"]["artifact"]
        return json.loads((self.disk.root / reference["path"]).read_bytes())


def test_output_reader_uses_its_explicit_byte_bound_and_rejects_wrong_measured_size(tmp_path):
    from appsec_review.jobs.job_openvex_export.reporting import read_output

    payload = b'{"status":"bound"}\n'
    (tmp_path / "artifact.json").write_bytes(payload)
    reference = ArtifactRef("artifact.json", hashlib.sha256(payload).hexdigest())
    settings = enabled_settings(max_artifact_bytes=1)
    assert read_output(tmp_path, reference, settings, max_bytes=len(payload)) == payload
    with pytest.raises(ExportError):
        read_output(tmp_path, reference, settings, max_bytes=len(payload) - 1)
    with pytest.raises(ExportError):
        read_output(tmp_path, SizedArtifactRef(reference.path, reference.sha256, len(payload) + 1),
                    settings, max_bytes=len(payload))


def test_output_reader_rejects_a_hardlink_created_during_read(tmp_path, monkeypatch):
    from appsec_review.jobs.job_openvex_export import reporting

    payload = b"{}\n"
    (tmp_path / "artifact.json").write_bytes(payload)
    reference = ArtifactRef("artifact.json", hashlib.sha256(payload).hexdigest())
    original, calls = reporting.os.fstat, [0]

    def fstat(descriptor):
        result = original(descriptor)
        calls[0] += 1
        if calls[0] == 2:
            return SimpleNamespace(st_nlink=2, **{key: getattr(result, key) for key in (
                "st_size", "st_mtime_ns", "st_dev", "st_ino", "st_mode")})
        return result

    monkeypatch.setattr(reporting.os, "fstat", fstat)
    with pytest.raises(ExportError):
        reporting.read_output(tmp_path, reference, enabled_settings(), max_bytes=len(payload))
    assert calls[0] == 2


@pytest.mark.parametrize("buckets", [(), ("publishable",), ("verification_backlog",), ("withheld",),
                                    ("publishable", "verification_backlog", "withheld")])
def test_units_prove_outputs_and_report_only_exact_accepted_state(tmp_path, monkeypatch, buckets):
    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=buckets)
    units = ExportUnits(disk)
    assert units.view().state == ExportReportState.NOT_RUN
    units.assemble()
    # Even completed domain assembly is not accepted data.
    assert units.view().state == ExportReportState.NOT_RUN
    units.accept()
    bundle = read_accepted_export(disk.root, units.reference, disk.settings, ROOT)
    view = units.view()
    count = buckets.count("publishable")
    assert view.state == (ExportReportState.AVAILABLE if count else ExportReportState.NO_STATEMENTS)
    assert bundle.result["statement_count"] == view.statement_count == count
    assert view.included_findings == count
    assert view.excluded_findings == len(buckets) - count
    assert (view.document is not None) == bool(count)
    assert report_section(view)["document"] == (None if view.document is None
                                                else view.document.reference.to_json())
    assert read_accepted_export(disk.root, units.reference, disk.settings, ROOT).result_bytes == bundle.result_bytes
    if not count:
        assert not list((units.context.attempt_root / "steps" / "export").rglob("openvex.json"))


def test_admission_refuses_disabled_or_wrong_task_topology(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    context = replace(units.context, config=replace(units.context.config, settings={
        **disk.settings.to_mapping(), "enabled": False,
    }))
    with pytest.raises(ValueError, match="disabled"):
        units.job.execute(context)
    with pytest.raises(ValueError, match="topology"):
        units.job.execute(replace(units.context, config=replace(units.context.config, steps={})))


@pytest.mark.parametrize("artifact", ["document", "manifest", "result", "verified_inputs", "input"])
def test_acceptance_reproves_each_artifact_and_original_inputs(tmp_path, monkeypatch, artifact):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    result = units.result()
    if artifact in {"document", "manifest"}:
        reference = result[artifact]
    elif artifact == "result":
        reference = units.outputs["export.assemble"]["artifact"]
    elif artifact == "verified_inputs":
        reference = units.outputs["load.verify_inputs"]["artifact"]
    else:
        reference = disk.gate_ref
    path = disk.root / reference["path"]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ExportError):
        units.execute("acceptance.publish_handoff")
    records, _ = PipelineLog(disk.root).read()
    assert any(row["event_type"] == "OPENVEX_EXPORT_FAILED" for row in records)
    assert not any(row["event_type"] == "OPENVEX_EXPORT_COMPLETED" for row in records)
    assert not (disk.root / "data" / "jobs" / JOB_ID / "latest.json").exists()


def test_schema_snapshots_are_bound_and_reproved_not_recreated(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    reference = units.outputs["load.verify_inputs"]["schema_artifacts"][0]
    (disk.root / reference["path"]).unlink()
    with pytest.raises(ExportError):
        units.execute("acceptance.publish_handoff")
    assert not (disk.root / reference["path"]).exists()


def test_replay_is_byte_identical_and_existing_output_is_never_overwritten(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    before = canonical_bytes(units.result())
    units.execute("export.assemble")
    assert canonical_bytes(units.result()) == before
    reference = units.outputs["export.assemble"]["artifact"]
    path = disk.root / reference["path"]
    path.write_bytes(b"{}")
    with pytest.raises(ExportError):
        units.execute("export.assemble")
    assert path.read_bytes() == b"{}"


def test_release_or_report_gate_mismatch_is_stale_without_any_output_links(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    units.accept()
    for view in (units.view(release="another-release"), units.view(gate={"path": "data/other.json", "sha256": "f" * 64})):
        assert view.state == ExportReportState.STALE
        assert view.document is view.manifest is view.result is view.statement_count is None


def test_undeclared_export_release_matches_nullable_runtime_identity_not_a_declared_release(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    handoff = units.accept()
    assert units.release == "undeclared"
    assert handoff["implementation_identity"] is None
    bundle = read_accepted_export(disk.root, units.reference, disk.settings, ROOT)
    assert bundle.manifest["provenance"]["exporter_release"] == "undeclared"
    assert units.view().state == ExportReportState.AVAILABLE
    handoff["implementation_identity"] = "different-declared-release"
    reference = ArtifactRef.from_mapping(disk.publish(JOB_ID, handoff))
    with pytest.raises(ExportError):
        read_accepted_export(disk.root, reference, disk.settings, ROOT)


def test_a_new_valid_gate_pointer_does_not_invalidate_old_bytes_but_makes_export_stale(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    units.accept()
    handoff = deepcopy(disk.gate_handoff)
    handoff["completed_at"] = "2026-10-28T15:00:00+00:00"
    reference = disk.put("data/jobs/job_final_publication_gate/attempts/two/handoff.json", handoff)
    disk.put("data/jobs/job_final_publication_gate/latest.json", {
        "handoff_path": reference["path"], "handoff_sha256": reference["sha256"],
    })
    assert read_accepted_export(disk.root, units.reference, disk.settings, ROOT)
    assert units.view().state == ExportReportState.STALE


def test_corrupt_accepted_output_is_an_integrity_failure_never_missing_or_stale(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    units.accept()
    reference = units.result()["manifest"]
    path = disk.root / reference["path"]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ExportError):
        units.view()


@pytest.mark.parametrize("mutation", ["tampered_runtime_artifact", "duplicate_artifact"])
def test_historical_reader_reproves_the_whole_runtime_artifact_declaration(tmp_path, monkeypatch, mutation):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    handoff = units.accept()
    if mutation == "duplicate_artifact":
        handoff["artifacts"].append(dict(handoff["artifacts"][0]))
    else:
        reference = disk.put("data/jobs/job_openvex_export/attempts/unit/receipt.json", {"status": "SUCCEEDED"})
        handoff["artifacts"].append(reference)
        path = disk.root / reference["path"]
        path.write_bytes(path.read_bytes() + b" ")
    reference = ArtifactRef.from_mapping(disk.publish(JOB_ID, handoff))
    with pytest.raises(ExportError):
        read_accepted_export(disk.root, reference, disk.settings, ROOT)


def test_disabled_reader_never_looks_for_a_pointer_and_directory_pointer_is_corrupt(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    pointer = disk.root / "data" / "jobs" / JOB_ID / "latest.json"
    pointer.mkdir(parents=True)
    disabled = replace(disk.settings, enabled=False)
    assert load_export(disk.root, disabled, ROOT, exporter_release="undeclared").state == ExportReportState.DISABLED
    with pytest.raises(ExportError):
        ExportUnits(disk).view()


def test_new_local_json_is_not_accepted_with_duplicate_keys_even_after_ref_rehash(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    handoff = units.accept()
    reference = units.outputs["export.assemble"]["artifact"]
    path = disk.root / reference["path"]
    payload = path.read_bytes().replace(b'{"', b'{"outcome":"exported","', 1)
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    handoff["outputs"]["acceptance.publish_handoff"]["artifact"]["sha256"] = digest
    for artifact in handoff["artifacts"]:
        if artifact["path"] == reference["path"]:
            artifact["sha256"] = digest
    ref = ArtifactRef.from_mapping(disk.publish(JOB_ID, handoff))
    with pytest.raises(ExportError):
        read_accepted_export(disk.root, ref, disk.settings, ROOT)


def test_original_attempt_deadline_applies_across_units_and_never_emits_completion(tmp_path, monkeypatch):
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    claim = units.context.attempt_root / "claim.json"
    claim.write_bytes(canonical_bytes({
        "started_at": (datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat(),
    }))
    with pytest.raises(ExportError, match="deadline"):
        units.execute("acceptance.publish_handoff")
    records, _ = PipelineLog(disk.root).read()
    assert not any(row["event_type"] == "OPENVEX_EXPORT_COMPLETED" for row in records)


@pytest.mark.parametrize("at_deadline", [False, True])
def test_final_result_read_cannot_cross_the_deadline_and_emit_success(tmp_path, monkeypatch, at_deadline):
    from appsec_review.jobs.job_openvex_export import job as exporter

    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    original_read = exporter.read_output
    clock, result_reads = [100.0], [0]
    started = datetime.fromisoformat(json.loads((units.context.attempt_root / "claim.json").read_bytes())["started_at"])

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return started

    def read(*args, **kwargs):
        payload = original_read(*args, **kwargs)
        if args[1].path.endswith("/openvex-result.json"):
            result_reads[0] += 1
            if result_reads[0] == 2:
                clock[0] = 100.0 + disk.settings.timeout_seconds + (0.0 if at_deadline else 1.0)
        return payload

    monkeypatch.setattr(exporter.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(exporter, "datetime", FixedClock)
    monkeypatch.setattr(exporter, "read_output", read)
    with pytest.raises(ExportError, match="deadline"):
        units.execute("acceptance.publish_handoff")
    assert result_reads[0] == 2
    records, _ = PipelineLog(disk.root).read()
    assert not any(row["event_type"] == "OPENVEX_EXPORT_COMPLETED" for row in records)


def test_real_accepted_reader_is_the_only_authority_for_semantic_metrics(tmp_path, monkeypatch):
    from appsec_review.jobs.job_openvex_export.metrics import aggregate_openvex_metrics

    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.context.events.write("JOB_STARTED")
    units.assemble()
    units.accept()
    records, _ = PipelineLog(disk.root).read()
    before = aggregate_openvex_metrics(disk.root, records, repository_root=ROOT)
    assert before["openvex_export_statements_total"]["affected"] is None
    units.context.events.write("JOB_COMPLETED_WITH_GAPS" if units.outputs[
        "acceptance.publish_handoff"]["gaps"] else "JOB_SUCCEEDED", duration_ms=100)
    units.context.events.write("HANDOFF_ACCEPTED", handoff_path=units.reference.path,
                              handoff_sha256=units.reference.sha256)
    records, _ = PipelineLog(disk.root).read()
    metrics = aggregate_openvex_metrics(disk.root, records, repository_root=ROOT)
    assert metrics["openvex_export_statements_total"]["affected"] == 1, {
        "gaps": metrics.get("telemetry_gaps", metrics.get("gaps")), "attempts": metrics.get("attempts"),
    }
    assert metrics["latest_state"] == "available"
    assert metrics["openvex_export_attempts_total"][units.result()["outcome"]] == 1
    reference = units.result()["document"]
    path = disk.root / reference["path"]
    path.write_bytes(path.read_bytes() + b" ")
    corrupted = aggregate_openvex_metrics(disk.root, records, repository_root=ROOT)
    assert corrupted["openvex_export_statements_total"]["affected"] is None
