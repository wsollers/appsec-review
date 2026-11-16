from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.job_openvex_export import contracts as c
from appsec_review.jobs.job_openvex_export import job as job_mod
from appsec_review.jobs.job_openvex_export import reporting
from appsec_review.jobs.job_openvex_export.projection import assemble_export
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from appsec_review.runtime import UnitContext
from tests.openvex_input_support import AcceptedInputDisk
from tests.openvex_support import (
    OUTPUT_PREFIX,
    RELEASE,
    ROOT,
    enabled_settings,
    fixture_id,
    fixture_ref,
    make_verified_inputs,
)
from tests.test_openvex_job_units import ExportUnits, altered_handoff


def test_contract_helpers_and_frozen_records_reject_invalid_shapes() -> None:
    with pytest.raises(ValueError, match="must be a string"):
        c.validate_text(123, max_bytes=16, field="author")  # type: ignore[arg-type]
    assert c.validate_text("", max_bytes=16, field="role", empty=True) == ""

    with pytest.raises(ValueError, match="encoded controls"):
        c.validate_repository_iri("https://example.test/%00repo")
    with pytest.raises(ValueError, match="invalid authority|invalid port|without credentials"):
        c.validate_repository_iri("https://bad_host/repo")
    with pytest.raises(ValueError, match="valid URN"):
        c.validate_repository_iri("urn:x:repo")
    with pytest.raises(ValueError, match="https: or urn:"):
        c.validate_repository_iri("http://example.test/repo")

    snap = "a" * 64
    with pytest.raises(ValueError, match="claim identity"):
        c.vulnerability_id("https://example.test/repo", snap, "not-a-claim")
    with pytest.raises(ValueError, match="must not hash its own @id"):
        c.document_id({"@id": "x"})

    with pytest.raises(ValueError, match="path and sha256"):
        c.ArtifactRef.from_mapping({"path": "data/a.json"})
    with pytest.raises(ValueError, match="path, sha256 and size_bytes"):
        c.SizedArtifactRef.from_mapping({"path": "data/a.json", "sha256": snap})

    verified = make_verified_inputs()
    prov_json = verified.provenance.to_json()
    with pytest.raises(ValueError, match="documented keys"):
        c.ExportProvenance.from_mapping({"gate": prov_json["gate"]})
    bad_prov = dict(prov_json, resolved_config_sha256="b" * 64)
    with pytest.raises(ValueError, match="disagrees with its reference"):
        c.ExportProvenance.from_mapping(bad_prov)
    with pytest.raises(ValueError, match="artifact reference"):
        replace(verified.provenance, gate="not-a-ref")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="accepted snapshot"):
        c.SourceIdentity("https://example.test/repo", c.RepositoryIdentityBasis.SOURCE_SNAPSHOT, snap, None, ())
    with pytest.raises(ValueError, match="exact artifact reference"):
        c.SourceIdentity("https://example.test/repo", c.RepositoryIdentityBasis.ACCEPTED_ACQUISITION, snap, None, ())
    with pytest.raises(ValueError, match="path/sha256 reference"):
        c.SourceIdentity(
            "https://example.test/repo",
            c.RepositoryIdentityBasis.ACCEPTED_ACQUISITION,
            snap,
            c.SizedArtifactRef("data/acq.json", snap, 1),  # type: ignore[arg-type]
            (),
        )
    with pytest.raises(ValueError, match="bounded sequence"):
        c.SourceIdentity(
            "https://example.test/repo", c.RepositoryIdentityBasis.OPERATOR_DECLARED, snap, None, "not-seq"  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="documented keys"):
        c.SourceIdentity.from_mapping({"repository_iri": "https://example.test/repo"})

    finding = verified.findings[0]
    with pytest.raises(ValueError, match="gate finding object"):
        c.VerifiedFinding("bad", (), ())  # type: ignore[arg-type]
    bad_proj = dict(finding.projection, finding_package_id="bad")
    with pytest.raises(ValueError, match="invalid finding_package_id"):
        c.VerifiedFinding(bad_proj, (), ())
    contradicting = dict(finding.projection, bucket="publishable", state="supported")
    with pytest.raises(ValueError, match="contradicts its bucket"):
        c.VerifiedFinding(contradicting, (), ())
    with pytest.raises(ValueError, match="bounded artifact references"):
        c.VerifiedFinding(finding.projection, ("bad",), ())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="documented keys"):
        c.VerifiedFinding.from_mapping({"projection": finding.projection})

    with pytest.raises(ValueError, match="frozen provenance and source identity"):
        replace(verified, provenance="bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="exact gate object"):
        replace(verified, gate="bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="expected schema and run"):
        replace(verified, run_id="other-run")
    gate_no_caps = {k: v for k, v in verified.gate.items() if k != "capabilities"}
    with pytest.raises(ValueError, match="strict capability and attachment context"):
        replace(verified, gate=gate_no_caps)
    with pytest.raises(ValueError, match="frozen finding records"):
        replace(verified, findings=("bad",))  # type: ignore[arg-type]


def test_export_bundle_report_view_and_output_reference_guards() -> None:
    settings = enabled_settings()
    verified = make_verified_inputs(settings=settings)
    bundle = assemble_export(verified, settings, RELEASE, output_prefix=OUTPUT_PREFIX)

    with pytest.raises(ValueError, match="only a no-statements document may be absent"):
        replace(bundle, manifest=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="canonical bytes and sized references"):
        replace(bundle, manifest="not-mapping")  # type: ignore[arg-type]
    oversized = b"x" * (c.MAX_RESULT_BYTES + 1)
    with pytest.raises(ValueError, match="hard byte bound"):
        replace(
            bundle,
            result_bytes=oversized,
            result_ref=c.SizedArtifactRef(bundle.result_ref.path, hashlib.sha256(oversized).hexdigest(), len(oversized)),
        )

    assert bundle.document_ref is not None
    handoff_ref = fixture_ref("handoff")
    with pytest.raises(ValueError, match="accepted references and outcome"):
        c.ExportReportView(
            c.ExportReportState.AVAILABLE, None, handoff_ref, bundle.result_ref, bundle.manifest_ref,
            bundle.document_ref, 1, 1, 0, (),
        )
    with pytest.raises(ValueError, match="bounded counts"):
        c.ExportReportView(
            c.ExportReportState.AVAILABLE, c.ExportOutcome.EXPORTED, handoff_ref, bundle.result_ref,
            bundle.manifest_ref, bundle.document_ref, -1, 1, 0, (),
        )
    with pytest.raises(ValueError, match="genuine no_statements"):
        c.ExportReportView(
            c.ExportReportState.NO_STATEMENTS, c.ExportOutcome.NO_STATEMENTS, handoff_ref, bundle.result_ref,
            bundle.manifest_ref, bundle.document_ref, 0, 0, 0, (),
        )
    with pytest.raises(ValueError, match="nonempty document"):
        c.ExportReportView(
            c.ExportReportState.AVAILABLE, c.ExportOutcome.EXPORTED, handoff_ref, bundle.result_ref,
            bundle.manifest_ref, None, 1, 1, 0, (),
        )
    with pytest.raises(ValueError, match="must not expose output links"):
        c.ExportReportView(
            c.ExportReportState.DISABLED, None, None, None, None, None, 0, None, None, (),
        )
    with pytest.raises(ValueError, match="bounded sequence"):
        c.ExportReportView(c.ExportReportState.DISABLED, None, None, None, None, None, None, None, None, "bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="invalid report gap token"):
        c.ExportReportView(c.ExportReportState.DISABLED, None, None, None, None, None, None, None, None, ("BAD GAP",))

    with pytest.raises(ValueError, match="unsupported OpenVEX output filename"):
        c.output_reference(OUTPUT_PREFIX, "other.json", b"{}")
    with pytest.raises(ValueError, match="canonical bytes"):
        c.output_reference(OUTPUT_PREFIX, c.RESULT_NAME, "{}")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="hard byte bound"):
        c.output_reference(OUTPUT_PREFIX, c.RESULT_NAME, oversized)


def test_job_validate_write_idempotence_and_error_classifications(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config(ROOT / "appsec-review.toml", profile="dev", overlay="")
    job_cfg = replace(config.job(c.JOB_ID), settings=enabled_settings().to_mapping())
    job_mod._validate(SimpleNamespace(config=job_cfg), None)

    bad_cfg = SimpleNamespace(
        settings=enabled_settings().to_mapping(),
        steps=("load",),
        step=lambda _s: SimpleNamespace(tasks=("verify_inputs",)),
    )
    with pytest.raises(ValueError, match="topology does not match"):
        job_mod._validate(SimpleNamespace(config=bad_cfg), None)

    disk = AcceptedInputDisk(tmp_path, monkeypatch, buckets=())
    units = ExportUnits(disk)
    step_dir = units.context.attempt_root / "steps" / "load" / "tasks" / "verify_inputs"
    step_dir.mkdir(parents=True, exist_ok=True)
    uctx = UnitContext(units.context, "load.verify_inputs", "load", "verify_inputs", step_dir, {})

    out_path = step_dir / "sample.json"
    ref1 = job_mod._write(uctx, out_path, b'{"ok":true}\n')
    ref2 = job_mod._write(uctx, out_path, b'{"ok":true}\n')
    assert ref1 == ref2
    with pytest.raises(c.ExportError, match="changed after acceptance"):
        job_mod._write(uctx, out_path, b'{"ok":false}\n')
    with patch("appsec_review.jobs.job_openvex_export.job.read_output", return_value=b"different"):
        with pytest.raises(c.ExportError, match="conflicts with existing bytes"):
            job_mod._write(uctx, out_path, b'{"ok":true}\n')

    symlink_path = step_dir / "link.json"
    symlink_path.symlink_to(out_path)
    with pytest.raises(c.ExportError) as exc_info:
        job_mod._write(uctx, symlink_path, b"{}")
    assert exc_info.value.reason == c.ExportFailureReason.INPUT_TAMPERED
    symlink_path.unlink()

    # Empty export (no_statements) must reject an unexpected openvex.json placed before publish
    units.assemble()
    unexpected_doc = units.context.attempt_root / "steps" / "export" / "tasks" / "assemble" / c.DOCUMENT_NAME
    unexpected_doc.write_bytes(b"{}")
    unexpected_doc.chmod(0o600)
    with pytest.raises(c.ExportError, match="unexpected document") as exc_info:
        units.execute("acceptance.publish_handoff")
    assert exc_info.value.reason == c.ExportFailureReason.IDENTITY_CONFLICT
    unexpected_doc.unlink()

    # Post-handler monotonic deadline check in measured()
    clock = iter([100.0, 100.0 + disk.settings.timeout_seconds + 1.0])
    with patch.object(job_mod, "time", SimpleNamespace(monotonic=lambda: next(clock))):
        with pytest.raises(c.ExportError, match="deadline exceeded") as exc_info:
            units.execute("acceptance.publish_handoff")
    assert exc_info.value.reason == c.ExportFailureReason.TIMED_OUT

    # Non-ExportError exceptions in measured() emit OPENVEX_EXPORT_FAILED with mapped reasons
    for raised in (OSError("disk error"), ValueError("bad value"), RuntimeError("boom")):
        with patch("appsec_review.jobs.job_openvex_export.job.verify_inputs", side_effect=raised):
            with pytest.raises(type(raised)):
                units.execute("load.verify_inputs")


def test_schema_tamper_after_registry_and_reprove_stale_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_copy = tmp_path / "repo"
    schema_dst = repo_copy / "docs" / "schemas"
    schema_dst.mkdir(parents=True)
    shutil.copytree(ROOT / "docs" / "schemas" / "openvex-export", schema_dst / "openvex-export")
    shutil.copytree(ROOT / "docs" / "schemas" / "final-report", schema_dst / "final-report")
    os.chmod(tmp_path, 0o700)

    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    (schema_dst / "openvex-export" / "common.schema.json").write_bytes(b"{}")

    with patch("appsec_review.jobs.job_openvex_export.job.schema_resource_root", return_value=schema_dst / "openvex-export"):
        with pytest.raises(c.ExportError, match="offline schema bytes changed") as exc_info:
            units.execute("load.verify_inputs")
    assert exc_info.value.reason == c.ExportFailureReason.INPUT_TAMPERED


def test_reporting_hardlink_frozen_settings_and_handoff_tamper_guards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    disk = AcceptedInputDisk(tmp_path, monkeypatch)
    units = ExportUnits(disk)
    units.assemble()
    handoff = units.accept()

    # frozen_configuration / frozen_export_settings with and without job_openvex_export configured
    settings_loaded, release = reporting.frozen_export_settings(disk.root)
    assert isinstance(settings_loaded, OpenVexExportSettings)
    assert isinstance(release, str)

    # Hard-linked output file rejected by read_output
    result_path = disk.root / units.outputs["export.assemble"]["artifact"]["path"]
    hardlink = result_path.parent / "hardlink-result.json"
    os.link(result_path, hardlink)
    try:
        with pytest.raises(c.ExportError, match="private regular file") as exc_info:
            reporting.read_output(
                disk.root,
                c.ArtifactRef.from_mapping(units.outputs["export.assemble"]["artifact"]),
                disk.settings,
                max_bytes=c.MAX_RESULT_BYTES,
            )
        assert exc_info.value.reason == c.ExportFailureReason.INPUT_TAMPERED
    finally:
        hardlink.unlink()

    # Invalid common envelope rejected as SCHEMA_INVALID
    bad_env = deepcopy(handoff)
    bad_env["run_id"] = "wrong-run"
    with pytest.raises(c.ExportError, match="common envelope is invalid") as exc_info:
        reporting.read_accepted_export(disk.root, altered_handoff(disk, bad_env), disk.settings, ROOT)
    assert exc_info.value.reason == c.ExportFailureReason.SCHEMA_INVALID

    # Accepted runtime artifacts exceeding max_bindings -> BOUND_EXCEEDED
    tight_settings = enabled_settings(max_bindings=2)
    with pytest.raises(c.ExportError, match="exceeds its bounds") as exc_info:
        reporting.read_accepted_export(disk.root, units.reference, tight_settings, ROOT)
    assert exc_info.value.reason == c.ExportFailureReason.BOUND_EXCEEDED

    # Accepted handoff missing OpenVEX result schema -> SCHEMA_INVALID
    bad_pub = deepcopy(handoff)
    bad_pub["outputs"]["acceptance.publish_handoff"]["schema"] = "wrong/1"
    with pytest.raises(c.ExportError, match="does not publish an OpenVEX result") as exc_info:
        reporting.read_accepted_export(disk.root, altered_handoff(disk, bad_pub), disk.settings, ROOT)
    assert exc_info.value.reason == c.ExportFailureReason.SCHEMA_INVALID

    # Duplicate artifact path in accepted["artifacts"] -> IDENTITY_CONFLICT
    dup_art = deepcopy(handoff)
    dup_art["artifacts"] = [*dup_art["artifacts"], dict(dup_art["artifacts"][0])]
    with patch("appsec_review.jobs.job_openvex_export.reporting.decode_handoff", side_effect=lambda h, **_: h):
        with pytest.raises(c.ExportError, match="repeats an artifact path") as exc_info:
            reporting.read_accepted_export(disk.root, altered_handoff(disk, dup_art), disk.settings, ROOT)
    assert exc_info.value.reason == c.ExportFailureReason.IDENTITY_CONFLICT

    # Runtime artifact inventory disagrees with verified.input_inventory -> IDENTITY_CONFLICT
    conflict_art = deepcopy(handoff)
    schema_item = next(a for a in conflict_art["artifacts"] if "/schemas/openvex-export/" in a["path"])
    schema_item["sha256"] = "f" * 64
    with patch("appsec_review.jobs.job_openvex_export.reporting.decode_handoff", side_effect=lambda h, **_: h):
        with pytest.raises(c.ExportError, match="inventories disagree") as exc_info:
            reporting.read_accepted_export(disk.root, altered_handoff(disk, conflict_art), disk.settings, ROOT)
    assert exc_info.value.reason == c.ExportFailureReason.IDENTITY_CONFLICT

    # Missing result artifact in accepted["artifacts"] -> INPUT_TAMPERED (or handoff integrity error)
    # Upstream pointer missing -> State.STALE
    gate_pointer = disk.root / "data" / "jobs" / "job_final_publication_gate" / "latest.json"
    saved_gate_ptr = gate_pointer.read_bytes()
    gate_pointer.unlink()
    try:
        stale_view = units.view()
        assert stale_view.state == c.ExportReportState.STALE
        assert stale_view.gaps == ("openvex_export_stale",)
    finally:
        gate_pointer.write_bytes(saved_gate_ptr)
        gate_pointer.chmod(0o600)

    # Corrupt upstream pointer -> INPUT_TAMPERED
    with patch("appsec_review.jobs.job_openvex_export.reporting.accepted_handoff", side_effect=[
        reporting.accepted_handoff(disk.root, c.JOB_ID),
        ValueError("corrupt upstream pointer"),
    ]):
        with pytest.raises(c.ExportError, match="upstream pointer cannot be verified") as exc_info:
            units.view()
        assert exc_info.value.reason == c.ExportFailureReason.INPUT_TAMPERED

    # Pointer changing concurrently during load_export -> INPUT_STALE
    orig_accepted = reporting.accepted_handoff(disk.root, c.JOB_ID)
    with patch("appsec_review.jobs.job_openvex_export.reporting.accepted_handoff", side_effect=[
        orig_accepted,
        reporting.accepted_handoff(disk.root, "job_final_publication_gate"),
        reporting.accepted_handoff(disk.root, "job_inference_security_review"),
        None,
    ]):
        with pytest.raises(c.ExportError, match="changed during report loading") as exc_info:
            units.view()
        assert exc_info.value.reason == c.ExportFailureReason.INPUT_STALE

    # Corrupt OpenVEX pointer -> INPUT_TAMPERED
    with patch("appsec_review.jobs.job_openvex_export.reporting.accepted_handoff", return_value=None):
        with pytest.raises(c.ExportError, match="pointer is unsafe") as exc_info:
            units.view()
        assert exc_info.value.reason == c.ExportFailureReason.INPUT_TAMPERED

    with patch("appsec_review.jobs.job_openvex_export.reporting.accepted_handoff", side_effect=ValueError("bad ptr")):
        with pytest.raises(c.ExportError, match="pointer cannot be verified") as exc_info:
            units.view()
        assert exc_info.value.reason == c.ExportFailureReason.INPUT_TAMPERED
