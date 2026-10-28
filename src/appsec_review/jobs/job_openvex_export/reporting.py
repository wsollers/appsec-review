"""Re-prove accepted exports; file presence and domain events never imply acceptance."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from appsec_review.indexing.store import accepted_handoff

from .contracts import (
    ArtifactRef, ExportBundle, ExportError, ExportFailureReason as Reason, ExportOutcome,
    ExportPhase, ExportReportState as State, ExportReportView, JOB_ID, MAX_RESULT_BYTES,
    OPENVEX_EXPORT_HANDOFF_SCHEMA, SizedArtifactRef, VerifiedInputs, parse_json_bytes,
)
from .inputs import BoundedInputReader, reprove_inputs
from .settings import OpenVexExportSettings
from .validation import schema_registry, validate_export


def read_output(run_root: Path, reference: ArtifactRef, settings: OpenVexExportSettings, *,
                max_bytes: int, phase: ExportPhase = ExportPhase.ACCEPT) -> bytes:
    """Read one output with its own limit; manifests may exceed an individual input limit."""
    reader = BoundedInputReader(run_root, settings, phase=phase)
    path = reader.path(reference.path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ExportError("export artifact is not a private regular file", reason=Reason.INPUT_TAMPERED,
                              phase=phase)
        if before.st_size > max_bytes:
            raise ExportError("export artifact exceeds its byte bound", reason=Reason.BOUND_EXCEEDED, phase=phase)
        payload = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    current = reader.path(reference.path).stat()
    if (after.st_nlink != 1 or current.st_nlink != 1
            or len(payload) > max_bytes or len(payload) != before.st_size
            or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
            or hashlib.sha256(payload).hexdigest() != reference.sha256
            or isinstance(reference, SizedArtifactRef) and len(payload) != reference.size_bytes):
        raise ExportError("export artifact changed after acceptance", reason=Reason.INPUT_TAMPERED, phase=phase)
    return payload


def frozen_configuration(run_root: Path) -> tuple[dict[str, Any], ArtifactRef]:
    reader = BoundedInputReader(run_root, OpenVexExportSettings(), phase=ExportPhase.LOAD)
    manifest = reader.json(reader.pin("data/configuration/manifest.json").reference)
    reference = ArtifactRef("data/configuration/resolved.json", manifest["resolved_sha256"])
    document = parse_json_bytes(reader.read(reference), max_bytes=reader.settings.max_artifact_bytes)
    return document, reference


def frozen_export_settings(run_root: Path) -> tuple[OpenVexExportSettings | None, str]:
    configuration, _ = frozen_configuration(run_root)
    job = configuration.get("jobs", {}).get(JOB_ID)
    settings = None if job is None else OpenVexExportSettings.from_mapping(job["settings"])
    releases = configuration.get("review_policy", {}).get("releases", {})
    return settings, releases.get(JOB_ID, releases.get("platform", "undeclared"))


def _json_output(run_root: Path, reference: ArtifactRef, settings: OpenVexExportSettings, *,
                 max_bytes: int) -> tuple[dict[str, Any], bytes]:
    payload = read_output(run_root, reference, settings, max_bytes=max_bytes)
    return parse_json_bytes(payload, max_bytes=max_bytes), payload


def upstream_inputs(verified: VerifiedInputs) -> VerifiedInputs:
    """Schema snapshots are export bindings, not the incoming accepted review boundary."""
    return replace(verified, input_inventory=tuple(
        ref for ref in verified.input_inventory if "/steps/load/tasks/verify_inputs/schemas/" not in ref.path))


def read_accepted_export(run_root: Path, handoff: ArtifactRef, settings: OpenVexExportSettings,
                         repository_root: Path) -> ExportBundle:
    """Verify an immutable historical acceptance, without requiring its pointer to be latest."""
    try:
        return _read_accepted_export(run_root, handoff, settings, repository_root)
    except (ValueError, KeyError, TypeError) as exc:
        raise ExportError("accepted OpenVEX structure is invalid", reason=Reason.SEMANTIC_INVALID,
                          phase=ExportPhase.ACCEPT) from exc


def _read_accepted_export(run_root: Path, handoff: ArtifactRef, settings: OpenVexExportSettings,
                          repository_root: Path) -> ExportBundle:
    schema_registry(repository_root=repository_root)
    reader = BoundedInputReader(run_root, settings, phase=ExportPhase.ACCEPT)
    accepted = reader.json(handoff)
    if (accepted.get("schema") != "appsec-review/job-handoff/1"
            or accepted.get("job_id") != JOB_ID or accepted.get("status") != "ACCEPTED"
            or accepted.get("schema_identity") != OPENVEX_EXPORT_HANDOFF_SCHEMA):
        raise ExportError("unsupported accepted OpenVEX handoff", reason=Reason.SCHEMA_INVALID,
                          phase=ExportPhase.ACCEPT)
    outputs = accepted.get("outputs", {})
    published = outputs.get("acceptance.publish_handoff", {})
    if published.get("schema") != OPENVEX_EXPORT_HANDOFF_SCHEMA:
        raise ExportError("accepted handoff does not publish an OpenVEX result", reason=Reason.SCHEMA_INVALID,
                          phase=ExportPhase.ACCEPT)
    verified_ref = ArtifactRef.from_mapping(outputs["load.verify_inputs"]["artifact"])
    verified_document, _ = _json_output(run_root, verified_ref, settings, max_bytes=settings.max_manifest_bytes)
    verified = VerifiedInputs.from_mapping(verified_document)
    if verified.settings_sha256 != settings.settings_sha256():
        raise ExportError("accepted export uses different settings", reason=Reason.IDENTITY_CONFLICT,
                          phase=ExportPhase.ACCEPT)
    for reference in verified.input_inventory:
        reader.read(reference)
    reader.reprove()
    result_reference = ArtifactRef.from_mapping(published["artifact"])
    result, result_bytes = _json_output(run_root, result_reference, settings, max_bytes=MAX_RESULT_BYTES)
    manifest_ref = SizedArtifactRef.from_mapping(result["manifest"])
    manifest, manifest_bytes = _json_output(run_root, manifest_ref, settings, max_bytes=settings.max_manifest_bytes)
    document_ref = None if result["document"] is None else SizedArtifactRef.from_mapping(result["document"])
    document, document_bytes = (None, None) if document_ref is None else _json_output(
        run_root, document_ref, settings, max_bytes=settings.max_document_bytes)
    bundle = ExportBundle(
        document, manifest, result, document_bytes, manifest_bytes, result_bytes, document_ref,
        manifest_ref, SizedArtifactRef(result_reference.path, result_reference.sha256, len(result_bytes)),
    )
    validate_export(bundle, verified, settings)
    implementation_identity = accepted.get("implementation_identity")
    if implementation_identity is None:
        implementation_identity = "undeclared"
    if (published.get("item_count") != result["statement_count"]
            or accepted.get("resolved_config_sha256") != verified.provenance.resolved_config_sha256
            or accepted.get("upstream_handoff_sha256", {}).get("job_final_publication_gate")
            != verified.provenance.gate_handoff.sha256
            or accepted.get("upstream_handoff_sha256", {}).get("job_inference_security_review")
            != verified.provenance.review_handoff.sha256
            or implementation_identity != manifest["provenance"]["exporter_release"]):
        raise ExportError("accepted export identities disagree", reason=Reason.IDENTITY_CONFLICT,
                          phase=ExportPhase.ACCEPT)
    artifacts = {}
    bounds = {
        verified_ref.path: settings.max_manifest_bytes,
        bundle.result_ref.path: MAX_RESULT_BYTES, bundle.manifest_ref.path: settings.max_manifest_bytes,
        **({bundle.document_ref.path: settings.max_document_bytes} if bundle.document_ref else {}),
    }
    for item in accepted.get("artifacts", []):
        reference = ArtifactRef(item["path"], item["sha256"])
        if reference.path in artifacts:
            raise ExportError("accepted handoff repeats an artifact path", reason=Reason.IDENTITY_CONFLICT,
                              phase=ExportPhase.ACCEPT)
        artifacts[reference.path] = reference.sha256
        read_output(run_root, reference, settings, max_bytes=bounds.get(reference.path, settings.max_artifact_bytes))
    for reference in (verified_ref, bundle.result_ref, bundle.manifest_ref, bundle.document_ref):
        if reference is not None and artifacts.get(reference.path) != reference.sha256:
            raise ExportError("export artifact is not bound by its accepted handoff", reason=Reason.INPUT_TAMPERED,
                              phase=ExportPhase.ACCEPT)
    if result["run_id"] != verified.run_id or result["gate"] != verified.provenance.gate.to_json():
        raise ExportError("export result belongs to another reviewed gate", reason=Reason.IDENTITY_CONFLICT,
                          phase=ExportPhase.ACCEPT)
    return bundle


def _unavailable(state: State, *gaps: str) -> ExportReportView:
    return ExportReportView(state, None, None, None, None, None, None, None, None, gaps)


def load_export(run_root: Path, settings: OpenVexExportSettings, repository_root: Path, *,
                exporter_release: str, gate_handoff: Mapping[str, str] | None = None) -> ExportReportView:
    if not settings.enabled:
        return _unavailable(State.DISABLED)
    reader = BoundedInputReader(run_root, settings, phase=ExportPhase.ACCEPT)
    pointer = "data/jobs/job_openvex_export/latest.json"
    try:
        reader.path(pointer)
    except ExportError as exc:
        if exc.reason == Reason.INPUT_MISSING:
            return _unavailable(State.NOT_RUN, "openvex_export_not_run")
        raise
    try:
        accepted = accepted_handoff(run_root, JOB_ID)
    except (ValueError, OSError) as exc:
        raise ExportError("accepted OpenVEX pointer cannot be verified", reason=Reason.INPUT_TAMPERED,
                          phase=ExportPhase.ACCEPT) from exc
    if accepted is None:
        raise ExportError("existing OpenVEX pointer is unsafe", reason=Reason.INPUT_TAMPERED,
                          phase=ExportPhase.ACCEPT)
    reference = ArtifactRef(accepted.path, accepted.sha256)
    bundle = read_accepted_export(run_root, reference, settings, repository_root)
    provenance = bundle.manifest["provenance"]
    _, configuration_ref = frozen_configuration(run_root)
    if (provenance["resolved_config_sha256"] != configuration_ref.sha256
            or provenance["exporter_release"] != exporter_release
            or gate_handoff is not None and provenance["gate_handoff"] != dict(gate_handoff)):
        return _unavailable(State.STALE, "openvex_export_stale")
    for job_id, key in (("job_final_publication_gate", "gate_handoff"),
                        ("job_inference_security_review", "review_handoff")):
        pointer_path = f"data/jobs/{job_id}/latest.json"
        try:
            reader.path(pointer_path)
        except ExportError as exc:
            if exc.reason == Reason.INPUT_MISSING:
                return _unavailable(State.STALE, "openvex_export_stale")
            raise
        try:
            current = accepted_handoff(run_root, job_id)
        except (ValueError, OSError) as exc:
            raise ExportError("current upstream pointer cannot be verified", reason=Reason.INPUT_TAMPERED,
                              phase=ExportPhase.ACCEPT) from exc
        if current is None or {"path": current.path, "sha256": current.sha256} != provenance[key]:
            return _unavailable(State.STALE, "openvex_export_stale")
    verified_ref = ArtifactRef.from_mapping(accepted.handoff["outputs"]["load.verify_inputs"]["artifact"])
    verified_document, _ = _json_output(run_root, verified_ref, settings, max_bytes=settings.max_manifest_bytes)
    verified = VerifiedInputs.from_mapping(verified_document)
    reprove_inputs(run_root, upstream_inputs(verified), settings, repository_root)
    reader.read(reader.pin(pointer).reference)
    latest = accepted_handoff(run_root, JOB_ID)
    if latest is None or latest.sha256 != reference.sha256 or latest.path != reference.path:
        raise ExportError("OpenVEX acceptance changed during report loading", reason=Reason.INPUT_STALE,
                          phase=ExportPhase.ACCEPT)
    outcome = ExportOutcome(bundle.result["outcome"])
    return ExportReportView(
        State.NO_STATEMENTS if outcome == ExportOutcome.NO_STATEMENTS else State.AVAILABLE, outcome,
        reference, bundle.result_ref, bundle.manifest_ref, bundle.document_ref,
        bundle.result["statement_count"], bundle.result["included_findings"], bundle.result["excluded_findings"],
        tuple(bundle.result["gaps"]),
    )


def report_section(view: ExportReportView) -> dict[str, Any]:
    reasons = {
        State.DISABLED: "OpenVEX export is disabled in this run's frozen configuration.",
        State.NOT_RUN: "OpenVEX export is enabled but has no accepted result; no safety verdict is implied.",
        State.STALE: "The accepted OpenVEX export is stale; rerun export before linking its outputs.",
        State.NO_STATEMENTS: "No gate-publishable confirmed finding was eligible; this is not a clean verdict.",
        State.AVAILABLE: "Affected-only statements for the exact reviewed source snapshot and configuration.",
    }
    def reference(value: ArtifactRef | None) -> dict[str, str] | None:
        return None if value is None else {"path": value.path, "sha256": value.sha256}

    return {
        "state": view.state.value, "reason": reasons[view.state],
        "handoff": reference(view.handoff), "result": reference(view.result),
        "manifest": reference(view.manifest), "document": reference(view.document),
        "statement_count": view.statement_count, "included_findings": view.included_findings,
        "excluded_findings": view.excluded_findings,
    }
