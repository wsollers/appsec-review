"""Re-prove accepted exports; file presence and domain events never imply acceptance."""
from __future__ import annotations

from dataclasses import replace
from collections import Counter
import hashlib
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from jsonschema import ValidationError

from appsec_review.indexing.store import accepted_handoff
from appsec_review.interchange import HANDOFF_SCHEMA
from appsec_review.runtime.inputs import decode_consumed_handoff as decode_handoff
from appsec_review.runtime.handoff import verify_handoff_integrity
from appsec_review.runtime.consume import upstream_scope

from .contracts import (
    ArtifactRef, ExportBundle, ExportError, ExportFailureReason as Reason, ExportOutcome,
    ExportPhase, ExportReportState as State, ExportReportView, JOB_ID, MAX_RESULT_BYTES,
    OPENVEX_EXPORT_HANDOFF_SCHEMA, SizedArtifactRef, VerifiedInputs, canonical_bytes, document_id,
    parse_json_bytes, statement_id,
)
from . import dependencies
from .datasets import CONTRACT
from .inputs import (
    BoundedInputReader, _pin_configuration_snapshot, _require, compatible_settings, reprove_inputs,
)
from .settings import OpenVexExportSettings
from .validation import schema_registry, schema_validator, validate_export


def read_output(run_root: Path, reference: ArtifactRef, settings: OpenVexExportSettings, *,
                max_bytes: int | None, phase: ExportPhase = ExportPhase.ACCEPT) -> bytes:
    """Read a bound output, or an input binding without an input-byte ceiling."""
    reader = BoundedInputReader(run_root, settings, phase=phase)
    path = reader.path(reference.path)
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ExportError("export artifact is not a private regular file", reason=Reason.INPUT_TAMPERED,
                              phase=phase)
        if max_bytes is not None and before.st_size > max_bytes:
            raise ExportError("export artifact exceeds its byte bound", reason=Reason.BOUND_EXCEEDED, phase=phase)
        chunks: list[bytes] = []
        size = 0
        limit = before.st_size if max_bytes is None else max_bytes
        while True:
            chunk = stream.read(min(65536, limit - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if max_bytes is not None and size > max_bytes:
                raise ExportError("export artifact exceeds its byte bound", reason=Reason.BOUND_EXCEEDED, phase=phase)
            if size > before.st_size:
                break
            chunks.append(chunk)
        payload = b"".join(chunks)
        after = os.fstat(stream.fileno())
    current = reader.path(reference.path).stat()
    if (after.st_nlink != 1 or current.st_nlink != 1
            or (max_bytes is not None and len(payload) > max_bytes) or len(payload) != before.st_size
            or before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
            or hashlib.sha256(payload).hexdigest() != reference.sha256
            or isinstance(reference, SizedArtifactRef) and len(payload) != reference.size_bytes):
        raise ExportError("export artifact changed after acceptance", reason=Reason.INPUT_TAMPERED, phase=phase)
    return payload


def frozen_configuration(
    run_root: Path, expected_sha256: str | None = None,
) -> tuple[dict[str, Any], ArtifactRef]:
    reader = BoundedInputReader(run_root, OpenVexExportSettings(), phase=ExportPhase.LOAD)
    _, reference, document = _pin_configuration_snapshot(
        reader, expected_sha256, missing_reason=Reason.CONFIGURATION_INVALID,
    )
    return document, reference


def frozen_export_settings(
    run_root: Path, expected_sha256: str | None = None,
) -> tuple[OpenVexExportSettings | None, str]:
    configuration, _ = frozen_configuration(run_root, expected_sha256)
    job = configuration.get("jobs", {}).get(JOB_ID)
    settings = None if job is None else OpenVexExportSettings.from_frozen_mapping(job["settings"])
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


def _recorded_settings(reader: BoundedInputReader, accepted: Mapping[str, Any]) -> OpenVexExportSettings:
    from appsec_review.runtime.configuration import (
        base_configuration_sha256, configuration_directory, configuration_snapshot,
    )
    identity = accepted["resolved_config_sha256"]
    try:
        base_sha = base_configuration_sha256(reader.root)
        directory = configuration_directory(reader.root, identity)
        if identity != base_sha:
            configuration_snapshot(reader.root, identity)
    except (OSError, ValueError) as exc:
        raise ExportError("accepted export configuration snapshot is invalid",
                          reason=Reason.INPUT_TAMPERED, phase=ExportPhase.ACCEPT) from exc
    config = reader.json(ArtifactRef((directory / "resolved.json").relative_to(reader.root).as_posix(), identity))
    recorded = OpenVexExportSettings.from_frozen_mapping(config["jobs"][JOB_ID]["settings"])
    _require(compatible_settings(recorded, reader.settings), "accepted export uses different settings",
             Reason.IDENTITY_CONFLICT, phase=ExportPhase.ACCEPT)
    return recorded


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
    if (accepted.get("schema") != HANDOFF_SCHEMA
            or accepted.get("job_id") != JOB_ID or accepted.get("status") != "ACCEPTED"
            or accepted.get("schema_identity") != OPENVEX_EXPORT_HANDOFF_SCHEMA):
        raise ExportError("unsupported accepted OpenVEX handoff", reason=Reason.SCHEMA_INVALID,
                          phase=ExportPhase.ACCEPT)
    try:
        accepted = decode_handoff(accepted, run_id=run_root.name, job_id=JOB_ID)
    except ValueError as exc:
        raise ExportError("accepted OpenVEX common envelope is invalid", reason=Reason.SCHEMA_INVALID,
                          phase=ExportPhase.ACCEPT) from exc
    caller_max_bindings = settings.max_bindings
    settings = _recorded_settings(reader, accepted)
    if len(accepted["artifacts"]) > min(settings.max_bindings, caller_max_bindings):
        raise ExportError("accepted runtime artifact inventory exceeds its bounds", reason=Reason.BOUND_EXCEEDED,
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
        reader.verify(reference)
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
    implementation_identity = accepted["implementation_identity"]
    from appsec_review.runtime.configuration import configurations_compatible
    if (published.get("item_count") != result["statement_count"]
            or not configurations_compatible(
                run_root, accepted["resolved_config_sha256"], verified.provenance.resolved_config_sha256)
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
    companion = published.get("dependencies")
    if isinstance(companion, Mapping):
        bounds[ArtifactRef.from_mapping(companion["artifact"]).path] = MAX_RESULT_BYTES
        if companion.get("document") is not None:
            bounds[ArtifactRef.from_mapping(companion["document"]).path] = settings.max_document_bytes
    admitted = {reference.path: reference for reference in verified.input_inventory}
    for item in accepted["artifacts"]:
        reference = SizedArtifactRef.from_mapping(item)
        if reference.path in artifacts:
            raise ExportError("accepted handoff repeats an artifact path", reason=Reason.IDENTITY_CONFLICT,
                              phase=ExportPhase.ACCEPT)
        artifacts[reference.path] = reference.sha256
        if reference.path in admitted and admitted[reference.path] != reference:
            raise ExportError("runtime and export inventories disagree", reason=Reason.IDENTITY_CONFLICT,
                              phase=ExportPhase.ACCEPT)
        admitted[reference.path] = reference
    if len(admitted) > min(settings.max_bindings, caller_max_bindings):
        raise ExportError("accepted export inventory exceeds its bounds", reason=Reason.BOUND_EXCEEDED,
                          phase=ExportPhase.ACCEPT)
    for item in accepted["artifacts"]:
        reference = SizedArtifactRef.from_mapping(item)
        read_output(run_root, reference, settings, max_bytes=bounds.get(reference.path))
    verify_handoff_integrity(run_root, accepted)
    reader.reprove()
    for item in accepted["artifacts"]:
        reference = SizedArtifactRef.from_mapping(item)
        read_output(run_root, reference, settings, max_bytes=bounds.get(reference.path))
    for reference in (verified_ref, bundle.result_ref, bundle.manifest_ref, bundle.document_ref):
        if reference is not None and artifacts.get(reference.path) != reference.sha256:
            raise ExportError("export artifact is not bound by its accepted handoff", reason=Reason.INPUT_TAMPERED,
                              phase=ExportPhase.ACCEPT)
    if result["run_id"] != verified.run_id or result["gate"] != verified.provenance.gate.to_json():
        raise ExportError("export result belongs to another reviewed gate", reason=Reason.IDENTITY_CONFLICT,
                          phase=ExportPhase.ACCEPT)
    return bundle


def read_accepted_dependency_export(
    run_root: Path, handoff: ArtifactRef, settings: OpenVexExportSettings, repository_root: Path,
) -> dict[str, Any] | None:
    """Verify historical companion accounting without consulting a newer producer pointer.

    Absent companion fields remain valid for primary-only historical handoffs. Existing
    companion schemas are verified as published, not regenerated with today's projection.
    """
    read_accepted_export(run_root, handoff, settings, repository_root)
    try:
        return _read_accepted_dependency_export(run_root, handoff, settings, repository_root)
    except ExportError:
        raise
    except ValidationError as exc:
        raise ExportError("accepted dependency export schema is invalid", reason=Reason.SCHEMA_INVALID,
                          phase=ExportPhase.ACCEPT) from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise ExportError("accepted dependency export structure is invalid", reason=Reason.SEMANTIC_INVALID,
                          phase=ExportPhase.ACCEPT) from exc


def _read_accepted_dependency_export(
    run_root: Path, handoff: ArtifactRef, settings: OpenVexExportSettings, repository_root: Path,
) -> dict[str, Any] | None:
    reader = BoundedInputReader(run_root, settings, phase=ExportPhase.ACCEPT)
    accepted = reader.json(handoff)
    settings = _recorded_settings(reader, accepted)
    outputs = accepted["outputs"]
    companion = outputs["acceptance.publish_handoff"].get("dependencies")
    if companion is None:
        return None

    def require(condition: bool, message: str, reason: Reason = Reason.IDENTITY_CONFLICT) -> None:
        _require(condition, message, reason, phase=ExportPhase.ACCEPT)

    require(isinstance(companion, dict), "accepted dependency publication is not an object")
    artifacts = {item["path"]: SizedArtifactRef.from_mapping(item) for item in accepted["artifacts"]}

    def bound_output(reference: ArtifactRef, limit: int) -> tuple[dict[str, Any], bytes]:
        require(reference.path in artifacts and artifacts[reference.path].sha256 == reference.sha256,
                "dependency export artifact is not bound by its accepted handoff")
        return _json_output(run_root, artifacts[reference.path], settings, max_bytes=limit)

    reference = ArtifactRef.from_mapping(companion["artifact"])
    result, payload = bound_output(reference, MAX_RESULT_BYTES)
    schema_validator("openvex-dependencies.schema.json", repository_root=repository_root).validate(result)
    require(canonical_bytes(result) == payload, "dependency accounting is not canonical", Reason.SEMANTIC_INVALID)
    require(companion == {
        "artifact": reference.to_json(), "document": result["document"],
        "gaps": result["gaps"], "statements_by_status": result["statements_by_status"],
    } and outputs["export.assemble"].get("dependencies") == companion,
        "dependency publication and accounting disagree")
    require(result["terminal_status"] == ("COMPLETED_WITH_GAPS" if result["gaps"] else "SUCCEEDED"),
            "dependency completion disagrees with its gaps", Reason.SEMANTIC_INVALID)
    verified_ref = ArtifactRef.from_mapping(outputs["load.verify_inputs"]["artifact"])
    verified_document, _ = bound_output(verified_ref, settings.max_manifest_bytes)
    verified = VerifiedInputs.from_mapping(verified_document)
    require(result["run_id"] == verified.run_id == run_root.name,
            "dependency accounting belongs to another run")
    pins = accepted["upstream_handoff_sha256"]
    require(pins.get(dependencies.DEPENDENCY_JOB) == result["source"]["handoff"]["sha256"],
            "dependency companion source was not admitted by the accepted export")
    with upstream_scope(run_root, JOB_ID, pins, contract=CONTRACT):
        for item in verified.input_inventory:
            reader.verify(item)
        loaded = dependencies.read_dependency_inputs(
            reader, repository_root, resolved_config_sha256=verified.provenance.resolved_config_sha256,
            target_snapshot=verified.source.target_snapshot)
        require(loaded is not None, "accepted dependency source is missing", Reason.INPUT_MISSING)
        assert loaded is not None
        source, source_ref, _ = loaded
        require(result["source"] == {
            "handoff": {"path": source.path, "sha256": source.sha256},
            "artifact": source_ref.to_json(), "gate": verified.provenance.gate.to_json(),
        } == outputs["load.verify_inputs"].get("dependency_source"),
            "dependency accounting source identities disagree")
        reader.reprove()
    inventory = dict(artifacts)
    for item in reader.inventory:
        require(item.path not in inventory or inventory[item.path] == item,
                "historical dependency inventories disagree")
        inventory[item.path] = item
    require(len(inventory) <= settings.max_bindings,
            "historical dependency inventory exceeds its bounds", Reason.BOUND_EXCEEDED)
    counts = dict.fromkeys(result["statements_by_status"], 0)
    if result["document"] is not None:
        document, document_bytes = bound_output(
            ArtifactRef.from_mapping(result["document"]), settings.max_document_bytes)
        schema_validator("upstream/openvex-v0.2.0.schema.json", repository_root=repository_root).validate(document)
        require(canonical_bytes(document) == document_bytes
                and document["@id"] == document_id({key: value for key, value in document.items() if key != "@id"}),
                "dependency document identity disagrees with its bytes", Reason.SEMANTIC_INVALID)
        for statement in document["statements"]:
            require(statement["status"] in counts and statement["@id"] == statement_id(
                document["author"], {key: value for key, value in statement.items() if key != "@id"}),
                "dependency statement identity or status is invalid", Reason.SEMANTIC_INVALID)
        counts.update(Counter(statement["status"] for statement in document["statements"]))
    require(counts == result["statements_by_status"],
            "dependency statement counts disagree with the document", Reason.SEMANTIC_INVALID)
    return result


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
    settings = _recorded_settings(reader, accepted.handoff)
    bundle = read_accepted_export(run_root, reference, settings, repository_root)
    provenance = bundle.manifest["provenance"]
    from appsec_review.runtime.configuration import configurations_compatible
    _, configuration_ref = frozen_configuration(run_root)
    try:
        config_compatible = configurations_compatible(
            run_root, provenance["resolved_config_sha256"], configuration_ref.sha256,
        )
    except (OSError, ValueError):
        config_compatible = False
    if (not config_compatible
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
    with upstream_scope(run_root, JOB_ID, accepted.handoff["upstream_handoff_sha256"], contract=CONTRACT):
        reprove_inputs(
            run_root, upstream_inputs(verified), settings, repository_root,
            resolved_config_sha256=verified.provenance.resolved_config_sha256,
        )
    reader.verify(reader.pin(pointer).reference)
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
