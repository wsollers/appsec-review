"""Model-free affected-only projection, with reproof immediately before runtime acceptance."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import time
from typing import Any, Callable, Mapping

from appsec_review.observability.spans import operation_span
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor

from .contracts import (
    ArtifactRef, DOCUMENT_NAME, ExportError, ExportFailureReason as Reason, ExportPhase,
    JOB_ID, MAX_RESULT_BYTES, OPENVEX_EXPORT_HANDOFF_SCHEMA, SCHEMA_SHA256,
    SizedArtifactRef, UPSTREAM_LICENSE_SHA256, UPSTREAM_LOCK_SHA256, VERIFIED_INPUTS_NAME,
    VerifiedInputs, canonical_bytes, json_body, normalize_timestamp, parse_json_bytes,
)
from .datasets import CONTRACT, DATASETS
from . import dependencies
from .inputs import BoundedInputReader, reprove_inputs, verify_inputs
from .projection import assemble_export
from .reporting import read_output, upstream_inputs
from .settings import OpenVexExportSettings
from .validation import schema_registry, schema_resource_root, schema_validator, validate_export

TOPOLOGY = {"load": ("verify_inputs",), "export": ("assemble",), "acceptance": ("publish_handoff",)}
_SCHEMA_DIRECTORY = "steps/load/tasks/verify_inputs/schemas/openvex-export"


def _settings(unit: UnitContext) -> OpenVexExportSettings:
    settings = OpenVexExportSettings.from_mapping(unit.job.config.settings)
    settings.require_enabled()
    return settings


def _release(unit: UnitContext) -> str:
    releases = unit.job.review_policy.releases.values
    return releases.get(JOB_ID, releases.get("platform", "undeclared"))


def _validate(context: Any, _result: Any) -> None:
    settings = OpenVexExportSettings.from_mapping(context.config.settings)
    settings.require_enabled()
    if tuple(context.config.steps) != tuple(TOPOLOGY) or any(
            tuple(context.config.step(step).tasks) != tasks for step, tasks in TOPOLOGY.items()):
        raise ValueError("OpenVEX task topology does not match central configuration")


def _write(unit: UnitContext, path: Path, payload: bytes) -> SizedArtifactRef:
    root = unit.job.run_root.resolve()
    relative = path.absolute().relative_to(root).as_posix()
    reference = SizedArtifactRef(relative, hashlib.sha256(payload).hexdigest(), len(payload))
    reader = BoundedInputReader(root, _settings(unit), phase=ExportPhase.ACCEPT)
    try:
        reader.path(relative)
    except ExportError as exc:
        if exc.reason != Reason.INPUT_MISSING:
            raise
    else:
        if read_output(root, reference, _settings(unit), max_bytes=len(payload)) != payload:
            raise ExportError("immutable output conflicts with existing bytes", reason=Reason.IDENTITY_CONFLICT,
                              phase=ExportPhase.ACCEPT)
        path.chmod(0o600)
        return reference
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    reader.path(path.parent.relative_to(root).as_posix())
    path.parent.chmod(0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)
    read_output(root, reference, _settings(unit), max_bytes=len(payload))
    return reference


def build_job(*, repository_root: Path | None = None) -> Job:
    def repo(unit: UnitContext) -> Path:
        return Path(repository_root or unit.job.repository_root)

    def schemas(unit: UnitContext, verified: VerifiedInputs, *, create: bool) -> VerifiedInputs:
        settings = _settings(unit)
        schema_registry(repository_root=repo(unit))
        source = schema_resource_root(repo(unit))
        prefix = unit.job.attempt_root / _SCHEMA_DIRECTORY
        references = []
        for relative, expected in {
            **SCHEMA_SHA256, "upstream/upstream.lock.json": UPSTREAM_LOCK_SHA256,
            "upstream/LICENSE": UPSTREAM_LICENSE_SHA256,
        }.items():
            payload = (source / relative).read_bytes()
            if hashlib.sha256(payload).hexdigest() != expected:
                raise ExportError("offline schema bytes changed", reason=Reason.INPUT_TAMPERED, phase=ExportPhase.LOAD)
            path = (prefix / relative).absolute()
            name = Path(os.path.normpath(path)).relative_to(unit.job.run_root.resolve()).as_posix()
            reference = SizedArtifactRef(name, expected, len(payload))
            if create:
                _write(unit, unit.job.run_root / name, payload)
            else:
                read_output(unit.job.run_root, reference, settings, max_bytes=settings.max_artifact_bytes)
            references.append(reference)
        measured = BoundedInputReader(unit.job.run_root, settings, phase=ExportPhase.ACCEPT)
        for reference in (*verified.input_inventory, *references):
            measured.read(reference)
        measured.reprove()
        return replace(verified, input_inventory=measured.inventory)

    def loaded(unit: UnitContext) -> VerifiedInputs:
        reference = ArtifactRef.from_mapping(unit.output("load.verify_inputs")["artifact"])
        payload = read_output(unit.job.run_root, reference, _settings(unit),
                              max_bytes=_settings(unit).max_manifest_bytes)
        return VerifiedInputs.from_mapping(parse_json_bytes(payload, max_bytes=_settings(unit).max_manifest_bytes))

    def reprove(unit: UnitContext, verified: VerifiedInputs) -> None:
        reprove_inputs(unit.job.run_root, upstream_inputs(verified), _settings(unit), repo(unit))
        current = schemas(unit, upstream_inputs(verified), create=False)
        if canonical_bytes(current.to_json()) != canonical_bytes(verified.to_json()):
            raise ExportError("verified inputs changed before acceptance", reason=Reason.INPUT_STALE,
                              phase=ExportPhase.ACCEPT)

    def load(unit: UnitContext) -> Mapping[str, Any]:
        unit.job.events.write("OPENVEX_EXPORT_STARTED", invocation_id=unit.job.attempt_id)
        verified = schemas(unit, verify_inputs(unit.job.run_root, _settings(unit), repo(unit)), create=True)
        reference = _write(unit, unit.unit_root / VERIFIED_INPUTS_NAME, canonical_bytes(verified.to_json()))
        dependency_result, _ = dependencies.dependency_projection(
            unit.job.run_root, verified, _settings(unit), repo(unit), _release(unit))
        unit.job.events.write("OPENVEX_INPUTS_VERIFIED", invocation_id=unit.job.attempt_id,
                              package_count=len(verified.findings), binding_count=len(verified.input_inventory),
                              input_bytes=verified.total_input_bytes,
                              resolved_config_sha256=verified.provenance.resolved_config_sha256,
                              gate_handoff_sha256=verified.provenance.gate_handoff.sha256)
        return {"artifact": reference.reference.to_json(),
                "dependency_source": None if dependency_result is None else dependency_result["source"],
                "schema_artifacts": [ref.to_json() for ref in verified.input_inventory
                                     if "/steps/load/tasks/verify_inputs/schemas/" in ref.path],
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def assemble(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        verified = loaded(unit)
        reprove(unit, verified)
        bundle = assemble_export(verified, settings, _release(unit),
                                 output_prefix=unit.unit_root.relative_to(unit.job.run_root).as_posix())
        with operation_span(unit.job.events, "openvex.validate", unit_id=unit.unit_id):
            validate_export(bundle, verified, settings)
        for reference, payload in ((bundle.document_ref, bundle.document_bytes),
                                   (bundle.manifest_ref, bundle.manifest_bytes), (bundle.result_ref, bundle.result_bytes)):
            if reference is not None:
                assert payload is not None
                _write(unit, unit.job.run_root / reference.path, payload)
        dependency = dependency_files(unit, verified, create=True)
        unit.job.events.write("OPENVEX_EXPORT_ACCOUNTED", invocation_id=unit.job.attempt_id,
                              **json_body(bundle.manifest["accounting"]))
        return {"artifact": bundle.result_ref.reference.to_json(),
                "manifest": bundle.manifest_ref.reference.to_json(),
                "document": None if bundle.document_ref is None else bundle.document_ref.reference.to_json(),
                "dependencies": dependency,
                "gaps": [], "terminal_status": "SUCCEEDED"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        settings, verified = _settings(unit), loaded(unit)
        reprove(unit, verified)
        dependency = dependency_files(unit, verified, create=False)
        if unit.output("export.assemble").get("dependencies") != dependency:
            raise ExportError("dependency export identity changed", reason=Reason.IDENTITY_CONFLICT,
                              phase=ExportPhase.ACCEPT)
        prefix = (unit.job.attempt_root / "steps" / "export" / "tasks" / "assemble").relative_to(
            unit.job.run_root).as_posix()
        expected = assemble_export(verified, settings, _release(unit), output_prefix=prefix)
        validate_export(expected, verified, settings)
        if unit.output("export.assemble")["artifact"] != expected.result_ref.reference.to_json():
            raise ExportError("assembled result identity changed", reason=Reason.IDENTITY_CONFLICT,
                              phase=ExportPhase.ACCEPT)
        for reference, payload, bound in (
            (expected.document_ref, expected.document_bytes, settings.max_document_bytes),
            (expected.manifest_ref, expected.manifest_bytes, settings.max_manifest_bytes),
            (expected.result_ref, expected.result_bytes, MAX_RESULT_BYTES),
        ):
            if reference is not None and read_output(
                    unit.job.run_root, reference, settings, max_bytes=bound) != payload:
                raise ExportError("export bytes do not match canonical reassembly", reason=Reason.INPUT_TAMPERED,
                                  phase=ExportPhase.ACCEPT)
        if expected.document_ref is None:
            absent = unit.job.run_root / prefix / DOCUMENT_NAME
            if absent.exists() or absent.is_symlink():
                raise ExportError("empty export has an unexpected document", reason=Reason.IDENTITY_CONFLICT,
                                  phase=ExportPhase.ACCEPT)
        reprove(unit, verified)
        result = expected.result
        return {"schema": OPENVEX_EXPORT_HANDOFF_SCHEMA, "artifact": expected.result_ref.reference.to_json(),
                "dependencies": dependency,
                "item_count": result["statement_count"],
                "gaps": list(result["gaps"]) + (dependency["gaps"] if dependency else []),
                "terminal_status": "COMPLETED_WITH_GAPS" if result["gaps"] or dependency and dependency["gaps"]
                else "SUCCEEDED"}

    def dependency_files(unit: UnitContext, verified: VerifiedInputs, *, create: bool) -> dict[str, Any] | None:
        settings = _settings(unit)
        result, payload = dependencies.dependency_projection(
            unit.job.run_root, verified, settings, repo(unit), _release(unit))
        source = None if result is None else result["source"]
        if source != unit.output("load.verify_inputs").get("dependency_source"):
            raise ExportError("admitted dependency input changed", reason=Reason.INPUT_STALE, phase=ExportPhase.ACCEPT)
        if result is None:
            return None
        prefix = unit.job.attempt_root / "steps" / "export" / "tasks" / "assemble"

        def persist(name: str, data: bytes, *, max_bytes: int) -> dict[str, str]:
            if len(data) > max_bytes:
                raise ExportError("dependency export artifact exceeds its byte bound",
                                  reason=Reason.BOUND_EXCEEDED,
                                  phase=ExportPhase.ASSEMBLE if create else ExportPhase.ACCEPT)
            path = prefix / name
            ref = ArtifactRef(path.relative_to(unit.job.run_root).as_posix(), hashlib.sha256(data).hexdigest())
            if create:
                _write(unit, path, data)
            elif read_output(unit.job.run_root, ref, settings, max_bytes=max_bytes) != data:
                raise ExportError("dependency export bytes changed", reason=Reason.INPUT_TAMPERED, phase=ExportPhase.ACCEPT)
            return ref.to_json()

        document_ref = None if payload is None else persist(
            dependencies.DOCUMENT_NAME, payload, max_bytes=settings.max_document_bytes)
        result["document"] = document_ref
        schema_validator("openvex-dependencies.schema.json", repository_root=repo(unit)).validate(result)
        result_ref = persist(dependencies.RESULT_NAME, canonical_bytes(result), max_bytes=MAX_RESULT_BYTES)
        return {"artifact": result_ref, "document": document_ref, "gaps": result["gaps"],
                "statements_by_status": result["statements_by_status"]}

    def measured(handler: Callable[[UnitContext], Mapping[str, Any]], phase: ExportPhase,
                 operation: str) -> Callable[[UnitContext], Mapping[str, Any]]:
        def execute(unit: UnitContext) -> Mapping[str, Any]:
            try:
                settings = _settings(unit)
                reader = BoundedInputReader(unit.job.run_root, settings, phase=phase)
                claim_path = (unit.job.attempt_root / "claim.json").relative_to(unit.job.run_root).as_posix()
                claim = reader.json(reader.pin(claim_path).reference)
                started = datetime.fromisoformat(normalize_timestamp(claim["started_at"]).replace("Z", "+00:00"))
                elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                if elapsed < 0 or elapsed >= settings.timeout_seconds:
                    raise ExportError("OpenVEX attempt deadline exceeded", reason=Reason.TIMED_OUT, phase=phase)
                deadline = time.monotonic() + settings.timeout_seconds - elapsed
                with operation_span(unit.job.events, operation, unit_id=unit.unit_id):
                    result = handler(unit)
                    document = None
                    if phase == ExportPhase.ACCEPT:
                        reference = ArtifactRef.from_mapping(result["artifact"])
                        document = parse_json_bytes(read_output(
                            unit.job.run_root, reference, settings, max_bytes=MAX_RESULT_BYTES),
                            max_bytes=MAX_RESULT_BYTES)
                    if time.monotonic() >= deadline:
                        raise ExportError("OpenVEX attempt deadline exceeded", reason=Reason.TIMED_OUT, phase=phase)
                    if document is not None:
                        unit.job.events.write(
                            "OPENVEX_EXPORT_COMPLETED", invocation_id=unit.job.attempt_id,
                            outcome=document["outcome"], result_reference=reference.to_json(),
                            document_present=document["document"] is not None,
                            document_bytes=0 if document["document"] is None else document["document"]["size_bytes"],
                            **dependencies.telemetry(result.get("dependencies")))
                    return result
            except Exception as exc:
                reason = (exc.reason if isinstance(exc, ExportError) else Reason.IO_ERROR if isinstance(exc, OSError)
                          else Reason.SEMANTIC_INVALID if isinstance(exc, ValueError) else Reason.INTERNAL_ERROR)
                unit.job.events.write("OPENVEX_EXPORT_FAILED", invocation_id=unit.job.attempt_id,
                                      phase=(exc.phase if isinstance(exc, ExportError) else phase).value,
                                      reason=reason.value)
                raise
        return execute

    units = (
        Unit("load.verify_inputs", measured(load, ExportPhase.LOAD, "openvex.verify_inputs")),
        Unit("export.assemble", measured(assemble, ExportPhase.ASSEMBLE, "openvex.assemble"), ("load.verify_inputs",)),
        Unit("acceptance.publish_handoff", measured(publish, ExportPhase.ACCEPT, "openvex.accept"),
             ("load.verify_inputs", "export.assemble")),
    )
    return Job(JOB_ID, "openvex_export", UnitExecutor(units).execute, input_validators=(_validate,),
               schema_identity=OPENVEX_EXPORT_HANDOFF_SCHEMA, units=units, datasets=DATASETS, contract=CONTRACT)
