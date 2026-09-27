"""Closed, config-driven orchestration for the ADR-0010 vendor evidence workers.

This adapter owns paths and publication only. Scanner execution remains in the public
``build`` seams, which in turn use the authenticated B13 collector. Each scanner sibling
therefore retains its own terminal status and coverage gaps.
"""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any

import binary_hardening
import binary_hardening_input
import automatic_evidence_inputs as automatic_inputs
import container_image_inventory
from execution_state import Blocked, beneath, data_path, digest, file_hash, identifier, read_json, run_path
import iac_config_scan
import mobile_sast
import vendor_evidence_workers as vendor_workers
from publish_job_output import mark_attempt_started, publish_validated, record_noncurrent
import secrets_inventory
from validate_job_output import OrchestrationFacts

REQUEST_SCHEMA = "appsec-review/vendor-evidence-orchestration-request/1.1"
LEGACY_BINARY_REQUEST_SCHEMA = "appsec-review/vendor-evidence-orchestration-request/1.0"
WORKERS = {
    "02-secrets-inventory": secrets_inventory,
    "02-iac-config-scan": iac_config_scan,
    "02-container-image-inventory": container_image_inventory,
    "02-binary-hardening": binary_hardening,
    "02-mobile-sast": mobile_sast,
}
_REQUEST_KEYS = {"schema", "run_id", "job_id", "source_generation", "generated_at",
                 "source_root", "source_binding", "applicability"}
_LEGACY_BINARY_REQUEST_KEYS = {"schema", "run_id", "job_id", "source_generation", "generated_at", "source_root"}


def _owned(value: Any, owner: Path, label: str, *, directory: bool = False) -> Path:
    if not isinstance(value, str) or not value:
        raise Blocked(f"vendor evidence orchestration: {label} path is required")
    path = Path(value).absolute()
    try:
        path = beneath(owner, path)
    except ValueError as exc:
        raise Blocked(f"vendor evidence orchestration: {label} path is not run-owned") from exc
    present = path.is_dir() if directory else path.is_file()
    if not present or path.is_symlink():
        raise Blocked(f"vendor evidence orchestration: {label} is absent or linked")
    return path


def _new_canonical(value: str, expected: Path, owner: Path, label: str) -> Path:
    path = Path(value).absolute()
    try:
        beneath(owner, path.parent)
    except ValueError as exc:
        raise Blocked(f"vendor evidence orchestration: {label} is not run-owned") from exc
    if path != expected.absolute():
        raise Blocked(f"vendor evidence orchestration: {label} is not the canonical run-owned path")
    if path.exists() or path.is_symlink():
        raise Blocked(f"vendor evidence orchestration: {label} already exists")
    return path


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise Blocked("vendor evidence orchestration: generated_at must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise Blocked("vendor evidence orchestration: generated_at is invalid") from None
    if parsed.tzinfo is None:
        raise Blocked("vendor evidence orchestration: generated_at must include a timezone")
    return parsed


def execute(*, job_id: str, run_id: str, dagster_run_id: str, input_path: str,
            output_root: str, attempt_root: str, execution_root: str) -> dict[str, Any]:
    """Execute, materialize, validate, and publish exactly one explicit immutable attempt."""
    if job_id not in WORKERS:
        raise Blocked("vendor evidence orchestration: unknown lifecycle job")
    run_id, dagster_run_id = identifier(run_id), identifier(dagster_run_id)
    owner = run_path(run_id).absolute()
    request_path = _owned(input_path, owner, "input request")
    base = data_path(run_id, "jobs", job_id, "whole").absolute()
    if Path(output_root).absolute() != base:
        raise Blocked("vendor evidence orchestration: output root is not the canonical job scope")

    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise Blocked("vendor evidence orchestration: input request is unreadable") from None
    legacy_binary = (job_id == "02-binary-hardening" and isinstance(request, dict) and
                     set(request) == _LEGACY_BINARY_REQUEST_KEYS and
                     request.get("schema") == LEGACY_BINARY_REQUEST_SCHEMA)
    if not isinstance(request, dict) or (set(request) != _REQUEST_KEYS and not legacy_binary):
        raise Blocked("vendor evidence orchestration: request shape is not closed")
    if ((request.get("schema") != REQUEST_SCHEMA and not legacy_binary) or request.get("run_id") != run_id or
            request.get("job_id") != job_id):
        raise Blocked("vendor evidence orchestration: request identity is invalid")
    manifest_path = owner / "inputs" / "artifact-manifest.json"
    manifest = _owned(str(manifest_path), owner, "artifact manifest")
    generation = "sha256:" + file_hash(manifest)
    if request.get("source_generation") != generation:
        raise Blocked("vendor evidence orchestration: request source generation is stale")
    observed_at = _timestamp(request.get("generated_at"))
    source = _owned(request.get("source_root"), owner, "source root", directory=True)
    projection = None
    if not legacy_binary:
        projection, _binding, _files = automatic_inputs.source_projection(run_id)
        automatic_inputs.validate_source_projection(run_id, projection, request.get("source_binding"))

    # The validators independently recover the source boundary from the immutable run manifest.
    if job_id in {"02-secrets-inventory", "02-iac-config-scan", "02-mobile-sast"} and source != projection:
        raise Blocked("vendor evidence orchestration: source root differs from the accepted source projection")
    if not legacy_binary:
        probe = vendor_workers.probe(job_id, source)
        applicable = any(probe["candidates"].values()) or job_id == "02-secrets-inventory"
        expected_applicability = {"decision": "EXECUTE" if applicable else "SKIPPED_NA",
            "skip_reason": None if applicable else vendor_workers.SKIP,
            "probe_sha256": "sha256:" + digest(probe), "probe": probe}
        if request.get("applicability") != expected_applicability:
            raise Blocked("vendor evidence orchestration: applicability evidence is stale or mismatched")
    if job_id == "02-binary-hardening":
        binary_hardening_input.validate(run_id, source)
    if job_id == "02-container-image-inventory" and source != (owner / "inputs").absolute():
        raise Blocked("vendor evidence orchestration: container inventory source must be the run inputs root")

    attempt_id = identifier(Path(attempt_root).name)
    attempt = _new_canonical(attempt_root, base / "attempts" / attempt_id, owner, "attempt root")
    execution = _new_canonical(execution_root, base / "executions" / attempt_id, owner, "execution root")
    base.mkdir(parents=True, exist_ok=True)
    mark_attempt_started(base, attempt_id)
    documents = WORKERS[job_id].build(
        source, execution_root=execution, now=request["generated_at"], run_id=run_id,
        attempt_id=attempt_id, source_snapshot_sha256=generation)
    WORKERS[job_id].materialize_attempt(
        documents, attempt, dagster_run_id=dagster_run_id,
        started_at=request["generated_at"], finished_at=request["generated_at"])
    envelope_path = attempt / "result.json"
    envelope = read_json(envelope_path)
    if envelope.get("execution_status") in {"BLOCKED", "FAILED", "CANCELED"}:
        pointer = record_noncurrent(base, envelope_path, envelope)
        raise Blocked("vendor evidence orchestration: worker did not produce current evidence: " + pointer["status"])
    pointer = publish_validated(
        base, attempt, envelope_path, envelope["input_fingerprint"],
        expected_run_id=run_id, expected_job_id=job_id,
        orchestration=OrchestrationFacts(dagster_run_id, generation, observed_at))
    return pointer


def execute_binary_from_native(*, run_id: str, dagster_run_id: str) -> dict[str, Any]:
    """Route the current accepted native-build binaries into a canonical hardening attempt."""
    run_id, dagster_run_id = identifier(run_id), identifier(dagster_run_id)
    request = binary_hardening_input.stage_request(run_id, dagster_run_id)
    base = data_path(run_id, "jobs", "02-binary-hardening", "whole").absolute()
    attempt_id = "native-" + dagster_run_id
    return execute(job_id="02-binary-hardening", run_id=run_id,
        dagster_run_id=dagster_run_id, input_path=str(request), output_root=str(base),
        attempt_root=str(base / "attempts" / attempt_id),
        execution_root=str(base / "executions" / attempt_id))
