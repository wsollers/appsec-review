#!/usr/bin/env python3
"""Zero-configuration automatic lifecycle adapter for D01-D04 discovery.

The qualified persona request construction and invocation runtime remain in ``discovery_gate``.
This module removes the legacy publication seam: every automatic discovery job is exposed through
one ``run(run_id, dagster_run_id, job_id, force=False)`` API and publishes an immutable common
worker-result envelope with permission and source-lineage receipts.

No caller supplies a target, prompt, model response, upstream artifact, or applicability answer.
Those inputs are derived from fresh accepted intake and accepted upstream discovery.  Model and
invoker resolution happens during preflight, so genuine unavailability is retained as BLOCKED;
invalid or rejected model output remains FAILED and is never repackaged as evidence.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import discovery_gate as discovery
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, file_hash, now, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document
import registry_paths

JOBS = (discovery.ADOPTED_JOB, discovery.CONSUMER_JOB, discovery.DEVOPS_JOB, discovery.SRE_JOB)


def root(run_id: str, job_id: str) -> Path:
    if job_id not in JOBS:
        raise Blocked(f"{job_id}: no automatic discovery lifecycle adapter")
    return discovery.root(run_id, job_id)


def _template(job_id: str) -> dict[str, Any]:
    value = read_json(registry_paths.template(job_id))
    composition = value.get("composition")
    if not isinstance(composition, dict):
        raise Blocked(f"{job_id}: registry template lacks a composition")
    return value


def _contract(job_id: str) -> str:
    value = _template(job_id).get("composition", {}).get("output_contract_id")
    if not isinstance(value, str) or not value:
        raise Blocked(f"{job_id}: registry output contract is absent")
    return value


def _receipts(run_id: str, job_id: str, source_snapshot_sha256: str) -> tuple[dict, dict]:
    return discovery._producer_receipts(run_id, job_id, source_snapshot_sha256)


def current_inputs(run_id: str, job_id: str) -> dict[str, Any]:
    if job_id == discovery.ADOPTED_JOB:
        record = discovery._automatic_partition_inputs(run_id)
    elif job_id in discovery.AUTOMATIC_JOBS:
        record = discovery._automatic_project_inputs(run_id, job_id)
    else:
        raise Blocked(f"{job_id}: no automatic discovery lifecycle adapter")
    record["run_id"] = run_id
    return record


def _fingerprint(record: dict[str, Any]) -> str:
    return discovery._input_fingerprint(record)


def _validate_attempt(run_id: str, job_id: str, attempt: Path,
                      record: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != record:
        raise Blocked(f"{job_id}: immutable automatic discovery inputs changed")
    spec = discovery.AUTOMATIC_JOBS[job_id]
    value = read_json(attempt / spec["result"])
    errors = validate_document(value, discovery.SCHEMAS[job_id])
    if errors:
        raise Blocked(f"{job_id}: accepted discovery result fails schema ({len(errors)} errors)")
    discovery._require_upstream_inputs(run_id, job_id, value)
    permission, lineage = _receipts(run_id, job_id, record["source_snapshot_sha256"])
    if (read_json(attempt / "permission.json") != permission or
            read_json(attempt / "lineage.json") != lineage):
        raise Blocked(f"{job_id}: permission/lineage receipt changed")


def _run_chained(run_id: str, dagster_run_id: str, job_id: str,
                 force: bool) -> dict[str, Any]:
    base = root(run_id, job_id)
    contract = _contract(job_id)
    resume = (f"python -B appsec-review-process/launch_job.py --run-id {run_id} "
              "--job full_review --wait")
    prepared: dict[str, Any] = {}

    def derive() -> dict[str, Any]:
        record = current_inputs(run_id, job_id)
        prepared["record"] = record
        return record

    def failure_inputs(exc: BaseException) -> dict[str, Any]:
        if "record" in prepared:
            return prepared["record"]
        return {"run_id": run_id, "job": job_id, "mode": "automatic",
            "preflight_error": f"{type(exc).__name__}: {exc}",
            "code": {"automatic_discovery.py": file_hash(Path(__file__)),
                     "discovery_gate.py": file_hash(Path(discovery.__file__))}}

    def preflight(record: dict[str, Any]) -> None:
        target = Path(record["target_root"])
        if not target.is_absolute() or not target.is_dir() or target.is_symlink():
            raise Blocked(f"{job_id}: accepted intake target is unavailable")

    def execute(allocation: dict[str, Any], record: dict[str, Any], fingerprint: str):
        value, summary, facts = discovery._dispatch_project_persona(run_id, base, record)
        errors = validate_document(value, discovery.SCHEMAS[job_id])
        if errors:
            raise Blocked(f"{job_id}: persona result fails schema ({len(errors)} errors)")
        discovery._require_upstream_inputs(run_id, job_id, value)
        attempt = allocation["attempt"]
        spec = discovery.AUTOMATIC_JOBS[job_id]
        atomic_json(attempt / spec["result"], value)
        atomic_bytes(attempt / spec["summary"], summary.encode("utf-8"))
        permission, lineage = _receipts(run_id, job_id, record["source_snapshot_sha256"])
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", lineage)
        gaps = list(value.get("coverage_gaps") or [])
        execution_status = "OK_WITH_GAPS" if gaps else "OK"
        status = {"process": "02-evidence-pregather", "status": execution_status,
            "budget": facts["budget"], "persona_id": facts["persona_id"],
            "role_id": facts["role_id"], "domain_id": facts["domain_id"],
            "tooling_profile_id": facts["tooling_profile_id"],
            "artifacts_read": facts["artifacts_read"], "run_id": run_id,
            "job": job_id, "attempt_id": allocation["attempt_id"],
            "dagster_run_id": dagster_run_id, "started_at": allocation["started_at"],
            "ended_at": now(), "fingerprint": fingerprint,
            "dispatch_mode": "automatic", "persona_job_id": facts["persona_job_id"],
            "persona_attempt_id": facts["persona_attempt_id"],
            "persona_result_sha256": facts["persona_result_sha256"], "model": facts["model"]}
        atomic_json(attempt / "status.json", status)
        return record_terminal_current(
            base, attempt, run_id=run_id, job_id=job_id, dagster_run_id=dagster_run_id,
            worker_kind="persona", output_contract=contract,
            input_fingerprint=fingerprint, started_at=allocation["started_at"],
            execution_status=execution_status,
            summary=f"Automatic persona dispatch produced accepted {job_id} evidence.",
            status_record=status,
            artifact_paths=[spec["result"], spec["summary"], "status.json",
                            "permission.json", "lineage.json"], gaps=gaps or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(
                run_id, job_id, path, record))

    def reuse(admitted: dict[str, Any]) -> None:
        atomic_json(data_path(run_id, "orchestration", "dagster", dagster_run_id,
                              job_id + "-reuse.json"),
                    {"status": admitted["envelope"]["execution_status"], "reused": True,
                     "publication_recovered": admitted["recovered_publication"],
                     "producer": admitted["pointer"], "time": now()})

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=job_id, dagster_run_id=dagster_run_id,
        worker_kind="persona", output_contract=contract, resume_command=resume,
        derive_inputs=derive, fingerprint_inputs=_fingerprint, execute_attempt=execute,
        preflight_failure_inputs=failure_inputs, force=force, preflight_validate=preflight,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(
            run_id, job_id, attempt, record), on_reuse=reuse,
        blocked_summary=("Automatic discovery preflight could not resolve accepted inputs or "
                         "the configured model/invoker."),
        failed_summary="Automatic discovery persona output was not accepted.")


def run(run_id: str, dagster_run_id: str, job_id: str,
        force: bool = False) -> dict[str, Any]:
    """Execute one automatic D01-D04 discovery job without caller-supplied analysis."""
    if job_id == discovery.ADOPTED_JOB:
        return discovery._run_partition_automatic(run_id, dagster_run_id, force)
    if job_id not in discovery.AUTOMATIC_JOBS:
        raise Blocked(f"{job_id}: no automatic discovery lifecycle adapter")
    return _run_chained(run_id, dagster_run_id, job_id, force)


def validate(run_id: str, job_id: str, pointer: dict[str, Any] | None = None) -> Path:
    """Re-derive current automatic inputs and validate the accepted common publication."""
    if job_id == discovery.ADOPTED_JOB:
        pointer = pointer or read_json(root(run_id, job_id) / "accepted.json")
        return discovery._validate_common(run_id, pointer)
    record = current_inputs(run_id, job_id)
    base = root(run_id, job_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _envelope = validate_published(
        base, pointer, _fingerprint(record), expected_run_id=run_id,
        expected_job_id=job_id)
    _validate_attempt(run_id, job_id, attempt, record)
    return attempt
