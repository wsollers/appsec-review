"""Shared worker-result state and envelope validation.

This module is the runtime boundary for the v1.0 common result contract. It is deliberately
independent of Dagster and of any target-controlled code. Attempts are immutable; supersession is
an acceptance-view disposition and never an execution-state rewrite.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from execution_state import ROOT, file_hash
from schema_validate import validate_document

CONTRACT_PATH = ROOT / "worker-result-contract.json"

MEDIA_TYPES = {
    ".json": "application/json",
    ".md": "text/markdown",
    ".log": "text/plain",
    ".txt": "text/plain",
}


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_worker_result(envelope: dict[str, Any],
                           allowed_skip_reasons: set[str] | None = None) -> list[str]:
    """Validate the shared terminal envelope plus cross-field state semantics."""
    errors = validate_document(envelope, "worker-result-envelope.schema.json")
    status = envelope.get("execution_status")
    acceptance = envelope.get("acceptance_status")
    skip_reason = envelope.get("skip_reason")
    gaps = envelope.get("gaps")
    cause = envelope.get("cause")
    superseded_by = envelope.get("superseded_by_attempt_id")
    if status == "SKIPPED":
        if not skip_reason:
            errors.append("$.skip_reason: SKIPPED requires an explicit edge-authorized reason")
        elif allowed_skip_reasons is not None and skip_reason not in allowed_skip_reasons:
            errors.append(f"$.skip_reason: {skip_reason!r} is not authorized for this dependency edge")
    elif skip_reason is not None:
        errors.append("$.skip_reason: only SKIPPED may declare a skip reason")
    if status in {"OK_WITH_GAPS", "UNRESOLVED"} and not gaps:
        errors.append(f"$.gaps: {status} requires at least one explicit gap")
    if status in {"BLOCKED", "FAILED", "CANCELED", "UNRESOLVED"} and not cause:
        errors.append(f"$.cause: {status} requires an explicit cause")
    if status in {"OK", "OK_WITH_GAPS"} and cause is not None:
        errors.append(f"$.cause: {status} cannot declare a failure cause")
    if acceptance == "CURRENT" and status not in {"OK", "OK_WITH_GAPS", "SKIPPED"}:
        errors.append(f"$.acceptance_status: {status} cannot be CURRENT")
    if acceptance == "SUPERSEDED":
        if not superseded_by:
            errors.append("$.superseded_by_attempt_id: SUPERSEDED requires the replacement attempt")
        elif superseded_by == envelope.get("attempt_id"):
            errors.append("$.superseded_by_attempt_id: an attempt cannot supersede itself")
    elif superseded_by is not None:
        errors.append("$.superseded_by_attempt_id: only SUPERSEDED may name a replacement attempt")
    retry = envelope.get("retry")
    if isinstance(retry, dict):
        if retry.get("allowed") and not retry.get("resume_command"):
            errors.append("$.retry.resume_command: retryable results require a resume command")
        if not retry.get("allowed") and retry.get("resume_command") is not None:
            errors.append("$.retry.resume_command: non-retryable results cannot declare a resume command")
    return errors


def validate_transition(previous: str, current: str, dimension: str = "execution",
                        contract: dict[str, Any] | None = None) -> list[str]:
    contract = contract or load_contract()
    field = "execution_states" if dimension == "execution" else "acceptance_states"
    if dimension not in {"execution", "acceptance"}:
        return [f"unknown state dimension: {dimension}"]
    transitions = contract[field].get("transitions", {})
    if previous not in transitions:
        return [f"unknown {dimension} state: {previous}"]
    if current not in transitions[previous]:
        return [f"illegal {dimension} transition: {previous} -> {current}"]
    return []


def validate_immutable_reuse(existing: dict[str, Any], candidate: dict[str, Any]) -> list[str]:
    """A reuse is the exact same accepted attempt and input, never a repaired mutation."""
    errors: list[str] = []
    if existing.get("attempt_id") != candidate.get("attempt_id"):
        errors.append("reuse attempt_id differs from the accepted attempt")
    if existing.get("input_fingerprint") != candidate.get("input_fingerprint"):
        errors.append("reuse input fingerprint differs from the accepted attempt")
    if existing != candidate:
        errors.append("reuse candidate mutates the immutable accepted envelope")
    if candidate.get("acceptance_status") != "CURRENT":
        errors.append("reuse candidate is not the current accepted attempt")
    if candidate.get("execution_status") not in {"OK", "OK_WITH_GAPS", "SKIPPED"}:
        errors.append("reuse candidate does not have a publishable execution status")
    return errors


def artifact_records(attempt_root: Path, relative_paths: list[str]) -> list[dict[str, str]]:
    """Build the hashed artifact list after every declared file is durable."""
    records: list[dict[str, str]] = []
    for relative in relative_paths:
        path = Path(attempt_root) / Path(*relative.split("/"))
        records.append({"path": relative, "sha256": file_hash(path),
                        "media_type": MEDIA_TYPES.get(path.suffix.lower(),
                                                      "application/octet-stream")})
    return records


def terminal_envelope(*, run_id: str, job_id: str, attempt_id: str, worker_kind: str,
                      execution_status: str, acceptance_status: str,
                      input_fingerprint: str, output_contract: str,
                      started_at: str, finished_at: str, summary: str,
                      artifacts: list[dict[str, str]], gaps: list[str] | None = None,
                      skip_reason: str | None = None, cause: str | None = None,
                      retry_allowed: bool = False, resume_command: str | None = None
                      ) -> dict[str, Any]:
    """Create, but do not validate or publish, one complete terminal envelope."""
    return {
        "schema": "appsec-review/worker-result-envelope/1.0",
        "run_id": run_id,
        "job_id": job_id,
        "attempt_id": attempt_id,
        "worker_kind": worker_kind,
        "execution_status": execution_status,
        "acceptance_status": acceptance_status,
        "input_fingerprint": input_fingerprint,
        "output_contract": output_contract,
        "started_at": started_at,
        "finished_at": finished_at,
        "summary": summary,
        "artifacts": artifacts,
        "gaps": list(gaps or []),
        "skip_reason": skip_reason,
        "cause": cause,
        "retry": {"allowed": retry_allowed,
                  "resume_command": resume_command if retry_allowed else None},
        "superseded_by_attempt_id": None,
    }
