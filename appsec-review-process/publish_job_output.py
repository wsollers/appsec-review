#!/usr/bin/env python3
"""Atomic publication boundary for validated common worker results.

Validation remains read-only in ``validate_job_output.py``. This module publishes only after that
validator returns no errors and after confirming the candidate is still the newest attempt.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
import uuid

from execution_state import (Blocked, Lock, atomic_json, file_hash, identifier, now, read_json,
                             tree_hashes)
from validate_job_output import validate_job_output
from worker_result import artifact_records, terminal_envelope, validate_worker_result

ACCEPTED_SCHEMA = "appsec-review/accepted-worker-result/1.0"
NONCURRENT_SCHEMA = "appsec-review/noncurrent-worker-result/1.0"


def coordinate_worker_lifecycle(
        base: Path, *, run_id: str, job_id: str, dagster_run_id: str,
        worker_kind: str, output_contract: str, resume_command: str,
        derive_inputs: Callable[[], dict[str, Any]],
        fingerprint_inputs: Callable[[dict[str, Any]], str],
        execute_attempt: Callable[[dict[str, Any], dict[str, Any], str], dict[str, Any]],
        preflight_failure_inputs: Callable[[BaseException], dict[str, Any]],
        force: bool = False, consumer_job_id: str | None = None,
        registry_root: Path | None = None, graph_path: Path | None = None,
        preflight_validate: Callable[[dict[str, Any]], None] | None = None,
        post_validate: Callable[[Path, dict[str, Any], dict[str, Any]], None] | None = None,
        on_reuse: Callable[[dict[str, Any]], None] | None = None,
        blocked_summary: str = "Worker preflight did not complete.",
        failed_summary: str = "Worker execution did not publish.",
        attempt_id_factory=None) -> dict[str, Any]:
    """Run one adopted worker lifecycle while holding its per-job lock.

    Input derivation and payload production remain explicit worker callbacks. This coordinator owns
    only lock-scoped reuse, interrupted-attempt recovery/allocation, and terminal exception routing.
    It always re-raises the original callback exception so Dagster observes the same failure or
    cancellation type. Exactly the two explicitly adopted callers use this function.
    """
    base = Path(base)
    allocation: dict[str, Any] | None = None
    record: dict[str, Any] | None = None
    fingerprint: str | None = None

    def terminal_for(exc: BaseException, *, preflight: bool) -> None:
        nonlocal allocation, record, fingerprint
        try:
            if allocation is None:
                record = preflight_failure_inputs(exc)
                if not isinstance(record, dict):
                    raise TypeError("preflight failure input callback must return an object")
                fingerprint = fingerprint_inputs(record)
                allocation = allocate_attempt(
                    base, run_id=run_id, job_id=job_id, dagster_run_id=dagster_run_id,
                    worker_kind=worker_kind, output_contract=output_contract,
                    input_record=record, input_fingerprint=fingerprint,
                    resume_command=resume_command, attempt_id_factory=attempt_id_factory)
            pointer_path = base / "accepted.json"
            pointer = read_json(pointer_path) if pointer_path.exists() else {}
            if (pointer.get("schema") != NONCURRENT_SCHEMA or
                    pointer.get("status") != "PENDING" or
                    pointer.get("attempt_id") != allocation["attempt_id"]):
                return
            execution_status = ("CANCELED" if isinstance(exc, KeyboardInterrupt) else
                                "BLOCKED" if preflight else "FAILED")
            record_terminal_noncurrent(
                base, allocation["attempt"], run_id=run_id, job_id=job_id,
                dagster_run_id=dagster_run_id, worker_kind=worker_kind,
                output_contract=output_contract, input_fingerprint=fingerprint,
                started_at=allocation["started_at"], execution_status=execution_status,
                cause=f"{type(exc).__name__}: {exc}",
                summary=blocked_summary if preflight else failed_summary,
                resume_command=resume_command)
        except BaseException as recording_error:
            if hasattr(exc, "add_note"):
                exc.add_note("terminal lifecycle recording also failed: "
                             f"{type(recording_error).__name__}: {recording_error}")

    with Lock(base / "job.lock"):
        try:
            record = derive_inputs()
            if not isinstance(record, dict):
                raise TypeError("input derivation callback must return an object")
            fingerprint = fingerprint_inputs(record)
            if preflight_validate is not None:
                preflight_validate(record)
            if not force:
                validator = None
                if post_validate is not None:
                    validator = lambda attempt, envelope: post_validate(attempt, envelope, record)
                admitted = admit_reusable(
                    base, fingerprint, expected_run_id=run_id, expected_job_id=job_id,
                    consumer_job_id=consumer_job_id, registry_root=registry_root,
                    graph_path=graph_path, post_validate=validator)
                if admitted is not None:
                    if on_reuse is not None:
                        on_reuse(admitted)
                    return admitted["pointer"]
            allocation = allocate_attempt(
                base, run_id=run_id, job_id=job_id, dagster_run_id=dagster_run_id,
                worker_kind=worker_kind, output_contract=output_contract,
                input_record=record, input_fingerprint=fingerprint,
                resume_command=resume_command, attempt_id_factory=attempt_id_factory)
        except BaseException as exc:
            terminal_for(exc, preflight=True)
            raise

        try:
            return execute_attempt(allocation, record, fingerprint)
        except BaseException as exc:
            terminal_for(exc, preflight=False)
            raise


def _latest_matches(base: Path, attempt_id: str) -> None:
    latest = read_json(Path(base) / "latest.json")
    if latest.get("attempt_id") != attempt_id:
        raise Blocked("candidate is not the newest allocated attempt")


def _pending_matches(base: Path, attempt_id: str) -> None:
    pointer = read_json(Path(base) / "accepted.json")
    if (pointer.get("schema") != NONCURRENT_SCHEMA or pointer.get("status") != "PENDING" or
            pointer.get("attempt_id") != attempt_id):
        raise Blocked("candidate is not the current pending allocation")


def common_pointer(pointer: dict[str, Any]) -> bool:
    return pointer.get("schema") == ACCEPTED_SCHEMA


def mark_attempt_started(base: Path, attempt_id: str,
                         input_fingerprint: str | None = None) -> None:
    """Invalidate prior acceptance before work starts; retained for focused boundary tests."""
    base = Path(base)
    # PENDING is written first so a crash between the two atomic file replacements fails closed:
    # readers cannot observe an older accepted success after the new attempt has begun allocation.
    pointer = {
        "schema": NONCURRENT_SCHEMA, "status": "PENDING", "attempt_id": attempt_id,
        "updated_at": now(),
    }
    if input_fingerprint is not None:
        pointer["fingerprint"] = input_fingerprint
    atomic_json(base / "accepted.json", pointer)
    atomic_json(base / "latest.json", {"attempt_id": attempt_id, "updated_at": now()})


def _unique_attempt(base: Path, attempt_id_factory=None) -> tuple[str, Path]:
    factory = attempt_id_factory or (lambda: uuid.uuid4().hex)
    attempts = Path(base) / "attempts"
    attempts.mkdir(parents=True, exist_ok=True)
    for _ in range(32):
        attempt_id = identifier(factory())
        attempt = attempts / attempt_id
        try:
            attempt.mkdir()
            return attempt_id, attempt
        except FileExistsError:
            continue
    raise Blocked("could not allocate a unique immutable attempt after 32 collisions")


def record_terminal_noncurrent(
        base: Path, attempt_root: Path, *, run_id: str, job_id: str,
        dagster_run_id: str, worker_kind: str, output_contract: str,
        input_fingerprint: str, started_at: str, execution_status: str, cause: str,
        summary: str, resume_command: str, envelope_name: str = "result.json") -> dict[str, Any]:
    """Persist one immutable failure envelope and make it the non-current public state."""
    if execution_status not in {"BLOCKED", "FAILED", "CANCELED"}:
        raise ValueError("terminal non-current recording supports BLOCKED, FAILED, or CANCELED")
    base, attempt_root = Path(base), Path(attempt_root)
    attempt_id = identifier(attempt_root.name)
    if attempt_root.absolute() != (base / "attempts" / attempt_id).absolute():
        raise Blocked("terminal attempt is outside the owning job root")
    _latest_matches(base, attempt_id)
    _pending_matches(base, attempt_id)
    finished_at = now()
    status = {
        "status": execution_status, "run_id": run_id, "job": job_id,
        "attempt_id": attempt_id, "dagster_run_id": dagster_run_id,
        "started_at": started_at, "ended_at": finished_at,
        "fingerprint": input_fingerprint, "cause": cause,
    }
    atomic_json(attempt_root / "status.json", status)
    envelope_path = attempt_root / envelope_name
    if envelope_name == "result.json" and envelope_path.exists():
        # A worker may have durably written a candidate CURRENT envelope before read-only
        # validation rejects it. Preserve that immutable candidate and record the terminal
        # non-current outcome beside it instead of rewriting history.
        envelope_path = attempt_root / "failure-result.json"
    expected = terminal_envelope(
        run_id=run_id, job_id=job_id, attempt_id=attempt_id,
        worker_kind=worker_kind, execution_status=execution_status,
        acceptance_status="NOT_ACCEPTED", input_fingerprint=input_fingerprint,
        output_contract=output_contract, started_at=started_at, finished_at=finished_at,
        summary=summary, artifacts=[], cause=cause, retry_allowed=True,
        resume_command=resume_command)
    if envelope_path.exists():
        existing = read_json(envelope_path)
        stable_fields = {key: value for key, value in expected.items() if key != "finished_at"}
        if ({key: existing.get(key) for key in stable_fields} != stable_fields or
                validate_worker_result(existing)):
            raise Blocked("existing terminal envelope conflicts with interrupted-attempt recovery")
        envelope = existing
    else:
        atomic_json(envelope_path, expected)
        envelope = expected
    _latest_matches(base, attempt_id)
    _pending_matches(base, attempt_id)
    return record_noncurrent(base, envelope_path, envelope)


def _recover_interrupted(base: Path, *, run_id: str, job_id: str,
                         dagster_run_id: str, worker_kind: str, output_contract: str,
                         resume_command: str) -> dict[str, Any] | None:
    """Convert an abandoned PENDING/RUNNING attempt into a durable FAILED result."""
    base = Path(base)
    accepted_path, latest_path = base / "accepted.json", base / "latest.json"
    accepted = read_json(accepted_path) if accepted_path.exists() else {}
    latest = read_json(latest_path) if latest_path.exists() else {}
    pending_id = (accepted.get("attempt_id") if accepted.get("schema") == NONCURRENT_SCHEMA and
                  accepted.get("status") == "PENDING" else None)
    candidate_id = pending_id or latest.get("attempt_id")
    if not candidate_id:
        return None
    attempt_id = identifier(candidate_id)
    attempt = base / "attempts" / attempt_id
    status_path = attempt / "status.json"
    if not status_path.exists():
        raise Blocked("newest attempt lacks durable allocation status; manual recovery required")
    status = read_json(status_path)
    if status.get("status") not in {"PENDING", "READY", "RUNNING"}:
        return None
    # Repair the safe crash point where PENDING was durable but latest.json was not yet advanced.
    if latest.get("attempt_id") != attempt_id:
        atomic_json(latest_path, {"attempt_id": attempt_id, "updated_at": now()})
    envelope_name = "recovery-result.json" if (attempt / "result.json").exists() else "result.json"
    return record_terminal_noncurrent(
        base, attempt, run_id=run_id, job_id=job_id,
        dagster_run_id=status.get("dagster_run_id", dagster_run_id),
        worker_kind=worker_kind, output_contract=output_contract,
        input_fingerprint=status["fingerprint"], started_at=status["started_at"],
        execution_status="FAILED", cause="INTERRUPTED_WORKER",
        summary="Interrupted worker attempt was recovered as failed before replacement.",
        resume_command=resume_command, envelope_name=envelope_name)


def allocate_attempt(
        base: Path, *, run_id: str, job_id: str, dagster_run_id: str,
        worker_kind: str, output_contract: str, input_record: dict[str, Any],
        input_fingerprint: str, resume_command: str,
        attempt_id_factory=None) -> dict[str, Any]:
    """Recover abandoned work, allocate an immutable attempt, and invalidate old acceptance."""
    base = Path(base)
    recovered = _recover_interrupted(
        base, run_id=run_id, job_id=job_id, dagster_run_id=dagster_run_id,
        worker_kind=worker_kind, output_contract=output_contract,
        resume_command=resume_command)
    attempt_id, attempt = _unique_attempt(base, attempt_id_factory)
    started_at = now()
    atomic_json(attempt / "inputs.json", input_record)
    atomic_json(attempt / "status.json", {
        "status": "RUNNING", "run_id": run_id, "job": job_id,
        "attempt_id": attempt_id, "dagster_run_id": dagster_run_id,
        "started_at": started_at, "fingerprint": input_fingerprint,
    })
    mark_attempt_started(base, attempt_id, input_fingerprint)
    return {"attempt_id": attempt_id, "attempt": attempt, "started_at": started_at,
            "recovered": recovered}


def record_noncurrent(base: Path, envelope_path: Path, envelope: dict[str, Any]) -> dict[str, Any]:
    """Record a failed/blocked/canceled attempt so readers cannot fall back to old success."""
    base, envelope_path = Path(base), Path(envelope_path)
    _latest_matches(base, envelope["attempt_id"])
    _pending_matches(base, envelope["attempt_id"])
    if envelope.get("acceptance_status") != "NOT_ACCEPTED":
        raise ValueError("non-current attempt must have NOT_ACCEPTED acceptance")
    if envelope.get("execution_status") in {"OK", "OK_WITH_GAPS", "SKIPPED"}:
        raise ValueError("publishable terminal cannot be recorded as a non-current failure")
    errors = validate_worker_result(envelope)
    if errors:
        raise Blocked("non-current worker result is invalid: " + "; ".join(errors))
    try:
        relative_envelope = envelope_path.relative_to(base / "attempts" /
                                                     envelope["attempt_id"]).as_posix()
    except ValueError:
        raise Blocked("non-current envelope is outside its immutable attempt") from None
    pointer = {
        "schema": NONCURRENT_SCHEMA,
        "status": envelope["execution_status"],
        "run_id": envelope["run_id"],
        "job": envelope["job_id"],
        "attempt_id": envelope["attempt_id"],
        "fingerprint": envelope["input_fingerprint"],
        "envelope_path": relative_envelope,
        "envelope_sha256": file_hash(envelope_path),
        "updated_at": now(),
    }
    atomic_json(base / "accepted.json", pointer)
    return pointer


def publish_validated(base: Path, attempt_root: Path, envelope_path: Path,
                      expected_input_fingerprint: str, *, expected_run_id: str,
                      expected_job_id: str, consumer_job_id: str | None = None,
                      registry_root: Path | None = None, graph_path: Path | None = None,
                      pre_publish_validate: Callable[[Path, dict[str, Any]], None] | None = None
                      ) -> dict[str, Any]:
    """Validate a durable envelope and atomically publish its compatibility pointer."""
    base, attempt_root, envelope_path = Path(base), Path(attempt_root), Path(envelope_path)
    envelope = read_json(envelope_path)
    attempt_id = identifier(envelope.get("attempt_id"))
    if attempt_root.absolute() != (base / "attempts" / attempt_id).absolute():
        raise Blocked("publishable attempt is outside the owning job root")
    if envelope_path.absolute() != (attempt_root / "result.json").absolute():
        raise Blocked("publishable envelope must be the attempt's result.json")
    _latest_matches(base, attempt_id)
    _pending_matches(base, attempt_id)
    kwargs: dict[str, Any] = {"consumer_job_id": consumer_job_id}
    if registry_root is not None:
        kwargs["registry_root"] = registry_root
    if graph_path is not None:
        kwargs["graph_path"] = graph_path
    errors = validate_job_output(
        attempt_root, envelope, expected_input_fingerprint,
        expected_run_id=expected_run_id, expected_job_id=expected_job_id, **kwargs)
    if errors:
        raise Blocked("worker result validation failed: " + "; ".join(errors))
    if envelope.get("acceptance_status") != "CURRENT":
        raise Blocked("only a CURRENT envelope may be published")
    if pre_publish_validate is not None:
        pre_publish_validate(attempt_root, envelope)
    pointer = {
        "schema": ACCEPTED_SCHEMA,
        "status": envelope["execution_status"],
        "run_id": expected_run_id,
        "job": expected_job_id,
        "attempt_id": envelope["attempt_id"],
        "fingerprint": expected_input_fingerprint,
        "envelope_path": "result.json",
        "envelope_sha256": file_hash(envelope_path),
        "hashes": tree_hashes(attempt_root),
        "accepted_at": now(),
    }
    if envelope.get("skip_reason"):
        pointer["reason"] = envelope["skip_reason"]
    _latest_matches(base, envelope["attempt_id"])
    _pending_matches(base, envelope["attempt_id"])
    atomic_json(base / "accepted.json", pointer)
    return pointer


def validate_published(base: Path, pointer: dict[str, Any], expected_input_fingerprint: str,
                       *, expected_run_id: str, expected_job_id: str,
                       consumer_job_id: str | None = None,
                       registry_root: Path | None = None, graph_path: Path | None = None,
                       reuse: bool = False) -> tuple[Path, dict[str, Any]]:
    """Read and validate a published common result without modifying it."""
    if not common_pointer(pointer):
        raise Blocked("accepted pointer does not use the common worker-result publication format")
    required = {"run_id", "job", "attempt_id", "fingerprint", "status", "envelope_path",
                "envelope_sha256", "hashes"}
    missing = sorted(required - pointer.keys())
    if missing:
        raise Blocked("accepted pointer lacks required fields: " + ", ".join(missing))
    if pointer["run_id"] != expected_run_id or pointer["job"] != expected_job_id:
        raise Blocked("accepted pointer run/job identity mismatch")
    if pointer["fingerprint"] != expected_input_fingerprint:
        raise Blocked("accepted pointer input fingerprint mismatch")
    attempt_id = identifier(pointer["attempt_id"])
    _latest_matches(Path(base), attempt_id)
    attempt = Path(base) / "attempts" / attempt_id
    if tree_hashes(attempt) != pointer.get("hashes"):
        raise Blocked("accepted attempt artifacts changed")
    envelope_path = attempt / pointer.get("envelope_path", "")
    if file_hash(envelope_path) != pointer.get("envelope_sha256"):
        raise Blocked("accepted worker-result envelope changed")
    envelope = read_json(envelope_path)
    if (envelope.get("attempt_id") != attempt_id or
            envelope.get("execution_status") != pointer["status"]):
        raise Blocked("accepted pointer and worker-result envelope disagree")
    kwargs: dict[str, Any] = {"consumer_job_id": consumer_job_id, "reuse": reuse}
    if reuse:
        kwargs["accepted_envelope"] = envelope
    if registry_root is not None:
        kwargs["registry_root"] = registry_root
    if graph_path is not None:
        kwargs["graph_path"] = graph_path
    errors = validate_job_output(
        attempt, envelope, expected_input_fingerprint,
        expected_run_id=expected_run_id, expected_job_id=expected_job_id, **kwargs)
    if errors:
        raise Blocked("accepted worker result is invalid: " + "; ".join(errors))
    return attempt, envelope


def admit_reusable(
        base: Path, expected_input_fingerprint: str, *, expected_run_id: str,
        expected_job_id: str, consumer_job_id: str | None = None,
        registry_root: Path | None = None, graph_path: Path | None = None,
        post_validate: Callable[[Path, dict[str, Any]], None] | None = None
        ) -> dict[str, Any] | None:
    """Admit only a newest, fully validated reusable result; recover pending publication."""
    base = Path(base)
    pointer_path = base / "accepted.json"
    if not pointer_path.exists():
        return None
    pointer = read_json(pointer_path)
    recovered_publication = False
    if common_pointer(pointer):
        if "fingerprint" not in pointer:
            raise Blocked("accepted pointer lacks its input fingerprint")
        if pointer["fingerprint"] != expected_input_fingerprint:
            return None
    elif pointer.get("schema") == NONCURRENT_SCHEMA and pointer.get("status") == "PENDING":
        attempt_id = identifier(pointer.get("attempt_id"))
        _latest_matches(base, attempt_id)
        attempt = base / "attempts" / attempt_id
        status_path = attempt / "status.json"
        if not status_path.exists():
            raise Blocked("pending reusable candidate lacks durable status")
        status = read_json(status_path)
        if status.get("fingerprint") != expected_input_fingerprint:
            return None
        envelope_path = attempt / "result.json"
        if not envelope_path.exists():
            return None
        envelope = read_json(envelope_path)
        if (envelope.get("acceptance_status") != "CURRENT" or
                envelope.get("execution_status") not in {"OK", "OK_WITH_GAPS", "SKIPPED"}):
            raise Blocked("pending reusable candidate is not a publishable CURRENT envelope")
        pointer = publish_validated(
            base, attempt, envelope_path, expected_input_fingerprint,
            expected_run_id=expected_run_id, expected_job_id=expected_job_id,
            consumer_job_id=consumer_job_id, registry_root=registry_root,
            graph_path=graph_path, pre_publish_validate=post_validate)
        recovered_publication = True
    else:
        return None
    attempt, envelope = validate_published(
        base, pointer, expected_input_fingerprint, expected_run_id=expected_run_id,
        expected_job_id=expected_job_id, consumer_job_id=consumer_job_id,
        registry_root=registry_root, graph_path=graph_path, reuse=True)
    if post_validate is not None and not recovered_publication:
        post_validate(attempt, envelope)
    return {"pointer": pointer, "attempt": attempt, "envelope": envelope,
            "recovered_publication": recovered_publication}


def persist_terminal_current(
        base: Path, attempt_root: Path, *, run_id: str, job_id: str,
        dagster_run_id: str, worker_kind: str, output_contract: str,
        input_fingerprint: str, started_at: str, execution_status: str,
        summary: str, status_record: dict[str, Any], artifact_paths: list[str],
        gaps: list[str] | None = None, skip_reason: str | None = None,
        pre_envelope_validate: Callable[[Path, dict[str, Any]], None] | None = None
        ) -> dict[str, Any]:
    """Persist final status and one immutable publishable envelope, but not its pointer."""
    if execution_status not in {"OK", "OK_WITH_GAPS", "SKIPPED"}:
        raise ValueError("terminal current persistence requires a publishable execution status")
    base, attempt_root = Path(base), Path(attempt_root)
    attempt_id = identifier(attempt_root.name)
    if attempt_root.absolute() != (base / "attempts" / attempt_id).absolute():
        raise Blocked("terminal attempt is outside the owning job root")
    _latest_matches(base, attempt_id)
    _pending_matches(base, attempt_id)
    finished_at = now()
    status = dict(status_record)
    canonical = {"status": execution_status, "run_id": run_id, "job": job_id,
                 "attempt_id": attempt_id, "dagster_run_id": dagster_run_id,
                 "started_at": started_at, "ended_at": finished_at,
                 "fingerprint": input_fingerprint}
    for key, expected in canonical.items():
        if key in status and status[key] != expected and key not in {"status", "ended_at"}:
            raise Blocked(f"terminal status {key} conflicts with the current attempt")
    status.update(canonical)
    if skip_reason is not None:
        status["reason"] = skip_reason
    atomic_json(attempt_root / "status.json", status)
    if pre_envelope_validate is not None:
        pre_envelope_validate(attempt_root, status)
    envelope = terminal_envelope(
        run_id=run_id, job_id=job_id, attempt_id=attempt_id, worker_kind=worker_kind,
        execution_status=execution_status, acceptance_status="CURRENT",
        input_fingerprint=input_fingerprint, output_contract=output_contract,
        started_at=started_at, finished_at=finished_at, summary=summary,
        artifacts=artifact_records(attempt_root, artifact_paths), gaps=gaps,
        skip_reason=skip_reason)
    errors = validate_worker_result(envelope)
    if errors:
        raise Blocked("publishable worker result is invalid: " + "; ".join(errors))
    envelope_path = attempt_root / "result.json"
    if envelope_path.exists():
        if read_json(envelope_path) != envelope:
            raise Blocked("existing publishable envelope conflicts with terminal persistence")
    else:
        atomic_json(envelope_path, envelope)
    _latest_matches(base, attempt_id)
    _pending_matches(base, attempt_id)
    return envelope


def record_terminal_current(
        base: Path, attempt_root: Path, *, run_id: str, job_id: str,
        dagster_run_id: str, worker_kind: str, output_contract: str,
        input_fingerprint: str, started_at: str, execution_status: str,
        summary: str, status_record: dict[str, Any], artifact_paths: list[str],
        gaps: list[str] | None = None, skip_reason: str | None = None,
        consumer_job_id: str | None = None, registry_root: Path | None = None,
        graph_path: Path | None = None,
        pre_envelope_validate: Callable[[Path, dict[str, Any]], None] | None = None
        ) -> dict[str, Any]:
    """Persist and validate one publishable terminal, then atomically publish its pointer."""
    persist_terminal_current(
        base, attempt_root, run_id=run_id, job_id=job_id,
        dagster_run_id=dagster_run_id, worker_kind=worker_kind,
        output_contract=output_contract, input_fingerprint=input_fingerprint,
        started_at=started_at, execution_status=execution_status, summary=summary,
        status_record=status_record, artifact_paths=artifact_paths, gaps=gaps,
        skip_reason=skip_reason, pre_envelope_validate=pre_envelope_validate)
    return publish_validated(
        base, attempt_root, Path(attempt_root) / "result.json", input_fingerprint,
        expected_run_id=run_id, expected_job_id=job_id,
        consumer_job_id=consumer_job_id, registry_root=registry_root,
        graph_path=graph_path)
