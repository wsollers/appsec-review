"""Bounded Dagster qualification worker for the B13 pinned-container adapter.

This is deliberately not a scanner and is not a lifecycle graph node.  It runs the tracked
``fixture-harmless`` image with one of two fixed argv arrays (success or a qualification-only
non-zero fault), through B13, then publishes the verified adapter evidence on the common worker
envelope.  The ``result_sha256`` returned by ``run_container`` stays in caller memory until
``to_worker_envelope`` has re-derived the attempt; only then is it written to the caller-owned
qualification receipt outside the adapter log.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any, Callable

import container_execution as ce
from execution_state import (Blocked, ROOT, atomic_json, data_path, digest, file_hash, now,
                             read_json, run_path)
import permission_capabilities as pc
from publish_job_output import coordinate_worker_lifecycle, publish_validated, validate_published
from schema_validate import validate_document
from worker_result import validate_worker_result

JOB = "b13-harmless-container"
DAGSTER_JOB = "b13_harmless_container"
CONTRACT = "b13-harmless-container"
WORKER_KIND = ce.WORKER_KIND
CONTROL_SCHEMA = "appsec-review/b13-harmless-qualification-input/1.0"
RECEIPT_SCHEMA = "appsec-review/b13-harmless-qualification/1.0"
CONTROL_FILE = "b13-harmless-qualification.json"
RECEIPT_FILE = "qualification.json"
IMAGE_ID = "fixture-harmless"
ARGV = {"success": ["/bin/true"], "exit-nonzero": ["/bin/false"]}
CODE_FILES = (
    "b13_harmless.py", "container_execution.py", "deterministic_child.py", "execution_state.py",
    "permission_capabilities.py", "publish_job_output.py", "validate_job_output.py",
    "worker_result.py", "registry/output-contracts/b13-harmless-container.json",
    "registry/container-images/fixture-harmless.json",
)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def control_path(run_id: str) -> Path:
    return run_path(run_id) / "inputs" / CONTROL_FILE


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    values["schemas/b13-harmless-qualification-input.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "b13-harmless-qualification-input.schema.json")
    return values


def stage_control(run_id: str, mode: str = "success") -> Path:
    """Install the closed qualification input. It grants no capability because the fixed image
    executes no target content, mounts no target, and has no network. The B11 evaluator still
    re-derives a GRANTED decision for that exact empty requirement on every attempt."""
    value = {
        "schema": CONTROL_SCHEMA,
        "mode": mode,
        "permission": {
            "requirement": {
                "schema": "appsec-review/permission-requirement/1.0",
                "job_id": JOB,
                "capabilities": [],
            },
            "grants": [],
        },
    }
    errors = validate_document(value, "b13-harmless-qualification-input.schema.json")
    if errors:
        raise ValueError("invalid B13 harmless qualification input")
    atomic_json(control_path(run_id), value)
    return control_path(run_id)


def _source_snapshot(run_id: str) -> str:
    manifest = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not manifest.is_file():
        raise Blocked(f"{JOB}: a staged run manifest is required")
    return "sha256:" + file_hash(manifest)


def _permission(control: dict[str, Any], run_id: str, source_snapshot: str,
                evaluated_at: str) -> dict[str, Any]:
    permission = control.get("permission")
    if not isinstance(permission, dict):
        raise Blocked(f"{JOB}: the qualification permission record is missing")
    requirement, grants = permission.get("requirement"), permission.get("grants")
    if not isinstance(requirement, dict) or not isinstance(grants, list):
        raise Blocked(f"{JOB}: the qualification permission requirement or grant list is missing")
    # This diagnostic requires no elevated capability. A supplied grant is therefore widening,
    # not authority to do more, and is refused before B13 sees the request.
    if requirement.get("job_id") != JOB or requirement.get("capabilities") != [] or grants:
        raise Blocked(f"{JOB}: qualification requires the exact zero-capability permission boundary")
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source_snapshot,
               "now": evaluated_at, "registry_ceiling": None}
    decision = pc.evaluate(requirement, grants, context)
    pc.require_granted(decision, requirement=requirement, grants=grants, context=context)
    return {"requirement": requirement, "grants": grants, "decision": decision}


def current_inputs(run_id: str) -> dict[str, Any]:
    path = control_path(run_id)
    if not path.is_file():
        raise Blocked(f"{JOB}: missing inputs/{CONTROL_FILE}; stage the closed qualification input")
    control = read_json(path)
    errors = validate_document(control, "b13-harmless-qualification-input.schema.json")
    if errors:
        raise Blocked(f"{JOB}: qualification input fails its closed schema ({len(errors)} errors)")
    source_snapshot = _source_snapshot(run_id)
    # Validate the exact boundary without making the evaluation timestamp part of reuse identity.
    permission = _permission(control, run_id, source_snapshot, _utc_now())
    image = ce.load_image_registry(ce.IMAGES_DIR)[IMAGE_ID]
    return {
        "job": JOB,
        "control": {"path": f"inputs/{CONTROL_FILE}", "sha256": file_hash(path),
                    "mode": control["mode"]},
        "source_snapshot_sha256": source_snapshot,
        "image": {"image_id": IMAGE_ID, "digest": image["digest"],
                  "reference": ce.image_reference(image),
                  "record_sha256": "sha256:" + digest(image)},
        "argv": ARGV[control["mode"]],
        "permission_fingerprint_sha256": pc.input_fingerprint_component(
            permission["decision"]),
        "boundary_sha256": ce.boundary_sha256(),
        "code": _code_hashes(),
    }


def _runtime(source_snapshot: str) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked(f"{JOB}: Docker is unavailable on the host")
    return ce.ContainerRuntime(
        docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=ce.IMAGES_DIR, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source_snapshot,
        registry_ceiling=None, clock=_utc_now, cancel=threading.Event())


def _request(run_id: str, attempt_id: str, record: dict[str, Any],
             evaluated_at: str | None = None) -> dict[str, Any]:
    control = read_json(control_path(run_id))
    permission = _permission(control, run_id, record["source_snapshot_sha256"],
                             evaluated_at or _utc_now())
    return {
        "schema": ce.REQUEST_ID,
        "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
        "image": {"image_id": record["image"]["image_id"],
                  "digest": record["image"]["digest"]},
        "argv": list(record["argv"]),
        "environment": [{"name": "LANG", "value": "C"}],
        "target_mounts": [],
        "scratch_path": "scratch",
        "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []},
        "permission": permission,
        "limits": {"timeout_seconds": 30, "memory_bytes": 32 * 1024 * 1024,
                   "cpu_millis": 250, "pids": 16, "tmpfs_bytes": 2 * 1024 * 1024,
                   "stdout_limit_bytes": 65536, "stderr_limit_bytes": 65536},
    }


def _host_facts(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable,
            "container_user": runtime.container_user}


def _validate_attempt(run_id: str, attempt: Path, record: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != record:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    receipt = read_json(attempt / RECEIPT_FILE)
    required = {"schema", "run_id", "job_id", "attempt_id", "image_reference",
                "expected_result_sha256", "permission_fingerprint_sha256", "verified_at"}
    if set(receipt) != required or receipt.get("schema") != RECEIPT_SCHEMA:
        raise Blocked(f"{JOB}: caller-owned qualification receipt is invalid")
    if (receipt.get("run_id"), receipt.get("job_id"), receipt.get("attempt_id")) != (
            run_id, JOB, attempt.name):
        raise Blocked(f"{JOB}: qualification receipt identity mismatch")
    if receipt.get("image_reference") != record["image"]["reference"]:
        raise Blocked(f"{JOB}: qualification receipt image mismatch")
    if receipt.get("permission_fingerprint_sha256") != record["permission_fingerprint_sha256"]:
        raise Blocked(f"{JOB}: qualification receipt permission mismatch")
    request = read_json(attempt / "logs" / "container" / ce.REQUEST_FILE)
    if (request.get("image") != {"image_id": record["image"]["image_id"],
                                 "digest": record["image"]["digest"]}
            or request.get("argv") != record["argv"] or request.get("target_mounts") != []
            or request.get("network") != {"mode": "none", "destinations": []}):
        raise Blocked(f"{JOB}: recorded adapter request differs from the fingerprinted input")
    runtime = _runtime(record["source_snapshot_sha256"])
    errors = ce.verify_container_result(
        attempt, run_id=run_id, job_id=JOB, attempt_id=attempt.name, request=request,
        images_dir=ce.IMAGES_DIR, expected_result_sha256=receipt["expected_result_sha256"],
        **_host_facts(runtime))
    if errors:
        raise Blocked(f"{JOB}: B13 evidence failed re-verification ({len(errors)} errors)")
    result = ce.load_verified_result(
        attempt, run_id=run_id, job_id=JOB, attempt_id=attempt.name, request=request,
        images_dir=ce.IMAGES_DIR, expected_result_sha256=receipt["expected_result_sha256"],
        **_host_facts(runtime))
    if result["execution_status"] != "OK" or result["image_reference"] != record["image"]["reference"]:
        raise Blocked(f"{JOB}: qualification attempt is not a successful run of the pinned image")


def run(run_id: str, dagster_id: str, force: bool = False, *,
        after_container: Callable[[Path, dict[str, Any], str], None] | None = None) -> dict[str, Any]:
    base = root(run_id)
    resume = (f"python -B appsec-review-process/launch_job.py --run-id {run_id} "
              f"--job {DAGSTER_JOB} --wait")

    def execute_attempt(allocation, record, fingerprint):
        attempt, attempt_id = allocation["attempt"], allocation["attempt_id"]
        if record["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before container execution")
        runtime = _runtime(record["source_snapshot_sha256"])
        request = _request(run_id, attempt_id, record)
        result = ce.run_container(runtime, run_id=run_id, job_id=JOB,
                                  attempt_id=attempt_id, attempt_root=attempt, request=request)
        # This local variable is the trust root for the immediate verifier. It is never recovered
        # from container-result.json or any other adapter-owned file.
        expected_result_sha256 = result["result_sha256"]
        if after_container is not None:
            after_container(attempt, request, expected_result_sha256)
        ce.to_worker_envelope(
            attempt, run_id=run_id, job_id=JOB, attempt_id=attempt_id, request=request,
            images_dir=ce.IMAGES_DIR, input_fingerprint=fingerprint, output_contract=CONTRACT,
            output_paths=[], resume_command=resume,
            expected_result_sha256=expected_result_sha256, **_host_facts(runtime))
        if result["execution_status"] != "OK":
            message = f"{JOB}: harmless container ended {result['execution_status']}"
            if result["execution_status"] == "BLOCKED":
                raise Blocked(message)
            raise RuntimeError(message)
        receipt = {
            "schema": RECEIPT_SCHEMA, "run_id": run_id, "job_id": JOB,
            "attempt_id": attempt_id, "image_reference": result["image_reference"],
            "expected_result_sha256": expected_result_sha256,
            "permission_fingerprint_sha256": result["permission_fingerprint_sha256"],
            "verified_at": now(),
        }
        atomic_json(attempt / RECEIPT_FILE, receipt)
        atomic_json(attempt / "status.json", {
            "status": "OK", "run_id": run_id, "job": JOB, "attempt_id": attempt_id,
            "dagster_run_id": dagster_id, "started_at": allocation["started_at"],
            "ended_at": now(), "fingerprint": fingerprint,
            "image_reference": result["image_reference"],
            "expected_result_sha256": expected_result_sha256,
            "permission_fingerprint_sha256": result["permission_fingerprint_sha256"],
        })
        envelope = ce.to_worker_envelope(
            attempt, run_id=run_id, job_id=JOB, attempt_id=attempt_id, request=request,
            images_dir=ce.IMAGES_DIR, input_fingerprint=fingerprint, output_contract=CONTRACT,
            output_paths=[RECEIPT_FILE, "status.json"], resume_command=resume,
            expected_result_sha256=expected_result_sha256, **_host_facts(runtime))
        envelope = {**ce.thaw(envelope), "acceptance_status": "CURRENT"}
        errors = validate_worker_result(envelope)
        if errors:
            raise Blocked(f"{JOB}: adapter envelope cannot be published ({len(errors)} errors)")
        atomic_json(attempt / "result.json", envelope)
        _validate_attempt(run_id, attempt, record)
        return publish_validated(base, attempt, attempt / "result.json", fingerprint,
                                 expected_run_id=run_id, expected_job_id=JOB)

    def failure_inputs(exc: BaseException) -> dict[str, Any]:
        return {"run_id": run_id, "job": JOB,
                "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}

    return coordinate_worker_lifecycle(
        base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind=WORKER_KIND, output_contract=CONTRACT, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: "sha256:" + digest(value),
        execute_attempt=execute_attempt, preflight_failure_inputs=failure_inputs, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        blocked_summary="B13 harmless-container qualification preflight did not complete.",
        failed_summary="B13 harmless-container qualification did not publish.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    record = current_inputs(run_id)
    attempt, _envelope = validate_published(
        base, pointer, "sha256:" + digest(record), expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, record)
    return attempt
