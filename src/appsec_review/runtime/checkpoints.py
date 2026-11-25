"""Uniform, conservative admission of portable successful units from failed attempts."""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.runtime.job import Job
from appsec_review.runtime.release import digest, read_document
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import immutable_bytes, reference, safe_path, verify_reference

SCHEMA = "appsec-review/unit-checkpoint/1"
_REFERENCE_KEYS = {"path", "sha256", "size_bytes"}


def _artifact_reference(value: Mapping[str, Any]) -> bool:
    return (set(value) == _REFERENCE_KEYS
            and isinstance(value["path"], str) and bool(value["path"])
            and isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None
            and type(value["size_bytes"]) is int and value["size_bytes"] >= 0)


def input_key(claim: Mapping[str, Any]) -> str:
    prior = claim.get("optional_prior_handoffs")
    return digest({
        **{key: claim.get(key) for key in (
            "resolved_config_sha256", "job_id", "source_fingerprint", "job_config_sha256",
            "component_identities", "upstream_handoffs", "input_identity", "deployment_identity")},
        **({"optional_prior_handoffs": dict(prior)} if prior else {}),
    })


def portable(value: Any) -> bool:
    """Allow hash-bound artifact references, never unbound paths or process/budget state."""
    if isinstance(value, Mapping):
        if _artifact_reference(value):
            return True
        from appsec_review.interchange import classify_producer_status
        status = value.get("terminal_status")
        if status is not None and (not isinstance(status, str) or not status.strip()):
            return False
        if (value.get("retry_required") is True
                or classify_producer_status(status).retry_required):
            return False
        if "artifact" in value and (not isinstance(value["artifact"], Mapping)
                                    or not _artifact_reference(value["artifact"])):
            return False
        if set(value) & {"path", "pointer", "budget", "budget_path", "workspace",
                         "index_manifest", "index_identity", "command", "pid", "process", "dispositions"}:
            return False
        return all(portable(item) for key, item in value.items() if key != "schema")
    if isinstance(value, list):
        return all(portable(item) for item in value)
    return not isinstance(value, str) or not any(char in value for char in ("/", "\\"))


def _verify_artifacts(run_root: Path, value: Any) -> None:
    if isinstance(value, Mapping):
        if _artifact_reference(value):
            verify_reference(run_root, value)
        else:
            for child in value.values():
                _verify_artifacts(run_root, child)
    elif isinstance(value, list):
        for child in value:
            _verify_artifacts(run_root, child)


def publish_checkpoint(run_root: Path, unit_root: Path, claim: Mapping[str, Any], unit_id: str,
                       result: Mapping[str, Any]) -> None:
    value = {"schema": SCHEMA, "unit_id": unit_id, "input_key": input_key(claim),
             "claim": reference(run_root, safe_path(run_root, claim["attempt_path"] + "/claim.json")),
             "status": reference(run_root, unit_root / "status.json"),
             "result": reference(run_root, unit_root / "result.json"),
             "portable": portable(result) and len(canonical_json(result)) <= 1024 * 1024}
    immutable_bytes(run_root, (unit_root / "checkpoint.json").relative_to(run_root).as_posix(),
                    canonical_json(value))


def admitted_output(run_root: Path, entry: Mapping[str, Any], claim: Mapping[str, Any],
                    unit_id: str) -> dict[str, Any]:
    checkpoint = read_document(verify_reference(run_root, entry["checkpoint"]))
    if "undeclared" in claim.get("component_identities", {}).values():
        raise ValueError("unit checkpoint lacks measured implementation provenance")
    if (checkpoint.get("schema") != SCHEMA or checkpoint["unit_id"] != unit_id
            or checkpoint["input_key"] != input_key(claim)):
        raise ValueError("unit checkpoint input/implementation/portability changed")
    original = read_document(verify_reference(run_root, checkpoint["claim"]))
    if original.get("attempt_id") != claim.get("attempt_id"):
        raise ValueError("cross-attempt unit salvage is not a whole-job recovery")
    if input_key(original) != input_key(claim):
        raise ValueError("checkpoint claim differs from the admitted fresh attempt")
    status = read_document(verify_reference(run_root, checkpoint["status"]))
    result_path = verify_reference(run_root, checkpoint["result"])
    if (status.get("status") != "SUCCEEDED" or status.get("unit_id") != unit_id
            or status.get("result_sha256") != checkpoint["result"]["sha256"]):
        raise ValueError("checkpoint has no committed successful unit")
    result = read_document(result_path, limit=1024 * 1024)
    if not portable(result):
        raise ValueError("checkpoint result is coupled to its original attempt")
    _verify_artifacts(run_root, result)
    return result


def _reusable_predecessor(run_root: Path, previous: Path, claim: Mapping[str, Any]) -> bool:
    state = read_document(previous / "status.json")["status"]
    if state == "FAILED":
        return True
    if state != "RUNNING":
        return False
    from appsec_review.runtime.repair import WORKER_PROTOCOL, read_verified_dispatch_stop
    original = read_document(previous / "claim.json")
    orchestration = original.get("orchestration", {})
    if original.get("worker_protocol") != WORKER_PROTOCOL or orchestration.get("system") != "dagster":
        return False
    dispatch = orchestration.get("run_id")
    if dispatch == claim.get("orchestration", {}).get("run_id"):
        raise ValueError("checkpoint predecessor belongs to the current dispatch")
    read_verified_dispatch_stop(run_root, dispatch)
    return True


def select_units(run_root: Path, job: Job, claim: Mapping[str, Any]) -> dict[str, Any]:
    """A failed/new job executes every unit; only accepted whole jobs are reusable."""
    from appsec_review.runtime.launch import unit_order
    return {unit_id: {"action": "RUN", "reason": "whole-job attempt; no prior cell reuse"}
            for unit_id in unit_order(job)}
