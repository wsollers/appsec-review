"""Uniform, conservative admission of portable successful units from failed attempts."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from appsec_review.runtime.job import Job
from appsec_review.runtime.release import digest, read_document
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import immutable_bytes, reference, safe_path, verify_reference

SCHEMA = "appsec-review/unit-checkpoint/1"


def input_key(claim: Mapping[str, Any]) -> str:
    return digest({key: claim.get(key) for key in (
        "resolved_config_sha256", "job_id", "source_fingerprint", "job_config_sha256",
        "component_identities", "upstream_handoffs", "input_identity", "deployment_identity")})


def portable(value: Any) -> bool:
    """Do not transplant path-coupled files, process/budget state, or side-effect receipts."""
    if isinstance(value, Mapping):
        from appsec_review.interchange import classify_producer_status
        status = value.get("terminal_status")
        if status is not None and (not isinstance(status, str) or not status.strip()):
            return False
        if (value.get("retry_required") is True
                or classify_producer_status(status).retry_required):
            return False
        if set(value) & {"artifact", "path", "pointer", "budget", "budget_path", "workspace",
                         "index_manifest", "index_identity", "command", "pid", "process", "dispositions"}:
            return False
        return all(portable(item) for key, item in value.items() if key != "schema")
    if isinstance(value, list):
        return all(portable(item) for item in value)
    return not isinstance(value, str) or not any(char in value for char in ("/", "\\"))


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
            or checkpoint["input_key"] != input_key(claim) or checkpoint["portable"] is not True):
        raise ValueError("unit checkpoint input/implementation/portability changed")
    original = read_document(verify_reference(run_root, checkpoint["claim"]))
    if input_key(original) != input_key(claim):
        raise ValueError("checkpoint claim differs from the admitted fresh attempt")
    status = read_document(verify_reference(run_root, checkpoint["status"]))
    result_path = verify_reference(run_root, checkpoint["result"])
    if status.get("status") != "SUCCEEDED" or status.get("result_sha256") != checkpoint["result"]["sha256"]:
        raise ValueError("checkpoint has no committed successful unit")
    result = read_document(result_path, limit=1024 * 1024)
    if not portable(result):
        raise ValueError("checkpoint result is coupled to its original attempt")
    return result


def select_units(run_root: Path, job: Job, claim: Mapping[str, Any]) -> dict[str, Any]:
    from appsec_review.runtime.launch import unit_order
    candidates = sorted((run_root / f"data/jobs/{job.job_id}/attempts").glob("*/claim.json"))
    candidates = [path for path in candidates if path.parent.name < claim.get("attempt_id", "attempt_9999")]
    previous = candidates[-1].parent if candidates else None
    result = {}
    for unit_id in unit_order(job):
        entry: dict[str, Any] = {"action": "RUN", "reason": "no failed predecessor with a successful checkpoint"}
        unit = next(unit for unit in job.units if unit.unit_id == unit_id)
        if previous is not None and (previous / "status.json").exists():
            step, task = unit_id.split(".")
            checkpoint = previous / "steps" / step / "tasks" / task / "checkpoint.json"
            try:
                if read_document(previous / "status.json")["status"] == "FAILED" and checkpoint.exists():
                    entry["checkpoint"] = reference(run_root, checkpoint)
                    admitted_output(run_root, entry, claim, unit_id)
                    if any(result[dep]["action"] != "REUSE" for dep in unit.dependencies):
                        entry["reason"] = "dependency unit is not admitted for reuse"
                    else:
                        entry.update(action="REUSE", reason="successful portable unit; exact inputs and implementation")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                entry["reason"] = f"checkpoint admission refused: {type(exc).__name__}"
        result[unit_id] = entry
    return result
