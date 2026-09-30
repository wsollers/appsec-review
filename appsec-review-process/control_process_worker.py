#!/usr/bin/env python3
"""Common immutable-attempt publisher for deterministic review-control processes."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from execution_state import Blocked, atomic_json, digest, file_hash
from schema_validate import validate_document
from worker_result import artifact_records, terminal_envelope, validate_worker_result
import registry_paths

PERMISSIONS = ["read-run-data", "write-run-data"]
REGISTRY = registry_paths.OUTPUT_CONTRACTS_DIR


def _validated_contract(job_id: str, contract_id: str, result_name: str,
                        result: dict[str, Any]) -> dict[str, Any]:
    """Resolve the registered output contract and validate the exact result it declares."""
    contract_path = REGISTRY / f"{contract_id}.json"
    if contract_path.is_symlink() or not contract_path.is_file():
        raise Blocked(f"{job_id}: registered output contract is absent")
    import json
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Blocked(f"{job_id}: registered output contract is unreadable") from exc
    declared = contract.get("result_schema")
    required = contract.get("required_files")
    if (contract.get("contract_id") != contract_id or not isinstance(declared, dict) or
            declared.get("artifact") != result_name or
            not isinstance(required, list) or set(required) != {
                result_name, "permission.json", "lineage.json", "status.json"}):
        raise Blocked(f"{job_id}: contract/result binding is invalid")
    schema_name = declared.get("schema_file")
    if not isinstance(schema_name, str):
        raise Blocked(f"{job_id}: result schema binding is invalid")
    errors = validate_document(result, schema_name)
    if errors:
        raise Blocked(f"{job_id}: result violates its registered schema ({errors[0]})")
    return contract


def publish(*, run_id: str, job_id: str, attempt_id: str, contract_id: str, result_name: str,
            result: dict[str, Any], output_root: Path, source_snapshot_sha256: str,
            input_binding: dict[str, Any], started_at: str, finished_at: str) -> dict[str, Any]:
    """Publish one complete control result atomically; never leave a partial immutable attempt."""
    output_root = Path(output_root)
    if output_root.exists():
        raise Blocked(f"{job_id}: immutable attempt already exists")
    if not source_snapshot_sha256.startswith("sha256:"):
        raise Blocked(f"{job_id}: source snapshot binding is invalid")
    _validated_contract(job_id, contract_id, result_name, result)
    parent = output_root.parent; parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{job_id}-", dir=parent))
    try:
        atomic_json(staging / result_name, result)
        atomic_json(staging / "permission.json", {"schema":"appsec-review/producer-permission-receipt/1.0",
            "run_id":run_id,"job_id":job_id,"source_snapshot_sha256":source_snapshot_sha256,
            "permissions":PERMISSIONS})
        atomic_json(staging / "lineage.json", {"schema":"appsec-review/producer-lineage-receipt/1.0",
            "run_id":run_id,"job_id":job_id,"source_snapshot_sha256":source_snapshot_sha256,
            "build_lineage_sha256":"sha256:"+digest(input_binding)})
        atomic_json(staging / "status.json", {"process":job_id,"status":"OK","result":result_name,
            "claim_limit":"CONTROL_DECISION_ONLY"})
        names=[result_name,"permission.json","lineage.json","status.json"]
        envelope=terminal_envelope(run_id=run_id,job_id=job_id,attempt_id=attempt_id,
            worker_kind="deterministic_python",execution_status="OK",acceptance_status="CURRENT",
            input_fingerprint="sha256:"+digest(input_binding),output_contract=contract_id,
            started_at=started_at,finished_at=finished_at,
            summary=f"Deterministic {job_id} control result.",artifacts=artifact_records(staging,names))
        errors=validate_worker_result(envelope)
        if errors: raise Blocked(f"{job_id}: common result envelope is invalid ({errors[0]})")
        atomic_json(staging/"result.json",envelope)
        try: os.replace(staging,output_root)
        except OSError as exc: raise Blocked(f"{job_id}: atomic attempt publication failed") from exc
        return {"attempt_path":str(output_root),"result_sha256":"sha256:"+file_hash(output_root/result_name),
                "envelope_sha256":"sha256:"+file_hash(output_root/"result.json")}
    finally:
        if staging.exists(): shutil.rmtree(staging)
