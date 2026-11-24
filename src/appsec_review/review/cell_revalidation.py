"""Current validation of retained cell data; never a new model execution."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from appsec_review.review.identity import sha256_hex


SCHEMA = "appsec-review/cell-input-revalidation/1"
JOB_ID = "job_inference_security_review"
_BASE = {"schema", "namespace", "object_sha256", "consumer_claim_sha256", "cell_id", "attempt"}
_CELL = _BASE | {"executor_version", "validator_version", "guidance_sha256", "provider", "model",
                 "result_sha256"}
_CHECK = _BASE | {"check_schema", "markers_sha256", "cell_input_receipt"}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CHECK_SCHEMAS = {
    "appsec-review/verifier-request-check/1": "independence-attempt-",
    "appsec-review/judge-request-check/1": "judge-request-check-",
}


def _document(root: Path, ref: Mapping[str, Any]) -> dict[str, Any]:
    from appsec_review.storage.shared import verify_reference
    raw = verify_reference(root, ref).read_bytes()
    if len(raw) != ref["size_bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
        raise ValueError("retained cell bytes changed during validation")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("retained cell metadata must be an object")
    return value


def result_proof(owner, obj: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any] | None:
    # Cross-cell memo provenance is not promoted into an own-cell revalidation proof.
    if "reused_from" in receipt:
        return None
    return {
        "schema": SCHEMA, "namespace": "review-cell", "object_sha256": obj["sha256"],
        "consumer_claim_sha256": owner.actor["claim"]["sha256"],
        "cell_id": receipt["cell_id"], "attempt": receipt["attempt"],
        "executor_version": receipt["executor_version"], "validator_version": receipt["validator_version"],
        "guidance_sha256": receipt["guidance_bundle_sha256"],
        "provider": receipt["provider"], "model": receipt["model"],
        "result_sha256": receipt["result_sha256"],
    }


def check_proof(owner, obj: Mapping[str, Any], markers_sha256: str) -> dict[str, Any] | None:
    from appsec_review.storage.shared import reference, safe_path
    document = _document(owner.run_root, obj)
    if document.get("markers_sha256") != markers_sha256:
        raise ValueError("retained request check has different current markers")
    cell_path = (f"data/jobs/{JOB_ID}/cells/{document['cell_id']}"
                 f"/attempt-{document['attempt']}.json")
    cell_ref = reference(owner.run_root, safe_path(owner.run_root, cell_path))
    imported = owner.local_named_input("review-cell", cell_ref)
    if imported is None:
        return None
    return {
        "schema": SCHEMA, "namespace": "cell-check", "object_sha256": obj["sha256"],
        "consumer_claim_sha256": owner.actor["claim"]["sha256"],
        "cell_id": document["cell_id"], "attempt": document["attempt"],
        "check_schema": document["schema"], "markers_sha256": markers_sha256,
        "cell_input_receipt": imported,
    }


def verify_revalidation(root: Path, value: Mapping[str, Any], original: Mapping[str, Any],
                        claim: Mapping[str, Any], *, seen: frozenset[str] = frozenset()) -> None:
    """Validate an input-import certificate and its unchanged original model provenance."""
    from appsec_review.runtime.release import validate_claim_release
    from appsec_review.storage.shared import verify_receipt

    proof = value.get("revalidation")
    if (value["namespace"] != "shared-input" or value["mode"] != "reused"
            or value["producer_receipt"] is None or not isinstance(proof, dict)
            or proof.get("schema") != SCHEMA
            or original["namespace"] not in {"review-cell", "cell-check"}
            or original["mode"] != "computed" or original.get("layout") != "named-immutable"
            or original["legacy"] is not None):
        raise ValueError("invalid retained-cell input revalidation")
    namespace = original["namespace"]
    if set(proof) != (_CELL if namespace == "review-cell" else _CHECK):
        raise ValueError("invalid retained-cell revalidation fields")
    if (proof["namespace"] != namespace or proof["object_sha256"] != value["object"]["sha256"]
            or proof["consumer_claim_sha256"] != value["actor"]["claim"]["sha256"]):
        raise ValueError("retained-cell validation is not bound to this input and claimant")
    source_claim = _document(root, original["actor"]["claim"])
    if (claim["job_id"] != JOB_ID or source_claim["job_id"] != JOB_ID
            or claim["run_id"] != source_claim["run_id"] or claim["run_id"] != root.name
            or claim["attempt_id"] == source_claim["attempt_id"]
            or not isinstance(claim.get("repair_admission_sha256"), str)
            or not _SHA.fullmatch(claim["repair_admission_sha256"])
            or any(claim.get(key) != source_claim.get(key) for key in
                   ("resolved_config_sha256", "source_fingerprint", "evidence_target_snapshot",
                    "deployment_identity", "review_policy"))
            or claim["component_identities"]["schema"] != source_claim["component_identities"]["schema"]):
        raise ValueError("retained cell belongs to an incompatible run, policy, deployment or schema")
    if validate_claim_release(root, claim) is None or validate_claim_release(root, source_claim) is None:
        raise ValueError("retained-cell revalidation requires both measured source identities")
    document = _document(root, value["object"])
    cell_id, attempt = document.get("cell_id"), document.get("attempt")
    if (not isinstance(cell_id, str) or "/" in cell_id or "\\" in cell_id
            or type(attempt) is not int or attempt < 1
            or (proof["cell_id"], proof["attempt"]) != (cell_id, attempt)):
        raise ValueError("retained-cell identity differs from its validation")
    prefix = f"data/jobs/{JOB_ID}/cells/{cell_id}/"
    if namespace == "review-cell":
        from appsec_review.review.cells import EXECUTOR_VERSION, RECEIPT_SCHEMA, _RECEIPT_KEYS
        if (set(document) != _RECEIPT_KEYS or document["schema"] != RECEIPT_SCHEMA
                or document["status"] != "succeeded"
                or value["object"]["path"] != prefix + f"attempt-{attempt}.json"
                or document["executor_version"] != EXECUTOR_VERSION
                or not isinstance(document["result"], dict)
                or document["result_sha256"] != sha256_hex(document["result"])):
            raise ValueError("only a verified successful original cell result can be revalidated")
        fields = {
            "cell_fingerprint": cell_id, "executor_version": document["executor_version"],
            "validator_version": document["validator_version"],
            "guidance_sha256": document["guidance_bundle_sha256"],
            "provider": document["provider"], "model": document["model"],
        }
        if any(original["computation"].get(key) != expected for key, expected in fields.items()):
            raise ValueError("retained cell's producing computation does not match its result")
        if (any(proof[key] != fields[key] for key in fields if key != "cell_fingerprint")
                or proof["result_sha256"] != document["result_sha256"]):
            raise ValueError("retained result or validator differs from the current revalidation")
    else:
        schema = document.get("schema")
        keys = {"schema", "cell_id", "attempt", "markers_sha256", "request_sha256s",
                "contains_forbidden_marker"} | ({"leaked"} if schema == "appsec-review/judge-request-check/1" else set())
        if (schema not in _CHECK_SCHEMAS or set(document) != keys
                or value["object"]["path"] != prefix + _CHECK_SCHEMAS[schema] + f"{attempt}.json"
                or proof["check_schema"] != schema or proof["markers_sha256"] != document["markers_sha256"]
                or not isinstance(document["markers_sha256"], str) or not _SHA.fullmatch(document["markers_sha256"])
                or type(document["contains_forbidden_marker"]) is not bool
                or not isinstance(document["request_sha256s"], list) or not document["request_sha256s"]
                or any(not isinstance(item, str) or not _SHA.fullmatch(item)
                       for item in document["request_sha256s"])
                or original["computation"].get("cell_id") != cell_id
                or original["computation"].get("markers_sha256") != document["markers_sha256"]):
            raise ValueError("retained request-check structure or markers changed")
        if schema == "appsec-review/judge-request-check/1" and (
                not isinstance(document["leaked"], list)
                or any(not isinstance(item, str) for item in document["leaked"])
                or bool(document["leaked"]) != document["contains_forbidden_marker"]):
            raise ValueError("retained judge check contradicts its marker result")
        cell_input = _document(root, proof["cell_input_receipt"])
        if (cell_input.get("actor") != value["actor"] or cell_input.get("namespace") != "shared-input"
                or cell_input.get("revalidation", {}).get("namespace") != "review-cell"
                or cell_input.get("object", {}).get("path") != prefix + f"attempt-{attempt}.json"):
            raise ValueError("request check lacks this claimant's revalidated cell input")
        own_path = (f"{claim['attempt_path']}/shared/shared-input/{value['fingerprint']}.json")
        verify_receipt(root, proof["cell_input_receipt"], seen=seen | {own_path})
