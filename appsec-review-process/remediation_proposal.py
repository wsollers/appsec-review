#!/usr/bin/env python3
"""Evidence-bounded remediation proposals for independently verified claims.

This worker does not edit target source, author a patch, execute a target, or claim a fix.  It
turns only current accepted verification decisions into reviewable remediation objectives and
routes each proposal to a same-environment retest bound to the current accepted native build.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import claim_lifecycle_core
import native_build
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import validate_document
import registry_paths

JOB = "11-remediation-proposal"
CONTRACT = "11-remediation-proposal"
RESULT = "remediation-proposal.json"
SUMMARY = "remediation-proposal-summary.md"
PERMISSIONS = ["read-run-data", "write-run-data"]


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes() -> dict[str, str]:
    names = ("remediation_proposal.py", "claim_lifecycle_core.py", "native_build.py",
             "build_replay.py", "publish_job_output.py", "validate_job_output.py",
             registry_paths.contract_rel("11-remediation-proposal"))
    result = {name: file_hash(ROOT / name) for name in names}
    result["schemas/remediation-proposal.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "remediation-proposal.schema.json")
    return result


def _accepted_verification(run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    pointer = data_path(run_id, "jobs", "09-independent-verification", "accepted.json")
    return claim_lifecycle_core.load_accepted(
        pointer, run_id=run_id, job_id="09-independent-verification",
        contract="09-independent-verification", artifact="independent-verification.json",
        schema="09-independent-verification.schema.json")


def current_inputs(run_id: str) -> dict[str, Any]:
    verification, verification_binding = _accepted_verification(run_id)
    build_attempt = native_build.validate(run_id)
    build_base = native_build.root(run_id)
    build_pointer_path = build_base / "accepted.json"
    build_pointer = read_json(build_pointer_path)
    build_result_path = build_attempt / native_build.RESULT
    build_result = read_json(build_result_path)
    build_inputs = read_json(build_attempt / "inputs.json")
    source_generation = build_inputs.get("source_snapshot_sha256")
    generations = {item.get("source_generation") for item in verification["verifications"]}
    if len(generations) > 1:
        raise Blocked(f"{JOB}: accepted verification mixes source generations")
    verification_source = next(iter(generations), source_generation)
    environment = {
        "job_id": native_build.JOB,
        "attempt_id": build_attempt.name,
        "accepted_pointer_sha256": "sha256:" + file_hash(build_pointer_path),
        "envelope_sha256": "sha256:" + file_hash(build_attempt / "result.json"),
        "artifact_path": build_result_path.relative_to(data_path(run_id)).as_posix(),
        "artifact_sha256": "sha256:" + file_hash(build_result_path),
        "source_revision": build_result["source_revision"],
        "source_generation": source_generation,
        "units": [{
            "unit_id": unit["unit_id"], "image_id": unit["image_id"],
            "image_digest": unit["image_digest"],
            "compile_database_sha256": unit["compile_database"]["sha256"],
            "binary_sha256": sorted(item["sha256"] for item in unit["binaries"]),
        } for unit in sorted(build_result["units"], key=lambda item: item["unit_id"])],
    }
    environment["environment_sha256"] = _sha(environment)
    return {"run_id": run_id, "verification": verification,
            "verification_binding": verification_binding, "environment": environment,
            "verification_source_generation": verification_source,
            "build_pointer_status": build_pointer["status"], "code": _code_hashes()}


def build_result(inputs: dict[str, Any], attempt_id: str) -> dict[str, Any]:
    verification = inputs["verification"]
    environment = inputs["environment"]
    verified = sorted((item for item in verification["verifications"]
                       if item["status"] == "VERIFIED"), key=lambda item: item["claim_id"])
    proposals = []
    for record in verified:
        citations: dict[str, dict[str, Any]] = {}
        for item in record["citations"] + record["verification_citations"]:
            prior = citations.setdefault(item["citation_id"], item)
            if prior != item:
                raise Blocked(f"{JOB}: one citation id names contradictory evidence")
        evidence = [citations[key] for key in sorted(citations)]
        proposal_id = "remediation-" + digest({
            "claim_id": record["claim_id"], "ledger_head": verification["ledger_head_sha256"],
            "environment": environment["environment_sha256"]})[:24]
        proposals.append({
            "proposal_id": proposal_id, "claim_id": record["claim_id"],
            "status": "PROPOSED_REVIEW_REQUIRED", "hypothesis": record["hypothesis"],
            "component_ids": sorted(record["component_ids"]),
            "source_generation": record["source_generation"],
            "component_generation": record["component_generation"],
            "remediation_objective": (
                "Address the independently verified claim at the cited evidence locations while "
                "preserving documented valid behavior and compatibility constraints."),
            "evidence": evidence,
            "proof_obligations": record["proof_obligations"],
            "dissent_ids": sorted(record["dissent_ids"]),
            "patch_status": "NOT_GENERATED", "target_modified": False,
            "retest": {"status": "NOT_RUN", "required": True,
                "same_environment_required": True,
                "environment_sha256": environment["environment_sha256"],
                "source_revision": environment["source_revision"],
                "required_verifier_role": "independent-verifier",
                "next_job_id": "remediation-retest-feedback"},
        })
    no_op = {"applicable": not bool(proposals),
             "reason": "no-independently-verified-claims" if not proposals else None}
    gaps = ([] if not proposals else [
        "No target change or patch was generated by this evidence-only worker.",
        "Same-environment retesting has not run; no proposal is a verified fix."])
    result = {"schema": "appsec-review/remediation-proposal/1.0", "run_id": inputs["run_id"],
        "job_id": JOB, "attempt_id": attempt_id,
        "status": "SKIPPED_NA" if no_op["applicable"] else "OK_WITH_GAPS",
        "source_generation": inputs["verification_source_generation"],
        "verification": inputs["verification_binding"], "environment": environment,
        "proposals": proposals, "no_op": no_op, "gaps": gaps,
        "claim_limits": {"target_modified": False, "patch_generated": False,
            "retest_executed": False, "fixed_claimed": False}}
    errors = validate_document(result, "remediation-proposal.schema.json")
    if errors:
        raise Blocked(f"{JOB}: generated result is invalid ({errors[0]})")
    return result


def _receipts(inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    source = inputs["verification_source_generation"]
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB, "source_snapshot_sha256": source,
        "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB, "source_snapshot_sha256": source,
        "build_lineage_sha256": _sha({"verification": inputs["verification_binding"],
            "environment": inputs["environment"]})}
    return permission, lineage


def _summary(result: dict[str, Any]) -> bytes:
    lines = ["# Remediation proposals", "", f"- result status: `{result['status']}`",
             f"- independently verified claims routed: {len(result['proposals'])}",
             f"- target modified: false", "- same-environment retest executed: false"]
    if result["no_op"]["applicable"]:
        lines.append(f"- not applicable: `{result['no_op']['reason']}`")
    return ("\n".join(lines) + "\n").encode()


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked(f"{JOB}: immutable inputs or implementation changed")
    if current_inputs(run_id) != inputs:
        raise Blocked(f"{JOB}: accepted verification or build environment changed")
    result = read_json(attempt / RESULT)
    if result != build_result(inputs, attempt.name):
        raise Blocked(f"{JOB}: result differs from deterministic accepted inputs")
    if (attempt / SUMMARY).read_bytes() != _summary(result):
        raise Blocked(f"{JOB}: summary differs from the result")
    permission, lineage = _receipts(inputs)
    if (read_json(attempt / "permission.json") != permission or
            read_json(attempt / "lineage.json") != lineage):
        raise Blocked(f"{JOB}: permission or lineage receipt changed")


def run(run_id: str, dagster_run_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        attempt = allocation["attempt"]
        result = build_result(inputs, allocation["attempt_id"])
        atomic_json(attempt / RESULT, result)
        atomic_bytes(attempt / SUMMARY, _summary(result))
        permission, lineage = _receipts(inputs)
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", lineage)
        status = {"process": JOB, "status": "OK_WITH_GAPS" if result["proposals"] else "OK",
            "result_status": result["status"], "proposals": len(result["proposals"]),
            "no_op": result["no_op"]["applicable"],
            "claim_limit": "proposal-only-no-target-change-no-fix-claim"}
        execution = status["status"]
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_run_id, worker_kind="deterministic_python",
            output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=execution,
            summary=("Published evidence-bounded remediation proposals." if result["proposals"] else
                     "No independently verified claims; retained an accepted non-applicable receipt."),
            status_record=status,
            artifact_paths=[RESULT, SUMMARY, "permission.json", "lineage.json", "status.json"],
            gaps=result["gaps"] or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB,
        dagster_run_id=dagster_run_id, worker_kind="deterministic_python",
        output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/remediation_proposal.py --run-id {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: _sha(value),
        execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job_id": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()},
        force=force, post_validate=lambda attempt, _envelope, inputs:
            _validate_attempt(run_id, attempt, inputs),
        blocked_summary="Accepted verification or build/environment lineage was unavailable.",
        failed_summary="Remediation proposals were not published.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-remediation-proposal")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
