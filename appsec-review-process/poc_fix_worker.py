#!/usr/bin/env python3
"""12b-poc-and-fix: light static PoC and proposed fix for verified, Critical, REACHABLE findings (brief F).

Lifecycle worker (``coordinate_worker_lifecycle`` / ``record_terminal_current``), run after
``12-scoring-prioritization``:

1. Load the accepted 12 result with full hash verification (12 carries each claim's verification
   status, citations and severity).
2. :mod:`poc_fix_select` decides eligibility with the report's own reachability code (verified +
   CRITICAL + REACHABLE) and builds one request workspace per eligible finding, at most
   ``poc_findings_max``. With none the job publishes SKIPPED ``not-applicable-no-eligible-findings``
   and launches nothing.
3. One ``poc-fix-author`` cell per request (:mod:`poc_fix_pool`); :mod:`poc_fix_derive` runs inside
   the invoker repair loop. :func:`build_result` (pure) reads the merge back into one record per
   finding, re-verifying citations, hashes and the denylist; a failed cell, mismatch, missing PoC or
   denylist rejection is a gap, never a job failure.

Nothing is executed, compiled or applied: every PoC is ``UNVALIDATED`` static text and every fix
``PATCH_PROPOSED_UNVALIDATED``. The job fails only on a broken input binding.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import claim_lifecycle_core
import persona_dispatch
import persona_prompt_assembly
import poc_fix_pool as fix_pool
import poc_fix_select as selector
import pool_specification
import review_cli
import tunables
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json, run_path
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import SchemaStore, validate_document

JOB = "12b-poc-and-fix"
CONTRACT = "12b-poc-and-fix"
RESULT = "poc-fix.json"
RESULT_SCHEMA = "poc-fix.schema.json"
SUMMARY = "poc-fix.md"
MERGE = "poc-fix-pool-merge.json"
SKIP_REASON = "not-applicable-no-eligible-findings"
PERMISSIONS = ["read-run-data", "write-run-data"]
ARTIFACTS = [RESULT, SUMMARY, MERGE, "permission.json", "lineage.json", "pool-receipt.json", "status.json"]
SCORING = ("12-scoring-prioritization", "scoring-prioritization.json", "scoring-prioritization.schema.json")
CLAIM_LIMITS = {"executed": False, "validated": False, "target_modified": False, "fixed_claimed": False,
                "finding_created": False, "severity_assigned": False}


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def tunable(name: str) -> Any:
    return tunables.value(JOB, name)


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes() -> dict[str, str]:
    values = fix_pool.code_hashes()
    for path in ("poc_fix_worker.py", f"registry/job-templates/{JOB}.json", f"registry/output-contracts/{CONTRACT}.json"):
        values[path] = file_hash(ROOT / path)
    values["schemas/" + RESULT_SCHEMA] = file_hash(ROOT.parent / "schemas" / RESULT_SCHEMA)
    return values


def load_scoring(run_id: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    """(accepted 12 result, its binding, accepted_at); raises Blocked on tamper or absence."""
    pointer = data_path(run_id, "jobs", SCORING[0], "accepted.json")
    if not pointer.is_file():
        raise Blocked(f"{JOB}: accepted 12-scoring-prioritization is required")
    scoring, binding = claim_lifecycle_core.load_accepted(pointer, run_id=run_id, job_id=SCORING[0],
        contract=SCORING[0], artifact=SCORING[1], schema=SCORING[2])
    return scoring, binding, read_json(pointer)["accepted_at"]


def prepare(run_id: str) -> dict[str, Any]:
    """The stable, fingerprinted inputs of one attempt (no model)."""
    scoring, binding, accepted_at = load_scoring(run_id)
    selected = selector.select(scoring, run_path(run_id), findings_max=tunable("poc_findings_max"),
                               window=tunable("poc_citation_window_lines"))
    records = scoring.get("priorities", [])
    source = records[0]["source_generation"] if records else None
    evaluated_at = datetime.fromisoformat(accepted_at.replace("Z", "+00:00")).astimezone(
        timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    permission = persona_dispatch._permission_block(JOB, run_id=run_id,
        source_snapshot_sha256=source or "sha256:" + "0" * 64, now=evaluated_at)
    requests = selected["requests"]
    spec = fix_pool.pool_spec(run_id, JOB, requests, permission=permission, binding=binding,
                              rendezvous_timeout_seconds=tunable("rendezvous_timeout_seconds"))
    return {"run_id": run_id, "source_generation": source, "scoring": binding,
            "ledger_head_sha256": scoring["ledger_head_sha256"],
            "eligibility": {key: selected[key] for key in ("rule", "considered", "eligible", "excluded")},
            "selection_gaps": selected["gaps"], "enrichment_inputs": selected["enrichment_inputs"],
            "requests": requests, "spec": spec, "accepted_at": evaluated_at,
            "applicability": "APPLICABLE" if requests else "SKIPPED_NA_NO_ELIGIBLE_FINDINGS", "code": _code_hashes()}


# --- post-pool bookkeeping (pure) ---------------------------------------------------------------

def build_result(inputs: dict[str, Any], merge: dict[str, Any]) -> dict[str, Any]:
    records, gaps, _coverage = fix_pool.collect(inputs["requests"], merge)
    requests = inputs["requests"]
    result = {"schema": "appsec-review/poc-fix/1.0", "run_id": inputs["run_id"], "job_id": JOB,
              "source_snapshot_sha256": inputs["source_generation"], "scoring": inputs["scoring"],
              "ledger_head_sha256": inputs["ledger_head_sha256"], "enrichment_inputs": inputs["enrichment_inputs"],
              "eligibility": {**inputs["eligibility"], "selected": len(requests)},
              "requests": [{"request_id": doc["request_id"], "claim_id": doc["claim_id"],
                            "workspace_sha256": _sha(doc)} for doc in requests],
              "records": records, "gaps": inputs["selection_gaps"] + gaps,
              "skip_reason": None if requests else SKIP_REASON,
              "pool": {"instances": len(requests),
                       "expected_worker_ids": list(merge.get("expected_worker_ids", [])),
                       "missing_worker_ids": list(merge.get("missing_worker_ids", [])),
                       "conflict_candidate_ids": [row["candidate_id"] for row in merge.get("conflicts", [])]},
              "claim_limits": dict(CLAIM_LIMITS)}
    errors = validate_document(result, RESULT_SCHEMA)
    if errors:
        raise Blocked(f"{JOB}: result fails its closed schema ({errors[0]})")
    return result


def summary(result: dict[str, Any]) -> str:
    eligibility = result["eligibility"]
    lines = ["# Light PoC and proposed fix (lane 12b)", "",
             f"Eligibility: {eligibility['rule']}.", "",
             f"{eligibility['considered']} scored claim(s); {eligibility['eligible']} eligible; "
             f"{eligibility['selected']} sent to a poc-and-fix cell; {len(result['records'])} record(s); "
             f"{len(result['gaps'])} gap(s).", ""]
    if result["skip_reason"]:
        lines += [f"SKIPPED: {result['skip_reason']} (no finding is verified, CRITICAL and REACHABLE).", ""]
    if result["records"]:
        lines += ["| Claim | PoC | Fix | Cited ranges |", "|---|---|---|---|"]
        for record in result["records"]:
            lines.append(f"| `{record['claim_id']}` | {record['poc']['status']} | {record['fix']['status']} | "
                         f"{len(record['cited_lines'])} |")
    if result["gaps"]:
        lines += ["", "## Gaps", ""] + [f"- {gap['reason']} ({gap['scope']} {gap['id']}): {gap['detail']}"
                                         for gap in result["gaps"]]
    lines += ["", "Every PoC is UNVALIDATED static text that was never executed; every fix is "
                  "PATCH_PROPOSED_UNVALIDATED and was not applied.", ""]
    return "\n".join(lines)


def _receipts(inputs: dict[str, Any], result: dict[str, Any], launched: dict[str, Any]) -> tuple[dict, dict, dict]:
    source = inputs["source_generation"]
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": inputs["run_id"],
                  "job_id": JOB, "source_snapshot_sha256": source, "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
               "source_snapshot_sha256": source,
               "build_lineage_sha256": _sha({"scoring": inputs["scoring"], "enrichment": inputs["enrichment_inputs"],
                                             "spec": pool_specification.spec_sha256(inputs["spec"]),
                                             "pool": launched, "result": _sha(result)})}
    receipt = {"schema": "appsec-review/poc-fix-pool-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
               "decision": inputs["applicability"], **launched}
    return permission, lineage, receipt


def _validate_attempt(attempt: Path, inputs: dict[str, Any], *, reprepare: bool = True) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked(f"{JOB}: immutable inputs or implementation changed")
    if reprepare and prepare(inputs["run_id"]) != inputs:
        raise Blocked(f"{JOB}: accepted 12 result or reachability inputs changed")
    result = read_json(attempt / RESULT)
    if result != build_result(inputs, read_json(attempt / MERGE)):
        raise Blocked(f"{JOB}: result differs from the retained merge")
    if (attempt / SUMMARY).read_bytes() != summary(result).encode("utf-8"):
        raise Blocked(f"{JOB}: summary differs from the result")
    receipt = read_json(attempt / "pool-receipt.json")
    launched = {key: receipt.get(key) for key in ("pool_directory", "pool_outcome", "instance_count",
                                                  "expansion_sha256", "terminal_manifest_sha256")}
    if (read_json(attempt / "permission.json"), read_json(attempt / "lineage.json"), receipt) != \
            _receipts(inputs, result, launched):
        raise Blocked(f"{JOB}: retained receipts changed")


def _budget_usd() -> float | None:
    template = persona_prompt_assembly.load_job_template(fix_pool.TEMPLATE, SchemaStore())
    value = (review_cli.load_model_config().get("budget_max_usd_per_call") or {}).get(template["budget_default"])
    return float(value) if isinstance(value, (int, float)) else None


def run(run_id: str, dagster_run_id: str, force: bool = False, *, invoker: Any = None) -> dict[str, Any]:
    """Dispatch the poc-and-fix pool (or skip) and publish the records."""
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        requests = inputs["requests"]
        merge = {"schema": "appsec-review/deterministic-pool-merge/1.0", "run_id": run_id, "expected_worker_ids": [],
                 "observed_worker_ids": [], "missing_worker_ids": [], "candidates": [], "conflicts": []}
        launched = {"pool_directory": None, "pool_outcome": "NOT_LAUNCHED", "instance_count": 0,
                    "expansion_sha256": None, "terminal_manifest_sha256": None}
        if requests:
            context = fix_pool.context(requests, spec=inputs["spec"], attempt=attempt,
                                       source_snapshot_sha256=inputs["source_generation"])
            effort = review_cli.resolve_model(fix_pool.TEMPLATE, "standard").get("effort") or "high"
            merge, pool = fix_pool.dispatch(run_id, inputs["spec"], context,
                invoker=invoker or fix_pool.PocFixInvoker(effort=effort, budget_usd=_budget_usd()),
                clock=lambda: inputs["accepted_at"], max_parallel=tunable("max_parallel"),
                wait_limit_seconds=tunable("rendezvous_timeout_seconds"))
            launched = {"pool_directory": pool.pool_directory, "pool_outcome": pool.outcome,
                        "instance_count": pool.instance_count, "expansion_sha256": pool.expansion_sha256,
                        "terminal_manifest_sha256": pool.terminal_manifest_sha256}
        result = build_result(inputs, merge)
        atomic_json(attempt / MERGE, merge); atomic_json(attempt / RESULT, result)
        atomic_bytes(attempt / SUMMARY, summary(result).encode("utf-8"))
        permission, lineage, receipt = _receipts(inputs, result, launched)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "pool-receipt.json", receipt)
        skip = result["skip_reason"]
        gaps = [f"{gap['reason']}: {gap['scope']} {gap['id']}: {gap['detail']}" for gap in result["gaps"]]
        status_value = "SKIPPED" if skip else ("OK_WITH_GAPS" if gaps else "OK")
        status = {"process": JOB, "status": status_value, "result": RESULT, "records": len(result["records"]),
                  "gaps": len(result["gaps"]), "eligible": result["eligibility"]["eligible"],
                  "claim_limit": "unvalidated-static-text-never-executed", "applicability": inputs["applicability"]}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
            worker_kind="pool_coordinator", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=status_value,
            summary=(f"SKIPPED {skip}: no PoC or fix written." if skip else
                     f"Published {len(result['records'])} unvalidated PoC-and-fix record(s)."),
            status_record=status, artifact_paths=ARTIFACTS, gaps=gaps or None, skip_reason=skip,
            consumer_job_id="10-synthesis-report",
            pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs, reprepare=False))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
        worker_kind="pool_coordinator", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/poc_fix_worker.py --run-id {run_id}",
        derive_inputs=lambda: prepare(run_id), fingerprint_inputs=_sha, execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Accepted 12 result was not current.",
        failed_summary="PoC-and-fix pool did not publish.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-poc-and-fix")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
