#!/usr/bin/env python3
"""Claim-ledger status decisions after independent verification (ADR-0034 V1).

``claim-ledger-routing`` admits candidates before stage 07; nothing else wrote to the ledger, so every
claim stayed ``candidate`` whatever 07, 08 and 09 decided. This job takes the accepted routing ledger as
the prior and appends one authorized ``status_decision`` per claim and stage, in stage order, through
``claim_ledger.build_ledger`` (which re-derives each transition from the stage's exact accepted
attempt via ``claim_ledger.load_decision``). The report reads this ledger.

A stage verdict that repeats the claim's current status adds no event. A stage that is not accepted,
or that bound a different ledger head, is skipped and recorded as a gap, together with the stages
after it: uncertainty is published, never a reason to block (ADR-0034 item 4).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
import bounded_analysis_workers
import claim_ledger
import registry_paths

JOB = "claim-ledger-decisions"
CONTRACT = "claim-ledger-decisions"
LEDGER = claim_ledger.LEDGER
SUMMARY = "claim-ledger-decisions-summary.md"
PERMISSIONS = ["read-run-data", "write-run-data"]
STAGES = ("07-red-team-adversarial", "08-blue-team-refutation", "09-independent-verification")
CODE_FILES = ("claim_ledger_decisions.py", "claim_ledger.py", "publish_job_output.py",
              registry_paths.template_rel(JOB), registry_paths.contract_rel(CONTRACT))


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in ("claim-decision-ledger.schema.json", "claim-ledger-entry.schema.json",
                 "claim-ledger-citation.schema.json", *claim_ledger.DECISION_SCHEMAS.values()):
        values[f"schemas/{name}"] = file_hash(ROOT.parent / "schemas" / name)
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(values)


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def current_inputs(run_id: str) -> dict[str, Any]:
    """Bindings only (the fingerprint): the accepted routing ledger and each accepted stage result."""
    ledger, routing = bounded_analysis_workers.load_accepted(
        claim_ledger.root(run_id) / "accepted.json", run_id=run_id, job_id=claim_ledger.JOB,
        contract=claim_ledger.CONTRACT, artifact=LEDGER, schema="claim-decision-ledger.schema.json")
    stages: dict[str, Any] = {}
    for stage in STAGES:
        _job, artifact, _collection, _actor, _citations, _statuses = claim_ledger.DECISION_PRODUCERS[stage]
        pointer = data_path(run_id, "jobs", stage, "accepted.json")
        if not pointer.is_file():
            stages[stage] = None
            continue
        _result, binding = bounded_analysis_workers.load_accepted(
            pointer, run_id=run_id, job_id=stage, contract=stage, artifact=artifact,
            schema=claim_ledger.DECISION_SCHEMAS[stage])
        stages[stage] = binding
    return {"run_id": run_id, "routing": routing, "routing_head": ledger["head_hash"],
            "stages": stages, "code": _code_hashes()}


def plan(run_id: str, prior: dict[str, Any], jobs_root: Path,
         stages: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """(decision requests in stage order, gaps). Pure over the accepted stage artifacts it reads."""
    head_id, head_hash = prior["entries"][-1]["event_id"], prior["head_hash"]
    status = {item["claim_id"]: item["status"] for item in prior["claim_states"]}
    requests: list[dict[str, Any]] = []
    gaps: list[str] = []
    for stage in STAGES:
        binding = stages.get(stage)
        if binding is None:
            gaps.append(f"{stage} has no accepted result; its decisions and every later stage's are not in "
                        "the ledger")
            break
        _job, artifact, collection, _actor, _citations, statuses = claim_ledger.DECISION_PRODUCERS[stage]
        result = read_json(Path(jobs_root) / stage / "attempts" / binding["attempt_id"] / artifact)
        if (result.get("ledger_head_id"), result.get("ledger_head_sha256")) != (head_id, head_hash):
            gaps.append(f"{stage} reviewed a different ledger head; its decisions and every later stage's are "
                        "not in the ledger")
            break
        for row in sorted(result.get(collection, []), key=lambda item: item["claim_id"]):
            claim_id, target = row["claim_id"], statuses.get(row.get("status"))
            if claim_id not in status:
                gaps.append(f"{stage}: claim {claim_id} is not in the routing ledger")
            elif target is None:
                gaps.append(f"{stage}: claim {claim_id} disposition {row.get('status')} has no ledger status")
            elif target == status[claim_id]:
                continue
            elif target not in claim_ledger.TRANSITIONS[status[claim_id]]:
                gaps.append(f"{stage}: claim {claim_id} cannot move from {status[claim_id]} to {target}")
            else:
                requests.append({"claim_id": claim_id, "producer_job_id": stage})
                status[claim_id] = target
    return requests, gaps


def build(run_id: str, attempt_id: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    prior = read_json(data_path(run_id, "jobs", claim_ledger.JOB, "attempts", inputs["routing"]["attempt_id"], LEDGER))
    if prior["head_hash"] != inputs["routing_head"]:
        raise Blocked(f"{JOB}: routing ledger changed after its binding")
    jobs_root = data_path(run_id, "jobs")
    requests, gaps = plan(run_id, prior, jobs_root, inputs["stages"])
    ledger = claim_ledger.build_ledger(run_id, attempt_id, [], prior=prior, decisions=requests,
                                       decision_jobs_root=jobs_root, job_id=JOB)
    return ledger, gaps


def _receipts(inputs: dict[str, Any], ledger: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": inputs["run_id"],
        "job_id": JOB, "source_snapshot_sha256": ledger["source_generation"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": inputs["run_id"],
        "job_id": JOB, "source_snapshot_sha256": ledger["source_generation"],
        "build_lineage_sha256": _sha({"routing": inputs["routing"], "stages": inputs["stages"]})}
    return permission, lineage


def _summary(ledger: dict[str, Any], gaps: list[str]) -> str:
    counts: dict[str, int] = {}
    for item in ledger["claim_states"]:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    decisions = sum(entry["event_type"] == "status_decision" for entry in ledger["entries"])
    lines = ["# Claim ledger after stage decisions", "",
             f"{len(ledger['claim_states'])} claims; {decisions} status decisions appended; head "
             f"`{ledger['head_hash']}`.", "", "| Status | Claims |", "|---|---:|"]
    lines += [f"| {key} | {counts[key]} |" for key in sorted(counts)]
    if gaps:
        lines += ["", "## Gaps", ""] + [f"- {gap}" for gap in gaps]
    lines += ["", "A ledger status is a review state, not a finding, severity, runtime or compliance claim.", ""]
    return "\n".join(lines)


def _validate_attempt(attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable inputs changed")
    ledger, _gaps = build(inputs["run_id"], attempt.name, inputs)
    if read_json(attempt / LEDGER) != ledger:
        raise Blocked(f"{JOB}: ledger differs from immutable inputs")
    permission, lineage = _receipts(inputs, ledger)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: permission or lineage receipt differs from canonical inputs")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        attempt = allocation["attempt"]
        ledger, gaps = build(run_id, attempt.name, inputs)
        atomic_json(attempt / LEDGER, ledger)
        atomic_bytes(attempt / SUMMARY, _summary(ledger, gaps).encode())
        permission, lineage = _receipts(inputs, ledger)
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", lineage)
        execution = "OK_WITH_GAPS" if gaps else "OK"
        status = {"process": JOB, "status": execution, "claims": len(ledger["claim_states"]),
                  "decisions": sum(entry["event_type"] == "status_decision" for entry in ledger["entries"]),
                  "ledger_head_hash": ledger["head_hash"], "claim_limit": "candidate-only"}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="deterministic_python", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=execution,
            summary="Claim ledger with the accepted 07, 08 and 09 status decisions appended.",
            status_record=status, artifact_paths=[LEDGER, SUMMARY, "permission.json", "lineage.json", "status.json"],
            gaps=gaps or None, pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/claim_ledger_decisions.py --run-id {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=_sha,
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Claim ledger decisions were blocked.",
        failed_summary="Claim ledger decisions failed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-claim-ledger-decisions")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))
