#!/usr/bin/env python3
"""Final claim-decision ledger: the L01 ledger plus the accepted 07/08/09 lifecycle decisions.

``claim-ledger-routing`` (L01) admits candidates and 07/08/09/12 review its head, so the decisions
cannot be appended there. This job runs after 12: Python re-derives every claim's decision requests
(``{claim_id, producer_job_id}``) from the exact accepted stage publications, and
``claim_ledger.build_ledger`` appends them, stage by stage, through ``load_decision``'s authority. The
L01 entries and head stay byte-identical: the report's lifecycle origin (system guide section 9: the
report keeps the admission head and the later decision head).

12 assigns no ledger status (``claim_ledger.AUTHORITY`` has none); its publication must review the
same head and agree with 09. Dispositions map to ledger statuses only through
``claim_ledger.DECISION_PRODUCERS`` (09 ``BLOCKED`` is ``unresolved``). A claim a stage has no row for
keeps its status and is a named gap. A disposition equal to the current status (09 ``REFUTED`` after an
08 refutation) appends nothing. An 08 refutation that 09 does not confirm (09 ``UNRESOLVED`` or ``BLOCKED``)
is not appended, because ``refuted`` is terminal in the ledger and 09 is the independent check of it: the
ledger records 09's ``unresolved`` and names the unconfirmed refutation as a gap, so the claim stays open
in the report (run 20261006T150309Z-fdd8d6 blocked on "illegal transition refuted -> unresolved"). Any other
illegal transition, an authority the producer does not hold, or a stage that reviewed another ledger head
blocks.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import bounded_analysis_workers
import claim_ledger
import tool_evidence
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
import registry_paths

JOB = "claim-ledger-final"
CONTRACT = "claim-ledger-final"
LEDGER = claim_ledger.LEDGER
SUMMARY = "claim-ledger-final-summary.md"
PERMISSIONS = ["read-run-data", "write-run-data"]
STAGES = ("07-red-team-adversarial", "08-blue-team-refutation", "09-independent-verification")
SCORING = "12-scoring-prioritization"
RED, BLUE, VERIFY = STAGES
# job -> (contract, artifact, schema, collection, status field) of every accepted input.
SOURCES = {claim_ledger.JOB: (claim_ledger.CONTRACT, LEDGER, "claim-decision-ledger.schema.json", None, None),
           **{job: (spec[0], spec[1], claim_ledger.DECISION_SCHEMAS[job], spec[2], "status")
              for job, spec in claim_ledger.DECISION_PRODUCERS.items()},
           SCORING: (SCORING, "scoring-prioritization.json", "scoring-prioritization.schema.json",
                     "priorities", "verification_status")}
CODE_FILES = ("claim_ledger_final.py", "claim_ledger.py", registry_paths.template_rel(JOB),
              registry_paths.contract_rel(CONTRACT),
              # cited structural records re-run through these (ADR-0035)
              "tool_evidence.py", "code_query_mcp.py", "code_index.py", "reachability.py")
SCHEMA_FILES = ("claim-decision-ledger.schema.json", "claim-ledger-entry.schema.json",
                "claim-ledger-citation.schema.json", *(SOURCES[job][2] for job in (*STAGES, SCORING)))


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes() -> dict[str, str]:
    values = {name: file_hash(ROOT / name) for name in CODE_FILES}
    values.update({"schemas/" + name: file_hash(ROOT.parent / "schemas" / name) for name in SCHEMA_FILES})
    return values


def _load(jobs_root: Path, run_id: str, job: str) -> tuple[dict[str, Any], dict[str, Any]]:
    contract, artifact, schema, _collection, _field = SOURCES[job]
    return bounded_analysis_workers.load_accepted(Path(jobs_root) / job / "accepted.json", run_id=run_id,
        job_id=job, contract=contract, artifact=artifact, schema=schema)


def current_inputs(run_id: str, jobs_root: Path | None = None) -> dict[str, Any]:
    jobs_root = Path(jobs_root) if jobs_root is not None else data_path(run_id, "jobs")
    return {"run_id": run_id, "bindings": {job: _load(jobs_root, run_id, job)[1] for job in SOURCES},
            "code": _code_hashes()}


def _rows(job: str, document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for row in document[SOURCES[job][3]]:
        if row["claim_id"] in rows:
            raise Blocked(f"{JOB}: {job} decides claim {row['claim_id']} more than once")
        rows[row["claim_id"]] = row
    return rows


def plan(run_id: str, documents: dict[str, dict[str, Any]], bindings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Decision requests in lifecycle order, plus the claims each stage left undecided (named gaps)."""
    origin = documents[claim_ledger.JOB]
    errors = claim_ledger.validate_ledger(origin)
    if errors or origin["run_id"] != run_id:
        raise Blocked(f"{JOB}: accepted L01 ledger is invalid ({errors[0] if errors else 'run identity'})")
    if any(entry["event_type"] != "candidate_admitted" for entry in origin["entries"]):
        raise Blocked(f"{JOB}: accepted L01 ledger already holds decisions; it is not the lifecycle origin")
    head = (origin["entries"][-1]["event_id"], origin["head_hash"])
    previous = bindings[claim_ledger.JOB]
    for job in (*STAGES, SCORING):
        document, upstream = documents[job], documents[job]["upstream"]
        if (document["ledger_head_id"], document["ledger_head_sha256"]) != head:
            raise Blocked(f"{JOB}: {job} reviewed another ledger head than the accepted L01 ledger")
        if ((upstream["job_id"], upstream["attempt_id"], upstream["pointer_sha256"], upstream["artifact_sha256"]) !=
                (previous["job_id"], previous["attempt_id"], previous["accepted_pointer_sha256"],
                 previous["artifact_sha256"])):
            raise Blocked(f"{JOB}: {job} does not consume the accepted {previous['job_id']} publication")
        previous = bindings[job]
    statuses = {item["claim_id"]: item["status"] for item in origin["claim_states"]}
    requests, gaps, concurred = [], [], {job: 0 for job in STAGES}
    for job in STAGES:
        outcomes, rows = claim_ledger.DECISION_PRODUCERS[job][5], _rows(job, documents[job])
        if set(rows) - set(statuses):
            raise Blocked(f"{JOB}: {job} decides claims the L01 ledger never admitted")
        for claim_id in sorted(statuses):
            row, current = rows.get(claim_id), statuses[claim_id]
            if row is None:
                gaps.append(f"LEDGER-GAP {job}-undecided: claim {claim_id} has no {job} decision; "
                            f"the ledger keeps it {current}.")
                continue
            target = outcomes.get(row["status"])
            if target is None:
                raise Blocked(f"{JOB}: {job} disposition {row['status']} of claim {claim_id} maps to no ledger status")
            if job == BLUE and target == "refuted":
                check = _rows(VERIFY, documents[VERIFY]).get(claim_id)
                answered = check and claim_ledger.DECISION_PRODUCERS[VERIFY][5].get(check["status"])
                if answered and answered != "refuted":
                    gaps.append(f"LEDGER-GAP {job}-refutation-unconfirmed: claim {claim_id} was refuted at {job}, but "
                                f"{VERIFY} answered {check['status']}; the ledger records the independent "
                                f"verification ({answered}), not the refutation.")
                    continue
            if target == current:
                concurred[job] += 1
                continue
            if target not in claim_ledger.TRANSITIONS[current]:
                raise Blocked(f"{JOB}: illegal transition {current} -> {target} for claim {claim_id} at {job}")
            if target not in claim_ledger.AUTHORITY[job]:
                raise Blocked(f"{JOB}: {job} holds no authority for {target} (claim {claim_id})")
            requests.append({"claim_id": claim_id, "producer_job_id": job}); statuses[claim_id] = target
    verified = _rows("09-independent-verification", documents["09-independent-verification"])
    scored = _rows(SCORING, documents[SCORING])
    if set(scored) != set(verified) or any(scored[key]["verification_status"] != verified[key]["status"]
                                           for key in scored):
        raise Blocked(f"{JOB}: {SCORING} does not score exactly the accepted 09 dispositions")
    if not requests:
        raise Blocked(f"{JOB}: no accepted lifecycle decision for any claim; the final ledger would have no decision chain")
    return {"requests": requests, "gaps": gaps, "concurred": concurred, "statuses": statuses,
            "origin_head_id": head[0], "origin_head_hash": head[1]}


def verify_structural(run_id: str, jobs_root: Path, documents: dict[str, dict[str, Any]]) -> int:
    """Every ``tev:`` citation a 07/08/09 decision carries into the ledger is the canonical citation of an
    untampered tool-evidence record whose query still re-runs to the recorded answer (ADR-0035)."""
    checked: set[str] = set()
    for job in STAGES:
        field = claim_ledger.DECISION_PRODUCERS[job][4]
        for row in _rows(job, documents[job]).values():
            items = list(row.get(field) or [])
            for obligation in row.get("proof_obligations") or []:
                items += obligation.get("citations") or []
            for citation in items:
                key = json.dumps(citation, sort_keys=True)
                if not tool_evidence.is_citation(citation) or key in checked:
                    continue
                try:
                    tool_evidence.verify_citation(run_id, citation, data_root=Path(jobs_root).resolve().parent)
                except (ValueError, OSError) as exc:
                    raise Blocked(f"{JOB}: {job} claim {row['claim_id']} cites invalid tool evidence "
                                  f"({str(exc)[:300]})") from None
                checked.add(key)
    return len(checked)


def derive(run_id: str, attempt_id: str, inputs: dict[str, Any],
           jobs_root: Path | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    jobs_root = Path(jobs_root) if jobs_root is not None else data_path(run_id, "jobs")
    documents = {}
    for job in SOURCES:
        documents[job], binding = _load(jobs_root, run_id, job)
        if binding != inputs["bindings"][job]:
            raise Blocked(f"{JOB}: accepted {job} changed after the inputs were bound")
    steps = plan(run_id, documents, inputs["bindings"])
    verify_structural(run_id, jobs_root, documents)
    origin = documents[claim_ledger.JOB]
    ledger = claim_ledger.build_ledger(run_id, attempt_id, [], prior=origin, decisions=steps["requests"],
                                       decision_jobs_root=jobs_root)
    count = len(origin["entries"])
    if (ledger["entries"][:count] != origin["entries"] or ledger["entries"][count - 1]["entry_hash"] != origin["head_hash"] or
            {item["claim_id"]: item["status"] for item in ledger["claim_states"]} != steps["statuses"]):
        raise Blocked(f"{JOB}: appended ledger does not extend the L01 origin as planned")
    return ledger, steps


def _receipts(inputs: dict[str, Any], ledger: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    common = {"run_id": inputs["run_id"], "job_id": JOB, "source_snapshot_sha256": ledger["source_generation"]}
    return ({"schema": "appsec-review/producer-permission-receipt/1.0", **common, "permissions": PERMISSIONS},
            {"schema": "appsec-review/producer-lineage-receipt/1.0", **common,
             "build_lineage_sha256": _sha(inputs["bindings"])})


def _summary(ledger: dict[str, Any], steps: dict[str, Any]) -> str:
    appended = {job: sum(item["producer_job_id"] == job for item in steps["requests"]) for job in STAGES}
    undecided = {job: sum(gap.startswith(f"LEDGER-GAP {job}-") for gap in steps["gaps"]) for job in STAGES}
    states: dict[str, int] = {}
    for item in ledger["claim_states"]:
        states[item["status"]] = states.get(item["status"], 0) + 1
    lines = ["# Final claim-decision ledger", "",
             f"{len(ledger['claim_states'])} claims; L01 origin head `{steps['origin_head_hash']}`; "
             f"final head `{ledger['head_hash']}`.", "",
             "| Stage | Decisions appended | Concurring (no transition) | Undecided (gap) |", "|---|---:|---:|---:|"]
    lines += [f"| {job} | {appended[job]} | {steps['concurred'][job]} | {undecided[job]} |" for job in STAGES]
    lines += ["", "| Ledger status | Claims |", "|---|---:|"] + [f"| {key} | {states[key]} |" for key in sorted(states)]
    lines += ["", "12-scoring-prioritization assigns no ledger status; it reviews the same origin head and agrees "
              "with 09. An undecided claim keeps its status and is a gap, not a pass.", "",
              "Ledger decisions do not create a finding, severity, runtime, or compliance claim.", ""]
    return "\n".join(lines)


def _validate_attempt(attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable inputs changed")
    ledger, steps = derive(inputs["run_id"], attempt.name, inputs)
    if read_json(attempt / LEDGER) != ledger:
        raise Blocked(f"{JOB}: ledger differs from its accepted lifecycle inputs")
    permission, lineage = _receipts(inputs, ledger)
    if read_json(attempt / "permission.json") != permission or read_json(attempt / "lineage.json") != lineage:
        raise Blocked(f"{JOB}: permission or lineage receipt differs from canonical inputs")
    if (attempt / SUMMARY).read_text(encoding="utf-8") != _summary(ledger, steps):
        raise Blocked(f"{JOB}: summary differs from the ledger")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes(): raise Blocked(f"{JOB}: implementation changed before execution")
        attempt = allocation["attempt"]
        ledger, steps = derive(run_id, attempt.name, inputs)
        atomic_json(attempt / LEDGER, ledger)
        atomic_bytes(attempt / SUMMARY, _summary(ledger, steps).encode())
        permission, lineage = _receipts(inputs, ledger)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        execution = "OK_WITH_GAPS" if steps["gaps"] else "OK"
        status = {"process": JOB, "status": execution, "claims": len(ledger["claim_states"]),
                  "decisions": len(steps["requests"]), "gaps": len(steps["gaps"]),
                  "origin_head_hash": steps["origin_head_hash"], "ledger_head_hash": ledger["head_hash"],
                  "claim_limit": "candidate-only"}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
            worker_kind="deterministic_python", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=execution,
            summary=f"L01 ledger extended with {len(steps['requests'])} accepted lifecycle decisions.",
            status_record=status, artifact_paths=[LEDGER, SUMMARY, "permission.json", "lineage.json", "status.json"],
            gaps=steps["gaps"] or None, pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs))
    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="deterministic_python", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/claim_ledger_final.py --run-id {run_id}",
        derive_inputs=lambda: current_inputs(run_id), fingerprint_inputs=lambda value: _sha(value),
        execute_attempt=execute, preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Accepted L01 ledger or lifecycle decisions were not current and exact.",
        failed_summary="Final claim-decision ledger was not published.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id); inputs = current_inputs(run_id)
    pointer = pointer or read_json(base / "accepted.json")
    attempt, _ = validate_published(base, pointer, _sha(inputs), expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(attempt, inputs)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-claim-ledger-final")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(); print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
