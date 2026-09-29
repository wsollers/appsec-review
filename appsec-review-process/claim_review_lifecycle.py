#!/usr/bin/env python3
"""Run-owned lifecycle orchestration for red, blue, verification, and scoring decisions.

Applicable decisions come only from an accepted deterministic merge of persona/tool-pool outputs.
The worker never supplies reviewer judgment itself.  Empty accepted claim populations execute as
honest no-op results without requiring a pool.  Every other missing or degraded pool blocks.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import attack_reference
import bounded_analysis_workers
import claim_lifecycle_core as core
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import validate_document

STAGES = tuple(core.STAGES)
ARRAYS = {"07-red-team-adversarial": "candidates", "08-blue-team-refutation": "hypotheses",
          "09-independent-verification": "reviews", "12-scoring-prioritization": "verifications"}
OUTPUT_ARRAYS = {"07-red-team-adversarial": "hypotheses", "08-blue-team-refutation": "reviews",
                 "09-independent-verification": "verifications", "12-scoring-prioritization": "priorities"}
POOL_CLASSES = {"07-red-team-adversarial": "candidate_only",
                "08-blue-team-refutation": "refutation",
                "09-independent-verification": "verification_observation",
                "12-scoring-prioritization": "verification_observation"}
WORKERS = {"07-red-team-adversarial": "red_team_adversarial.py",
           "08-blue-team-refutation": "blue_team_refutation.py",
           "09-independent-verification": "independent_verification.py",
           "12-scoring-prioritization": "scoring_prioritization.py"}
PERMISSIONS = ["read-run-data", "write-run-data"]
DECISION_KEYS = {
    "07-red-team-adversarial": {"claim_id", "reviewer", "attacker_case", "citations", "dissent_ids"},
    "08-blue-team-refutation": {"claim_id", "reviewer", "disposition", "rationale",
                                "proof_obligations", "citations", "dissent_ids"},
    "09-independent-verification": {"claim_id", "verifier", "disposition", "method",
                                    "proof_obligations", "citations", "dissent_ids"},
    "12-scoring-prioritization": {"claim_id", "factors", "rationale"},
}
# Optional reviewer judgment (ADR-0020): CWE at 07/09/12; CVSS v4.0 base metrics + remediation at 12;
# ATT&CK/CAPEC labels at 07 (ADR-0026).
OPTIONAL_DECISION_KEYS = {"07-red-team-adversarial": {"cwe", "attack_refs", "capec_refs"},
                          "08-blue-team-refutation": set(),
                          "09-independent-verification": {"cwe"},
                          "12-scoring-prioritization": {"cwe", "cvss_v4", "remediation"}}


def root(run_id: str, stage: str) -> Path:
    _stage(stage)
    return data_path(run_id, "jobs", stage)


def pool_pointer(run_id: str, stage: str) -> Path:
    _stage(stage)
    return data_path(run_id, "jobs", "deterministic-pool-merge", stage, "accepted.json")


def _stage(stage: str) -> None:
    if stage not in STAGES:
        raise Blocked("claim review lifecycle: unknown stage")


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes(stage: str) -> dict[str, str]:
    names = ("claim_review_lifecycle.py", "claim_lifecycle_core.py", WORKERS[stage],
             "publish_job_output.py", "validate_job_output.py",
             f"registry/output-contracts/{stage}.json")
    if stage == "07-red-team-adversarial":          # ATT&CK/CAPEC label validation (ADR-0026)
        names += ("attack_reference.py", "mitre_feed.py")
    result = {name: file_hash(ROOT / name) for name in names}
    result["schemas/claim-review-decision.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "claim-review-decision.schema.json")
    result["schemas/" + core.STAGES[stage][3]] = file_hash(ROOT.parent / "schemas" / core.STAGES[stage][3])
    template = f"registry/job-templates/{stage}.json"
    result[template] = file_hash(ROOT / template)
    return result


def _upstream_pointer(run_id: str, stage: str) -> Path:
    upstream_contract = core.STAGES[stage][0]
    upstream_job = "claim-ledger-routing" if stage == "07-red-team-adversarial" else upstream_contract
    return data_path(run_id, "jobs", upstream_job, "accepted.json")


def _load_upstream(run_id: str, stage: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    contract, artifact, schema, _out_schema, _out_artifact = core.STAGES[stage]
    job = "claim-ledger-routing" if stage == "07-red-team-adversarial" else contract
    pointer_path = _upstream_pointer(run_id, stage)
    upstream, binding = core.load_accepted(pointer_path, run_id=run_id, job_id=job,
                                           contract=contract, artifact=artifact, schema=schema)
    pointer = read_json(pointer_path)
    lineage_path = pointer_path.parent / "attempts" / pointer["attempt_id"] / "lineage.json"
    lineage = read_json(lineage_path)
    source = lineage.get("source_snapshot_sha256")
    if (lineage.get("run_id") != run_id or lineage.get("job_id") != job or
            not isinstance(source, str) or not source.startswith("sha256:") or len(source) != 71):
        raise Blocked("claim review lifecycle: accepted upstream lineage is invalid")
    records = upstream[ARRAYS[stage]]
    generations = {item.get("source_generation") for item in records}
    if generations and generations != {source}:
        raise Blocked("claim review lifecycle: upstream records and lineage use different source generations")
    return upstream, binding, source


def _load_pool(run_id: str, stage: str) -> tuple[dict[str, Any], dict[str, Any]]:
    pool, binding = bounded_analysis_workers.load_accepted(
        pool_pointer(run_id, stage), run_id=run_id, job_id="deterministic-pool-merge",
        contract="deterministic-pool-merge", artifact="deterministic-pool-merge.json",
        schema="deterministic-pool-merge.schema.json")
    _validate_pool(pool, run_id=run_id)
    return pool, binding


def _validate_pool(pool: dict[str, Any], *, run_id: str | None = None) -> None:
    if run_id is not None and pool.get("run_id") != run_id:
        raise Blocked("claim review lifecycle: accepted pool belongs to another run")
    if pool.get("merge_sha256") != _sha({key: value for key, value in pool.items()
                                         if key != "merge_sha256"}):
        raise Blocked("claim review lifecycle: accepted pool merge hash is invalid")
    expected, observed, missing = (set(pool[name]) for name in
                                   ("expected_worker_ids", "observed_worker_ids", "missing_worker_ids"))
    if observed - expected or missing != expected - observed:
        raise Blocked("claim review lifecycle: accepted pool population is inconsistent")
    candidate_ids: set[str] = set()
    for candidate in pool["candidates"]:
        if (candidate["candidate_id"] in candidate_ids or not candidate["worker_ids"] or
                not candidate["producer_ids"] or not set(candidate["worker_ids"]) <= observed):
            raise Blocked("claim review lifecycle: pool candidate provenance is invalid")
        candidate_ids.add(candidate["candidate_id"])
        semantic = _sha({key: candidate[key] for key in
                         ("subject_id", "assertion", "claim_class")})
        if candidate["semantic_sha256"] != semantic:
            raise Blocked("claim review lifecycle: accepted pool candidate semantic hash is invalid")


def decisions_from_pool(stage: str, upstream: dict[str, Any], pool: dict[str, Any]) -> dict[str, Any]:
    _stage(stage)
    _validate_pool(pool, run_id=upstream.get("run_id"))
    records = upstream[ARRAYS[stage]]
    expected = {item["claim_id"] for item in records}
    if len(expected) != len(records):
        raise Blocked("claim review lifecycle: upstream claim identities are duplicated")
    if pool.get("missing_worker_ids"):
        raise Blocked("claim review lifecycle: accepted decision pool is incomplete")
    if pool.get("conflicts"):
        raise Blocked("claim review lifecycle: accepted decision pool retains conflicts")
    decisions: dict[str, dict[str, Any]] = {}
    for candidate in pool.get("candidates", []):
        if candidate.get("claim_class") != POOL_CLASSES[stage]:
            raise Blocked("claim review lifecycle: pool candidate has the wrong claim class")
        claim_id = candidate.get("subject_id")
        if claim_id not in expected or claim_id in decisions:
            raise Blocked("claim review lifecycle: pool decision is unexpected or duplicated")
        try:
            decision = json.loads(candidate["assertion"])
        except (TypeError, ValueError) as exc:
            raise Blocked("claim review lifecycle: pool assertion is not a JSON decision") from exc
        if not isinstance(decision, dict):
            raise Blocked("claim review lifecycle: pool decision is not an object")
        if not DECISION_KEYS[stage] <= set(decision) <= DECISION_KEYS[stage] | OPTIONAL_DECISION_KEYS[stage]:
            raise Blocked("claim review lifecycle: pool decision fields do not match the stage contract")
        errors = validate_document({"stage": stage, "decision": decision},
                                   "claim-review-decision.schema.json")
        if errors:
            raise Blocked(f"claim review lifecycle: pool decision violates its closed schema ({errors[0]})")
        if decision.get("claim_id") != claim_id:
            raise Blocked("claim review lifecycle: decision claim differs from pool subject")
        decisions[claim_id] = decision
    if set(decisions) != expected:
        raise Blocked("claim review lifecycle: every and only upstream claim needs one pool decision")
    return {"decisions": [decisions[key] for key in sorted(decisions)]}


def current_inputs(run_id: str, stage: str) -> dict[str, Any]:
    upstream, upstream_binding, source = _load_upstream(run_id, stage)
    records = upstream[ARRAYS[stage]]
    if records:
        pool, pool_binding = _load_pool(run_id, stage)
        decisions = decisions_from_pool(stage, upstream, pool)
    else:
        pool, pool_binding, decisions = None, None, {"decisions": []}
    inputs = {"run_id": run_id, "stage": stage, "source_generation": source,
              "upstream": upstream, "upstream_binding": upstream_binding,
              "pool": pool, "pool_binding": pool_binding, "decisions": decisions,
              "applicability": "APPLICABLE" if records else "SKIPPED_NA_NO_CANDIDATES",
              "code": _code_hashes(stage)}
    if stage == "07-red-team-adversarial" and any("attack_refs" in row or "capec_refs" in row
                                                  for row in decisions["decisions"]):
        # ADR-0026: the MITRE reference identity (or its gap) is an input, so a stale or re-pinned
        # snapshot re-executes the stage and a re-validation reproduces the same tags.
        inputs["mitre_reference"] = attack_reference.binding()
    return inputs


def build_result(inputs: dict[str, Any], attempt_id: str) -> dict[str, Any]:
    stage = inputs["stage"]
    function = {"07-red-team-adversarial": core.red_team,
                "08-blue-team-refutation": core.blue_team,
                "09-independent-verification": core.verify,
                "12-scoring-prioritization": core.score}[stage]
    if "mitre_reference" in inputs:
        return function(inputs["upstream"], inputs["upstream_binding"], inputs["decisions"],
                        inputs["mitre_reference"])
    return function(inputs["upstream"], inputs["upstream_binding"], inputs["decisions"])


def _receipts(inputs: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": inputs["stage"],
        "source_snapshot_sha256": inputs["source_generation"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": inputs["stage"],
        "source_snapshot_sha256": inputs["source_generation"],
        "build_lineage_sha256": _sha({"upstream": inputs["upstream_binding"],
            "pool": inputs["pool_binding"], "applicability": inputs["applicability"]})}
    return permission, lineage


def _applicability(inputs: dict[str, Any]) -> dict[str, Any]:
    count = len(inputs["upstream"][ARRAYS[inputs["stage"]]])
    applicable = inputs["applicability"] == "APPLICABLE"
    return {"schema": "appsec-review/claim-review-applicability/1.0",
            "run_id": inputs["run_id"], "job_id": inputs["stage"],
            "decision": "APPLICABLE" if applicable else "SKIPPED_NA",
            "reason": ("Accepted upstream claims require this control stage." if applicable else
                       "The accepted upstream population contains no claims for this control stage."),
            "upstream_claim_count": count,
            "upstream_binding": inputs["upstream_binding"]}


def _validate_attempt(run_id: str, stage: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes(stage):
        raise Blocked("claim review lifecycle: immutable inputs or implementation changed")
    if current_inputs(run_id, stage) != inputs:
        raise Blocked("claim review lifecycle: accepted upstream or pool changed")
    artifact = core.STAGES[stage][4]
    if read_json(attempt / artifact) != build_result(inputs, attempt.name):
        raise Blocked("claim review lifecycle: result differs from accepted inputs")
    permission, lineage = _receipts(inputs)
    if (read_json(attempt / "permission.json") != permission or
            read_json(attempt / "lineage.json") != lineage or
            read_json(attempt / "applicability.json") != _applicability(inputs)):
        raise Blocked("claim review lifecycle: permission or lineage receipt changed")


def run(run_id: str, dagster_run_id: str, stage: str, force: bool = False) -> dict[str, Any]:
    _stage(stage)
    base = root(run_id, stage)
    artifact = core.STAGES[stage][4]

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        if inputs["code"] != _code_hashes(stage):
            raise Blocked("claim review lifecycle: implementation changed before execution")
        attempt = allocation["attempt"]
        result = build_result(inputs, allocation["attempt_id"])
        atomic_json(attempt / artifact, result)
        permission, lineage = _receipts(inputs)
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "applicability.json", _applicability(inputs))
        records = result[OUTPUT_ARRAYS[stage]]
        no_op = inputs["applicability"] == "SKIPPED_NA_NO_CANDIDATES"
        status = {"process": stage, "status": "OK", "result": artifact,
                  "claim_limit": "CONTROL_DECISION_ONLY", "records": len(records),
                  "applicability": inputs["applicability"]}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=stage,
            dagster_run_id=dagster_run_id, worker_kind="deterministic_python",
            output_contract=stage, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status="OK",
            summary=(f"Published {len(records)} accepted pool-derived claim decisions." if not no_op else
                     "No accepted upstream claims; published an evidence-bound no-op result."),
            status_record=status,
            artifact_paths=[artifact, "permission.json", "lineage.json", "applicability.json",
                            "status.json"],
            gaps=(["No upstream claim candidates were applicable to this stage."] if no_op else None),
            pre_envelope_validate=lambda path, _status:
                _validate_attempt(run_id, stage, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=stage,
        dagster_run_id=dagster_run_id, worker_kind="deterministic_python", output_contract=stage,
        resume_command=(f"python -B appsec-review-process/claim_review_lifecycle.py --run-id {run_id} "
                        f"--stage {stage}"),
        derive_inputs=lambda: current_inputs(run_id, stage),
        fingerprint_inputs=lambda value: _sha(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "stage": stage,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes(stage)},
        force=force,
        post_validate=lambda attempt, _envelope, inputs:
            _validate_attempt(run_id, stage, attempt, inputs),
        blocked_summary="Accepted claim inputs or persona/tool-pool decisions were unavailable.",
        failed_summary="Claim review lifecycle result was not published.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-claim-review")
    parser.add_argument("--stage", required=True, choices=STAGES)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.stage, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
