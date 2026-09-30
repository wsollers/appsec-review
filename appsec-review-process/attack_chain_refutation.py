#!/usr/bin/env python3
"""14-attack-chain-refutation: try to break every composed chain and publish the attack-chain ledger.

Lifecycle worker after ``14-attack-chain-composition`` (ADR-0016 decisions 4, 6, 7, 10):

1. Load the accepted composition (a SKIPPED composition is passed through as SKIPPED
   ``not-applicable-no-chain-seeds``) and its seeds artifact with hash verification.
2. :func:`attack_chain_refute.batches` ranks the chains and cuts at ``chains_refuted_max``; one
   ``attack-chain-refuter`` cell per ``chain_refutation_batch`` chains. Under a ``probe`` budget no
   refuter runs (a gap; states stay capped).
3. :func:`build_result` (pure) applies the outcomes: the weakest-link ceiling, refuted chains dropped
   with their reason, ``supported`` at most; a failed refuter cell caps its chains with a gap.
4. Publishes ``attack-chain-ledger.json``: hash-linked ``chain_composed`` / ``chain_refutation`` /
   ``chain_state_derived`` events bound to the claim-ledger head and the 09 accepted pointer.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import attack_chain_composition as composition
import attack_chain_pool as chain_pool
import attack_chain_refute as refute
import bounded_analysis_workers
import persona_dispatch
import persona_prompt_assembly
import pool_specification
import review_cli
import tunables
from execution_state import Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import SchemaStore, validate_document
import registry_paths

JOB = "14-attack-chain-refutation"
CONTRACT = "14-attack-chain-refutation"
RESULT = "attack-chain-ledger.json"
SUMMARY = "attack-chain-ledger.md"
MERGE = "refutation-pool-merge.json"
PERMISSIONS = ["read-run-data", "write-run-data"]
ARTIFACTS = [RESULT, SUMMARY, MERGE, "permission.json", "lineage.json", "pool-receipt.json", "status.json"]


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def tunable(name: str) -> Any:
    return tunables.value(JOB, name)


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes() -> dict[str, str]:
    values = chain_pool.code_hashes()
    for path in ("attack_chain_refutation.py", "attack_chain_composition.py", registry_paths.template_rel(JOB),
                 registry_paths.template_rel(composition.JOB), registry_paths.contract_rel(CONTRACT)):
        values[path] = file_hash(ROOT / path)
    return values


def load_composition(run_id: str) -> dict[str, Any]:
    """The accepted composition (or its SKIPPED pointer) and its seeds, hash-verified."""
    pointer_path = composition.root(run_id) / "accepted.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise Blocked(f"{JOB}: accepted 14-attack-chain-composition is required")
    pointer = read_json(pointer_path)
    if pointer.get("status") == "SKIPPED":
        if pointer.get("run_id") != run_id or pointer.get("job") != composition.JOB:
            raise Blocked(f"{JOB}: skipped composition pointer identity is invalid")
        return {"skipped": pointer.get("reason"), "binding": {"job_id": composition.JOB,
                "attempt_id": pointer.get("attempt_id"), "accepted_pointer_sha256": "sha256:" + file_hash(pointer_path)}}
    result, binding = bounded_analysis_workers.load_accepted(pointer_path, run_id=run_id, job_id=composition.JOB,
        contract=composition.CONTRACT, artifact=composition.RESULT, schema=composition.RESULT_SCHEMA)
    seeds_path = composition.root(run_id) / "attempts" / binding["attempt_id"] / composition.SEEDS
    seeds = read_json(seeds_path)    # hash-checked with every other artifact by load_accepted
    if result["seeds_sha256"] != _sha(seeds):
        raise Blocked(f"{JOB}: composition seeds do not match the accepted result")
    return {"skipped": None, "binding": binding, "result": result, "seeds": seeds}


def _index(seeds: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    facts = {fact["fact_id"]: fact for cluster in seeds["clusters"] for fact in cluster["facts"]}
    claims = {claim["claim_id"]: claim for cluster in seeds["clusters"] for claim in cluster["claims"]}
    return facts, claims


def prepare(run_id: str) -> dict[str, Any]:
    loaded = load_composition(run_id)
    code = _code_hashes()
    if loaded["skipped"]:
        return {"run_id": run_id, "skipped": loaded["skipped"], "binding": loaded["binding"], "code": code}
    result, seeds = loaded["result"], loaded["seeds"]
    facts, claims = _index(seeds)
    limits = seeds["bounds"]
    batches, gaps = refute.batches(run_id, result["chains"], facts=facts, claims=claims, bounds=limits)
    if result["budget_class"] == "probe" and batches:
        gaps += [{"scope": "chain", "id": chain["chain_id"], "reason": "refutation-skipped-budget",
                  "detail": "probe budget: refutation not run; state capped"} for batch in batches for chain in batch["chains"]]
        batches = []
    menu = composition.evidence_menu.build(run_id, JOB, [])
    accepted_at = read_json(composition.root(run_id) / "accepted.json")["accepted_at"]
    evaluated_at = datetime.fromisoformat(accepted_at.replace("Z", "+00:00")).astimezone(
        timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    source = result["source_snapshot_sha256"]
    permission = persona_dispatch._permission_block(JOB, run_id=run_id, source_snapshot_sha256=source, now=evaluated_at)
    spec = chain_pool.pool_spec(run_id, JOB, "refute", batches, menu=menu, permission=permission,
                                binding=loaded["binding"], rendezvous_timeout_seconds=tunable("rendezvous_timeout_seconds"))
    return {"run_id": run_id, "skipped": None, "binding": loaded["binding"], "source_generation": source,
            "composition": result, "facts": facts, "batches": batches, "pre_gaps": gaps, "evidence_menu": menu,
            "spec": spec, "accepted_at": evaluated_at, "code": code}


def build_result(inputs: dict[str, Any], merge: dict[str, Any]) -> dict[str, Any]:
    result = inputs["composition"]
    outcomes, reasons, gaps = chain_pool.collect_refutation(inputs["batches"], merge)
    for gap in inputs["pre_gaps"]:
        reasons.setdefault(gap["id"], gap["detail"])
    published, dropped = refute.apply(result["chains"], outcomes, reasons)
    coverage = {**result["coverage"], "chains_sent_to_refutation": sum(len(b["chains"]) for b in inputs["batches"]),
                "chains_refutation_answered": len(outcomes), "chains_published": len(published),
                "chains_refuted": len(dropped),
                "states": {state: sum(1 for chain in published if chain["state"] == state)
                           for state in ("supported", "plausible", "hypothesis")}}
    return refute.ledger(inputs["run_id"], claim_ledger_head_sha256=result["ledger_head_sha256"],
                         verification_pointer_sha256=result["bindings"]["verification"]["pointer_sha256"],
                         link_candidates=result["link_candidate_ids"], composed=result["chains"], outcomes=outcomes,
                         published=published, dropped=dropped, gaps=result["gaps"] + inputs["pre_gaps"] + gaps,
                         coverage=coverage, facts=inputs["facts"])


def skipped_result(inputs: dict[str, Any]) -> dict[str, Any]:
    return {"schema": refute.LEDGER_SCHEMA_ID, "run_id": inputs["run_id"], "claim_ledger_head_sha256": None,
            "verification_pointer_sha256": None, "entries": [], "head_hash": None, "chains": [], "dropped": [],
            "gaps": [], "coverage": {"skip_reason": inputs["skipped"]},
            "claim_limits": {"finding_created": False, "severity_assigned": False},
            "note": f"No chain composed: {inputs['skipped']}."}


def summary(ledger: dict[str, Any]) -> str:
    lines = ["# Attack-chain ledger", "", f"{len(ledger['chains'])} published chain(s), {len(ledger['dropped'])} "
             f"refuted (counted, not listed); {len(ledger['gaps'])} gap(s).", ""]
    if ledger["chains"]:
        lines += ["| Rank | Chain | Impact | State | Weakest | Refutation |", "|---|---|---|---|---|---|"]
        for chain in ledger["chains"]:
            lines.append(f"| {chain['rank']} | `{chain['chain_id']}` | {chain['impact_kind']} | {chain['state']} | "
                         f"{chain['weakest']['reason'].replace('|', '/')} | {chain['refutation']['disposition']} |")
    lines += ["", ledger["note"], ""]
    return "\n".join(lines)


def _receipts(inputs: dict[str, Any], ledger: dict[str, Any], launched: dict[str, Any]) -> tuple[dict, dict, dict]:
    source = inputs.get("source_generation") or "sha256:" + "0" * 64
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": inputs["run_id"],
                  "job_id": JOB, "source_snapshot_sha256": source, "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
               "source_snapshot_sha256": source,
               "build_lineage_sha256": _sha({"binding": inputs["binding"], "pool": launched, "ledger": _sha(ledger),
                   "spec": pool_specification.spec_sha256(inputs["spec"]) if inputs.get("spec") else None})}
    receipt = {"schema": "appsec-review/attack-chain-pool-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
               "decision": "SKIPPED_NA" if inputs["skipped"] else "APPLICABLE", **launched}
    return permission, lineage, receipt


def _expected(inputs: dict[str, Any], merge: dict[str, Any]) -> dict[str, Any]:
    return skipped_result(inputs) if inputs["skipped"] else build_result(inputs, merge)


def _validate_attempt(attempt: Path, inputs: dict[str, Any], *, reprepare: bool = True) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked(f"{JOB}: immutable inputs or implementation changed")
    if reprepare and prepare(inputs["run_id"]) != inputs:
        raise Blocked(f"{JOB}: accepted composition changed")
    ledger = read_json(attempt / RESULT)
    if ledger != _expected(inputs, read_json(attempt / MERGE)):
        raise Blocked(f"{JOB}: ledger differs from the retained merge")
    if not inputs["skipped"]:
        refute.verify_ledger(ledger)
    receipt = read_json(attempt / "pool-receipt.json")
    launched = {key: receipt.get(key) for key in ("pool_directory", "pool_outcome", "instance_count",
                                                  "expansion_sha256", "terminal_manifest_sha256")}
    if (read_json(attempt / "permission.json"), read_json(attempt / "lineage.json"), receipt) != \
            _receipts(inputs, ledger, launched):
        raise Blocked(f"{JOB}: retained receipts changed")


def _budget_usd() -> float | None:
    template = persona_prompt_assembly.load_job_template(chain_pool.REFUTER_TEMPLATE, SchemaStore())
    value = (review_cli.load_model_config().get("budget_max_usd_per_call") or {}).get(template["budget_default"])
    return float(value) if isinstance(value, (int, float)) else None


def run(run_id: str, dagster_run_id: str, force: bool = False, *, invoker: Any = None) -> dict[str, Any]:
    """Dispatch the refuter pool (or pass a skip through) and publish the attack-chain ledger."""
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        merge = {"schema": "appsec-review/deterministic-pool-merge/1.0", "run_id": run_id, "expected_worker_ids": [],
                 "observed_worker_ids": [], "missing_worker_ids": [], "candidates": [], "conflicts": []}
        launched = {"pool_directory": None, "pool_outcome": "NOT_LAUNCHED", "instance_count": 0,
                    "expansion_sha256": None, "terminal_manifest_sha256": None}
        if not inputs["skipped"] and inputs["batches"]:
            context = chain_pool.context(run_id, "refute", inputs["batches"], menu=inputs["evidence_menu"],
                                         spec=inputs["spec"], attempt=attempt,
                                         source_snapshot_sha256=inputs["source_generation"])
            effort = review_cli.resolve_model(chain_pool.REFUTER_TEMPLATE, "standard").get("effort") or "high"
            merge, pool = chain_pool.dispatch(run_id, inputs["spec"], context,
                invoker=invoker or chain_pool.ChainInvoker("refute", effort=effort, budget_usd=_budget_usd()),
                clock=lambda: inputs["accepted_at"], max_parallel=tunable("max_parallel"),
                wait_limit_seconds=tunable("rendezvous_timeout_seconds"))
            launched = {"pool_directory": pool.pool_directory, "pool_outcome": pool.outcome,
                        "instance_count": pool.instance_count, "expansion_sha256": pool.expansion_sha256,
                        "terminal_manifest_sha256": pool.terminal_manifest_sha256}
        ledger = _expected(inputs, merge)
        atomic_json(attempt / MERGE, merge); atomic_json(attempt / RESULT, ledger)
        atomic_bytes(attempt / SUMMARY, summary(ledger).encode("utf-8"))
        permission, lineage, receipt = _receipts(inputs, ledger, launched)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "pool-receipt.json", receipt)
        skip = inputs["skipped"]
        gaps = [f"{gap['reason']}: {gap['scope']} {gap['id']}: {gap['detail']}" for gap in ledger["gaps"]]
        status_value = "SKIPPED" if skip else ("OK_WITH_GAPS" if gaps else "OK")
        status = {"process": JOB, "status": status_value, "result": RESULT, "chains": len(ledger["chains"]),
                  "refuted": len(ledger["dropped"]), "gaps": len(ledger["gaps"]), "claim_limit": "candidate-only"}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
            worker_kind="pool_coordinator", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=status_value,
            summary=(f"SKIPPED {skip}: no chain composed." if skip else
                     f"Published {len(ledger['chains'])} attack chain(s); {len(ledger['dropped'])} refuted."),
            status_record=status, artifact_paths=ARTIFACTS, gaps=gaps or None, skip_reason=skip,
            consumer_job_id="10-synthesis-report",
            pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs, reprepare=False))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
        worker_kind="pool_coordinator", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/attack_chain_refutation.py --run-id {run_id}",
        derive_inputs=lambda: prepare(run_id), fingerprint_inputs=_sha, execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Accepted 14-attack-chain-composition was not current.",
        failed_summary="Refuter pool did not publish the attack-chain ledger.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-attack-chain-refutation")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
