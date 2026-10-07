#!/usr/bin/env python3
"""14-attack-chain-composition: seed clusters from reviewed claims and compose attack chains (ADR-0016).

Lifecycle worker (``coordinate_worker_lifecycle`` / ``record_terminal_current``), run after
``09-independent-verification``:

1. Load the accepted 09 result (and, through its upstream binding, the 08 result that says which
   open claims were narrowed), the accepted integrated threat model (03) and component map (01)
   with full hash verification; read the CPG records and IR facts the supporting-evidence menu pins.
2. :mod:`attack_chain_seeds` builds link candidates, entry seeds, adjacency and ranked clusters.
   With no cluster the job publishes SKIPPED ``not-applicable-no-chain-seeds`` and launches nothing.
   Under a ``probe`` budget only the first cluster gets a composer cell (the rest is a gap).
3. One ``attack-chain-composer`` cell per cluster (:mod:`attack_chain_pool`); the derive step runs
   inside the invoker repair loop. :func:`build_result` (pure) reads the merge back into chain
   records; a failed cell, conflict or no-chain answer is a gap, never a job failure.

The job fails only on a broken input binding (tamper, missing accepted pointer), as other lifecycle
jobs do. Chains are candidates for ``14-attack-chain-refutation``; none is a finding.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

import attack_chain_pool as chain_pool
import attack_chain_seeds as seeds_core
import bounded_analysis_workers
import claim_lifecycle_core
import persona_dispatch
import persona_prompt_assembly
import pool_specification
import review_cli
import supporting_evidence_menu as evidence_menu
import tunables
from execution_state import (ACCEPTED_ALIAS, Blocked, ROOT, atomic_bytes, atomic_json, data_path, digest, file_hash,
                             read_json, resolve_accepted_alias)
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import SchemaStore, validate_document
import registry_paths

JOB = "14-attack-chain-composition"
CONTRACT = "14-attack-chain-composition"
RESULT = "attack-chain-composition.json"
RESULT_SCHEMA = "attack-chain-composition.schema.json"
SEEDS = "attack-chain-seeds.json"
SUMMARY = "attack-chain-composition.md"
MERGE = "chain-pool-merge.json"
PERMISSIONS = ["read-run-data", "write-run-data"]
ARTIFACTS = [RESULT, SEEDS, SUMMARY, MERGE, "permission.json", "lineage.json", "pool-receipt.json", "status.json"]
VERIFICATION = ("09-independent-verification", "independent-verification.json", "09-independent-verification.schema.json")
BLUE = ("08-blue-team-refutation", "blue-team-refutation.json", "08-blue-team-refutation.schema.json")
BOUND_NAMES = tuple(seeds_core.DEFAULT_BOUNDS)


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def tunable(name: str) -> Any:
    return tunables.value(JOB, name)


def bound_values() -> dict[str, int]:
    return {name: tunable(name) for name in BOUND_NAMES}


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _code_hashes() -> dict[str, str]:
    values = chain_pool.code_hashes()
    for path in ("attack_chain_composition.py", registry_paths.template_rel(JOB),
                 registry_paths.contract_rel(CONTRACT)):
        values[path] = file_hash(ROOT / path)
    values["schemas/" + RESULT_SCHEMA] = file_hash(ROOT.parent / "schemas" / RESULT_SCHEMA)
    return values


# --- inputs -------------------------------------------------------------------------------------

def load_upstreams(run_id: str) -> dict[str, Any]:
    """Accepted 09 (+ its 08 upstream), 03 and 01 with their bindings; raises Blocked on tamper."""
    jobs = data_path(run_id, "jobs")
    pointer = jobs / VERIFICATION[0] / "accepted.json"
    if not pointer.is_file():
        raise Blocked(f"{JOB}: accepted 09-independent-verification is required")
    verification, verification_binding = claim_lifecycle_core.load_accepted(pointer, run_id=run_id,
        job_id=VERIFICATION[0], contract=VERIFICATION[0], artifact=VERIFICATION[1], schema=VERIFICATION[2])
    upstream = verification["upstream"]
    blue_pointer = jobs / BLUE[0] / "accepted.json"
    blue, blue_binding = claim_lifecycle_core.load_accepted(blue_pointer, run_id=run_id, job_id=BLUE[0],
        contract=BLUE[0], artifact=BLUE[1], schema=BLUE[2])
    if (upstream.get("attempt_id"), upstream.get("artifact_sha256")) != (blue_binding["attempt_id"],
                                                                      blue_binding["artifact_sha256"]):
        raise Blocked(f"{JOB}: accepted 08 result is not the one 09 verified")
    threat_model, threat_binding = bounded_analysis_workers.load_accepted(
        jobs / "03-threat-model-dfd-stride" / "accepted.json", run_id=run_id, job_id="03-threat-model-dfd-stride",
        contract="threat-model-core", artifact="integrated-threat-model.json", schema="integrated-threat-model.schema.json")
    component_map, component_binding = bounded_analysis_workers.load_accepted(
        jobs / "01-component-characterization" / "accepted.json", run_id=run_id,
        job_id="01-component-characterization", contract="component-map", artifact="component-purpose-map.json",
        schema="component-purpose-map.schema.json")
    return {"verification": verification, "blue": blue, "threat_model": threat_model, "component_map": component_map,
            "bindings": {"verification": verification_binding, "blue": blue_binding, "threat_model": threat_binding,
                         "component_map": component_binding},
            "accepted_at": read_json(pointer)["accepted_at"]}


def ledger_states(verification: dict[str, Any], blue: dict[str, Any]) -> dict[str, str]:
    """The ledger's latest state where 09 left a claim open: 08 SURVIVING + 09 BLOCKED is ``narrowed``
    (the same correspondence report_input_assembly enforces)."""
    surviving = {row["claim_id"] for row in blue.get("reviews", []) if row.get("status") == "SURVIVING"}
    return {row["claim_id"]: "narrowed" for row in verification.get("verifications", [])
            if row["status"] == "BLOCKED" and row["claim_id"] in surviving}


def native_facts(run_id: str, menu: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any] | None,
                                                               dict[str, dict[str, Any]]]:
    """(CPG records, IR facts, artifact refs) read from the files the evidence menu pins (hash-checked)."""
    jobs = data_path(run_id, "jobs")
    records, ir, artifacts = [], None, {}
    for item in menu["items"]:
        if item["status"] != "AVAILABLE" or item["item_id"] not in {seeds_core.CPG_ITEM, seeds_core.IR_ITEM}:
            continue
        for entry in item["files"]:
            name = entry["path"].rsplit("/", 1)[-1]
            wanted = ("code-property-graph.records.jsonl" if item["item_id"] == seeds_core.CPG_ITEM else "ir-facts.json")
            if name != wanted:
                continue
            path = jobs.joinpath(*resolve_accepted_alias(jobs, entry["path"]).split("/"))
            if path.is_symlink() or not path.is_file() or "sha256:" + file_hash(path) != entry["sha256"]:
                raise Blocked(f"{JOB}: pinned {item['item_id']} evidence changed")
            artifacts[item["item_id"]] = {"path": entry["path"], "sha256": entry["sha256"]}
            if item["item_id"] == seeds_core.CPG_ITEM:
                records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            else:
                ir = read_json(path)
    return records, ir, artifacts


def plan(run_id: str, upstreams: dict[str, Any], menu: dict[str, Any], cpg_records: list[dict[str, Any]],
         ir_facts: dict[str, Any] | None, artifacts: dict[str, dict[str, Any]],
         limits: dict[str, int]) -> dict[str, Any]:
    """Seeds and the budget cut (pure)."""
    for key, value in (("threat_model", upstreams["threat_model"]), ("component_map", upstreams["component_map"])):
        artifacts.setdefault({"threat_model": seeds_core.TM_ITEM, "component_map": seeds_core.CM_ITEM}[key],
            {"path": f"{upstreams['bindings'][key]['job_id']}/{ACCEPTED_ALIAS}/"
                     f"{upstreams['bindings'][key]['artifact_path']}",
             "sha256": upstreams["bindings"][key]["artifact_sha256"]})
    seeds = seeds_core.build(run_id, upstreams["verification"],
        ledger_states=ledger_states(upstreams["verification"], upstreams["blue"]), cpg_records=cpg_records,
        ir_facts=ir_facts, threat_model=upstreams["threat_model"], component_map=upstreams["component_map"],
        artifacts=artifacts, bound_values=limits)
    budget = upstreams["threat_model"].get("budget_class", "standard")
    if budget == "probe" and len(seeds["clusters"]) > 1:
        for cluster in seeds["clusters"][1:]:
            seeds["gaps"].append({"scope": "cluster", "id": cluster["cluster_id"], "reason": "cluster-cap",
                                  "detail": "probe budget: one composer cell per run"})
        seeds["clusters"] = seeds["clusters"][:1]
        seeds["coverage"]["clusters_selected"] = 1
    errors = validate_document(seeds, "attack-chain-seeds.schema.json")
    if errors:
        raise Blocked(f"{JOB}: seeds fail their schema ({errors[0]})")
    return {"seeds": seeds, "budget_class": budget}


def prepare(run_id: str) -> dict[str, Any]:
    """The stable, fingerprinted inputs of one attempt (no model)."""
    upstreams = load_upstreams(run_id)
    records = upstreams["verification"]["verifications"]
    source = (records[0]["source_generation"] if records else
              upstreams["threat_model"].get("source_snapshot"))
    claims = [{"claim_id": row["claim_id"], "citations": row["citations"]} for row in records]
    menu = evidence_menu.build(run_id, JOB, claims)
    cpg_records, ir_facts, artifacts = native_facts(run_id, menu)
    planned = plan(run_id, upstreams, menu, cpg_records, ir_facts, artifacts, bound_values())
    evaluated_at = datetime.fromisoformat(upstreams["accepted_at"].replace("Z", "+00:00")).astimezone(
        timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    permission = persona_dispatch._permission_block(JOB, run_id=run_id, source_snapshot_sha256=source, now=evaluated_at)
    clusters = planned["seeds"]["clusters"]
    spec = chain_pool.pool_spec(run_id, JOB, "compose", clusters, menu=menu, permission=permission,
        binding=upstreams["bindings"], rendezvous_timeout_seconds=tunable("rendezvous_timeout_seconds"))
    return {"run_id": run_id, "source_generation": source, "bindings": upstreams["bindings"],
            "budget_class": planned["budget_class"], "seeds": planned["seeds"], "evidence_menu": menu, "spec": spec,
            "accepted_at": evaluated_at, "applicability": "APPLICABLE" if clusters else "SKIPPED_NA_NO_CHAIN_SEEDS",
            "code": _code_hashes()}


# --- post-pool bookkeeping (pure) ---------------------------------------------------------------

def build_result(inputs: dict[str, Any], merge: dict[str, Any]) -> dict[str, Any]:
    seeds = inputs["seeds"]
    chains, gaps, pool_coverage = chain_pool.collect_composition(seeds, merge)
    result = {"schema": "appsec-review/attack-chain-composition/1.0", "run_id": inputs["run_id"], "job_id": JOB,
              "source_snapshot_sha256": inputs["source_generation"], "bindings": inputs["bindings"],
              "budget_class": inputs["budget_class"], "seeds_sha256": _sha(seeds),
              "ledger_head_sha256": seeds["verification"]["ledger_head_sha256"],
              "skip_reason": seeds["skip_reason"],
              "link_candidate_ids": sorted({claim["claim_id"] for cluster in seeds["clusters"]
                                            for claim in cluster["claims"]}),
              "chains": chains, "gaps": seeds["gaps"] + gaps,
              "coverage": {**seeds["coverage"], **pool_coverage},
              "pool": {"instances": len(seeds["clusters"]),
                       "expected_worker_ids": list(merge.get("expected_worker_ids", [])),
                       "missing_worker_ids": list(merge.get("missing_worker_ids", [])),
                       "conflict_candidate_ids": [row["candidate_id"] for row in merge.get("conflicts", [])]},
              "claim_limits": {"candidate_only": True, "finding_created": False, "severity_assigned": False}}
    errors = validate_document(result, RESULT_SCHEMA)
    if errors:
        raise Blocked(f"{JOB}: result fails its closed schema ({errors[0]})")
    return result


def summary(result: dict[str, Any]) -> str:
    lines = ["# Attack-chain composition", "",
             f"{len(result['chains'])} composed chain(s) from {result['pool']['instances']} composer cell(s); "
             f"{len(result['gaps'])} gap(s).", ""]
    if result["skip_reason"]:
        lines += [f"SKIPPED: {result['skip_reason']} (no cluster has an entry seed and a P1 or verified claim).", ""]
    if result["chains"]:
        lines += ["| Chain | Impact | State (before refutation) | Links | Weakest |", "|---|---|---|---|---|"]
        for chain in result["chains"]:
            lines.append(f"| `{chain['chain_id']}` | {chain['impact_kind']} | {chain['state']} | {len(chain['links'])} | "
                         f"{chain['weakest']['reason'].replace('|', '/')} |")
    if result["gaps"]:
        lines += ["", "## Gaps", ""] + [f"- {gap['reason']} ({gap['scope']} {gap['id']}): {gap['detail']}"
                                         for gap in result["gaps"]]
    lines += ["", "Chains are candidates for 14-attack-chain-refutation; none is a finding or a severity.", ""]
    return "\n".join(lines)


def _receipts(inputs: dict[str, Any], result: dict[str, Any], launched: dict[str, Any]) -> tuple[dict, dict, dict]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0", "run_id": inputs["run_id"],
                  "job_id": JOB, "source_snapshot_sha256": inputs["source_generation"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
               "source_snapshot_sha256": inputs["source_generation"],
               "build_lineage_sha256": _sha({"bindings": inputs["bindings"], "seeds": result["seeds_sha256"],
                                             "spec": pool_specification.spec_sha256(inputs["spec"]),
                                             "pool": launched, "result": _sha(result)})}
    receipt = {"schema": "appsec-review/attack-chain-pool-receipt/1.0", "run_id": inputs["run_id"], "job_id": JOB,
               "decision": inputs["applicability"], **launched}
    return permission, lineage, receipt


def _validate_attempt(attempt: Path, inputs: dict[str, Any], *, reprepare: bool = True) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked(f"{JOB}: immutable inputs or implementation changed")
    if reprepare and prepare(inputs["run_id"]) != inputs:
        raise Blocked(f"{JOB}: accepted upstreams changed")
    result = read_json(attempt / RESULT)
    if result != build_result(inputs, read_json(attempt / MERGE)) or read_json(attempt / SEEDS) != inputs["seeds"]:
        raise Blocked(f"{JOB}: result differs from the retained merge")
    receipt = read_json(attempt / "pool-receipt.json")
    launched = {key: receipt.get(key) for key in ("pool_directory", "pool_outcome", "instance_count",
                                                  "expansion_sha256", "terminal_manifest_sha256")}
    expected = _receipts(inputs, result, launched)
    if (read_json(attempt / "permission.json"), read_json(attempt / "lineage.json"), receipt) != expected:
        raise Blocked(f"{JOB}: retained receipts changed")


def _budget_usd() -> float | None:
    template = persona_prompt_assembly.load_job_template(chain_pool.COMPOSER_TEMPLATE, SchemaStore())
    value = (review_cli.load_model_config().get("budget_max_usd_per_call") or {}).get(template["budget_default"])
    return float(value) if isinstance(value, (int, float)) else None


def run(run_id: str, dagster_run_id: str, force: bool = False, *, invoker: Any = None) -> dict[str, Any]:
    """Dispatch the composer pool (or skip) and publish the composed chains."""
    base = root(run_id)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        clusters = inputs["seeds"]["clusters"]
        empty = {"schema": "appsec-review/deterministic-pool-merge/1.0", "run_id": run_id, "expected_worker_ids": [],
                 "observed_worker_ids": [], "missing_worker_ids": [], "candidates": [], "conflicts": []}
        launched = {"pool_directory": None, "pool_outcome": "NOT_LAUNCHED", "instance_count": 0,
                    "expansion_sha256": None, "terminal_manifest_sha256": None}
        merge = empty
        if clusters:
            context = chain_pool.context(run_id, "compose", clusters, menu=inputs["evidence_menu"], spec=inputs["spec"],
                                         attempt=attempt, source_snapshot_sha256=inputs["source_generation"])
            effort = review_cli.resolve_model(chain_pool.COMPOSER_TEMPLATE, "standard").get("effort") or "high"
            merge, pool = chain_pool.dispatch(run_id, inputs["spec"], context,
                invoker=invoker or chain_pool.ChainInvoker("compose", effort=effort, budget_usd=_budget_usd()),
                clock=lambda: inputs["accepted_at"], max_parallel=tunable("max_parallel"),
                wait_limit_seconds=tunable("rendezvous_timeout_seconds"))
            launched = {"pool_directory": pool.pool_directory, "pool_outcome": pool.outcome,
                        "instance_count": pool.instance_count, "expansion_sha256": pool.expansion_sha256,
                        "terminal_manifest_sha256": pool.terminal_manifest_sha256}
        result = build_result(inputs, merge)
        atomic_json(attempt / MERGE, merge); atomic_json(attempt / SEEDS, inputs["seeds"])
        atomic_json(attempt / RESULT, result); atomic_bytes(attempt / SUMMARY, summary(result).encode("utf-8"))
        permission, lineage, receipt = _receipts(inputs, result, launched)
        atomic_json(attempt / "permission.json", permission); atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "pool-receipt.json", receipt)
        skip = result["skip_reason"]
        gaps = [f"{gap['reason']}: {gap['scope']} {gap['id']}: {gap['detail']}" for gap in result["gaps"]]
        status_value = "SKIPPED" if skip else ("OK_WITH_GAPS" if gaps else "OK")
        status = {"process": JOB, "status": status_value, "result": RESULT, "chains": len(result["chains"]),
                  "gaps": len(result["gaps"]), "instances": result["pool"]["instances"],
                  "claim_limit": "candidate-only", "applicability": inputs["applicability"]}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
            worker_kind="pool_coordinator", output_contract=CONTRACT, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status=status_value,
            summary=(f"SKIPPED {skip}: no chain composed." if skip else
                     f"Composed {len(result['chains'])} attack chain(s) for refutation."),
            status_record=status, artifact_paths=ARTIFACTS, gaps=gaps or None, skip_reason=skip,
            consumer_job_id="14-attack-chain-refutation",
            pre_envelope_validate=lambda path, _status: _validate_attempt(path, inputs, reprepare=False))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_run_id,
        worker_kind="pool_coordinator", output_contract=CONTRACT,
        resume_command=f"python -B appsec-review-process/attack_chain_composition.py --run-id {run_id}",
        derive_inputs=lambda: prepare(run_id), fingerprint_inputs=_sha, execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs: _validate_attempt(attempt, inputs),
        blocked_summary="Accepted 09, 08, 03 or 01 inputs were not current.",
        failed_summary="Composer pool did not publish attack chains.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-attack-chain-composition")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.force), indent=2))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
