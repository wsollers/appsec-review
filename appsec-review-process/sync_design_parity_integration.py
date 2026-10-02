#!/usr/bin/env python3
"""Synchronize lifecycle integration facts while retaining honest qualification gaps."""
from __future__ import annotations

import json
from pathlib import Path

from validate_design_parity import _registry_for
import registry_paths


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
GRAPH = registry_paths.JOB_GRAPH
MANIFEST = ROOT / "design-parity-manifest.json"

WORKERS = {
    "claim-ledger-routing": ("deterministic_python", "appsec-review-process/claim_ledger.py:run",
                              "appsec-review-process/claim_ledger.py:validate_ledger"),
    "claim-ledger-decisions": ("deterministic_python", "appsec-review-process/claim_ledger_decisions.py:run",
                               "appsec-review-process/claim_ledger.py:validate_ledger"),
    "07-hypothesis-discovery": ("pool_coordinator", "appsec-review-process/hypothesis_discovery.py:run",
                                "appsec-review-process/hypothesis_discovery.py:_validate_attempt"),
    "14-attack-chain-composition": ("pool_coordinator", "appsec-review-process/attack_chain_composition.py:run",
                                    "appsec-review-process/attack_chain_composition.py:_validate_attempt"),
    "14-attack-chain-refutation": ("pool_coordinator", "appsec-review-process/attack_chain_refutation.py:run",
                                   "appsec-review-process/attack_chain_refutation.py:_validate_attempt"),
    "03-threat-model-dfd-stride": ("pool_coordinator", "appsec-review-process/threat_model_core.py:run",
                                   "appsec-review-process/threat_model_core.py:validate"),
    "12b-poc-and-fix": ("pool_coordinator", "appsec-review-process/poc_fix_worker.py:run",
                        "appsec-review-process/poc_fix_worker.py:_validate_attempt"),
    "11-remediation-proposal": ("deterministic_python", "appsec-review-process/remediation_proposal.py:run",
                                 "appsec-review-process/remediation_proposal.py:_validate_attempt"),
    "06-reachability-codeql": ("pinned_container", "appsec-review-process/reachability_engine_jobs.py:run_codeql",
                               "appsec-review-process/reachability_engine_jobs.py:validate_codeql"),
    "06-reachability-ir": ("deterministic_python", "appsec-review-process/reachability_engine_jobs.py:run_ir",
                           "appsec-review-process/reachability_engine_jobs.py:validate_ir"),
    "02-treesitter-ast": ("pinned_container", "appsec-review-process/treesitter_ast_job.py:run",
                          "appsec-review-process/treesitter_ast_job.py:validate"),
    "02-code-index": ("deterministic_python", "appsec-review-process/code_index_job.py:run",
                      "appsec-review-process/code_index_job.py:validate"),
}

for _discovery_job in ("02-repository-partition-discovery", "02-dev-project-discovery",
                       "02-devops-project-discovery", "02-sre-operations-topology"):
    WORKERS[_discovery_job] = ("deterministic_python",
        "appsec-review-process/automatic_discovery.py:run",
        "appsec-review-process/automatic_discovery.py:validate")

STALE_GAPS = {
    "shared_dagster_graph_not_integrated", "dagster_lifecycle_not_integrated",
    "full_review_input_assembler_not_implemented", "not_automatic_analysis_dispatch",
    "supplied_result_required", "common_lifecycle_publication_not_integrated",
    "owasp_common_lifecycle_wrapper_missing", "downstream_decision_append_wiring_missing",
    "unassigned_resource_pool", "required_producers_and_c01_c02_runtime_binding_missing",
    "automatic_dispatch_facts_derivation_pending", "missing_dedicated_output_schema",
    "missing_output_contract", "missing_registry_composition", "missing_validator",
    "missing_worker", "no_qualification", "claim_ledger_routing_not_integrated",
    "accepted_test_execution_lifecycle_not_integrated", "operator_test_control_staging_not_integrated",
}

INTEGRATED_CAPABILITIES = {
    "persona-tool-pool-dispatch", "wait-all-rendezvous", "deterministic-pool-merge",
    "evidence-qualified-quorum", "claim-ledger-routing", "remediation-retest-feedback",
    "dynamic-rescope", "completeness-audit-control", "synthetic-hypothesis-resynthesis",
    "threat-model-standard", "owasp-checklist-model", "disa-nsa-hardening-model",
    "final-publication-gate",
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def pool(job_id: str, record: dict) -> str:
    mode = record["execution"]["mode"]
    if mode in {"persona", "pool_coordinator"} or job_id in {
            "02-evidence-assembly", "04-asvs-masvs", "07-red-team-adversarial",
            "08-blue-team-refutation", "09-independent-verification", "12-scoring-prioritization"}:
        return "persona_llm"
    if mode == "pinned_container" or job_id in {
            "02-native-sast", "02-debug-symbol-index", "02-binary-triage", "02-binary-cfg",
            "02-test-execution", "02-secrets-inventory", "02-iac-config-scan",
            "02-container-image-inventory", "02-mobile-sast", "02-sbom-inventory",
            "02-sca-vulnerability-match", "02-license-scan", "02-dependency-lifecycle"}:
        return "docker"
    return "cpu"


def output_record(node: dict, prior: dict) -> dict:
    contract_id = node["contract"]
    contract_path = registry_paths.contract(contract_id)
    contract = load(contract_path)
    result_schema = contract.get("result_schema") or {}
    claim = contract.get("claim_class") or {}
    return {"contract": contract_id,
            "contract_file": registry_paths.repo_rel(registry_paths.contract_rel(contract_id)),
            "schema_file": (f"schemas/{result_schema['schema_file']}" if result_schema else None),
            "claim_class": claim.get("claim_class_id", prior.get("claim_class", "control_decision"))}


def new_record(job_id: str, node: dict, capability: dict | None) -> dict:
    mode, worker, validator = WORKERS[job_id]
    return {"id": job_id, "design_refs": (capability or {}).get("design_refs", ["docs/architecture/design-v3.md"]),
            "graph": {}, "registry": None,
            "execution": {"mode": mode, "worker": worker, "validator": validator},
            "output": {}, "permissions": [],
            "dagster": {"standalone_jobs": [], "lifecycle_binding": {},
                        "launcher_jobs": ["full_review"], "sensor_jobs": ["full_review"]},
            "resource_pool": "cpu", "readiness": "implemented_not_qualified",
            "qualification": {"levels": ["unit"], "references": [
                "appsec-review-process/tests/test_claim_ledger.py"]},
            "gaps": ["no_live_qualification"],
            "next_prerequisite": "Execute and retain this worker in the fresh Hello full_review run."}


def main() -> int:
    graph = load(GRAPH)["jobs"]
    manifest = load(MANIFEST)
    records = {row["id"]: row for row in manifest["jobs"]}
    capabilities = {row["id"]: row for row in manifest["capabilities"]}
    for job_id, node in graph.items():
        record = records.get(job_id)
        if record is None:
            record = new_record(job_id, node, capabilities.get(job_id))
            manifest["jobs"].append(record)
            records[job_id] = record
        record["graph"] = {"node": job_id, "implemented": bool(node["implemented"]),
                           "dependencies": [row["job"] for row in node["dependencies"]]}
        record["registry"] = _registry_for(node, REPO)
        template = load(registry_paths.JOB_TEMPLATES_DIR / f"{node['template']}.json")
        record["permissions"] = template.get("permissions", [])
        record["output"] = output_record(node, record.get("output", {}))
        if job_id in WORKERS:
            mode, worker, validator = WORKERS[job_id]
            record["execution"] = {"mode": mode, "worker": worker, "validator": validator}
        record["dagster"]["lifecycle_binding"] = {
            "kind": "actual_worker", "entrypoint": "appsec-review-process/dagster_workflow.py:full_review"}
        record["dagster"]["launcher_jobs"] = sorted(set(record["dagster"].get("launcher_jobs", [])) | {"full_review"})
        record["resource_pool"] = pool(job_id, record)
        record["gaps"] = [gap for gap in record.get("gaps", []) if gap not in STALE_GAPS]
        record["readiness"] = ("implemented_and_qualified" if
            "live_dagster" in record.get("qualification", {}).get("levels", []) else
            "implemented_not_qualified")
        if record["gaps"]:
            record["next_prerequisite"] = "Close the retained qualification and coverage gaps listed for this job."
        else:
            record["next_prerequisite"] = "Execute and retain this worker in the fresh Hello full_review run."
    for capability in manifest["capabilities"]:
        if capability["id"] not in INTEGRATED_CAPABILITIES:
            continue
        capability["readiness"] = "implemented_not_qualified"
        capability["gaps"] = [gap for gap in capability.get("gaps", []) if gap not in STALE_GAPS and
                              gap not in {"threat_model_schema_and_scope_undecided",
                                          "owasp_versions_profiles_applicability_and_promotion_rules_undecided",
                                          "platform_applicability_precedence_tailoring_and_reference_storage_undecided"}]
        if "no_live_qualification" not in capability["gaps"]:
            capability["gaps"].append("no_live_qualification")
        capability["resource_pool"] = ("persona_llm" if capability["id"] in {
            "persona-tool-pool-dispatch", "wait-all-rendezvous"} else "cpu")
        capability["next_prerequisite"] = (
            "Execute and retain this capability in the fresh Hello full_review run.")
    manifest["jobs"].sort(key=lambda row: list(graph).index(row["id"]))
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
