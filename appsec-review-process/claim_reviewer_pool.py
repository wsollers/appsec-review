#!/usr/bin/env python3
"""Automatic C01/C02 reviewer pool and stage-scoped deterministic merge for 07/08/09/12."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import claude_cli_invoker as cli
import claim_review_lifecycle as lifecycle
import container_execution
import deterministic_pool_merge
import model_version_registry as model_versions
import persona_dispatch
import persona_invocation
import persona_prompt_assembly
import permission_capabilities
import pool_launcher
import pool_rendezvous
import pool_specification
import resource_pools
import review_cli
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import SchemaStore, validate_document

JOB = "deterministic-pool-merge"
TEMPLATE = "claim-review-pool-cell"
RESULT = "deterministic-pool-merge.json"
PERMISSIONS = ["read-run-data", "write-run-data"]
ROOT_ID = "stage-upstream"
CLASS = lifecycle.POOL_CLASSES
ROLE = {"07-red-team-adversarial": "red-team-adversary",
        "08-blue-team-refutation": "blue-team-refuter",
        "09-independent-verification": "independent-verifier"}


def root(run_id: str, stage: str) -> Path:
    lifecycle._stage(stage)
    return data_path(run_id, "jobs", JOB, stage)


def _sha(value: Any) -> str:
    return "sha256:" + digest(value)


def _pool_claims(value: dict[str, Any], inputs: tuple, allowed: tuple,
                 result_filename: str) -> list[dict[str, Any]]:
    """Map mechanically validated candidates to B14 transport claims without promotion."""
    first = inputs[0]
    claims = []
    for candidate in value["candidates"]:
        if candidate["claim_class"] not in allowed:
            raise cli.InvokerOutputError("reviewer candidate exceeds the invocation claim ceiling")
        claims.append({"claim_id": candidate["candidate_id"],
            "claim_class": candidate["claim_class"], "statement": candidate["assertion"],
            "file": result_filename,
            "citations": [{"root": first.root, "path": first.path, "sha256": first.sha256,
                           "locator": candidate["subject_id"]}]})
    return claims


# ClaudeCliInvoker intentionally has an explicit schema-to-claim-builder allowlist. Register this
# lane's closed schema once; the model still passes the same strict envelope/schema validation.
cli._CLAIM_BUILDERS.setdefault("claim-review-pool-candidates.schema.json", _pool_claims)


def _runtime_instructions(package: Any) -> str:
    request = package.request
    stage = request["job_id"]
    claim_class = CLASS[stage]
    identity = {"job_id": stage, "attempt_id": request["attempt_id"],
        "role_id": ROLE.get(stage), "artifact_path": f"requests/{request['attempt_id']}.json",
        "artifact_sha256": package.request_sha256,
        "permission_receipt_path": f"requests/{request['attempt_id']}.json",
        "permission_receipt_sha256": package.request_sha256,
        "reason": "Bounded stage reviewer selected by the accepted reviewer-pool specification."}
    if stage == "07-red-team-adversarial":
        fields = ["claim_id", "reviewer", "attacker_case", "citations", "dissent_ids"]
        rule = "reviewer is the identity below plus each claim's source_generation and component_generation"
    elif stage == "08-blue-team-refutation":
        fields = ["claim_id", "reviewer", "disposition", "rationale", "proof_obligations",
                  "citations", "dissent_ids"]
        rule = "reviewer is the identity below plus each claim's source_generation and component_generation"
    elif stage == "09-independent-verification":
        fields = ["claim_id", "verifier", "disposition", "method", "proof_obligations",
                  "citations", "dissent_ids"]
        rule = ("verifier is the identity below plus each claim's source_generation and component_generation; "
                "this invocation has no new independent target evidence, so never emit VERIFIED")
    else:
        fields = ["claim_id", "factors", "rationale"]
        rule = "factors are null unless the accepted upstream status is VERIFIED; otherwise each factor is 0..4"
    upstream_sha = package.inputs[0].sha256
    return "\n\n## Trusted stage runtime (not target data)\n\n" + json.dumps({
        "stage": stage, "required_claim_class": claim_class,
        "upstream_artifact_sha256": upstream_sha, "decision_exact_fields": fields,
        "actor_identity": identity, "decision_rule": rule,
        "candidate_rule": "one candidate for every and only upstream claim_id"
    }, indent=2, sort_keys=True)


class ClaimReviewerInvoker:
    """Lane adapter over the real strict Claude CLI invoker, adding trusted instance identity."""
    invoker_id = "claude-cli"

    def __init__(self, *, effort: str, budget_usd: float | None = None,
                 timeout_seconds: int = cli.DEFAULT_TIMEOUT_SECONDS, dispatch_fn=None) -> None:
        self.effort, self.budget_usd, self.timeout_seconds = effort, budget_usd, timeout_seconds
        self.dispatch_fn = dispatch_fn or review_cli._dispatch_streaming

    def invoke(self, package: Any, *, output_root: Path, cancel: Any) -> None:
        instructions = _runtime_instructions(package)

        def dispatch(argv: list[str], prompt: str, timeout: int, transcript: Path) -> dict[str, Any]:
            return self.dispatch_fn(argv, prompt + instructions, timeout, transcript)

        cli.ClaudeCliInvoker(effort=self.effort, budget_usd=self.budget_usd,
            timeout_seconds=self.timeout_seconds, dispatch_fn=dispatch).invoke(
                package, output_root=output_root, cancel=cancel)


def _code_hashes() -> dict[str, str]:
    paths = ["claim_reviewer_pool.py", "claim_review_lifecycle.py", "claim_lifecycle_core.py",
             "claude_cli_invoker.py", "persona_invocation.py", "deterministic_pool_merge.py",
             "pool_launcher.py", "pool_rendezvous.py", "pool_specification.py",
             "registry/job-templates/claim-review-pool-cell.json",
             "registry/output-contracts/claim-review-pool-candidates.json",
             "registry/personas/claim-reviewer.json", "registry/roles/claim-reviewer.json",
             "registry/domains/claim-review-lifecycle.json",
             "registry/tooling-profiles/claim-review-static.json", "claim-review-pool-task.md"]
    result = {path: file_hash(ROOT / path) for path in paths}
    result["schemas/claim-review-pool-candidates.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "claim-review-pool-candidates.schema.json")
    result["schemas/claim-review-pool-receipt.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "claim-review-pool-receipt.schema.json")
    result["schemas/claim-review-decision.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "claim-review-decision.schema.json")
    return result


def _upstream_location(run_id: str, stage: str) -> tuple[Path, str]:
    pointer_path = lifecycle._upstream_pointer(run_id, stage)
    pointer = read_json(pointer_path)
    attempt = pointer_path.parent / "attempts" / pointer["attempt_id"]
    artifact = lifecycle.core.STAGES[stage][1]
    path = attempt / artifact
    if attempt.is_symlink() or path.is_symlink() or not path.is_file():
        raise Blocked("claim reviewer pool: accepted upstream artifact path is unsafe")
    return attempt, artifact


def _request_template(run_id: str, stage: str, upstream_path: Path,
                      source: str, evaluated_at: str) -> tuple[dict, dict]:
    store = SchemaStore()
    template = persona_prompt_assembly.load_job_template(TEMPLATE, store)
    outer = persona_prompt_assembly.assemble_outer_prompt(TEMPLATE, store=store)
    composition = persona_dispatch._composition_block(TEMPLATE, template, store)
    records = persona_invocation.load_composition(persona_invocation.REGISTRY_DIR, composition, store)
    ceiling = persona_invocation.claim_ceiling(records["role"], records["tooling_profile"])
    if CLASS[stage] not in ceiling["allowed"]:
        raise Blocked("claim reviewer pool: registry composition forbids this stage claim class")
    resolved = review_cli.resolve_model(TEMPLATE, template["budget_default"])
    model = model_versions.model_identity_for(run_id, resolved["model"])
    data = upstream_path.read_bytes()
    readable = [{"root": ROOT_ID, "path": upstream_path.name,
                 "sha256": persona_invocation._bytes_sha(data), "bytes": len(data),
                 "role": "evidence", "producer_request_sha256": None}]
    request = {"invocation_role": "produce", "invoker_id": "claude-cli",
        "outer_prompt": outer, "persona": composition, "model": model, "tools": [],
        "budget": dict(persona_dispatch.PERSONA_BUDGETS[template["budget_default"]]),
        "readable_inputs": readable, "allowed_claim_classes": list(ceiling["allowed"]),
        "prohibited_claim_classes": list(ceiling["prohibited"]), "producers": []}
    permission = persona_dispatch._permission_block(stage, run_id=run_id,
        source_snapshot_sha256=source, now=evaluated_at)
    return request, permission


def prepare(run_id: str, dagster_run_id: str, stage: str, force: bool = False) -> dict[str, Any]:
    """Derive the stable C01 specification only from the newest accepted stage population."""
    del dagster_run_id, force
    lifecycle._stage(stage)
    upstream, binding, source = lifecycle._load_upstream(run_id, stage)
    attempt_root, artifact = _upstream_location(run_id, stage)
    pointer = read_json(lifecycle._upstream_pointer(run_id, stage))
    evaluated_at = pointer["accepted_at"]
    request, permission = _request_template(run_id, stage, attempt_root / artifact,
                                             source, evaluated_at)
    count = len(upstream[lifecycle.ARRAYS[stage]])
    group = {"group_id": "reviewers", "worker_kind": pool_specification.PERSONA,
        "count": 1 if count else 0, "memory_heavy": False, "permission": permission,
        "persona_request": request, "tool_request": None}
    spec = {"schema": pool_specification.SPEC_ID,
        "pool_id": "claim-review-" + stage, "lane": stage, "run_id": run_id, "job_id": stage,
        "attempt_id": "review-" + digest({"stage": stage, "binding": binding})[:24],
        "budget_class": "standard",
        "pool_budget": {"max_instances": 1, "max_persona_input_units": 800_000,
                        "max_persona_output_units": 200_000, "max_total_timeout_seconds": 3600},
        "resource_pool_policy": {"allowed_pools": [resource_pools.PERSONA_LLM]},
        "wait_all": True, "rendezvous_timeout_seconds": 2400,
        "empty_pool_reason": None if count else "upstream_produced_no_work",
        "worker_groups": [group]}
    return {"run_id": run_id, "stage": stage, "source_generation": source,
        "upstream": upstream, "upstream_binding": binding,
        "upstream_attempt": str(attempt_root), "upstream_artifact": artifact,
        "accepted_at": evaluated_at, "spec": spec,
        "applicability": "APPLICABLE" if count else "SKIPPED_NA_NO_CANDIDATES",
        "code": _code_hashes()}


def _context(inputs: dict[str, Any], attempt: Path) -> pool_specification.PoolContext:
    pool_parent, rendezvous = attempt / "pools", attempt / "rendezvous"
    pool_parent.mkdir(); rendezvous.mkdir()
    upstream = Path(inputs["upstream_attempt"])
    model = inputs["spec"]["worker_groups"][0]["persona_request"]["model"]
    return pool_specification.PoolContext(pool_parent=pool_parent,
        registry_dir=persona_invocation.REGISTRY_DIR, prompt_root=ROOT,
        readable_roots={ROOT_ID: upstream}, allowed_models=(model,), invoker_id="claude-cli",
        images_dir=container_execution.IMAGES_DIR,
        host_flavor="windows" if __import__("os").name == "nt" else "posix",
        docker_host=None, docker_executable=None, container_user=None, mount_roots={},
        source_snapshot_sha256=inputs["source_generation"], registry_ceiling=None)


def _validate_merge(inputs: dict[str, Any], merge: dict[str, Any]) -> None:
    if validate_document(merge, "deterministic-pool-merge.schema.json"):
        raise Blocked("claim reviewer pool: deterministic merge fails its closed schema")
    decisions = lifecycle.decisions_from_pool(inputs["stage"], inputs["upstream"], merge)
    # Validate not only JSON shape and population coverage but the stage's evidence, independence,
    # authority, proof-obligation and monotonic-transition rules before the merge is accepted.
    lifecycle.build_result({"stage": inputs["stage"], "upstream": inputs["upstream"],
        "upstream_binding": inputs["upstream_binding"], "decisions": decisions}, "pool-validation")


def _receipts(inputs: dict[str, Any], merge: dict[str, Any], launched: Any) -> tuple[dict, dict, dict]:
    permission = {"schema": "appsec-review/producer-permission-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB,
        "source_snapshot_sha256": inputs["source_generation"], "permissions": PERMISSIONS}
    lineage = {"schema": "appsec-review/producer-lineage-receipt/1.0",
        "run_id": inputs["run_id"], "job_id": JOB,
        "source_snapshot_sha256": inputs["source_generation"],
        "build_lineage_sha256": _sha({"stage": inputs["stage"],
            "upstream": inputs["upstream_binding"], "spec": pool_specification.spec_sha256(inputs["spec"]),
            "expansion": launched.expansion_sha256, "manifest": launched.terminal_manifest_sha256,
            "merge": merge["merge_sha256"]})}
    receipt = {"schema": "appsec-review/claim-review-pool-receipt/1.0",
        "run_id": inputs["run_id"], "stage": inputs["stage"],
        "decision": "APPLICABLE" if inputs["applicability"] == "APPLICABLE" else "SKIPPED_NA",
        "reason": ("Accepted upstream claims were dispatched to the reviewer pool." if
                   inputs["applicability"] == "APPLICABLE" else
                   "The newest accepted upstream artifact contains no claims."),
        "pool_directory": launched.pool_directory, "pool_outcome": launched.outcome,
        "instance_count": launched.instance_count, "expansion_sha256": launched.expansion_sha256,
        "terminal_manifest_sha256": launched.terminal_manifest_sha256,
        "merge_sha256": merge["merge_sha256"]}
    return permission, lineage, receipt


def _validate_attempt(run_id: str, stage: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs or inputs["code"] != _code_hashes():
        raise Blocked("claim reviewer pool: immutable inputs or implementation changed")
    if prepare(run_id, "validation", stage) != inputs:
        raise Blocked("claim reviewer pool: newest accepted upstream changed")
    merge = read_json(attempt / RESULT)
    _validate_merge(inputs, merge)
    receipt = read_json(attempt / "pool-receipt.json")
    if (validate_document(receipt, "claim-review-pool-receipt.schema.json") or
            receipt.get("merge_sha256") != merge["merge_sha256"] or receipt.get("stage") != stage):
        raise Blocked("claim reviewer pool: pool receipt is inconsistent")
    launched = type("RetainedPool", (), {"pool_directory": receipt.get("pool_directory"),
        "outcome": receipt.get("pool_outcome"), "instance_count": receipt.get("instance_count"),
        "expansion_sha256": receipt.get("expansion_sha256"),
        "terminal_manifest_sha256": receipt.get("terminal_manifest_sha256")})()
    permission, lineage, expected_receipt = _receipts(inputs, merge, launched)
    if (read_json(attempt / "permission.json") != permission or
            read_json(attempt / "lineage.json") != lineage or receipt != expected_receipt):
        raise Blocked("claim reviewer pool: retained receipts changed")


def run(run_id: str, dagster_run_id: str, stage: str, force: bool = False) -> dict[str, Any]:
    """Dispatch the real reviewer pool and publish its verified deterministic merge."""
    lifecycle._stage(stage)
    base = root(run_id, stage)

    def execute(allocation: dict[str, Any], inputs: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        attempt = allocation["attempt"]
        context = _context(inputs, attempt)
        rendezvous_parent = attempt / "rendezvous"
        runtime = pool_rendezvous.RendezvousRuntime(rendezvous_parent=rendezvous_parent,
            invoker=ClaimReviewerInvoker(effort="high"), clock=lambda: inputs["accepted_at"],
            stop_grace_seconds=5, cancel=pool_rendezvous.PoolCancel(), max_parallel=1,
            wait_limit_seconds=2400, drain_seconds=10)
        launched = pool_launcher.launch(inputs["spec"], context=context, runtime=runtime)
        pool_root = context.pool_parent / launched.pool_directory
        verified = pool_rendezvous.load_verified_manifest(pool_root, expected_spec=inputs["spec"],
            context=context, rendezvous_parent=rendezvous_parent)
        merge = deterministic_pool_merge.merge_verified_manifest(
            verified, pool_root=pool_root, run_id=run_id)
        _validate_merge(inputs, merge)
        atomic_json(attempt / RESULT, merge)
        permission, lineage, receipt = _receipts(inputs, merge, launched)
        atomic_json(attempt / "permission.json", permission)
        atomic_json(attempt / "lineage.json", lineage)
        atomic_json(attempt / "pool-receipt.json", receipt)
        skipped = inputs["applicability"] != "APPLICABLE"
        status = {"process": JOB, "status": "OK_WITH_GAPS" if skipped else "OK", "result": RESULT,
                  "claim_limit": "CONTROL_DECISION_ONLY", "stage": stage,
                  "applicability": inputs["applicability"]}
        return record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_run_id, worker_kind="pool_coordinator",
            output_contract=JOB, input_fingerprint=fingerprint,
            started_at=allocation["started_at"], execution_status="OK_WITH_GAPS" if skipped else "OK",
            summary=("Reviewer pool was not applicable because the accepted population was empty." if skipped
                     else "Published the C02-verified stage reviewer merge."), status_record=status,
            artifact_paths=[RESULT, "permission.json", "lineage.json", "pool-receipt.json", "status.json"],
            gaps=(["SKIPPED_NA: no accepted upstream claims; zero reviewer instances were launched."]
                  if skipped else None),
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, stage, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB,
        dagster_run_id=dagster_run_id, worker_kind="pool_coordinator", output_contract=JOB,
        resume_command=(f"python -B appsec-review-process/claim_reviewer_pool.py --run-id {run_id} "
                        f"--stage {stage}"), derive_inputs=lambda: prepare(run_id, dagster_run_id, stage),
        fingerprint_inputs=lambda value: _sha(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "stage": stage,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, inputs:
            _validate_attempt(run_id, stage, attempt, inputs),
        blocked_summary="Newest accepted claims or trusted reviewer-pool context were unavailable.",
        failed_summary="Reviewer pool did not publish a verified deterministic merge.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dagster-run-id", default="standalone-claim-review-pool")
    parser.add_argument("--stage", required=True, choices=lifecycle.STAGES)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run(args.run_id, args.dagster_run_id, args.stage, args.force), indent=2))
