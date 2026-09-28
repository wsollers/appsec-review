#!/usr/bin/env python3
"""Automatic C01/C02 reviewer pool and stage-scoped deterministic merge for 07/08/09/12.

The stage's accepted claims are sharded across ``claim_review_pool_instances`` reviewer instances
(claim_review_sharding, ADR-0021): each claim is reviewed exactly once per stage, each instance
reads only its own shard of the upstream document and runs as its own registry persona chosen from
the job template's ``stage_personas``. The shard outputs are merged by the deterministic pool merge
and the full population is then checked by the stage's lifecycle rules exactly as before.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

import claude_cli_invoker as cli
import claim_review_derive as derive
import claim_review_sharding as sharding
import claim_review_lifecycle as lifecycle
import container_execution
import deterministic_pool_merge
import model_version_registry as model_versions
import persona_dispatch
import persona_invocation
import pipeline_log
import persona_prompt_assembly
import permission_capabilities
import pool_launcher
import pool_rendezvous
import pool_specification
import resource_pools
import review_cli
import supporting_evidence_menu as evidence_menu
import tunables
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, read_json
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current
from schema_validate import SchemaStore, validate_document

JOB = "deterministic-pool-merge"
TEMPLATE = "claim-review-pool-cell"
RESULT = "deterministic-pool-merge.json"
PERMISSIONS = ["read-run-data", "write-run-data"]
ROOT_ID = "stage-upstream"
SHARD_DIR = "stage-shards"
COVERAGE = "shard-coverage.json"
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
    """Trusted per-stage block appended to the prompt. It no longer carries the actor identity,
    hashes or candidate wrapper for the model to copy: claim_review_derive builds those."""
    stage = package.request["job_id"]
    required, optional = derive.PERSONA_FIELDS[stage]
    if stage == "07-red-team-adversarial":
        rule = ("attacker_case is your adversarial hypothesis for the claim; citation_ids name the "
                "claim's own upstream citations that support it")
    elif stage == "08-blue-team-refutation":
        rule = ("answer every upstream proof obligation of the claim by obligation_id with a status "
                "and the citation_ids it rests on; REFUTED needs a FAILED obligation, SURVIVING needs "
                "every obligation SATISFIED, UNRESOLVED keeps an UNRESOLVED obligation")
    elif stage == "09-independent-verification":
        rule = ("answer every upstream proof obligation by obligation_id; this invocation has no new "
                "independent target evidence, so never emit VERIFIED; UNRESOLVED or BLOCKED keeps an "
                "UNRESOLVED obligation")
    else:
        rule = "factors are null unless the accepted upstream status is VERIFIED; otherwise each factor is 0..4"
    citable = {"07-red-team-adversarial": "the claim's citations",
               "08-blue-team-refutation": "the claim's citations or review_citations",
               "09-independent-verification": "the claim's citations or refutation_citations"}
    return "\n\n## Trusted stage runtime (not target data)\n\n" + json.dumps({
        "stage": stage, "reviewer_role": ROLE.get(stage),
        "reviewer_persona": (package.request.get("persona") or {}).get("persona_id"),
        "scope_rule": ("your stage upstream document is one shard of the stage's claims; review exactly "
                       "its claims. The supporting-evidence menu may list claims assigned to other "
                       "reviewers: never decide those"),
        "reply_shape": ("the candidates envelope value is {\"decisions\": [...]} and validates "
                        f"{derive.PERSONA_SCHEMA}; one decision per upstream claim_id"),
        "decision_required_fields": sorted(required), "decision_optional_fields": sorted(optional),
        "decision_rule": rule,
        "judgment_fields": {key: value for key, value in {
            "cwe": ("optional: {cwe_id: 'CWE-<n>', rationale} naming the weakness the claim instantiates; "
                    "it must be in the pinned CWE catalog; omit when unsure"),
            "cvss_v4": ("VERIFIED claims only: {metrics: the eleven CVSS v4.0 base metrics AV AC AT PR UI VC VI "
                        "VA SC SI SA, rationale: one justification per metric}; Python computes vector, score and "
                        "severity (reachability may cap it later)"),
            "remediation": ("VERIFIED claims only, optional: {objective, patch_proposal}; published as "
                            "PATCH_PROPOSED_UNVALIDATED")}.items() if key in optional},
        "citation_rule": (("cite by citation_id only, using ids from " + citable[stage] +
                           "; never copy or invent citation objects") if stage in citable else
                          "no citations for this stage"),
        "orchestrator_supplies": ("candidate_id, subject_id, claim_class, evidence_sha256, the "
                                  "reviewer/verifier identity, canonical citation objects, proof "
                                  "obligation statements and the assertion string; do not write them"),
        "candidate_rule": "exactly one decision for every and only upstream claim_id"
    }, indent=2, sort_keys=True)


def _derive_fill(package: Any):
    """fill_result hook: replace the model's reply with the derived candidates document."""
    stage = package.request["job_id"]
    first = package.inputs[0]
    upstream = derive.upstream_from_bytes(stage, first.data)

    def fill(envelope: dict[str, Any], result_field: str) -> list[str]:
        value, limitations = derive.derive(stage, upstream, envelope.get(result_field),
            request=package.request, request_sha256=package.request_sha256,
            evidence_sha256=first.sha256)
        envelope[result_field] = value
        return limitations

    return fill


class ClaimReviewerInvoker:
    """Lane adapter over the real strict Claude CLI invoker: renders the persona-facing reply
    schema and derives the strict candidates document from the reviewer's judgment."""
    invoker_id = "claude-cli"

    def __init__(self, *, effort: str, budget_usd: float | None = None,
                 timeout_seconds: int = cli.DEFAULT_TIMEOUT_SECONDS, dispatch_fn=None) -> None:
        self.effort, self.budget_usd, self.timeout_seconds = effort, budget_usd, timeout_seconds
        self.dispatch_fn = dispatch_fn or review_cli._dispatch_streaming

    def invoke(self, package: Any, *, output_root: Path, cancel: Any) -> None:
        instructions = _runtime_instructions(package)

        def dispatch(argv: list[str], prompt: str, timeout: int, transcript: Path) -> dict[str, Any]:
            return self.dispatch_fn(argv, prompt + instructions, timeout, transcript)

        # persona_invocation records only "the invoker raised" and drops the text by design, so print
        # the traceback to the step log (stderr) here, then re-raise unchanged.
        try:
            cli.ClaudeCliInvoker(effort=self.effort, budget_usd=self.budget_usd,
                timeout_seconds=self.timeout_seconds, dispatch_fn=dispatch,
                fill_result=_derive_fill(package), persona_schema=derive.PERSONA_SCHEMA).invoke(
                    package, output_root=output_root, cancel=cancel)
        except BaseException as exc:
            import traceback
            print(f"[reviewer-diag] invocation raised {type(exc).__name__}: {str(exc)[:2000]} "
                  f"(job={package.request.get('job_id')} attempt={package.request.get('attempt_id')})",
                  file=sys.stderr, flush=True)
            traceback.print_exc(file=sys.stderr)
            pipeline_log.log(f"[reviewer-diag] invocation raised {type(exc).__name__}: {str(exc)[:600]}",
                             run_id=package.request.get("run_id"), job=package.request.get("job_id"))
            raise


def _code_hashes() -> dict[str, str]:
    paths = ["claim_reviewer_pool.py", "claim_review_derive.py", "claim_review_lifecycle.py",
             "claim_lifecycle_core.py",
             "claude_cli_invoker.py", "persona_invocation.py", "deterministic_pool_merge.py",
             "pool_launcher.py", "pool_rendezvous.py", "pool_specification.py",
             "registry/job-templates/claim-review-pool-cell.json",
             "registry/output-contracts/claim-review-pool-candidates.json",
             "registry/personas/claim-reviewer.json", "registry/roles/claim-reviewer.json",
             "registry/domains/claim-review-lifecycle.json",
             "registry/tooling-profiles/claim-review-static.json", "claim-review-pool-task.md"]
    result = {path: file_hash(ROOT / path) for path in paths}
    result["supporting_evidence_menu.py"] = file_hash(ROOT / "supporting_evidence_menu.py")
    result["claim_review_sharding.py"] = file_hash(ROOT / "claim_review_sharding.py")
    for persona_id in sorted({item for ids in _stage_personas().values() for item in ids}):
        path = f"registry/personas/{persona_id}.json"
        result[path] = file_hash(ROOT / path)
    result["schemas/claim-review-pool-candidates.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "claim-review-pool-candidates.schema.json")
    result["schemas/claim-review-pool-receipt.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "claim-review-pool-receipt.schema.json")
    result["schemas/claim-review-decision.schema.json"] = file_hash(
        ROOT.parent / "schemas" / "claim-review-decision.schema.json")
    result["schemas/" + derive.PERSONA_SCHEMA] = file_hash(ROOT.parent / "schemas" / derive.PERSONA_SCHEMA)
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


def _template() -> dict[str, Any]:
    return persona_prompt_assembly.load_job_template(TEMPLATE, SchemaStore())


def _stage_personas() -> dict[str, list[str]]:
    value = _template().get("stage_personas")
    if not isinstance(value, dict) or set(value) != set(lifecycle.STAGES):
        raise Blocked("claim reviewer pool: job template stage_personas must name every review stage")
    return value


def _persona_records(ids: list[str]) -> dict[str, dict[str, Any]]:
    store = SchemaStore()
    return {persona_id: persona_invocation._load_record(persona_invocation.REGISTRY_DIR, "personas",
                "persona.schema.json", "persona_id", persona_id, store) for persona_id in ids}


def _request_template(run_id: str, stage: str, upstream_path: Path,
                      source: str, evaluated_at: str, menu: dict | None = None,
                      persona_id: str | None = None, upstream_bytes: bytes | None = None
                      ) -> tuple[dict, dict]:
    """One reviewer instance's request. ``upstream_path`` names the shard file (its bytes given in
    ``upstream_bytes`` when it is not on disk yet); ``persona_id`` one of the template's variants."""
    store = SchemaStore()
    template = persona_prompt_assembly.load_job_template(TEMPLATE, store)
    outer = persona_prompt_assembly.assemble_outer_prompt(TEMPLATE, store=store, persona_id=persona_id)
    composition = persona_dispatch._composition_block(TEMPLATE, template, store)
    if persona_id is not None and persona_id != composition["persona_id"]:
        record = _persona_records([persona_id])[persona_id]
        composition = {**composition, "persona_id": persona_id,
                       "persona_sha256": persona_invocation._sha(record)}
    records = persona_invocation.load_composition(persona_invocation.REGISTRY_DIR, composition, store)
    ceiling = persona_invocation.claim_ceiling(records["role"], records["tooling_profile"])
    if CLASS[stage] not in ceiling["allowed"]:
        raise Blocked("claim reviewer pool: registry composition forbids this stage claim class")
    resolved = review_cli.resolve_model(TEMPLATE, template["budget_default"])
    model = model_versions.model_identity_for(run_id, resolved["model"])
    data = upstream_bytes if upstream_bytes is not None else upstream_path.read_bytes()
    readable = [{"root": ROOT_ID, "path": upstream_path.name,
                 "sha256": persona_invocation._bytes_sha(data), "bytes": len(data),
                 "role": "evidence", "producer_request_sha256": None}]
    # The stage upstream stays readable_inputs[0]; the supporting-evidence menu and every file it
    # pins follow, so the reviewer may read exactly what the menu points at.
    readable += evidence_menu.readable_inputs(menu) if menu else []
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
    # Pointers carry isoformat (micros, +00:00); the permission model takes whole-second Z.
    from datetime import datetime, timezone
    evaluated_at = datetime.fromisoformat(pointer["accepted_at"].replace("Z", "+00:00")).astimezone(
        timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    records = upstream[lifecycle.ARRAYS[stage]]
    menu = evidence_menu.build(run_id, stage, records)
    shards = plan(stage, upstream)
    groups = []
    for shard in shards:
        request, permission = _request_template(run_id, stage, Path(shard["file"]), source,
            evaluated_at, menu, persona_id=shard["persona_id"], upstream_bytes=_shard_bytes(
                stage, upstream, shard["claim_ids"]))
        groups.append({"group_id": shard["group_id"], "worker_kind": pool_specification.PERSONA,
            "count": 1, "memory_heavy": False, "permission": permission,
            "persona_request": request, "tool_request": None})
    if not groups:
        # An empty population still records one (zero-count) group so the pool is well-formed.
        request, permission = _request_template(run_id, stage, attempt_root / artifact,
                                                 source, evaluated_at, menu)
        groups.append({"group_id": "reviewers", "worker_kind": pool_specification.PERSONA,
            "count": 0, "memory_heavy": False, "permission": permission,
            "persona_request": request, "tool_request": None})
    count = len(shards)
    per = groups[0]["persona_request"]["budget"]
    spec = {"schema": pool_specification.SPEC_ID,
        "pool_id": "claim-review-" + stage, "lane": stage, "run_id": run_id, "job_id": stage,
        "attempt_id": "review-" + digest({"stage": stage, "binding": binding})[:24],
        "budget_class": "standard",
        "pool_budget": {"max_instances": max(1, count),
                        "max_persona_input_units": max(1, count) * per["input_unit_limit"],
                        "max_persona_output_units": max(1, count) * per["output_unit_limit"],
                        "max_total_timeout_seconds": max(1, count) * 2 * per["timeout_seconds"]},
        "resource_pool_policy": {"allowed_pools": [resource_pools.PERSONA_LLM]},
        "wait_all": True, "rendezvous_timeout_seconds": 2400 * max(1, math.ceil(count / _max_parallel())),
        "empty_pool_reason": None if count else "upstream_produced_no_work",
        "worker_groups": groups}
    return {"run_id": run_id, "stage": stage, "source_generation": source,
        "upstream": upstream, "upstream_binding": binding,
        "upstream_attempt": str(attempt_root), "upstream_artifact": artifact,
        "accepted_at": evaluated_at, "spec": spec, "shards": shards,
        "applicability": "APPLICABLE" if records else "SKIPPED_NA_NO_CANDIDATES",
        "evidence_menu": menu, "code": _code_hashes()}


def _max_parallel() -> int:
    return max(1, int(tunables.value(TEMPLATE, "claim_review_pool_max_parallel")))


def _shard_bytes(stage: str, upstream: dict[str, Any], claim_ids: list[str]) -> bytes:
    return sharding.shard_bytes(sharding.shard_document(lifecycle.ARRAYS[stage], upstream, claim_ids))


def plan(stage: str, upstream: dict[str, Any]) -> list[dict[str, Any]]:
    """The stage's shard plan: claim ids, reviewer persona and shard file per reviewer instance.

    Deterministic in the accepted population and the registry (template tunables and personas)."""
    records = upstream[lifecycle.ARRAYS[stage]]
    if not records:
        return []
    try:
        claim_sets = sharding.plan_within_limit(records,
            int(tunables.value(TEMPLATE, "claim_review_pool_instances")),
            units_max=int(tunables.value(TEMPLATE, "claim_review_shard_input_units_max")),
            instances_max=min(pool_specification.MAX_INSTANCES, tunables.shared("pool_groups_max")))
        candidates = _stage_personas()[stage]
        assigned = sharding.assign_personas(stage, claim_sets, records, candidates,
                                            _persona_records(candidates))
    except ValueError as exc:
        raise Blocked(f"claim reviewer pool: {exc}") from exc
    shards = []
    for row in assigned:
        name = f"shard-{row['shard_index']:02d}.json"
        data = _shard_bytes(stage, upstream, row["claim_ids"])
        shards.append({**row, "group_id": f"reviewer-{row['shard_index']:02d}", "file": name,
                       "sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                       "estimated_input_units": sharding.shard_units(records, row["claim_ids"])})
    return shards


def _context(inputs: dict[str, Any], attempt: Path) -> pool_specification.PoolContext:
    pool_parent, rendezvous = attempt / "pools", attempt / "rendezvous"
    pool_parent.mkdir(); rendezvous.mkdir()
    model = inputs["spec"]["worker_groups"][0]["persona_request"]["model"]
    if inputs.get("shards"):
        shard_root = attempt / SHARD_DIR
        shard_root.mkdir()
        for shard in inputs["shards"]:
            data = _shard_bytes(inputs["stage"], inputs["upstream"], shard["claim_ids"])
            if "sha256:" + hashlib.sha256(data).hexdigest() != shard["sha256"]:
                raise Blocked("claim reviewer pool: shard bytes differ from the prepared plan")
            (shard_root / shard["file"]).write_bytes(data)
        roots = {ROOT_ID: shard_root}
    else:
        roots = {ROOT_ID: Path(inputs["upstream_attempt"])}
    if inputs.get("evidence_menu"):
        menu_root = evidence_menu.write(attempt / "evidence-menu", inputs["evidence_menu"])
        roots.update(evidence_menu.readable_roots(inputs["run_id"], inputs["evidence_menu"], menu_root))
    return pool_specification.PoolContext(pool_parent=pool_parent,
        registry_dir=persona_invocation.REGISTRY_DIR, prompt_root=ROOT,
        readable_roots=roots, allowed_models=(model,), invoker_id="claude-cli",
        images_dir=container_execution.IMAGES_DIR,
        host_flavor="windows" if __import__("os").name == "nt" else "posix",
        docker_host=None, docker_executable=None, container_user=None, mount_roots={},
        source_snapshot_sha256=inputs["source_generation"], registry_ceiling=None)


def shard_coverage(inputs: dict[str, Any], merge: dict[str, Any]) -> dict[str, Any]:
    """Which shard's claims the merge decided, by shard, from the merged candidates' worker ids."""
    spec_digest = pool_specification.spec_sha256(inputs["spec"])
    decided: dict[str, set[str]] = {}
    for candidate in merge.get("candidates", []):
        for worker_id in candidate.get("worker_ids", []):
            decided.setdefault(worker_id, set()).add(candidate.get("subject_id"))
    rows, unreviewed = [], []
    for shard in inputs.get("shards") or []:
        worker_id = pool_specification.instance_id(spec_digest, shard["group_id"], 0)
        missing = sorted(set(shard["claim_ids"]) - decided.get(worker_id, set()))
        unreviewed += missing
        rows.append({"group_id": shard["group_id"], "worker_id": worker_id,
                     "persona_id": shard["persona_id"], "claim_ids": shard["claim_ids"],
                     "worker_missing": worker_id in set(merge.get("missing_worker_ids", [])),
                     "unreviewed_claim_ids": missing})
    return {"schema": "appsec-review/claim-review-shard-coverage/1.0", "run_id": inputs["run_id"],
            "stage": inputs["stage"], "claim_count": len(inputs["upstream"][lifecycle.ARRAYS[inputs["stage"]]]),
            "shards": rows, "unreviewed_claim_ids": sorted(unreviewed)}


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
    if read_json(attempt / COVERAGE) != shard_coverage(inputs, merge):
        raise Blocked("claim reviewer pool: shard coverage record changed")
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
            stop_grace_seconds=5, cancel=pool_rendezvous.PoolCancel(),
            max_parallel=min(_max_parallel(), max(1, len(inputs.get("shards") or []))),
            wait_limit_seconds=inputs["spec"]["rendezvous_timeout_seconds"], drain_seconds=10)
        launched = pool_launcher.launch(inputs["spec"], context=context, runtime=runtime)
        pool_root = context.pool_parent / launched.pool_directory
        verified = pool_rendezvous.load_verified_manifest(pool_root, expected_spec=inputs["spec"],
            context=context, rendezvous_parent=rendezvous_parent)
        merge = deterministic_pool_merge.merge_verified_manifest(
            verified, pool_root=pool_root, run_id=run_id)
        coverage = shard_coverage(inputs, merge)
        atomic_json(attempt / COVERAGE, coverage)
        if coverage["unreviewed_claim_ids"]:
            # The stage contract needs one decision per claim (claim_review_lifecycle), so a failed
            # shard cannot be published as a partial stage. Its claims are recorded here as
            # unreviewed; a rerun re-asks only that shard (the persona result cache answers the rest).
            failed = [row["group_id"] for row in coverage["shards"] if row["unreviewed_claim_ids"]]
            raise Blocked(f"claim reviewer pool: {len(coverage['unreviewed_claim_ids'])} of "
                          f"{coverage['claim_count']} claims unreviewed (reviewer shard(s) "
                          f"{', '.join(failed)} did not return decisions; see {COVERAGE})")
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
            artifact_paths=[RESULT, "permission.json", "lineage.json", "pool-receipt.json", COVERAGE,
                            "status.json"],
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


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
