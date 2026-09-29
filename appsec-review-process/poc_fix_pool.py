#!/usr/bin/env python3
"""Lane-12b persona pool: one ``poc-fix-author`` cell per eligible finding (brief F).

Modelled on the lane-14 pools (:mod:`attack_chain_pool`): a ``pool_specification`` expanded and
dispatched on the persona pool, awaited with ``pool_rendezvous`` and merged with
``deterministic_pool_merge``. Each cell reads its hash-pinned request workspace as readable input 0
and nothing else. The persona writes judgment only; :mod:`poc_fix_derive` runs inside the invoker's
bounded repair loop and publishes the strict candidates document.

After the pool, :func:`collect` (pure) reads the merged candidates back into one record per request,
re-verifies each (:func:`poc_fix_derive.recheck`), and turns every missing cell, conflict, mismatch
or denylist rejection into a gap. A failed cell never fails the job.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import claude_cli_invoker as cli
import container_execution
import deterministic_pool_merge
import model_version_registry as model_versions
import persona_dispatch
import persona_invocation
import persona_prompt_assembly
import poc_fix_derive as derive
import pool_launcher
import pool_rendezvous
import pool_specification
import resource_pools
import review_cli
from execution_state import Blocked, ROOT, atomic_bytes, digest, file_hash
from schema_validate import SchemaStore

TEMPLATE = "poc-and-fix-cell"
LANE = "12b-poc-and-fix"
RULES = (
    "Static text only: the PoC is never executed. It only triggers the crash or overflow, or shows the faulty "
    "control flow.",
    "Nothing hostile: no shellcode, payload bytes, exec or process spawn, sockets, URLs, file writes outside a "
    "temp name, deletion, persistence, credentials, encoded or obfuscated text, eval or pipes into interpreters.",
    "Cite only workspace citable files inside their line windows; at least one range covers a finding location.",
    "The fix is a unified diff of citable files only; it is a proposal and is not applied.",
    "Write only your judgment. Ids, hashes, labels, statuses and the denylist result are derived.",
)


def code_hashes() -> dict[str, str]:
    """Implementation files the lane-12b job depends on (the worker adds its own module)."""
    paths = ["poc_fix_derive.py", "poc_fix_denylist.py", "poc_fix_select.py", "poc_fix_pool.py",
             "finding_enrichment.py", "reachability.py", "entry_exports.py", "code_snippets.py", "cwe_catalog.py",
             "persona_invocation.py", "deterministic_pool_merge.py", "pool_launcher.py", "pool_rendezvous.py",
             "pool_specification.py", "personas/personas/poc-fix-author/persona.json", "personas/roles/poc-fix-author/role.json",
             "personas/roles/poc-fix-coordinator/role.json", "registry/domains/poc-and-fix.json",
             "registry/tooling-profiles/claim-review-static.json", "registry/output-contracts/poc-fix-candidates.json",
             f"registry/job-templates/{TEMPLATE}.json", f"{LANE}/task-{TEMPLATE}.md"]
    values = {path: file_hash(ROOT / path) for path in paths}
    for name in (derive.PERSONA_SCHEMA, derive.RECORD_SCHEMA, derive.CANDIDATES_SCHEMA, derive.WORKSPACE_SCHEMA):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def actor(package: Any) -> dict[str, Any]:
    request = package.request
    return {"job_id": str(request.get("job_id") or ""), "attempt_id": str(request.get("attempt_id") or ""),
            "persona_id": str((request.get("persona") or {}).get("persona_id") or ""),
            "request_sha256": getattr(package, "request_sha256", None)}


def _fill(package: Any):
    first = package.inputs[0]
    if first.root != derive.WORKSPACE_ROOT_ID:
        raise cli.InvokerOutputError("poc-fix workspace must be readable input 0")
    workspace = derive.read_workspace(first.data)

    def fill(envelope: dict[str, Any], result_field: str) -> list[str]:
        record, notes = derive.derive(workspace, envelope.get(result_field), author=actor(package))
        envelope[result_field] = derive.candidates(record, first.sha256)
        return notes

    return fill


cli._CLAIM_BUILDERS.setdefault(derive.CANDIDATES_SCHEMA, derive.poc_fix_claims)


def _runtime(workspace: dict[str, Any]) -> str:
    block = {"job": LANE, "request_id": workspace["request_id"], "claim_id": workspace["claim_id"],
             "bounds": workspace["bounds"],
             "citable": [{"path": row["path"], "windows": row["windows"]} for row in workspace["citable"]],
             "readable_roots": {derive.WORKSPACE_ROOT_ID: "your request workspace (pinned input 0)"},
             "reply_shape": ("the candidates envelope value is {\"poc\": {...} | null, \"no_poc_reason\": ..., "
                             "\"explanation\": ..., \"cited_lines\": [...], \"fix\": {\"diff\", \"rationale\"}} and "
                             f"validates {derive.PERSONA_SCHEMA}"),
             "rules": list(RULES)}
    return "\n\n## Trusted PoC-and-fix runtime (not target data)\n\n" + json.dumps(block, indent=2, sort_keys=True)


class PocFixInvoker:
    """Lane adapter over the strict Claude CLI invoker for the poc-and-fix cell."""
    invoker_id = "claude-cli"

    def __init__(self, *, effort: str, budget_usd: float | None = None,
                 timeout_seconds: int = cli.DEFAULT_TIMEOUT_SECONDS, dispatch_fn=None) -> None:
        self.effort, self.budget_usd, self.timeout_seconds = effort, budget_usd, timeout_seconds
        self.dispatch_fn = dispatch_fn or review_cli._dispatch_streaming

    def invoke(self, package: Any, *, output_root: Path, cancel: Any) -> None:
        instructions = _runtime(derive.read_workspace(package.inputs[0].data))

        def dispatch(argv: list[str], prompt: str, timeout: int, transcript: Path) -> dict[str, Any]:
            return self.dispatch_fn(argv, prompt + instructions, timeout, transcript)

        cli.ClaudeCliInvoker(effort=self.effort, budget_usd=self.budget_usd, timeout_seconds=self.timeout_seconds,
                             dispatch_fn=dispatch, fill_result=_fill(package),
                             persona_schema=derive.PERSONA_SCHEMA).invoke(package, output_root=output_root,
                                                                          cancel=cancel)


def cell_request(run_id: str, readable: list[dict[str, Any]], store: SchemaStore) -> dict[str, Any]:
    template = persona_prompt_assembly.load_job_template(TEMPLATE, store)
    composition = persona_dispatch._composition_block(TEMPLATE, template, store)
    records = persona_invocation.load_composition(persona_invocation.REGISTRY_DIR, composition, store)
    ceiling = persona_invocation.claim_ceiling(records["role"], records["tooling_profile"])
    if "candidate_only" not in ceiling["allowed"]:
        raise Blocked(f"{TEMPLATE}: registry composition forbids candidate_only claims")
    resolved = review_cli.resolve_model(TEMPLATE, template["budget_default"])
    return {"invocation_role": "produce", "invoker_id": "claude-cli",
            "outer_prompt": persona_prompt_assembly.assemble_outer_prompt(TEMPLATE, store=store),
            "persona": composition, "model": model_versions.model_identity_for(run_id, resolved["model"]),
            "tools": [], "budget": dict(persona_dispatch.PERSONA_BUDGETS[template["budget_default"]]),
            "readable_inputs": readable, "allowed_claim_classes": list(ceiling["allowed"]),
            "prohibited_claim_classes": list(ceiling["prohibited"]), "producers": []}


def _input_row(path: str, data: bytes) -> dict[str, Any]:
    return {"root": derive.WORKSPACE_ROOT_ID, "path": path, "sha256": persona_invocation._bytes_sha(data),
            "bytes": len(data), "role": "evidence", "producer_request_sha256": None}


def pool_spec(run_id: str, job_id: str, requests: list[dict[str, Any]], *, permission: dict[str, Any],
              binding: Any, rendezvous_timeout_seconds: int, store: SchemaStore | None = None) -> dict[str, Any]:
    """The pool specification: one group per request workspace."""
    store = store or SchemaStore()
    groups = []
    for document in requests:
        data = derive.workspace_bytes(document)
        groups.append({"group_id": document["request_id"], "worker_kind": pool_specification.PERSONA, "count": 1,
                       "memory_heavy": False, "permission": permission,
                       "persona_request": cell_request(run_id, [_input_row(document["request_id"] + ".json", data)],
                                                       store),
                       "tool_request": None})
    count = len(groups)
    if not groups:   # an empty pool still states one (count 0) group so the expansion is well formed
        placeholder = {"schema": derive.WORKSPACE_SCHEMA_ID, "request_id": "pocreq-" + "0" * 16}
        data = derive.workspace_bytes(placeholder)
        groups.append({"group_id": placeholder["request_id"], "worker_kind": pool_specification.PERSONA, "count": 0,
                       "memory_heavy": False, "permission": permission,
                       "persona_request": cell_request(run_id, [_input_row(placeholder["request_id"] + ".json", data)],
                                                       store),
                       "tool_request": None})
    budget = groups[0]["persona_request"]["budget"]
    return {"schema": pool_specification.SPEC_ID, "pool_id": "poc-and-fix", "lane": LANE,
            "run_id": run_id, "job_id": job_id,
            "attempt_id": "poc-fix-" + digest({"binding": binding, "requests": requests})[:24],
            "budget_class": "standard",
            "pool_budget": {"max_instances": count, "max_persona_input_units": count * budget["input_unit_limit"],
                            "max_persona_output_units": count * budget["output_unit_limit"],
                            "max_total_timeout_seconds": max(1, count) * budget["timeout_seconds"]},
            "resource_pool_policy": {"allowed_pools": [resource_pools.PERSONA_LLM]}, "wait_all": True,
            "rendezvous_timeout_seconds": rendezvous_timeout_seconds,
            "empty_pool_reason": None if count else "no_applicable_work",
            "worker_groups": sorted(groups, key=lambda group: group["group_id"])}


def context(requests: list[dict[str, Any]], *, spec: dict[str, Any], attempt: Path,
            source_snapshot_sha256: str) -> pool_specification.PoolContext:
    """Write the request workspaces under the attempt and name the readable root."""
    pool_parent, rendezvous = attempt / "pools", attempt / "rendezvous"
    pool_parent.mkdir(); rendezvous.mkdir()
    folder = attempt / derive.WORKSPACE_ROOT_ID
    folder.mkdir()
    for document in requests:
        atomic_bytes(folder / (document["request_id"] + ".json"), derive.workspace_bytes(document))
    models = tuple({json.dumps(group["persona_request"]["model"], sort_keys=True): group["persona_request"]["model"]
                    for group in spec["worker_groups"]}.values())
    return pool_specification.PoolContext(pool_parent=pool_parent, registry_dir=persona_invocation.REGISTRY_DIR,
        prompt_root=ROOT, readable_roots={derive.WORKSPACE_ROOT_ID: folder}, allowed_models=models,
        invoker_id="claude-cli", images_dir=container_execution.IMAGES_DIR,
        host_flavor="windows" if os.name == "nt" else "posix", docker_host=None, docker_executable=None,
        container_user=None, mount_roots={}, source_snapshot_sha256=source_snapshot_sha256, registry_ceiling=None)


def dispatch(run_id: str, spec: dict[str, Any], pool_context: pool_specification.PoolContext, *, invoker: Any,
             clock, max_parallel: int, wait_limit_seconds: int) -> tuple[dict[str, Any], Any]:
    """Launch, await and merge the pool; returns (deterministic merge, launch record)."""
    rendezvous_parent = pool_context.pool_parent.parent / "rendezvous"
    runtime = pool_rendezvous.RendezvousRuntime(rendezvous_parent=rendezvous_parent, invoker=invoker, clock=clock,
        stop_grace_seconds=5, cancel=pool_rendezvous.PoolCancel(), max_parallel=max_parallel,
        wait_limit_seconds=wait_limit_seconds, drain_seconds=10)
    launched = pool_launcher.launch(spec, context=pool_context, runtime=runtime)
    pool_root = pool_context.pool_parent / launched.pool_directory
    verified = pool_rendezvous.load_verified_manifest(pool_root, expected_spec=spec, context=pool_context,
                                                      rendezvous_parent=rendezvous_parent)
    return deterministic_pool_merge.merge_verified_manifest(verified, pool_root=pool_root, run_id=run_id), launched


# --- post-pool bookkeeping (pure) -----------------------------------------------------------------

def collect(requests: list[dict[str, Any]], merge: dict[str, Any]
            ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """(records, gaps, coverage) from the pool merge: at most one re-verified record per request."""
    by_request = {document["request_id"]: document for document in requests}
    records: dict[str, dict[str, Any]] = {}
    gaps: list[dict[str, Any]] = []
    for candidate in merge.get("candidates", []):
        request_id = candidate.get("subject_id")
        if request_id not in by_request or request_id in records:
            continue
        try:
            record = json.loads(candidate["assertion"])
        except (ValueError, KeyError, TypeError):
            gaps.append({"scope": "request", "id": request_id, "reason": "record-unreadable",
                         "detail": "merged candidate assertion is not a JSON record; not published"})
            continue
        problems = derive.recheck(record, by_request[request_id]) if isinstance(record, dict) else ["not an object"]
        if problems or record.get("poc_fix_id") != candidate.get("candidate_id"):
            gaps.append({"scope": "request", "id": request_id, "reason": "record-mismatch",
                         "detail": ("re-verification failed: " + "; ".join(problems or ["candidate id differs"]))[:600]})
            continue
        records[request_id] = record
        for part in derive.rejected_parts(record):
            gaps.append({"scope": "finding", "id": record["claim_id"], "reason": "denylist-rejected", "detail": part})
        if record["poc"]["status"] == "NOT_PROVIDED":
            gaps.append({"scope": "finding", "id": record["claim_id"], "reason": "no-poc",
                         "detail": f"author gave no PoC: {record['poc']['reason']}"[:600]})
    for conflict in merge.get("conflicts", []):
        gaps.append({"scope": "request", "id": str(conflict.get("candidate_id")), "reason": "merge-conflict",
                     "detail": f"candidate differs between workers {conflict.get('worker_ids')}"[:600]})
    for request_id in sorted(set(by_request) - set(records)):
        if not any(gap["id"] == request_id for gap in gaps):
            gaps.append({"scope": "request", "id": request_id, "reason": "author-failed",
                         "detail": f"poc-and-fix cell for {by_request[request_id]['claim_id']} failed, timed out or "
                                   "exhausted repair; no PoC or fix for this finding"})
    coverage = {"requests": len(by_request), "records": len(records),
                "poc_proposed": sum(1 for r in records.values() if r["poc"]["status"] == "PROPOSED_UNVALIDATED"),
                "poc_rejected": sum(1 for r in records.values() if r["poc"]["status"] == "REJECTED_DENYLIST"),
                "fix_proposed": sum(1 for r in records.values() if r["fix"]["status"] == "PATCH_PROPOSED_UNVALIDATED")}
    return [records[key] for key in sorted(records, key=lambda k: by_request[k]["claim_id"])], gaps, coverage
