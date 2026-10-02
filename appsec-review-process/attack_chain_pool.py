#!/usr/bin/env python3
"""Lane-14 persona pools: one ``attack-chain-composer`` cell per cluster, one
``attack-chain-refuter`` cell per refutation batch (ADR-0016 decisions 5, 6, 8, 10).

Modelled on ``hypothesis_discovery`` / ``claim_reviewer_pool``: the pool is a ``pool_specification``
expanded and dispatched on the persona pool, awaited with ``pool_rendezvous`` and merged with
``deterministic_pool_merge``. Each cell reads a hash-pinned request document as readable input 0
(the cluster workspace or the refutation batch), then the supporting-evidence menu and the files it
pins. The persona writes judgment only; ``attack_chain_derive`` / ``attack_chain_refute`` run
inside the invoker's bounded repair loop and publish the strict candidates document.

After the pool, :func:`collect_composition` and :func:`collect_refutation` (pure) read the merged
candidates back into chain records and outcomes and turn every missing cell, conflict or
no-chain answer into a gap. A failed cell never fails the job.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import attack_chain_derive as compose
import attack_chain_refute as refute
import claude_cli_invoker as cli
import container_execution
import deterministic_pool_merge
import model_version_registry as model_versions
import persona_dispatch
import persona_invocation
import persona_prompt_assembly
import pool_launcher
import pool_rendezvous
import pool_specification
import resource_pools
import review_cli
import supporting_evidence_menu as evidence_menu
from execution_state import Blocked, ROOT, atomic_bytes, digest, file_hash
from schema_validate import SchemaStore
import registry_paths

COMPOSER_TEMPLATE = "attack-chain-composition-cell"
REFUTER_TEMPLATE = "attack-chain-refutation-cell"
LANE = "14-attack-chain"
COMPOSER_RULES = (
    "Every link cites exactly one workspace claim_id or fact_ref; a claim or fact appears once per chain.",
    "Stages in order (skip, never reorder): entry, execution, privilege_gain, persistence | lateral_movement, "
    "impact. One entry first, one impact last.",
    "Each hop i->i+1 names the fact_ref that joins the two links; without one it is synthetic.",
    "Describe how the reviewed weaknesses combine. No exploit code, commands or payloads; no severity.",
    "Write only your judgment. Chain ids, link states, edge bases, citations and chain state are derived.",
)
REFUTER_RULES = (
    "Give one outcome per chain of the batch: broken, narrowed, holds or cannot_assess.",
    "Try the weakest link first (each chain names it), then any other link or edge you can break.",
    "A tainted-data chain is broken only by a cited sanitisation, validation or block at a specific hop; "
    "'the sink looks safe' is not a refutation.",
    "broken and narrowed name the target link or edge, the mechanism and at least one citation: a citation id or "
    "fact ref of that chain, or supporting-evidence:<pinned path>[#locator].",
    "You decide the chain only; you cannot change a claim's review state. No code, commands or payloads; no "
    "severity and no wording that calls a chain, exploit or vulnerability verified or confirmed.",
)


def code_hashes() -> dict[str, str]:
    """Implementation files both lane-14 jobs depend on (the workers add their own module)."""
    paths = ["attack_chain_seeds.py", "attack_chain_derive.py", "attack_chain_refute.py", "attack_chain_pool.py",
             "attack_reference.py", "mitre_feed.py",
             "claim_ledger.py", "persona_invocation.py", "deterministic_pool_merge.py", "pool_launcher.py",
             "pool_rendezvous.py", "pool_specification.py", "supporting_evidence_menu.py",
             "personas/personas/attack-chain-composer/persona.json", "personas/personas/attack-chain-refuter/persona.json",
             "personas/roles/chain-composer/role.json", "personas/roles/chain-refuter/role.json",
             "personas/roles/attack-chain-coordinator/role.json",
             registry_paths.rel(registry_paths.DOMAINS, "attack-chain-lifecycle"), registry_paths.rel(registry_paths.TOOLING_PROFILES, "claim-review-static"),
             registry_paths.contract_rel("attack-chain-candidates"),
             registry_paths.template_rel(COMPOSER_TEMPLATE), registry_paths.template_rel(REFUTER_TEMPLATE),
             f"{LANE}/task-{COMPOSER_TEMPLATE}.md", f"{LANE}/task-{REFUTER_TEMPLATE}.md"]
    paths += [path for template in (COMPOSER_TEMPLATE, REFUTER_TEMPLATE)
              for path in persona_prompt_assembly.prompt_source_paths(template)]
    values = {path: file_hash(ROOT / path) for path in paths}
    for name in ("attack-chain-seeds.schema.json", "attack-chain-workspace.schema.json",
                 compose.PERSONA_SCHEMA, compose.RECORD_SCHEMA, compose.CANDIDATES_SCHEMA,
                 refute.PERSONA_SCHEMA, refute.LEDGER_SCHEMA):
        values["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return values


def actor(package: Any) -> dict[str, Any]:
    request = package.request
    return {"job_id": str(request.get("job_id") or ""), "attempt_id": str(request.get("attempt_id") or ""),
            "persona_id": str((request.get("persona") or {}).get("persona_id") or ""),
            "request_sha256": getattr(package, "request_sha256", None)}


def _menu_refs(inputs: tuple) -> dict[str, str]:
    return {f"{item.root}:{item.path}": item.sha256 for item in inputs if item.root in refute.MENU_ROOTS}


def _composer_fill(package: Any):
    first = package.inputs[0]
    if first.root != compose.WORKSPACE_ROOT_ID:
        raise cli.InvokerOutputError("chain workspace must be readable input 0")
    workspace = compose.read_workspace(first.data)

    def fill(envelope: dict[str, Any], result_field: str) -> list[str]:
        document, notes = compose.derive(workspace, envelope.get(result_field), composer=actor(package))
        envelope[result_field] = compose.candidates(document, first.sha256)
        return notes

    return fill


def _refuter_fill(package: Any):
    first = package.inputs[0]
    if first.root != refute.BATCH_ROOT_ID:
        raise cli.InvokerOutputError("refutation batch must be readable input 0")
    batch = refute.read_batch(first.data)

    def fill(envelope: dict[str, Any], result_field: str) -> list[str]:
        document, notes = refute.derive(batch, envelope.get(result_field), refuter=actor(package),
                                        menu=_menu_refs(package.inputs))
        envelope[result_field] = refute.candidates(document, first.sha256)
        return notes

    return fill


cli._CLAIM_BUILDERS.setdefault(compose.CANDIDATES_SCHEMA, compose.chain_claims)


def _runtime(kind: str, document: dict[str, Any]) -> str:
    if kind == "compose":
        block = {"job": "14-attack-chain-composition", "cluster_id": document["cluster_id"],
                 "bounds": document["bounds"], "readable_roots": {
                     compose.WORKSPACE_ROOT_ID: "your cluster workspace (pinned input 0): claims, facts, adjacency",
                     evidence_menu.MENU_ROOT_ID: "the supporting-evidence menu",
                     evidence_menu.ROOT_ID: "accepted evidence the menu pins (CPG records, IR facts, threat model)"},
                 "reply_shape": ("the candidates envelope value is {\"chains\": [...], \"no_chain_reason\": ...} and "
                                 f"validates {compose.PERSONA_SCHEMA}; chains [] with a reason is a valid answer"),
                 "rules": list(COMPOSER_RULES)}
    else:
        block = {"job": "14-attack-chain-refutation", "batch_id": document["batch_id"],
                 "chains": [{"chain_id": chain["chain_id"], "weakest": chain["weakest"]} for chain in document["chains"]],
                 "readable_roots": {
                     refute.BATCH_ROOT_ID: "your refutation batch (pinned input 0): chains, their facts and claims",
                     evidence_menu.MENU_ROOT_ID: "the supporting-evidence menu",
                     evidence_menu.ROOT_ID: "accepted evidence the menu pins"},
                 "reply_shape": ("the candidates envelope value is {\"chains\": [...]} and validates "
                                 f"{refute.PERSONA_SCHEMA}; one outcome per chain"),
                 "rules": list(REFUTER_RULES)}
    return "\n\n## Trusted attack-chain runtime (not target data)\n\n" + json.dumps(block, indent=2, sort_keys=True)


class ChainInvoker:
    """Lane adapter over the strict Claude CLI invoker for both lane-14 cells."""
    invoker_id = "claude-cli"

    def __init__(self, kind: str, *, effort: str, budget_usd: float | None = None,
                 timeout_seconds: int = cli.DEFAULT_TIMEOUT_SECONDS, dispatch_fn=None) -> None:
        if kind not in {"compose", "refute"}:
            raise ValueError(kind)
        self.kind, self.effort, self.budget_usd, self.timeout_seconds = kind, effort, budget_usd, timeout_seconds
        self.dispatch_fn = dispatch_fn or review_cli._dispatch_streaming

    def invoke(self, package: Any, *, output_root: Path, cancel: Any) -> None:
        document = (compose.read_workspace(package.inputs[0].data) if self.kind == "compose"
                    else refute.read_batch(package.inputs[0].data))
        instructions = _runtime(self.kind, document)

        def dispatch(argv: list[str], prompt: str, timeout: int, transcript: Path) -> dict[str, Any]:
            return self.dispatch_fn(argv, prompt + instructions, timeout, transcript)

        fill = _composer_fill(package) if self.kind == "compose" else _refuter_fill(package)
        schema = compose.PERSONA_SCHEMA if self.kind == "compose" else refute.PERSONA_SCHEMA
        cli.ClaudeCliInvoker(effort=self.effort, budget_usd=self.budget_usd, timeout_seconds=self.timeout_seconds,
                             dispatch_fn=dispatch, fill_result=fill, persona_schema=schema).invoke(
                                 package, output_root=output_root, cancel=cancel)


def cell_request(run_id: str, template_id: str, readable: list[dict[str, Any]], store: SchemaStore) -> dict[str, Any]:
    template = persona_prompt_assembly.load_job_template(template_id, store)
    composition = persona_dispatch._composition_block(template_id, template, store)
    records = persona_invocation.load_composition(persona_invocation.REGISTRY_DIR, composition, store)
    ceiling = persona_invocation.claim_ceiling(records["role"], records["tooling_profile"])
    if "candidate_only" not in ceiling["allowed"]:
        raise Blocked(f"{template_id}: registry composition forbids candidate_only chain claims")
    resolved = review_cli.resolve_model(template_id, template["budget_default"])
    return {"invocation_role": "produce", "invoker_id": "claude-cli",
            "outer_prompt": persona_prompt_assembly.assemble_outer_prompt(template_id, store=store),
            "persona": composition, "model": model_versions.model_identity_for(run_id, resolved["model"]),
            "tools": [], "budget": dict(persona_dispatch.PERSONA_BUDGETS[template["budget_default"]]),
            "readable_inputs": readable, "allowed_claim_classes": list(ceiling["allowed"]),
            "prohibited_claim_classes": list(ceiling["prohibited"]), "producers": []}


def _input_row(root: str, path: str, data: bytes) -> dict[str, Any]:
    return {"root": root, "path": path, "sha256": persona_invocation._bytes_sha(data), "bytes": len(data),
            "role": "evidence", "producer_request_sha256": None}


def pool_spec(run_id: str, job_id: str, kind: str, documents: list[dict[str, Any]], *, menu: dict[str, Any],
              permission: dict[str, Any], binding: Any, rendezvous_timeout_seconds: int,
              store: SchemaStore | None = None) -> dict[str, Any]:
    """The pool specification: one group per workspace (compose) or batch (refute)."""
    store = store or SchemaStore()
    template = COMPOSER_TEMPLATE if kind == "compose" else REFUTER_TEMPLATE
    root_id = compose.WORKSPACE_ROOT_ID if kind == "compose" else refute.BATCH_ROOT_ID
    key = "cluster_id" if kind == "compose" else "batch_id"
    groups = []
    for document in documents:
        data = compose.workspace_bytes(document)
        readable = [_input_row(root_id, document[key] + ".json", data)] + evidence_menu.readable_inputs(menu)
        groups.append({"group_id": document[key], "worker_kind": pool_specification.PERSONA, "count": 1,
                       "memory_heavy": False, "permission": permission,
                       "persona_request": cell_request(run_id, template, readable, store), "tool_request": None})
    count = len(groups)
    if not groups:   # an empty pool still states one (count 0) group so the expansion is well formed
        placeholder = ({"schema": compose.WORKSPACE_SCHEMA_ID, "cluster_id": "cluster-" + "0" * 16}
                       if kind == "compose" else {"schema": refute.BATCH_SCHEMA_ID, "batch_id": "batch-" + "0" * 16})
        data = compose.workspace_bytes(placeholder)
        readable = [_input_row(root_id, placeholder[key] + ".json", data)]
        groups.append({"group_id": placeholder[key], "worker_kind": pool_specification.PERSONA, "count": 0,
                       "memory_heavy": False, "permission": permission,
                       "persona_request": cell_request(run_id, template, readable, store), "tool_request": None})
    budget = groups[0]["persona_request"]["budget"]
    return {"schema": pool_specification.SPEC_ID, "pool_id": f"attack-chain-{kind}", "lane": LANE,
            "run_id": run_id, "job_id": job_id,
            "attempt_id": f"chain-{kind}-" + digest({"binding": binding, "documents": documents})[:24],
            "budget_class": "standard",
            "pool_budget": {"max_instances": count, "max_persona_input_units": count * budget["input_unit_limit"],
                            "max_persona_output_units": count * budget["output_unit_limit"],
                            "max_total_timeout_seconds": max(1, count) * budget["timeout_seconds"]},
            "resource_pool_policy": {"allowed_pools": [resource_pools.PERSONA_LLM]}, "wait_all": True,
            "rendezvous_timeout_seconds": rendezvous_timeout_seconds,
            "empty_pool_reason": None if count else "no_applicable_work",
            "worker_groups": sorted(groups, key=lambda group: group["group_id"])}


def context(run_id: str, kind: str, documents: list[dict[str, Any]], *, menu: dict[str, Any], spec: dict[str, Any],
            attempt: Path, source_snapshot_sha256: str) -> pool_specification.PoolContext:
    """Write the request documents and the menu under the attempt and name the readable roots."""
    pool_parent, rendezvous = attempt / "pools", attempt / "rendezvous"
    pool_parent.mkdir(); rendezvous.mkdir()
    root_id = compose.WORKSPACE_ROOT_ID if kind == "compose" else refute.BATCH_ROOT_ID
    key = "cluster_id" if kind == "compose" else "batch_id"
    requests = attempt / root_id
    requests.mkdir()
    for document in documents:
        atomic_bytes(requests / (document[key] + ".json"), compose.workspace_bytes(document))
    menu_root = evidence_menu.write(attempt / "evidence-menu", menu)
    roots = {root_id: requests, **evidence_menu.readable_roots(run_id, menu, menu_root)}
    models = tuple({json.dumps(group["persona_request"]["model"], sort_keys=True): group["persona_request"]["model"]
                    for group in spec["worker_groups"]}.values())
    return pool_specification.PoolContext(pool_parent=pool_parent, registry_dir=persona_invocation.REGISTRY_DIR,
        prompt_root=ROOT, readable_roots=roots, allowed_models=models, invoker_id="claude-cli",
        images_dir=container_execution.IMAGES_DIR, host_flavor="windows" if os.name == "nt" else "posix",
        docker_host=None, docker_executable=None, container_user=None, mount_roots={},
        source_snapshot_sha256=source_snapshot_sha256, registry_ceiling=None)


def dispatch(run_id: str, spec: dict[str, Any], pool_context: pool_specification.PoolContext, *, invoker: Any,
             clock, max_parallel: int, wait_limit_seconds: int) -> tuple[dict[str, Any], Any]:
    """Launch, await and merge one pool; returns (deterministic merge, launch record)."""
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

def _assertions(merge: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    rows = []
    for candidate in merge.get("candidates", []):
        try:
            rows.append((candidate, json.loads(candidate["assertion"])))
        except (ValueError, KeyError, TypeError):
            continue
    return rows


def collect_composition(seeds: dict[str, Any], merge: dict[str, Any]
                        ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """(composed chains, gaps, coverage) from the composer pool merge. Every selected cluster ends
    with chains, a no-chain reason, or a gap."""
    clusters = {cluster["cluster_id"]: cluster for cluster in seeds["clusters"]}
    chains: dict[str, dict[str, Any]] = {}
    answered, no_chain, gaps = set(), {}, []
    for candidate, value in _assertions(merge):
        cluster_id = candidate["subject_id"]
        if cluster_id not in clusters:
            continue
        answered.add(cluster_id)
        if "no_chain_reason" in value and "chain_id" not in value:
            no_chain[cluster_id] = value["no_chain_reason"]
        elif value.get("chain_id") == candidate["candidate_id"] and value.get("cluster_id") == cluster_id:
            chains.setdefault(value["chain_id"], value)
    for conflict in merge.get("conflicts", []):
        gaps.append({"scope": "chain", "id": conflict["candidate_id"], "reason": "merge-conflict",
                     "detail": f"chain candidate differs between composer workers {conflict['worker_ids']}"})
    for cluster_id in sorted(set(clusters) - answered):
        gaps.append({"scope": "cluster", "id": cluster_id, "reason": "composer-failed",
                     "detail": "composer cell failed, timed out or exhausted repair; no chain for this cluster"})
    for cluster_id, reason in sorted(no_chain.items()):
        gaps.append({"scope": "cluster", "id": cluster_id, "reason": "composer-no-chain",
                     "detail": (reason or "no chain")[:500]})
    for chain in chains.values():
        for edge in chain["edges"]:
            if edge["basis"] == "synthetic":
                gaps.append({"scope": "chain", "id": chain["chain_id"], "reason": "synthetic-edge",
                             "detail": f"edge {edge['from']}->{edge['to']} has no resolvable fact; route for "
                                       f"synthetic-hypothesis-resynthesis"})
    coverage = {"clusters_selected": len(clusters), "clusters_answered": len(answered),
                "clusters_no_chain": len(no_chain), "clusters_failed": len(set(clusters) - answered),
                "chains_composed": len(chains)}
    return [chains[key] for key in sorted(chains)], gaps, coverage


def collect_refutation(batches: list[dict[str, Any]], merge: dict[str, Any]
                       ) -> tuple[dict[str, dict[str, Any]], dict[str, str], list[dict[str, Any]]]:
    """(outcomes by chain id, not-run reasons, gaps) from the refuter pool merge."""
    sent = {chain["chain_id"]: batch["batch_id"] for batch in batches for chain in batch["chains"]}
    outcomes: dict[str, dict[str, Any]] = {}
    for candidate, value in _assertions(merge):
        chain_id = candidate["subject_id"]
        if chain_id in sent and value.get("chain_id") == chain_id:
            outcomes.setdefault(chain_id, value)
    reasons, gaps = {}, []
    for chain_id in sorted(set(sent) - set(outcomes)):
        reasons[chain_id] = "refuter cell failed; state capped"
        gaps.append({"scope": "chain", "id": chain_id, "reason": "refuter-failed",
                     "detail": f"refuter cell for {sent[chain_id]} failed, timed out or exhausted repair; "
                               f"refutation not run"})
    return outcomes, reasons, gaps
