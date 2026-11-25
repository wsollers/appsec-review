"""Static verification of already cited finding paths and replay of historical chain decisions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from appsec_review.config.inference_review import JOB_ID
from appsec_review.jobs.completion_contracts import ATTACK_CHAIN_MANIFEST_SCHEMA
from appsec_review.review import attack_chains as policy
from appsec_review.review.capability import CellCapability
from appsec_review.review.cells import RECEIPT_SCHEMA, CellSpec
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.ledger import LedgerWriter, Projection
from appsec_review.review.models import (
    ClaimState, GapClass, IntegrityError, Lane, Role,
    make_gap,
)
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from . import finding_paths
from .teams import ReviewContext, _admission_summary, _Cell

TASKS = {"composer": ("chain_composer", Role.ATTACK_CHAIN_ANALYST, "chain-composer-result"),
         "refuter": ("chain_refuter", Role.BLUE_TEAM_REFUTER, "chain-challenge-result"),
         "weakest_link_verifier": ("chain_weakest_link_verifier", Role.INDEPENDENT_VERIFIER, "chain-challenge-result")}


def _write(ctx: ReviewContext, path: Path, value: Mapping[str, Any]) -> policy.Artifact:
    if path.exists() and path.read_bytes() != canonical_json(value):
        raise IntegrityError("an immutable chain artifact already exists with different bytes")
    atomic_json(path, value)
    return policy.Artifact(path.resolve().relative_to(ctx.run_root.resolve()).as_posix(), file_sha256(path))


def read_artifact(run_root: Path, reference: Mapping[str, Any]) -> dict[str, Any]:
    artifact = policy.Artifact(**reference)
    path = (run_root / artifact.path).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or file_sha256(path) != artifact.sha256:
        raise IntegrityError("chain artifact is unavailable, outside the run, or changed")
    return json.loads(path.read_text(encoding="utf-8"))


def _cell(ctx: ReviewContext, kind: str, inputs: Mapping[str, Any], entities: Sequence[str], identity: str) -> _Cell:
    task, role, schema = TASKS[kind]
    profile, bounds = ctx.profile(role), ctx.settings.attack_chains
    package_sha = sha256_hex(inputs)
    candidates, tools, population = ctx.review_grant(role, ctx.index_names)
    capability = CellCapability.issue(
        run_id=ctx.run_id, manifest_sha256=ctx.core.manifest_sha256, package_id=identity,
        package_sha256=package_sha, role=role, round=0,
        tools=tools,
        indexes=ctx.index_names, entities=entities,
        read_view_sha256=(getattr(ctx.core, "read_view_sha256", None)
                          if kind in {"refuter", "weakest_link_verifier"} else None),
        max_queries=min(profile.max_queries, bounds.max_queries),
        max_turns=min(profile.max_turns, bounds.max_turns), page_size=min(ctx.max_page_size, 100),
        max_depth=1, max_result_bytes=bounds.max_result_bytes)
    guidance = ctx.bundle(role=role, persona="generalist", stack="generic", task=task,
                          lane=Lane.HUNT, capability=capability, population=population)
    spec = CellSpec(
        manifest_sha256=ctx.core.manifest_sha256, lane=Lane.HUNT, package_id=identity,
        package_sha256=package_sha, claim_id=None, role=role, persona="generalist", stack_profile="generic",
        strategy=None, task=task, task_input=inputs, round=0, round_delta_sha256=None,
        evidence_set=tuple(sorted(set(entities))), guidance_bundle_sha256=guidance["bundle"]["sha256"],
        guidance_text=guidance["text"], provider=profile.provider, model=profile.model, reasoning=profile.reasoning,
        max_input_tokens=profile.max_input_tokens,
        max_output_tokens=profile.max_output_tokens,
        timeout_seconds=profile.timeout_seconds, output_schema=f"appsec-review/{schema}/1",
        validator_version=policy.POLICY,
        admission=_admission_summary(candidates, capability, population, guidance["bundle"]))
    return _Cell(spec, capability, kind)


def effective_max_links(bounds: Any) -> int:
    return bounds.max_links


def compose(ctx: ReviewContext, projection: Projection, adjudications: Sequence[Mapping[str, Any]], *,
            extra_verifier_claims: set[str], seeds: Sequence[Mapping[str, Any]], out_dir: Path,
            ledger_path: Path, stream: str, component_severities=None, component_units=None) -> dict[str, Any]:
    """Stable stage ID; inspect existing citations only. Seeds and component pairs are not inputs."""
    bounds = ctx.settings.attack_chains
    paths, gaps = [], set()
    limit = min(ctx.settings.rounds.max_attack_chains, bounds.max_candidates_per_composition)
    for record in sorted(adjudications, key=lambda item: item["claim_id"]):
        if record["state"] not in {ClaimState.SUPPORTED.value, ClaimState.CONFIRMED.value}:
            continue
        cid = record["claim_id"]
        claim = projection.claims[cid].claim
        counted = set(record.get("counted_relation_ids", ()))
        pred = next((p for p in record["predicates"] if p["predicate"] == finding_paths.REACH), {})
        # Match the actual finding-package citation set (including its publication bounds).
        direct = sorted({r for p in record["predicates"] for r in p.get("supporting", ())})[:256]
        relations = projection.relations.get(cid, ())
        analyst = sorted(r.relation_id for r in relations if r.kind.value == "supports" and r.complete
                         and r.admissibility.value == "analyst_assessed")[:256]
        cited = set(direct + analyst)
        counter = set(pred.get("contradicting", ())) & counted
        candidates = [r for r in relations if r.entity_kind == "dataflow_path" and r.predicate.value == finding_paths.REACH
                      and r.provenance is None and (r.relation_id in cited and r.kind.value == "supports"
                      or finding_paths.cited_alternate(r))]
        if not candidates:
            gaps.add("reported_findings_without_cited_graph_path")
        for relation in sorted(candidates, key=lambda r: r.relation_id):
            if len(paths) >= limit:
                gaps.add("reported_finding_path_assessment_limit")
                break
            path = finding_paths.assess(ctx, record, claim, relation,
                                        counted=relation.relation_id in counted, counter_ids=counter)
            if path["status"] != "statically_supported":
                gaps.add("reported_finding_path_not_statically_supported")
            ctx.schemas.validate("finding-path", path)
            paths.append(path)
    accounting = dict(proposed=0, admitted=0, assessed=0, capped=0, rejected=0, deduplicated=0,
                      seeds_received=len(seeds), seeds_rejected=len(seeds))
    exploration = {"expanded": 0, "limit": bounds.max_expansions, "frontier": [], "frontier_truncated": False}
    return _finish(LedgerWriter(ledger_path, stream), {"finding_paths": paths, "candidates": [],
                   "gaps": sorted(gaps), "accounting": accounting, "exploration": exploration, "expected_cells": {}})


def challenge(ctx: ReviewContext, composition: Mapping[str, Any], previous: Mapping[str, Any] | None, *,
              kind: str, out_dir: Path, ledger_path: Path, stream: str) -> dict[str, Any]:
    if kind not in {"refuter", "weakest_link_verifier"} or composition["candidates"]:
        raise IntegrityError("finding path assessment does not accept composed candidates")
    writer = LedgerWriter(ledger_path, stream)
    result = {"challenges": [], "expected_cells": {}}
    if kind == "weakest_link_verifier":
        manifest = {"schema": ATTACK_CHAIN_MANIFEST_SCHEMA, "run_id": ctx.run_id, "items": [],
                    **{key: composition[key] for key in ("finding_paths", "gaps", "accounting", "exploration")}}
        ctx.schemas.validate("attack-chain-manifest", manifest)
        for gap in manifest["gaps"]:
            writer.record_gap(make_gap(GapClass.CHAIN_GAP, "attack_chains", gap))
        result["attack_chain_manifest"] = policy.document(_write(ctx, out_dir / "manifest.json", manifest))
        result["gaps"] = manifest["gaps"]
    return _finish(writer, result)


def _finish(writer: LedgerWriter, result: Mapping[str, Any]) -> dict[str, Any]:
    receipt = writer.seal()
    return {**result, "ledger_shard": {"events": receipt.event_count, "sha256": file_sha256(writer.path)}}


def verify_publication(run_root: Path, projection: Projection, reference: Mapping[str, Any], schemas,
                       run_id: str) -> dict[str, Any]:
    """Revalidate the manifest and every bound pre-publication artifact against the single ledger."""
    manifest = read_artifact(run_root, reference)
    parts = Path(reference["path"]).parts
    receipts_root = run_root / "data" / "jobs" / JOB_ID / "cells"
    if len(parts) > 5 and parts[:4] == ("data", "jobs", JOB_ID, "attempts"):
        from appsec_review.runtime.release import read_document
        from appsec_review.storage.shared import safe_path
        attempt_path = Path(*parts[:5])
        claim = read_document(safe_path(run_root, (attempt_path / "claim.json").as_posix()))
        if (claim.get("job_id"), claim.get("run_id"), claim.get("attempt_id")) != (JOB_ID, run_id, parts[4]):
            raise IntegrityError("chain manifest belongs to another attempt")
        if claim.get("recovery_boundary") == "whole_job":
            receipts_root = run_root / attempt_path / "cells"
    schemas.validate("attack-chain-manifest", manifest)
    if manifest["run_id"] != run_id or {item["chain_id"] for item in manifest["items"]} != set(projection.attack_chains):
        raise IntegrityError("attack-chain manifest does not exactly cover the current run's chain ledger")
    if len(manifest["items"]) != len(projection.attack_chains):
        raise IntegrityError("attack-chain manifest duplicates a chain")
    counts = manifest["accounting"]
    if (counts["admitted"] != len(manifest["items"]) or counts["admitted"] != counts["assessed"] + counts["capped"]
            or counts["proposed"] != counts["admitted"] + counts["rejected"] + counts["deduplicated"]
            or counts["capped"] != sum(item["disposition"] == "capped" for item in manifest["items"])):
        raise IntegrityError("attack-chain manifest candidate accounting is not exact")
    seen = set()
    for path in manifest.get("finding_paths", ()):
        cid, pin = path["claim_id"], path["citation"]
        view = projection.claims.get(cid)
        relations = {r.relation_id: r for r in projection.relations.get(cid, ())}
        relation = relations.get(pin["relation_id"])
        if (view is None or view.claim.state not in {ClaimState.CONFIRMED, ClaimState.SUPPORTED}
                or not view.history or view.history[-1].adjudication_id != path["adjudication_id"]
                or relation is None or relation.claim_id != cid or relation.entity_kind != "dataflow_path"
                or relation.predicate.value != finding_paths.REACH
                or (relation.kind.value != "supports" and not finding_paths.cited_alternate(relation))
                or (pin["shard_id"] == finding_paths.ALT_PATH_SHARD and path["status"] != "unverified")
                or relation.provenance is not None or finding_paths.citation(relation) != pin
                or any(ref not in relations or relations[ref].predicate.value != finding_paths.REACH
                       or relations[ref].kind.value != "contradicts" for ref in path["counter_relations"])
                or pin["relation_id"] in seen):
            raise IntegrityError("finding path does not match the adjudicated ledger citation")
        seen.add(pin["relation_id"])
    for item in manifest["items"]:
        view = projection.attack_chains[item["chain_id"]]
        proposal = policy.proposal_from_json(read_artifact(run_root, policy.document(view.proposal_artifact)))
        artifact = read_artifact(run_root, item["artifact"])
        schemas.validate("attack-chain", artifact)
        if (view.decision is None or proposal != view.proposal
                or view.decision.artifact != policy.Artifact(**item["artifact"])
                or artifact["run_id"] != run_id or artifact["proposal"] != policy.document(view.proposal)
                or artifact["challenges"] != [policy.document(challenge) for challenge in view.challenges]
                or item["status"] != artifact["status"] or item["status"] != view.decision.status.value
                or item["limitations"] != artifact["limitations"]
                or item["limitations"] != list(view.decision.limitations)
                or item["component_claim_ids"] != [component.claim_id for component in proposal.components]
                or item.get("composed_severity") != artifact["assessment"].get("composed_severity")
                or item.get("chain_boundary_crossings", []) != artifact["assessment"].get("chain_boundary_crossings", [])):
            raise IntegrityError("attack-chain manifest, artifact and ledger decision disagree")
        _verify_actor_receipt(run_root, projection, proposal.composer, "composer", "succeeded", None, schemas, receipts_root=receipts_root)
        for challenge in view.challenges:
            receipt = _verify_actor_receipt(run_root, projection, challenge.actor, challenge.kind,
                                            challenge.status, challenge.receipt, schemas, receipts_root=receipts_root)
            if receipt and receipt["turns"][0]["request_sha256"] != challenge.request_sha256:
                raise IntegrityError("chain challenge is not bound to its original independent request")
    return manifest


def _verify_actor_receipt(run_root: Path, projection: Projection, actor, kind: str, status: str,
                          reference: policy.Artifact | None, schemas, *, receipts_root: Path | None = None):
    task, role, schema = TASKS[kind]
    cell_id = actor.conversation_id
    records = projection.cells.get(cell_id, ())
    if (len(records) != 1 or records[0].task != task or records[0].role is not role
            or records[0].status.value != status or records[0].claim_id is not None
            or actor.actor_id != make_id("actor", 1, {"cell_id": cell_id})):
        raise IntegrityError("chain actor is not bound to exactly one matching terminal cell")
    record = records[0]
    if record.receipt_sha256 is None:
        if status != "not_launched" or record.attempts or reference is not None:
            raise IntegrityError("attempted chain work is missing its original receipt")
        return None
    path = ((receipts_root or run_root / "data" / "jobs" / JOB_ID / "cells") / cell_id / f"attempt-{record.attempts}.json")
    expected = policy.Artifact(path.relative_to(run_root).as_posix(), record.receipt_sha256)
    if reference is not None and reference != expected:
        raise IntegrityError("chain challenge receipt is not its terminal cell's receipt")
    receipt = read_artifact(run_root, policy.document(expected))
    if (receipt.get("schema") != RECEIPT_SCHEMA or receipt.get("cell_id") != cell_id
            or receipt.get("provider") != actor.provider or receipt.get("model") != actor.model
            or receipt.get("status") != status or receipt.get("attempt") != record.attempts
            or receipt.get("validator_version") != policy.POLICY or not receipt.get("turns")):
        raise IntegrityError("chain actor, status and original cell receipt disagree")
    if status == "succeeded":
        if receipt.get("result_sha256") != sha256_hex(receipt.get("result")):
            raise IntegrityError("chain cell result hash does not match its original result")
        schemas.validate(schema, receipt["result"])
    return receipt
