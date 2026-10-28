"""Bounded composition and blind challenges using the normal review-cell transport and ledger."""
from __future__ import annotations

from dataclasses import replace
import itertools
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from appsec_review.jobs.completion_contracts import ATTACK_CHAIN_MANIFEST_SCHEMA
from appsec_review.review import attack_chains as policy
from appsec_review.review.capability import CellCapability, IN_PROCESS_TOOLS
from appsec_review.review.cells import CellSpec
from appsec_review.review.identity import sha256_hex
from appsec_review.review.ledger import LedgerWriter, Projection
from appsec_review.review.models import (
    CellStatus, ChainStatus, ClaimState, ContinuityDimension, ContinuityOutcome, GapClass, IntegrityError, Lane, Role,
    make_gap,
)
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from .teams import ReviewContext, _Cell, _actor, _not_launched, _run

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
    capability = CellCapability.issue(
        run_id=ctx.run_id, manifest_sha256=ctx.core.manifest_sha256, package_id=identity,
        package_sha256=package_sha, role=role, round=0,
        tools=tuple(sorted(set(ctx.role_tools.get(role.value, ())) & IN_PROCESS_TOOLS)),
        indexes=ctx.index_names, entities=entities,
        max_queries=max(1, min(profile.max_queries, bounds.max_queries)),
        max_turns=min(profile.max_turns, bounds.max_turns), page_size=min(ctx.max_page_size, 100),
        max_depth=1, max_result_bytes=bounds.max_result_bytes)
    guidance = ctx.bundle(role=role, persona="generalist", stack="generic", task=task,
                          lane=Lane.HUNT, capability=capability)
    spec = CellSpec(
        manifest_sha256=ctx.core.manifest_sha256, lane=Lane.HUNT, package_id=identity,
        package_sha256=package_sha, claim_id=None, role=role, persona="generalist", stack_profile="generic",
        strategy=None, task=task, task_input=inputs, round=0, round_delta_sha256=None,
        evidence_set=tuple(sorted(set(entities))), guidance_bundle_sha256=guidance["bundle"]["sha256"],
        guidance_text=guidance["text"], provider=profile.provider, model=profile.model, reasoning=profile.reasoning,
        max_input_tokens=profile.max_input_tokens, max_output_tokens=profile.max_output_tokens,
        timeout_seconds=profile.timeout_seconds, output_schema=f"appsec-review/{schema}/1",
        validator_version=policy.POLICY)
    return _Cell(spec, capability, kind)


def _record(writer: LedgerWriter, cell: _Cell) -> None:
    writer.cell_terminal(cell.record)
    if cell.outcome:
        for gap in cell.outcome.gaps:
            writer.record_gap(gap)


def _run_cell(ctx: ReviewContext, cell: _Cell, validate) -> None:
    profile = ctx.profile(cell.spec.role)
    if not profile.enabled:
        cell.record, gap = _not_launched(cell, "model_profile_disabled", GapClass.CHAIN_GAP)
        from appsec_review.review.cells import CellOutcome
        cell.outcome = CellOutcome(cell.record, None, (gap,), (), (), False, {})
        return
    with ctx.semaphore.acquire(Lane.HUNT):
        _run(ctx, cell, validate, capture=True)


def _empty_edge(left: str, right: str, output: str, input_: str) -> policy.Edge:
    return policy.Edge(left, right, output, input_,
                       tuple(policy.Obligation(dimension) for dimension in ContinuityDimension))


def _resolve(ctx: ReviewContext, edge: policy.Edge, environment: str, *, cites=None):
    settings = ctx.settings.attack_chains
    if not ctx.budget.cell_launch_allowed():
        return edge, ("continuity_resolution:job_budget_exhausted",)
    ctx.budget.charge(retrieval_queries=1)
    return policy.resolve_edge(
        ctx.core, edge, environment, producers=settings.continuity_producers, limit=ctx.max_page_size,
        evidence_limit=settings.max_evidence_per_obligation, cited_relations=cites)


def compose(ctx: ReviewContext, projection: Projection, adjudications: Sequence[Mapping[str, Any]], *,
            extra_verifier_claims: set[str], seeds: Sequence[Mapping[str, Any]], out_dir: Path,
            ledger_path: Path, stream: str) -> dict[str, Any]:
    bounds = ctx.settings.attack_chains
    components: dict[str, policy.Component] = {}
    for record in sorted(adjudications, key=lambda item: item["claim_id"]):
        claim_id, state = record["claim_id"], ClaimState(record["state"])
        if state not in {ClaimState.SUPPORTED, ClaimState.CONFIRMED}:
            continue
        missing = tuple(sorted(item["predicate"] for item in record["predicates"]
                               if item["required"] and item["outcome"] != "satisfied"))
        if state is ClaimState.SUPPORTED and not missing:
            missing = ("independent_confirmation",)
        components[claim_id] = policy.Component(claim_id, record["adjudication_id"], state, missing,
                                                claim_id in extra_verifier_claims)
    writer = LedgerWriter(ledger_path, stream)
    gaps: list[str] = []
    counters = dict(proposed=0, admitted=0, assessed=0, capped=0, rejected=0, deduplicated=0,
                    seeds_received=len(seeds), seeds_rejected=0)
    hints = []
    for seed in seeds:
        ids = [seed.get("proposal_claims", {}).get(step.get("proposal_id"))
               for step in (seed.get("seed") or {}).get("steps", ())]
        if not 2 <= len(ids) <= bounds.max_links or len(set(ids)) != len(ids) or any(
                claim_id not in components for claim_id in ids):
            counters["seeds_rejected"] += 1
            continue
        # Strip original seed prose/edges: it cannot become a continuity fact.
        hints.append({"component_claim_ids": ids})
    ids = sorted(components)
    pairs = list(itertools.islice(((left, right) for left in ids for right in ids if left != right),
                                 bounds.max_expansions + 1))
    admitted_pairs = pairs[:bounds.max_expansions]
    frontier = [{"from_claim_id": left, "to_claim_id": right} for left, right in pairs[bounds.max_expansions:]]
    exploration = {"expanded": len(admitted_pairs), "limit": bounds.max_expansions,
                   "frontier": frontier, "frontier_truncated": bool(frontier)}
    if frontier:
        gaps.append("max_expansions reached; unexplored frontier is not a count of all possible paths")
    records: list[dict[str, Any]] = []
    expected: dict[str, str] = {}
    max_chains = ctx.settings.rounds.max_attack_chains
    if len(components) < 2:
        gaps.append("fewer_than_two_adjudicated_chain_components")
    elif max_chains == 0:
        gaps.append("attack_chain_composition_disabled_by_max_attack_chains")
    else:
        entities = tuple(sorted({ref for claim_id in ids for ref in projection.claims[claim_id].claim.affected_entities}))
        inputs = {
            "environment": ctx.core.manifest["target_snapshot"],
            "components": [{**policy.document(components[claim_id]),
                            "affected_entities": list(projection.claims[claim_id].claim.affected_entities),
                            "security_predicate": projection.claims[claim_id].claim.security_predicate.value}
                           for claim_id in ids],
            "admitted_pairs": [{"from_claim_id": left, "to_claim_id": right} for left, right in admitted_pairs],
            "seed_hints": hints[:bounds.max_candidates_per_composition],
            "output_contract": ctx.schemas.documents["chain-composer-result.schema.json"],
            "candidate_limit": bounds.max_candidates_per_composition, "max_links": bounds.max_links}
        cell = _cell(ctx, "composer", inputs, entities, "attack-chain-composition")

        def validate(result):
            errors = ctx.schemas.errors("chain-composer-result", result)
            if not errors and len(result["candidates"]) > bounds.max_candidates_per_composition:
                errors.append("candidate output exceeds the configured bound")
            return errors

        _run_cell(ctx, cell, validate)
        _record(writer, cell)
        expected[cell.cell_id] = Lane.HUNT.value
        if cell.outcome and cell.outcome.result:
            result = cell.outcome.result
            gaps.extend(result["gaps"])
            candidates = sorted(result["candidates"], key=sha256_hex)
            counters["proposed"] = len(candidates)
            seen = set()
            for candidate in candidates:
                ordered = candidate["component_claim_ids"]
                edge_values = candidate["edges"]
                if (len(ordered) > bounds.max_links or len(edge_values) != len(ordered) - 1
                        or any(claim_id not in components for claim_id in ordered)
                        or any(pair not in admitted_pairs for pair in zip(ordered, ordered[1:]))
                        or any(item["output_entity"] not in projection.claims[left].claim.affected_entities
                               or item["input_entity"] not in projection.claims[right].claim.affected_entities
                               for (left, right), item in zip(zip(ordered, ordered[1:]), edge_values))):
                    counters["rejected"] += 1
                    gaps.append("candidate_rejected:nonadjudicated_component_or_unadmitted_edge")
                    continue
                edges = tuple(_empty_edge(left, right, value["output_entity"], value["input_entity"])
                              for (left, right), value in zip(zip(ordered, ordered[1:]), edge_values))
                parts = tuple(components[claim_id] for claim_id in ordered)
                environment = str(inputs["environment"])
                chain_id = policy.chain_identity(parts, edges, candidate["objective"], environment)
                if chain_id in seen:
                    counters["deduplicated"] += 1
                    continue
                seen.add(chain_id)
                capped = len(records) >= max_chains
                if not capped:
                    resolved = [_resolve(ctx, edge, environment) for edge in edges]
                    edges = tuple(item[0] for item in resolved)
                    gaps.extend(gap for item in resolved for gap in item[1])
                proposal = policy.Proposal(chain_id, candidate["objective"], environment, parts, edges,
                                           tuple(sorted(set(candidate["prerequisites"]))), _actor(cell))
                artifact = _write(ctx, out_dir / f"{chain_id}.proposal.json", policy.document(proposal))
                writer.propose_chain(proposal, artifact)
                records.append({"proposal": policy.document(proposal), "artifact": policy.document(artifact),
                                "disposition": "capped" if capped else "assessed"})
                counters["capped" if capped else "assessed"] += 1
            counters["admitted"] = len(records)
            if not records:
                gaps.append("no_meaningful_chain_candidates_proposed")
        else:
            gaps.append(f"composition:{cell.record.status.value}")
    if counters["seeds_rejected"]:
        gaps.append("seed_hints_rejected:nonadjudicated_or_invalid_components")
    if not bounds.continuity_producers:
        gaps.append("no_commissioned_native_continuity_producer; source narratives cannot prove chain continuity")
    return _finish(writer, {"candidates": sorted(records, key=lambda item: item["proposal"]["chain_id"]),
                            "gaps": sorted(set(gaps)), "accounting": counters, "exploration": exploration,
                            "expected_cells": expected})


def challenge(ctx: ReviewContext, composition: Mapping[str, Any], previous: Mapping[str, Any] | None, *,
              kind: str, out_dir: Path, ledger_path: Path, stream: str) -> dict[str, Any]:
    writer = LedgerWriter(ledger_path, stream)
    results: list[dict[str, Any]] = []
    expected: dict[str, str] = {}
    used = len(previous.get("challenges", ())) if previous else 0
    prior = {item["chain_id"]: policy.challenge_from_json(item) for item in previous["challenges"]} if previous else {}
    for entry in composition["candidates"]:
        proposal = policy.proposal_from_json(read_artifact(ctx.run_root, entry["artifact"]))
        if proposal != policy.proposal_from_json(entry["proposal"]):
            raise IntegrityError("chain proposal artifact and composition output disagree")
        if kind == "weakest_link_verifier" and not proposal.requires_extra_verifier:
            continue
        neutral = {key: value for key, value in policy.document(proposal).items() if key != "composer"}
        inputs = {"chain": neutral,
                  "weakest_first": [{"edge_index": index, "dimension": item.dimension.value,
                                     "outcome": item.outcome.value}
                                    for index, edge in enumerate(proposal.edges) for item in sorted(
                                        edge.obligations, key=lambda value: (
                                            value.outcome is ContinuityOutcome.SATISFIED, value.dimension.value))],
                  "output_contract": ctx.schemas.documents["chain-challenge-result.schema.json"]}
        entities = tuple(sorted({identity for edge in proposal.edges
                                 for identity in (edge.output_entity, edge.input_entity)}))
        cell = _cell(ctx, kind, inputs, entities, proposal.chain_id)
        peers = [proposal.composer]
        if kind == "weakest_link_verifier" and proposal.chain_id in prior:
            peers.append(prior[proposal.chain_id].actor)
        independent = policy.independent(_actor(cell), peers, distinct_model=kind == "weakest_link_verifier")
        reason = None
        if entry["disposition"] == "capped":
            reason = "max_attack_chains"
        elif used >= ctx.settings.attack_chains.max_challenge_cells:
            reason = "max_challenge_cells"
        elif not independent:
            reason = "independence_not_established"
        if reason:
            cell.record, gap = _not_launched(cell, reason, GapClass.CHAIN_GAP)
            writer.record_gap(gap)
        else:
            def validate(result):
                errors = ctx.schemas.errors("chain-challenge-result", result)
                if not errors:
                    keys = [(item["edge_index"], item["dimension"]) for item in result["checks"]]
                    expected_keys = [(index, dimension.value) for index in range(len(proposal.edges))
                                     for dimension in ContinuityDimension]
                    if result["chain_id"] != proposal.chain_id or sorted(keys) != sorted(expected_keys):
                        errors.append("challenge must account for each edge and dimension exactly once")
                return errors
            _run_cell(ctx, cell, validate)
            used += 1
        _record(writer, cell)
        expected[cell.cell_id] = Lane.HUNT.value
        edges = tuple(_empty_edge(edge.from_claim_id, edge.to_claim_id, edge.output_entity, edge.input_entity)
                      for edge in proposal.edges)
        gaps = [reason] if reason else []
        receipt = None
        request_sha = sha256_hex(inputs)
        if cell.outcome and cell.outcome.receipt_paths:
            receipt_path = cell.outcome.receipt_paths[-1]
            receipt = policy.Artifact(receipt_path.relative_to(ctx.run_root).as_posix(), file_sha256(receipt_path))
            stored = json.loads(receipt_path.read_text(encoding="utf-8"))
            request_sha = stored["turns"][0]["request_sha256"]
        if cell.outcome and cell.outcome.result:
            result = cell.outcome.result
            gaps.extend(result["gaps"])
            resolved_edges = []
            for index, edge in enumerate(edges):
                checks = [check for check in result["checks"] if check["edge_index"] == index]
                resolved, resolution_gaps = _resolve(ctx, edge, proposal.environment,
                                                      cites={ref for check in checks for ref in check["cites"]})
                # Each dimension must be independently cited; one fact cannot fill another check.
                obligations = []
                for obligation in resolved.obligations:
                    refs = next(check["cites"] for check in checks if check["dimension"] == obligation.dimension.value)
                    obligations.append(policy.Obligation(obligation.dimension, tuple(
                        ref for ref in obligation.evidence if ref.relation_id in refs)))
                resolved_edges.append(replace(resolved, obligations=tuple(obligations)))
                gaps.extend(resolution_gaps)
            edges = tuple(resolved_edges)
        item = policy.Challenge(
            policy.challenge_identity(proposal.chain_id, kind, _actor(cell)), proposal.chain_id, kind, _actor(cell),
            cell.record.status.value, request_sha, receipt, edges, independent, tuple(sorted(set(gaps))))
        writer.challenge_chain(item)
        results.append(policy.document(item))
    result = {"challenges": sorted(results, key=lambda item: item["challenge_id"]), "expected_cells": expected}
    if kind == "weakest_link_verifier":
        manifest = publish(ctx, composition, previous, result, out_dir=out_dir, writer=writer)
        result["attack_chain_manifest"] = policy.document(_write(ctx, out_dir / "manifest.json", manifest))
        result["gaps"] = manifest["gaps"]
    return _finish(writer, result)


def publish(ctx: ReviewContext, composition: Mapping[str, Any], refutations: Mapping[str, Any],
            verifications: Mapping[str, Any], *, out_dir: Path, writer: LedgerWriter) -> dict[str, Any]:
    records = [policy.challenge_from_json(item) for document in (refutations, verifications)
               for item in document["challenges"]]
    items, gaps = [], list(composition["gaps"])
    for entry in composition["candidates"]:
        proposal = policy.proposal_from_json(read_artifact(ctx.run_root, entry["artifact"]))
        challenges = tuple(sorted((item for item in records if item.chain_id == proposal.chain_id),
                                  key=lambda item: item.challenge_id))
        status, limitations = policy.decide(proposal, challenges)
        boundary_counted = all(item.outcome is ContinuityOutcome.SATISFIED
                               for edge in proposal.edges for item in edge.obligations
                               if item.dimension is ContinuityDimension.TRUST_BOUNDARY)
        artifact = {
            "schema": policy.CHAIN_SCHEMA, "run_id": ctx.run_id, "proposal": policy.document(proposal),
            "challenges": [policy.document(item) for item in challenges], "status": status.value,
            "limitations": list(limitations),
            "assessment": {"objective": proposal.objective,
                           "path_confidence": {ChainStatus.CONFIRMED: "evidence_complete",
                                               ChainStatus.QUALIFIED_SUPPORTED: "qualified",
                                               ChainStatus.REFUTED: "defeated",
                                               ChainStatus.INSUFFICIENT_EVIDENCE: "unavailable"}[status],
                           "prerequisites": list(proposal.prerequisites),
                           "boundary_exposure": "counted" if boundary_counted else "unresolved",
                           "remediation_choke_points": [], "shipment_decision": "not_assessed_by_chain_policy"}}
        ctx.schemas.validate("attack-chain", artifact)
        reference = _write(ctx, out_dir / f"{proposal.chain_id}.json", artifact)
        decision = policy.Decision(proposal.chain_id, status, limitations,
                                   tuple(item.challenge_id for item in challenges), reference)
        writer.decide_chain(decision)
        if status is not ChainStatus.CONFIRMED:
            writer.record_gap(make_gap(GapClass.CHAIN_GAP, proposal.chain_id,
                                       f"{status.value}:{';'.join(limitations)}"))
            gaps.append(f"{proposal.chain_id}:{status.value}")
        items.append({"chain_id": proposal.chain_id, "status": status.value,
                      "component_claim_ids": [component.claim_id for component in proposal.components],
                      "limitations": list(limitations), "disposition": entry["disposition"],
                      "artifact": policy.document(reference)})
    counters = composition["accounting"]
    if (counters["admitted"] != len(items) or counters["admitted"] != counters["assessed"] + counters["capped"]
            or counters["proposed"] != counters["admitted"] + counters["rejected"] + counters["deduplicated"]):
        raise IntegrityError("attack-chain candidate accounting is not exact")
    manifest = {"schema": ATTACK_CHAIN_MANIFEST_SCHEMA, "run_id": ctx.run_id, "items": items,
                "gaps": sorted(set(gaps)), "accounting": dict(counters), "exploration": dict(composition["exploration"])}
    ctx.schemas.validate("attack-chain-manifest", manifest)
    for gap in manifest["gaps"]:
        writer.record_gap(make_gap(GapClass.CHAIN_GAP, "attack_chains", gap))
    return manifest


def _finish(writer: LedgerWriter, result: Mapping[str, Any]) -> dict[str, Any]:
    receipt = writer.seal()
    return {**result, "ledger_shard": {"events": receipt.event_count, "sha256": file_sha256(writer.path)}}


def verify_publication(run_root: Path, projection: Projection, reference: Mapping[str, Any], schemas,
                       run_id: str) -> dict[str, Any]:
    """Revalidate the manifest and every bound pre-publication artifact against the single ledger."""
    manifest = read_artifact(run_root, reference)
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
                or item["component_claim_ids"] != [component.claim_id for component in proposal.components]):
            raise IntegrityError("attack-chain manifest, artifact and ledger decision disagree")
        for challenge in view.challenges:
            if challenge.receipt:
                receipt = read_artifact(run_root, policy.document(challenge.receipt))
                if receipt["turns"][0]["request_sha256"] != challenge.request_sha256:
                    raise IntegrityError("chain challenge is not bound to its original independent request")
    return manifest
