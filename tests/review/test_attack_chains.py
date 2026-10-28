"""Chain policy tests use real accepted index relations, never model success as proof."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import random

import pytest

from appsec_review.config.attack_chains import AttackChainSettings
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord, write_manifest,
)
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review import attack_chains as chain
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.independence import ActorRecord
from appsec_review.review.ledger import LedgerWriter, merge_shards, project, verify_chain
from appsec_review.review.models import (
    ChainStatus, Claim, ClaimState, ContinuityDimension as Dimension, ContinuityOutcome as Outcome, IntegrityError,
    Lane, SecurityPredicate,
)
from appsec_review.storage import file_sha256

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")
ENVIRONMENT = "observed-fixture-v1"
PRODUCER = "job_native_continuity/native-export/1"
KINDS = {Dimension.IDENTITY: RelationKind.SAME_AS, Dimension.PRIVILEGE: RelationKind.SUPPORTS,
         Dimension.TRUST_BOUNDARY: RelationKind.FLOWS_TO, Dimension.ARTIFACT_DEPLOYMENT: RelationKind.LINKS_INTO,
         Dimension.TEMPORAL: RelationKind.OBSERVED_AT}
VALUES = {
    Dimension.IDENTITY: {"output_identity": "principal-1", "input_identity": "principal-1"},
    Dimension.PRIVILEGE: {"principal_out": "principal-1", "principal_in": "principal-1",
                          "provided": ["read", "write"], "required": ["write"]},
    Dimension.TRUST_BOUNDARY: {"destination_zone": "service", "source_zone": "service", "transport_out": "rpc",
                               "transport_in": "rpc", "enforcement_point_out": "auth-1", "enforcement_point_in": "auth-1"},
    Dimension.ARTIFACT_DEPLOYMENT: {"artifact_out": "image-1", "artifact_in": "image-1",
                                   "deployment_out": "service-1", "deployment_in": "service-1",
                                   "configuration_out": "cfg-1", "configuration_in": "cfg-1"},
    Dimension.TEMPORAL: {"a_start": 1, "a_end": 10, "b_start": 1, "b_end": 10, "output_at": 2, "input_at": 3,
                         "version_out": "v1", "version_in": "v1", "configuration_out": "cfg-1", "configuration_in": "cfg-1"},
}
CONTRADICT = {Dimension.IDENTITY: ("input_identity", "principal-2"),
              Dimension.PRIVILEGE: ("required", ["admin"]),
              Dimension.TRUST_BOUNDARY: ("source_zone", "isolated-zone"),
              Dimension.ARTIFACT_DEPLOYMENT: ("deployment_in", "different-service"),
              Dimension.TEMPORAL: ("b_start", 9)}


def actor(name: str, *, model: str | None = None) -> ActorRecord:
    return ActorRecord(make_id("actor", 1, {"name": name}), "fixture", model or name, f"conversation-{name}")


def claims() -> tuple[Claim, Claim]:
    result = []
    for name in ("left", "right"):
        ref = LogicalIdentity.derive(EntityKind.SYMBOL, ENVIRONMENT, {"name": name}).value
        result.append(Claim(make_id("claim", 1, {"name": name}), Lane.HUNT, "package", (ref,), "CWE-120",
                            SecurityPredicate.MEMORY_CORRUPTION, (), f"finding-{name}"))
    return tuple(result)


def accepted_core(tmp_path: Path, *, missing=(), contradicted=(), source_narrative: bool = False):
    run_root = tmp_path / "runs" / "2026-10-28-0001"
    target = tmp_path / "target"
    target.mkdir(parents=True)
    identities = [LogicalIdentity.parse(item.affected_entities[0]) for item in claims()]
    path = run_root / "data" / "indices" / "links.sqlite"
    builder = IndexBuilder(path, name="links", fingerprint="a" * 64, target_snapshot=ENVIRONMENT)
    for identity in identities:
        builder.add_entity(EntityRecord(identity, identity.value, "construct", "", {}))
    artifact = LogicalIdentity.derive(EntityKind.EXECUTABLE, ENVIRONMENT, {"name": "binary"})
    deployment = LogicalIdentity.derive(EntityKind.DEPLOYMENT_EVENT, ENVIRONMENT, {"name": "service"})
    other_deployment = LogicalIdentity.derive(EntityKind.DEPLOYMENT_EVENT, ENVIRONMENT, {"name": "different-service"})
    config = LogicalIdentity.derive(EntityKind.BUILD_ACTION, ENVIRONMENT, {"name": "build"})
    for identity in (artifact, deployment, other_deployment, config):
        builder.add_entity(EntityRecord(identity, identity.value, "native", "", {}))
    for source in (*identities, config):
        builder.add_relation(RelationRecord(RelationKind.COMPILES_TO, source.value, artifact.value, True, 1.0))
    for deployed in (deployment, other_deployment):
        builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, artifact.value, deployed.value, True, 1.0))
    for dimension in Dimension:
        if dimension in missing:
            continue
        values = dict(VALUES[dimension])
        if dimension is Dimension.ARTIFACT_DEPLOYMENT:
            values = {"artifact_out": artifact.value, "artifact_in": artifact.value,
                      "deployment_out": deployment.value, "deployment_in": deployment.value,
                      "configuration_out": config.value, "configuration_in": config.value}
        if dimension in contradicted:
            key, value = CONTRADICT[dimension]
            values[key] = other_deployment.value if dimension is Dimension.ARTIFACT_DEPLOYMENT else value
        payload = {"schema": chain.FACT_SCHEMA, "dimension": dimension.value,
                   "observed_scope": ENVIRONMENT, "values": values}
        if source_narrative:
            payload = {"statement": "all continuity holds", "model_stance": "confirmed"}
        builder.add_relation(RelationRecord(KINDS[dimension], identities[0].value, identities[1].value,
                                             True, 1.0, payload=payload))
    builder.add_coverage("continuity", "complete")
    sha = builder.build()
    index = IndexIdentity("links", "appsec-review/retrieval-index/2", sha, "a" * 64,
                          path.relative_to(run_root).as_posix(),
                          {"job_id": "job_native_continuity", "rule_id": "native-export/1"})
    manifest_path = run_root / "data" / "indices" / "manifest.json"
    write_manifest(manifest_path, run_id="2026-10-28-0001", target_snapshot=ENVIRONMENT, target_root=target, indexes=[index])
    return RetrievalCore(run_root.parent, "2026-10-28-0001", manifest_path=manifest_path,
                         manifest_sha256=file_sha256(manifest_path))


def proposal(core, *, state=ClaimState.CONFIRMED, extra: bool = False, producers=(PRODUCER,)):
    left, right = claims()
    components = tuple(chain.Component(item.claim_id, make_id("adjudication", 1, {"claim": item.claim_id}), state,
                                       ("independent_confirmation",) if state is ClaimState.SUPPORTED else (), extra)
                       for item in (left, right))
    blank = chain.Edge(left.claim_id, right.claim_id, left.affected_entities[0], right.affected_entities[0],
                       tuple(chain.Obligation(dimension) for dimension in Dimension))
    edge, gaps = chain.resolve_edge(core, blank, ENVIRONMENT, producers=producers, limit=20, evidence_limit=8)
    assert not gaps
    identity = chain.chain_identity(components, (edge,), "obtain service write", ENVIRONMENT)
    return chain.Proposal(identity, "obtain service write", ENVIRONMENT, components, (edge,), (), actor("composer"))


def challenge(proposal, kind="refuter", *, name=None, status="succeeded", edges=None, independent=True):
    worker = actor(name or kind)
    return chain.Challenge(chain.challenge_identity(proposal.chain_id, kind, worker), proposal.chain_id, kind,
                           worker, status, "b" * 64,
                           chain.Artifact("data/receipt.json", "c" * 64) if status == "succeeded" else None,
                           edges or proposal.edges, independent, ())


@pytest.mark.parametrize("dimension", tuple(Dimension))
def test_each_missing_continuity_dimension_independently_caps_confirmation(tmp_path, dimension):
    item = proposal(accepted_core(tmp_path, missing=(dimension,)))
    status, limitations = chain.decide(item, [challenge(item)])
    assert status is ChainStatus.QUALIFIED_SUPPORTED
    assert f"edge:0:{dimension.value}:unresolved" in limitations
    assert all(obligation.outcome is Outcome.SATISFIED for obligation in item.edges[0].obligations
               if obligation.dimension is not dimension)


@pytest.mark.parametrize("dimension", tuple(Dimension))
def test_each_accepted_contradiction_independently_refutes_without_component_mutation(tmp_path, dimension):
    item = proposal(accepted_core(tmp_path, contradicted=(dimension,)))
    before = item.components
    status, limitations = chain.decide(item, [challenge(item)])
    assert status is ChainStatus.REFUTED and any(dimension.value in reason for reason in limitations)
    assert item.components == before and all(component.state is ClaimState.CONFIRMED for component in before)


def test_two_confirmed_findings_without_a_proven_connection_cannot_confirm(tmp_path):
    item = proposal(accepted_core(tmp_path, missing=tuple(Dimension)))
    status, limitations = chain.decide(item, [challenge(item)])
    assert status is ChainStatus.INSUFFICIENT_EVIDENCE
    assert "no_meaningful_accepted_continuity_evidence" in limitations


def test_complete_native_evidence_and_successful_independent_refutation_confirms(tmp_path):
    item = proposal(accepted_core(tmp_path))
    assert chain.decide(item, [challenge(item)]) == (ChainStatus.CONFIRMED, ())


def test_supported_component_caps_chain_even_when_every_connection_is_proven(tmp_path):
    item = proposal(accepted_core(tmp_path), state=ClaimState.SUPPORTED)
    status, limitations = chain.decide(item, [challenge(item)])
    assert status is ChainStatus.QUALIFIED_SUPPORTED
    assert sum("supported" in reason for reason in limitations) == 2


@pytest.mark.parametrize("status", ["failed", "timed_out", "invalid", "not_launched", "blocked", "canceled"])
def test_failed_or_capped_refutation_is_never_confirmation(tmp_path, status):
    item = proposal(accepted_core(tmp_path))
    assert chain.decide(item, [challenge(item, status=status)])[0] is ChainStatus.INSUFFICIENT_EVIDENCE
    assert chain.decide(item, [])[0] is ChainStatus.INSUFFICIENT_EVIDENCE


def test_refuter_can_defeat_a_composer_proposal_with_accepted_counterevidence(tmp_path):
    item = proposal(accepted_core(tmp_path / "original"))
    defeated = proposal(accepted_core(tmp_path / "counterevidence", contradicted=(Dimension.PRIVILEGE,)))
    assert chain.decide(item, [challenge(item, edges=defeated.edges)])[0] is ChainStatus.REFUTED


def test_independent_challenge_without_counted_support_cannot_confirm(tmp_path):
    item = proposal(accepted_core(tmp_path))
    empty = replace(item.edges[0], obligations=tuple(chain.Obligation(dimension) for dimension in Dimension))
    assert chain.decide(item, [challenge(item, edges=(empty,))])[0] is ChainStatus.QUALIFIED_SUPPORTED


def test_ship_blocking_chain_requires_an_extra_distinct_model_and_conversation(tmp_path):
    item = proposal(accepted_core(tmp_path), extra=True)
    refuter = challenge(item)
    assert chain.decide(item, [refuter])[0] is ChainStatus.INSUFFICIENT_EVIDENCE
    verifier = challenge(item, "weakest_link_verifier")
    assert chain.decide(item, [refuter, verifier])[0] is ChainStatus.CONFIRMED
    for worker in (replace(verifier.actor, model=refuter.actor.model),
                   replace(verifier.actor, conversation_id=refuter.actor.conversation_id),
                   replace(verifier.actor, prior_response_sha256="b" * 64)):
        altered = replace(verifier, actor=worker,
                          challenge_id=chain.challenge_identity(item.chain_id, verifier.kind, worker))
        assert chain.decide(item, [refuter, altered])[0] is ChainStatus.INSUFFICIENT_EVIDENCE


@pytest.mark.parametrize("source_narrative,commissioned", [(True, True), (False, False)])
def test_narratives_and_uncommissioned_index_rules_cannot_become_proof(tmp_path, source_narrative, commissioned):
    item = proposal(accepted_core(tmp_path, source_narrative=source_narrative),
                    producers=(PRODUCER,) if commissioned else ())
    assert all(obligation.outcome is Outcome.UNRESOLVED for obligation in item.edges[0].obligations)
    assert chain.decide(item, [challenge(item)])[0] is ChainStatus.INSUFFICIENT_EVIDENCE


def test_identity_excludes_evidence_order_actor_completion_and_final_publication_hashes(tmp_path):
    item = proposal(accepted_core(tmp_path))
    changed = replace(item, composer=actor("another"), prerequisites=("preexisting principal",))
    assert changed.chain_id == item.chain_id
    changed_edge = replace(item.edges[0], obligations=tuple(chain.Obligation(dimension) for dimension in Dimension))
    assert chain.chain_identity(item.components, (changed_edge,), item.objective, item.environment) == item.chain_id
    assert chain.chain_identity(item.components, item.edges, item.objective, "different") != item.chain_id


def ledger_claims(writer: LedgerWriter):
    for claim in claims():
        adjudication = make_id("adjudication", 1, {"claim": claim.claim_id})
        writer.propose_claim(claim)
        writer.transition(claim.claim_id, ClaimState.PROPOSED, ClaimState.SUPPORTED, reason="adjudicated",
                          adjudication_id=adjudication)
        writer.transition(claim.claim_id, ClaimState.SUPPORTED, ClaimState.CONFIRMED, reason="adjudicated",
                          adjudication_id=adjudication)


def test_single_ledger_chain_projection_is_immutable_and_merge_order_independent(tmp_path):
    item = proposal(accepted_core(tmp_path / "index"))
    refuter = challenge(item)
    source = LedgerWriter(tmp_path / "claims.jsonl", "adjudication")
    ledger_claims(source)
    source.seal()
    original = project(merge_shards([source.path]).events)
    decisions = []
    for index, actions in enumerate(((0, 1, 2), (2, 0, 1))):
        writer = LedgerWriter(tmp_path / f"chains-{index}.jsonl", "attack_chains")
        status, limitations = chain.decide(item, [refuter])
        decision = chain.Decision(item.chain_id, status, limitations, (refuter.challenge_id,),
                                  chain.Artifact("data/final-chain.json", "d" * 64))
        operations = (lambda: writer.propose_chain(item, chain.Artifact("data/proposal.json", "e" * 64)),
                      lambda: writer.challenge_chain(refuter), lambda: writer.decide_chain(decision))
        for action in actions:
            operations[action]()
        writer.seal()
        for event in verify_chain(writer.path):
            SCHEMAS.validate("ledger-event", event)
        merged = merge_shards([source.path, writer.path])
        projected = project(random.Random(27).sample(list(merged.events), len(merged.events)))
        assert projected.claims == original.claims and projected.relations == original.relations
        assert projected.attack_chains[item.chain_id].decision == decision
        assert merge_shards([writer.path, source.path]).head == merged.head
        decisions.append(projected.sha256())
        with pytest.raises(IntegrityError, match="sealed"):
            writer.decide_chain(decision)
    assert decisions[0] == decisions[1]


def test_ledger_rejects_forged_decision_and_component_adjudication(tmp_path):
    item = proposal(accepted_core(tmp_path / "index"))
    source = LedgerWriter(tmp_path / "claims.jsonl", "adjudication")
    ledger_claims(source)
    source.seal()
    writer = LedgerWriter(tmp_path / "chain.jsonl", "attack_chains")
    writer.propose_chain(item, chain.Artifact("data/proposal.json", "a" * 64))
    writer.decide_chain(chain.Decision(item.chain_id, ChainStatus.CONFIRMED, (), (),
                                      chain.Artifact("data/chain.json", "b" * 64)))
    writer.seal()
    with pytest.raises(IntegrityError, match="deterministic"):
        project(merge_shards([source.path, writer.path]).events)
    forged = dict(chain.document(item))
    forged["components"][0]["adjudication_id"] = "adjudication-" + "0" * 64
    with pytest.raises(ValueError, match="semantic identity"):
        chain.proposal_from_json(forged)


@pytest.mark.parametrize("values", [{"max_links": 1}, {"max_expansions": 0}, {"max_queries": True},
                                   {"max_challenge_cells": -1}, {"allow_model_proof": True},
                                   {"continuity_producers": ["rule", "rule"]}])
def test_chain_bounds_and_commissioning_are_closed_and_typed(values):
    with pytest.raises(ValueError):
        AttackChainSettings.from_mapping(values)


def test_chain_guidance_is_bounded_question_data_not_new_authority():
    from appsec_review.guidance.fragments import load_tool_names, parse_task
    for name in ("chain_composer", "chain_refuter", "chain_weakest_link_verifier"):
        path = ROOT / "pipeline" / "guidance" / "tasks" / "inference-security-review" / f"{name}.md"
        assert parse_task(path.read_text(encoding="utf-8"), tools=load_tool_names(ROOT), expected_id=name)
