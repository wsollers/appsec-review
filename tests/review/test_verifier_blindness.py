"""ISR-F02: real cell receipts, team independence and R5 on a tiny accepted index."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.inference import ModelResult
from appsec_review.jobs.job_inference_security_review import teams
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.retrieval import RetrievalCore
from appsec_review.review.adjudication import adjudicate
from appsec_review.review.cells import TURN_SCHEMA, reuse_or_run
from appsec_review.review.claims import normalize_claim
from appsec_review.review.models import CellStatus, ClaimState, GapClass, Lane, Role
from appsec_review.review.obligations import required_predicates_for
from tests.review.test_cells import capability, spec
from tests.review.test_evidence import RUN_ID, _accepted_fixture


@pytest.fixture
def review(tmp_path):
    runs, ids, source = _accepted_fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    claim = normalize_claim(
        lane=Lane.LEAD, package_id="package-1", affected_entities=[ids["span"]],
        weakness_cwe="CWE-89", security_predicate="sql_injection",
        preconditions=["attacker_controls_request_field"], statement="short",
        accepted_cwe_ids={"CWE-89"},
    ).claim
    predicates = tuple(sorted(required_predicates_for(claim), key=lambda item: item.value))
    schemas = SchemaSet(Path(__file__).resolve().parents[2] / SCHEMA_DIRECTORY)
    ctx = SimpleNamespace(
        run_root=runs / RUN_ID, receipts_root=runs / RUN_ID / "cells", attempt_id="attempt_0001",
        core=core, rule_predicates={ids["observation"]: predicates},
    )

    def cell(role, *, task_input=None):
        return teams._Cell(
            spec(manifest_sha256=core.manifest_sha256, lane=Lane.LEAD, role=role,
                 claim_id=claim.claim_id, task="blind_verifier",
                 task_input=task_input or {"claim_id": claim.claim_id}, evidence_set=(ids["observation"],),
                 output_schema="appsec-review/verifier-result/1"),
            capability(manifest_sha256=core.manifest_sha256, role=role, indexes=("observations",),
                       tools=("find",), entities=(ids["observation"],)),
            "verifier" if role is Role.INDEPENDENT_VERIFIER else "red",
        )

    red = cell(Role.RED_TEAM_ANALYST)
    group = {"claim": claim, "cells": [red], "narratives": teams._markers([claim.statement])}

    def run(*, previous=None, retrieve=True, task_input=None, citation=None):
        verifier = cell(Role.INDEPENDENT_VERIFIER, task_input=task_input)
        if previous is not None:
            verifier = teams._Cell(previous.spec, previous.capability, "verifier")
        entity = citation or ids["observation"]
        response = {
            "schema": "appsec-review/verifier-result/1", "claim_id": claim.claim_id,
            "citations": {p.value: [entity] for p in predicates},
            "proposed_relations": [
                {"predicate": p.value, "kind": "supports", "entity_id": entity, "rationale": "observed"}
                for p in predicates
            ],
            "evidence_requests": [], "rationale": "observed", "proposed_disposition": "confirmed",
        }
        replies = ([{"action": "retrieve", "requests": [
            {"tool": "find", "parameters": {"identity": ids["observation"]}}]}] if retrieve else [])
        replies.append({"action": "final", "result": response})

        def infer(request, *, timeout_seconds):
            assert previous is None, "reuse must not dispatch another model request"
            return ModelResult({"schema": TURN_SCHEMA, **replies.pop(0)}, input_tokens=100, output_tokens=10)

        ctx.infer = infer
        guard = teams._Guard(ctx, verifier, None, capture=True)
        outcome = reuse_or_run(
            verifier.spec, infer=guard.dispatch, core=core, capability=verifier.capability,
            receipts_root=ctx.receipts_root,
            validate_final=teams._validator(SimpleNamespace(schemas=schemas), Role.INDEPENDENT_VERIFIER,
                                           claim_id=claim.claim_id),
            max_attempts=1,
        )
        assert outcome.record.status is CellStatus.SUCCEEDED, outcome.gaps
        verifier.record, verifier.outcome = outcome.record, outcome
        return verifier

    def decide(verifier):
        result = teams.TeamResult("package-1", Lane.LEAD, None)
        teams._review(ctx, group, (), verifier, result)
        decision = adjudicate(
            claim, result.relations, any(row["independent"] for row in result.independence[claim.claim_id]),
            claim.affected_entities, (),
        )
        return result, decision

    def sidecar(verifier):
        return ctx.receipts_root / verifier.cell_id / f"independence-attempt-{verifier.record.attempts}.json"

    return SimpleNamespace(ctx=ctx, ids=ids, source=source, claim=claim, predicates=predicates,
                           red=red, group=group, run=run, decide=decide, sidecar=sidecar)


def test_missing_reused_request_check_cannot_confirm_even_without_narrative_markers(review):
    fresh = review.run()
    _, initial = review.decide(fresh)
    assert initial.state is ClaimState.CONFIRMED
    review.sidecar(fresh).unlink()
    reused = review.run(previous=fresh)
    assert reused.outcome.reused and reused.requests == [] and review.group["narratives"] == []
    result, decision = review.decide(reused)
    assert decision.state is ClaimState.SUPPORTED
    assert decision.verifier_independent is False
    assert {gap.reason for gap in result.gaps if gap.gap_class is GapClass.INDEPENDENCE_GAP} == {
        "verifier_request_check_unavailable"}
    assert result.independence[review.claim.claim_id][0]["audit"]["request_check"] is None


@pytest.mark.parametrize("damage", [
    "invalid-json", "non-object", "schema", "cell", "attempt", "markers", "missing-result",
    "falsey-result", "empty-requests", "invalid-hash",
])
def test_reused_request_check_requires_original_well_formed_evidence(review, damage):
    fresh = review.run()
    review.decide(fresh)
    path = review.sidecar(fresh)
    document = json.loads(path.read_text())
    if damage == "schema":
        document["schema"] = "unknown"
    elif damage == "cell":
        document["cell_id"] = review.red.cell_id
    elif damage == "attempt":
        document["attempt"] += 1
    elif damage == "markers":
        review.group["narratives"] = ["new red narrative not checked previously"]
    elif damage == "missing-result":
        del document["contains_forbidden_marker"]
    elif damage == "falsey-result":
        document["contains_forbidden_marker"] = 0
    elif damage == "empty-requests":
        document["request_sha256s"] = []
    elif damage == "invalid-hash":
        document["request_sha256s"] = ["not a request digest"]
    path.write_text("{" if damage == "invalid-json" else
                    json.dumps(["not an object"] if damage == "non-object" else document))
    result, decision = review.decide(review.run(previous=fresh))
    assert decision.state is ClaimState.SUPPORTED
    assert any(gap.reason == "verifier_request_check_unavailable" for gap in result.gaps)


@pytest.mark.parametrize("leak", ["narrative", "actor"])
def test_nonblind_fresh_and_reused_requests_cannot_confirm(review, leak):
    marker = ("a red narrative that must stay hidden" if leak == "narrative"
              else teams._actor(review.red).actor_id)
    if leak == "narrative":
        review.group["narratives"] = [marker]
    fresh = review.run(task_input={"claim_id": review.claim.claim_id, "leak": marker})
    result, decision = review.decide(fresh)
    assert decision.state is ClaimState.SUPPORTED
    assert any(gap.reason == "verifier_request_contains_forbidden_marker" for gap in result.gaps)
    result, decision = review.decide(review.run(previous=fresh))
    assert decision.state is ClaimState.SUPPORTED
    assert any(gap.gap_class is GapClass.INDEPENDENCE_GAP for gap in result.gaps)


def test_real_blind_receipt_preserves_same_model_confirmation_on_reuse(review):
    fresh = review.run()
    result, decision = review.decide(fresh)
    assert decision.state is ClaimState.CONFIRMED and result.gaps == []
    check = json.loads(review.sidecar(fresh).read_text())
    assert len(check["request_sha256s"]) == len(fresh.requests) == 2
    assert check["contains_forbidden_marker"] is False
    reused = review.run(previous=fresh)
    repeated, decision = review.decide(reused)
    assert decision.state is ClaimState.CONFIRMED and repeated.gaps == []
    assert repeated.relations == result.relations
    row = repeated.independence[review.claim.claim_id][0]
    assert row["independent"] and not row["provider_distinct"] and not row["verifier_model_distinct"]


def test_blind_request_without_verifier_read_lineage_cannot_confirm(review):
    result, decision = review.decide(review.run(retrieve=False))
    assert decision.state is ClaimState.SUPPORTED
    assert len(result.relations) == len(review.predicates)
    assert all(relation.retrieval_receipt_sha256 is None for relation in result.relations)
    assert {gap.predicate for gap in result.gaps if gap.reason == "verifier_lacks_independent_support"} == set(
        review.predicates)


def test_blind_request_with_unresolvable_citation_keeps_evidence_gaps(review):
    fresh = review.run()
    review.source.unlink()
    result, decision = review.decide(fresh)
    assert decision.state is ClaimState.INSUFFICIENT_EVIDENCE
    assert any(gap.gap_class is GapClass.EVIDENCE_GAP for gap in result.gaps)
    assert any(gap.reason == "verifier_lacks_independent_support" for gap in result.gaps)
