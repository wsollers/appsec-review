from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_inference_security_review.teams import (
    PackageWork, TeamResult, _normalize, _review, _seal, _triage,
)
from appsec_review.review.models import CellStatus, Lane
from appsec_review.storage import canonical_json

from .helpers import BLUE, JUDGE, RED, VERIFIER, fixture


@pytest.mark.parametrize("reason", ["active", "package", "admitted", "repeated", "unresolvable"])
def test_actual_triage_capture_preserves_original_membership_and_state(tmp_path, reason):
    f = fixture(tmp_path)
    claim = next(iter(f.inputs.projection.claims.values())).claim
    work = PackageWork("package-1", Lane.HUNT if reason == "unresolvable" else Lane.LEAD,
                       "a" * 64, {}, (0, "package-1"), "b" * 64, (), None)
    settings = SimpleNamespace(
        lanes=SimpleNamespace(lead_max_claims_per_package=0 if reason == "package" else 10,
                              hunt_max_claims_per_package=10),
        rounds=SimpleNamespace(max_active_claims=0 if reason == "active" else 10))
    cell = SimpleNamespace(cell_id=RED, record=f.inputs.projection.cells[RED][0])
    proposal = {"local_id": "original-local-1", "proof_obligation_ids": ["proof-1"], "taint_path_ids": [],
                "affected_entities": list(claim.affected_entities), "attacker_entry": {"entity_id": None},
                "evidence_ids": [], "counterevidence_ids": []}
    red = {"proof_obligations": [{"local_id": "proof-1", "evidence_ids": ["evidence-1"]}],
           "evidence_refs": [{"local_id": "evidence-1", "entity_id": claim.affected_entities[0]}], "taint_paths": []}
    group = {"claim": claim, "items": [(cell, proposal, red, set())], "support": 0,
             "relations": [], "relation_gaps": [], "requests": []}
    team = TeamResult("package-1", work.lane, None)
    if reason == "repeated":
        team.claims.append(claim)
        team.triage.append({"claim_id": claim.claim_id, "decision": "admitted"})
    before_claim = canonical_json(claim.__dict__) if hasattr(claim, "__dict__") else repr(claim)
    _triage(SimpleNamespace(settings=settings, resolves=lambda identity: False), work, [group], team)
    assert len(team.audit_proposals) == 1
    capture = team.audit_proposals[0]
    assert capture["proposal_ref"] == "original-local-1"
    assert capture["cell_id"] == RED
    assert capture["receipt_sha256"] == cell.record.receipt_sha256
    assert (capture["claim_id"] is None) is (reason == "active")
    assert capture["decision"] == {"active": "over_cap", "package": "over_cap", "unresolvable": "rejected"}.get(
        reason, "admitted")
    assert (canonical_json(claim.__dict__) if hasattr(claim, "__dict__") else repr(claim)) == before_claim


def test_real_normalizer_records_invalid_proposal_without_claim(tmp_path):
    f = fixture(tmp_path)
    work = PackageWork("package-1", Lane.LEAD, "a" * 64, {}, (0, "package-1"), "b" * 64, (), None)
    result = {"lead_accounting": [], "gaps": [], "chain_seeds": [], "proposals": [{
        "local_id": "invalid-original", "weakness": None, "affected_entities": ["invalid-id"],
        "security_predicate": "invalid", "attacker_entry": {"preconditions": []}, "statement": "not copied"}]}
    cell = SimpleNamespace(cell_id=RED, record=f.inputs.projection.cells[RED][0],
                           outcome=SimpleNamespace(result=result, receipt_paths=()),
                           spec=SimpleNamespace(persona="general"))
    team = TeamResult("package-1", Lane.LEAD, None)
    assert _normalize(SimpleNamespace(accepted_cwe_ids=frozenset()), work, [cell], team) == []
    assert team.claims == []
    assert team.audit_proposals[0]["claim_id"] is None
    assert team.audit_proposals[0]["reason"] == "closed_vocabulary"
    assert team.audit_proposals[0]["proposal_ref"] == "invalid-original"


def test_seal_keeps_capture_but_does_not_change_lead_accounting(tmp_path):
    f = fixture(tmp_path)
    original = deepcopy(f.inputs.lanes[0].value["proposal_audit"]["items"])
    team = TeamResult("package-1", Lane.LEAD, None, leads=("lead-1",))
    team.audit_proposals = list(reversed(original))
    team.lead_entries = [(RED, "lead-1", "no_proposal")]
    document = _seal(None, Lane.LEAD, [team], {Lane.LEAD: 1, Lane.HUNT: 0},
                     tmp_path / "sealed/ledger.jsonl", "lead_review.teams")
    assert document["proposal_audit"]["items"] == original
    assert document["lead_accounting"]["package-1"]["lead-1"] == {
        "outcome": "no_proposal", "cells": {RED: "no_proposal"}}
    assert document["proposals"] == {}


@pytest.mark.parametrize("has_request", [False, True])
def test_real_review_captures_structural_checks_without_changing_r6(tmp_path, has_request):
    f = fixture(tmp_path)
    claim = next(iter(f.inputs.projection.claims.values())).claim
    cells = {}
    for identity in (RED, BLUE, JUDGE, VERIFIER):
        record = f.inputs.projection.cells[identity][0]
        cells[identity] = SimpleNamespace(
            cell_id=identity, record=record, requests=[b"fresh blind request"] if has_request else [],
            spec=SimpleNamespace(provider="same-provider", model="same-model", role=record.role, package_id="package-1"),
            capability=SimpleNamespace(body=lambda: {"round": 0}, capability_sha256="a" * 64),
            outcome=SimpleNamespace(result={"proposed_relations": []}, gaps=[], security_events=[],
                                    reused=False, reuse_source=None, memo_status=None,
                                    receipt_paths=[f.root / f.inputs.receipts[identity].source.path]))
    ctx = SimpleNamespace(run_root=tmp_path / "fresh", receipts_root=tmp_path / "fresh/cells")
    group = {"claim": claim, "cells": [cells[RED]], "narratives": ["original red narrative"]}
    team = TeamResult("package-1", Lane.LEAD, None)
    _review(ctx, group, (cells[BLUE], cells[JUDGE]), cells[VERIFIER], team)
    original = team.independence[claim.claim_id][0]
    assert original["independent"] is False
    assert original["verifier_model_distinct"] is False
    capture = original["audit"]
    assert all(capture[name] for name in ("actor_distinct", "conversation_fresh", "prior_response_absent",
                                         "shared_actor_cache_absent"))
    assert (capture["request_check"] is not None) is has_request
    assert capture["request_markers_absent"] is (True if has_request else None)
    if has_request:
        cells[VERIFIER].requests = []
        reused = TeamResult("package-1", Lane.LEAD, None)
        _review(ctx, group, (cells[BLUE], cells[JUDGE]), cells[VERIFIER], reused)
        second = reused.independence[claim.claim_id][0]
        assert second["independent"] == original["independent"]
        assert second["audit"]["request_check"] == capture["request_check"]
        assert second["audit"]["request_markers_absent"] is None
