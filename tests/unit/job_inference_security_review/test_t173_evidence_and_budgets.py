"""Focused T-173 unit tests for Round 2 requests_evidence fulfillment, thinking token floors, and 6-step chains."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.config.inference_review import ModelProfileSettings
from appsec_review.review.chain_composition import (
    ChainStepFinding,
    DEFAULT_MAX_CHAIN_STEPS,
    evaluate_chain_elevation,
)
from appsec_review.jobs.job_inference_security_review.evidence_fulfillment import (
    DEFAULT_MAX_EVIDENCE_REQUESTS,
    attach_querying_skill_to_bundle,
    fulfill_evidence_requests,
)
from appsec_review.jobs.job_inference_security_review.schemas import schema_set
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore,
    SourceLocation, write_manifest,
)
from appsec_review.review.evidence_obligations import (
    RequestSubmission, coalesce_obligations, pending_followup_requests,
)
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import Claim, ClaimState, Lane, Predicate, SecurityPredicate
from appsec_review.storage import file_sha256

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def evidence_core(tmp_path):
    run_id = "2026-11-19-0001"
    run_root = tmp_path / "runs" / run_id
    target = tmp_path / "target"
    target.mkdir()
    snapshot = "target-sha256:" + "1" * 64
    index_path = run_root / "data" / "analysis.sqlite"
    builder = IndexBuilder(index_path, name="analysis", fingerprint="2" * 64,
                           target_snapshot=snapshot, shard_id="symbols")
    identities = {}
    for name, path, start in (("parse_token", "src/auth.py", 40),
                              ("run_export_query", "src/export.py", 75)):
        identity = LogicalIdentity.derive(EntityKind.SYMBOL, snapshot, {"name": name})
        identities[name] = identity.value
        location = SourceLocation(snapshot, path, "3" * 64, 0, 100, start, start + 10, 1, 1,
                                  {"native": name}, "fixture-exact", 1.0)
        builder.add_entity(EntityRecord(
            identity, name, name, name,
            {"guard_polarity": "auth_or_role_check", "resolution_tier": "hybrid_fused"}, location))
    opaque = LogicalIdentity.derive(EntityKind.SYMBOL, snapshot, {"name": "opaque"})
    builder.add_entity(EntityRecord(opaque, "opaque", "opaque", "opaque", {}))
    builder.add_coverage("symbols", "complete")
    shard = IndexIdentity("analysis", "appsec-review/retrieval-index/2", builder.build(), "2" * 64,
                          index_path.relative_to(run_root).as_posix(), {}, (), "symbols")
    manifest_path = run_root / "data" / "manifest.json"
    write_manifest(manifest_path, run_id=run_id, target_snapshot=snapshot,
                   target_root=target, indexes=[shard])
    core = RetrievalCore(tmp_path / "runs", run_id, manifest_path=manifest_path,
                         manifest_sha256=file_sha256(manifest_path))
    return core, identities


def _pending(requests, affected):
    claim = Claim(
        claim_id="claim-" + "c" * 64, lane=Lane.LEAD, package_id="package",
        security_predicate=SecurityPredicate.SQL_INJECTION, affected_entities=(affected,),
        preconditions=(), weakness_cwe="CWE-89", state=ClaimState.PROPOSED,
        origin_cell_ids=(), statement="Untrusted data reaches query",
    )
    submissions = [
        RequestSubmission("evreq-" + sha256_hex({"index": i}), claim.claim_id,
                          Predicate.ATTACKER_INPUT_CONTROL, "symbol", tuple(anchors), question, round=i)
        for i, (question, anchors) in enumerate(requests)
    ]
    obligations = coalesce_obligations(submissions, claims_by_id={claim.claim_id: claim},
                                      scope_ceiling="package")
    return pending_followup_requests(obligations, max_requests=len(requests))[0]


@pytest.mark.parametrize("anchored", [True, False], ids=["anchor", "question"])
def test_round2_consumes_canonical_requests_and_retrieval_rows(evidence_core, anchored):
    core, ids = evidence_core
    entity_id = ids["parse_token"]
    pending = _pending([("Check parse_token in src/auth.py:45", [entity_id] if anchored else [])],
                       entity_id)
    outcome = fulfill_evidence_requests(core, list(ids.values()), pending)
    assert (outcome.fulfilled_count, outcome.unfulfilled_count) == (1, 0)
    item, = outcome.fulfilled_items
    assert item["obligation_id"] == pending[0]["obligation_id"]
    assert item["question"] == pending[0]["question"]
    assert item["requested_kind"] == "symbol"
    citation, = item["resolved_citations"]
    row, = core.find(identity=entity_id, limit=1)["results"]
    assert citation["entity_id"] == entity_id
    assert citation["location"] == row["location"]
    assert citation["shard_sha256"] == core.indexes["analysis"][0]["sha256"]
    assert citation["content_sha256"] == sha256_hex(row)
    assert citation["index_manifest_sha256"] == core.manifest_sha256
    assert citation["guard_polarity"] == "auth_or_role_check"


def test_round2_requests_evidence_fulfillment_bounded_and_counted(evidence_core) -> None:
    core, ids = evidence_core
    requests = [
        ("Check parse_token in src/auth.py:45", [ids["parse_token"]]),
        ("Verify sink at src/export.py:77", []),
        ("Unrelated widget zzz_not_found", []),
        ("Another missing target qqq_missing", []),
        ("parse_token overflow", [ids["parse_token"]]),
    ]
    outcome = fulfill_evidence_requests(
        core,
        package_entities=list(ids.values()),
        pending_requests=_pending(requests, ids["parse_token"]),
        unfulfilled_prior=1,
        max_requests=DEFAULT_MAX_EVIDENCE_REQUESTS,
    )
    audits = [r for r in core.log.read()[0] if r["event_type"] == "RETRIEVAL_QUERY"]
    assert audits and all(r["job_id"] == "job_inference_security_review" and
                          r["details"]["caller_kind"] == "evidence_fulfillment" for r in audits)
    assert outcome.fulfilled_count == 2
    assert outcome.unfulfilled_count == 4
    assert len(outcome.fulfilled_items) == 2
    assert outcome.fulfilled_items[0]["resolved_citations"][0]["guard_polarity"] == "auth_or_role_check"
    assert outcome.fulfilled_items[1]["resolved_citations"][0]["resolution_tier"] == "hybrid_fused"
    assert set(outcome.extra_entities) == set(ids.values())


def test_round2_zero_requests_does_not_read(evidence_core, monkeypatch):
    core, ids = evidence_core
    pending = _pending([("Check parse_token", [ids["parse_token"]])], ids["parse_token"])
    monkeypatch.setattr(core, "resolve_identities", lambda *a, **kw: pytest.fail("zero requests must not retrieve"))
    outcome = fulfill_evidence_requests(core, list(ids.values()), pending, max_requests=0)
    assert (outcome.fulfilled_count, outcome.unfulfilled_count) == (0, 1)
    assert outcome.fulfilled_items == outcome.extra_entities == ()


def test_round2_missing_and_out_of_package_evidence_stays_unfulfilled(evidence_core):
    core, ids = evidence_core
    missing = "asr:symbol:" + "f" * 64
    pending = _pending([("Unknown zzz_missing", [missing]),
                        ("Check run_export_query at src/export.py:77", [ids["run_export_query"]])],
                       ids["parse_token"])
    outcome = fulfill_evidence_requests(core, [ids["parse_token"], missing], pending)
    assert (outcome.fulfilled_count, outcome.unfulfilled_count) == (0, 2)
    assert outcome.fulfilled_items == outcome.extra_entities == ()


def test_round2_locationless_row_does_not_match_an_arbitrary_source_path(evidence_core):
    core, ids = evidence_core
    row, = core.find(name="opaque", limit=1)["results"]
    pending = _pending([("Check src/absent.py:17", [])], ids["parse_token"])
    outcome = fulfill_evidence_requests(core, [row["identity"]], pending)
    assert (outcome.fulfilled_count, outcome.unfulfilled_count) == (0, 1)


def test_review_lookup_propagates_shard_integrity_failure_without_caching_absence(evidence_core):
    from threading import Lock
    from types import SimpleNamespace
    from appsec_review.jobs.job_inference_security_review.teams import ReviewContext
    from appsec_review.retrieval.core import RetrievalIntegrityError
    from appsec_review.review.models import IntegrityError

    core, ids = evidence_core
    ctx = SimpleNamespace(core=core, _lock=Lock(), _resolves={})
    shard = core.run_root / core.indexes["analysis"][0]["relative_path"]
    with shard.open("ab") as handle:
        handle.write(b"changed after manifest verification")
    with pytest.raises(IntegrityError, match="failed verification") as failure:
        ReviewContext.resolves(ctx, ids["parse_token"])
    assert isinstance(failure.value.__cause__, RetrievalIntegrityError)
    assert ctx._resolves == {}


@pytest.mark.parametrize("status", ["timeout", "error", None])
def test_failed_lookup_cannot_fulfill_request_even_with_a_returned_row(evidence_core, monkeypatch, status):
    core, ids = evidence_core
    entity = ids["parse_token"]
    response = core.find(identity=entity, limit=1)
    assert response["results"]
    monkeypatch.setattr(core, "resolve_identities", lambda ids: {eid: {**response, "status": status} for eid in ids})
    outcome = fulfill_evidence_requests(core, [entity], _pending([("Check parse_token", [entity])], entity))
    assert (outcome.fulfilled_count, outcome.unfulfilled_count) == (0, 1)
    assert not outcome.fulfilled_items and not outcome.extra_entities


def test_round2_rejects_citation_without_accepted_shard_identity(evidence_core, monkeypatch):
    from appsec_review.review.models import IntegrityError

    core, ids = evidence_core
    entity_id = ids["parse_token"]
    response = core.find(identity=entity_id, limit=1)
    response["indexes"] = []
    monkeypatch.setattr(core, "resolve_identities", lambda ids: {eid: response for eid in ids})
    pending = _pending([("Check parse_token", [entity_id])], entity_id)
    with pytest.raises(IntegrityError, match="not bound to one accepted shard"):
        fulfill_evidence_requests(core, [entity_id], pending)


@pytest.mark.parametrize("delivered", [True, False], ids=["partial", "unavailable"])
def test_round2_retains_retrieval_qualifications(evidence_core, monkeypatch, delivered):
    core, ids = evidence_core
    entity_id = ids["parse_token"]
    response = core.find(identity=entity_id, limit=1)
    response.update(coverage_gaps=["query execution-time budget exceeded"], truncated=True)
    if not delivered:
        response["results"] = []
    monkeypatch.setattr(core, "resolve_identities", lambda ids: {eid: response for eid in ids})
    pending = _pending([("Check parse_token", [entity_id])], entity_id)
    outcome = fulfill_evidence_requests(core, [entity_id], pending)
    assert (outcome.fulfilled_count, outcome.unfulfilled_count) == (int(delivered), int(not delivered))
    if delivered:
        citation, = outcome.fulfilled_items[0]["resolved_citations"]
        assert citation["coverage_gaps"] == response["coverage_gaps"]
        assert citation["truncated"] is True
    else:
        assert outcome.fulfilled_items == ()


@pytest.fixture
def review_context(evidence_core):
    from appsec_review.config import load_config
    from appsec_review.jobs.job_inference_security_review.job import _taxonomy
    from appsec_review.jobs.job_inference_security_review.teams import ReviewContext
    from appsec_review.review.budget import JobBudget
    from appsec_review.review.models import Role
    from appsec_review.review.teams import ReviewTeamSemaphore

    core, _ = evidence_core
    settings = load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").typed_settings
    settings = replace(settings, models={name: replace(profile, max_queries=0)
                                        for name, profile in settings.models.items()})
    vocabulary, crosswalk = _taxonomy(ROOT)
    return ReviewContext(
        run_root=core.run_root, run_id=core.run_id, repository_root=ROOT, settings=settings,
        core=core, infer=lambda *a, **kw: pytest.fail("no model should be called during construction"),
        receipts_root=core.run_root / "data" / "cells",
        budget=JobBudget.for_run(core.run_root, settings.budgets),
        semaphore=ReviewTeamSemaphore.for_run(core.run_root, 1),
        vocabulary=vocabulary, crosswalk=crosswalk, covers={},
        role_tools={role.value: ("find",) for role in Role}, schemas=schema_set(ROOT),
        accepted_cwe_ids=frozenset(), rule_predicates={}, source_languages={},
        build_unit_languages={}, index_names=("analysis",), available_sources=(),
    )


def test_round2_deliveries_reach_discovery_cells_without_new_grants(review_context, evidence_core):
    from appsec_review.jobs.job_inference_security_review import teams

    ctx = review_context
    core, ids = evidence_core
    entity_id = ids["parse_token"]
    pending = _pending([("Check parse_token at src/auth.py:45", [entity_id])], entity_id)
    delivered = fulfill_evidence_requests(core, [entity_id], pending)
    work = teams.PackageWork(
        "package", Lane.LEAD, "4" * 64, {}, (1, "package"), "basis", (entity_id,), None,
        round_index=1, pending_requests=pending, fulfilled_evidence=delivered.fulfilled_items)
    cells = teams._red_cells(ctx, work, {"stack": "generic", "persona": "generalist"})
    assert cells
    for cell in cells:
        request, = cell.spec.task_input["evidence_requests"]
        fulfillment, = cell.spec.task_input["fulfilled_evidence"]
        assert request["obligation_id"] == fulfillment["obligation_id"] == pending[0]["obligation_id"]
        assert request["question"] == fulfillment["question"] == pending[0]["question"]
        citation, = fulfillment["resolved_citations"]
        assert citation["label"] == request["anchors"][0] != "?"
        assert citation["location"]["file_sha256"] == "3" * 64
        assert cell.capability.entities == (entity_id,)
        assert cell.capability.max_queries == 0


@pytest.mark.parametrize("kind", ["team", "composer", "refuter", "weakest_link_verifier"])
def test_zero_query_profile_is_not_widened_in_cell_construction(review_context, kind):
    from appsec_review.jobs.job_inference_security_review import chains, teams
    from appsec_review.review.capability import AuthorityDenied
    from appsec_review.review.models import Role

    ctx = review_context
    if kind == "team":
        work = teams.PackageWork("package", Lane.LEAD, "4" * 64, {}, (1, "package"), "basis", (), None)
        cell = teams._cell(ctx, work, {"stack": "generic"}, role=Role.RED_TEAM_ANALYST,
                           persona="generalist", task=teams.LEAD_LENSES[0], kind="red", task_input={})
    else:
        cell = chains._cell(ctx, kind, {}, (), "package")
    assert cell.capability.max_queries == 0
    cell.capability.verify()
    request = {"tool": "find", "parameters": {"name": "parse_token"}}
    decision = cell.capability.authorize(request)
    assert isinstance(decision, AuthorityDenied)
    assert decision.code == "query_cap_exceeded"
    assert cell.capability.indexes == ("analysis",)
    assert set(cell.capability.tools) <= {"find", "expand"}


@pytest.mark.parametrize("action", ["final", "retrieve"])
def test_zero_query_cell_is_final_only_and_never_retrieves(tmp_path, action):
    from appsec_review.review.models import CellStatus
    from tests.review.test_cells import FakeCore, ScriptedInfer, capability, final, retrieve, run

    core = FakeCore()
    turn = final() if action == "final" else retrieve({"tool": "search", "parameters": {"query": "token"}})
    infer = ScriptedInfer(turn)
    outcome = run(tmp_path, infer, cap=capability(max_queries=0), core=core)
    assert core.calls == []
    assert outcome.counts["queries"] == 0
    assert len(infer.requests) == 1
    assert infer.requests[0].task_input["capability"]["max_queries"] == 0
    receipt = json.loads(outcome.receipt_paths[0].read_text())
    assert receipt["turns"][0]["final_required"] is True
    assert receipt["turns"][0]["retrievals"] == []
    if action == "final":
        assert outcome.record.status is CellStatus.SUCCEEDED
        assert outcome.gaps == ()
    else:
        assert outcome.record.status is CellStatus.TIMED_OUT
        assert any(gap.reason == "cap_reached_without_final" for gap in outcome.gaps)


@pytest.mark.parametrize(
    ("reasoning", "configured", "expected"),
    [
        ("high", 1200, 1200),
        ("medium", 2048, 2048),
        ("xhigh", 8192, 8192),
        ("max", 1024, 1024),
        ("low", 1200, 1200),
        ("none", 1200, 1200),
    ],
)
def test_thinking_output_cap_is_not_silently_raised(reasoning: str, configured: int, expected: int) -> None:
    profile = ModelProfileSettings(
        provider="openai",
        model="gpt-5.3-codex",
        reasoning=reasoning,
        max_input_tokens=32000,
        max_output_tokens=configured,
        max_queries=6,
        max_turns=4,
        timeout_seconds=120,
    )
    assert profile.max_output_tokens == expected


def test_explicit_thinking_floor_rejects_inconsistent_profile() -> None:
    with pytest.raises(ValueError, match="max_output_tokens must be >= thinking_min_output_tokens"):
        ModelProfileSettings(
            provider="openai", model="reasoner", reasoning="high", max_input_tokens=32000,
            max_output_tokens=1200, max_queries=6, max_turns=4, timeout_seconds=120,
            thinking_min_output_tokens=4096)


def test_selected_querying_guidance_cannot_silently_fall_back(tmp_path):
    from appsec_review.guidance.fragments import GuidanceError
    from appsec_review.review.models import Role

    bundle = {"sections": [{"name": "procedures", "items": []}]}
    with pytest.raises(GuidanceError):
        attach_querying_skill_to_bundle(tmp_path, bundle, role=Role.HYPOTHESIS_HUNTER, task="sink_up")


def test_six_step_chain_elevation_and_inference_schemas() -> None:
    assert DEFAULT_MAX_CHAIN_STEPS == 6
    steps = [
        ChainStepFinding("claim-" + "1" * 64, "spec_drift", standalone_severity="medium", unit_key="gateway", trust_boundary="public_edge", has_spec_drift=True),
        ChainStepFinding("claim-" + "2" * 64, "ssrf", standalone_severity="medium", unit_key="proxy", trust_boundary="dmz"),
        ChainStepFinding("claim-" + "3" * 64, "authn_bypass", standalone_severity="medium", unit_key="auth", trust_boundary="internal_mesh"),
        ChainStepFinding("claim-" + "4" * 64, "sql_injection", standalone_severity="medium", weakness_cwe="CWE-89", unit_key="billing_db", trust_boundary="data_plane"),
    ]
    composed, crossings = evaluate_chain_elevation(steps)
    assert composed == "critical"
    assert len(crossings) >= 3

    schemas = schema_set(ROOT)
    crossing_dicts = [c.to_json() for c in crossings]
    finding_pkg = {
        "schema": "appsec-review/finding-package/2",
        "finding_package_id": "finding-" + "a" * 64,
        "claim_id": "claim-" + "1" * 64,
        "lane": "lead",
        "state": "confirmed",
        "label": "confirmed",
        "title": "Spec drift to internal SQL injection chain",
        "adjudication_id": "adjudication-" + "c" * 64,
        "direct_evidence": ["evrel-" + "e" * 64],
        "analyst_assessed_evidence": [],
        "missing_predicates": [],
        "verification_review_id": "review-" + "b" * 64,
        "scores": ["score-" + "d" * 64],
        "poc": None,
        "attack_chains": ["chain-" + "f" * 64],
        "remediation_inputs": {"safe_regression_artifact": None},
        "independence": {
            "independent": True,
            "provider_distinct": True,
            "verifier_model_distinct": True,
            "judge_model_distinct": None,
        },
        "judge_verdict": None,
        "lead_severities": [],
        "ship_block": {
            "policy": "ship-block-policy/1",
            "policy_sha256": "0" * 64,
            "status": "not_ship_blocking",
            "conditions": {
                "claim_confirmed": True,
                "claim_supported": True,
                "technical_severity_qualifies": False,
                "dependency_finding": False,
                "kev_dependency_qualifies": False,
                "distinct_verification_required": True,
                "verifier_model_distinct": True,
                "decision_input_missing": False,
            },
            "reasons": ["standalone_medium_elevated_by_chain"],
            "inputs": {
                "claim_state": "confirmed",
                "technical_severity": {
                    "provider": "application_risk_matrix/3",
                    "rating": "medium",
                    "score_id": "score-" + "d" * 64,
                    "severity_floor": "low",
                    "severity_ceiling": "critical",
                    "missing_factors": [],
                },
                "lead_families": ["codeql"],
                "kev_listed": None,
                "verifier_model_distinct": True,
            },
            "citations": {
                "adjudication_id": "adjudication-" + "c" * 64,
                "score_ids": ["score-" + "d" * 64],
                "verification_review_id": "review-" + "b" * 64,
            },
            "displayed_context": {
                "decides": False,
                "reference_cvss": [],
                "non_deciding_scores": [],
            },
        },
        "gaps": [],
        "provenance": {
            "run_manifest_sha256": "1" * 64,
            "ledger_head_sha256": "2" * 64,
        },
        "composed_severity": composed,
        "chain_boundary_crossings": crossing_dicts,
    }
    schemas.validate("finding-package", finding_pkg)
