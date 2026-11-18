"""Focused T-173 unit tests for Round 2 requests_evidence fulfillment, thinking token floors, and 6-step chains."""
from __future__ import annotations

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

ROOT = Path(__file__).resolve().parents[3]


class _FakeCore:
    def __init__(self, records: dict[str, dict]) -> None:
        self._records = records

    def find(self, *, identity: str = "", limit: int = 1) -> dict:
        rec = self._records.get(identity)
        return {"results": [rec]} if rec is not None else {"results": []}


def test_round2_requests_evidence_fulfillment_bounded_and_counted() -> None:
    assert DEFAULT_MAX_EVIDENCE_REQUESTS == 4
    records = {
        "asr:symbol:parse_token": {
            "entity_id": "asr:symbol:parse_token",
            "kind": "symbol",
            "name": "parse_token",
            "index": "code_graph",
            "shard_id": "shard-1",
            "shard_sha256": "a" * 64,
            "content_sha256": "b" * 64,
            "source_location": {"path": "src/auth.py", "start_line": 40, "end_line": 58},
            "payload": {"guard_polarity": "auth_or_role_check", "resolution_tier": "hybrid_fused"},
        },
        "asr:flow:sql_sink": {
            "entity_id": "asr:flow:sql_sink",
            "kind": "taint_flow",
            "name": "run_export_query",
            "index": "cpg",
            "shard_id": "shard-2",
            "shard_sha256": "c" * 64,
            "content_sha256": "d" * 64,
            "source_location": {"path": "src/export.py", "start_line": 75, "end_line": 82},
            "payload": {"resolution_tier": "codeql_semantic"},
        },
    }
    core = _FakeCore(records)
    requests = [
        {"request_id": "req-1", "claim_id": "c-1", "predicate": "authz_bypass", "need": "Check parse_token in src/auth.py:45", "anchors": ["asr:symbol:parse_token"]},
        {"request_id": "req-2", "claim_id": "c-1", "predicate": "sql_injection", "need": "Verify sink at src/export.py:77", "anchors": []},
        {"request_id": "req-3", "claim_id": "c-1", "predicate": "sql_injection", "need": "Unrelated widget zzz_not_found", "anchors": []},
        {"request_id": "req-4", "claim_id": "c-1", "predicate": "sql_injection", "need": "Another missing target qqq_missing", "anchors": []},
        {"request_id": "req-5-overflow", "claim_id": "c-1", "predicate": "sql_injection", "need": "parse_token overflow", "anchors": ["asr:symbol:parse_token"]},
    ]
    outcome = fulfill_evidence_requests(
        core,
        package_entities=list(records.keys()),
        pending_requests=requests,
        unfulfilled_prior=1,
        max_requests=4,
    )
    assert outcome.fulfilled_count == 2
    assert outcome.unfulfilled_count == 4
    assert len(outcome.fulfilled_items) == 2
    assert outcome.fulfilled_items[0]["resolved_citations"][0]["guard_polarity"] == "auth_or_role_check"
    assert outcome.fulfilled_items[1]["resolved_citations"][0]["resolution_tier"] == "codeql_semantic"
    assert set(outcome.extra_entities) == {"asr:symbol:parse_token", "asr:flow:sql_sink"}


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
