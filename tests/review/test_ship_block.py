"""ship-block-policy/1 (decision 1) with the decision 2 distinct-verification condition."""
from __future__ import annotations

from dataclasses import replace

import pytest

from appsec_review.review.models import ClaimState
from appsec_review.review.ship_block import (
    POLICY_VERSION, ShipBlockInputs, ShipBlockSettings, ShipBlockStatus, decide, policy_sha256, summarize,
)

BASE = ShipBlockInputs(claim_state=ClaimState.CONFIRMED, technical_severity="high", severity_score_id="score-x",
                       lead_families=("codeql",), kev_listed=None, verifier_model_distinct=True)
KEV_DEPENDENCY = replace(BASE, technical_severity="low", lead_families=("dependency_advisory",), kev_listed=True)


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_confirmed_high_or_critical_with_distinct_verification_blocks(severity: str) -> None:
    decision = decide(replace(BASE, technical_severity=severity))
    assert decision.status is ShipBlockStatus.SHIP_BLOCKING
    assert decision.conditions["technical_severity_qualifies"] and decision.reasons == (f"technical_severity_{severity}",)


@pytest.mark.parametrize("severity", ["low", "medium", None])
def test_confirmed_below_the_threshold_does_not_block(severity) -> None:
    decision = decide(replace(BASE, technical_severity=severity))
    assert decision.status is ShipBlockStatus.NOT_SHIP_BLOCKING
    assert ("technical_severity_unrated" in decision.reasons) is (severity is None)


def test_kev_listed_dependency_finding_blocks_whatever_its_severity() -> None:
    decision = decide(KEV_DEPENDENCY)
    assert decision.status is ShipBlockStatus.SHIP_BLOCKING and decision.reasons == ("kev_listed_dependency",)
    assert decision.conditions["dependency_finding"] and decision.conditions["kev_dependency_qualifies"]
    assert decide(replace(KEV_DEPENDENCY, lead_families=("artifact_scanner",))).status is ShipBlockStatus.SHIP_BLOCKING


@pytest.mark.parametrize("change", [
    {"kev_listed": False}, {"kev_listed": None},                 # not KEV-listed (or no advisory context)
    {"lead_families": ("codeql",)}, {"lead_families": ()},       # KEV-listed but not a dependency finding
])
def test_kev_needs_both_a_dependency_finding_and_a_kev_listing(change) -> None:
    assert decide(replace(KEV_DEPENDENCY, **change)).status is ShipBlockStatus.NOT_SHIP_BLOCKING


def test_supported_that_would_qualify_needs_verification_and_never_blocks() -> None:
    for inputs in (BASE, KEV_DEPENDENCY):
        decision = decide(replace(inputs, claim_state=ClaimState.SUPPORTED))
        assert decision.status is ShipBlockStatus.NEEDS_VERIFICATION and "claim_not_confirmed" in decision.reasons
    low = replace(BASE, claim_state=ClaimState.SUPPORTED, technical_severity="medium")
    assert decide(low).status is ShipBlockStatus.NOT_SHIP_BLOCKING
    # A supported claim never blocks even with distinct verification and the requirement off.
    assert decide(replace(BASE, claim_state=ClaimState.SUPPORTED),
                  require_distinct_model=False).status is ShipBlockStatus.NEEDS_VERIFICATION


@pytest.mark.parametrize("state", [ClaimState.CONTRADICTED, ClaimState.INSUFFICIENT_EVIDENCE, ClaimState.NOT_REACHABLE])
def test_other_states_never_block(state: ClaimState) -> None:
    assert decide(replace(BASE, claim_state=state)).status is ShipBlockStatus.NOT_SHIP_BLOCKING


def test_same_model_verification_is_pending_distinct_verification() -> None:
    for inputs in (BASE, KEV_DEPENDENCY):
        decision = decide(replace(inputs, verifier_model_distinct=False))
        assert decision.status is ShipBlockStatus.PENDING_DISTINCT_VERIFICATION
        assert "verifier_model_not_distinct" in decision.reasons
    # Turning the requirement off publishes the same finding as ship_blocking.
    off = decide(replace(BASE, verifier_model_distinct=False), require_distinct_model=False)
    assert off.status is ShipBlockStatus.SHIP_BLOCKING and not off.conditions["distinct_verification_required"]
    # Below the threshold, distinctness is irrelevant.
    low = replace(BASE, technical_severity="medium", verifier_model_distinct=False)
    assert decide(low).status is ShipBlockStatus.NOT_SHIP_BLOCKING


def test_cvss_and_ssvc_never_decide() -> None:
    """Only the application_risk_matrix/2 rating is an input; CVSS context is displayed, never read."""
    decision = decide(replace(BASE, technical_severity="low"))
    record = decision.record(replace(BASE, technical_severity="low"), adjudication_id="adjudication-x",
                             verification_review_id=None, displayed_context={
                                 "reference_cvss": [{"cve_id": "CVE-2026-0001", "version": "3.1",
                                                     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                                     "base_score": 9.8}],
                                 "non_deciding_scores": ["score-cvss"]})
    assert decision.status is ShipBlockStatus.NOT_SHIP_BLOCKING
    assert record["displayed_context"]["decides"] is False
    assert record["inputs"]["technical_severity"]["provider"] == "application_risk_matrix/2"
    assert record["citations"] == {"adjudication_id": "adjudication-x", "score_ids": ["score-x"],
                                   "verification_review_id": None}
    assert record["policy"] == POLICY_VERSION


def test_configured_thresholds_override_the_defaults() -> None:
    critical_only = ShipBlockSettings(blocking_technical_severities=("critical",))
    assert decide(BASE, critical_only).status is ShipBlockStatus.NOT_SHIP_BLOCKING
    assert decide(replace(BASE, technical_severity="critical"), critical_only).status is ShipBlockStatus.SHIP_BLOCKING
    with_medium = ShipBlockSettings(blocking_technical_severities=("medium", "high", "critical"))
    assert decide(replace(BASE, technical_severity="medium"), with_medium).status is ShipBlockStatus.SHIP_BLOCKING
    no_kev = ShipBlockSettings(kev_dependency_blocks=False)
    assert decide(KEV_DEPENDENCY, no_kev).status is ShipBlockStatus.NOT_SHIP_BLOCKING
    sca_only = ShipBlockSettings(dependency_lead_families=("dependency_advisory",))
    assert decide(replace(KEV_DEPENDENCY, lead_families=("artifact_scanner",)), sca_only).status is \
        ShipBlockStatus.NOT_SHIP_BLOCKING
    # The policy identity changes with every threshold and with the distinctness requirement.
    hashes = {policy_sha256(item, True) for item in (ShipBlockSettings(), critical_only, no_kev, sca_only)}
    assert len(hashes) == 4 and policy_sha256(ShipBlockSettings(), False) not in hashes


@pytest.mark.parametrize("value,message", [
    ({"blocking_technical_severities": []}, "at least one band"),
    ({"blocking_technical_severities": ["severe"]}, "unknown bands"),
    ({"blocking_technical_severities": ["high", "high"]}, "distinct"),
    ({"kev_dependency_blocks": "yes"}, "Boolean"),
    ({"dependency_lead_families": ["npm"]}, "unknown lead families"),
    ({"cvss_threshold": 7.0}, "unknown settings"),
])
def test_settings_are_validated(value, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ShipBlockSettings.from_mapping(value, "ship_block", known_families=("dependency_advisory", "artifact_scanner"))


def test_decisions_are_deterministic_and_summaries_count_every_status_per_lane() -> None:
    assert decide(BASE) == decide(BASE)
    summary = summarize([{"lane": "lead", "status": "ship_blocking"}, {"lane": "hunt", "status": "needs_verification"},
                         {"lane": "lead", "status": "ship_blocking"}])
    assert summary["by_status"] == {"ship_blocking": 2, "ship_blocking_pending_distinct_verification": 0,
                                    "needs_verification": 1, "not_ship_blocking": 0}
    assert summary["by_lane"]["lead"]["ship_blocking"] == 2 and summary["by_lane"]["hunt"]["needs_verification"] == 1
