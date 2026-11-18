from appsec_review.reporting.dossiers import _build_classification_badge
from appsec_review.reporting.executive_posture import (
    build_attack_chain_cards, build_executive_posture, build_remediation_roadmap,
)


def test_ship_block_decision_not_severity_or_chain_membership_controls_banner():
    report = {
        "findings": [{"claim_id": "c", "ship_block": {"technical_severity": "critical"}}],
        "attack_chains": {"items": [{"chain_id": "chain", "status": "confirmed", "component_claim_ids": ["c"]}]},
        "status": {"review_complete": True}, "summary": {"ship_block": {"by_status": {"not_ship_blocking": 1}}},
    }
    radar = {"coverage_confidence": {"gap_axes": 0, "verified_axes": 12, "confidence_score": 100,
                                     "summary_statement": "Recorded coverage"}, "axes": []}
    assert build_executive_posture(report, radar)["release_readiness"] == "READY_WITH_RESIDUAL_ACCEPTANCE"
    report["summary"]["ship_block"]["by_status"] = {"ship_blocking": 1}
    report["findings"][0]["ship_block"]["technical_severity"] = "low"
    assert build_executive_posture(report, radar)["release_readiness"] == "BLOCK_RELEASE"


def test_chain_rating_only_comes_from_the_manifest_and_proposals_are_not_verified():
    report = {
        "findings": [{"finding_package_id": "f", "claim_id": "c", "ship_block": {"technical_severity": "critical"}}],
        "attack_chains": {"items": [{"chain_id": "chain", "status": "confirmed", "component_claim_ids": ["c", "other"]}]},
        "remediation_planning": {"items": [{"finding": {"finding_package_id": "f"},
                                          "status": "proposal_generated", "plan": {"patch": "proposed"}}]},
    }
    card = build_attack_chain_cards(report)[0]
    assert (card["composed_severity"], card["severity_gap"], card["gap_count"]) == (
        "unrated", "chain_severity_unrated", 1)
    card = build_attack_chain_cards(report, manifest_items=[{"chain_id": "chain", "composed_severity": "low"}])[0]
    assert (card["composed_severity"], card["severity_gap"]) == ("low", None)
    assert build_remediation_roadmap(report)[0]["validation_status"] == "proposal_only"
    report["remediation_validation"] = {"items": [{"finding": {"finding_package_id": "f"}, "status": "static_checked"}]}
    assert build_remediation_roadmap(report)[0]["validation_status"] == "static_checked"


def test_adjudication_confirmation_does_not_imply_reachability():
    badge = _build_classification_badge(
        state="confirmed", title="Finding", weakness_cwe="", security_predicate="", ship_block={},
        evidence=[], sources=[], claim={})
    assert badge["reachability_badge"] == "unknown"
