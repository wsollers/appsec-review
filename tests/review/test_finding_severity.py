import pytest

from appsec_review.review.finding_severity import resolve_finding_chain_severity


def test_preserves_standalone_and_chain_severity_without_downgrading():
    crossing = {"edge_index": 0, "from_claim_id": "medium", "to_claim_id": "critical",
                "crossing_kind": "trust_boundary", "from_scope": "edge", "to_scope": "core"}
    chains = [{"chain_id": "chain-a", "status": "confirmed",
               "step_claim_ids": ["medium", "critical"], "composed_severity": "high",
               "chain_boundary_crossings": [crossing]}]
    medium = resolve_finding_chain_severity("medium", standalone_severity="medium", chain_records=chains)
    assert medium.standalone_severity == "medium"
    assert medium.composed_severity == medium.effective_severity == "high"
    assert medium.chain_elevated and medium.attack_chain_ids == ("chain-a",)
    assert medium.chain_boundary_crossings == (crossing,)
    critical = resolve_finding_chain_severity("critical", standalone_severity="critical", chain_records=chains)
    assert critical.standalone_severity == critical.composed_severity == critical.effective_severity == "critical"
    assert not critical.chain_elevated


@pytest.mark.parametrize("status", [None, "insufficient_evidence", "refuted"])
def test_unconfirmed_chain_cannot_supply_severity(status):
    chain = {"chain_id": "chain-a", "step_claim_ids": ["c"], "composed_severity": "critical"}
    if status is not None:
        chain["status"] = status
    result = resolve_finding_chain_severity("c", standalone_severity=None, chain_records=[chain])
    assert result.effective_severity is None
    assert not result.attack_chain_ids and not result.chain_elevated
