"""Actionability: can a developer act on a published finding as written? (T-069)."""
from __future__ import annotations

import copy

import pytest

from appsec_review.observability.findings import actionability as a
from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings.identity import fingerprint

FULL = {"entry_to_sink_path": True, "preconditions": True, "remediation": True, "remediation_validated": True}


def finding(finding_id="F1", **changes):
    value = {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "lane": "lead", "locations": [{"path": "src/net/parse.c", "start_line": 10, "end_line": 12,
                                            "function": f"fn_{finding_id}", "code": "strcpy(b, p);"}]}
    value.update(changes)
    return value


def complete(finding_id, **changes):
    return finding(finding_id, **{"actionability": dict(FULL), "owner": "net-team",
                                  "attacker_position": "client_to_server", **changes})


def snapshot(findings):
    return c.build_snapshot(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                            fingerprint=fingerprint)


def test_item_vocabulary():
    assert a.ACTIONABILITY_ITEMS == ("entry_to_sink_path", "preconditions", "remediation", "remediation_validated",
                                     "owner", "attacker_position")
    assert a.COMPLETENESS_ITEMS == ("entry_to_sink_path", "preconditions", "remediation", "owner",
                                    "attacker_position")


def test_completeness_counts_present_absent_and_unknown_per_item():
    built = snapshot([
        complete("A"),
        complete("B", actionability={**FULL, "remediation_validated": False}, severity="critical"),
        complete("C", actionability={**FULL, "remediation_validated": None}, state="supported"),
        complete("D", actionability={**FULL, "remediation": False}),
        complete("E", actionability={"entry_to_sink_path": True}, owner=None),
        finding("F", severity=None),
        complete("G", attacker_position=None),
        complete("X", state="contradicted"),
    ])
    before = copy.deepcopy(built)
    result = a.completeness(built)
    assert built == before
    assert result["available"] is True and result["published"] == 7
    assert list(result["items"]) == list(a.ACTIONABILITY_ITEMS)
    assert result["items"]["entry_to_sink_path"] == {"present": 6, "absent": 0, "unknown": 1,
                                                     "share": c.ratio(6, 7, interval=True)}
    assert result["items"]["preconditions"] == {"present": 5, "absent": 0, "unknown": 2,
                                                "share": c.ratio(5, 7, interval=True)}
    assert result["items"]["remediation"] == {"present": 4, "absent": 1, "unknown": 2,
                                              "share": c.ratio(4, 7, interval=True)}
    assert result["items"]["remediation_validated"] == {"present": 3, "absent": 1, "unknown": 3,
                                                        "share": c.ratio(3, 7, interval=True)}
    assert result["items"]["owner"] == {"present": 5, "absent": 2, "unknown": 0,
                                        "share": c.ratio(5, 7, interval=True)}
    assert result["items"]["attacker_position"] == {"present": 5, "absent": 2, "unknown": 0,
                                                    "share": c.ratio(5, 7, interval=True)}
    assert result["complete"] == {"count": 3, "share": c.ratio(3, 7, interval=True), "finding_ids": ["A", "B", "C"]}
    assert result["per_finding"] == [
        {"finding_id": "A", "severity": "high", "missing": []},
        {"finding_id": "B", "severity": "critical", "missing": ["remediation_validated"]},
        {"finding_id": "C", "severity": "high", "missing": ["remediation_validated"]},
        {"finding_id": "D", "severity": "high", "missing": ["remediation"]},
        {"finding_id": "E", "severity": "high", "missing": ["owner", "preconditions", "remediation",
                                                           "remediation_validated"]},
        {"finding_id": "F", "severity": None, "missing": ["attacker_position", "entry_to_sink_path", "owner",
                                                         "preconditions", "remediation", "remediation_validated"]},
        {"finding_id": "G", "severity": "high", "missing": ["attacker_position"]},
    ]
    assert result["per_finding_truncated"] == 0
    for item in result["items"].values():
        assert item["present"] + item["absent"] + item["unknown"] == 7


@pytest.mark.parametrize("change, missing", [
    ({"actionability": {**FULL, "entry_to_sink_path": False}}, "entry_to_sink_path"),
    ({"actionability": {**FULL, "preconditions": None}}, "preconditions"),
    ({"actionability": {**FULL, "remediation": None}}, "remediation"),
    ({"attacker_position": None}, "attacker_position"),
    ({"owner": None}, "owner"),
], ids=["path", "preconditions", "remediation", "attacker", "owner"])
def test_each_required_item_alone_makes_a_finding_incomplete(change, missing):
    result = a.completeness(snapshot([complete("A", **change)]))
    assert result["complete"] == {"count": 0, "share": c.ratio(0, 1, interval=True), "finding_ids": []}
    assert result["per_finding"] == [{"finding_id": "A", "severity": "high", "missing": [missing]}]


def test_a_validated_remediation_is_reported_but_not_required():
    result = a.completeness(snapshot([complete("A", actionability={**FULL, "remediation_validated": False})]))
    assert result["complete"]["count"] == 1 and result["complete"]["share"]["value"] == 1.0
    assert result["items"]["remediation_validated"]["share"]["value"] == 0.0


def test_no_published_finding_gives_empty_denominators_not_zeros():
    for built in (snapshot([]), snapshot([complete("A", state="contradicted")])):
        result = a.completeness(built)
        assert result["published"] == 0 and result["per_finding"] == [] and result["per_finding_truncated"] == 0
        shares = [item["share"] for item in result["items"].values()] + [result["complete"]["share"]]
        assert len(shares) == 7
        for share in shares:
            assert (share["value"], share["status"], share["interval"]) == (None, "empty_denominator", None)


def test_shares_carry_a_wilson_interval():
    result = a.completeness(snapshot([complete("A"), finding("B")]))
    share = result["items"]["owner"]["share"]
    assert share["value"] == 0.5 and share["interval"] == c.wilson(1, 2)
    assert result["complete"]["share"]["interval"] == c.wilson(1, 2)


def test_per_finding_listing_truncates_at_its_exact_bound():
    def built(count):
        return snapshot([finding(f"F{index:04d}") for index in range(count)])

    exact = a.completeness(built(a.MAX_PER_FINDING_ROWS))
    assert len(exact["per_finding"]) == a.MAX_PER_FINDING_ROWS and exact["per_finding_truncated"] == 0
    over = a.completeness(built(a.MAX_PER_FINDING_ROWS + 1))
    assert len(over["per_finding"]) == a.MAX_PER_FINDING_ROWS and over["per_finding_truncated"] == 1
    assert over["per_finding"][-1]["finding_id"] == "F0499"
    assert over["published"] == 501 and over["items"]["owner"]["absent"] == 501, "the counts are never truncated"


def test_completeness_is_deterministic_and_refuses_a_foreign_snapshot():
    one = a.completeness(snapshot([complete("B"), finding("A")]))
    two = a.completeness(snapshot([finding("A"), complete("B")]))
    assert c.digest(one) == c.digest(two)
    with pytest.raises(ValueError):
        a.completeness({"schema": "other"})
