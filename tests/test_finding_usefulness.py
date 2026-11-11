"""Volume and usefulness of the published findings: counts, severity, actionable yield, precision."""
from __future__ import annotations

import copy

import pytest

from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import usefulness as us
from appsec_review.observability.findings.identity import fingerprint


def finding(finding_id, state="confirmed", severity="high", **changes):
    value = {"finding_id": finding_id, "state": state, "weakness_cwe": "CWE-121", "severity": severity,
             "lane": "lead", "bucket": "findings",
             "locations": [{"path": "src/net/parse.c", "start_line": 10, "end_line": 12,
                            "function": f"fn_{finding_id}", "code": None}]}
    value.update(changes)
    return value


def snapshot(*findings):
    return c.build_snapshot(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                            fingerprint=fingerprint)


def labels_for(built, **outcomes):
    """``finding_id="true"`` or ``finding_id=("true", "high")`` -> labels keyed by fingerprint exact."""
    exact = {item["finding_id"]: item["fingerprint"]["exact"] for item in built["findings"]}
    table = {}
    for finding_id, value in outcomes.items():
        outcome, expected = value if isinstance(value, tuple) else (value, None)
        table[exact[finding_id]] = {"outcome": outcome, "source": "answer_key", "expected_severity": expected,
                                    "disposition": None}
    return table


def mixed():
    return snapshot(
        finding("A", "confirmed", "critical"),
        finding("B", "confirmed", "high", ship_block_status="ship_blocking"),
        finding("C", "confirmed", "medium", lane="hunt"),
        finding("D", "confirmed", None, bucket="verification_backlog"),
        finding("E", "supported", "critical", ship_block_status="decision_pending"),
        finding("F", "supported", "low", lane=None, bucket=None),
        finding("G", "supported", None, ship_block_status="decision_pending"),
        finding("H", "contradicted", "critical", bucket="withheld"),
        finding("I", "insufficient_evidence", "high", bucket="withheld"),
    )


def pair(metric):
    return metric["numerator"], metric["denominator"]


# -------------------------------------------------------------------------------------- volume

def test_volume_is_a_final_state_count_of_deduplicated_root_causes():
    same = [{"path": "a.c", "start_line": 1, "end_line": 1, "function": "f", "code": None}]
    built = snapshot(finding("A", locations=same), finding("A2", locations=same), finding("A3", locations=same),
                     finding("B", "supported", lane="hunt"), finding("C", "contradicted", lane=None, bucket=None),
                     finding("D", "supported", bucket="withheld", duplicates_collapsed=1))
    before = copy.deepcopy(built)
    assert us.volume(built) == {
        "findings": 4, "published": 3,
        "by_state": {"confirmed": 1, "contradicted": 1, "supported": 2},
        "by_bucket": {"findings": 2, "verification_backlog": 0, "withheld": 1, "null": 1},
        "by_lane": {"lead": 2, "hunt": 1, "null": 1},
        "duplicates_collapsed": 3,
        "duplicate_rate": c.ratio(3, 7)}
    assert built == before


def test_volume_of_an_empty_snapshot_has_no_duplicate_rate():
    empty = us.volume(snapshot())
    assert (empty["findings"], empty["published"], empty["by_state"]) == (0, 0, {})
    assert empty["duplicate_rate"]["value"] is None and empty["duplicate_rate"]["status"] == "empty_denominator"


# ------------------------------------------------------------------------------------ severity

def test_severity_distribution_covers_published_findings_only():
    result = us.severity(mixed())
    assert result["published"] == 7
    assert result["distribution"] == {"low": 1, "medium": 1, "high": 1, "critical": 2, "null": 2}
    assert result["by_ship_block_status"] == {
        "ship_blocking": 1, "ship_blocking_pending_distinct_verification": 0, "needs_verification": 0,
        "decision_pending": 2, "not_ship_blocking": 0, "null": 4}


def test_unrated_share_counts_missing_severity_or_a_pending_decision_once():
    result = us.severity(mixed())
    assert pair(result["unrated_share"]) == (3, 7), "D has no band, E is pending, G is both and counts once"
    assert result["unrated_share"]["interval"] == c.wilson(3, 7)
    assert us.severity(snapshot(finding("H", "contradicted")))["unrated_share"]["status"] == "empty_denominator"


# ---------------------------------------------------------------------------- actionable yield

def test_actionable_yield_separates_confirmed_from_supported_high_and_critical():
    result = us.actionable_yield(mixed())
    assert result["confirmed_actionable"] == {"count": 2, "finding_ids": ["A", "B"]}
    assert result["supported_actionable"] == {"count": 1, "finding_ids": ["E"]}
    assert result["per_reviewed_kloc"] == {"value": None, "reviewed_kloc": None,
                                           "reason": "reviewed_kloc_unavailable"}
    assert result["cost_per_confirmed_actionable"] == {"amount": None, "currency": None, "kind": None,
                                                       "reason": "cost_unavailable"}


@pytest.mark.parametrize("kloc, expected", [(4, 0.5), (0.5, 4.0), (3, 0.666667)], ids=str)
def test_actionable_yield_per_reviewed_kloc(kloc, expected):
    assert us.actionable_yield(mixed(), reviewed_kloc=kloc)["per_reviewed_kloc"] == {
        "value": expected, "reviewed_kloc": kloc, "reason": None}


@pytest.mark.parametrize("kloc", [0, -1, True, float("nan"), float("inf"), "3"], ids=repr)
def test_reviewed_kloc_must_be_a_positive_number(kloc):
    with pytest.raises(ValueError):
        us.actionable_yield(mixed(), reviewed_kloc=kloc)


@pytest.mark.parametrize("amount, expected", [("10.00", "5.000000"), ("0.10", "0.050000"), ("1", "0.500000"),
                                              ("0", "0.000000"), ("0.000001", "0.000000"), ("0.000003", "0.000002"),
                                              ("123456789012345678.123456789012", "61728394506172839.061728")],
                         ids=["dollars", "cents", "integer", "zero", "half-even-down", "half-even-up", "large"])
def test_cost_per_confirmed_actionable_is_exact_decimal_arithmetic(amount, expected):
    cost = {"amount": amount, "currency": "USD", "kind": "provider_reported"}
    before = dict(cost)
    result = us.actionable_yield(mixed(), cost=cost)["cost_per_confirmed_actionable"]
    assert result == {"amount": expected, "currency": "USD", "kind": "provider_reported", "reason": None}
    assert cost == before and isinstance(result["amount"], str)


def test_cost_divides_by_the_confirmed_count_without_binary_rounding():
    built = snapshot(*(finding(f"F{index}") for index in range(3)))
    cost = {"amount": "10", "currency": "EUR", "kind": "api_estimate"}
    assert us.actionable_yield(built, cost=cost)["cost_per_confirmed_actionable"] == {
        "amount": "3.333333", "currency": "EUR", "kind": "api_estimate", "reason": None}


def test_cost_without_a_confirmed_actionable_finding_is_null_with_a_reason():
    built = snapshot(finding("E", "supported", "critical"), finding("C", "confirmed", "medium"))
    cost = {"amount": "12.50", "currency": "USD", "kind": "api_estimate"}
    assert us.actionable_yield(built, reviewed_kloc=2, cost=cost) == {
        "confirmed_actionable": {"count": 0, "finding_ids": []},
        "supported_actionable": {"count": 1, "finding_ids": ["E"]},
        "per_reviewed_kloc": {"value": 0.0, "reviewed_kloc": 2, "reason": None},
        "cost_per_confirmed_actionable": {"amount": None, "currency": "USD", "kind": "api_estimate",
                                          "reason": "no_confirmed_actionable_findings"}}


@pytest.mark.parametrize("cost", [
    {"amount": "-1.00", "currency": "USD", "kind": "api_estimate"},
    {"amount": "NaN", "currency": "USD", "kind": "api_estimate"},
    {"amount": "Infinity", "currency": "USD", "kind": "api_estimate"},
    {"amount": "1e3", "currency": "USD", "kind": "api_estimate"},
    {"amount": 1.5, "currency": "USD", "kind": "api_estimate"},
    {"amount": "1.", "currency": "USD", "kind": "api_estimate"},
    {"amount": "1.00\n", "currency": "USD", "kind": "api_estimate"},
    {"amount": "1.00", "currency": "usd", "kind": "api_estimate"},
    {"amount": "1.00", "currency": "USDT", "kind": "api_estimate"},
    {"amount": "1.00", "currency": "USD", "kind": "guess"},
    {"amount": "1.00", "currency": "USD"},
    {"amount": "1.00", "currency": "USD", "kind": "api_estimate", "note": "x"},
    "1.00",
], ids=["negative", "nan", "infinite", "exponent", "float", "dangling-point", "newline", "lowercase", "four-letter",
        "kind", "missing", "unknown-field", "not-mapping"])
def test_cost_refuses_negative_non_finite_and_untyped_amounts(cost):
    with pytest.raises(ValueError):
        us.actionable_yield(mixed(), cost=cost)


# ----------------------------------------------------------------------------------- precision

def test_precision_is_unavailable_without_finding_labels():
    assert us.precision(mixed(), None) == {"available": False, "reason": "no_finding_labels"}
    assert us.precision_at_budget(mixed(), None, 5) == {"available": False, "reason": "no_finding_labels"}


def test_published_precision_counts_decided_labels_and_keeps_the_rest_apart():
    built = mixed()
    labels = labels_for(built, A="true", B="false", C="true", E="unresolved", F="false", H="true", I="false")
    before = copy.deepcopy((built, labels))
    result = us.precision(built, labels)
    assert (built, labels) == before and result["available"] is True
    assert result["published_precision"] == {"considered": 7, "true": 2, "false": 2, "unresolved": 1,
                                             "unlabelled": 2, "precision": c.ratio(2, 4, interval=True)}
    assert result["published_precision"]["precision"]["interval"] == c.wilson(2, 4)


def test_actionable_precision_is_restricted_to_confirmed_high_and_critical():
    built = mixed()
    result = us.precision(built, labels_for(built, A="true", B="false", C="true", E="true"))
    assert result["actionable_precision"] == {"considered": 2, "true": 1, "false": 1, "unresolved": 0,
                                              "unlabelled": 0, "precision": c.ratio(1, 2, interval=True)}


def test_precision_without_a_decided_label_is_an_empty_denominator_not_a_score():
    built = mixed()
    result = us.precision(built, labels_for(built, A="unresolved"))
    assert result["published_precision"]["precision"]["value"] is None
    assert result["published_precision"]["precision"]["status"] == "empty_denominator"
    assert (result["published_precision"]["unresolved"], result["published_precision"]["unlabelled"]) == (1, 6)
    assert us.precision(built, {})["actionable_precision"]["unlabelled"] == 2


def test_severity_agreement_compares_reported_and_expected_bands_of_published_findings():
    built = mixed()
    labels = labels_for(built, A=("true", "critical"), B=("true", "medium"), C=("true", "critical"),
                        D=("true", "high"), E=("false", "low"), F="true", H=("true", "low"))
    assert us.precision(built, labels)["severity_agreement"] == {"equal": 1, "over_rated": 2, "under_rated": 1,
                                                                 "unrated": 1}
    assert us.precision(built, {})["severity_agreement"] == {"equal": 0, "over_rated": 0, "under_rated": 0,
                                                             "unrated": 0}


@pytest.mark.parametrize("label", [{"outcome": "maybe"}, {"expected_severity": "high"}, "true",
                                   {"outcome": "true", "expected_severity": "severe"}],
                         ids=["outcome", "no-outcome", "bare", "severity"])
def test_precision_refuses_labels_outside_the_contract(label):
    with pytest.raises(ValueError):
        us.precision(mixed(), {"a" * 64: label})
    with pytest.raises(ValueError):
        us.precision_at_budget(mixed(), {"a" * 64: label}, 3)
    with pytest.raises(ValueError):
        us.precision(mixed(), [label])


def test_precision_at_budget_ranks_confirmed_first_then_severity_then_id():
    built = mixed()                 # rank: A, B, C, D, E, F, G; H and I are not published
    labels = labels_for(built, A="true", B="false", C="unresolved", E="true", F="true", H="true")
    assert us.precision_at_budget(built, labels, 1) == {
        "available": True, "budget": 1, "considered": 1, "true": 1, "false": 0, "unresolved": 0, "unlabelled": 0,
        "precision": c.ratio(1, 1, interval=True)}
    top4 = us.precision_at_budget(built, labels, 4)
    assert (top4["considered"], top4["true"], top4["false"], top4["unresolved"], top4["unlabelled"]) == (
        4, 1, 1, 1, 1)
    top5 = us.precision_at_budget(built, labels, 5)
    assert pair(top5["precision"]) == (2, 3) and top5["precision"]["interval"] == c.wilson(2, 3)


def test_precision_at_budget_orders_ties_by_finding_id_and_unrated_last():
    built = snapshot(finding("Z", "confirmed", "high"), finding("Y", "confirmed", "high"),
                     finding("X", "confirmed", None), finding("W", "supported", "critical"),
                     finding("V", "confirmed", "low"))
    for budget, last in ((1, "Y"), (2, "Z"), (3, "V"), (4, "X"), (5, "W")):
        only_last = us.precision_at_budget(built, labels_for(built, **{last: "true"}), budget)
        assert only_last["true"] == 1, f"finding {last} is ranked at position {budget}"
        if budget > 1:
            assert us.precision_at_budget(built, labels_for(built, **{last: "true"}), budget - 1)["true"] == 0


def test_precision_at_budget_reports_the_actual_count_when_fewer_are_published():
    built = mixed()
    result = us.precision_at_budget(built, labels_for(built, A="true"), us.MAX_BUDGET)
    assert (result["budget"], result["considered"], result["true"], result["unlabelled"]) == (1000, 7, 1, 6)
    assert us.precision_at_budget(snapshot(), {}, 1)["precision"]["status"] == "empty_denominator"


@pytest.mark.parametrize("budget", [0, 1001, -3, True, 2.0, "5", None], ids=repr)
def test_alert_budget_is_bounded(budget):
    with pytest.raises(ValueError):
        us.precision_at_budget(mixed(), {}, budget)
    with pytest.raises(ValueError):
        us.precision_at_budget(mixed(), None, budget)


# ---------------------------------------------------------------------------------- snapshots

@pytest.mark.parametrize("call", [
    us.volume, us.severity, us.actionable_yield, lambda value: us.precision(value, {}),
    lambda value: us.precision(value, None), lambda value: us.precision_at_budget(value, {}, 1),
], ids=["volume", "severity", "yield", "precision", "precision-unlabelled", "budget"])
def test_every_metric_refuses_a_document_that_is_not_a_finding_snapshot(call):
    built = mixed()
    with pytest.raises(ValueError):
        call({**built, "schema": "appsec-review/finding-snapshot/0"})
    with pytest.raises(ValueError):
        call({**built, "findings": [{**built["findings"][0], "fingerprint": None}]})
    with pytest.raises(ValueError):
        call(None)


def test_metrics_do_not_depend_on_the_stored_order_of_findings():
    built = mixed()
    shuffled = {**built, "findings": list(reversed(built["findings"]))}
    labels = labels_for(built, A="true", B="false", E="true")
    for call in (us.volume, us.severity, us.actionable_yield, lambda value: us.precision(value, labels),
                 lambda value: us.precision_at_budget(value, labels, 3)):
        assert c.digest(call(built)) == c.digest(call(shuffled))
