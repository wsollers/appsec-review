"""Triage metrics: split disposition ratios, labelled effectiveness and the audit miss rate."""
from __future__ import annotations

import copy

import pytest

from appsec_review.observability import triage_reduction as tr
from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import triage as tg


def section(confirmed=3, supported=2, dismissed=7, no_claim=11, unresolved=5, **changes):
    dispositions = {"survived_confirmed": confirmed, "survived_supported": supported,
                    "dismissed_by_adjudication": dismissed, "no_claim_raised": no_claim, "unresolved": unresolved}
    value = {"schema": tr.TRIAGE_REDUCTION_SCHEMA, "available": True,
             "leads": {"collected": 40, "admitted": sum(dispositions.values())},
             "admitted_dispositions": dispositions, "accounting_complete": False,
             "reduction": {"ratio_over_resolved": 0.78}}
    value.update(changes)
    return value


def lead(lead_id, disposition="survived_confirmed", stage=None, **changes):
    if stage is None and disposition == "dismissed_by_adjudication":
        stage = "judge"
    if stage is None and disposition == "no_claim_raised":
        stage = "red_no_proposal"
    value = {"lead_id": lead_id, "admitted": disposition is not None, "disposition": disposition,
             "removed_stage": stage, "family": None, "scanner": None, "control_id": None}
    value.update(changes)
    return value


def labelled(**outcomes):
    return {lead_id: {"outcome": outcome, "source": "answer_key"} for lead_id, outcome in outcomes.items()}


def pair(metric):
    return metric["numerator"], metric["denominator"]


# -------------------------------------------------------------------------------- split ratios

@pytest.mark.parametrize("value", [None, {}, {"available": False}, tr.unavailable_section(["review_incomplete"]),
                                   {"available": "yes", "admitted_dispositions": {}}],
                         ids=["none", "empty", "false", "unavailable-section", "not-true"])
def test_split_ratios_are_unavailable_without_an_available_section(value):
    assert tg.split_ratios(value) == {"available": False, "reason": "triage_reduction_unavailable"}


def test_split_ratios_report_each_outcome_over_resolved_and_unresolved_over_admitted():
    source = section()
    before = copy.deepcopy(source)
    ratios = tg.split_ratios(source)
    assert source == before
    assert (ratios["available"], ratios["admitted"], ratios["resolved"]) == (True, 28, 23)
    assert pair(ratios["dismissed_over_resolved"]) == (7, 23)
    assert pair(ratios["no_claim_over_resolved"]) == (11, 23)
    assert pair(ratios["survived_over_resolved"]) == (5, 23)
    assert pair(ratios["unresolved_share"]) == (5, 28)
    assert ratios["unresolved_share"]["interval"] == c.wilson(5, 28)
    assert all(ratios[name]["interval"] is not None for name in ratios if name.endswith("_over_resolved"))


def test_silence_and_refutation_are_never_summed_and_no_combined_reduction_is_emitted():
    ratios = tg.split_ratios(section())
    assert not {"reduction", "ratio_over_resolved", "lower_bound_over_admitted", "reduced"} & set(ratios)
    numerators = [value["numerator"] for value in ratios.values() if isinstance(value, dict)]
    assert 7 in numerators and 11 in numerators and 18 not in numerators
    only_silence = tg.split_ratios(section(confirmed=0, supported=0, dismissed=0, no_claim=4, unresolved=0))
    assert only_silence["dismissed_over_resolved"]["value"] == 0.0
    assert only_silence["no_claim_over_resolved"]["value"] == 1.0


@pytest.mark.parametrize("complete, expected", [(False, False), (None, False), (True, True)], ids=str)
def test_split_ratios_carry_accounting_complete_through(complete, expected):
    assert tg.split_ratios(section(accounting_complete=complete))["accounting_complete"] is expected


def test_split_ratios_with_nothing_resolved_are_empty_denominators_not_zero():
    ratios = tg.split_ratios(section(confirmed=0, supported=0, dismissed=0, no_claim=0, unresolved=2))
    assert ratios["survived_over_resolved"]["value"] is None
    assert ratios["survived_over_resolved"]["status"] == "empty_denominator"
    assert ratios["unresolved_share"]["value"] == 1.0


@pytest.mark.parametrize("changes", [
    {"admitted_dispositions": None},
    {"admitted_dispositions": {"survived_confirmed": 1}},
    {"admitted_dispositions": {**dict.fromkeys(tr.DISPOSITIONS, 1), "extra": 1}},
    {"admitted_dispositions": {**dict.fromkeys(tr.DISPOSITIONS, 1), "unresolved": None}},
    {"admitted_dispositions": {**dict.fromkeys(tr.DISPOSITIONS, 1), "unresolved": -1}},
    {"admitted_dispositions": {**dict.fromkeys(tr.DISPOSITIONS, 1), "unresolved": True}},
    {"leads": {"admitted": 99}},
], ids=["missing", "partial", "extra", "null-count", "negative", "boolean", "not-a-partition"])
def test_split_ratios_refuse_a_malformed_partition(changes):
    with pytest.raises(ValueError):
        tg.split_ratios(section(**changes))


# ------------------------------------------------------------------------------- effectiveness

def test_effectiveness_is_unavailable_without_lead_labels():
    assert tg.effectiveness([lead("a")], None) == {"available": False, "reason": "no_lead_labels"}


def scenario():
    leads = [
        lead("t-conf", "survived_confirmed", family="buffer", scanner="codeql"),
        lead("t-supp", "survived_supported", family="buffer", scanner="cppcheck"),
        lead("t-blue", "dismissed_by_adjudication", "blue", family="buffer", scanner="codeql"),
        lead("t-judge", "dismissed_by_adjudication", "judge", family="taint"),
        lead("t-verifier", "dismissed_by_adjudication", "verifier", family="taint", scanner="codeql"),
        lead("t-silent", "no_claim_raised", family="taint", scanner="codeql"),
        lead("t-open", "unresolved", family="buffer", scanner="codeql"),
        lead("t-out", None, family="buffer", scanner="codeql"),
        lead("f-conf", "survived_confirmed", family="buffer", scanner="codeql", control_id="K1"),
        lead("f-judge", "dismissed_by_adjudication", "unattributed", family="buffer", scanner="codeql",
             control_id="K1"),
        lead("f-silent", "no_claim_raised", scanner="cppcheck", control_id="K2"),
        lead("f-open", "unresolved", control_id="K3"),
        lead("f-out", None, control_id="K4"),
        lead("u-label", "survived_supported"),
        lead("no-label", "dismissed_by_adjudication", "blue"),
    ]
    labels = labelled(**{"t-conf": "true", "t-supp": "true", "t-blue": "true", "t-judge": "true",
                         "t-verifier": "true", "t-silent": "true", "t-open": "true", "t-out": "true",
                         "f-conf": "false", "f-judge": "false", "f-silent": "false", "f-open": "false",
                         "f-out": "false", "u-label": "unresolved", "ghost": "true"})
    return leads, labels


def test_effectiveness_counts_labelled_admitted_leads_only():
    leads, labels = scenario()
    before = copy.deepcopy((leads, labels))
    result = tg.effectiveness(leads, labels)
    assert (leads, labels) == before
    assert (result["available"], result["admitted"]) == (True, 13)
    assert (result["labelled"], result["unlabelled"], result["label_unresolved"]) == (12, 1, 1)
    assert (result["true_leads"], result["false_leads"]) == (7, 4)
    assert result["true_leads_not_admitted"] == 1 and result["labels_without_lead"] == 1


def test_effectiveness_reports_retention_beside_removal_over_resolved_leads():
    result = tg.effectiveness(*scenario())
    assert pair(result["true_lead_retention"]) == (2, 6), "the unresolved true lead is in neither term"
    assert pair(result["false_lead_removal"]) == (2, 3)
    assert result["true_lead_retention"]["interval"] == c.wilson(2, 6)
    assert result["false_lead_removal"]["interval"] == c.wilson(2, 3)
    assert (result["true_leads_unresolved"], result["false_leads_unresolved"]) == (1, 1)
    assert pair(result["retained_precision"]) == (2, 3)
    assert result["retained_precision"]["interval"] is not None


def test_effectiveness_names_the_stage_that_removed_each_true_lead():
    result = tg.effectiveness(*scenario())
    assert result["true_leads_removed_by_stage"] == {"red_no_proposal": 1, "blue": 1, "judge": 1, "verifier": 1,
                                                     "unattributed": 0}
    assert result["false_leads_removed_by_stage"] == {"red_no_proposal": 1, "blue": 0, "judge": 0, "verifier": 0,
                                                      "unattributed": 1}
    assert list(result["true_leads_removed_by_stage"]) == list(c.TRIAGE_STAGES)


def test_control_false_positive_rate_is_over_distinct_admitted_controls():
    result = tg.effectiveness(*scenario())
    assert pair(result["control_false_positive_rate"]) == (1, 3), "K4 was never admitted; K1 counts once"
    assert result["control_false_positive_rate"]["interval"] == c.wilson(1, 3)
    none = tg.effectiveness([lead("a")], {})
    assert none["control_false_positive_rate"]["status"] == "empty_denominator"


def test_effectiveness_slices_by_family_and_scanner_with_a_null_row():
    result = tg.effectiveness(*scenario())
    assert list(result["by_family"]) == ["buffer", "null", "taint"]
    assert list(result["by_scanner"]) == ["codeql", "cppcheck", "null"]
    buffer = result["by_family"]["buffer"]
    assert (buffer["true_leads"], buffer["false_leads"]) == (4, 2)
    assert pair(buffer["true_lead_retention"]) == (2, 3) and pair(buffer["false_lead_removal"]) == (1, 2)
    taint = result["by_family"]["taint"]
    assert pair(taint["true_lead_retention"]) == (0, 3)
    assert taint["false_lead_removal"]["status"] == "empty_denominator"
    assert pair(result["by_family"]["null"]["false_lead_removal"]) == (1, 1)
    assert pair(result["by_scanner"]["cppcheck"]["true_lead_retention"]) == (1, 1)
    assert pair(result["by_scanner"]["null"]["true_lead_retention"]) == (0, 1)
    for row in (*result["by_family"].values(), *result["by_scanner"].values()):
        assert {"true_lead_retention", "false_lead_removal"} <= set(row), "never one without the other"


def test_a_triage_that_dismisses_every_lead_does_not_look_good():
    leads = [lead(f"t{index}", "dismissed_by_adjudication") for index in range(4)]
    leads += [lead(f"s{index}", "no_claim_raised") for index in range(2)]
    leads += [lead(f"f{index}", "dismissed_by_adjudication", control_id=f"K{index}") for index in range(5)]
    labels = labelled(**{item["lead_id"]: "false" if item["lead_id"].startswith("f") else "true"
                         for item in leads})
    result = tg.effectiveness(leads, labels)
    assert result["false_lead_removal"]["value"] == 1.0
    assert result["true_lead_retention"]["value"] == 0.0 and pair(result["true_lead_retention"]) == (0, 6)
    assert result["true_leads_removed_by_stage"]["judge"] == 4
    assert result["true_leads_removed_by_stage"]["red_no_proposal"] == 2
    assert result["retained_precision"]["status"] == "empty_denominator", "nothing retained is not perfect precision"


def test_effectiveness_keeps_silence_and_refutation_apart_per_stage():
    leads = [lead("a", "no_claim_raised"), lead("b", "dismissed_by_adjudication", "blue"),
             lead("c", "dismissed_by_adjudication", "judge")]
    result = tg.effectiveness(leads, labelled(a="true", b="true", c="true"))
    assert result["true_leads_removed_by_stage"]["red_no_proposal"] == 1
    assert sum(result["true_leads_removed_by_stage"].values()) - 1 == 2


def test_effectiveness_is_order_independent():
    leads, labels = scenario()
    assert c.digest(tg.effectiveness(leads, labels)) == c.digest(tg.effectiveness(list(reversed(leads)), labels))


@pytest.mark.parametrize("record", [
    lead("a", "dismissed_by_adjudication", removed_stage=None),
    lead("a", "no_claim_raised", removed_stage=None),
    lead("a", "survived_confirmed", "judge"),
    lead("a", "survived_supported", "blue"),
    lead("a", "unresolved", "verifier"),
    lead("a", "no_claim_raised", "judge"),
    lead("a", "dismissed_by_adjudication", "red_no_proposal"),
    lead("a", "dismissed_by_adjudication", "triage"),
    lead("a", "dismissed"),
    lead("a", None, admitted=True),
    lead("a", "unresolved", admitted=False),
    lead("a", None, "judge"),
    lead("a", admitted="yes"),
    lead(""),
    lead(7),
    lead("a", note="x"),
    lead("a", family="null"),
    lead("a", scanner=""),
    lead("a", control_id=3),
    "a",
], ids=["dismissed-no-stage", "silent-no-stage", "confirmed-stage", "supported-stage", "unresolved-stage",
        "silent-wrong-stage", "dismissed-silent-stage", "unknown-stage", "unknown-disposition",
        "admitted-no-disposition", "unadmitted-disposition", "unadmitted-stage", "admitted-type", "empty-id",
        "int-id", "unknown-field", "reserved-family", "empty-scanner", "control-type", "row-type"])
def test_effectiveness_refuses_inconsistent_lead_records(record):
    with pytest.raises(ValueError):
        tg.effectiveness([record], {})
    with pytest.raises(ValueError):
        tg.effectiveness([record], None)


def test_effectiveness_accepts_a_minimal_lead_record():
    result = tg.effectiveness([{"lead_id": "a", "admitted": True, "disposition": "survived_confirmed"}],
                              labelled(a="true"))
    assert pair(result["true_lead_retention"]) == (1, 1) and list(result["by_family"]) == ["null"]


@pytest.mark.parametrize("leads, labels", [
    ([lead("a"), lead("a", "unresolved")], {}),
    ({"lead_id": "a"}, {}),
    ("a", {}),
    ([lead("a")], {"a": {"outcome": "maybe"}}),
    ([lead("a")], {"a": "true"}),
    ([lead("a")], ["a"]),
], ids=["repeat-id", "mapping", "string", "outcome", "bare-label", "labels-type"])
def test_effectiveness_refuses_invalid_lead_sets_and_labels(leads, labels):
    with pytest.raises(ValueError):
        tg.effectiveness(leads, labels)


def minimal_leads(count):
    return ({"lead_id": f"L{index}", "admitted": False} for index in range(count))


def test_effectiveness_accepts_exactly_the_bounded_number_of_leads():
    assert tg.effectiveness(minimal_leads(c.MAX_LEADS), None)["reason"] == "no_lead_labels"


def test_effectiveness_refuses_one_lead_beyond_the_bound():
    with pytest.raises(ValueError, match="bounded"):
        tg.effectiveness(minimal_leads(c.MAX_LEADS + 1), None)


# ----------------------------------------------------------------------------- audit miss rate

def audit_sample(*members):
    members = members or (("a", "dismissed_by_adjudication"), ("b", "no_claim_raised"), ("c", "no_claim_raised"),
                          ("d", "dismissed_by_adjudication"), ("e", "dismissed_by_adjudication"))
    return {"schema": c.AUDIT_SAMPLE_SCHEMA, "seed": "s", "eligible": 9, "requested": len(members),
            "sample": [{"lead_id": lead_id, "disposition": disposition} for lead_id, disposition in members],
            "sample_sha256": c.digest(sorted(lead_id for lead_id, _ in members))}


def test_audit_miss_rate_is_unavailable_without_audit_labels():
    assert tg.audit_miss_rate(audit_sample(), None) == {"available": False, "reason": "no_audit_labels"}


def test_audit_miss_rate_is_true_over_decided_sampled_leads_with_an_interval():
    sample = audit_sample()
    before = copy.deepcopy(sample)
    result = tg.audit_miss_rate(sample, labelled(a="true", b="true", c="false", d="unresolved"))
    assert sample == before
    assert result == {"available": True, "sample_size": 5, "labelled_true": 2, "labelled_false": 1,
                      "unresolved": 2,
                      "missed_by_disposition": {"dismissed_by_adjudication": 1, "no_claim_raised": 1},
                      "miss_rate": c.ratio(2, 3, interval=True)}
    assert result["miss_rate"]["interval"] is not None


def test_audit_miss_rate_with_no_decided_label_is_an_empty_denominator():
    result = tg.audit_miss_rate(audit_sample(), {})
    assert result["unresolved"] == 5 and result["miss_rate"]["value"] is None
    assert result["miss_rate"]["status"] == "empty_denominator"


@pytest.mark.parametrize("sample, labels", [
    (audit_sample(), labelled(z="true")),
    (audit_sample(), {"a": {"outcome": "maybe"}}),
    ({**audit_sample(), "schema": "appsec-review/audit-sample/0"}, {}),
    ({**audit_sample(), "sample": None}, {}),
    (audit_sample(("a", "survived_confirmed")), {}),
    (audit_sample(("a", "no_claim_raised"), ("a", "no_claim_raised")), {}),
    (None, {}),
], ids=["outside", "outcome", "schema", "no-members", "not-removed", "repeat", "none"])
def test_audit_miss_rate_refuses_foreign_labels_and_samples(sample, labels):
    with pytest.raises(ValueError):
        tg.audit_miss_rate(sample, labels)
