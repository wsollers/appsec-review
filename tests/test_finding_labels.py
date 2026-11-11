"""Label sources of the finding-metrics domain: answer key, developer outcomes, audit sample, merge."""
from __future__ import annotations

import copy
import hashlib

import pytest

from appsec_review.acceptance.scoring_model import EntryKind, KeyEntry, ScoringKey
from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import labels as lb
from appsec_review.observability.findings.identity import fingerprint

DEFECT_PATH = "src/net/parse.c"
CONTROL_PATH = "src/net/safe.c"


def location(path=DEFECT_PATH, start=10, end=12, function="parse_packet"):
    return {"path": path, "start_line": start, "end_line": end, "function": function, "code": None}


def finding(finding_id="F1", **changes):
    value = {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "locations": [location(function=f"fn_{finding_id}")]}
    value.update(changes)
    return value


def findings_of(*records):
    return c.build_snapshot(run_id="run-1", target_id="game", source_revision="a" * 40, findings=records,
                            fingerprint=fingerprint)["findings"]


def exact(records, finding_id):
    return next(item["fingerprint"]["exact"] for item in records if item["finding_id"] == finding_id)


def defect(entry_id="D1", scope=(10, 12), cwe="CWE-787", path=DEFECT_PATH):
    lines = (scope[0],) if scope else (1,)
    return KeyEntry(id=entry_id, kind=EntryKind.DEFECT, path=path, cwe=cwe, lines=lines, scope=scope)


def control(entry_id="C1", scope=None, path=CONTROL_PATH):
    lines = (scope[0],) if scope else (1,)
    return KeyEntry(id=entry_id, kind=EntryKind.CONTROL, path=path, cwe=None, lines=lines, scope=scope)


def key(*entries):
    return ScoringKey(corpus={"name": "unit"}, entries=entries or (defect(), control()))


def label(outcome, source="answer_key", expected_severity=None, disposition=None):
    return {"outcome": outcome, "source": source, "expected_severity": expected_severity,
            "disposition": disposition}


# --------------------------------------------------------------------------------- answer key

def test_finding_in_a_defect_scope_with_the_same_family_is_true_with_the_expected_severity():
    records = findings_of(finding())
    labels = lb.label_findings_from_key(key(), records, severities={"D1": "critical"})
    assert labels == {exact(records, "F1"): label("true", expected_severity="critical")}
    assert lb.label_findings_from_key(key(), records) == {exact(records, "F1"): label("true")}


@pytest.mark.parametrize("start, end, labelled", [(8, 9, False), (8, 10, True), (11, 11, True), (12, 14, True),
                                                   (13, 15, False)], ids=["before", "touch-start", "inside",
                                                                          "touch-end", "after"])
def test_a_location_is_inside_a_scope_when_its_line_range_overlaps(start, end, labelled):
    records = findings_of(finding(locations=[location(start=start, end=end)]))
    assert bool(lb.label_findings_from_key(key(), records)) is labelled


def test_wrong_weakness_family_in_a_defect_scope_is_false():
    records = findings_of(finding(weakness_cwe="CWE-78"))
    assert lb.label_findings_from_key(key(), records) == {exact(records, "F1"): label("false")}
    assert lb.key_case_hits(key(), records) == {"C1": [], "D1": []}


def test_any_finding_inside_a_control_scope_is_false():
    records = findings_of(finding(locations=[location(path=CONTROL_PATH, start=900, end=901)]))
    assert lb.label_findings_from_key(key(), records) == {exact(records, "F1"): label("false")}
    scoped = key(control(scope=(5, 6)))
    assert lb.label_findings_from_key(scoped, records) == {}


def test_a_finding_touching_no_key_case_gets_no_label():
    records = findings_of(finding("A", locations=[location(path="src/other.c")]),
                          finding("B", locations=[location(start=40, end=41)]))
    assert lb.label_findings_from_key(key(), records) == {}
    assert lb.key_case_hits(key(), records) == {"C1": [], "D1": []}


def test_true_wins_when_a_finding_is_both_true_and_false_across_locations():
    records = findings_of(finding(locations=[location(), location(path=CONTROL_PATH)]))
    assert lb.label_findings_from_key(key(), records)[exact(records, "F1")]["outcome"] == "true"
    assert lb.key_case_hits(key(), records) == {"C1": ["F1"], "D1": ["F1"]}


def test_a_finding_without_a_weakness_in_a_defect_scope_is_unresolved_but_false_in_a_control():
    in_defect = findings_of(finding(weakness_cwe=None))
    assert lb.label_findings_from_key(key(), in_defect) == {exact(in_defect, "F1"): label("unresolved")}
    in_both = findings_of(finding(weakness_cwe=None, locations=[location(), location(path=CONTROL_PATH)]))
    assert lb.label_findings_from_key(key(), in_both) == {exact(in_both, "F1"): label("false")}


@pytest.mark.parametrize("severities, expected", [({"D1": "high", "D2": "high"}, "high"),
                                                  ({"D1": "high", "D2": "low"}, None),
                                                  ({"D1": "medium"}, "medium"), ({}, None)],
                         ids=["agree", "disagree", "one", "none"])
def test_expected_severity_of_a_finding_matching_several_defects(severities, expected):
    both = key(defect("D1"), defect("D2", scope=(12, 20), cwe="CWE-125"))
    records = findings_of(finding())
    assert lb.label_findings_from_key(both, records, severities=severities)[exact(records, "F1")] == label(
        "true", expected_severity=expected)


@pytest.mark.parametrize("severities", [{"D9": "high"}, {"C1": "high"}, {"D1": "severe"}, ["D1"]],
                         ids=["unknown-id", "control-id", "bad-band", "not-mapping"])
def test_expected_severities_must_name_defects_and_bands(severities):
    with pytest.raises(ValueError):
        lb.label_findings_from_key(key(), findings_of(finding()), severities=severities)


def test_key_case_hits_lists_every_case_and_the_findings_that_hit_it():
    records = findings_of(finding("T2"), finding("T1", locations=[location(function="other")]),
                          finding("W", weakness_cwe="CWE-78"),
                          finding("K", weakness_cwe="CWE-78", locations=[location(path=CONTROL_PATH)]))
    assert lb.key_case_hits(key(defect(), control(), defect("D0", path="src/unseen.c")), records) == {
        "C1": ["K"], "D0": [], "D1": ["T1", "T2"]}


def test_key_labelling_is_order_independent_and_does_not_mutate_its_inputs():
    records = findings_of(finding("A"), finding("B", weakness_cwe="CWE-78"))
    before = copy.deepcopy(records)
    forward = lb.label_findings_from_key(key(), records)
    assert forward == lb.label_findings_from_key(key(control(), defect()), list(reversed(records)))
    assert list(forward) == sorted(forward) and records == before


@pytest.mark.parametrize("bad", ["key", "fingerprint", "locations", "repeat", "entry-ids", "not-list"])
def test_key_labelling_refuses_invalid_inputs(bad):
    records = findings_of(finding())
    answer_key = key()
    if bad == "key":
        answer_key = {"entries": []}
    elif bad == "fingerprint":
        records = [{**records[0], "fingerprint": {"exact": "abc"}}]
    elif bad == "locations":
        records = [{**records[0], "locations": []}]
    elif bad == "repeat":
        records = [records[0], {**records[0], "finding_id": "F2"}]
    elif bad == "entry-ids":
        answer_key = key(defect(), defect())
    else:
        records = records[0]
    with pytest.raises(ValueError):
        lb.label_findings_from_key(answer_key, records)
    with pytest.raises(ValueError):
        lb.key_case_hits(answer_key, records)


def bare_findings(count):
    return [{"finding_id": f"F{index}", "fingerprint": {"exact": f"{index:064x}"}, "weakness_cwe": None,
             "locations": [{"path": "x.c", "start_line": 1}]} for index in range(count)]


def test_key_labelling_accepts_exactly_the_bounded_number_of_findings():
    assert lb.label_findings_from_key(key(), bare_findings(c.MAX_FINDINGS)) == {}


def test_key_labelling_refuses_one_finding_beyond_the_bound():
    with pytest.raises(ValueError, match="bounded"):
        lb.label_findings_from_key(key(), bare_findings(c.MAX_FINDINGS + 1))


# ------------------------------------------------------------------------- developer outcomes

def outcome(fingerprint_="a" * 64, disposition="fixed", **changes):
    value = {"fingerprint": fingerprint_, "disposition": disposition, "opened_on": "2026-01-01",
             "decided_on": "2026-01-11", "expires_on": None}
    value.update(changes)
    return value


def document(*outcomes, **changes):
    value = {"schema": c.OUTCOME_FILE_SCHEMA, "target_id": "game", "outcomes": list(outcomes)}
    value.update(changes)
    return value


def test_admit_outcomes_sorts_outcomes_and_derives_labels_per_disposition():
    doc = document(outcome("d" * 64, "duplicate"), outcome("c" * 64, "accepted_risk", expires_on="2026-12-31"),
                   outcome("b" * 64, "rejected_false"), outcome("a" * 64, "fixed"))
    before = copy.deepcopy(doc)
    admitted = lb.admit_outcomes(doc, as_of="2026-06-01")
    assert doc == before and set(admitted) == {"target_id", "outcomes", "labels"}
    assert admitted["target_id"] == "game"
    assert [row["fingerprint"][0] for row in admitted["outcomes"]] == ["a", "b", "c", "d"]
    assert all(row["expired"] is False for row in admitted["outcomes"])
    assert admitted["labels"] == {
        "a" * 64: label("true", "developer_outcome", disposition="fixed"),
        "b" * 64: label("false", "developer_outcome", disposition="rejected_false"),
        "c" * 64: label("true", "developer_outcome", disposition="accepted_risk")}


@pytest.mark.parametrize("as_of, expired", [("2026-03-01", False), ("2026-03-02", True)], ids=["on-expiry", "after"])
def test_an_accepted_risk_expires_only_after_its_expiry_date(as_of, expired):
    doc = document(outcome(disposition="accepted_risk", expires_on="2026-03-01"))
    admitted = lb.admit_outcomes(doc, as_of=as_of)
    assert admitted["outcomes"][0]["expired"] is expired
    assert admitted["labels"]["a" * 64]["outcome"] == "true", "an expired acceptance is still a real finding"


def test_admit_outcomes_accepts_optional_dates_and_a_same_day_decision():
    minimal = {"fingerprint": "a" * 64, "disposition": "fixed", "decided_on": "2026-01-01"}
    assert lb.admit_outcomes(document(minimal), as_of="2026-01-01")["outcomes"] == [
        {**minimal, "opened_on": None, "expires_on": None, "expired": False}]
    same_day = lb.admit_outcomes(document(outcome(opened_on="2026-01-11")), as_of="2026-01-01")
    assert same_day["outcomes"][0]["opened_on"] == same_day["outcomes"][0]["decided_on"]
    assert lb.admit_outcomes(document(), as_of="2026-01-01") == {"target_id": "game", "outcomes": [], "labels": {}}


@pytest.mark.parametrize("doc", [
    document(outcome(), note="x"),
    document(outcome(owner="me")),
    document(outcome(), schema="appsec-review/developer-outcomes/0"),
    document(outcome(), target_id=""),
    document(outcomes={}),
    {"schema": c.OUTCOME_FILE_SCHEMA, "outcomes": []},
    document({"fingerprint": "a" * 64, "disposition": "fixed"}),
    document(outcome("A" * 64)),
    document(outcome("a" * 63)),
    document(outcome(), outcome()),
    document(outcome(disposition="wontfix")),
    document(outcome(decided_on="2026-02-30")),
    document(outcome(decided_on="20260111")),
    document(outcome(opened_on="2026-1-1")),
    document(outcome(decided_on=None)),
    document(outcome(decided_on="2026-01-11\n")),
    document(outcome(opened_on="2026-01-12")),
    document(outcome(disposition="accepted_risk")),
    document(outcome(expires_on="2026-12-31")),
    document(outcome(disposition="accepted_risk", expires_on="soon")),
    document("fixed"),
    [],
], ids=["top-unknown", "row-unknown", "schema", "target", "not-list", "top-missing", "row-missing", "fp-upper",
        "fp-short", "fp-repeat", "disposition", "date-unreal", "date-compact", "date-short", "date-null",
        "date-newline", "decided-first", "risk-no-expiry", "expiry-on-fixed", "expiry-text", "row-type",
        "doc-type"])
def test_admit_outcomes_refuses_invalid_files(doc):
    with pytest.raises(ValueError):
        lb.admit_outcomes(doc, as_of="2026-06-01")


@pytest.mark.parametrize("as_of", ["", "2026-13-01", "today", None, "2026-06-01T00:00:00"],
                         ids=["empty", "unreal", "word", "null", "datetime"])
def test_admit_outcomes_needs_a_real_evaluation_date(as_of):
    with pytest.raises(ValueError):
        lb.admit_outcomes(document(outcome()), as_of=as_of)


def many_outcomes(count):
    return document(*({"fingerprint": f"{index:064x}", "disposition": "fixed", "decided_on": "2026-01-01"}
                      for index in range(count)))


def test_admit_outcomes_accepts_exactly_the_bounded_number_of_outcomes():
    assert len(lb.admit_outcomes(many_outcomes(lb.MAX_OUTCOMES), as_of="2026-06-01")["labels"]) == 10_000


def test_admit_outcomes_refuses_one_outcome_beyond_the_bound():
    with pytest.raises(ValueError, match="bounded"):
        lb.admit_outcomes(many_outcomes(lb.MAX_OUTCOMES + 1), as_of="2026-06-01")


def test_outcome_metrics_are_unavailable_without_an_outcomes_file():
    assert lb.outcome_metrics(None, {}) == {"available": False, "reason": "no_developer_outcomes"}


def test_outcome_metrics_report_rates_expiry_and_time_to_disposition():
    doc = document(
        outcome("a" * 64, "fixed", opened_on="2026-01-01", decided_on="2026-01-05"),          # 4 days, high
        outcome("b" * 64, "fixed", opened_on="2026-01-01", decided_on="2026-01-11"),          # 10 days, high
        outcome("c" * 64, "rejected_false", opened_on="2026-01-01", decided_on="2026-01-03"),  # 2 days, unrated
        outcome("d" * 64, "accepted_risk", opened_on=None, expires_on="2026-02-01"),          # no opening date
        outcome("e" * 64, "accepted_risk", opened_on="2026-01-01", decided_on="2026-01-21",
                expires_on="2026-09-01"),                                                     # 20 days, absent
        outcome("f" * 64, "duplicate", opened_on="2026-01-01", decided_on="2026-01-02"))      # 1 day, low
    found = {"a" * 64: {"severity": "high"}, "b" * 64: {"severity": "high"}, "c" * 64: {"severity": None},
             "d" * 64: {"severity": "critical"}, "f" * 64: {"severity": "low"}}
    metrics = lb.outcome_metrics(lb.admit_outcomes(doc, as_of="2026-06-01"), found)
    assert metrics["available"] is True and metrics["outcomes"] == 6 and metrics["target_id"] == "game"
    assert metrics["by_disposition"] == {"fixed": 2, "rejected_false": 1, "accepted_risk": 2, "duplicate": 1}
    assert (metrics["fix_rate"]["numerator"], metrics["fix_rate"]["denominator"]) == (2, 6)
    assert metrics["fix_rate"]["interval"] == c.wilson(2, 6)
    assert (metrics["rejected_false_rate"]["numerator"], metrics["rejected_false_rate"]["denominator"]) == (1, 6)
    assert metrics["rejected_false_rate"]["interval"] is not None
    assert metrics["accepted_risk"] == {"total": 2, "expired": 1}
    timing = metrics["time_to_disposition_days"]
    assert (timing["median"], timing["count"]) == (4.0, 5)
    assert timing["by_severity"] == {
        "low": {"median": 1.0, "count": 1}, "medium": {"median": None, "count": 0},
        "high": {"median": 7.0, "count": 2}, "critical": {"median": None, "count": 0},
        "null": {"median": 11.0, "count": 2}}
    assert metrics["unmatched_outcomes"] == 1


def test_outcome_metrics_of_an_empty_file_are_empty_denominators_not_zero_rates():
    metrics = lb.outcome_metrics(lb.admit_outcomes(document(), as_of="2026-06-01"), {})
    assert metrics["fix_rate"]["value"] is None and metrics["fix_rate"]["status"] == "empty_denominator"
    assert metrics["time_to_disposition_days"]["median"] is None and metrics["unmatched_outcomes"] == 0


@pytest.mark.parametrize("admitted, found", [({"outcomes": None}, {}), ("x", {}), ({"outcomes": []}, None)],
                         ids=["no-outcomes", "not-mapping", "no-findings-map"])
def test_outcome_metrics_refuse_inputs_that_are_not_admitted_outcomes(admitted, found):
    with pytest.raises(ValueError):
        lb.outcome_metrics(admitted, found)


def test_outcome_metrics_refuse_a_finding_severity_outside_the_vocabulary():
    admitted = lb.admit_outcomes(document(outcome()), as_of="2026-06-01")
    with pytest.raises(ValueError):
        lb.outcome_metrics(admitted, {"a" * 64: {"severity": "severe"}})


# -------------------------------------------------------------------------------- audit sample

DISPOSITION_CYCLE = ("dismissed_by_adjudication", "no_claim_raised", "survived_confirmed", "unresolved", None)


def leads(count=40):
    return [{"lead_id": f"L{index:03d}", "disposition": DISPOSITION_CYCLE[index % 5]} for index in range(count)]


def test_audit_sample_takes_only_removed_leads_in_seeded_hash_order():
    pool = leads()
    before = copy.deepcopy(pool)
    sample = lb.export_audit_sample(pool, seed="s1", size=5)
    eligible = [lead["lead_id"] for lead in pool if lead["disposition"] in ("dismissed_by_adjudication",
                                                                            "no_claim_raised")]
    ranked = sorted(eligible, key=lambda lead_id: hashlib.sha256(f"s1\0{lead_id}".encode()).hexdigest())
    ids = [member["lead_id"] for member in sample["sample"]]
    assert pool == before and ids == sorted(ranked[:5])
    assert sample == {"schema": c.AUDIT_SAMPLE_SCHEMA, "seed": "s1", "eligible": 16, "requested": 5,
                      "sample": [{"lead_id": lead_id, "disposition": pool[int(lead_id[1:])]["disposition"]}
                                 for lead_id in ids],
                      "sample_sha256": c.digest(ids)}


def test_audit_sample_is_reproducible_for_any_input_order_and_changes_with_the_seed():
    one = lb.export_audit_sample(leads(), seed="s1", size=5)
    assert one == lb.export_audit_sample(list(reversed(leads())), seed="s1", size=5)
    assert one["sample_sha256"] != lb.export_audit_sample(leads(), seed="s2", size=5)["sample_sha256"]


def test_audit_sample_reports_the_shortfall_when_fewer_leads_are_eligible():
    sample = lb.export_audit_sample(leads(10), seed="s1", size=lb.MAX_AUDIT_SAMPLE)
    assert (sample["eligible"], sample["requested"], len(sample["sample"])) == (4, 5000, 4)
    empty = lb.export_audit_sample([], seed="s1", size=1)
    assert empty["sample"] == [] and empty["eligible"] == 0 and empty["sample_sha256"] == c.digest([])


@pytest.mark.parametrize("size", [0, 5001, -1, True, 2.0, "3"], ids=str)
def test_audit_sample_size_is_bounded(size):
    with pytest.raises(ValueError):
        lb.export_audit_sample(leads(), seed="s1", size=size)


@pytest.mark.parametrize("seed", ["", None, 7], ids=repr)
def test_audit_sample_needs_a_seed(seed):
    with pytest.raises(ValueError):
        lb.export_audit_sample(leads(), seed=seed, size=1)


@pytest.mark.parametrize("pool", [
    [{"lead_id": "A", "disposition": "no_claim_raised"}, {"lead_id": "A", "disposition": "unresolved"}],
    [{"lead_id": "A", "disposition": "dismissed"}], [{"disposition": "no_claim_raised"}], ["A"],
    {"lead_id": "A"}, "A"], ids=["repeat", "disposition", "no-id", "row-type", "mapping", "string"])
def test_audit_sample_refuses_invalid_leads(pool):
    with pytest.raises(ValueError):
        lb.export_audit_sample(pool, seed="s1", size=1)


def unresolved_leads(count):
    return ({"lead_id": f"L{index}", "disposition": None} for index in range(count))


def test_audit_sample_accepts_exactly_the_bounded_number_of_leads():
    assert lb.export_audit_sample(unresolved_leads(c.MAX_LEADS), seed="s", size=1)["eligible"] == 0


def test_audit_sample_refuses_one_lead_beyond_the_bound():
    with pytest.raises(ValueError, match="bounded"):
        lb.export_audit_sample(unresolved_leads(c.MAX_LEADS + 1), seed="s", size=1)


def test_audit_labels_cover_every_sample_member_and_default_to_unresolved():
    sample = lb.export_audit_sample(leads(), seed="s1", size=3)
    first, second, third = (member["lead_id"] for member in sample["sample"])
    admitted = lb.admit_audit_labels(sample, {second: "false", first: "true"})
    assert admitted == {first: label("true", "audit_sample"), second: label("false", "audit_sample"),
                        third: label("unresolved", "audit_sample")}
    assert list(admitted) == sorted(admitted)
    assert {item["outcome"] for item in lb.admit_audit_labels(sample, {}).values()} == {"unresolved"}


@pytest.mark.parametrize("bad", ["outside", "outcome", "schema", "tampered", "labels-type"])
def test_audit_labels_refuse_foreign_leads_outcomes_and_samples(bad):
    sample = lb.export_audit_sample(leads(), seed="s1", size=3)
    member = sample["sample"][0]["lead_id"]
    human = {member: "true"}
    if bad == "outside":
        human = {"L999": "true"}
    elif bad == "outcome":
        human = {member: "maybe"}
    elif bad == "schema":
        sample = {**sample, "schema": "appsec-review/audit-sample/0"}
    elif bad == "tampered":
        sample = {**sample, "sample": sample["sample"][:2]}
    else:
        human = [member]
    with pytest.raises(ValueError):
        lb.admit_audit_labels(sample, human)


# -------------------------------------------------------------------------------------- merge

def test_merge_keeps_the_highest_authority_and_records_opposite_decisions_as_conflicts():
    merged = lb.merge({"s1": label("true", "answer_key", "high"), "s2": label("false", "developer_outcome")},
                      {"s1": label("false", "developer_outcome", disposition="rejected_false"),
                       "s2": label("true", "audit_sample"), "s3": label("true", "crash")},
                      {"s1": label("false", "audit_sample")})
    assert merged["schema"] == c.LABEL_SET_SCHEMA
    assert merged["labels"] == {"s1": label("true", "answer_key", "high"),
                                "s2": label("false", "developer_outcome"), "s3": label("true", "crash")}
    assert merged["conflicts"] == [
        {"subject_id": "s1", "kept_source": "answer_key", "overridden_source": "audit_sample"},
        {"subject_id": "s1", "kept_source": "answer_key", "overridden_source": "developer_outcome"},
        {"subject_id": "s2", "kept_source": "developer_outcome", "overridden_source": "audit_sample"}]
    assert merged["counts"] == {
        "labels": 3, "conflicts": 3,
        "by_source": {"answer_key": 1, "developer_outcome": 1, "audit_sample": 0, "crash": 1},
        "by_outcome": {"true": 2, "false": 1, "unresolved": 0}}


def test_merge_records_no_conflict_when_sources_agree():
    merged = lb.merge({"s": label("true", "developer_outcome")}, {"s": label("true", "audit_sample")})
    assert merged["labels"]["s"]["source"] == "developer_outcome" and merged["conflicts"] == []


def test_unresolved_never_overrides_a_decided_label_from_a_lower_authority():
    merged = lb.merge({"s": label("unresolved", "answer_key")}, {"s": label("false", "audit_sample")})
    assert merged["labels"] == {"s": label("false", "audit_sample")} and merged["conflicts"] == []
    undecided = lb.merge({"s": label("unresolved", "audit_sample")}, {"s": label("unresolved", "answer_key")})
    assert undecided["labels"] == {"s": label("unresolved", "answer_key")}
    assert undecided["counts"]["by_outcome"] == {"true": 0, "false": 0, "unresolved": 1}


def test_merge_does_not_depend_on_argument_order_and_does_not_mutate():
    maps = [{"b": label("true", "answer_key"), "a": label("false", "crash")},
            {"b": label("false", "audit_sample")}, {"a": label("true", "developer_outcome")}]
    before = copy.deepcopy(maps)
    assert c.digest(lb.merge(*maps)) == c.digest(lb.merge(*reversed(maps)))
    assert list(lb.merge(*maps)["labels"]) == ["a", "b"] and maps == before


def test_merge_of_nothing_is_an_empty_label_set_and_minimal_labels_are_completed():
    assert lb.merge() == {"schema": c.LABEL_SET_SCHEMA, "labels": {}, "conflicts": [], "counts": {
        "labels": 0, "conflicts": 0, "by_source": dict.fromkeys(c.LABEL_AUTHORITY, 0),
        "by_outcome": {"true": 0, "false": 0, "unresolved": 0}}}
    assert lb.merge({"s": {"outcome": "true", "source": "crash"}})["labels"] == {"s": label("true", "crash")}


def test_merge_accepts_one_source_repeating_itself_but_not_contradicting_itself():
    same = lb.merge({"s": label("true", "answer_key")}, {"s": label("true", "answer_key")})
    assert same["counts"]["labels"] == 1 and same["conflicts"] == []
    with pytest.raises(ValueError, match="two different labels"):
        lb.merge({"s": label("true", "answer_key")}, {"s": label("false", "answer_key")})


@pytest.mark.parametrize("value", [
    {"outcome": "maybe", "source": "answer_key"}, {"outcome": "true", "source": "model_dismissal"},
    {"outcome": "true"}, {"source": "crash"}, {"outcome": "true", "source": "crash", "confidence": 0.9},
    {"outcome": "true", "source": "crash", "expected_severity": "severe"},
    {"outcome": "true", "source": "crash", "disposition": "wontfix"}, "true",
], ids=["outcome", "source", "no-source", "no-outcome", "unknown-field", "severity", "disposition", "not-mapping"])
def test_merge_refuses_labels_outside_the_contract(value):
    with pytest.raises(ValueError):
        lb.merge({"s": value})


@pytest.mark.parametrize("label_map", [["s"], {"": label("true")}, {7: label("true")}],
                         ids=["not-mapping", "empty-id", "int-id"])
def test_merge_refuses_invalid_label_maps(label_map):
    with pytest.raises(ValueError):
        lb.merge(label_map)


def test_every_label_source_feeds_one_label_set():
    records = findings_of(finding("A"), finding("B", weakness_cwe="CWE-78"))
    from_key = lb.label_findings_from_key(key(), records)
    outcomes = lb.admit_outcomes(document(outcome(exact(records, "B"), "fixed")), as_of="2026-06-01")
    merged = lb.merge(outcomes["labels"], from_key)
    assert merged["labels"][exact(records, "B")] == label("false")
    assert merged["conflicts"] == [{"subject_id": exact(records, "B"), "kept_source": "answer_key",
                                    "overridden_source": "developer_outcome"}]
