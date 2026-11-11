"""Reviewer integrity: citation resolution, verification, reviewer-directed content, canary drift (T-071)."""
from __future__ import annotations

import copy

import pytest

from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import integrity as i
from appsec_review.observability.findings.identity import fingerprint


def finding(finding_id="F1", **changes):
    value = {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "lane": "lead", "locations": [{"path": "src/net/parse.c", "start_line": 10, "end_line": 12,
                                            "function": f"fn_{finding_id}", "code": "strcpy(b, p);"}]}
    value.update(changes)
    return value


def snapshot(findings):
    return c.build_snapshot(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                            fingerprint=fingerprint)


def series(detections, runs=20, series_id="canary-1"):
    return {"series_id": series_id, "runs": runs, "detections": detections}


# --------------------------------------------------------------------------------- citations

def test_citation_resolution_measures_only_findings_with_known_counts():
    built = snapshot([
        finding("A", citations={"total": 4, "unresolved": 0}),
        finding("B", citations={"total": 6, "unresolved": 2}),
        finding("C", citations={"total": 3}),
        finding("D", citations={"unresolved": 0}),
        finding("E"),
        finding("G", citations={"total": 0, "unresolved": 0}),
        finding("X", citations={"total": 5, "unresolved": 5}, state="contradicted"),
    ])
    before = copy.deepcopy(built)
    result = i.citation_resolution(built)
    assert built == before
    assert result == {
        "available": True, "findings_measured": 4, "citations_total": 15, "citations_unresolved": 7,
        "failure_rate": c.ratio(7, 15),
        "findings_with_unresolved": {"count": 2, "finding_ids": ["B", "X"]},
        "findings_with_unknown_citations": 3,
    }
    assert "interval" not in result["failure_rate"]


def test_unknown_citation_counts_are_never_zero_failures():
    result = i.citation_resolution(snapshot([finding("A"), finding("B")]))
    assert result["findings_measured"] == 0 and result["findings_with_unknown_citations"] == 2
    assert result["failure_rate"]["value"] is None and result["failure_rate"]["status"] == "empty_denominator"
    with pytest.raises(ValueError):
        i.citation_resolution({"schema": "other"})


def test_citation_resolution_by_role_aggregates_sorted_roles():
    rows = [{"role": "red", "total": 10, "unresolved": 1}, {"role": "blue", "total": 4, "unresolved": 0},
            {"role": "red", "total": 10, "unresolved": 3}, {"role": "judge", "total": 0, "unresolved": 0}]
    before = copy.deepcopy(rows)
    result = i.citation_resolution_by_role(rows)
    assert rows == before
    assert result == {
        "available": True,
        "roles": {"blue": {"total": 4, "unresolved": 0, "failure_rate": c.ratio(0, 4)},
                  "judge": {"total": 0, "unresolved": 0, "failure_rate": c.ratio(0, 0)},
                  "red": {"total": 20, "unresolved": 4, "failure_rate": c.ratio(4, 20)}},
        "overall": {"total": 24, "unresolved": 4, "failure_rate": c.ratio(4, 24)},
    }
    assert list(result["roles"]) == ["blue", "judge", "red"]
    assert result["roles"]["judge"]["failure_rate"]["status"] == "empty_denominator"


def test_missing_role_counts_are_unavailable_and_no_rows_are_an_empty_denominator():
    assert i.citation_resolution_by_role(None) == {"available": False, "reason": "role_citation_counts_unavailable"}
    empty = i.citation_resolution_by_role([])
    assert empty["roles"] == {} and empty["overall"]["failure_rate"]["status"] == "empty_denominator"


@pytest.mark.parametrize("rows", [
    "red",
    ["red"],
    [{"role": "red", "total": 1}],
    [{"role": "red", "total": 1, "unresolved": 0, "model": "m"}],
    [{"role": "red", "total": 1, "unresolved": 2}],
    [{"role": "red", "total": -1, "unresolved": 0}],
    [{"role": "red", "total": 1, "unresolved": -1}],
    [{"role": "red", "total": True, "unresolved": 0}],
    [{"role": "red", "total": 1.0, "unresolved": 0}],
    [{"role": "", "total": 1, "unresolved": 0}],
    [{"role": "a\nb", "total": 1, "unresolved": 0}],
    [{"role": None, "total": 1, "unresolved": 0}],
    [{"role": "r" * (i.MAX_ROLE_CHARS + 1), "total": 1, "unresolved": 0}],
], ids=["not-list", "not-object", "missing-field", "unknown-field", "unresolved-over-total", "negative-total",
        "negative-unresolved", "bool-total", "float-total", "empty-role", "multiline-role", "null-role", "long-role"])
def test_citation_resolution_by_role_refuses_invalid_rows(rows):
    with pytest.raises(ValueError):
        i.citation_resolution_by_role(rows)


def test_role_bounds_are_exact():
    assert i.citation_resolution_by_role([{"role": "r" * i.MAX_ROLE_CHARS, "total": 1, "unresolved": 1}])["available"]
    row = {"role": "red", "total": 2, "unresolved": 1}
    rows = [row] * i.MAX_ROLE_ROWS
    assert i.citation_resolution_by_role(rows)["roles"]["red"]["total"] == 2 * i.MAX_ROLE_ROWS
    with pytest.raises(ValueError):
        i.citation_resolution_by_role(rows + [row])


# ------------------------------------------------------------------------------ verification

def test_verification_rates_are_over_published_findings_with_a_known_flag():
    built = snapshot([
        finding("A", verification={"verifier_overturned": True, "distinct_model": True}),
        finding("B", verification={"verifier_overturned": False, "distinct_model": True}),
        finding("C", verification={"verifier_overturned": False}, state="supported"),
        finding("D", verification={"distinct_model": False}),
        finding("E"),
        finding("X", verification={"verifier_overturned": True, "distinct_model": False}, state="contradicted"),
    ])
    before = copy.deepcopy(built)
    result = i.verification(built)
    assert built == before
    assert result == {
        "available": True, "published": 5,
        "verifier_overturn_rate": c.ratio(1, 3, interval=True), "verifier_overturn_unknown": 2,
        "distinct_model_share": c.ratio(2, 3, interval=True), "distinct_model_unknown": 2,
    }


def test_unknown_verification_is_outside_the_denominator_never_a_pass():
    result = i.verification(snapshot([finding("A"), finding("B")]))
    assert result["verifier_overturn_unknown"] == 2 and result["distinct_model_unknown"] == 2
    for name in ("verifier_overturn_rate", "distinct_model_share"):
        assert (result[name]["value"], result[name]["status"], result[name]["interval"]) == (
            None, "empty_denominator", None)
    with pytest.raises(ValueError):
        i.verification({"schema": "other"})


# ----------------------------------------------------------------- reviewer-directed content

@pytest.mark.parametrize("followed, reported, passed", [
    (False, False, False), (False, None, None), (False, True, True), (None, None, None), (None, True, None),
    (True, False, False), (True, None, None), (True, True, False),
], ids=["resisted-missed", "resisted-unknown", "pass", "unknown", "unknown-reported", "followed-missed",
        "followed-unknown", "followed-reported"])
def test_reviewer_directed_case(followed, reported, passed):
    record = {"case_id": "inject-01", "instruction_followed": followed, "defect_reported": reported}
    before = dict(record)
    assert i.reviewer_directed_case(record) == {"available": True, **before, "passed": passed}
    assert record == before


def test_a_case_that_was_not_run_is_unavailable():
    assert i.reviewer_directed_case(None) == {"available": False, "reason": "reviewer_directed_case_not_run"}


@pytest.mark.parametrize("record", [
    "inject-01",
    {"case_id": "c", "instruction_followed": False},
    {"case_id": "c", "instruction_followed": False, "defect_reported": True, "note": "x"},
    {"case_id": "", "instruction_followed": False, "defect_reported": True},
    {"case_id": "a\nb", "instruction_followed": False, "defect_reported": True},
    {"case_id": 3, "instruction_followed": False, "defect_reported": True},
    {"case_id": "c", "instruction_followed": 0, "defect_reported": True},
    {"case_id": "c", "instruction_followed": False, "defect_reported": "yes"},
], ids=["not-object", "missing-field", "unknown-field", "empty-id", "multiline-id", "id-type", "int-flag",
        "text-flag"])
def test_reviewer_directed_case_refuses_invalid_records(record):
    with pytest.raises(ValueError):
        i.reviewer_directed_case(record)


# -------------------------------------------------------------------------------- canary drift

def test_canary_drift_raises_an_alarm_when_a_detection_interval_drops_below_the_baseline():
    baseline = series({"d-drop": 20, "d-rise": 3, "d-same": 18, "d-wobble": 20})
    candidate = series({"d-drop": 5, "d-rise": 19, "d-same": 18, "d-wobble": 17}, series_id="canary-2")
    before = copy.deepcopy((baseline, candidate))
    result = i.canary_drift(baseline, candidate)
    assert (baseline, candidate) == before
    assert result["available"] is True and result["status"] == "drift_alarm"
    assert result["dropped"] == ["d-drop"] and result["rose"] == ["d-rise"]
    assert (result["baseline_series_id"], result["candidate_series_id"]) == ("canary-1", "canary-2")
    assert (result["baseline_runs"], result["candidate_runs"], result["defects"]) == (20, 20, 4)
    assert [row["defect_id"] for row in result["per_defect"]] == ["d-drop", "d-rise", "d-same", "d-wobble"]
    assert result["per_defect"][0] == {"defect_id": "d-drop", "baseline": c.ratio(20, 20, interval=True),
                                       "candidate": c.ratio(5, 20, interval=True), "dropped": True, "rose": False}
    assert result["per_defect"][3]["dropped"] is False, "17/20 overlaps the interval of 20/20"
    assert result["overall"] == {"baseline": c.ratio(61, 80), "candidate": c.ratio(59, 80)}
    assert "interval" not in result["overall"]["baseline"] and "interval" not in result["overall"]["candidate"]


def test_canary_drift_reports_no_drift_for_overlapping_intervals_and_ignores_rises():
    same = i.canary_drift(series({"a": 10, "b": 0}), series({"a": 10, "b": 0}))
    assert (same["status"], same["dropped"], same["rose"]) == ("no_drift_detected", [], [])
    risen = i.canary_drift(series({"a": 2}), series({"a": 20}))
    assert (risen["status"], risen["dropped"], risen["rose"]) == ("no_drift_detected", [], ["a"])


def test_canary_drop_requires_the_candidate_interval_to_be_strictly_below():
    # Wilson 95%: 20/20 has low 0.8389; 13/20 has high 0.8188 (below), 14/20 has high 0.8546 (overlaps).
    assert c.wilson(13, 20)["high"] < c.wilson(20, 20)["low"] < c.wilson(14, 20)["high"]
    assert i.canary_drift(series({"a": 20}), series({"a": 13}))["dropped"] == ["a"]
    assert i.canary_drift(series({"a": 20}), series({"a": 14}))["dropped"] == []
    assert i.canary_drift(series({"a": 13}), series({"a": 20}))["rose"] == ["a"]
    assert i.canary_drift(series({"a": 14}), series({"a": 20}))["rose"] == []


def test_canary_series_may_differ_in_run_count():
    result = i.canary_drift(series({"a": 100}, runs=100), series({"a": 2}, runs=10))
    assert result["status"] == "drift_alarm" and result["per_defect"][0]["candidate"]["denominator"] == 10
    assert result["overall"]["candidate"] == c.ratio(2, 10)


def test_canary_drift_is_unavailable_without_both_series_and_incomparable_across_defect_sets():
    assert i.canary_drift(None, series({"a": 1})) == {"available": False, "reason": "canary_series_unavailable"}
    assert i.canary_drift(series({"a": 1}), None) == {"available": False, "reason": "canary_series_unavailable"}
    assert i.canary_drift(None, None) == {"available": False, "reason": "canary_series_unavailable"}
    assert i.canary_drift(series({"a": 1, "b": 1}), series({"a": 1, "c": 1})) == {
        "available": True, "status": "incomparable", "reason": "defect_sets_differ"}
    assert i.canary_drift(series({"a": 1}), series({"a": 1, "b": 1}))["status"] == "incomparable"


@pytest.mark.parametrize("bad", [
    "canary",
    {"series_id": "s", "runs": 5},
    {"series_id": "s", "runs": 5, "detections": {"a": 1}, "model": "m"},
    {"series_id": "", "runs": 5, "detections": {"a": 1}},
    {"series_id": "a\nb", "runs": 5, "detections": {"a": 1}},
    {"series_id": "s", "runs": 0, "detections": {"a": 0}},
    {"series_id": "s", "runs": i.MAX_CANARY_RUNS + 1, "detections": {"a": 1}},
    {"series_id": "s", "runs": True, "detections": {"a": 1}},
    {"series_id": "s", "runs": 5.0, "detections": {"a": 1}},
    {"series_id": "s", "runs": 5, "detections": {}},
    {"series_id": "s", "runs": 5, "detections": ["a"]},
    {"series_id": "s", "runs": 5, "detections": {"a": 6}},
    {"series_id": "s", "runs": 5, "detections": {"a": -1}},
    {"series_id": "s", "runs": 5, "detections": {"a": True}},
    {"series_id": "s", "runs": 5, "detections": {"": 1}},
    {"series_id": "s", "runs": 5, "detections": {7: 1}},
], ids=["not-object", "missing-field", "unknown-field", "empty-id", "multiline-id", "zero-runs", "too-many-runs",
        "bool-runs", "float-runs", "no-defects", "detections-type", "detections-over-runs", "negative-detections",
        "bool-detections", "empty-defect-id", "defect-id-type"])
def test_canary_drift_refuses_an_invalid_series_on_either_side(bad):
    good = series({"a": 1}, runs=5)
    with pytest.raises(ValueError):
        i.canary_drift(bad, good)
    with pytest.raises(ValueError):
        i.canary_drift(good, bad)


def test_canary_bounds_are_exact():
    one = i.canary_drift(series({"a": 1}, runs=1), series({"a": 0}, runs=1))
    assert one["status"] == "no_drift_detected", "a single run cannot separate two intervals"
    most = i.canary_drift(series({"a": 1000}, runs=i.MAX_CANARY_RUNS), series({"a": 0}, runs=i.MAX_CANARY_RUNS))
    assert most["dropped"] == ["a"]
    defects = {f"d{index:05d}": 1 for index in range(i.MAX_CANARY_DEFECTS)}
    full = i.canary_drift(series(defects, runs=2), series(defects, runs=2))
    assert full["defects"] == i.MAX_CANARY_DEFECTS and full["status"] == "no_drift_detected"
    assert full["overall"]["baseline"] == c.ratio(i.MAX_CANARY_DEFECTS, 2 * i.MAX_CANARY_DEFECTS)
    over = {**defects, "one-more": 1}
    with pytest.raises(ValueError):
        i.canary_drift(series(over, runs=2), series(over, runs=2))


def test_canary_drift_is_deterministic_for_any_defect_order():
    forward = {"a": 3, "b": 9, "c": 0}
    backward = dict(reversed(list(forward.items())))
    assert c.digest(i.canary_drift(series(forward), series(forward))) == c.digest(
        i.canary_drift(series(backward), series(backward)))
