"""Targeted fix re-check (T-061): bounded requests, strict admission, an injected transport only."""
from __future__ import annotations

import copy
import hashlib

import pytest

from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import lifecycle as lc
from appsec_review.observability.findings import recheck as rc
from appsec_review.observability.findings.identity import fingerprint

H1, H2 = "1" * 64, "2" * 64
CHANGED, SAME, CMD, NEW, UNHASHED, RESIDUAL, GONE = (
    "src/changed.c", "src/same.c", "src/cmd.c", "src/new.c", "src/unhashed.c", "src/residual.c", "src/gone.c")


def finding(finding_id, path, *, severity="high", cwe="CWE-121", predicate=None):
    return {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": cwe, "severity": severity,
            "security_predicate": predicate,
            "locations": [{"path": path, "start_line": 10, "end_line": 12, "function": f"fn_{finding_id.lower()}",
                           "code": f"use_{finding_id.lower()}(p);"}]}


def snapshot(findings, **changes):
    arguments = dict(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                     fingerprint=fingerprint)
    arguments.update(changes)
    return c.build_snapshot(**arguments)


def scenario():
    """run-1 -> run-2: A (low) and C (critical) are fix candidates, B (high) is not re-detected, D persists,
    E was not covered."""
    prior = snapshot(
        [finding("A", CHANGED, severity="low", predicate="unbounded copy"), finding("B", SAME),
         finding("C", CMD, severity="critical", cwe="CWE-78"), finding("D", SAME, cwe="CWE-416"),
         finding("E", GONE, cwe="CWE-190")],
        reviewed_units={CHANGED: H1, SAME: H1, CMD: H1, UNHASHED: H1, GONE: H1},
        unreviewed_units={RESIDUAL: "not_built"})
    current = snapshot([finding("D", SAME, cwe="CWE-416")], run_id="run-2", source_revision="b" * 40,
                       reviewed_units={CHANGED: H2, SAME: H1, CMD: H2, NEW: H2, UNHASHED: None, RESIDUAL: H2})
    return prior, current, lc.classify(prior, current)


def request_for(finding_id="A"):
    prior, current, lifecycle = scenario()
    request = next(item for item in rc.build_requests(lifecycle, prior)["requests"] if item["finding_id"] == finding_id)
    return request, prior, current


def cite(path, start=3, end=5):
    return {"path": path, "start_line": start, "end_line": end}


def admit(result, finding_id="A", **snapshots):
    request, prior, current = request_for(finding_id)
    return rc.admit_result(request, result, prior_snapshot=snapshots.get("prior", prior),
                           current_snapshot=snapshots.get("current", current))


# ---------------------------------------------------------------------------- build_requests

def test_the_scenario_classifies_as_the_tests_assume():
    _, _, lifecycle = scenario()
    assert {row["finding_id"]: row["state"] for row in lifecycle["prior"]} == {
        "A": "fix_candidate", "B": "not_redetected", "C": "fix_candidate", "D": "persisting", "E": "not_covered"}


def test_one_request_per_recheckable_row_with_actionable_findings_first():
    prior, _, lifecycle = scenario()
    kept = copy.deepcopy((prior, lifecycle))
    built = rc.build_requests(lifecycle, prior)
    assert (prior, lifecycle) == kept
    assert (built["eligible"], built["truncated"]) == (3, 0) and list(built) == ["requests", "eligible", "truncated"]
    assert [item["finding_id"] for item in built["requests"]] == ["B", "C", "A"]
    row = next(item for item in lifecycle["prior"] if item["finding_id"] == "A")
    assert built["requests"][2] == {
        "schema": "appsec-review/fix-recheck-request/1", "finding_id": "A",
        "fingerprint_exact": row["fingerprint_exact"], "lifecycle_state": "fix_candidate",
        "weakness_cwe": "CWE-121", "security_predicate": "unbounded copy", "severity": "low",
        "prior_run_id": "run-1", "current_run_id": "run-2",
        "prior_locations": [{"path": CHANGED, "start_line": 10, "end_line": 12, "function": "fn_a",
                             "code": "use_a(p);"}]}
    assert built["requests"][0]["lifecycle_state"] == "not_redetected"
    assert built["requests"][0]["security_predicate"] is None


def test_requests_are_truncated_and_the_truncation_is_counted():
    prior, _, lifecycle = scenario()
    built = rc.build_requests(lifecycle, prior, max_requests=2)
    assert [item["finding_id"] for item in built["requests"]] == ["B", "C"]
    assert (built["eligible"], built["truncated"]) == (3, 1)
    assert rc.build_requests(lifecycle, prior, max_requests=3)["truncated"] == 0


def test_a_lifecycle_with_nothing_to_recheck_builds_no_requests():
    prior = snapshot([finding("D", SAME)])
    lifecycle = lc.classify(prior, snapshot([finding("D", SAME)], run_id="run-2"))
    assert rc.build_requests(lifecycle, prior) == {"requests": [], "eligible": 0, "truncated": 0}


@pytest.mark.parametrize("bound", [1, 1000], ids=["min-1", "max-1000"])
def test_max_requests_accepts_its_bounds(bound):
    prior, _, lifecycle = scenario()
    assert len(rc.build_requests(lifecycle, prior, max_requests=bound)["requests"]) == min(bound, 3)


@pytest.mark.parametrize("bound", [0, 1001, -1, True, 2.0, "5", None], ids=repr)
def test_max_requests_outside_its_bounds_is_refused(bound):
    prior, _, lifecycle = scenario()
    with pytest.raises(ValueError):
        rc.build_requests(lifecycle, prior, max_requests=bound)


def test_the_default_request_bound_is_200():
    findings = [finding(f"F{index:03d}", f"src/unit{index:03d}.c") for index in range(201)]
    units = {item["locations"][0]["path"]: H1 for item in findings}
    prior = snapshot(findings, reviewed_units=units)
    current = snapshot([], run_id="run-2", reviewed_units={path: H2 for path in units})
    built = rc.build_requests(lc.classify(prior, current), prior)
    assert rc.DEFAULT_MAX_REQUESTS == 200 and len(built["requests"]) == 200
    assert (built["eligible"], built["truncated"]) == (201, 1)
    assert built["requests"][-1]["finding_id"] == "F199"


def test_build_requests_refuses_a_snapshot_that_is_not_the_lifecycles_prior_run():
    prior, current, lifecycle = scenario()
    with pytest.raises(ValueError):
        rc.build_requests(lifecycle, current)
    with pytest.raises(ValueError):
        rc.build_requests(lifecycle, snapshot([], stage="verified"))
    with pytest.raises(ValueError):
        rc.build_requests(lifecycle, snapshot([finding("B", SAME)], reviewed_units={SAME: H1}))
    with pytest.raises(ValueError):
        rc.build_requests({**lifecycle, "stage": "final"}, prior)
    with pytest.raises(ValueError):
        rc.build_requests(lifecycle, {**prior, "schema": "other/1"})


# ------------------------------------------------------------------------------ admit_result

def test_a_fixed_claim_citing_changed_reviewed_code_is_admitted():
    reason = "the copy is now bounded by sizeof(b)"
    admitted = admit({"finding_id": "A", "outcome": "fixed", "cited": [cite("./src//changed.c", 7, 9)],
                      "reason": reason})
    assert admitted == {"finding_id": "A", "outcome": "fixed", "claimed_outcome": "fixed", "downgrade_reason": None,
                        "cited": [{"path": CHANGED, "start_line": 7, "end_line": 9}],
                        "reason_sha256": hashlib.sha256(reason.encode()).hexdigest()}
    assert reason not in repr(admitted)


def test_a_fixed_claim_citing_a_new_unit_is_admitted():
    admitted = admit({"finding_id": "A", "outcome": "fixed", "cited": [cite(SAME), cite(NEW)]})
    assert (admitted["outcome"], admitted["downgrade_reason"], admitted["reason_sha256"]) == ("fixed", None, None)
    assert [item["path"] for item in admitted["cited"]] == [NEW, SAME]


@pytest.mark.parametrize("cited", [
    [], [cite(SAME)], [cite(UNHASHED)], [cite(RESIDUAL)], [cite("src/never_reviewed.c")], [cite(GONE)],
    [cite(SAME), cite(UNHASHED), cite(GONE)],
], ids=["no-citation", "unchanged", "current-hash-unknown", "was-unreviewed-not-new", "not-reviewed-now",
        "no-longer-reviewed", "several-none-changed"])
def test_a_fixed_claim_without_a_changed_citation_is_downgraded(cited):
    admitted = admit({"finding_id": "A", "outcome": "fixed", "cited": cited, "reason": "trust me"})
    assert (admitted["outcome"], admitted["claimed_outcome"], admitted["downgrade_reason"]) == (
        "insufficient_evidence", "fixed", "fixed_without_changed_citation")


@pytest.mark.parametrize("units", [None, {CHANGED: None}], ids=["prior-coverage-unknown", "prior-hash-unknown"])
def test_a_fixed_claim_is_downgraded_when_the_prior_content_is_unknown(units):
    request, prior, current = request_for("A")
    admitted = rc.admit_result(request, {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED)]},
                               prior_snapshot={**prior, "reviewed_units": units}, current_snapshot=current)
    assert (admitted["outcome"], admitted["downgrade_reason"]) == (
        "insufficient_evidence", "fixed_without_changed_citation")


def test_a_fixed_claim_is_downgraded_when_current_coverage_is_unknown():
    request, prior, current = request_for("A")
    admitted = rc.admit_result(request, {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED)]},
                               prior_snapshot=prior, current_snapshot={**current, "reviewed_units": None})
    assert admitted["outcome"] == "insufficient_evidence"


@pytest.mark.parametrize("path", [SAME, UNHASHED, CHANGED], ids=["unchanged", "hash-unknown", "changed"])
def test_a_still_present_claim_citing_a_reviewed_unit_is_admitted(path):
    admitted = admit({"finding_id": "B", "outcome": "still_present", "cited": [cite(path)]}, "B")
    assert (admitted["outcome"], admitted["claimed_outcome"], admitted["downgrade_reason"]) == (
        "still_present", "still_present", None)


@pytest.mark.parametrize("cited", [[], [cite(GONE)], [cite("src/never_reviewed.c")]],
                         ids=["no-citation", "no-longer-reviewed", "not-reviewed"])
def test_a_still_present_claim_without_a_reviewed_citation_is_downgraded(cited):
    admitted = admit({"finding_id": "B", "outcome": "still_present", "cited": cited}, "B")
    assert (admitted["outcome"], admitted["claimed_outcome"], admitted["downgrade_reason"]) == (
        "insufficient_evidence", "still_present", "still_present_without_citation")


def test_insufficient_evidence_passes_through_and_citations_are_normalized_and_deduplicated():
    admitted = admit({"finding_id": "A", "outcome": "insufficient_evidence",
                      "cited": [cite(SAME, 9, 9), {"path": CHANGED, "start_line": 4}, cite("src/./same.c", 9, 9)]})
    assert admitted == {"finding_id": "A", "outcome": "insufficient_evidence",
                        "claimed_outcome": "insufficient_evidence", "downgrade_reason": None,
                        "cited": [{"path": CHANGED, "start_line": 4, "end_line": 4},
                                  {"path": SAME, "start_line": 9, "end_line": 9}], "reason_sha256": None}
    assert admit({"finding_id": "A", "outcome": "insufficient_evidence"})["cited"] == []


def test_admit_result_does_not_mutate_its_inputs():
    request, prior, current = request_for("A")
    result = {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED)], "reason": "bounded"}
    kept = copy.deepcopy((request, result, prior, current))
    rc.admit_result(request, result, prior_snapshot=prior, current_snapshot=current)
    assert (request, result, prior, current) == kept


@pytest.mark.parametrize("result", [
    None, "fixed", [],
    {"outcome": "fixed"}, {"finding_id": "A"},
    {"finding_id": "B", "outcome": "fixed"},
    {"finding_id": "A", "outcome": "resolved"}, {"finding_id": "A", "outcome": None},
    {"finding_id": "A", "outcome": ["fixed"]},
    {"finding_id": "A", "outcome": "fixed", "confidence": 0.9},
    {"finding_id": "A", "outcome": "fixed", "cited": "src/changed.c"},
    {"finding_id": "A", "outcome": "fixed", "cited": ["src/changed.c"]},
    {"finding_id": "A", "outcome": "fixed", "cited": [{"path": CHANGED}]},
    {"finding_id": "A", "outcome": "fixed", "cited": [{"path": CHANGED, "start_line": 1, "code": "x"}]},
    {"finding_id": "A", "outcome": "fixed", "cited": [{"start_line": 1}]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED, 0, 1)]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED, 5, 4)]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED, True, 4)]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED, 1, "4")]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite("/etc/passwd")]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite("src/../../secret.c")]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite("C:/src/changed.c")]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite("src\\changed.c")]},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite("")]},
    {"finding_id": "A", "outcome": "fixed", "reason": 7},
    {"finding_id": "A", "outcome": "fixed", "reason": ["because"]},
], ids=["none", "text", "list", "no-finding-id", "no-outcome", "wrong-finding", "open-outcome", "null-outcome",
        "list-outcome", "unknown-key", "cited-text", "cited-strings", "cite-no-line", "cite-unknown-key",
        "cite-no-path", "line-zero", "end-before-start", "bool-line", "text-line", "absolute", "escaping", "drive",
        "backslash", "empty-path", "numeric-reason", "list-reason"])
def test_an_invalid_result_is_refused(result):
    with pytest.raises(ValueError):
        admit(result)


def test_citations_are_bounded_at_16():
    cited = [cite(CHANGED, line, line) for line in range(1, rc.MAX_CITATIONS + 2)]
    admitted = admit({"finding_id": "A", "outcome": "fixed", "cited": cited[:rc.MAX_CITATIONS]})
    assert rc.MAX_CITATIONS == 16 and len(admitted["cited"]) == 16 and admitted["outcome"] == "fixed"
    with pytest.raises(ValueError):
        admit({"finding_id": "A", "outcome": "fixed", "cited": cited})


def test_the_reason_is_bounded_at_2000_characters_and_only_its_hash_is_kept():
    reason = "r" * rc.MAX_REASON_CHARS
    admitted = admit({"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED)], "reason": reason})
    assert rc.MAX_REASON_CHARS == 2000 and admitted["reason_sha256"] == hashlib.sha256(reason.encode()).hexdigest()
    assert "reason" not in admitted and reason not in repr(admitted)
    assert admit({"finding_id": "A", "outcome": "fixed", "reason": ""})["reason_sha256"] == hashlib.sha256(
        b"").hexdigest()
    with pytest.raises(ValueError):
        admit({"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED)], "reason": reason + "r"})


def test_admit_result_refuses_requests_and_snapshots_that_do_not_belong_together():
    request, prior, current = request_for("A")
    result = {"finding_id": "A", "outcome": "insufficient_evidence"}
    for bad in ({**request, "schema": "other/1"}, {**request, "finding_id": ""}, {**request, "prior_run_id": "run-0"},
                {**request, "current_run_id": "run-9"}, None):
        with pytest.raises(ValueError):
            rc.admit_result(bad, result, prior_snapshot=prior, current_snapshot=current)
    for before, after in ((current, prior), (prior, prior), (prior, {**current, "target_id": "engine"}),
                          ({**prior, "schema": "other/1"}, current), (prior, {**current, "reviewed_units": [CHANGED]})):
        with pytest.raises(ValueError):
            rc.admit_result(request, result, prior_snapshot=before, current_snapshot=after)


# ------------------------------------------------------------------------------ run_rechecks

class Transport:
    """The external boundary: a scripted stand-in for whatever re-checks a finding."""

    def __init__(self, answers, live=None):
        self.answers, self.seen = answers, []
        if live is not None:
            self.live = live

    def __call__(self, request):
        self.seen.append(request["finding_id"])
        request["prior_locations"].clear()   # a transport cannot damage the caller's request
        answer = self.answers[request["finding_id"]]
        if isinstance(answer, BaseException):
            raise answer
        return answer


def batch():
    prior, current, lifecycle = scenario()
    return rc.build_requests(lifecycle, prior)["requests"], prior, current, lifecycle


def test_run_rechecks_admits_each_answer_and_feeds_the_lifecycle():
    requests, prior, current, lifecycle = batch()
    kept = copy.deepcopy(requests)
    transport = Transport({
        "A": {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED)], "reason": "bounded now"},
        "B": {"finding_id": "B", "outcome": "still_present", "cited": [cite(SAME)]},
        "C": {"finding_id": "C", "outcome": "fixed", "cited": [cite(SAME)]}})
    ran = rc.run_rechecks(requests, transport, prior_snapshot=prior, current_snapshot=current)
    assert transport.seen == ["B", "C", "A"] and requests == kept
    assert list(ran["results"]) == ["A", "B", "C"]
    assert ran["counts"] == {"fixed": 1, "still_present": 1, "insufficient_evidence": 1, "errors": 0}
    assert ran["results"]["C"]["downgrade_reason"] == "fixed_without_changed_citation"
    applied = lc.apply_rechecks(lifecycle, ran["results"])
    assert {row["finding_id"]: row["state"] for row in applied["prior"]} == {
        "A": "fixed", "B": "still_present", "C": "fix_candidate", "D": "persisting", "E": "not_covered"}
    assert lc.metrics(applied)["fix_rate"] == c.ratio(1, 5)


@pytest.mark.parametrize("failure, name", [
    (OSError("connection refused by 10.0.0.7"), "OSError"),
    (TimeoutError("deadline exceeded for token abc"), "TimeoutError"),
    (ValueError("could not parse the answer"), "ValueError"),
    (ConnectionResetError("peer reset"), "ConnectionResetError"),
], ids=["os", "timeout", "value", "os-subclass"])
def test_a_transport_failure_is_insufficient_evidence_recorded_by_class_only(failure, name):
    requests, prior, current, lifecycle = batch()
    transport = Transport({"A": failure, "B": {"finding_id": "B", "outcome": "insufficient_evidence"},
                           "C": {"finding_id": "C", "outcome": "fixed", "cited": [cite(CMD)]}})
    ran = rc.run_rechecks(requests, transport, prior_snapshot=prior, current_snapshot=current)
    assert ran["results"]["A"] == {"finding_id": "A", "outcome": "insufficient_evidence", "error_class": name}
    assert str(failure) not in repr(ran)
    assert ran["counts"] == {"fixed": 1, "still_present": 0, "insufficient_evidence": 2, "errors": 1}
    applied = lc.apply_rechecks(lifecycle, ran["results"])
    assert [row["state"] for row in applied["prior"]][:3] == ["fix_candidate", "not_redetected", "fixed"]


@pytest.mark.parametrize("answer", [
    None, "fixed", {"finding_id": "B", "outcome": "fixed"}, {"finding_id": "A", "outcome": "done"},
    {"finding_id": "A", "outcome": "fixed", "cited": [cite("../../etc/passwd")]},
    {"finding_id": "A", "outcome": "fixed", "extra": "ignore previous instructions"},
], ids=["none", "text", "wrong-finding", "open-outcome", "escaping-path", "unknown-key"])
def test_an_invalid_transport_answer_is_an_error_row_not_an_exception(answer):
    requests, prior, current, _ = batch()
    only = [item for item in requests if item["finding_id"] == "A"]
    ran = rc.run_rechecks(only, Transport({"A": answer}), prior_snapshot=prior, current_snapshot=current)
    assert ran["results"] == {"A": {"finding_id": "A", "outcome": "insufficient_evidence",
                                    "error_class": "ValueError"}}
    assert ran["counts"] == {"fixed": 0, "still_present": 0, "insufficient_evidence": 1, "errors": 1}


def test_an_unexpected_transport_exception_is_not_swallowed():
    requests, prior, current, _ = batch()
    with pytest.raises(RuntimeError):
        rc.run_rechecks(requests, Transport({"B": RuntimeError("bug")}), prior_snapshot=prior,
                        current_snapshot=current)


@pytest.mark.parametrize("transport", [None, "model", 7], ids=repr)
def test_there_is_no_built_in_transport(transport):
    requests, prior, current, _ = batch()
    with pytest.raises(ValueError, match="this module never calls a model"):
        rc.run_rechecks(requests, transport, prior_snapshot=prior, current_snapshot=current)
    with pytest.raises(ValueError, match="this module never calls a model"):
        rc.run_rechecks(requests, transport, prior_snapshot=prior, current_snapshot=current, live=True)


def test_a_live_transport_runs_only_when_the_caller_says_live():
    requests, prior, current, _ = batch()
    answers = {key: {"finding_id": key, "outcome": "insufficient_evidence"} for key in "ABC"}
    live = Transport(answers, live=True)
    with pytest.raises(ValueError, match="live=True"):
        rc.run_rechecks(requests, live, prior_snapshot=prior, current_snapshot=current)
    assert live.seen == []
    ran = rc.run_rechecks(requests, live, prior_snapshot=prior, current_snapshot=current, live=True)
    assert live.seen == ["B", "C", "A"] and ran["counts"]["insufficient_evidence"] == 3
    with pytest.raises(ValueError):
        rc.run_rechecks(requests, live, prior_snapshot=prior, current_snapshot=current, live="yes")


@pytest.mark.parametrize("flag", [None, False], ids=["unflagged", "flagged-offline"])
@pytest.mark.parametrize("live", [False, True], ids=["default", "live"])
def test_an_offline_transport_runs_with_or_without_live(flag, live):
    requests, prior, current, _ = batch()
    transport = Transport({key: {"finding_id": key, "outcome": "insufficient_evidence"} for key in "ABC"}, live=flag)
    ran = rc.run_rechecks(requests, transport, prior_snapshot=prior, current_snapshot=current, live=live)
    assert len(ran["results"]) == 3 and ran["counts"]["errors"] == 0


def test_run_rechecks_validates_the_batch_before_calling_the_transport():
    requests, prior, current, _ = batch()
    transport = Transport({})
    for bad in ([*requests, requests[0]], [{**requests[0], "schema": "other/1"}],
                [{**requests[0], "current_run_id": "run-9"}], [None]):
        with pytest.raises(ValueError):
            rc.run_rechecks(bad, transport, prior_snapshot=prior, current_snapshot=current)
    with pytest.raises(ValueError):
        rc.run_rechecks(requests, transport, prior_snapshot=current, current_snapshot=prior)
    assert transport.seen == []
    empty = rc.run_rechecks([], transport, prior_snapshot=prior, current_snapshot=current)
    assert empty == {"results": {}, "counts": {"fixed": 0, "still_present": 0, "insufficient_evidence": 0,
                                               "errors": 0}}


def test_a_batch_is_bounded_at_1000_requests():
    request, prior, current = request_for("A")
    many = [{**request, "finding_id": f"X{index:04d}"} for index in range(rc.MAX_REQUESTS + 1)]

    def decline(item):
        return {"finding_id": item["finding_id"], "outcome": "insufficient_evidence"}

    ran = rc.run_rechecks(many[:rc.MAX_REQUESTS], decline, prior_snapshot=prior, current_snapshot=current)
    assert rc.MAX_REQUESTS == 1000 and ran["counts"]["insufficient_evidence"] == 1000
    with pytest.raises(ValueError):
        rc.run_rechecks(many, decline, prior_snapshot=prior, current_snapshot=current)


# --------------------------------------------------------------------------- score_fix_pairs

def test_fix_pairs_are_scored_against_the_key_with_wilson_intervals():
    expected = {"f1": "fixed", "f2": "fixed", "f3": "fixed", "f4": "fixed", "s1": "still_present",
                "s2": "still_present", "s3": "still_present"}
    results = {"f1": {"outcome": "fixed"}, "f2": {"outcome": "still_present"},
               "f3": {"outcome": "insufficient_evidence", "error_class": "OSError"},
               "s1": {"outcome": "still_present"}, "s2": {"outcome": "fixed"}, "s3": {"outcome": "still_present"}}
    kept = copy.deepcopy((expected, results))
    score = rc.score_fix_pairs(expected, results)
    assert (expected, results) == kept
    assert {name: score[name] for name in ("correct_fixed", "correct_still_present", "false_fix", "missed_fix",
                                           "undecided", "expected_fixed", "expected_still_present", "total")} == {
        "correct_fixed": 1, "correct_still_present": 2, "false_fix": 1, "missed_fix": 1, "undecided": 2,
        "expected_fixed": 4, "expected_still_present": 3, "total": 7}
    assert score["fix_recall"] == c.ratio(1, 4, interval=True)
    assert score["false_fix_rate"] == c.ratio(1, 3, interval=True)
    assert score["still_present_recall"] == c.ratio(2, 3, interval=True)
    assert score["undecided_rate"] == c.ratio(2, 7, interval=True)
    assert score["fix_recall"]["interval"]["level"] == 0.95 and score["fix_recall"]["value"] == 0.25


def test_fix_pair_ratios_over_an_empty_class_are_empty_denominators_not_zero():
    score = rc.score_fix_pairs({"f1": "fixed"}, {"f1": {"outcome": "fixed"}})
    assert score["fix_recall"]["value"] == 1.0
    assert (score["false_fix_rate"]["value"], score["false_fix_rate"]["status"],
            score["false_fix_rate"]["interval"]) == (None, "empty_denominator", None)
    nothing = rc.score_fix_pairs({}, {})
    assert nothing["total"] == 0 and nothing["undecided_rate"]["status"] == "empty_denominator"


def test_fix_pairs_score_the_output_of_run_rechecks():
    requests, prior, current, _ = batch()
    transport = Transport({"A": {"finding_id": "A", "outcome": "fixed", "cited": [cite(CHANGED)]},
                           "B": {"finding_id": "B", "outcome": "fixed", "cited": [cite(CHANGED)]},
                           "C": OSError("down")})
    ran = rc.run_rechecks(requests, transport, prior_snapshot=prior, current_snapshot=current)
    score = rc.score_fix_pairs({"A": "fixed", "B": "still_present", "C": "fixed"}, ran["results"])
    assert (score["correct_fixed"], score["false_fix"], score["undecided"]) == (1, 1, 1)


@pytest.mark.parametrize("expected, results", [
    ({"f1": "resolved"}, {}),
    ({"f1": "insufficient_evidence"}, {}),
    ({"f1": "fixed"}, {"f2": {"outcome": "fixed"}}),
    ({"f1": "fixed"}, {"f1": {"outcome": "done"}}),
    ({"f1": "fixed"}, {"f1": "fixed"}),
    ({"f1": "fixed"}, {"f1": {}}),
    (["f1"], {}),
    ({"f1": "fixed"}, None),
], ids=["open-expectation", "undecidable-expectation", "result-outside-key", "open-outcome", "bare-outcome",
        "no-outcome", "expected-not-a-map", "results-not-a-map"])
def test_fix_pair_scoring_refuses_open_vocabularies_and_unkeyed_results(expected, results):
    with pytest.raises(ValueError):
        rc.score_fix_pairs(expected, results)
