"""Lifecycle of prior findings in a new run: absence is never a fix (finding-metrics.md 4.2, 5.6)."""
from __future__ import annotations

import copy

import pytest

from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import lifecycle as lc
from appsec_review.observability.findings.identity import fingerprint

CODE = "void f(char *p) {\n  char b[8];\n  strcpy(b, p); // copy\n}\n"
PATH = "src/net/parse.c"
H1, H2, H3 = "1" * 64, "2" * 64, "3" * 64


def located(path=PATH, line=10, function="parse_packet", code=CODE):
    return [{"path": path, "start_line": line, "end_line": line + 2, "function": function, "code": code}]


def finding(finding_id="F1", **changes):
    value = {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "lane": "lead", "locations": located()}
    value.update(changes)
    return value


def other(finding_id="F2", path="src/cmd/run.c", function="run_command", code="system(cmd);"):
    return finding(finding_id, weakness_cwe="CWE-78", severity="low",
                   locations=located(path=path, function=function, code=code))


def snapshot(findings, **changes):
    arguments = dict(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                     fingerprint=fingerprint)
    arguments.update(changes)
    return c.build_snapshot(**arguments)


def prior_row(result, finding_id="F1"):
    return next(row for row in result["prior"] if row["finding_id"] == finding_id)


def unmatched(prior_units, current_units, *, unreviewed=None, findings=None):
    """Classify a prior finding the current run (which found nothing) did not match."""
    before = snapshot(findings or [finding()], reviewed_units=prior_units)
    after = snapshot([], run_id="run-2", reviewed_units=current_units, unreviewed_units=unreviewed)
    return prior_row(lc.classify(before, after))


def lifecycle(states, *, severities=None, current=("new",)):
    """A hand-built lifecycle with one prior row per state, for apply_rechecks and metrics."""
    severities = severities or ["high"] * len(states)
    prior = []
    for index, (state, severity) in enumerate(zip(states, severities)):
        persisting = state == "persisting"
        prior.append({"finding_id": f"P{index}", "fingerprint_exact": f"{index:064x}", "state": state,
                      "match_tier": "exact" if persisting else None,
                      "matched_finding_id": f"C{index}" if persisting else None,
                      "reason": "unit_not_reviewed" if state == "not_covered" else None,
                      "change_known": True if state in ("fix_candidate", "not_redetected") else None,
                      "severity": severity, "weakness_cwe": "CWE-121"})
    rows = [{"finding_id": f"N{index}", "fingerprint_exact": f"{index + 100:064x}", "state": state,
             "severity": "high"} for index, state in enumerate(current)]
    return {"prior_run_id": "run-1", "current_run_id": "run-2", "target_id": "game", "stage": "published",
            "prior": prior, "current": rows}


# ---------------------------------------------------------------------------------- classify

def test_matched_findings_persist_with_their_tier_and_current_id():
    before = snapshot([finding("P1"), other("P2", path="src/old/run.c")])
    after = snapshot([finding("C1"), other("C2", path="src/new/run.c")], run_id="run-2")
    result = lc.classify(before, after)
    assert result["prior"] == [
        {"finding_id": "P1", "fingerprint_exact": before["findings"][0]["fingerprint"]["exact"],
         "state": "persisting", "match_tier": "exact", "matched_finding_id": "C1", "reason": None,
         "change_known": None, "severity": "high", "weakness_cwe": "CWE-121"},
        {"finding_id": "P2", "fingerprint_exact": before["findings"][1]["fingerprint"]["exact"],
         "state": "persisting", "match_tier": "relocated", "matched_finding_id": "C2", "reason": None,
         "change_known": None, "severity": "low", "weakness_cwe": "CWE-78"}]
    assert result["current"] == [
        {"finding_id": "C1", "fingerprint_exact": after["findings"][0]["fingerprint"]["exact"],
         "state": "persisting", "severity": "high"},
        {"finding_id": "C2", "fingerprint_exact": after["findings"][1]["fingerprint"]["exact"],
         "state": "persisting", "severity": "low"}]
    assert {key: result[key] for key in ("prior_run_id", "current_run_id", "target_id", "stage")} == {
        "prior_run_id": "run-1", "current_run_id": "run-2", "target_id": "game", "stage": "published"}
    assert list(result) == list(lc.LIFECYCLE_FIELDS) and lc.check_lifecycle(result) == result


def test_unknown_current_coverage_is_not_covered_never_progress():
    row = unmatched({PATH: H1}, None)
    assert (row["state"], row["reason"], row["change_known"]) == ("not_covered", "coverage_unknown", None)
    assert row["match_tier"] is None and row["matched_finding_id"] is None


@pytest.mark.parametrize("unreviewed, reason", [
    (None, "unit_not_reviewed"),
    ({"src/else.c": "not_built"}, "unit_not_reviewed"),
    ({PATH: "not_built"}, "not_built"),
], ids=["no-residual", "other-unit", "named"])
def test_an_unreviewed_unit_is_not_covered_with_its_residual_reason(unreviewed, reason):
    row = unmatched({PATH: H1}, {"src/unrelated.c": H1}, unreviewed=unreviewed)
    assert (row["state"], row["reason"], row["change_known"]) == ("not_covered", reason, None)


def test_any_unreviewed_location_makes_the_finding_not_covered_even_when_another_changed():
    two = finding(locations=located() + located(path="src/net/util.c", function="copy_in", code="memcpy(a, b, n);"))
    row = unmatched({PATH: H1, "src/net/util.c": H1}, {PATH: H2}, unreviewed={"src/net/util.c": "budget_exhausted"},
                    findings=[two])
    assert (row["state"], row["reason"]) == ("not_covered", "budget_exhausted")


def test_changed_content_in_a_reviewed_unit_is_only_a_fix_candidate():
    row = unmatched({PATH: H1}, {PATH: H2})
    assert (row["state"], row["reason"], row["change_known"]) == ("fix_candidate", None, True)


def test_unchanged_content_in_a_reviewed_unit_is_not_redetected():
    row = unmatched({PATH: H1}, {PATH: H1})
    assert (row["state"], row["reason"], row["change_known"]) == ("not_redetected", None, True)


@pytest.mark.parametrize("prior_units, current_units", [
    (None, {PATH: H2}),
    ({"src/unrelated.c": H1}, {PATH: H2}),
    ({PATH: None}, {PATH: H2}),
    ({PATH: H1}, {PATH: None}),
], ids=["prior-coverage-unknown", "prior-unit-absent", "prior-hash-unknown", "current-hash-unknown"])
def test_an_unknown_hash_never_claims_a_change(prior_units, current_units):
    row = unmatched(prior_units, current_units)
    assert (row["state"], row["change_known"]) == ("not_redetected", False)


@pytest.mark.parametrize("second_before, second_after, state, known", [
    (H1, H3, "fix_candidate", True),
    (None, H3, "not_redetected", False),
    (H3, H3, "not_redetected", True),
], ids=["one-changed", "one-unknown", "all-equal"])
def test_multi_location_findings_compare_every_path(second_before, second_after, state, known):
    two = finding(locations=located() + located(path="src/net/util.c", function="copy_in", code="memcpy(a, b, n);"))
    row = unmatched({PATH: H1, "src/net/util.c": second_before}, {PATH: H1, "src/net/util.c": second_after},
                    findings=[two])
    assert (row["state"], row["change_known"]) == (state, known)


def test_one_known_change_is_a_fix_candidate_even_beside_an_unknown_hash():
    two = finding(locations=located() + located(path="src/net/util.c", function="copy_in", code="memcpy(a, b, n);"))
    row = unmatched({PATH: None, "src/net/util.c": H1}, {PATH: H1, "src/net/util.c": H2}, findings=[two])
    assert (row["state"], row["change_known"]) == ("fix_candidate", True)


def test_unmatched_current_findings_are_new_unless_the_history_recorded_a_fix():
    before = snapshot([finding("P1")], reviewed_units={PATH: H1})
    after = snapshot([other("C1"), other("C2", path="src/cmd/exec.c", function="exec_script", code="popen(s);")],
                     run_id="run-2", reviewed_units={PATH: H1})
    exact, relocated = (after["findings"][index]["fingerprint"] for index in (0, 1))
    plain = lc.classify(before, after)
    assert [row["state"] for row in plain["current"]] == ["new", "new"]
    by_exact = lc.classify(before, after, previously_fixed=frozenset({exact["exact"]}))
    assert [row["state"] for row in by_exact["current"]] == ["regressed", "new"]
    by_relocated = lc.classify(before, after, previously_fixed=frozenset({relocated["relocated"], "f" * 64}))
    assert [row["state"] for row in by_relocated["current"]] == ["new", "regressed"]


def test_a_matched_current_finding_persists_even_when_its_key_was_once_fixed():
    before, after = snapshot([finding("P1")]), snapshot([finding("C1")], run_id="run-2")
    key = after["findings"][0]["fingerprint"]["exact"]
    assert lc.classify(before, after, previously_fixed=frozenset({key}))["current"][0]["state"] == "persisting"


def test_rows_are_sorted_by_finding_id_and_inputs_are_not_mutated():
    before = snapshot([other("B"), finding("A")], reviewed_units={PATH: H1})
    after = snapshot([other("Z", path="src/z.c", function="zed", code="execl(z);"), finding("Y")], run_id="run-2")
    kept = copy.deepcopy((before, after))
    result = lc.classify(before, after)
    assert [row["finding_id"] for row in result["prior"]] == ["A", "B"]
    assert [row["finding_id"] for row in result["current"]] == ["Y", "Z"]
    assert (before, after) == kept
    assert result == lc.classify(copy.deepcopy(before), copy.deepcopy(after))


@pytest.mark.parametrize("change", [{"target_id": "other"}, {"stage": "verified"}, {"run_id": "run-1"}],
                         ids=["target", "stage", "same-run"])
def test_classify_refuses_incomparable_snapshots(change):
    arguments = {"run_id": "run-2", **change}
    with pytest.raises(ValueError):
        lc.classify(snapshot([finding()]), snapshot([finding()], **arguments))


@pytest.mark.parametrize("side", ["prior", "current"])
def test_classify_refuses_a_document_that_is_not_a_snapshot(side):
    good, bad = snapshot([finding()]), {**snapshot([finding()], run_id="run-2"), "schema": "other/1"}
    with pytest.raises(ValueError):
        lc.classify(bad, good) if side == "prior" else lc.classify(good, bad)


@pytest.mark.parametrize("keys", ["abc", [1]], ids=["string", "non-text"])
def test_classify_refuses_previously_fixed_that_is_not_a_set_of_keys(keys):
    with pytest.raises(ValueError):
        lc.classify(snapshot([finding()]), snapshot([finding()], run_id="run-2"), previously_fixed=keys)


# ---------------------------------------------------------------------------- apply_rechecks

def test_only_an_admitted_recheck_moves_a_row_to_fixed_or_still_present():
    before = lifecycle(["fix_candidate", "not_redetected", "fix_candidate", "persisting"])
    kept = copy.deepcopy(before)
    after = lc.apply_rechecks(before, {"P0": {"outcome": "fixed"}, "P1": {"outcome": "still_present"},
                                       "P2": {"outcome": "insufficient_evidence", "error_class": "OSError"}})
    assert [row["state"] for row in after["prior"]] == ["fixed", "still_present", "fix_candidate", "persisting"]
    assert before == kept and after is not before and after["prior"][0] is not before["prior"][0]
    assert lc.apply_rechecks(before, {}) == before
    assert lc.check_lifecycle(after) == after


@pytest.mark.parametrize("state", ["fixed", "not_covered", "persisting", "still_present"])
@pytest.mark.parametrize("outcome", ["fixed", "insufficient_evidence"])
def test_a_recheck_result_for_a_row_in_another_state_is_refused(state, outcome):
    with pytest.raises(ValueError):
        lc.apply_rechecks(lifecycle([state]), {"P0": {"outcome": outcome}})


@pytest.mark.parametrize("results", [
    {"P9": {"outcome": "fixed"}}, {"N0": {"outcome": "fixed"}}, {"P0": {"outcome": "resolved"}}, {"P0": {}},
    {"P0": "fixed"}, {7: {"outcome": "fixed"}}, [("P0", "fixed")],
], ids=["unknown-id", "current-id", "open-outcome", "no-outcome", "not-a-mapping", "non-text-id", "not-a-map"])
def test_apply_rechecks_refuses_unknown_findings_and_outcomes(results):
    with pytest.raises(ValueError):
        lc.apply_rechecks(lifecycle(["fix_candidate"]), results)


# ----------------------------------------------------------------------------------- metrics

def test_metrics_are_unavailable_without_a_named_prior_run():
    assert lc.metrics(None) == {"available": False, "reason": "no_prior_run"}
    assert lc.metrics(None, ages={"a" * 64: 3}) == c.unavailable("no_prior_run")


def test_metrics_count_every_state_and_only_fixed_as_a_fix():
    states = ["persisting", "persisting", "not_covered", "not_redetected", "fix_candidate", "fixed",
              "still_present", "not_redetected"]
    severities = ["high", "low", "critical", "medium", "high", "critical", None, "high"]
    doc = lifecycle(states, severities=severities, current=("new", "new", "regressed", "persisting", "persisting"))
    doc["prior"][3]["change_known"] = False
    doc["prior"][1]["match_tier"] = "relocated"
    kept = copy.deepcopy(doc)
    section = lc.metrics(doc)
    assert doc == kept
    assert section["available"] is True
    assert (section["prior_run_id"], section["current_run_id"]) == ("run-1", "run-2")
    assert section["prior_states"] == {"persisting": 2, "not_covered": 1, "not_redetected": 2, "fix_candidate": 1,
                                       "fixed": 1, "still_present": 1, "null": 0}
    assert section["current_states"] == {"new": 2, "regressed": 1, "persisting": 2, "null": 0}
    assert section["fix_rate"] == c.ratio(1, 8) and section["fix_rate"]["value"] == 0.125
    assert section["not_redetected_rate"] == c.ratio(2, 8)
    assert section["not_covered_rate"] == c.ratio(1, 8)
    assert "interval" not in section["fix_rate"]
    assert section["change_unknown"] == 1
    assert section["match_tiers"] == {"exact": 1, "relocated": 1}
    assert section["actionable"] == {"persisting": 1, "not_covered": 1, "not_redetected": 1, "fix_candidate": 1,
                                     "fixed": 1, "still_present": 0, "null": 0}
    assert section["introduced"] == 2
    assert section["median_age_of_persisting_actionable"] is None


def test_a_fix_candidate_never_counts_toward_the_fix_rate():
    section = lc.metrics(lifecycle(["fix_candidate", "not_redetected", "not_covered"]))
    assert section["fix_rate"]["numerator"] == 0 and section["fix_rate"]["value"] == 0.0
    assert section["prior_states"]["fixed"] == 0


def test_metrics_over_an_empty_prior_run_report_empty_denominators_not_zero():
    section = lc.metrics(lifecycle([], current=()))
    for name in ("fix_rate", "not_redetected_rate", "not_covered_rate"):
        assert (section[name]["value"], section[name]["status"]) == (None, "empty_denominator")
    assert section["introduced"] == 0 and section["median_age_of_persisting_actionable"] is None


@pytest.mark.parametrize("supplied, expected", [
    ([3], 3), ([1, 4], 2.5), ([5, 1, 2], 2),
], ids=["one", "even", "odd"])
def test_median_age_covers_persisting_high_and_critical_rows_only(supplied, expected):
    count = len(supplied)
    doc = lifecycle(["persisting"] * count + ["persisting", "not_redetected"],
                    severities=["high", "critical", "high"][:count] + ["low", "critical"])
    ages = {row["fingerprint_exact"]: age for row, age in zip(doc["prior"], supplied + [90, 80])}
    kept = dict(ages)
    assert lc.metrics(doc, ages=ages)["median_age_of_persisting_actionable"] == expected
    assert ages == kept


def test_median_age_is_null_when_nothing_actionable_persists_or_an_age_is_missing():
    doc = lifecycle(["persisting", "persisting", "fixed"], severities=["high", "low", "critical"])
    first, second = (row["fingerprint_exact"] for row in doc["prior"][:2])
    assert lc.metrics(doc, ages={second: 4})["median_age_of_persisting_actionable"] is None
    assert lc.metrics(doc, ages={first: 4})["median_age_of_persisting_actionable"] == 4
    nothing = lifecycle(["persisting", "fixed"], severities=["medium", "high"])
    assert lc.metrics(nothing, ages={})["median_age_of_persisting_actionable"] is None


@pytest.mark.parametrize("age", [0, -1, True, 1.5, "3"], ids=repr)
def test_a_finding_age_is_a_positive_count_of_runs(age):
    doc = lifecycle(["persisting"])
    with pytest.raises(ValueError):
        lc.metrics(doc, ages={doc["prior"][0]["fingerprint_exact"]: age})
    with pytest.raises(ValueError):
        lc.metrics(doc, ages=[age])


def test_metrics_of_a_classified_pair_end_to_end():
    before = snapshot([finding("P1"), other("P2")], reviewed_units={PATH: H1, "src/cmd/run.c": H1})
    after = snapshot([finding("C1")], run_id="run-2", reviewed_units={PATH: H1, "src/cmd/run.c": H2})
    classified = lc.classify(before, after)
    section = lc.metrics(classified, ages={before["findings"][0]["fingerprint"]["exact"]: 2})
    assert section["prior_states"]["persisting"] == 1 and section["prior_states"]["fix_candidate"] == 1
    assert section["fix_rate"] == c.ratio(0, 2) and section["median_age_of_persisting_actionable"] == 2
    fixed = lc.metrics(lc.apply_rechecks(classified, {"P2": {"outcome": "fixed"}}))
    assert fixed["fix_rate"] == c.ratio(1, 2) and fixed["prior_states"]["fix_candidate"] == 0


# --------------------------------------------------------------------------- check_lifecycle

def _edit_row(side, **changes):
    def edit(doc):
        doc[side][0].update(changes)
    return edit


def _drop(key):
    def edit(doc):
        del doc[key]
    return edit


def _set(key, value):
    def edit(doc):
        doc[key] = value
    return edit


def _repeat(side):
    def edit(doc):
        doc[side].append(copy.deepcopy(doc[side][0]))
    return edit


@pytest.mark.parametrize("edit", [
    _drop("stage"), _set("extra", 1), _set("stage", "final"), _set("prior_run_id", ""), _set("target_id", None),
    _set("current_run_id", "run-1"), _set("prior", ()), _set("current", None),
    _edit_row("prior", state="new"), _edit_row("prior", state="regressed"), _edit_row("current", state="fixed"),
    _edit_row("prior", fingerprint_exact="abc"), _edit_row("prior", severity="severe"),
    _edit_row("prior", match_tier="exact"), _edit_row("prior", matched_finding_id="C0"),
    _edit_row("prior", change_known="yes"), _edit_row("prior", reason=""), _edit_row("prior", weakness_cwe="121"),
    _edit_row("prior", note="x"), _edit_row("current", finding_id=""), _edit_row("current", match_tier=None),
    _repeat("prior"), _repeat("current"),
], ids=["no-stage", "extra-field", "open-stage", "empty-run", "null-target", "same-run", "prior-not-list",
        "current-not-list", "prior-new", "prior-regressed", "current-fixed", "bad-fingerprint", "open-severity",
        "tier-without-match", "match-without-tier", "bad-change-known", "empty-reason", "raw-cwe", "extra-row-field",
        "empty-id", "extra-current-field", "repeat-prior", "repeat-current"])
def test_check_lifecycle_refuses_documents_classify_could_not_produce(edit):
    doc = lifecycle(["fix_candidate"])
    edit(doc)
    with pytest.raises(ValueError):
        lc.check_lifecycle(doc)
    with pytest.raises(ValueError):
        lc.metrics(doc)


def test_check_lifecycle_refuses_a_persisting_row_without_its_match_and_non_documents():
    doc = lifecycle(["persisting"])
    doc["prior"][0]["match_tier"] = "nearby"
    with pytest.raises(ValueError):
        lc.check_lifecycle(doc)
    doc["prior"][0]["match_tier"] = None
    with pytest.raises(ValueError):
        lc.check_lifecycle(doc)
    with pytest.raises(ValueError):
        lc.check_lifecycle([])


def test_lifecycle_rows_are_bounded_at_the_snapshot_finding_limit():
    row = {"finding_id": "N", "fingerprint_exact": "0" * 64, "state": "new", "severity": None}
    doc = lifecycle([], current=())
    doc["current"] = [{**row, "finding_id": f"N{index}"} for index in range(c.MAX_FINDINGS)]
    assert lc.metrics(doc)["introduced"] == c.MAX_FINDINGS
    doc["current"].append({**row, "finding_id": "one-more"})
    with pytest.raises(ValueError):
        lc.check_lifecycle(doc)
