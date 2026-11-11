"""Stability of repeated runs, per-defect detection rates and the experiments adapter (T-065)."""
from __future__ import annotations

from copy import deepcopy

import pytest

from appsec_review.observability.experiments import population_id, rebuild, root_cause_id
from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import stability as s
from appsec_review.observability.findings.identity import fingerprint

HASHES = {"configuration_sha256": "1" * 64, "guidance_sha256": "2" * 64, "model_sha256": "3" * 64}


def finding(name, **changes):
    value = {"finding_id": f"F-{name}", "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "source_symbol": "recv", "sink_symbol": f"copy_{name}",
             "locations": [{"path": f"src/{name}.c", "start_line": 10, "end_line": 12,
                            "function": f"parse_{name}", "code": f"copy_{name}(b, p);"}]}
    value.update(changes)
    return value


def snap(run_id, findings, **changes):
    arguments = dict(run_id=run_id, target_id="game", source_revision="a" * 40, fingerprint=fingerprint,
                     findings=[finding(item) if isinstance(item, str) else item for item in findings], **HASHES)
    arguments.update(changes)
    return c.build_snapshot(**arguments)


def runs(*sets, **changes):
    return [snap(f"run-{index}", names, **changes) for index, names in enumerate(sets, 1)]


def key(name):
    return fingerprint(c.normalize_finding(finding(name)))["exact"]


def launch(index, **changes):
    value = {"run_index": index, "started_at": f"2026-11-06T00:{index:02d}:00Z",
             "completed_at": f"2026-11-06T01:{index:02d}:00Z", "raw_artifact_sha256": f"{index:064x}",
             "status": "complete", "scope_sha256": "4" * 64, "agent_sha256": "5" * 64, "tools_sha256": "6" * 64,
             "decoding_sha256": "7" * 64, "context_condition": "source_only",
             "positive_event": "genuine in-scope vulnerability"}
    value.update(changes)
    return value


def launches(snapshots, **changes):
    return {row["run_id"]: launch(index, **changes) for index, row in enumerate(snapshots, 1)}


def rates(detected_by_run, defects=("d1", "d2", "d3")):
    return s.detection_rates([{"run_id": f"run-{index}", "detected": list(found)}
                              for index, found in enumerate(detected_by_run, 1)], defects)


# ------------------------------------------------------------------------------- comparability

def test_comparison_key_is_the_frozen_identity_only():
    snapshot = snap("run-1", "A")
    assert s.comparison_key(snapshot) == {"target_id": "game", "source_revision": "a" * 40, "stage": "published",
                                          **HASHES}
    assert s.comparable(snapshot, snap("run-2", "BC")) == (True, [])


@pytest.mark.parametrize("field, value", [
    ("configuration_sha256", "9" * 64), ("guidance_sha256", "9" * 64), ("model_sha256", "9" * 64),
    ("source_revision", "b" * 40), ("stage", "verified"), ("target_id", "engine")], ids=lambda item: str(item)[:24])
def test_a_differing_identity_field_is_named(field, value):
    assert s.comparable(snap("run-1", "A"), snap("run-2", "A", **{field: value})) == (False, [field])


@pytest.mark.parametrize("field", sorted(HASHES), ids=str)
def test_an_unknown_identity_hash_is_not_equal_even_to_another_unknown(field):
    unknown = snap("run-1", "A", **{field: None})
    assert s.comparable(unknown, snap("run-2", "A")) == (False, [field])
    assert s.comparable(snap("run-2", "A"), unknown) == (False, [field])
    assert s.comparable(unknown, snap("run-3", "A", **{field: None})) == (False, [field])


# -------------------------------------------------------------------------------------- series

def test_series_hand_computed_overlap_and_retention():
    snapshots = runs("ABCD", "ABCEF")
    frozen = deepcopy(snapshots)
    result = s.series(snapshots)
    assert snapshots == frozen
    assert result["available"] is True and result["subset"] == "all"
    assert result["runs"] == [{"run_id": "run-1", "set_size": 4}, {"run_id": "run-2", "set_size": 5}]
    row, = result["adjacent"]
    assert (row["previous_run_id"], row["run_id"], row["status"], row["differing"]) == ("run-1", "run-2", "valid", [])
    assert (row["shared"], row["union"], row["new_to_previous"], row["dropped"]) == (3, 6, 2, 1)
    assert row["jaccard"]["value"] == 0.5 and row["retention"]["value"] == 0.75
    assert (row["retention"]["numerator"], row["retention"]["denominator"]) == (3, 4)
    assert result["mean_adjacent_jaccard"] == {"value": 0.5, "valid_count": 1, "total_count": 1}
    assert result["mean_pairwise"] == {"value": 0.5, "valid_count": 1, "both_empty_pairs": 0,
                                       "incomparable_pairs": 0, "total_count": 1}


def test_overlapping_pairs_never_carry_an_interval():
    result = s.series(runs("ABCD", "ABCEF", "AE"))
    assert result["interval"] == "none_overlapping_run_pairs"
    assert result["counterweight"] == "stability_is_not_precision"
    for row in result["adjacent"]:
        assert "interval" not in row["jaccard"] and "interval" not in row["retention"]
    assert all("interval" not in row["frequency"] for row in result["recurrence"])
    assert "interval" not in result["mean_pairwise"] and "interval" not in result["mean_adjacent_jaccard"]


def test_series_matches_the_documented_four_run_example():
    result = s.series(runs("ABCD", "ABCEF", "AE", "ADE"))
    assert result["mean_adjacent_jaccard"]["value"] == pytest.approx(47 / 90, abs=1e-6)
    assert result["mean_adjacent_jaccard"]["valid_count"] == result["mean_adjacent_jaccard"]["total_count"] == 3
    assert result["mean_pairwise"]["value"] == pytest.approx(5 / 12, abs=1e-6)
    assert result["mean_pairwise"]["valid_count"] == result["mean_pairwise"]["total_count"] == 6
    recurrence = {row["fingerprint"]: row for row in result["recurrence"]}
    assert [row["fingerprint"] for row in result["recurrence"]] == sorted(key(name) for name in "ABCDEF")
    assert recurrence[key("A")]["runs"] == 4 and recurrence[key("A")]["frequency"]["value"] == 1.0
    assert recurrence[key("E")]["frequency"]["numerator"] == 3 and recurrence[key("E")]["frequency"]["denominator"] == 4
    assert recurrence[key("F")]["frequency"]["value"] == 0.25
    assert result["mutually_comparable"] is True and result["recurrence_reason"] is None


def test_empty_against_non_empty_is_zero_and_two_empty_sets_are_not_applicable():
    result = s.series(runs("", "A", "", ""))
    first, second, third = result["adjacent"]
    assert first["status"] == "valid" and first["jaccard"]["value"] == 0.0
    assert first["retention"]["value"] is None and first["retention"]["status"] == "empty_denominator"
    assert second["status"] == "valid" and second["jaccard"]["value"] == 0.0 and second["retention"]["value"] == 0.0
    assert (second["new_to_previous"], second["dropped"]) == (0, 1)
    assert third["status"] == "both_empty" and (third["shared"], third["union"]) == (0, 0)
    assert third["jaccard"]["value"] is None and third["jaccard"]["status"] == "empty_denominator"
    assert result["mean_adjacent_jaccard"] == {"value": 0.0, "valid_count": 2, "total_count": 3}
    assert result["mean_pairwise"] == {"value": 0.0, "valid_count": 3, "both_empty_pairs": 3,
                                       "incomparable_pairs": 0, "total_count": 6}


def test_all_empty_runs_have_no_mean_rather_than_a_zero():
    result = s.series(runs("", ""))
    assert result["mean_adjacent_jaccard"] == {"value": None, "valid_count": 0, "total_count": 1}
    assert result["mean_pairwise"]["value"] is None and result["mean_pairwise"]["both_empty_pairs"] == 1
    assert result["recurrence"] == []


def test_incomparable_runs_are_reported_and_never_compared():
    snapshots = [snap("run-1", "AB"), snap("run-2", "AB", model_sha256="9" * 64), snap("run-3", "AB")]
    result = s.series(snapshots)
    first, second = result["adjacent"]
    for row in (first, second):
        assert row["status"] == "incomparable" and row["differing"] == ["model_sha256"]
        assert row["shared"] is row["union"] is row["new_to_previous"] is row["dropped"] is None
        assert row["jaccard"]["value"] is None and row["jaccard"]["status"] == "unavailable"
        assert row["jaccard"]["reason"] == row["retention"]["reason"] == "incomparable"
    assert result["mean_adjacent_jaccard"] == {"value": None, "valid_count": 0, "total_count": 2}
    assert result["mean_pairwise"] == {"value": 1.0, "valid_count": 1, "both_empty_pairs": 0,
                                       "incomparable_pairs": 2, "total_count": 3}
    assert result["recurrence"] is None and result["recurrence_reason"] == "runs_not_mutually_comparable"
    assert result["mutually_comparable"] is False


def test_runs_with_unknown_identity_have_no_recurrence():
    result = s.series(runs("A", "A", guidance_sha256=None))
    assert result["adjacent"][0]["status"] == "incomparable"
    assert result["adjacent"][0]["differing"] == ["guidance_sha256"]
    assert result["recurrence"] is None


@pytest.mark.parametrize("subset, sizes, jaccard", [
    ("actionable", [1, 2], 0.5), ("all", [4, 4], 1.0), ("published", [2, 3], 2 / 3)], ids=lambda item: str(item)[:12])
def test_subsets_select_which_findings_form_the_set(subset, sizes, jaccard):
    def mixed(promote):
        return [finding("A"),                                               # confirmed high: in every subset
                finding("B", state="supported", severity="critical"),     # published, not actionable
                finding("C", state="confirmed" if promote else "rejected", severity="critical"),
                finding("D", state="candidate", severity="low")]
    result = s.series([snap("run-1", mixed(False)), snap("run-2", mixed(True))], subset=subset)
    assert [row["set_size"] for row in result["runs"]] == sizes
    assert result["adjacent"][0]["jaccard"]["value"] == pytest.approx(jaccard, abs=1e-6)


@pytest.mark.parametrize("count", [0, 1], ids=str)
def test_fewer_than_two_runs_is_unavailable_not_zero(count):
    snapshots = runs(*["A"] * count)
    assert s.series(snapshots) == {"available": False, "reason": "fewer_than_two_runs"}
    assert s.flapping(snapshots) == {"available": False, "reason": "fewer_than_two_runs"}


def test_series_refuses_bad_input():
    with pytest.raises(ValueError, match="repeats a run_id"):
        s.series([snap("run-1", "A"), snap("run-1", "B")])
    with pytest.raises(ValueError, match="unknown stability subset"):
        s.series(runs("A", "A"), subset="high")
    with pytest.raises(ValueError, match="snapshot"):
        s.series([snap("run-1", "A"), {"schema": "other"}])
    with pytest.raises(ValueError, match="sequence"):
        s.series(snap("run-1", "A"))
    with pytest.raises(ValueError, match="repeats a run_id"):
        s.flapping([snap("run-1", "A"), snap("run-1", "A")])


def test_series_bound_is_exactly_512_runs():
    snapshots = [snap(f"run-{index}", "") for index in range(s.MAX_SERIES_RUNS)]
    result = s.series(snapshots)
    assert len(result["runs"]) == 512 and result["mean_pairwise"]["both_empty_pairs"] == 512 * 511 // 2
    with pytest.raises(ValueError, match="at most 512"):
        s.series([*snapshots, snap("run-extra", "")])
    with pytest.raises(ValueError, match="at most 512"):
        s.flapping([*snapshots, snap("run-extra", "")])


# ------------------------------------------------------------------------------------ flapping

def test_flapping_names_severity_and_state_changes_of_recurring_findings():
    snapshots = [
        snap("run-1", [finding("A"), finding("B"), finding("C", severity=None), finding("D")]),
        snap("run-2", [finding("A", severity="critical"), finding("B", state="supported"),
                       finding("C", severity="low"), finding("E", severity="low")]),
        snap("run-3", [finding("A"), finding("B"), finding("C", severity="low", state="rejected"), finding("G")]),
        snap("run-4", [finding("G")]),
    ]
    frozen = deepcopy(snapshots)
    result = s.flapping(snapshots)
    assert snapshots == frozen
    assert result["status"] == "measured" and result["runs"] == 4
    assert result["severity_flapping"] == sorted([
        {"fingerprint": key("A"), "severities": ["critical", "high"]},
        {"fingerprint": key("C"), "severities": ["low", "null"]}], key=lambda row: row["fingerprint"])
    assert result["state_flapping"] == sorted([
        {"fingerprint": key("B"), "states": ["confirmed", "supported"]},
        {"fingerprint": key("C"), "states": ["confirmed", "rejected"]}], key=lambda row: row["fingerprint"])
    assert (result["severity_flapping_count"], result["state_flapping_count"]) == (2, 2)
    # A, B, C and G recur; D and E appear once and can neither flap nor count. C flaps both ways, once.
    assert result["recurring_fingerprints"] == 4
    assert (result["flapping_share"]["numerator"], result["flapping_share"]["denominator"]) == (3, 4)
    assert result["flapping_share"]["value"] == 0.75 and "interval" not in result["flapping_share"]


def test_flapping_without_recurring_findings_has_an_empty_denominator():
    result = s.flapping(runs("A", "B"))
    assert result["recurring_fingerprints"] == 0 and result["severity_flapping"] == result["state_flapping"] == []
    assert result["flapping_share"]["value"] is None and result["flapping_share"]["status"] == "empty_denominator"


def test_flapping_over_incomparable_runs_is_reported_incomparable():
    result = s.flapping([snap("run-1", "A"), snap("run-2", [finding("A", severity="low")], stage="verified"),
                         snap("run-3", "A", configuration_sha256=None)])
    assert result == {"available": True, "status": "incomparable", "differing": ["stage", "configuration_sha256"]}


# ----------------------------------------------------------------------------- detection rates

def test_detection_rates_per_defect_carry_a_wilson_interval():
    result = rates([["d1", "d2"], ["d1", "d2"], ["d1"], ["d1"], ["d1"]], defects=("d3", "d1", "d2"))
    assert result["available"] is True and result["runs"] == 5 and result["defect_count"] == 3
    assert result["run_ids"] == ["run-1", "run-2", "run-3", "run-4", "run-5"]
    first, second, third = result["defects"]
    assert [row["defect_id"] for row in result["defects"]] == ["d1", "d2", "d3"]
    assert (first["detections"], first["runs"], first["rate"]["value"]) == (5, 5, 1.0)
    assert first["rate"]["interval"] == {"low": pytest.approx(0.565509, abs=1e-5), "high": 1.0, "level": 0.95}
    assert (second["detections"], second["rate"]["value"]) == (2, 0.4)
    assert second["rate"]["interval"]["low"] == pytest.approx(0.1176, abs=1e-4)
    assert second["rate"]["interval"]["high"] == pytest.approx(0.7693, abs=1e-4)
    assert third["rate"]["value"] == 0.0 and third["rate"]["interval"]["low"] == 0.0
    assert third["rate"]["interval"]["high"] == pytest.approx(0.434491, abs=1e-5)
    assert result["always_detected"] == {"count": 1, "defect_ids": ["d1"]}
    assert result["intermittent"] == {"count": 1, "defect_ids": ["d2"]}
    assert result["never_detected"] == {"count": 1, "defect_ids": ["d3"]}
    assert result["mean_single_run_recall"] == {"value": pytest.approx(7 / 15, abs=1e-6), "runs": 5,
                                                "basis": "mean_of_single_run_recalls_no_interval"}
    assert result["minimum_runs_recommended"] == 5 and result["sufficient_runs"] is True


@pytest.mark.parametrize("count, sufficient", [(1, False), (4, False), (5, True), (6, True)], ids=str)
def test_fewer_than_five_runs_is_marked_insufficient(count, sufficient):
    assert rates([["d1"]] * count)["sufficient_runs"] is sufficient


def test_detection_rates_do_not_mutate_their_input():
    records = [{"run_id": "run-1", "detected": ["d2", "d1"]}]
    frozen = deepcopy(records)
    s.detection_rates(records, ["d1", "d2"])
    assert records == frozen


def test_missing_detection_input_is_unavailable():
    assert s.detection_rates([], ["d1"]) == {"available": False, "reason": "no_runs"}
    assert s.detection_rates([{"run_id": "run-1", "detected": []}], []) == {"available": False,
                                                                           "reason": "no_defects"}


@pytest.mark.parametrize("records, defects, message", [
    ([{"run_id": "r", "detected": ["d1", "d1"]}], ["d1"], "repeats a detected"),
    ([{"run_id": "r", "detected": ["d9"]}], ["d1"], "outside the key"),
    ([{"run_id": "r", "detected": "d1"}], ["d1"], "list of defect ids"),
    ([{"run_id": "r", "detected": []}, {"run_id": "r", "detected": []}], ["d1"], "repeat a run_id"),
    ([{"run_id": "r", "detected": [], "extra": 1}], ["d1"], "exactly run_id and detected"),
    ([{"run_id": "", "detected": []}], ["d1"], "run_id"),
    ([{"run_id": "r", "detected": []}], ["d1", "d1"], "defect ids repeat"),
    ([{"run_id": "r", "detected": []}], [7], "defect id"),
    ("runs", ["d1"], "sequence of run records"),
], ids=["repeat-detected", "foreign", "detected-text", "repeat-run", "extra-key", "empty-run-id", "repeat-defect",
        "defect-type", "runs-text"])
def test_detection_rates_refuse_inconsistent_input(records, defects, message):
    with pytest.raises(ValueError, match=message):
        s.detection_rates(records, defects)


def test_detection_bounds_are_exact():
    many_runs = [{"run_id": f"run-{index}", "detected": []} for index in range(s.MAX_DETECTION_RUNS)]
    assert s.detection_rates(many_runs, ["d1"])["runs"] == 1000
    with pytest.raises(ValueError, match="at most 1000 runs"):
        s.detection_rates([*many_runs, {"run_id": "extra", "detected": []}], ["d1"])
    defects = [f"d{index}" for index in range(s.MAX_DEFECTS)]
    assert s.detection_rates([{"run_id": "r", "detected": []}], defects)["never_detected"]["count"] == 10_000
    with pytest.raises(ValueError, match="at most 10000 defects"):
        s.detection_rates([{"run_id": "r", "detected": []}], [*defects, "extra"])


def test_detection_alarm_names_defects_that_fell_below_their_prior_interval():
    baseline = rates([["d1", "d2"], ["d1", "d2"], ["d1"], ["d1"], ["d1"]])
    candidate = rates([["d2"], ["d2"], [], [], []])
    frozen = deepcopy((baseline, candidate))
    alarm = s.detection_alarm(baseline, candidate)
    assert (baseline, candidate) == frozen
    assert alarm["status"] == "detection_alarm" and alarm["scope"] == "operator_alarm_not_run_verdict"
    assert [row["defect_id"] for row in alarm["fell"]] == ["d1"] and alarm["fell_count"] == 1
    assert alarm["fell"][0]["baseline"]["numerator"] == 5 and alarm["fell"][0]["candidate"]["numerator"] == 0
    assert alarm["defect_count"] == 3 and alarm["sufficient_runs"] is True
    assert "verdict" not in alarm and "clean" not in alarm


def test_overlapping_intervals_raise_no_alarm_and_few_runs_are_flagged():
    baseline = rates([["d1"], ["d1"], ["d1"], ["d1"], ["d1"]])
    candidate = rates([["d1"], [], [], []])                # 1/4: upper bound 0.699 is above 0.5655
    alarm = s.detection_alarm(baseline, candidate)
    assert alarm["status"] == "no_alarm" and alarm["fell"] == [] and alarm["sufficient_runs"] is False


@pytest.mark.parametrize("high, status", [(0.499999, "detection_alarm"), (0.5, "no_alarm")], ids=str)
def test_alarm_needs_the_candidate_interval_strictly_below(high, status):
    def result(low_edge, high_edge):
        return {"available": True, "sufficient_runs": True, "defects": [
            {"defect_id": "d1", "rate": {"interval": {"low": low_edge, "high": high_edge, "level": 0.95}}}]}
    assert s.detection_alarm(result(0.5, 0.9), result(0.1, high))["status"] == status


def test_alarm_over_different_defects_or_missing_rates_is_not_a_comparison():
    alarm = s.detection_alarm(rates([["d1"]], defects=("d1", "d2")), rates([["d1"]], defects=("d1", "d3")))
    assert alarm["status"] == "incomparable" and alarm["reason"] == "different_defect_ids"
    assert (alarm["only_in_baseline"], alarm["only_in_candidate"]) == (["d2"], ["d3"])
    assert s.detection_alarm(s.detection_rates([], ["d1"]), rates([["d1"]])) == {
        "available": False, "reason": "detection_rates_unavailable"}


@pytest.mark.parametrize("value", [
    None, {"defects": []}, {"available": True}, {"available": True, "defects": [{"defect_id": "d1"}]},
    {"available": True, "defects": [{"defect_id": "d1", "rate": {"interval": None}}]},
    {"available": True, "defects": ["d1"]},
], ids=["none", "no-flag", "no-defects", "no-rate", "no-interval", "row-text"])
def test_alarm_refuses_anything_that_is_not_a_detection_result(value):
    with pytest.raises(ValueError, match="baseline"):
        s.detection_alarm(value, rates([["d1"]]))


# ------------------------------------------------------------------ experiments-domain adapter

def test_adapter_document_rebuilds_to_the_hand_computed_stability_and_agrees_with_series():
    snapshots = runs("ABCD", "ABCEF")
    frozen = deepcopy(snapshots)
    records = launches(snapshots)
    frozen_records = deepcopy(records)
    adapted = s.experiment_document(snapshots, experiment_id="corpus-series-1", launches=records)
    assert snapshots == frozen and records == frozen_records
    assert adapted["gaps"] == [] and adapted["stage_mapping"] == {"published": "verified"}
    rebuilt = rebuild(adapted["document"])
    first, second = rebuilt["runs"]
    transition = second["transition"]
    assert (transition["shared"], transition["union"]) == (3, 6)
    assert transition["jaccard"]["value"] == 0.5 and transition["retention"]["value"] == 0.75
    assert (transition["new_to_previous"], transition["dropped"]) == (2, 1)
    aggregate, = rebuilt["groups"]
    assert aggregate["mps"] == {"value": 0.5, "valid_count": 1, "total_count": 1}
    assert aggregate["unit"] == "root_cause" and aggregate["group"]["task"] == "discovery"
    own = s.series(snapshots)
    row, = own["adjacent"]
    assert [item["set_size"] for item in own["runs"]] == [first["set_size"], second["set_size"]] == [4, 5]
    for name in ("shared", "union", "new_to_previous", "dropped"):
        assert row[name] == transition[name]
    assert row["jaccard"]["value"] == transition["jaccard"]["value"]
    assert row["retention"]["value"] == transition["retention"]["value"]
    assert own["mean_pairwise"]["value"] == aggregate["mps"]["value"]
    assert own["mean_adjacent_jaccard"]["value"] == aggregate["ror"]["value"]


def test_adapter_and_series_agree_over_four_runs_and_empty_sets():
    snapshots = runs("ABCD", "ABCEF", "AE", "ADE", "", "")
    rebuilt = rebuild(s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots))["document"])
    own = s.series(snapshots)
    aggregate, = rebuilt["groups"]
    assert own["mean_pairwise"]["value"] == pytest.approx(aggregate["mps"]["value"], abs=1e-6)
    assert own["mean_pairwise"]["valid_count"] == aggregate["mps"]["valid_count"]
    assert own["mean_pairwise"]["both_empty_pairs"] == aggregate["empty_pair_count"] == 1
    assert own["mean_adjacent_jaccard"]["value"] == pytest.approx(aggregate["ror"]["value"], abs=1e-6)
    assert own["mean_adjacent_jaccard"]["valid_count"] == aggregate["ror"]["valid_count"] == 4
    for row, run in zip(own["adjacent"], rebuilt["runs"][1:], strict=True):
        expected = run["transition"]["jaccard"]["value"]
        assert row["jaccard"]["value"] == (None if expected is None else pytest.approx(expected, abs=1e-6))
        assert (row["status"] == "both_empty") == (run["transition"]["reason"] == "both_empty")
    frequencies = sorted(row["frequency"]["numerator"] for row in aggregate["recurrence"])
    assert sorted(row["runs"] for row in own["recurrence"]) == frequencies


def test_adapter_reports_carry_the_finding_identity_and_no_confidence():
    snapshot = snap("run-1", [finding("A", severity=None, source_symbol=None)])
    adapted = s.experiment_document([snapshot], experiment_id="e", launches=launches([snapshot]))
    completion, = adapted["document"]["completions"]
    report, = completion["reports"]
    assert report == {
        "raw_report_id": "F-A", "cwe": "CWE-121", "cause_key": snapshot["findings"][0]["fingerprint"]["relocated"],
        "source_symbol": None, "sink_symbol": "copy_A",
        "locations": [{"path": "src/A.c", "start_line": 10, "end_line": 12}], "severity": "null",
        "confidence": None, "evidence_ids": ["finding-snapshot:run-1:F-A"]}
    assert completion["usage"] == {
        "input_tokens": None, "output_tokens": None, "wall_seconds": None, "cost": None, "currency": None,
        "cost_kind": "unavailable", "evidence_ids": [], "missing_reason": "usage_not_supplied"}
    assert completion["decisions"] == [] and completion["coverage"] == [] and completion["error_ids"] == []
    launch_row, = adapted["document"]["launches"]
    assert launch_row["source_run_id"] == launch_row["run_id"] == "run-1"
    assert launch_row["group"] == {
        "source_revision": "a" * 40, "scope_sha256": "4" * 64, "context_condition": "source_only", **HASHES,
        "agent_sha256": "5" * 64, "tools_sha256": "6" * 64, "decoding_sha256": "7" * 64,
        "normalizer_version": "source-root-cause-exact/1", "stage": "verified", "task": "discovery",
        "positive_event": "genuine in-scope vulnerability", "warning_set_sha256": None}
    assert adapted["document"]["adjudications"]["labels"] == []
    assert rebuild(adapted["document"])["groups"][0]["input_tokens"]["missing_run_ids"] == ["run-1"]


def test_adapter_skips_and_counts_findings_without_a_cwe():
    snapshots = [snap("run-1", [finding("A"), finding("B", weakness_cwe=None), finding("C", weakness_cwe=None)]),
                 snap("run-2", [finding("A")])]
    adapted = s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots))
    assert adapted["gaps"] == [{"gap": "finding_without_cwe", "run_id": "run-1", "count": 2,
                                "finding_ids": ["F-B", "F-C"]}]
    rebuilt = rebuild(adapted["document"])
    assert [row["raw_report_count"] for row in rebuilt["runs"]] == [1, 1]
    assert rebuilt["runs"][1]["transition"]["jaccard"]["value"] == 1.0


def test_adapter_names_a_fingerprint_the_experiments_normalizer_would_split():
    moved = finding("A")
    moved["locations"][0].update(start_line=40, end_line=42)
    snapshots = [snap("run-1", "A"), snap("run-2", [moved])]
    assert s.series(snapshots)["adjacent"][0]["jaccard"]["value"] == 1.0
    adapted = s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots))
    assert adapted["gaps"] == [{"gap": "fingerprint_located_on_different_lines", "run_id": None, "count": 1,
                                "fingerprints": [key("A")]}]
    assert rebuild(adapted["document"])["runs"][1]["transition"]["jaccard"]["value"] == 0.0


@pytest.mark.parametrize("field", sorted(HASHES), ids=str)
def test_adapter_never_fabricates_a_missing_identity(field):
    snapshots = runs("A", **{field: None})
    with pytest.raises(ValueError, match=f"run-1 has no {field}"):
        s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots))
    adapted = s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots, **{field: "8" * 64}))
    assert adapted["document"]["launches"][0]["group"][field] == "8" * 64
    rebuild(adapted["document"])


def test_adapter_refuses_a_launch_identity_that_contradicts_or_malforms_the_snapshot():
    snapshots = runs("A")
    with pytest.raises(ValueError, match="contradicts the snapshot's model_sha256"):
        s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots, model_sha256="8" * 64))
    with pytest.raises(ValueError, match="model_sha256 must be a SHA-256"):
        s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots, model_sha256="abc"))
    same = s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots, model_sha256="3" * 64))
    assert same["document"]["launches"][0]["group"]["model_sha256"] == "3" * 64


@pytest.mark.parametrize("changes, message", [
    ({"agent_sha256": "xyz"}, "agent_sha256 must be a SHA-256"),
    ({"context_condition": "guessed"}, "outside its vocabulary"),
    ({"error_ids": "boom"}, "error_ids must be a list"),
    ({"raw_artifact_sha256": None}, "raw_artifact_sha256 must be a SHA-256"),
    ({"run_index": 0}, "run_index must be an integer"),
    ({"run_index": True}, "run_index must be an integer"),
    ({"started_at": 5}, "invalid quality document"),
    ({"status": "complete", "color": "red"}, "unknown \\['color'\\]"),
    ({"status": "done"}, "outside its vocabulary"),
    ({"status": "failed"}, "a failed run needs error_ids"),
    ({"usage": "none"}, "usage must be a usage object"),
], ids=["agent-hash", "context", "error-ids", "artifact-hash", "index-zero", "index-bool", "started-at",
        "unknown-key", "status", "failed-no-errors", "usage-type"])
def test_adapter_refuses_an_invalid_launch_record(changes, message):
    snapshots = runs("A")
    with pytest.raises(ValueError, match=message):
        s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots, **changes))


def test_adapter_refuses_inconsistent_inputs():
    snapshots = runs("A", "B")
    records = launches(snapshots)
    with pytest.raises(ValueError, match="without launch \\['run-2'\\]"):
        s.experiment_document(snapshots, experiment_id="e", launches={"run-1": records["run-1"]})
    with pytest.raises(ValueError, match="without snapshot \\['run-9'\\]"):
        s.experiment_document(snapshots, experiment_id="e", launches={**records, "run-9": launch(9)})
    incomplete = {key_: value for key_, value in records["run-1"].items() if key_ != "scope_sha256"}
    with pytest.raises(ValueError, match="missing \\['scope_sha256'\\]"):
        s.experiment_document(snapshots, experiment_id="e", launches={**records, "run-1": incomplete})
    with pytest.raises(ValueError, match="run_index must be unique"):
        s.experiment_document(snapshots, experiment_id="e", launches={**records, "run-2": launch(1)})
    with pytest.raises(ValueError, match="registers published snapshots"):
        s.experiment_document(runs("A", stage="verified"), experiment_id="e", launches={"run-1": launch(1)})
    with pytest.raises(ValueError, match="one target at one source revision"):
        s.experiment_document([snapshots[0], snap("run-2", "B", source_revision="b" * 40)], experiment_id="e",
                              launches=records)
    with pytest.raises(ValueError, match="repeats a run_id"):
        s.experiment_document([snapshots[0], snapshots[0]], experiment_id="e", launches=records)
    with pytest.raises(ValueError, match="experiment_id"):
        s.experiment_document(snapshots, experiment_id="", launches=records)
    with pytest.raises(ValueError, match="launches must map"):
        s.experiment_document(snapshots, experiment_id="e", launches=[records])


def test_adapter_registers_a_failed_run_and_supplied_usage():
    snapshots = runs("A", "A", "A")
    usage = {"input_tokens": 10, "output_tokens": 5, "wall_seconds": 3, "cost": "2.00", "currency": "USD",
             "cost_kind": "observed", "evidence_ids": ["usage-receipt-1"], "missing_reason": None}
    records = launches(snapshots, usage=usage)
    records["run-2"].update(status="failed", error_ids=["producer-gap:verifier"])
    rebuilt = rebuild(s.experiment_document(snapshots, experiment_id="e", launches=records)["document"])
    assert [row["status"] for row in rebuilt["runs"]] == ["complete", "failed", "complete"]
    assert rebuilt["runs"][2]["transition"]["reason"] == "predecessor_failed"
    aggregate, = rebuilt["groups"]
    assert aggregate["input_tokens"] == {"observed_sum": 30, "total": 30, "missing_run_ids": []}
    assert aggregate["cost"]["total"] == "6.00"


def test_incomparable_snapshots_become_separate_experiment_groups():
    snapshots = [snap("run-1", "A"), snap("run-2", "A", guidance_sha256="9" * 64)]
    rebuilt = rebuild(s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots))["document"])
    assert len(rebuilt["groups"]) == 2
    assert rebuilt["runs"][1]["transition"]["reason"] == "incomparable_predecessor"
    assert s.series(snapshots)["adjacent"][0]["status"] == "incomparable"


def test_a_stable_false_finding_is_stable_and_labels_stay_independent():
    snapshots = runs("AB", "AB", "A")
    unlabelled = s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots))["document"]
    group = unlabelled["launches"][0]["group"]
    report = unlabelled["completions"][0]["reports"][0]
    assert report["raw_report_id"] == "F-A"
    labels = {"schema": "appsec-review/quality-adjudications/1", "revision": "labels-1",
              "matching_snapshot_id": c.digest(unlabelled["matching"]),
              "labels": [{"population_id": population_id(group), "subject_id": root_cause_id(group, report),
                          "outcome": "fp", "is_real_bug": False, "is_rank1_critical": None,
                          "adjudicator_id": "independent-reviewer", "method": "independent_human",
                          "evidence_ids": ["adjudication-1"], "adjudicated_at": "2026-11-06T02:00:00Z"}]}
    frozen = deepcopy(labels)
    adapted = s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots), labels=labels)
    assert labels == frozen and adapted["document"]["adjudications"] == labels
    aggregate, = rebuild(adapted["document"])["groups"]
    stable_false = next(row for row in aggregate["recurrence"] if row["outcome"] == "fp")
    assert stable_false["frequency"]["value"] == 1                 # found by every run, and still false
    assert aggregate["distinct"]["precision"]["value"] == 0
    own = {row["fingerprint"]: row["frequency"]["value"] for row in s.series(snapshots)["recurrence"]}
    assert own == {key("A"): 1.0, key("B"): pytest.approx(2 / 3, abs=1e-6)}
    stale = {**labels, "matching_snapshot_id": "0" * 64}
    with pytest.raises(ValueError, match="different matching snapshot"):
        s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots), labels=stale)
    with pytest.raises(ValueError, match="adjudications document"):
        s.experiment_document(snapshots, experiment_id="e", launches=launches(snapshots), labels=[labels])


def test_adapter_bound_is_the_experiments_launch_bound():
    snapshots = [snap(f"run-{index}", "") for index in range(1, s.MAX_SERIES_RUNS + 2)]
    records = {row["run_id"]: launch(index, started_at="2026-11-06T00:00:00Z", completed_at="2026-11-06T01:00:00Z")
               for index, row in enumerate(snapshots, 1)}
    with pytest.raises(ValueError, match="at most 512"):
        s.experiment_document(snapshots, experiment_id="e", launches=records)
    records.pop("run-513")
    document = s.experiment_document(snapshots[:-1], experiment_id="e", launches=records)["document"]
    assert len(document["launches"]) == len(document["completions"]) == 512
