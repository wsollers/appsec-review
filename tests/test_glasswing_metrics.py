from copy import deepcopy
import csv
from io import StringIO
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from appsec_review.observability.experiments import (
    csv_exports, input_schema, output_schema, publish_snapshot, rebuild, root_cause_id,
)
from appsec_review.observability.experiments.contracts import digest
from tests.fixtures.glasswing import add_label, experiment, group, report, triage_experiment, usage


def test_exact_overlap_retention_mps_distinct_occurrences_and_stable_false_positive():
    document = experiment(
        [list("ABCD"), list("ABCEF"), list("AE"), list("ADE")],
        outcomes={name: "fp" if name == "A" else "tp" for name in "ABCDEF"})
    snapshot = rebuild(document)
    first, second, third, fourth = snapshot["runs"]
    transition = second["transition"]
    assert transition["shared"] == 3
    assert transition["union"] == 6
    assert transition["jaccard"]["value"] == 0.5
    assert transition["retention"]["value"] == 0.75
    assert transition["new_to_previous"] == second["first_seen"] == 2
    assert transition["dropped"] == 1
    assert third["first_seen"] == fourth["first_seen"] == 0
    assert fourth["transition"]["reappearing"] == 1
    assert first["transition"]["reason"] == "first_run"
    assert first["ror_5"] == {"value": None, "valid_count": 0, "total_count": 0}
    aggregate, = snapshot["groups"]
    assert aggregate["mps"] == {"value": pytest.approx(5 / 12), "valid_count": 6, "total_count": 6}
    assert aggregate["ror"]["value"] == fourth["ror_5"]["value"] == pytest.approx(47 / 90)
    assert aggregate["distinct"]["precision"]["value"] == 5 / 6
    assert aggregate["occurrences"]["precision"]["value"] == 5 / 7
    assert aggregate["macro_run_precision"]["value"] == pytest.approx((3 / 4 + 4 / 5 + 1 / 2 + 2 / 3) / 4)
    assert aggregate["unique_tp_yield"] == 5
    assert aggregate["unique_tp_per_completed_run"]["value"] == 1.25
    assert aggregate["input_tokens"] == {"observed_sum": 40, "total": 40, "missing_run_ids": []}
    assert aggregate["cost"]["total"] == "8.00"
    assert aggregate["cost"]["per_unique_tp"] == "1.60"
    repeated_fp = next(row for row in aggregate["recurrence"] if row["outcome"] == "fp")
    assert repeated_fp["frequency"]["value"] == 1
    assert repeated_fp["run_ids"] == ["run-1", "run-2", "run-3", "run-4"]
    assert snapshot["inference"]["status"] == "not_certified"
    assert snapshot["inference"]["lower_confidence_bound"] is None


@pytest.mark.parametrize("failed_status", ["failed", "partial", "cancelled", "pending"])
def test_failed_or_partial_predecessor_is_not_skipped_and_empty_runs_are_observations(failed_status):
    document = experiment([["A"], failed_status, ["A"], [], []], outcomes={"A": "fp"})
    if failed_status != "pending":
        document["completions"][1]["reports"] = [report("diagnostic-only")]
    snapshot = rebuild(document)
    rows = snapshot["runs"]
    assert rows[1]["set_size"] is None
    assert rows[1]["quality"] is None
    assert rows[2]["transition"]["reason"] == "predecessor_" + failed_status
    assert rows[2]["transition"]["previous_run_id"] == "run-2"
    assert rows[2]["transition"]["jaccard"]["value"] is None
    assert rows[3]["transition"]["jaccard"]["value"] == 0
    assert rows[3]["transition"]["retention"]["value"] == 0
    assert rows[4]["transition"]["reason"] == "both_empty"
    assert rows[4]["transition"]["shared"] == rows[4]["transition"]["union"] == 0
    assert rows[4]["transition"]["jaccard"]["value"] is None
    assert rows[4]["ror_5"] == {"value": 0, "valid_count": 1, "total_count": 4}
    aggregate, = snapshot["groups"]
    assert aggregate["counts"]["complete"] == 4
    assert aggregate["counts"]["completed_empty"] == 2
    assert aggregate["counts"][failed_status] == 1
    assert aggregate["mps"] == {"value": 0.2, "valid_count": 5, "total_count": 6}
    assert aggregate["empty_pair_count"] == 1
    assert aggregate["recurrence"][0]["frequency"]["denominator"] == 4
    assert aggregate["recurrence"][0]["frequency"]["value"] == 0.5
    assert aggregate["distinct"]["fp"] == 1
    assert aggregate["distinct"]["unresolved"] == 0


def test_empty_nonempty_is_zero_but_reverse_retention_has_no_denominator():
    snapshot = rebuild(experiment([[], ["A"], []]))
    assert snapshot["runs"][1]["transition"]["jaccard"]["value"] == 0
    assert snapshot["runs"][1]["transition"]["retention"]["value"] is None
    assert snapshot["runs"][1]["transition"]["retention"]["denominator"] == 0
    assert snapshot["runs"][2]["transition"]["retention"]["value"] == 0


@pytest.mark.parametrize("sets", [[], [[]], [[], [], []], ["failed"], ["pending"]])
def test_first_all_empty_and_no_complete_runs_never_invent_precision(sets):
    snapshot = rebuild(experiment(sets))
    for row in snapshot["runs"]:
        assert row["transition"]["jaccard"]["value"] is None
    for aggregate in snapshot["groups"]:
        assert aggregate["mps"]["value"] is None
        if aggregate["counts"]["complete"]:
            assert aggregate["distinct"]["precision"]["value"] is None
        else:
            assert aggregate["distinct"] is aggregate["occurrences"] is aggregate["unique_tp_yield"] is None
        assert aggregate["cost"]["per_unique_tp"] is None
        assert aggregate["open_world_recall"]["denominator"] is None
    assert snapshot["inference"]["status"] == "not_certified"


def test_missing_launch_is_distinct_from_empty_or_failed_and_rolling_window_is_scheduled():
    document = experiment([["A"]] * 8)
    document["launches"].pop(5)
    document["completions"].pop(5)
    snapshot = rebuild(document)
    seventh = next(row for row in snapshot["runs"] if row["run_index"] == 7)
    assert seventh["transition"]["reason"] == "missing_predecessor"
    assert seventh["transition"]["previous_run_id"] is None
    assert snapshot["runs"][-1]["ror_5"] == {"value": 1, "valid_count": 3, "total_count": 5}


def test_out_of_order_completion_rebuilds_both_neighbors_without_mutating_old_snapshot():
    final_input = experiment([["A"], ["B"], ["B", "C"]])
    pending_input = deepcopy(final_input)
    pending_input["completions"].pop(1)
    old = rebuild(pending_input)
    frozen_old = deepcopy(old)
    assert old["runs"][1]["transition"]["reason"] == "current_pending"
    assert old["runs"][2]["transition"]["reason"] == "predecessor_pending"
    pending_input["completions"].append(final_input["completions"][1])
    new = rebuild(pending_input)
    assert old == frozen_old
    assert new == rebuild(final_input)
    assert new["runs"][1]["transition"]["jaccard"]["value"] == 0
    assert new["runs"][2]["transition"]["jaccard"]["value"] == 0.5
    assert new["runs"][2]["first_seen"] == 1
    assert new["runs"][2]["ror_5"] == {"value": 0.25, "valid_count": 2, "total_count": 2}
    assert old["source_sha256"] != new["source_sha256"]


@pytest.mark.parametrize("change", [
    {"configuration_sha256": "a" * 64}, {"source_revision": "other-source"}, {"scope_sha256": "b" * 64},
    {"context_condition": "build_context"}, {"guidance_sha256": "c" * 64}, {"model_sha256": "d" * 64},
    {"agent_sha256": "e" * 64}, {"tools_sha256": "f" * 64}, {"decoding_sha256": "0" * 64},
    {"stage": "candidate"}, {"stage": "reproduced"}, {"positive_event": "rank-1 only"},
])
def test_frozen_groups_and_stages_never_mix_or_skip_incomparable_predecessors(change):
    snapshot = rebuild(experiment([["A"], ["A"], ["A"]], groups=[group(), group(**change), group()]))
    assert len(snapshot["groups"]) == 2
    assert snapshot["runs"][1]["transition"]["reason"] == "incomparable_predecessor"
    assert snapshot["runs"][2]["transition"]["reason"] == "incomparable_predecessor"
    original = next(row for row in snapshot["groups"] if len(row["completed_run_ids"]) == 2)
    assert original["mps"]["value"] == 1
    assert original["ror"]["value"] is None
    assert original["recurrence"][0]["frequency"]["denominator"] == 2


def test_label_revision_rebuilds_whole_history_but_not_detector_overlap():
    document = experiment([["A"], ["A", "B"]], outcomes={"A": "fp"})
    old = rebuild(document)
    document["adjudications"]["revision"] = "labels-2"
    document["adjudications"]["labels"][0].update(outcome="tp", is_real_bug=True)
    new = rebuild(document)
    assert old["label_snapshot_id"] != new["label_snapshot_id"]
    assert old["matching_snapshot_id"] == new["matching_snapshot_id"]
    for before, after in zip(old["runs"], new["runs"], strict=True):
        assert before["comparison_group_id"] == after["comparison_group_id"]
        assert before["transition"] == after["transition"]
        assert before["quality"]["fp"] == after["quality"]["tp"] == 1
    assert new["groups"][0]["recurrence"] != old["groups"][0]["recurrence"]
    quality = new["groups"][0]["distinct"]
    assert quality["unresolved"] == 1
    assert quality["precision"]["value"] == 1
    assert quality["pending_lower"]["value"] == 0.5
    assert quality["pending_upper"]["value"] == 1
    assert new["inference"]["pending_bounds"] == "not_confidence_intervals"


def test_matching_revision_merges_roots_only_via_explicit_rebuild_and_new_label_snapshot():
    document = experiment([["A"], ["B"]], outcomes={"A": "tp", "B": "fp"})
    old = rebuild(document)
    root_a = root_cause_id(group(), report("A"))
    document["matching"]["revision"] = "matching-2"
    document["matching"]["overrides"] = [
        {"run_id": "run-2", "raw_report_id": "B", "root_cause_id": root_a, "evidence_ids": ["merge-decision:1"]}]
    with pytest.raises(ValueError, match="different matching snapshot"):
        rebuild(document)
    document["adjudications"]["matching_snapshot_id"] = digest(document["matching"])
    document["adjudications"]["revision"] = "labels-after-merge"
    document["adjudications"]["labels"] = []
    add_label(document, group(), root_a, "tp")
    new = rebuild(document)
    assert old["runs"][1]["transition"]["jaccard"]["value"] == 0
    assert new["runs"][1]["transition"]["jaccard"]["value"] == 1
    assert old["runs"][0]["comparison_group_id"] != new["runs"][0]["comparison_group_id"]
    assert old["runs"][0]["frozen_group_id"] == new["runs"][0]["frozen_group_id"]
    assert new["groups"][0]["distinct"]["tp"] == 1
    assert new["groups"][0]["occurrences"]["tp"] == 2
    assert new["membership"][1]["raw_report_id"] == "B"
    assert new["membership"][1]["subject_id"] == root_a
    assert old["source"]["matching"]["revision"] == "matching-1"


def test_duplicate_reports_and_root_causes_do_not_inflate_yield_or_independent_evidence():
    document = experiment([["A", "A"]], outcomes={"A": "tp"})
    duplicate_root = report("A")
    duplicate_root.update(raw_report_id="new-wording", severity="low",
                          confidence={"kind": "vote_fraction", "raw": 1.0, "target": "is_vulnerable",
                                      "calibrated": False, "calibration_version": None})
    document["completions"][0]["reports"].append(duplicate_root)
    snapshot = rebuild(document)
    run, = snapshot["runs"]
    assert run["raw_report_count"] == 3
    assert run["duplicate_report_count"] == 1
    assert run["set_size"] == run["quality"]["tp"] == 1
    assert len(snapshot["membership"]) == 2
    assert len({row["subject_id"] for row in snapshot["membership"]}) == 1
    assert snapshot["membership"][1]["confidence"]["kind"] == "vote_fraction"
    document["completions"][0]["reports"][1]["cause_key"] = "distinct-root"
    with pytest.raises(ValueError, match="conflicting immutable raw report"):
        rebuild(document)


def test_root_matching_uses_exact_source_cause_symbols_and_locations_not_severity_or_order():
    identity, original = group(), report("A")
    changed = deepcopy(original)
    changed["raw_report_id"], changed["severity"] = "other", "low"
    changed["locations"] *= 2
    assert root_cause_id(identity, original) == root_cause_id(identity, changed)
    for field, value in [("cause_key", "B"), ("source_symbol", "different"), ("sink_symbol", "different"),
                         ("cwe", "CWE-79"), ("locations", [{"path": "other.c", "start_line": 1, "end_line": 2}])]:
        changed = {**original, field: value}
        assert root_cause_id(identity, original) != root_cause_id(identity, changed)
    assert root_cause_id(group(source_revision="new"), original) != root_cause_id(identity, original)


def test_fixed_warning_triage_preserves_abstentions_true_bug_retention_and_false_warning_removal():
    snapshot = rebuild(triage_experiment())
    row, = snapshot["runs"]
    score = row["triage"]
    assert score["warning_count"] == 7
    assert (score["retained"], score["rejected"], score["abstained"]) == (3, 2, 2)
    assert (score["tp"], score["fp"], score["tn"], score["fn"]) == (1, 1, 1, 1)
    assert score["known_positive"] == score["known_negative"] == 3
    assert score["abstained_tp"] == score["abstained_fp"] == 1
    assert score["tp_retention"]["value"] == score["fp_removal"]["value"] == 1 / 3
    assert score["false_positive_rate"]["value"] == score["rejection_precision"]["value"] == 0.5
    assert score["decision_coverage"]["value"] == 5 / 7
    assert score["abstention_rate"]["value"] == score["suppression_rate"]["value"] == 2 / 7
    assert row["quality"]["precision"]["value"] == 0.5
    assert row["quality"]["pending_lower"]["value"] == 1 / 3
    assert row["quality"]["pending_upper"]["value"] == 2 / 3
    assert score["unresolved_inputs"] == 1
    assert snapshot["groups"][0]["unit"] == "warning"
    assert snapshot["groups"][0]["triage"] == score
    assert len([entry for entry in snapshot["membership"] if entry["included"]]) == 3


def test_triage_and_discovery_have_no_shared_denominators_even_when_ids_overlap():
    document = triage_experiment()
    second = experiment([[], ["t1"]])
    document["launches"].append(second["launches"][1])
    document["completions"].append(second["completions"][1])
    snapshot = rebuild(document)
    assert len(snapshot["groups"]) == 2
    assert snapshot["runs"][1]["transition"]["reason"] == "incomparable_predecessor"
    discovery = next(row for row in snapshot["groups"] if row["unit"] == "root_cause")
    assert discovery["distinct"]["tp"] == 0
    assert discovery["distinct"]["unresolved"] == 1


def test_missing_usage_estimates_and_mixed_currencies_never_become_observed_zero():
    document = experiment([["A"], [], "failed"], outcomes={"A": "tp"})
    document["completions"][1]["usage"] = usage(input_tokens=None, cost=None, currency=None,
                                              cost_kind="unavailable", missing_reason="provider_did_not_report")
    snapshot = rebuild(document)
    aggregate = snapshot["groups"][0]
    assert aggregate["input_tokens"] == {"observed_sum": 20, "total": None, "missing_run_ids": ["run-2"]}
    assert aggregate["output_tokens"]["total"] == 15
    assert aggregate["cost"]["observed_sum"] == "4.00"
    assert aggregate["cost"]["total"] is aggregate["cost"]["per_unique_tp"] is None
    document["completions"][1]["usage"] = usage(cost_kind="estimated")
    assert rebuild(document)["groups"][0]["cost"]["missing_run_ids"] == ["run-2"]
    document["completions"][1]["usage"] = usage(currency="EUR")
    cost = rebuild(document)["groups"][0]["cost"]
    assert cost["incompatible_currency"] is True
    assert cost["observed_sum"] is cost["total"] is cost["per_unique_tp"] is None
    for completion in document["completions"]:
        completion["usage"] = usage(cost="0", input_tokens=0)
    aggregate = rebuild(document)["groups"][0]
    assert aggregate["cost"]["total"] == aggregate["cost"]["per_unique_tp"] == "0"
    assert aggregate["input_tokens"]["total"] == 0


def test_unresolved_and_out_of_scope_do_not_enter_adjudicated_precision_denominator():
    snapshot = rebuild(experiment([list("ABC")], outcomes={"A": "tp", "B": "out_of_scope"}))
    quality = snapshot["groups"][0]["distinct"]
    assert quality["tp"] == quality["unresolved"] == quality["out_of_scope"] == 1
    assert quality["precision"]["value"] == 1
    assert quality["adjudication_coverage"]["value"] == quality["pending_lower"]["value"] == 0.5


def test_predeclared_inference_policy_is_preserved_but_never_auto_certifies():
    document = experiment([["A"]] * 30, outcomes={"A": "tp"})
    document["inference_policy"] = {
        "policy_id": "synthetic-design", "predeclared_at": "2026-11-05T00:00:00Z", "design": "fixed_sample",
        "sampling_unit": "component/root-cause", "dependence_method": "whole-run bootstrap",
        "planned_runs": 30, "evidence_ids": ["fixture-preregistration"],
    }
    snapshot = rebuild(document)
    assert snapshot["groups"][0]["distinct"]["tp"] == 1
    assert snapshot["groups"][0]["occurrences"]["tp"] == 30
    assert snapshot["inference"]["reason"] == "inference_not_implemented"
    assert snapshot["inference"]["lower_confidence_bound"] is None


def test_closed_versioned_schemas_and_numeric_boundary_reject_invalid_inputs():
    Draft202012Validator.check_schema(input_schema())
    Draft202012Validator.check_schema(output_schema())
    bad = experiment([["A"]])
    for mutate in (
        lambda d: d.update(unregistered=True),
        lambda d: d.update(schema="appsec-review/quality-experiment/2"),
        lambda d: d["launches"][0].update(run_index=True),
        lambda d: d["launches"][0]["group"].update(normalizer_version="unimplemented/2"),
        lambda d: d["completions"][0]["usage"].update(input_tokens=-1),
        lambda d: d["completions"][0]["usage"].update(wall_seconds=float("nan")),
        lambda d: d["completions"][0]["usage"].update(wall_seconds=float("inf")),
        lambda d: d["completions"][0]["reports"][0].update(confidence={"raw": 1}),
    ):
        document = deepcopy(bad)
        mutate(document)
        with pytest.raises(ValueError):
            rebuild(document)


@pytest.mark.parametrize("mutation, message", [
    (lambda d: d["launches"][1].update(run_index=1), "run_index"),
    (lambda d: d["launches"][1].update(started_at="2026-11-05T00:00:00Z"), "launch-time"),
    (lambda d: d["launches"][1].update(source_run_id="source-1"), "source_run_id"),
    (lambda d: d["completions"][0].update(completed_at="2026-11-01T00:00:00Z"), "precedes"),
    (lambda d: d["completions"][0].update(run_id="foreign"), "immutable launch"),
    (lambda d: d["completions"][0].update(status="failed"), "error/gap"),
    (lambda d: d["completions"][0]["usage"].update(cost=None), "provenance"),
    (lambda d: d["completions"][0]["usage"].update(input_tokens=None), "explicit reason"),
    (lambda d: d["completions"][0]["usage"].update(evidence_ids=[]), "source evidence"),
    (lambda d: d["completions"][0]["reports"][0]["locations"][0].update(path="../foreign.c"), "source-relative"),
    (lambda d: d["completions"][0]["reports"][0]["locations"][0].update(end_line=0), "invalid quality"),
    (lambda d: d["completions"][0]["reports"][0]["locations"][0].update(start_line=3), "source-relative"),
])
def test_invalid_semantic_records_fail_explicitly(mutation, message):
    document = experiment([["A"], ["B"]])
    mutation(document)
    with pytest.raises(ValueError, match=message):
        rebuild(document)


@pytest.mark.parametrize("kind, raw", [("verbal_score", "likely"), ("token_margin", -4.5),
                                      ("vote_fraction", 0.7), ("token_probability", 0.3), ("probability", 0.8)])
def test_confidence_types_targets_and_calibration_provenance_are_not_reinterpreted(kind, raw):
    document = experiment([["A"]])
    confidence = {"kind": kind, "raw": raw, "target": "declared-outcome",
                  "calibrated": False, "calibration_version": None}
    document["completions"][0]["reports"][0]["confidence"] = confidence
    assert rebuild(document)["membership"][0]["confidence"] == confidence
    confidence["calibrated"] = True
    with pytest.raises(ValueError, match="calibrated correctness"):
        rebuild(document)


def test_triage_complete_missing_foreign_duplicate_and_zero_warning_denominators():
    document = triage_experiment()
    document["completions"][0]["decisions"].pop()
    with pytest.raises(ValueError, match="every fixed warning"):
        rebuild(document)
    document["completions"][0]["decisions"].append({"warning_id": "foreign", "decision": "reject"})
    with pytest.raises(ValueError, match="foreign warning"):
        rebuild(document)
    document = triage_experiment()
    document["completions"][0]["decisions"].append({"warning_id": "t1", "decision": "reject"})
    with pytest.raises(ValueError, match="conflicting immutable triage decision"):
        rebuild(document)
    warning_set = {"warning_ids": []}
    document = experiment([[]], groups=[group(task="triage", warning_set_sha256=digest(warning_set))])
    document["warning_sets"] = [{"warning_set_sha256": digest(warning_set), **warning_set}]
    score = rebuild(document)["runs"][0]["triage"]
    assert score["tp_retention"]["denominator"] == score["fp_removal"]["denominator"] == 0
    assert score["tp_retention"]["value"] is score["fp_removal"]["value"] is None


def test_immutable_idempotent_records_and_conflicting_versions():
    document = experiment([["A"]])
    expected = rebuild(document)
    document["launches"] *= 2
    document["completions"] *= 2
    assert rebuild(document) == expected
    document["completions"][1] = {**document["completions"][1], "raw_artifact_sha256": "0" * 64}
    with pytest.raises(ValueError, match="conflicting immutable completion"):
        rebuild(document)


def test_input_order_does_not_affect_snapshot_or_csv_and_inputs_are_not_mutated():
    document = experiment([list("BAC"), list("CD")], outcomes={"A": "tp", "B": "fp"})
    original = deepcopy(document)
    expected = rebuild(document)
    assert document == original
    document["launches"].reverse()
    document["completions"].reverse()
    document["adjudications"]["labels"].reverse()
    for completion in document["completions"]:
        completion["reports"].reverse()
    assert rebuild(document) == expected
    assert csv_exports(rebuild(document)) == csv_exports(expected)


def test_matching_overrides_require_evidence_and_cannot_merge_across_source_revisions():
    document = experiment([["A"], ["B"]], groups=[group(), group(source_revision="foreign")])
    document["matching"]["overrides"] = [{
        "run_id": "run-2", "raw_report_id": "B", "root_cause_id": root_cause_id(group(), report("A")),
        "evidence_ids": ["explicit-merge"],
    }]
    document["adjudications"]["matching_snapshot_id"] = digest(document["matching"])
    with pytest.raises(ValueError, match="across source revisions"):
        rebuild(document)
    document["matching"]["overrides"][0]["raw_report_id"] = "absent"
    document["adjudications"]["matching_snapshot_id"] = digest(document["matching"])
    with pytest.raises(ValueError, match="absent raw report"):
        rebuild(document)


def test_coverage_denominators_preserve_missing_and_zero_without_inventing_analysis_coverage():
    document = experiment([[]])
    document["completions"][0]["coverage"] = [
        {"unit": "functions", "analyzed": 0, "eligible": None, "evidence_ids": ["coverage-source"],
         "missing_reason": "eligible_inventory_missing"},
        {"unit": "translation_units", "analyzed": 0, "eligible": 0, "evidence_ids": ["empty-inventory"],
         "missing_reason": None},
    ]
    snapshot = rebuild(document)
    assert snapshot["source"]["completions"][0]["coverage"] == document["completions"][0]["coverage"]
    document["completions"][0]["coverage"][0]["missing_reason"] = None
    with pytest.raises(ValueError, match="missing coverage denominator"):
        rebuild(document)
    document["completions"][0]["coverage"][0].update(analyzed=1, eligible=0)
    with pytest.raises(ValueError, match="exceeds eligible"):
        rebuild(document)


def test_all_missing_usage_remains_unavailable_even_for_completed_empty_run():
    document = experiment([[]])
    document["completions"][0]["usage"] = usage(
        input_tokens=None, output_tokens=None, wall_seconds=None, cost=None, currency=None,
        cost_kind="unavailable", evidence_ids=[], missing_reason="usage_receipt_missing")
    aggregate = rebuild(document)["groups"][0]
    for field in ("input_tokens", "output_tokens", "wall_seconds"):
        assert aggregate[field] == {"observed_sum": None, "total": None, "missing_run_ids": ["run-1"]}
    assert aggregate["cost"]["observed_sum"] is aggregate["cost"]["total"] is None
    assert aggregate["unique_tp_yield"] == 0


def test_repeated_triage_warning_occurrences_are_not_distinct_yield():
    document = triage_experiment()
    second_launch = deepcopy(document["launches"][0])
    second_launch.update(run_id="run-2", source_run_id="source-2", run_index=2, started_at="2026-11-06T00:02:00Z")
    second_completion = {**deepcopy(document["completions"][0]), "run_id": "run-2"}
    document["launches"].append(second_launch)
    document["completions"].append(second_completion)
    aggregate = rebuild(document)["groups"][0]
    assert aggregate["triage"]["known_positive"] == aggregate["triage"]["known_negative"] == 6
    assert aggregate["triage"]["tp_retention"]["value"] == aggregate["triage"]["fp_removal"]["value"] == 1 / 3
    assert aggregate["distinct"]["tp"] == 1
    assert aggregate["occurrences"]["tp"] == 2


def test_exports_replay_exact_membership_nulls_and_revision_provenance(tmp_path):
    snapshot = rebuild(experiment([["A"], "failed", []], outcomes={"A": "fp"}))
    first = publish_snapshot(tmp_path, snapshot)
    path = Path(first["path"])
    assert first["status"] == "published"
    assert json.loads(path.read_text()) == snapshot
    assert publish_snapshot(tmp_path, snapshot)["status"] == "duplicate"
    assert rebuild(snapshot["source"]) == snapshot
    exports = csv_exports(snapshot)
    assert set(exports) == {"runs.csv", "groups.csv", "membership.csv", "launches.csv",
                            "completions.csv", "adjudications.csv"}
    for name, source_key in [("runs.csv", "runs"), ("groups.csv", "groups"), ("membership.csv", "membership")]:
        rows = [{key: json.loads(value) for key, value in row.items()}
                for row in csv.DictReader(StringIO(exports[name]))]
        for row, source in zip(rows, snapshot[source_key], strict=True):
            assert {key: row[key] for key in source} == source
            assert row["snapshot_id"] == first["snapshot_id"]
            assert row["matching_revision"] == snapshot["matching_revision"]
            assert row["label_snapshot_id"] == snapshot["label_snapshot_id"]
    changed = deepcopy(snapshot)
    changed["groups"][0]["unique_tp_yield"] = 999
    with pytest.raises(ValueError, match="rebuild"):
        csv_exports(changed)
    with pytest.raises(ValueError, match="rebuild"):
        publish_snapshot(tmp_path, changed)
    path.write_bytes(b"truncated")
    with pytest.raises(ValueError, match="incomplete publication"):
        publish_snapshot(tmp_path, snapshot)


def test_csv_text_cells_preserve_ids_without_spreadsheet_formula_execution():
    document = experiment([["=1+1"]])
    snapshot = rebuild(document)
    row = next(csv.DictReader(StringIO(csv_exports(snapshot)["membership.csv"])))
    assert row["raw_report_id"] == '"=1+1"'
    assert json.loads(row["raw_report_id"]) == "=1+1"


def test_publication_pins_launch_indices_and_results_but_allows_late_completion_and_new_labels(tmp_path):
    final = experiment([["A"], ["B"]], outcomes={"A": "fp"})
    pending = deepcopy(final)
    pending["completions"].pop(1)
    old = publish_snapshot(tmp_path, rebuild(pending))
    new = publish_snapshot(tmp_path, rebuild(final))
    assert old["snapshot_id"] != new["snapshot_id"]
    corrected = deepcopy(final)
    corrected["adjudications"]["revision"] = "labels-2"
    corrected["adjudications"]["labels"][0].update(outcome="tp", is_real_bug=True)
    assert publish_snapshot(tmp_path, rebuild(corrected))["status"] == "published"
    assert len(list((tmp_path / "launches").glob("*.json"))) == 2
    assert len(list((tmp_path / "completions").glob("*.json"))) == 2
    for mutate in (
        lambda d: d["launches"][0]["group"].update(model_sha256="f" * 64),
        lambda d: d["completions"][0].update(raw_artifact_sha256="a" * 64),
    ):
        changed = deepcopy(final)
        mutate(changed)
        with pytest.raises(ValueError, match="immutable quality record conflict"):
            publish_snapshot(tmp_path, rebuild(changed))
    renamed = deepcopy(final)
    renamed["launches"][0]["run_id"] = renamed["completions"][0]["run_id"] = "other-launch"
    with pytest.raises(ValueError, match="immutable quality record conflict"):
        publish_snapshot(tmp_path, rebuild(renamed))


def test_schema_documents_are_fresh_copies_and_all_objects_are_closed():
    def check(value):
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value["additionalProperties"] is False
                assert set(value["required"]) == set(value["properties"])
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(input_schema())
    check(output_schema())
    modified = input_schema()
    modified["properties"]["experiment_id"]["maxLength"] = 1
    assert input_schema()["properties"]["experiment_id"]["maxLength"] == 2048
