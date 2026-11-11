"""The assembled finding scorecard (finding-metrics.md sections 5 and 9), across the real metric modules."""
from __future__ import annotations

import json

import pytest

from appsec_review.acceptance.scoring_model import EntryKind, KeyEntry, ScoringKey
from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import lifecycle, scorecard, stability
from appsec_review.observability.findings.identity import fingerprint


def finding(finding_id, *, path="src/net/parse.c", line=10, cwe="CWE-121", state="confirmed", severity="high",
            lane="lead", code=None, **changes):
    value = {"finding_id": finding_id, "state": state, "weakness_cwe": cwe, "severity": severity, "lane": lane,
             "bucket": "findings", "ship_block_status": "ship_blocking" if severity in ("high", "critical")
             else "not_ship_blocking" if severity else "decision_pending",
             "scanner_backed": lane == "lead",
             "locations": [{"path": path, "start_line": line, "end_line": line + 2, "function": f"fn_{finding_id}",
                            "code": code or f"body_of_{finding_id}();"}],
             "citations": {"total": 2, "unresolved": 0}}
    value.update(changes)
    return value


def snapshot(findings, *, run_id="run-2", units=None, **changes):
    arguments = dict(run_id=run_id, target_id="game", source_revision="a" * 40, findings=findings,
                     fingerprint=fingerprint, reviewed_units=units, configuration_sha256="1" * 64,
                     guidance_sha256="2" * 64, model_sha256="3" * 64)
    arguments.update(changes)
    return c.build_snapshot(**arguments)


def key():
    return ScoringKey({"name": "mini"}, (
        KeyEntry("d1", EntryKind.DEFECT, "src/net/parse.c", "CWE-787", (11,), (5, 20), severity="critical"),
        KeyEntry("d2", EntryKind.DEFECT, "src/save/load.c", "CWE-190", (40,), (30, 60)),
        KeyEntry("c1", EntryKind.CONTROL, "src/net/safe.c", "CWE-787", (11,), (5, 20))))


FINDINGS = [finding("F1"),                                                    # hits d1 (memory-safety family)
            finding("F2", path="src/net/safe.c", cwe="CWE-787", severity="critical"),   # on the control: false
            finding("F3", path="src/ui/menu.c", cwe="CWE-476", state="supported", severity="medium", lane="hunt",
                    scanner_backed=False),
            finding("F4", path="src/ui/hud.c", cwe="CWE-134", severity=None, state="supported")]


def test_a_snapshot_alone_yields_a_complete_document_with_named_blind_spots():
    document = scorecard.build(snapshot(FINDINGS))
    assert document["schema"] == c.METRICS_SCHEMA
    assert document["identity"]["run_id"] == "run-2" and c.is_sha256(document["identity"]["snapshot_sha256"])
    assert document["volume"]["findings"] == 4 and document["volume"]["published"] == 4
    assert document["usefulness"]["yield"]["confirmed_actionable"]["count"] == 2
    assert [item["finding_id"] for item in document["actionable_findings"]] == ["F1", "F2"]
    # Nothing independent was supplied, so every label- or series-dependent family is unavailable, never zero.
    for path in (("triage", "volume"), ("triage", "effectiveness"), ("triage", "audit"),
                 ("usefulness", "precision"), ("correctness",), ("lifecycle",), ("outcomes",), ("crash",),
                 ("stability", "series"), ("stability", "detection"), ("coverage", "entry_points"),
                 ("coverage", "units"), ("labels",)):
        section = document
        for name in path:
            section = section[name]
        assert section["available"] is False and section["reason"], path
    assert "lifecycle: no_prior_run" in document["blind_spots"]
    assert "usefulness.precision: no_finding_labels" in document["blind_spots"]
    assert "crash: no_crash_source_registered" in document["blind_spots"]
    assert document["hunt_lane_value"]["scanner_independent"]["count"] == 1
    json.dumps(document)                                         # the document is plain JSON


def test_build_is_deterministic_and_does_not_mutate_its_inputs():
    built = snapshot(FINDINGS)
    before = c.digest(built)
    one, two = scorecard.build(built), scorecard.build(snapshot(list(reversed(FINDINGS))))
    assert c.digest(one) == c.digest(two) and c.digest(built) == before


def test_an_answer_key_labels_findings_and_measures_this_run():
    document = scorecard.build(snapshot(FINDINGS), scorecard.Inputs(answer_key=key()))
    correct = document["correctness"]
    assert (correct["defects_found"], correct["defects_missed"], correct["controls_reported"]) == (["d1"], ["d2"], ["c1"])
    assert correct["single_run_recall"]["numerator"] == 1 and correct["single_run_recall"]["denominator"] == 2
    assert correct["single_run_recall"]["interval"]["low"] < 0.5 < correct["single_run_recall"]["interval"]["high"]
    assert correct["control_false_positive_rate"]["value"] == 1.0
    precision = document["usefulness"]["precision"]
    # F1 is true (defect), F2 is false (control); F3 and F4 touch no key case and stay unlabelled.
    assert precision["published_precision"]["precision"]["value"] == 0.5
    assert precision["published_precision"]["unlabelled"] == 2
    assert document["labels"]["available"] is True
    assert "correctness: no_answer_key" not in document["blind_spots"]


def test_a_key_without_controls_reports_the_false_positive_rate_as_unavailable():
    only_defects = ScoringKey({}, key().entries[:2])
    correct = scorecard.build(snapshot(FINDINGS), scorecard.Inputs(answer_key=only_defects))["correctness"]
    assert correct["control_false_positive_rate"]["value"] is None
    assert correct["control_false_positive_rate"]["reason"] == "no_negative_controls"


def _leads():
    return [{"lead_id": "L1", "admitted": True, "disposition": "survived_confirmed", "removed_stage": None},
            {"lead_id": "L2", "admitted": True, "disposition": "dismissed_by_adjudication", "removed_stage": "blue"},
            {"lead_id": "L3", "admitted": True, "disposition": "no_claim_raised", "removed_stage": "red_no_proposal"},
            {"lead_id": "L4", "admitted": True, "disposition": "dismissed_by_adjudication", "removed_stage": "judge"}]


def _labels(**outcomes):
    return {lead_id: {"outcome": outcome, "source": "answer_key", "expected_severity": None, "disposition": None}
            for lead_id, outcome in outcomes.items()}


def test_triage_figures_are_paired_in_the_document_and_on_the_page():
    inputs = scorecard.Inputs(leads=_leads(), lead_labels=_labels(L1="true", L2="true", L3="false", L4="false"))
    document = scorecard.build(snapshot(FINDINGS), inputs)
    effect = document["triage"]["effectiveness"]
    assert effect["true_lead_retention"]["value"] == 0.5 and effect["false_lead_removal"]["value"] == 1.0
    assert effect["true_leads_removed_by_stage"]["blue"] == 1
    lines = scorecard.render_lines(document)
    paired = [line for line in lines if "false-lead removal" in line]
    assert len(paired) == 1 and "true-lead retention 1/2 (0.500" in paired[0]
    assert any(line.startswith("   true leads removed by stage:") and "blue=1" in line for line in lines)


def test_a_triage_that_removes_everything_cannot_look_good_on_the_page():
    leads = [{**lead, "disposition": "dismissed_by_adjudication", "removed_stage": "blue"} for lead in _leads()]
    inputs = scorecard.Inputs(leads=leads, lead_labels=_labels(L1="true", L2="true", L3="false", L4="false"))
    lines = scorecard.render_lines(scorecard.build(snapshot(FINDINGS), inputs))
    line = next(item for item in lines if "false-lead removal" in item)
    assert "true-lead retention 0/2 (0.000" in line and "false-lead removal 2/2 (1.000" in line


def test_lifecycle_against_a_prior_run_separates_progress_from_absence():
    units_then = {"src/net/parse.c": "a" * 64, "src/old/gone.c": "b" * 64, "src/same/still.c": "c" * 64}
    units_now = {"src/net/parse.c": "a" * 64, "src/old/gone.c": "d" * 64, "src/same/still.c": "c" * 64}
    prior = snapshot([finding("P1"), finding("P2", path="src/old/gone.c"), finding("P3", path="src/same/still.c"),
                      finding("P4", path="src/skipped/x.c")], run_id="run-1", units={**units_then,
                                                                                     "src/skipped/x.c": "e" * 64})
    current = snapshot([finding("P1"), finding("N1", path="src/new/n.c")], units={**units_now, "src/new/n.c": None})
    classified = lifecycle.classify(prior, current)
    document = scorecard.build(current, scorecard.Inputs(lifecycle=classified))
    life = document["lifecycle"]
    states = life["prior_states"]
    assert (states["persisting"], states["fix_candidate"], states["not_redetected"], states["not_covered"]) == (1, 1, 1, 1)
    assert states["fixed"] == 0 and life["fix_rate"]["value"] == 0.0      # absence alone is never a fix
    assert life["current_states"]["new"] == 1
    lines = scorecard.render_lines(document)
    assert "   since run-1: new=1 regressed=0 persisting=1 fixed=0 still_present=0" in lines
    assert "   not progress: fix_candidate=1 not_redetected=1 not_covered=1" in lines


def test_series_and_detection_inputs_are_carried_and_rendered():
    runs = [snapshot(FINDINGS, run_id=f"run-{index}") for index in (1, 2, 3)]
    detection = stability.detection_rates(
        [{"run_id": f"run-{index}", "detected": ["d1"] if index != 2 else []} for index in (1, 2, 3)], ["d1", "d2"])
    inputs = scorecard.Inputs(stability=stability.series(runs, subset="actionable"), detection=detection)
    document = scorecard.build(runs[-1], inputs)
    assert document["stability"]["series"]["mean_pairwise"]["value"] == 1.0
    lines = scorecard.render_lines(document)
    assert any("repeated-run detection: always=0 intermittent=1 never=1 sufficient_runs=False" in line for line in lines)
    assert any("stability is not precision" in line and "mean pairwise 1.0" in line for line in lines)


def test_render_has_the_four_parts_in_order_and_never_prints_a_zero_for_a_missing_input():
    lines = scorecard.render_lines(scorecard.build(snapshot(FINDINGS)))
    parts = [line for line in lines if line[:1].isdigit()]
    assert parts == ["1. For the team", "2. How far to trust it", "3. What triage did", "4. Where it is blind"]
    assert lines[0].startswith("finding scorecard run=run-2 target=game ") and "never asserted" in lines[0]
    assert "   precision: n/a (no_finding_labels)" in lines
    assert "   since prior run: n/a (no_prior_run)" in lines
    assert "   entry points reviewed: n/a (entry_point_catalog_unavailable)" in lines
    assert "   crash-corroborated high/critical: n/a (no_crash_source_registered)" in lines
    assert "   not measured: lifecycle: no_prior_run" in lines
    assert all("\n" not in line and "\r" not in line for line in lines)


def test_render_lists_each_actionable_finding_with_its_routing_fields():
    built = snapshot([finding("F1", owner="net-team", attacker_position="client_to_server", ownership="first_party")])
    lines = scorecard.render_lines(scorecard.build(built))
    assert ("   - F1 high CWE-121 src/net/parse.c owner=net-team attacker=client_to_server "
            "ownership=first_party") in lines


def test_snapshot_gaps_and_supplied_sections_reach_the_page():
    built = snapshot(FINDINGS, gaps=["reviewed_units_not_supplied"])
    crash = {"available": True, "corroborated_share_of_actionable": c.ratio(1, 2, interval=True),
             "memory_safety_buckets_without_finding": 3}
    lines = scorecard.render_lines(scorecard.build(built, scorecard.Inputs(crash=crash)))
    assert "   gap: reviewed_units_not_supplied" in lines
    assert "   memory-safety crash buckets with no finding: 3" in lines
    assert any(line.startswith("   crash-corroborated high/critical: 1/2 (0.500, 95% ") for line in lines)


def test_foreign_documents_are_refused():
    with pytest.raises(ValueError):
        scorecard.render_lines({"schema": "appsec-review/finding-metrics/0"})
    with pytest.raises(ValueError):
        scorecard.build({"schema": "appsec-review/finding-snapshot/0"})
