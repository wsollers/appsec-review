"""Assemble and render the per-run finding scorecard (finding-metrics.md sections 5 and 9).

:func:`build` joins the metric families into one ``finding-metrics/1`` document from a finding
snapshot and whatever independent inputs the operator has: an answer key, lead records and labels,
a prior run, developer outcomes, an audit sample, crash evidence, an entry-point catalogue, a
repeated-run series. Every input is optional. A family whose input is absent is
``{"available": false, "reason": ...}`` and is listed under ``blind_spots``; it is never a zero.

:func:`render_lines` prints the one-page scorecard in the fixed order of the design: what the team
gets, how far to trust it, what triage did, where the review is blind. Paired figures are printed
together; a reduction is never printed without its retention.

Nothing here reads a run, a target or a model, and nothing here is a verdict: the scorecard is
reported, never asserted, and no figure in it is evidence that a target is clean.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from appsec_review.acceptance.scoring_model import EntryKind, ScoringKey

from . import actionability, coverage, integrity, labels as label_rules, lifecycle as lifecycle_rules, slices
from . import triage, usefulness
from .contracts import METRICS_SCHEMA, check_snapshot, digest, is_actionable, is_published, ratio, unavailable

DEFAULT_BUDGET = 20
SLICE_DIMENSIONS = ("severity", "ship_block_status", "lane", "weakness_family", "attacker_position", "ownership",
                    "build_configuration", "component")


@dataclass(frozen=True)
class Inputs:
    """Optional, independent inputs of one scorecard. ``None`` always means "not supplied"."""

    triage_reduction: Mapping[str, Any] | None = None      # the run's existing triage_reduction section
    leads: Sequence[Mapping[str, Any]] | None = None       # lead records for labelled triage effectiveness
    lead_labels: Mapping[str, Mapping[str, Any]] | None = None
    audit_sample: Mapping[str, Any] | None = None
    audit_labels: Mapping[str, Mapping[str, Any]] | None = None
    answer_key: ScoringKey | None = None
    finding_labels: Mapping[str, Mapping[str, Any]] | None = None   # extra labels keyed by fingerprint
    outcomes: Mapping[str, Any] | None = None              # labels.admit_outcomes(...) result
    lifecycle: Mapping[str, Any] | None = None             # lifecycle.classify(...) result, rechecks applied
    ages: Mapping[str, int] | None = None                  # history.ages(...)
    entry_points: Sequence[Mapping[str, Any]] | None = None
    translation_units: Mapping[str, int | None] | None = None   # {"built", "extracted", "total"}
    crash: Mapping[str, Any] | None = None                 # crash.correlate.metrics(...) result
    crash_labels: Mapping[str, Mapping[str, Any]] | None = None
    stability: Mapping[str, Any] | None = None             # stability.series(...) of the repeated runs
    flapping: Mapping[str, Any] | None = None
    detection: Mapping[str, Any] | None = None             # stability.detection_rates(...) of the corpus series
    role_citations: Sequence[Mapping[str, Any]] | None = None
    reviewer_directed_case: Mapping[str, Any] | None = None
    canary: tuple[Mapping[str, Any] | None, Mapping[str, Any] | None] | None = None
    reviewed_kloc: float | None = None
    cost: Mapping[str, Any] | None = None
    slice_rules_sha256: str | None = None
    budget: int = DEFAULT_BUDGET


def _correctness(snapshot: Mapping[str, Any], key: ScoringKey | None) -> dict[str, Any]:
    """This run against the key: defect cases found and control cases reported, with intervals.

    One run on a small key is a noisy estimate; the repeated-run detection rate (``stability``
    section) is the figure to trend.
    """
    if key is None:
        return unavailable("no_answer_key")
    hits = label_rules.key_case_hits(key, snapshot["findings"])
    defects = [entry.id for entry in key.entries if entry.kind is EntryKind.DEFECT]
    controls = [entry.id for entry in key.entries if entry.kind is EntryKind.CONTROL]
    found = sorted(entry_id for entry_id in defects if hits.get(entry_id))
    reported = sorted(entry_id for entry_id in controls if hits.get(entry_id))
    return {
        "available": True, "defects": len(defects), "controls": len(controls),
        "defects_found": found, "defects_missed": sorted(set(defects) - set(found)),
        "controls_reported": reported,
        "single_run_recall": ratio(len(found), len(defects), interval=True),
        "control_false_positive_rate": (ratio(len(reported), len(controls), interval=True) if controls
                                        else ratio(None, None, reason="no_negative_controls")),
        "basis": "function_scope_and_weakness_family",
    }


def _labels(snapshot: Mapping[str, Any], inputs: Inputs) -> dict[str, Any] | None:
    maps = []
    if inputs.answer_key is not None:
        severities = {entry.id: entry.severity for entry in inputs.answer_key.entries
                      if entry.kind is EntryKind.DEFECT and entry.severity is not None}
        maps.append(label_rules.label_findings_from_key(inputs.answer_key, snapshot["findings"],
                                                        severities=severities))
    if inputs.outcomes is not None:
        maps.append(inputs.outcomes["labels"])
    for extra in (inputs.finding_labels, inputs.crash_labels):
        if extra is not None:
            maps.append(extra)
    return label_rules.merge(*maps) if maps else None


def _blind_spots(document: Mapping[str, Any], prefix: str = "") -> list[str]:
    found = []
    for name, value in document.items():
        if isinstance(value, Mapping):
            if value.get("available") is False:
                found.append(f"{prefix}{name}: {value.get('reason')}")
            else:
                found.extend(_blind_spots(value, f"{prefix}{name}."))
    return found


def build(snapshot: Mapping[str, Any], inputs: Inputs = Inputs()) -> dict[str, Any]:
    """The ``finding-metrics/1`` document of one snapshot. Deterministic; never mutates its inputs."""
    snapshot = check_snapshot(snapshot)
    findings = snapshot["findings"]
    label_set = _labels(snapshot, inputs)
    labels = None if label_set is None else label_set["labels"]
    by_fingerprint = {item["fingerprint"]["exact"]: item for item in findings}
    units = inputs.translation_units
    families = {
        "volume": usefulness.volume(snapshot),
        "triage": {
            "volume": triage.split_ratios(inputs.triage_reduction),
            "effectiveness": (triage.effectiveness(inputs.leads, inputs.lead_labels)
                              if inputs.leads is not None else unavailable("no_lead_records")),
            "audit": (triage.audit_miss_rate(inputs.audit_sample, inputs.audit_labels)
                      if inputs.audit_sample is not None else unavailable("no_audit_sample")),
        },
        "usefulness": {
            "severity": usefulness.severity(snapshot),
            "yield": usefulness.actionable_yield(snapshot, reviewed_kloc=inputs.reviewed_kloc, cost=inputs.cost),
            "precision": usefulness.precision(snapshot, labels),
            "precision_at_budget": usefulness.precision_at_budget(snapshot, labels, inputs.budget),
        },
        "correctness": _correctness(snapshot, inputs.answer_key),
        "stability": {
            "series": inputs.stability if inputs.stability is not None else unavailable("no_repeated_run_series"),
            "flapping": inputs.flapping if inputs.flapping is not None else unavailable("no_repeated_run_series"),
            "detection": inputs.detection if inputs.detection is not None else unavailable("no_corpus_series"),
        },
        "lifecycle": lifecycle_rules.metrics(inputs.lifecycle, ages=inputs.ages),
        "coverage": {
            "entry_points": coverage.entry_point_coverage(inputs.entry_points),
            "units": coverage.unit_coverage(snapshot),
            "translation_units": (coverage.translation_units(units.get("built"), units.get("extracted"),
                                                             units.get("total"))
                                  if units is not None else unavailable("translation_unit_counts_unavailable")),
        },
        "hunt_lane_value": coverage.hunt_lane_value(snapshot),
        "actionability": actionability.completeness(snapshot),
        "outcomes": label_rules.outcome_metrics(inputs.outcomes, by_fingerprint),
        "crash": inputs.crash if inputs.crash is not None else unavailable("no_crash_source_registered"),
        "integrity": {
            "citations": integrity.citation_resolution(snapshot),
            "citations_by_role": integrity.citation_resolution_by_role(inputs.role_citations),
            "verification": integrity.verification(snapshot),
            "reviewer_directed_case": integrity.reviewer_directed_case(inputs.reviewer_directed_case),
            "canary": (integrity.canary_drift(*inputs.canary) if inputs.canary is not None
                       else unavailable("canary_series_unavailable")),
        },
    }
    published = [item for item in findings if is_published(item)]
    document = {
        "schema": METRICS_SCHEMA,
        "identity": {"run_id": snapshot["run_id"], "target_id": snapshot["target_id"],
                     "source_revision": snapshot["source_revision"], "stage": snapshot["stage"],
                     "configuration_sha256": snapshot["configuration_sha256"],
                     "guidance_sha256": snapshot["guidance_sha256"], "model_sha256": snapshot["model_sha256"],
                     "snapshot_sha256": digest(snapshot), "slice_rules_sha256": inputs.slice_rules_sha256},
        **families,
        "labels": (unavailable("no_label_source") if label_set is None
                   else {"available": True, "counts": label_set["counts"], "conflicts": label_set["conflicts"]}),
        "slices": {"published": {name: slices.slice_counts(published, name) for name in SLICE_DIMENSIONS},
                   "routing": slices.routing(findings)},
        "actionable_findings": [
            {"finding_id": item["finding_id"], "severity": item["severity"], "weakness_cwe": item["weakness_cwe"],
             "owner": item["owner"], "attacker_position": item["attacker_position"],
             "ownership": item["ownership"], "path": item["locations"][0]["path"]}
            for item in findings if is_actionable(item)],
        "snapshot_gaps": list(snapshot["gaps"]),
        "interpretation": ("reported, never asserted; no figure here is evidence that a target is clean, "
                           "and an unavailable family is not a zero"),
    }
    document["blind_spots"] = sorted(_blind_spots(families) + _blind_spots({"labels": document["labels"]}))
    return document


# ------------------------------------------------------------------------------------ render

def _show(value: Mapping[str, Any] | None) -> str:
    """A ratio as ``n/d (0.xxx, 95% lo-hi)``, or ``n/a (<reason>)``; never a bare zero for missing input."""
    if not isinstance(value, Mapping) or "numerator" not in value:
        return "n/a"
    if value.get("value") is None:
        return f"n/a ({value.get('reason')})"
    text = f"{value['numerator']}/{value['denominator']} ({value['value']:.3f}"
    interval = value.get("interval")
    if interval:
        text += f", 95% {interval['low']:.3f}-{interval['high']:.3f}"
    return text + ")"


def _section(value: Mapping[str, Any]) -> bool:
    return value.get("available") is not False


def render_lines(document: Mapping[str, Any]) -> list[str]:
    """The one-page scorecard. Lines are stable for a given document."""
    if document.get("schema") != METRICS_SCHEMA:
        raise ValueError("unsupported finding metrics schema")
    identity = document["identity"]
    lines = [f"finding scorecard run={identity['run_id']} target={identity['target_id']} "
             f"revision={identity['source_revision']} stage={identity['stage']} (reported, never asserted)"]

    lines.append("1. For the team")
    gain = document["usefulness"]["yield"]
    lines.append(f"   confirmed high/critical: {gain['confirmed_actionable']['count']}"
                 f"   supported high/critical (unconfirmed): {gain['supported_actionable']['count']}")
    for item in document["actionable_findings"]:
        lines.append(f"   - {item['finding_id']} {item['severity']} {item['weakness_cwe'] or 'CWE n/a'} "
                     f"{item['path']} owner={item['owner'] or 'n/a'} attacker={item['attacker_position'] or 'n/a'} "
                     f"ownership={item['ownership'] or 'n/a'}")
    crash = document["crash"]
    lines.append("   crash-corroborated high/critical: "
                 + (_show(crash.get("corroborated_share_of_actionable")) if _section(crash)
                    else f"n/a ({crash['reason']})"))
    life = document["lifecycle"]
    if _section(life):
        prior, current = life["prior_states"], life["current_states"]
        lines.append(f"   since {life['prior_run_id']}: new={current['new']} regressed={current['regressed']} "
                     f"persisting={prior['persisting']} fixed={prior['fixed']} "
                     f"still_present={prior['still_present']}")
        lines.append(f"   not progress: fix_candidate={prior['fix_candidate']} "
                     f"not_redetected={prior['not_redetected']} not_covered={prior['not_covered']}")
    else:
        lines.append(f"   since prior run: n/a ({life['reason']})")

    lines.append("2. How far to trust it")
    cover = document["coverage"]
    entry = cover["entry_points"]
    lines.append("   entry points reviewed: "
                 + (_show(entry["reviewed_share"]) if _section(entry) else f"n/a ({entry['reason']})"))
    unit = cover["units"]
    lines.append("   units reviewed: " + (_show(unit["reviewed_share"]) if _section(unit) else f"n/a ({unit['reason']})"))
    precision = document["usefulness"]["precision"]
    if _section(precision):
        lines.append(f"   precision (published): {_show(precision['published_precision']['precision'])}"
                     f"   (high/critical): {_show(precision['actionable_precision']['precision'])}")
    else:
        lines.append(f"   precision: n/a ({precision['reason']})")
    correct = document["correctness"]
    if _section(correct):
        lines.append(f"   this run on the key: recall {_show(correct['single_run_recall'])}"
                     f"   controls reported {_show(correct['control_false_positive_rate'])}")
    else:
        lines.append(f"   this run on the key: n/a ({correct['reason']})")
    detection = document["stability"]["detection"]
    lines.append("   repeated-run detection: "
                 + (f"always={detection['always_detected']['count']} intermittent={detection['intermittent']['count']} "
                    f"never={detection['never_detected']['count']} sufficient_runs={detection['sufficient_runs']}"
                    if _section(detection) else f"n/a ({detection['reason']})"))
    series = document["stability"]["series"]
    lines.append("   stability of the set (no interval; stability is not precision): "
                 + (f"mean pairwise {series['mean_pairwise']['value']}" if _section(series)
                    else f"n/a ({series['reason']})"))
    severity = document["usefulness"]["severity"]
    lines.append(f"   unrated published findings: {_show(severity['unrated_share'])}")

    lines.append("3. What triage did")
    volume = document["triage"]["volume"]
    if _section(volume):
        lines.append(f"   admitted={volume['admitted']} removed by refutation {_show(volume['dismissed_over_resolved'])}"
                     f"   removed by silence {_show(volume['no_claim_over_resolved'])}")
        lines.append(f"   unresolved (left for a person): {_show(volume['unresolved_share'])}")
    else:
        lines.append(f"   lead dispositions: n/a ({volume['reason']})")
    effect = document["triage"]["effectiveness"]
    if _section(effect):
        lines.append(f"   true-lead retention {_show(effect['true_lead_retention'])}"
                     f"   false-lead removal {_show(effect['false_lead_removal'])}")
        stages = " ".join(f"{name}={count}" for name, count in effect["true_leads_removed_by_stage"].items())
        lines.append(f"   true leads removed by stage: {stages}")
    else:
        lines.append(f"   true-lead retention and false-lead removal: n/a ({effect['reason']})")
    audit = document["triage"]["audit"]
    lines.append("   audit miss rate on this target: "
                 + (_show(audit["miss_rate"]) if _section(audit) else f"n/a ({audit['reason']})"))
    hunt = document["hunt_lane_value"]
    lines.append(f"   found without any scanner: {hunt['scanner_independent']['count']} "
                 f"(backing unknown: {hunt['scanner_backing_unknown']})")

    lines.append("4. Where it is blind")
    if _section(entry):
        lines.append(f"   uncovered entry points: {len(entry['uncovered']) + entry['uncovered_truncated']}")
    if _section(crash):
        lines.append(f"   memory-safety crash buckets with no finding: {crash.get('memory_safety_buckets_without_finding')}")
    for gap in document["snapshot_gaps"]:
        lines.append(f"   gap: {gap}")
    for spot in document["blind_spots"]:
        lines.append(f"   not measured: {spot}")
    return lines


__all__ = ["DEFAULT_BUDGET", "Inputs", "SLICE_DIMENSIONS", "build", "render_lines"]
