"""Low-cardinality process metrics, never adjudication or runtime-proof evidence."""
from __future__ import annotations

from collections import Counter
import math
from typing import Any, Callable, Mapping, Sequence

from appsec_review.reporting.dimensions import DOMAIN_IDS, RADAR_SERIES_IDS


LANES = {
    "job_poc_generation": "poc_generation",
    "job_remediation_planning": "remediation_planning",
    "job_remediation_validation": "remediation_validation",
    "job_dossier_publication": "dossiers",
    "job_final_publication_gate": "publication_gate",
    "job_final_report_publication": "report_publication",
}
COUNTERS = frozenset({
    "proposed", "admitted", "assessed", "capped", "rejected", "deduplicated",
    "seeds_received", "seeds_rejected", "expanded", "challenges", "independent", "gaps",
    "candidate_count", "confirmed_count", "admitted_count", "omitted_count",
    "selected", "omitted", "items", "confirmed_finding_count", "poc_count", "source_excerpts",
    "supported_excluded_count", "proposal_count", "item_count", "gap_count",
    "finding_packages", "confirmed_findings", "poc_outcomes", "accepted_producers",
    "rendered_count", "render_failed_count", "latex_only_count", "dossier_count",
    "attachment_count", "publishable_count", "withheld_count", "backlog_count",
    "policy_failure_count", "build_failure_count", "compile_verified_count",
    "turn_count", "query_count", "input_tokens", "output_tokens", "cache_tokens",
    "timeout_count", "failure_count", "output_bytes",
    "usage_unavailable_count",
    "json_bytes", "latex_bytes", "pdf_bytes", "receipt_bytes",
    "radar_verified_axes", "radar_gap_axes", "chain_elevated_count",
    "remediation_roadmap_count", "named_gap_count", "dossiers_certified", "dossiers_read",
})
OUTCOME_FIELDS = ("outcomes", "outcome_counts", "by_kind", "by_status")
LIMITS = ("max_dossiers", "max_source_excerpts", "max_evidence_rows")
CAPABILITIES = frozenset({"poc_generation", "attack_chains", "remediation_planning",
                          "remediation_validation", "dossiers"})
CAPABILITY_COUNTERS = ("attachment_counts", "gap_counts", "omitted_counts", "certified_outcome_counts")
FLAGS = ("explicit_poc_admission", "frontier_truncated", "pdf_requested", "render_failed",
         "baseline_attempted", "patched_attempted", "usage_unavailable", "render_pdf")
DIMENSIONS = {"kind": {"confirmed_finding", "poc", "refuter", "weakest_link_verifier"},
              "adapter": {"native_syntax"}, "role": {"remediation_writer", "remediation_reviewer"}}
OUTCOMES = frozenset({
    "SUCCEEDED", "COMPLETED_WITH_GAPS", "SKIPPED_NA", "SKIPPED_POLICY", "GAP",
    "succeeded", "failed", "canceled", "cancelled", "timed_out", "blocked", "partial",
    "confirmed", "qualified_supported", "refuted", "insufficient_evidence",
    "compile_verified", "compile_failed", "policy_rejected", "generated", "unavailable",
    "artifact_generated", "policy_denied", "unsafe_to_attempt",
    "not_applicable", "not_attempted", "not_launched", "skipped_policy", "capped",
    "proposal_generated", "manual_design_required", "rejected", "inconclusive",
    "build_checked", "static_checked", "manual_validation_required",
    "rendered", "render_failed", "not_rendered", "latex_only", "confirmed_finding", "poc",
    "answered", "invalid", "declined", "cap_reached", "passed", "baseline_failed", "patched_failed", "unsafe",
})
REPORT_RATES = frozenset({"exposure_to_coverage_rate", "exposure_to_leads_rate", "leads_to_confirmed_rate"})
REPORT_GAP_REASONS = frozenset({
    "domain_coverage_unknown", "surface_exposure_unknown", "inspected_units_unknown",
    "corroborated_leads_unknown", "certified_reachability_unavailable", "syntactic_fallback_only",
    "verification_backlog_unconfirmed", "withheld_packages", "uninspected_exposed_units",
    "no_domain_coverage_bound", "review_incomplete", "review_degraded",
    "numerator_unknown", "denominator_unknown", "denominator_empty",
})


def _report_measurements(details: Mapping[str, Any], bucket: dict[str, Any],
                         invalid: Callable[[str], None]) -> None:
    """Ranges describe observed snapshots, not sums of percentages or accepted finding counts."""
    measurements = bucket.setdefault("measurements", {})
    qualifications = bucket.setdefault("qualifications", Counter())

    def measure(field: str, value: Any, *, integer: bool = True, maximum: float = 2**63 - 1) -> None:
        if value is not None and not (
            type(value) in ((int,) if integer else (int, float))
            and 0 <= value <= maximum and math.isfinite(value)
        ):
            invalid(field)
            return
        row = measurements.setdefault(field, {"count": 0, "unavailable": 0, "min": None, "max": None})
        if value is None:
            row["unavailable"] += 1
        else:
            row["count"] += 1
            row["min"] = value if row["min"] is None else min(row["min"], value)
            row["max"] = value if row["max"] is None else max(row["max"], value)

    def reasons(field: str, values: Any) -> None:
        if not isinstance(values, list) or len(values) > len(REPORT_GAP_REASONS):
            invalid(field)
            return
        for reason in values:
            if not isinstance(reason, str) or reason not in REPORT_GAP_REASONS:
                invalid(field)
            else:
                qualifications[f"{field}.{reason}"] += 1

    def entries(field: str, allowed: Sequence[str] | frozenset[str]):
        if field not in details:
            return ()
        value = details[field]
        if not isinstance(value, Mapping):
            invalid(field)
            return ()
        result = []
        for key, item in value.items():
            if key not in allowed:
                invalid(field)
            else:
                result.append((key, item))
        return result

    for field in ("coverage_confidence_score", "reachable_supply_chain_advisories_count"):
        if field in details:
            measure(field, details[field], maximum=100 if field == "coverage_confidence_score" else 2**63 - 1)
    for field in ("coverage_confidence_gap_reasons", "reachable_supply_chain_gap_reasons"):
        if field in details:
            reasons(field, details[field])
    for axis, values in entries("radar_counts_by_axis_and_series", DOMAIN_IDS):
        prefix = f"radar_counts_by_axis_and_series.{axis}"
        if not isinstance(values, Mapping):
            invalid(prefix)
            continue
        for series, value in values.items():
            if series not in RADAR_SERIES_IDS:
                invalid(prefix)
            else:
                measure(f"{prefix}.{series}", value)
    for field in ("radar_gap_reasons_by_axis", "radar_metric_gap_reasons_by_axis"):
        for axis, values in entries(field, DOMAIN_IDS):
            reasons(f"{field}.{axis}", values)
    for rate, value in entries("funnel_conversion_rates", REPORT_RATES):
        measure(f"funnel_conversion_rates.{rate}", value, integer=False)
    for rate, values in entries("funnel_gap_reasons", REPORT_RATES):
        reasons(f"funnel_gap_reasons.{rate}", values)


def _lane(record: Mapping[str, Any]) -> str | None:
    job = record.get("job_id")
    if job == "job_inference_security_review":
        if (record.get("step_id") == "attack_chains"
                or str(record.get("event_type", "")).startswith("INFERENCE_REVIEW_ATTACK_CHAIN")):
            return "attack_chains"
        return None
    return LANES.get(job)


def completion_metrics(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Keep attempts and stages separate: retries are work, not additional accepted findings."""
    lanes: dict[str, dict[str, Any]] = {
        name: {"observed": False, "events": {}} for name in ("attack_chains", *LANES.values())
    }
    gaps: list[dict[str, str]] = []
    gap_count = 0

    def invalid(lane: str, event: str, field: str) -> None:
        nonlocal gap_count
        gap_count += 1
        if len(gaps) < 200:
            gaps.append({"lane": lane, "event_type": event, "field": field,
                         "reason": "nonnegative_bounded_measurement_required"})

    for record in records:
        lane = _lane(record)
        if lane is None:
            continue
        event = str(record["event_type"])
        details = record.get("details", {})
        target = lanes[lane]
        target["observed"] = True
        bucket = target["events"].setdefault(
            event, {"count": 0, "counters": Counter(), "outcomes": Counter(),
                    "flags": Counter(), "dimensions": Counter(), "limits": {},
                    "duration_ms": [], "unavailable_token_measurements": 0})
        bucket["count"] += 1
        if lane == "report_publication" and event == "FINAL_REPORT_ASSEMBLED":
            _report_measurements(details, bucket, lambda field: invalid(lane, event, field))
        for field in sorted(COUNTERS & details.keys()):
            value = details[field]
            if value is None and field in {"input_tokens", "output_tokens", "cache_tokens"}:
                bucket["unavailable_token_measurements"] += 1
            elif type(value) is int and 0 <= value < 2**63:
                bucket["counters"][field] += value
            else:
                invalid(lane, event, field)
        for field in LIMITS:
            if field in details:
                value = details[field]
                if type(value) is int and 0 <= value < 2**63:
                    bucket["limits"].setdefault(field, set()).add(value)
                else:
                    invalid(lane, event, field)
        for field in CAPABILITY_COUNTERS:
            values = details.get(field)
            if values is None:
                continue
            if not isinstance(values, Mapping):
                invalid(lane, event, field)
                continue
            for capability, count in values.items():
                if capability not in CAPABILITIES:
                    invalid(lane, event, field)
                elif type(count) is int and 0 <= count < 2**63:
                    bucket["counters"][f"{field}.{capability}"] += count
                else:
                    invalid(lane, event, f"{field}.{capability}")
        for field in FLAGS:
            if field in details:
                if type(details[field]) is bool:
                    bucket["flags"][f"{field}.{str(details[field]).lower()}"] += 1
                else:
                    invalid(lane, event, field)
        for field, permitted in DIMENSIONS.items():
            value = details.get(field)
            if isinstance(value, str) and value in permitted:
                bucket["dimensions"][f"{field}.{value}"] += 1
        for field in ("dispositions", "enabled"):
            if lane != "publication_gate" or event != "FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED":
                continue
            values = details.get(field)
            if values is None:
                continue
            if not isinstance(values, Mapping):
                invalid(lane, event, field)
                continue
            for capability, value in values.items():
                if capability not in CAPABILITIES:
                    invalid(lane, event, field)
                elif field == "enabled" and type(value) is bool:
                    bucket["flags"][f"enabled.{capability}.{str(value).lower()}"] += 1
                elif field == "dispositions" and isinstance(value, str) and value in OUTCOMES:
                    bucket["outcomes"][f"dispositions.{capability}.{value}"] += 1
                else:
                    invalid(lane, event, f"{field}.{capability}")
        duration = details.get("duration_ms")
        if duration is not None:
            if (type(duration) in (int, float) and math.isfinite(duration)
                    and 0 <= duration < 2**63):
                bucket["duration_ms"].append(int(duration))
            else:
                invalid(lane, event, "duration_ms")
        for field in OUTCOME_FIELDS:
            values = details.get(field)
            if values is None:
                continue
            if not isinstance(values, Mapping):
                invalid(lane, event, field)
                continue
            for status, count in values.items():
                if status not in OUTCOMES:
                    invalid(lane, event, field)
                elif type(count) is int and 0 <= count < 2**63:
                    bucket["outcomes"][f"{field}.{status}"] += count
                else:
                    invalid(lane, event, f"{field}.{status}")
        outcome = details.get("outcome") or details.get("status")
        if isinstance(outcome, str) and outcome in OUTCOMES:
            bucket["outcomes"][outcome] += 1
        if lane == "report_publication" and event == "FINAL_REPORT_PUBLISHED" and "pdf" in details:
            pdf = details["pdf"]
            if isinstance(pdf, str) and pdf in {"rendered", "render_failed", "not_rendered"}:
                bucket["outcomes"][f"pdf.{pdf}"] += 1
            else:
                invalid(lane, event, "pdf")

    for lane in lanes.values():
        events = {}
        for event, bucket in sorted(lane["events"].items()):
            durations = sorted(bucket["duration_ms"])
            events[event] = {
                "count": bucket["count"],
                "counters": dict(sorted(bucket["counters"].items())),
                "outcomes": dict(sorted(bucket["outcomes"].items())),
                "flags": dict(sorted(bucket["flags"].items())),
                "dimensions": dict(sorted(bucket["dimensions"].items())),
                "limits": {field: {"min": min(values), "max": max(values)}
                           for field, values in sorted(bucket["limits"].items())},
                "unavailable_token_measurements": bucket["unavailable_token_measurements"],
                "duration_ms": {
                    "count": len(durations),
                    "p50": durations[max(0, math.ceil(len(durations) * .50) - 1)] if durations else None,
                    "p95": durations[max(0, math.ceil(len(durations) * .95) - 1)] if durations else None,
                    "max": max(durations) if durations else None,
                    "summed_work": sum(durations) if durations else None,
                },
            }
            if "measurements" in bucket:
                events[event]["measurements"] = dict(sorted(bucket["measurements"].items()))
                events[event]["qualifications"] = dict(sorted(bucket["qualifications"].items()))
        lane["events"] = events
    return {
        "semantics": "appsec-review/completion-process-metrics/1",
        "authority": "observational_process_metrics_not_security_evidence",
        "counting": "event-scoped attempted work; retries count; overlapping stages must not be summed",
        "lanes": lanes, "measurement_gap_count": gap_count, "measurement_gaps": gaps,
    }
