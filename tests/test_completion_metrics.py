from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.observability import PipelineLog, aggregate_run_metrics, write_run_metrics
from appsec_review.observability.completion import completion_metrics


def test_completion_metrics_track_stages_retries_outcomes_and_latency_without_content(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    secret = "protected source patch PoC or prompt content"
    for duration in (10, 30):
        log.write("DOSSIER_RENDER_COMPLETED", run_id=tmp_path.name,
                  job_id="job_dossier_publication", attempt_id=f"attempt_{duration}",
                  details={"outcome": "rendered", "duration_ms": duration, "pdf_bytes": 100,
                           "claim_id": secret, "source": secret, "patch": secret, "reason": secret})
    log.write("DOSSIER_PUBLICATION_ASSEMBLED", run_id=tmp_path.name,
              job_id="job_dossier_publication", details={
                  "by_kind": {"confirmed_finding": 1, "poc": 1},
                  "by_status": {"rendered": 1, "render_failed": 1},
                  "omitted_count": 2, "gap_count": 3})
    report = aggregate_run_metrics(tmp_path)["completion"]
    lane = report["lanes"]["dossiers"]
    assert lane["observed"] is True
    event = lane["events"]["DOSSIER_RENDER_COMPLETED"]
    assert event["count"] == 2
    assert event["counters"] == {"pdf_bytes": 200}
    assert event["outcomes"] == {"rendered": 2}
    assert event["duration_ms"] == {"count": 2, "p50": 10, "p95": 30, "max": 30, "summed_work": 40}
    summary = lane["events"]["DOSSIER_PUBLICATION_ASSEMBLED"]
    assert summary["outcomes"]["by_status.render_failed"] == 1
    assert summary["counters"]["omitted_count"] == 2
    assert secret not in json.dumps(report)
    assert report["measurement_gap_count"] == 0
    assert write_run_metrics(tmp_path)["completion"] == report
    assert json.loads((tmp_path / "data" / "telemetry" / "summary.json").read_text())["completion"] == report


def test_metrics_regeneration_replaces_stale_cache_without_mutating_or_recounting_events(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    log.write("POC_GENERATION_PUBLISHED", run_id=tmp_path.name,
              job_id="job_poc_generation", attempt_id="attempt_0001",
              details={"candidate_count": 2, "by_status": {"compile_verified": 1, "policy_denied": 1}})
    first = write_run_metrics(tmp_path)
    authoritative = log.path.read_bytes()
    summary = tmp_path / "data" / "telemetry" / "summary.json"
    summary.write_text('{"stale":true}', encoding="utf-8")
    assert write_run_metrics(tmp_path) == first
    assert json.loads(summary.read_text(encoding="utf-8")) == first
    assert log.path.read_bytes() == authoritative

    log.write("DOSSIER_PUBLICATION_PUBLISHED", run_id=tmp_path.name,
              job_id="job_dossier_publication", attempt_id="attempt_0001",
              details={"rendered_count": 1, "gap_count": 0})
    log.write("FINAL_REPORT_ASSEMBLED", run_id=tmp_path.name,
              job_id="job_final_report_publication", attempt_id="attempt_0001",
              details={"certified_outcome_counts": {"dossiers": 1, "attack_chains": 0}})
    authoritative = log.path.read_bytes()
    latest = write_run_metrics(tmp_path)
    lanes = latest["completion"]["lanes"]
    assert lanes["poc_generation"]["events"]["POC_GENERATION_PUBLISHED"]["count"] == 1
    assert lanes["dossiers"]["events"]["DOSSIER_PUBLICATION_PUBLISHED"]["counters"] == {
        "gap_count": 0, "rendered_count": 1}
    assert lanes["report_publication"]["events"]["FINAL_REPORT_ASSEMBLED"]["counters"] == {
        "certified_outcome_counts.attack_chains": 0, "certified_outcome_counts.dossiers": 1}
    assert latest["completion"]["measurement_gaps"] == []
    assert json.loads(summary.read_text(encoding="utf-8")) == latest
    assert write_run_metrics(tmp_path) == latest
    assert log.path.read_bytes() == authoritative


def test_chain_metrics_exclude_other_inference_work_and_preserve_unobserved_lanes() -> None:
    records = [
        {"job_id": "job_inference_security_review", "event_type": "INFERENCE_REVIEW_ATTACK_CHAINS_PUBLISHED",
         "details": {"admitted": 2, "assessed": 1, "capped": 1, "outcomes": {"qualified_supported": 1}}},
        {"job_id": "job_inference_security_review", "event_type": "TASK_COMPLETED", "step_id": "lead_review",
         "details": {"confirmed_count": 50}},
    ]
    report = completion_metrics(records)
    lane = report["lanes"]["attack_chains"]
    assert set(lane["events"]) == {"INFERENCE_REVIEW_ATTACK_CHAINS_PUBLISHED"}
    assert lane["events"]["INFERENCE_REVIEW_ATTACK_CHAINS_PUBLISHED"]["counters"]["admitted"] == 2
    assert report["lanes"]["remediation_validation"] == {"observed": False, "events": {}}


@pytest.mark.parametrize("value", [-1, True, "12", 2**63])
def test_invalid_completion_measurements_are_named_gaps_not_silent_zeroes(value) -> None:
    report = completion_metrics([{
        "job_id": "job_remediation_validation", "event_type": "REMEDIATION_VALIDATION_ADAPTER_COMPLETED",
        "details": {"failure_count": value, "outcomes": {"untrusted-status-prose": 1}},
    }])
    assert report["measurement_gap_count"] == 2
    event = report["lanes"]["remediation_validation"]["events"]["REMEDIATION_VALIDATION_ADAPTER_COMPLETED"]
    assert event["counters"] == {}
    assert event["outcomes"] == {}
    assert "untrusted-status-prose" not in json.dumps(report)


def test_missing_model_usage_is_not_fabricated_as_zero_tokens() -> None:
    report = completion_metrics([{
        "job_id": "job_remediation_planning", "event_type": "REMEDIATION_MODEL_COMPLETED",
        "details": {"input_tokens": None, "output_tokens": 15, "duration_ms": None},
    }])
    event = report["lanes"]["remediation_planning"]["events"]["REMEDIATION_MODEL_COMPLETED"]
    assert event["counters"] == {"output_tokens": 15}
    assert event["unavailable_token_measurements"] == 1
    assert event["duration_ms"]["p95"] is None


@pytest.mark.parametrize("counts", [
    {"dossiers": True}, {"dossiers": -1}, {"dossiers": "1"}, {"dossiers": 2**63},
    {"untrusted-capability-prose": 1},
])
def test_invalid_certified_report_counts_are_named_gaps_without_untrusted_labels(counts) -> None:
    report = completion_metrics([{
        "job_id": "job_final_report_publication", "event_type": "FINAL_REPORT_ASSEMBLED",
        "details": {"certified_outcome_counts": counts},
    }])
    assert report["measurement_gap_count"] == 1
    event = report["lanes"]["report_publication"]["events"]["FINAL_REPORT_ASSEMBLED"]
    assert event["counters"] == {}
    assert "untrusted-capability-prose" not in json.dumps(report)


def test_real_producer_statuses_caps_and_manual_admission_are_counted() -> None:
    report = completion_metrics([
        {"job_id": "job_poc_generation", "event_type": "POC_GENERATION_PUBLISHED",
         "details": {"by_status": {"artifact_generated": 1, "policy_denied": 2, "unsafe_to_attempt": 3}}},
        {"job_id": "job_final_publication_gate", "event_type": "FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED",
         "details": {"explicit_poc_admission": True, "enabled": {"poc_generation": False},
                     "dispositions": {"poc_generation": "SUCCEEDED", "dossiers": "GAP"},
                     "attachment_counts": {"dossiers": 2}, "omitted_counts": {"dossiers": 1}}},
        {"job_id": "job_remediation_validation", "event_type": "REMEDIATION_VALIDATION_ADAPTER_COMPLETED",
         "details": {"adapter": "native_syntax", "outcome": "baseline_failed", "baseline_attempted": True,
                     "patched_attempted": False, "failure_count": 1}},
        {"job_id": "job_final_report_publication", "event_type": "FINAL_REPORT_ASSEMBLED",
         "details": {"certified_outcome_counts": {
             "attack_chains": 0, "poc_generation": 1, "remediation_planning": 1,
             "remediation_validation": 1, "dossiers": 2}}},
    ])
    assert report["measurement_gap_count"] == 0
    gate = report["lanes"]["publication_gate"]["events"]["FINAL_PUBLICATION_GATE_CAPABILITIES_VERIFIED"]
    assert gate["flags"] == {"enabled.poc_generation.false": 1, "explicit_poc_admission.true": 1}
    assert gate["counters"] == {"attachment_counts.dossiers": 2, "omitted_counts.dossiers": 1}
    assert gate["outcomes"]["dispositions.dossiers.GAP"] == 1
    adapter = report["lanes"]["remediation_validation"]["events"]["REMEDIATION_VALIDATION_ADAPTER_COMPLETED"]
    assert adapter["dimensions"] == {"adapter.native_syntax": 1}
    assert adapter["outcomes"] == {"baseline_failed": 1}
    publication = report["lanes"]["report_publication"]["events"]["FINAL_REPORT_ASSEMBLED"]
    assert publication["counters"] == {
        "certified_outcome_counts.attack_chains": 0, "certified_outcome_counts.poc_generation": 1,
        "certified_outcome_counts.remediation_planning": 1,
        "certified_outcome_counts.remediation_validation": 1, "certified_outcome_counts.dossiers": 2}


def test_configured_limits_are_ranges_not_additive_retry_work() -> None:
    record = {"job_id": "job_dossier_publication", "event_type": "DOSSIER_BATCH_PLANNED",
              "details": {"admitted": 2, "max_dossiers": 10}}
    report = completion_metrics([record, record])
    event = report["lanes"]["dossiers"]["events"]["DOSSIER_BATCH_PLANNED"]
    assert event["counters"] == {"admitted": 4}
    assert event["limits"] == {"max_dossiers": {"min": 10, "max": 10}}


def test_chain_challenge_supports_every_real_cell_status_including_not_launched() -> None:
    from appsec_review.review.models import CellStatus

    outcomes = {status.value: 0 for status in CellStatus}
    outcomes["not_launched"] = 2
    report = completion_metrics([{
        "job_id": "job_inference_security_review",
        "event_type": "INFERENCE_REVIEW_ATTACK_CHAIN_CHALLENGE_COMPLETED",
        "details": {"kind": "refuter", "challenges": 2, "outcomes": outcomes},
    }])
    assert report["measurement_gaps"] == []
    event = report["lanes"]["attack_chains"]["events"][
        "INFERENCE_REVIEW_ATTACK_CHAIN_CHALLENGE_COMPLETED"]
    assert event["outcomes"] == {f"outcomes.{status}": count for status, count in outcomes.items()}
