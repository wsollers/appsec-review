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
    assert event["usage_unavailable_count"] == 1
    assert event["duration_ms"]["p95"] is None
