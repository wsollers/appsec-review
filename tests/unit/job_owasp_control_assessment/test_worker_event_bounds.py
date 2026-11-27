"""Regression tests for OWASP_WORKER_COMPLETED pipeline record bounds (MAX_RECORD_BYTES = 64 KiB)."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_owasp_control_assessment import job
from appsec_review.observability.events import EventLog, MAX_RECORD_BYTES, PipelineLog
from appsec_review.runtime import JobContext, Unit, UnitExecutor
from tests.test_owasp_assessment_job import _base_app_config


ROOT = Path(__file__).resolve().parents[3]
BATCH_ID = "batch-d416435b2bc204a3cad6"
EVENT_BASE = {
    "run_id": "2026-11-27-0001",
    "job_id": "job_owasp_control_assessment",
    "attempt_id": "attempt_0001",
}


def _verbose_cell_03_batch_result(*, attempt_count: int = 96, row_count: int = 64, citation_count: int = 120) -> dict:
    attempts = [
        {
            "schema_version": "1.0",
            "run_id": "2026-11-27-0001",
            "job_id": "job_owasp_control_assessment",
            "attempt_id": "attempt_0001",
            "unit_id": "validation.cell_03",
            "batch_id": BATCH_ID,
            "role": "control_assessor",
            "part": (idx // 2) + 1,
            "row_ids": [f"row-{(idx * 2 + offset) % row_count:04d}" for offset in range(4)],
            "turn": (idx % 2) + 1,
            "attempt": 1,
            "retry_number": 0,
            "dispatched": True,
            "provider": "openai_compatible",
            "model": "gpt-5.4",
            "reasoning_effort": "medium",
            "timeout_seconds": 180,
            "max_input_tokens": 32000,
            "max_output_tokens": 8000,
            "estimated_input_tokens": 6400 + idx * 17,
            "input_tokens": 6520 + idx * 17,
            "output_tokens": 940 + (idx % 19) * 11,
            "cache_tokens": 2048,
            "input_estimate_delta": 120,
            "duration_ms": 4250 + idx * 31,
            "outcome": "succeeded",
            "error_class": None,
            "error": None if idx % 11 else "transient retry note: " + ("detail-" * 20),
            "guidance": {
                "role": "control_assessor",
                "bundle_sha256": f"{idx + 1:064x}",
                "prompt_id": "owasp-control-assessor-v2",
            },
        }
        for idx in range(attempt_count)
    ]
    retrieval_events = [
        {
            "query_number": idx + 1,
            "source_identity": f"asr:source_file:{idx + 100:064x}",
            "locator": {"kind": "source", "lines": [1 + idx, 40 + idx]},
            "status": "resolved",
            "excerpt_preview": ("void handle_packet(const uint8_t* buf, size_t len) { /* check */ }\n" * 8),
        }
        for idx in range(48)
    ]
    citations = [
        {"source_identity": f"asr:source_file:{idx:064x}", "start_line": 1, "end_line": 12}
        for idx in range(citation_count)
    ]
    statuses = ("satisfied", "not_satisfied", "cannot_verify")
    rows = [
        {
            "row_id": f"row-{idx:04d}",
            "package_id": f"package-{idx:04d}",
            "status": statuses[idx % len(statuses)],
            "execution_completion": "completed",
            "coverage_completeness": "complete" if idx % 3 == 0 else "partial",
            "evidence_used": citations[idx % 10 : idx % 10 + 15] + ([citations[idx]] if idx < citation_count else []),
            "observations": ([{"id": f"obs-{idx}"}] if idx % 5 == 0 else []),
            "gaps": ([f"gap-{idx}"] if idx % 7 == 0 else []),
        }
        for idx in range(row_count)
    ]
    rows[0]["evidence_used"] = citations
    metrics = {
        "estimated_input_tokens": sum(item["estimated_input_tokens"] for item in attempts),
        "input_tokens": sum(item["input_tokens"] for item in attempts),
        "output_tokens": sum(item["output_tokens"] for item in attempts),
        "cache_tokens": sum(item["cache_tokens"] for item in attempts),
        "input_estimate_delta": sum(item["input_estimate_delta"] for item in attempts),
        "model_calls": len(attempts),
        "model_requested_retrievals": len(retrieval_events),
        "retrieval": {
            "attempts": len(retrieval_events),
            "denials": 0,
            "truncations": 3,
            "missing": 1,
            "events": retrieval_events,
        },
        "model_requested_retrieval_log": [dict(item) for item in retrieval_events],
        "attempts": attempts,
        "cost_usd": 1.875,
        "reused_model_results": 0,
        "input_tokens_reported": len(attempts),
        "output_tokens_reported": len(attempts),
        "known_input_tokens_subtotal": sum(item["input_tokens"] for item in attempts),
        "known_output_tokens_subtotal": sum(item["output_tokens"] for item in attempts),
        "unknown_usage_attempts": 0,
    }
    return {
        "batch_id": BATCH_ID,
        "fingerprint": "fp-cell-03",
        "terminal_state": "completed",
        "results": rows,
        "worker": {"status": "succeeded", "attempts": deepcopy(attempts)},
        "metrics": metrics,
    }


def test_unbounded_worker_metrics_exceed_max_record_bytes_pre_fix_repro(tmp_path):
    """Verify MAX_RECORD_BYTES remains 64 KiB and legacy **result['metrics'] overflows EventLog/PipelineLog."""
    assert MAX_RECORD_BYTES == 65_536
    result = _verbose_cell_03_batch_result()
    assert len(json.dumps(result["metrics"]).encode("utf-8")) > MAX_RECORD_BYTES

    evidence_used = sorted({
        citation["source_identity"]
        for item in result["results"]
        for citation in item.get("evidence_used", ())
    })
    legacy_unbounded_details = {
        "batch_id": BATCH_ID,
        "terminal_status": result["terminal_state"],
        "evidence_used": evidence_used[:100],
        "proposed_observation_count": sum(len(item.get("observations", ())) for item in result["results"]),
        "gap_count": sum(len(item.get("gaps", ())) for item in result["results"]),
        "dispositions": [item["status"] for item in result["results"]],
        **result["metrics"],
    }
    run_root = tmp_path / "repro_run"
    event_log = EventLog(
        run_root / "attempt" / "logs" / "events.jsonl",
        pipeline=PipelineLog(run_root),
        base=EVENT_BASE,
    )
    with pytest.raises(ValueError, match="critical pipeline event exceeds the record bound"):
        event_log.write(
            "OWASP_WORKER_COMPLETED",
            unit_id="validation.cell_03",
            **legacy_unbounded_details,
        )


def test_cell_03_bounds_worker_completed_event_and_preserves_full_artifact_metrics(tmp_path, monkeypatch):
    """validation.cell_03 succeeds on >64 KiB metrics/results while keeping full metrics in result.json."""
    verbose_result = _verbose_cell_03_batch_result()
    expected_metrics = deepcopy(verbose_result["metrics"])
    assert len(json.dumps(expected_metrics).encode("utf-8")) > 2 * MAX_RECORD_BYTES

    app_cfg = _base_app_config()
    base_job_cfg = app_cfg.job("job_owasp_control_assessment")
    settings = deepcopy(dict(base_job_cfg.settings))
    settings["mode"] = "assessment"
    settings["model"] = {**dict(settings["model"]), "enabled": True}
    job_cfg = replace(base_job_cfg, settings=settings)

    batches = [
        {"batch_id": "batch-cell-01", "fingerprint": "fp-1", "assignment": {"persona": "api_web"}},
        {"batch_id": "batch-cell-02", "fingerprint": "fp-2", "assignment": {"persona": "api_web"}},
        {"batch_id": BATCH_ID, "fingerprint": "fp-3", "assignment": {"persona": "api_web"}},
    ]
    packages_by_batch = {
        item["batch_id"]: [
            {
                "row_id": "row-0000",
                "package_id": "package-0000",
                "proof_obligations": [{"obligation_id": "obl-1", "subject_id": "sub-1", "supported": True}],
            }
        ]
        for item in batches
    }

    monkeypatch.setattr(job, "_resolver", lambda _unit: object())
    monkeypatch.setattr(job, "run_batch", lambda **_kwargs: deepcopy(verbose_result))
    monkeypatch.setattr(
        job,
        "assess_batch",
        lambda batch, packages, *, worker=None, **_kw: worker({"batch": batch, "packages": packages}),
    )

    real_units = {unit.unit_id: unit for unit in job.build_job().units}
    cell_03_unit = real_units["validation.cell_03"]
    executor = UnitExecutor((
        Unit("batching.partition_work", lambda _u: {"work": {"batches": batches}, "terminal_status": "SUCCEEDED"}),
        Unit(
            "batching.build_packages",
            lambda _u: {"packages": packages_by_batch, "terminal_status": "SUCCEEDED"},
            dependencies=("batching.partition_work",),
        ),
        cell_03_unit,
    ))

    run_root = tmp_path / "run"
    attempt_root = run_root / "data" / "jobs" / "job_owasp_control_assessment" / "attempts" / "attempt_0001"
    pipeline_log = PipelineLog(run_root)
    event_log = EventLog(
        attempt_root / "logs" / "events.jsonl",
        pipeline=pipeline_log,
        base=EVENT_BASE,
    )
    ctx = JobContext(
        run_id="2026-11-27-0001",
        attempt_id="attempt_0001",
        trigger="smoke-test",
        repository_root=ROOT,
        run_root=run_root,
        attempt_root=attempt_root,
        metadata_root=attempt_root / "metadata",
        orchestration={"backend": "unit"},
        config=job_cfg,
        events=event_log,
    )

    execution = executor.execute(ctx)
    assert execution['failed_units'] == []
    outputs = execution['outputs']
    receipts = execution['units']
    assert receipts["validation.cell_03"]["status"] == "SUCCEEDED"
    assert not (attempt_root / "steps" / "validation" / "tasks" / "cell_03" / "traceback.txt").exists()

    pipeline_path = run_root / "data" / "logs" / "pipeline.jsonl"
    raw_lines = pipeline_path.read_text(encoding="utf-8").splitlines()
    assert raw_lines
    worker_completed_records = []
    for line in raw_lines:
        raw_bytes = len(line.encode("utf-8"))
        assert raw_bytes <= MAX_RECORD_BYTES
        parsed = json.loads(line)
        if parsed["event_type"] == "OWASP_WORKER_COMPLETED":
            assert raw_bytes < 16 * 1024
            worker_completed_records.append(parsed)

    assert len(worker_completed_records) == 1
    record = worker_completed_records[0]
    assert record["task_id"] == "cell_03"
    details = record["details"]
    assert details["batch_id"] == BATCH_ID
    assert details["terminal_status"] == "completed"
    assert details["row_count"] == 64
    assert details["attempt_count"] == 96
    assert "attempts" not in details
    assert "model_requested_retrieval_log" not in details
    assert details["model_requested_retrieval_log_count"] == 48
    assert details["model_calls"] == 96
    assert details["input_tokens"] == expected_metrics["input_tokens"]
    assert details["output_tokens"] == expected_metrics["output_tokens"]
    assert details["cache_tokens"] == expected_metrics["cache_tokens"]
    assert details["model_requested_retrievals"] == 48
    assert details["reused_model_results"] == 0
    assert details["cost_usd"] == pytest.approx(1.875)
    assert details["retrieval"] == {
        "attempts": 48,
        "denials": 0,
        "truncations": 3,
        "missing": 1,
        "events_count": 48,
    }
    assert details["evidence_used_count"] == 120
    assert len(details["evidence_used"]) == 25
    assert sum(details["disposition_counts"].values()) == 64
    assert len(details["dispositions"]) == 64
    assert details["proposed_observation_count"] == sum(len(r["observations"]) for r in verbose_result["results"])
    assert details["gap_count"] == sum(len(r["gaps"]) for r in verbose_result["results"])

    # Also verify direct EventLog.write(..., pipeline=PipelineLog) accepts the bounded details cleanly.
    event_log.write("OWASP_WORKER_COMPLETED", unit_id="validation.cell_03", **details)

    # Full rich metrics (including all 96 verbose attempts and retrieval events) remain intact in cell output and result.json.
    assert outputs["validation.cell_03"]["batch_results"][0]["metrics"] == expected_metrics
    persisted_result_path = attempt_root / "steps" / "validation" / "tasks" / "cell_03" / "result.json"
    persisted_cell_output = json.loads(persisted_result_path.read_text(encoding="utf-8"))
    assert persisted_cell_output["batch_results"][0]["metrics"] == expected_metrics
    assert len(persisted_cell_output["batch_results"][0]["metrics"]["attempts"]) == 96
    assert len(persisted_cell_output["batch_results"][0]["metrics"]["retrieval"]["events"]) == 48


def test_worker_completed_details_bounds_sequence_retrieval_and_large_citations(tmp_path):
    """Sequence-valued retrieval metrics, >200 rows, and long source_identity strings stay well below 64 KiB."""
    long_citations = [
        {"source_identity": f"asr:source_file:{idx:04d}:" + ("path_segment_" * 40)}
        for idx in range(150)
    ]
    rows = [
        {
            "row_id": f"row-{idx:04d}",
            "status": "not_satisfied" if idx % 2 == 0 else "cannot_verify",
            "evidence_used": [long_citations[idx % len(long_citations)]],
            "observations": [{"id": f"obs-{idx}"}],
            "gaps": [],
        }
        for idx in range(250)
    ]
    rows[0]["evidence_used"] = long_citations
    result = {
        "terminal_state": "completed",
        "results": rows,
        "metrics": {
            "model_calls": 140,
            "attempts": [{"attempt": idx, "blob": "x" * 900} for idx in range(140)],
            "retrieval": [{"query": idx, "excerpt": "y" * 1200} for idx in range(150)],
        },
    }

    details = job._worker_completed_details("batch-large", result)
    assert details["row_count"] == 250
    assert details["attempt_count"] == 140
    assert details["retrieval_count"] == 150
    assert "attempts" not in details
    assert "retrieval" not in details
    assert details["evidence_used_count"] == 150
    assert len(details["evidence_used"]) == 25
    assert all(len(ident) <= 160 for ident in details["evidence_used"])
    assert details["disposition_counts"] == {"cannot_verify": 125, "not_satisfied": 125}
    assert len(details["dispositions"]) == 64

    run_root = tmp_path / "seq_run"
    event_log = EventLog(
        run_root / "attempt" / "events.jsonl",
        pipeline=PipelineLog(run_root),
        base=EVENT_BASE,
    )
    event_log.write("OWASP_WORKER_COMPLETED", unit_id="validation.cell_03", **details)
    raw_line = (run_root / "data" / "logs" / "pipeline.jsonl").read_text(encoding="utf-8").strip()
    assert len(raw_line.encode("utf-8")) < 16 * 1024
