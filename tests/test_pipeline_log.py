from __future__ import annotations

import json
import os
from multiprocessing import get_context
from pathlib import Path

import hashlib

import pytest

from appsec_review.observability import (
    FindingLifecycle, PipelineLog, aggregate_run_metrics, emit_model_event, validate_event,
)
from appsec_review.cli import main


def _writer(root: str, worker: int, count: int) -> None:
    log = PipelineLog(Path(root))
    for index in range(count):
        log.write("STRESS", run_id="run", job_id=f"job_{worker}", attempt_id="attempt_0001",
                  details={"worker": worker, "index": index, "token": "must-redact"})


def test_process_safe_log_has_contiguous_order_and_redaction(tmp_path: Path) -> None:
    context = get_context("spawn")
    processes = [context.Process(target=_writer, args=(str(tmp_path), worker, 15)) for worker in range(4)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    records, torn = PipelineLog(tmp_path).read()
    assert not torn
    assert [item["sequence"] for item in records] == list(range(1, 61))
    assert all(item["details"]["token"] == "<redacted>" for item in records)


def test_torn_final_record_is_ignored_and_recovered(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    log.write("FIRST", run_id="run")
    with log.path.open("ab") as stream:
        stream.write(b'{"sequence":2')
    records, torn = log.read()
    assert len(records) == 1 and torn
    log.write("SECOND", run_id="run")
    records, torn = log.read()
    assert not torn
    assert [record["sequence"] for record in records] == [1, 2]
    assert all(json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines())


def test_writer_failure_releases_kernel_lock(tmp_path: Path, monkeypatch) -> None:
    log = PipelineLog(tmp_path)
    original = os.fsync
    calls = 0
    def fail_once(descriptor):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected writer failure")
        return original(descriptor)
    monkeypatch.setattr(os, "fsync", fail_once)
    try:
        try:
            log.write("FAILED_WRITE", run_id="run")
        except OSError:
            pass
        log.write("RECOVERED_WRITE", run_id="run")
    finally:
        monkeypatch.setattr(os, "fsync", original)
    records, torn = log.read()
    assert not torn
    assert records[-1]["event_type"] == "RECOVERED_WRITE"


def test_cli_filters_global_log_without_external_tools(tmp_path: Path, capsys) -> None:
    source = Path(__file__).parents[1] / "appsec-review.toml"
    config = tmp_path / "appsec-review.toml"
    config.write_bytes(source.read_bytes())
    run_root = tmp_path / "runs/2026-10-08-0001"
    log = PipelineLog(run_root)
    log.write("ONE", run_id=run_root.name, job_id="job_review_intake", attempt_id="attempt_0001")
    log.write("TWO", run_id=run_root.name, job_id="job_target_catalog", attempt_id="attempt_0001")
    assert main(["--config", str(config), "logs", "--run-id", run_root.name,
                 "--job", "job_target_catalog", "--raw"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event_type"] == "TWO"


def test_canonical_event_model_tool_and_gap_metrics_are_deterministic(tmp_path: Path) -> None:
    log = PipelineLog(tmp_path)
    log.write("TASK_STARTED", run_id="run", job_id="job", attempt_id="attempt_0001",
              details={"dagster_run_id": "dagster", "dagster_node": "node", "tool_id": "tool-x"})
    emit_model_event(log, event_type="MODEL_CALL_STARTED", run_id="run", invocation_id="model-1",
                     provider="provider", model="model", reasoning_level="high",
                     guidance_bundle_sha256="a" * 64, request_sha256="b" * 64)
    emit_model_event(log, event_type="MODEL_CALL_COMPLETED", run_id="run", invocation_id="model-1",
                     provider="provider", model="model", reasoning_level="high",
                     guidance_bundle_sha256="a" * 64, request_sha256="b" * 64,
                     terminal_status="SUCCEEDED", duration_ms=12, input_tokens=10,
                     output_tokens=5, cache_tokens=2)
    log.write("TASK_COMPLETED_WITH_GAPS", run_id="run", job_id="job", attempt_id="attempt_0001",
              details={"completion_status": "COMPLETED_WITH_GAPS", "duration_ms": 20,
                       "prompt": "must not appear", "raw_model_output": "must not appear"})
    records, _ = log.read()
    assert all(validate_event(record) is None for record in records)
    assert "must not appear" not in log.path.read_text(encoding="utf-8")
    first = aggregate_run_metrics(tmp_path)
    second = aggregate_run_metrics(tmp_path)
    assert first == second
    assert first["model_tokens"] == {"cache_tokens": 2, "input_tokens": 10, "output_tokens": 5}
    assert first["dispositions"]["COMPLETED_WITH_GAPS"] == 1


def test_finding_transitions_are_valid_idempotent_and_distinct_from_observations(tmp_path: Path) -> None:
    lifecycle = FindingLifecycle(tmp_path)
    reason = hashlib.sha256(b"bounded reason").hexdigest()
    candidate = lifecycle.transition(run_id="run", finding_package_id="finding-1",
                                     new_state="CANDIDATE", evidence_identities=("observation-1",),
                                     actor_class="deterministic", reason_hash=reason)
    duplicate = lifecycle.transition(run_id="run", finding_package_id="finding-1",
                                     new_state="CANDIDATE", evidence_identities=("observation-1",),
                                     actor_class="deterministic", reason_hash=reason)
    assert duplicate["event_id"] == candidate["event_id"]
    lifecycle.transition(run_id="run", finding_package_id="finding-1", new_state="CONFIRMED",
                         evidence_identities=("observation-1",), actor_class="human", reason_hash=reason)
    with pytest.raises(ValueError, match="invalid finding transition"):
        lifecycle.transition(run_id="run", finding_package_id="finding-1", new_state="REFUTED",
                             evidence_identities=("observation-1",), actor_class="human", reason_hash=reason)
    metrics = aggregate_run_metrics(tmp_path)
    assert metrics["finding_states"] == {"CANDIDATE": 1, "CONFIRMED": 1}
