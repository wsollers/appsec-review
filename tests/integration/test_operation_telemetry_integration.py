"""Operation telemetry gaps end to end: progress heartbeats, phases and lost spans.

Manual integration validation; excluded from implicit collection and run only on request.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from appsec_review.config import load_config
from appsec_review.observability import PipelineLog, aggregate_run_metrics, spans, write_run_metrics
from appsec_review.observability.telemetry import RUN_METRICS_SCHEMA

LINUX = sys.platform.startswith("linux")
REPOSITORY = Path(__file__).resolve().parents[2]
PROGRESS_SECONDS = 0.02
SAMPLE_SECONDS = 0.005


@pytest.fixture(autouse=True)
def _restore_sampling():
    yield
    deadline = time.monotonic() + 5
    while spans._SAMPLER.entries and time.monotonic() < deadline:
        time.sleep(0.01)
    spans.configure_operation_sampling()


def _short_interval_config(config_path: Path):
    text = config_path.read_text(encoding="utf-8")
    assert "[runtime]\n" in text
    config_path.write_text(text.replace(
        "[runtime]\n",
        f"[runtime]\noperation_progress_interval_seconds = {PROGRESS_SECONDS}\n"
        f"operation_sample_interval_seconds = {SAMPLE_SECONDS}\n", 1), encoding="utf-8")
    return load_config(config_path)


def test_artifact_indexing_run_summary_exposes_progress_phases_and_hotspots(tmp_path: Path) -> None:
    from appsec_review.jobs.job_artifact_indexing import build_job
    from appsec_review.runtime import GraphRunner
    from tests.test_artifact_indexing import RUN_ID, _seed

    _config, target, snapshot, run_root, receipts, *_ = _seed(tmp_path)
    assert sum(len(receipt["artifacts"]) for receipt in receipts) > 1
    config = _short_interval_config(tmp_path / "appsec-review.toml")
    assert config.runtime.operation_progress_interval_seconds == PROGRESS_SECONDS

    GraphRunner(config, [build_job()]).run(target_root=target, source_fingerprint=snapshot, run_id=RUN_ID)

    records, torn = PipelineLog(run_root).read()
    assert not torn
    progress = [record for record in records if record["event_type"] == "OPERATION_PROGRESS"]
    assert progress, "a multi-second indexing job must emit heartbeats at a 20 ms interval"
    for record in progress:
        details = record["details"]
        assert not {"duration_ms", "terminal_status", "disposition"} & set(details)
        assert {"span_id", "progress_sequence", "elapsed_ms", "resources", "work", "expected",
                "phases", "thread_states"} <= set(details)
        assert details["progress_interval_ms"] == PROGRESS_SECONDS * 1000
    completed = [record["details"] for record in records if record["event_type"] == "OPERATION_COMPLETED"]
    assert sum(details["progress_count"] or 0 for details in completed) == len(progress)
    assert all(details["progress_write_failures"] == 0 for details in completed)
    relationships = [details for details in completed
                     if details.get("operation_id") == "unit.execute"
                     and details.get("unit_id") == "index.relationships"]
    assert relationships and relationships[0]["work"]["shards_built"] >= 1
    assert "index.sqlite_write" in relationships[0]["phases"]
    if LINUX:
        assert relationships[0]["resources"]["rusage_scope"] == "thread"
        assert relationships[0]["resources"]["write_syscalls"] is not None

    write_run_metrics(run_root)
    summary = json.loads((run_root / "data" / "telemetry" / "summary.json").read_text(encoding="utf-8"))
    assert summary["schema"] == RUN_METRICS_SCHEMA == "appsec-review/run-metrics/6"
    assert summary["operation_progress"] == []                  # every span completed
    hotspots = summary["operation_hotspots"]
    assert 1 <= len(hotspots) <= 20
    assert [row["duration_ms"] for row in hotspots] == sorted(
        (row["duration_ms"] for row in hotspots), reverse=True)
    assert any(row["dominant_phase"] for row in hotspots)
    assert any(span["phases"] for span in summary["resource_spans"])
    assert any((span["expected"] or {}).get("artifacts_processed") for span in summary["resource_spans"])
    assert sum(span["progress_count"] or 0 for span in summary["resource_spans"]) == len(progress)


_WORKER = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    from appsec_review.observability import spans
    from appsec_review.observability.events import EventLog, PipelineLog

    run_root = Path(sys.argv[1])
    spans.configure_operation_sampling(progress_interval_seconds=0.05, sample_interval_seconds=0.01)
    attempt = run_root / "data" / "jobs" / "job_artifact_indexing" / "attempts" / "attempt_0001"
    events = EventLog(attempt / "events.jsonl", PipelineLog(run_root), {
        "run_id": run_root.name, "job_id": "job_artifact_indexing", "attempt_id": "attempt_0001"})
    events.write("JOB_STARTED")
    with spans.operation_span(events, "unit.execute", unit_id="index.relationships"):
        spans.expect_work("artifacts_processed", 1000000)
        while True:
            spans.count_work("artifacts_processed")
            with spans.operation_phase("index.sqlite_write"):
                time.sleep(0.005)
""")


def _progress(run_root: Path) -> list[dict]:
    records, _torn = PipelineLog(run_root).read()
    return [record for record in records if record["event_type"] == "OPERATION_PROGRESS"]


@pytest.mark.skipif(not LINUX, reason="SIGKILL and /proc thread sampling are Linux semantics")
def test_sigkilled_worker_leaves_its_last_heartbeat_and_is_reported_lost(tmp_path: Path) -> None:
    run_root = tmp_path / "runs" / "2026-10-30-0001"
    run_root.mkdir(parents=True)
    environment = {**os.environ, "PYTHONPATH": os.pathsep.join(
        filter(None, (str(REPOSITORY / "src"), str(REPOSITORY), os.environ.get("PYTHONPATH"))))}
    worker = subprocess.Popen([sys.executable, "-c", _WORKER, str(run_root)], env=environment)
    try:
        deadline = time.monotonic() + 30
        while len(_progress(run_root)) < 3:
            assert worker.poll() is None, "worker exited before it was killed"
            assert time.monotonic() < deadline, "worker emitted no heartbeats"
            time.sleep(0.02)
    finally:
        worker.send_signal(signal.SIGKILL)
        worker.wait(timeout=30)
    assert worker.returncode == -signal.SIGKILL

    records, torn = PipelineLog(run_root).read()
    assert not torn                                              # each heartbeat was a whole, fsynced line
    assert not [record for record in records if record["event_type"] == "OPERATION_COMPLETED"]
    heartbeats = _progress(run_root)
    last = heartbeats[-1]["details"]
    assert [record["details"]["progress_sequence"] for record in heartbeats] == list(
        range(1, len(heartbeats) + 1))
    assert last["work"]["artifacts_processed"] >= 1
    assert last["expected"] == {"artifacts_processed": 1000000}
    assert last["phases"]["index.sqlite_write"]["count"] >= 1
    assert last["thread_states"]["samples"] >= 1

    # Silence past three progress intervals relative to the newest run event marks it lost.
    time.sleep(0.5)
    PipelineLog(run_root).write("TASK_STARTED", run_id=run_root.name, job_id="job_other",
                                attempt_id="attempt_0001", step_id="other", task_id="other",
                                level="INFO", trigger="application", orchestrator="application",
                                details={})
    row, = aggregate_run_metrics(run_root)["operation_progress"]
    assert row["state"] == "lost" and row["span_id"] == last["span_id"]
    assert row["progress_sequence"] == last["progress_sequence"]
    assert row["work"] == last["work"]
    assert row["completion_ratio"]["artifacts_processed"] < 1

    # The supervisor recording the failed attempt also closes it.
    PipelineLog(run_root).write("JOB_FAILED", run_id=run_root.name, job_id="job_artifact_indexing",
                                attempt_id="attempt_0001", step_id=None, task_id=None, level="ERROR",
                                trigger="application", orchestrator="application", details={})
    summary = write_run_metrics(run_root)
    assert summary["operation_progress"][0]["state"] == "lost"
    assert not summary["operation_hotspots"]                    # a lost span has no duration
