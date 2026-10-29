"""A deterministic synthetic run for the telemetry report tests.

``build_telemetry_run`` writes ``data/logs/pipeline.jsonl`` with fixed timestamps (the repository
ignores ``*.jsonl``, so it is generated, not committed) and, by default, the derived
``data/telemetry/summary.json``. The run has overlapping jobs, a retried job, model calls with
missing usage and a failure, tool invocations, a project image build, queue delay, finding
transitions, and hostile text wherever a target, tool or model could place it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_review.observability import write_run_metrics

from .fixture import HOSTILE, MODEL

RUN_ID = "2026-10-21-0099"
T0 = datetime(2026, 10, 21, 10, 0, 0, tzinfo=timezone.utc)
OUTCOMES = ("COMPLETED_WITH_GAPS", "FAILED", "RUNNING")
JOBS = ("job_target_analysis", "job_project_build", "job_inference_security_review",
        "job_final_report_publication")


class _Log:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.records: list[dict[str, Any]] = []

    def __call__(self, seconds: float, event_type: str, *, job: str = "-", attempt: str = "-",
                 step: str | None = None, task: str | None = None, **details: Any) -> None:
        sequence = len(self.records) + 1
        self.records.append({
            "schema": "appsec-review/telemetry-event/1", "sequence": sequence,
            "timestamp": (T0 + timedelta(seconds=seconds)).isoformat(),
            "level": "ERROR" if event_type.endswith("FAILED") else "INFO",
            "event_type": event_type, "run_id": self.run_id, "job_id": job, "attempt_id": attempt,
            "step_id": step, "task_id": task, "process": {"pid": 1, "name": "fixture"},
            "trigger": "manual", "orchestrator": "dagster",
            "message": event_type.replace("_", " ").lower(), "details": details,
            "event_id": hashlib.sha256(f"{self.run_id}:{sequence}:{event_type}".encode()).hexdigest(),
        })


def _model(log: _Log, start: float, seconds: float, job: str, attempt: str, invocation: str, *,
           role: str, model: str = MODEL, tokens: tuple[int, int, int] | None = (1200, 300, 0),
           status: str = "succeeded", error_class: str | None = None) -> None:
    log(start, "MODEL_CALL_STARTED", job=job, attempt=attempt, step="review", task=invocation,
        model_invocation_id=invocation, provider="anthropic", model=model, role=role)
    usage = (dict(zip(("input_tokens", "output_tokens", "cache_tokens"), tokens)) if tokens
             else {"input_tokens": None, "output_tokens": None, "cache_tokens": None})
    log(start + seconds, "MODEL_CALL_COMPLETED", job=job, attempt=attempt, step="review", task=invocation,
        model_invocation_id=invocation, provider="anthropic", model=model, role=role,
        duration_ms=int(seconds * 1000), retry_count=0, terminal_status=status,
        error_class=error_class, **usage)


def _tool(log: _Log, start: float, seconds: float, job: str, attempt: str, invocation: str, tool: str,
          status: str = "SUCCEEDED") -> None:
    log(start, "TOOL_INVOCATION_STARTED", job=job, attempt=attempt, step="scan", task=invocation,
        tool_invocation_id=invocation, tool_id=tool)
    log(start + seconds, "TOOL_INVOCATION_COMPLETED", job=job, attempt=attempt, step="scan", task=invocation,
        tool_invocation_id=invocation, tool_id=tool, duration_ms=int(seconds * 1000),
        disposition=status, result_count=3)  # producers record a tool's outcome as its disposition


def _job(log: _Log, start: float, end: float, job: str, attempt: str, terminal: str | None,
         queue_delay_ms: int) -> None:
    log(start - 0.5, "DAGSTER_QUEUE_DELAY", job=job, attempt=attempt, queue_delay_ms=queue_delay_ms)
    log(start, "JOB_STARTED", job=job, attempt=attempt)
    log(start + 0.1, "TASK_STARTED", job=job, attempt=attempt, step="main", task="main.run")
    if terminal is not None:
        log(end - 0.1, "TASK_SUCCEEDED" if terminal != "JOB_FAILED" else "TASK_FAILED", job=job,
            attempt=attempt, step="main", task="main.run", duration_ms=int((end - start - 0.2) * 1000))
        log(end, terminal, job=job, attempt=attempt, duration_ms=int((end - start) * 1000))


def build_telemetry_run(parent: Path, *, run_id: str = RUN_ID, outcome: str = "COMPLETED_WITH_GAPS",
                        write_summary: bool = True) -> Path:
    """Write the synthetic run under ``parent/run_id`` and return the run directory."""
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {OUTCOMES}")
    log = _Log(run_id)
    target, build, review, publish = JOBS
    log(0, "RUN_STARTED", trigger_source="fixture")
    log(0.2, "GRAPH_STARTED")

    _job(log, 1, 61, target, "a1", "JOB_SUCCEEDED", 400)
    _model(log, 5, 4.2, target, "a1", "m-plan-1", role="planner")

    _job(log, 62, 302, build, "a1", "JOB_COMPLETED_WITH_GAPS", 1200)
    log(70, "PROJECT_IMAGE_BUILD_STARTED", job=build, attempt="a1", build_unit_id="unit-cpp", family="cpp")
    log(190, "PROJECT_IMAGE_BUILT", job=build, attempt="a1", build_unit_id="unit-cpp", family="cpp",
        duration_ms=120000)
    _tool(log, 200, 45, build, "a1", "t-cppcheck", "cppcheck")
    _tool(log, 250, 30, build, "a1", "t-hostile", HOSTILE, status="FAILED")

    review_end = 900 if outcome != "RUNNING" else None
    _job(log, 64, review_end or 0, review, "a1", None if outcome == "RUNNING" else "JOB_SUCCEEDED", 900)
    _model(log, 80, 12.5, review, "a1", "m-red-1", role="red")
    _model(log, 95, 8.0, review, "a1", "m-blue-1", role="blue", tokens=(5400, 900, 4096),
           status="ACCEPTED")
    _model(log, 110, 20.0, review, "a1", "m-verify-1", role="verifier", tokens=None)
    _model(log, 140, 3.0, review, "a1", "m-red-2", role="red", model=HOSTILE, tokens=(10, 0, 0),
           status="failed", error_class=HOSTILE)
    log(150, "FINDING_TRANSITION", job=review, attempt="a1", finding_package_id="pkg-1",
        prior_state="NONE", new_state="CANDIDATE")
    log(400, "FINDING_TRANSITION", job=review, attempt="a1", finding_package_id="pkg-1",
        prior_state="CANDIDATE", new_state="CONFIRMED")

    if outcome == "RUNNING":
        _tool(log, 420, 15, review, "a1", "t-semgrep", "semgrep")
    elif outcome == "FAILED":
        _job(log, 905, 960, publish, "a1", "JOB_FAILED", 300)
        log(961, "GRAPH_FAILED", error_type="RuntimeError")
        log(962, "RUN_COMPLETED", completion_status="FAILURE")
    else:
        _job(log, 905, 960, publish, "a1", "JOB_FAILED", 300)
        _job(log, 970, 1010, publish, "a2", "JOB_SUCCEEDED", 250)
        log(1011, "GRAPH_COMPLETED_WITH_GAPS", completion_status="COMPLETED_WITH_GAPS", duration_ms=1010800)
        log(1012, "RUN_COMPLETED", completion_status="COMPLETED_WITH_GAPS")

    run_dir = Path(parent) / run_id
    path = run_dir / "data" / "logs" / "pipeline.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        for record in log.records))
    if write_summary:
        write_run_metrics(run_dir)
    return run_dir
