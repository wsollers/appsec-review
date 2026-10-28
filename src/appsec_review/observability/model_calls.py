"""Correlated transport telemetry without retaining model-facing text."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import time
from typing import Any
import uuid

from appsec_review.inference.request import Infer, ModelResult, ReviewModelRequest
from appsec_review.inference.recording import MODE_ENVIRONMENT
from appsec_review.observability.events import PipelineLog
from appsec_review.observability.telemetry import emit_model_event
from appsec_review.storage import canonical_json


def call_model(infer: Infer, request: ReviewModelRequest, *, timeout_seconds: int,
               run_root: Path, run_id: str, job_id: str, attempt_id: str,
               step_id: str, task_id: str, retry_count: int = 0,
               **correlation: Any) -> ModelResult:
    """Measure one actual dispatch; callers separately adjudicate output validity and reuse."""
    log, invocation = PipelineLog(run_root), uuid.uuid4().hex
    replay = os.environ.get(MODE_ENVIRONMENT) == "replay"
    fields = {
        "run_id": run_id, "invocation_id": invocation,
        "provider": request.provider, "model": request.model, "reasoning_level": request.reasoning,
        "guidance_bundle_sha256": request.guidance_bundle_sha256,
        "request_sha256": hashlib.sha256(canonical_json(asdict(request))).hexdigest(),
        "job_id": job_id, "attempt_id": attempt_id, "step_id": step_id, "task_id": task_id,
        "role": request.role, "persona": request.persona, "cell_id": request.cell_id,
        "execution_mode": "replay" if replay else "inference",
        **correlation,
    }
    emit_model_event(log, event_type="MODEL_CALL_STARTED", **fields)
    started = time.monotonic()
    try:
        result = infer(request, timeout_seconds=timeout_seconds)
    except BaseException as exc:
        status = ("TIMED_OUT" if isinstance(exc, TimeoutError) else
                  "CANCELLED" if not isinstance(exc, Exception) else "FAILED")
        emit_model_event(log, event_type="MODEL_CALL_COMPLETED", **fields,
                         terminal_status=status, retry_count=retry_count,
                         duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                         error_class=type(exc).__name__)
        raise
    usage = {name: getattr(result, name) for name in ("input_tokens", "output_tokens", "cache_tokens")}
    invalid = any(value is not None and (type(value) is not int or value < 0)
                  for value in usage.values())
    usage = {name: value if type(value) is int and value >= 0 else None for name, value in usage.items()}
    if replay:
        usage = dict.fromkeys(usage)
    emit_model_event(log, event_type="MODEL_CALL_COMPLETED", **fields,
                     terminal_status="SUCCEEDED", retry_count=retry_count,
                     duration_ms=max(0, int((time.monotonic() - started) * 1000)),
                     served_provider=result.served_provider, served_model=result.served_model,
                     usage_unavailable_reason=("recorded_replay" if replay else
                                               "invalid_provider_usage" if invalid else None), **usage)
    return result
