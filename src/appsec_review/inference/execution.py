"""Small shared mechanics for bounded model conversations.

Adapters own prompts, retrieval, final validation and repair policy. An execution owns only
dispatch bounds, cancellation checkpoints, retry scheduling, usage and hash-only receipts.
Infer implementations must honor their timeout and finish cancellation before returning.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import time
from typing import Any
from uuid import uuid4

from appsec_review.runtime import execution_safety as safety
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import current, immutable_bytes

from .errors import (
    ExecutionContractError, ExecutionLimit, FailureCategory, ModelOutputError, ProviderError,
    failure_category,
)
from .request import Infer, ModelRequest, ModelResult, ReviewModelRequest
from .usage import Usage

EXECUTION_VERSION = "bounded-model-execution/1"
RECEIPT_SCHEMA = "appsec-review/model-execution-receipt/1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:/@+-]{1,256}\Z")


def _identity(value: str) -> str:
    return value if _IDENTIFIER.fullmatch(value) else "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _json(value: Any, *, response: bool = False) -> bytes:
    try:
        json.dumps(value, allow_nan=False)
        return canonical_json(value)
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        if response:
            raise ModelOutputError("model reply must be finite JSON") from exc
        raise ExecutionContractError("model request must be finite JSON") from exc


@dataclass(frozen=True, slots=True)
class CallContext:
    run_root: Path
    run_id: str
    job_id: str
    attempt_id: str
    step_id: str = "-"
    task_id: str = "-"

    @classmethod
    def current(cls) -> CallContext | None:
        owner = current()
        if owner is None:
            return None
        return cls(owner.run_root, str(owner.actor["run_id"]), str(owner.actor["job_id"]),
                   str(owner.actor["attempt_id"]))


class Deadline:
    def __init__(self, seconds: float, *, clock: Callable[[], float] = time.monotonic,
                 check_cancelled: Callable[[], None] = safety.check_running) -> None:
        if isinstance(seconds, bool) or not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("execution deadline must be finite and positive")
        self.clock, self.check_cancelled = clock, check_cancelled
        self.started = clock()
        self.expires = self.started + seconds

    def remaining(self) -> float:
        self.check_cancelled()
        remaining = self.expires - self.clock()
        if remaining <= 0:
            raise ExecutionLimit("execution_deadline")
        return remaining

    def timeout(self, requested: int) -> int:
        if type(requested) is not int or requested <= 0:
            raise ValueError("model timeout must be a positive integer")
        return min(requested, max(1, math.ceil(self.remaining())))

    def wait(self, seconds: float, *, sleep: Callable[[float], None] = time.sleep) -> None:
        if isinstance(seconds, bool) or not math.isfinite(seconds) or seconds < 0:
            raise ValueError("backoff must be finite and non-negative")
        until = self.clock() + seconds
        while True:
            remaining = self.remaining()
            delay = until - self.clock()
            if delay <= 0:
                return
            sleep(min(delay, remaining, 0.1))


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 1
    on_timeout: bool = False
    on_provider_error: bool = False
    on_invalid_output: bool = False
    backoff_seconds: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 1000:
            raise ValueError("invalid model attempt bound")
        if any(type(value) is not int or not 0 <= value <= 3600 for value in self.backoff_seconds):
            raise ValueError("invalid model backoff schedule")

    @property
    def attempts(self) -> int:
        return 1 if safety.active() else self.max_attempts

    def allows(self, attempt: int, error: BaseException | FailureCategory) -> bool:
        if attempt >= self.attempts:
            return False
        if isinstance(error, ProviderError) and not error.retryable:
            return False
        category = error if isinstance(error, FailureCategory) else failure_category(error)
        return {FailureCategory.TIMEOUT: self.on_timeout,
                FailureCategory.PROVIDER: self.on_provider_error,
                FailureCategory.SCHEMA: self.on_invalid_output}.get(category, False)

    def delay(self, attempt: int) -> int:
        return self.backoff_seconds[min(attempt - 1, len(self.backoff_seconds) - 1)] \
            if self.backoff_seconds else 0


@dataclass(frozen=True, slots=True)
class CallReceipt:
    schema: str
    execution_version: str
    execution_id: str
    invocation_id: str
    sequence: int
    dispatched: bool
    request_sha256: str
    guidance_sha256: str
    response_sha256: str | None
    category: str | None
    error_class: str | None
    status: str
    retry_count: int
    retry_reason: str | None
    elapsed_ms: int
    usage: Usage
    requested_provider: str
    requested_model: str
    served_provider: str | None
    served_model: str | None


class Execution:
    """A sequential bounded conversation, with independent local authorization in its adapter."""

    def __init__(self, *, timeout_seconds: float, max_calls: int,
                 context: CallContext | None = None, max_request_bytes: int | None = None,
                 max_response_bytes: int | None = None, max_total_response_bytes: int | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 check_cancelled: Callable[[], None] = safety.check_running) -> None:
        if type(max_calls) is not int or max_calls < 1:
            raise ValueError("execution call bound must be positive")
        for bound in (max_request_bytes, max_response_bytes, max_total_response_bytes):
            if bound is not None and (type(bound) is not int or bound < 1):
                raise ValueError("execution byte bounds must be positive integers")
        self.deadline = Deadline(timeout_seconds, clock=clock, check_cancelled=check_cancelled)
        self.sleep, self.max_calls, self.calls = sleep, max_calls, 0
        self.max_request_bytes, self.max_response_bytes = max_request_bytes, max_response_bytes
        self.max_total_response_bytes, self.response_bytes = max_total_response_bytes, 0
        self.context = context if context is not None else CallContext.current()
        self.execution_id = uuid4().hex
        self.receipts: list[CallReceipt] = []

    def retry(self, attempt: int, error: BaseException | FailureCategory, policy: RetryPolicy) -> bool:
        if not policy.allows(attempt, error):
            return False
        self.deadline.wait(policy.delay(attempt), sleep=self.sleep)
        return True

    def _fields(self, request: ModelRequest | ReviewModelRequest, invocation: str,
                request_hash: str, guidance_hash: str, retry_count: int,
                retry_reason: str | None) -> dict[str, Any]:
        assert self.context is not None
        context = self.context
        fields = {
            "run_id": context.run_id, "job_id": context.job_id, "attempt_id": context.attempt_id,
            "step_id": context.step_id, "task_id": context.task_id, "invocation_id": invocation,
            "provider": _identity(request.provider), "model": _identity(request.model),
            "reasoning_level": _identity(request.reasoning),
            "request_sha256": request_hash, "guidance_bundle_sha256": guidance_hash,
            "execution_id": self.execution_id, "retry_count": retry_count, "retry_reason": retry_reason,
        }
        if isinstance(request, ReviewModelRequest):
            fields.update(role=_identity(request.role), persona=_identity(request.persona),
                          cell_id=_identity(request.cell_id))
        return fields

    def _emit(self, event: str, fields: dict[str, Any], **details: Any) -> None:
        if self.context is not None:
            from appsec_review.observability.events import PipelineLog
            from appsec_review.observability.telemetry import emit_model_event
            emit_model_event(PipelineLog(self.context.run_root), event_type=event, **fields, **details)

    def call(self, infer: Infer, request: ModelRequest | ReviewModelRequest, *,
             timeout_seconds: int, retry_count: int = 0, retry_reason: str | None = None) -> ModelResult:
        if not isinstance(request, (ModelRequest, ReviewModelRequest)):
            raise ExecutionContractError("unsupported inference request contract")
        if type(retry_count) is not int or retry_count < 0:
            raise ExecutionContractError("retry_count must be a non-negative integer")
        if retry_reason is not None and retry_reason not in {value.value for value in FailureCategory}:
            raise ExecutionContractError("retry_reason must be a closed failure category")
        encoded = _json(asdict(request))
        request_hash = hashlib.sha256(encoded).hexdigest()
        guidance_hash = (request.guidance_bundle_sha256 if isinstance(request, ReviewModelRequest)
                         else _digest({"guidance": request.guidance, "role": request.role,
                                       "persona": request.persona}))
        invocation, started = uuid4().hex, self.deadline.clock()
        fields = self._fields(request, invocation, request_hash, guidance_hash, retry_count, retry_reason) \
            if self.context is not None else {}
        result, response_hash, error, dispatched = None, None, None, False
        usage = Usage.from_result(None)
        try:
            timeout = self.deadline.timeout(timeout_seconds)
            if self.calls >= self.max_calls:
                raise ExecutionLimit("model_call_bound")
            request_bound = self.max_request_bytes if self.max_request_bytes is not None else \
                min(4 * 1024 * 1024, request.max_input_tokens * 4)
            if len(encoded) > request_bound:
                raise ExecutionLimit("input_byte_bound")
            self._emit("MODEL_CALL_STARTED", fields)
            dispatched = True
            self.calls += 1
            result = infer(request, timeout_seconds=timeout)
            usage = Usage.from_result(result)
            result = usage.normalize(result)
            payload = _json(result.proposal, response=True)
            if not isinstance(result.proposal, Mapping):
                raise ModelOutputError("model reply must be an object")
            response_hash = hashlib.sha256(payload).hexdigest()
            if result.raw_response is not None and not isinstance(result.raw_response, str):
                raise ExecutionContractError("ModelResult.raw_response must be text")
            size = max(len(payload), len(result.raw_response.encode()) if result.raw_response is not None else 0)
            self.response_bytes += size
            response_bound = self.max_response_bytes if self.max_response_bytes is not None else \
                min(2 * 1024 * 1024, request.max_output_tokens * 8)
            if size > response_bound:
                raise ModelOutputError("model reply exceeded response byte bound")
            if self.max_total_response_bytes is not None and self.response_bytes > self.max_total_response_bytes:
                raise ExecutionLimit("cumulative_output_byte_bound")
            if ((usage.input_tokens is not None and usage.input_tokens > request.max_input_tokens)
                    or (usage.output_tokens is not None and usage.output_tokens > request.max_output_tokens)):
                raise ExecutionLimit("model_token_cap")
            self.deadline.remaining()
            return result
        except BaseException as exc:
            error = exc
            safety.retain_failure("inference.execution", exc, request_sha256=request_hash,
                                  execution_id=self.execution_id)
            raise
        finally:
            category = failure_category(error) if error is not None else None
            status = ("SUCCEEDED" if category is None else "TIMED_OUT" if category is FailureCategory.TIMEOUT
                      else "CANCELLED" if category is FailureCategory.CANCELLED else "FAILED")
            served_provider = _identity(result.served_provider) if isinstance(result, ModelResult) \
                and isinstance(result.served_provider, str) else None
            served_model = _identity(result.served_model) if isinstance(result, ModelResult) \
                and isinstance(result.served_model, str) else None
            receipt = CallReceipt(
                RECEIPT_SCHEMA, EXECUTION_VERSION, self.execution_id, invocation, len(self.receipts) + 1,
                dispatched, request_hash, guidance_hash, response_hash,
                category.value if category is not None else None,
                type(error).__name__ if error is not None else None, status, retry_count, retry_reason,
                max(0, int((self.deadline.clock() - started) * 1000)), usage,
                _identity(request.provider), _identity(request.model), served_provider, served_model)
            self.receipts.append(receipt)
            if self.context is not None:
                context = self.context
                scope = _digest({"job_id": context.job_id, "attempt_id": context.attempt_id})
                immutable_bytes(context.run_root,
                    f"data/inference-executions/{scope}/{self.execution_id}/{receipt.sequence:06d}.json",
                    canonical_json({**asdict(receipt), "run_id": context.run_id,
                                    "job_id": context.job_id, "attempt_id": context.attempt_id,
                                    "step_id": context.step_id, "task_id": context.task_id}))
            if dispatched:
                self._emit("MODEL_CALL_COMPLETED", fields, terminal_status=status,
                    duration_ms=receipt.elapsed_ms, error_class=receipt.error_class,
                    failure_category=receipt.category, served_provider=served_provider, served_model=served_model,
                    execution_mode="replay" if usage.source == "replay" else "inference",
                    usage_source=usage.source, usage_unavailable_reason=usage.unavailable_reason, **usage.actual)
