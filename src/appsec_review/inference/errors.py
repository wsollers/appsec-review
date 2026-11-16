"""Closed failure categories at the model transport/application boundary."""
from __future__ import annotations

from typing import Any

import asyncio
from enum import Enum
import subprocess

from appsec_review.runtime.execution_safety import ReviewStopped


class FailureCategory(str, Enum):
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    PROVIDER = "provider"
    SCHEMA = "schema"
    BUDGET = "budget"
    CONTRACT = "contract"


# Closed classes of a reply that failed its response contract; the recording and the job's gap
# carry one of these so a failed call is diagnosable from the run without the reply text.
SCHEMA_FAILURE_CLASSES = frozenset({
    "empty_reply",        # the transport delivered no text
    "no_json_object",     # text without any decodable JSON object
    "schema_mismatch",    # JSON object(s), none carrying the declared schema
    "several_objects",    # more than one distinct object carries the declared schema
    "truncated_output",   # the provider stopped at its output budget
    "refusal",            # the provider declined to answer
})


class ModelOutputError(ValueError):
    def __init__(self, message: str, *, raw_response: str | None = None,
                 rejected_output: str | None = None, failure_class: str | None = None,
                 stop_reason: str | None = None, usage: dict[str, int | None] | None = None,
                 raw_response_truncated: bool = False) -> None:
        super().__init__(message)
        if failure_class is not None and failure_class not in SCHEMA_FAILURE_CLASSES:
            raise ValueError(f"unknown model output failure class: {failure_class!r}")
        self.raw_response = raw_response
        self.rejected_output = rejected_output
        self.failure_class = failure_class
        self.stop_reason = stop_reason
        self.usage = dict(usage) if usage is not None else None
        self.raw_response_truncated = bool(raw_response_truncated)


class ProviderError(RuntimeError):
    """An identified transport failure, not an arbitrary application exception."""

    def __init__(self, message: str, *, retryable: bool = False, code: str = "provider_failure") -> None:
        super().__init__(message)
        self.retryable = retryable
        self.code = code


class ModelTimeout(TimeoutError):
    def __init__(self, message: str = "model transport timed out", *, code: str = "provider_timeout") -> None:
        super().__init__(message)
        self.code = code


class ModelCancelled(ReviewStopped):
    """Cancellation remains control flow and cannot be converted into an ordinary gap."""


class ExecutionLimit(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ModelTokenCapExceeded(ExecutionLimit):
    """``model_token_cap`` tripped by the output-token accounting of a reply that was already received and parsed.

    The call is still a failed execution (receipt, budget charge and telemetry are unchanged), but the parsed reply
    exists: the caller decides what it is worth. The reply stays off ``args`` so failure records never carry it."""

    def __init__(self, result: Any, *, tokens: int, cap: int) -> None:
        super().__init__("model_token_cap")
        self.result = result
        self.tokens = tokens
        self.cap = cap


class ExecutionContractError(RuntimeError):
    """Malformed application/recording contracts must propagate to the job owner."""


def failure_category(error: BaseException) -> FailureCategory:
    if isinstance(error, (ReviewStopped, asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
        return FailureCategory.CANCELLED
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return FailureCategory.TIMEOUT
    if isinstance(error, ModelOutputError):
        return FailureCategory.SCHEMA
    if isinstance(error, ProviderError):
        return FailureCategory.PROVIDER
    if isinstance(error, ExecutionLimit):
        return FailureCategory.BUDGET
    return FailureCategory.CONTRACT
