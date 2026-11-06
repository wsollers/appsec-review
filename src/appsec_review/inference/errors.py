"""Closed failure categories at the model transport/application boundary."""
from __future__ import annotations

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


class ModelOutputError(ValueError):
    def __init__(self, message: str, *, raw_response: str | None = None,
                 rejected_output: str | None = None) -> None:
        super().__init__(message)
        self.raw_response = raw_response
        self.rejected_output = rejected_output


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
