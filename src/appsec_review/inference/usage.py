"""Provider-reported usage, separate from estimates, reservations and replay."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Literal

from .errors import ExecutionContractError
from .request import ModelResult

UsageSource = Literal["provider", "replay"]


def token_count(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def reported_cache_write(report: Any) -> Any:
    """Read an SDK event or JSON usage object. A reported zero is not a missing alias."""
    for name in ("cache_write_tokens", "cache_creation_input_tokens", "cache_write_input_tokens",
                 "cacheWriteTokens", "cacheCreationInputTokens", "cacheWriteInputTokens"):
        value = report.get(name) if isinstance(report, Mapping) else getattr(report, name, None)
        if value is not None:
            return value
    return None


@dataclass(frozen=True, slots=True)
class Usage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_tokens: int | None = None
    source: UsageSource = "provider"
    unavailable_reason: str | None = None
    cache_write_tokens: int | None = None

    @classmethod
    def from_result(cls, result: ModelResult | None) -> Usage:
        if result is None:
            return cls(unavailable_reason="no_provider_response")
        if not isinstance(result, ModelResult):
            raise ExecutionContractError("Infer must return ModelResult")
        if result.usage_source not in {"provider", "replay"}:
            raise ExecutionContractError("unsupported model usage source")
        raw = (result.input_tokens, result.output_tokens, result.cache_tokens, result.cache_write_tokens)
        values = tuple(token_count(value) for value in raw)
        invalid = any(value is not None and normalized is None for value, normalized in zip(raw, values))
        reason = ("recorded_replay" if result.usage_source == "replay" else
                  "invalid_provider_usage" if invalid else result.usage_unavailable_reason or
                  ("provider_usage_missing" if any(value is None for value in values[:2]) else None))
        return cls(values[0], values[1], values[2], source=result.usage_source, unavailable_reason=reason,
                   cache_write_tokens=values[3])

    @property
    def actual(self) -> dict[str, int | None]:
        """Only new provider reports are billable; cache tokens are not silently subtracted."""
        return {name: getattr(self, name) if self.source == "provider" else None
                for name in ("input_tokens", "output_tokens", "cache_tokens")}

    @property
    def actual_cache_write_tokens(self) -> int | None:
        # Keep the existing closed accounting dimensions in `actual`; writes are observational.
        return self.cache_write_tokens if self.source == "provider" else None

    def normalize(self, result: ModelResult) -> ModelResult:
        return replace(result, input_tokens=self.input_tokens, output_tokens=self.output_tokens,
                       cache_tokens=self.cache_tokens, cache_write_tokens=self.cache_write_tokens,
                       usage_source=self.source, usage_unavailable_reason=self.unavailable_reason)


def total_reported(values: list[int | None]) -> int | None:
    """A cumulative total is unknown if any contributing call is unknown."""
    return sum(value for value in values if value is not None) \
        if values and all(value is not None for value in values) else None
