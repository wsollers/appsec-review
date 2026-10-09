from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True, slots=True)
class ModelRequest:
    schema: str
    persona: str
    role: str
    guidance: str
    summary: Mapping[str, Any]
    allowed_scanners: tuple[str, ...]
    allowed_build_systems: tuple[str, ...]
    allowed_components: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    allowed_build_units: tuple[str, ...]
    provider: str
    model: str
    reasoning: str
    max_input_tokens: int
    max_output_tokens: int
    repair_errors: tuple[str, ...] = ()
    prior_response: str | None = None


@dataclass(frozen=True, slots=True)
class ModelResult:
    proposal: Mapping[str, Any]
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_tokens: int | None = None
    raw_response: str | None = None


class Infer(Protocol):
    """The shape of `appsec_review.inference.infer`, and of a test double that replaces it."""

    def __call__(self, request: ModelRequest, *, timeout_seconds: int) -> ModelResult: ...
