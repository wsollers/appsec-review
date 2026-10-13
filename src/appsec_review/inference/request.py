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
    allowed_image_profiles: tuple[str, ...] = ()
    repair_errors: tuple[str, ...] = ()
    prior_response: str | None = None


@dataclass(frozen=True, slots=True)
class ReviewModelRequest:
    """One bounded turn of an inference-review cell (design R2).

    The transport sends the hash-pinned guidance, the task input, and the application-mediated
    transcript. It never receives build-planning fields, and the model is granted no tools: every
    retrieval runs in-process through the application between turns.
    """

    schema: str                                  # worker-turn schema the reply must carry
    role: str
    persona: str
    stack_profile: str
    guidance_bundle_sha256: str
    guidance_text: str
    task_input: Mapping[str, Any]
    transcript: tuple[Mapping[str, Any], ...]
    provider: str
    model: str
    reasoning: str
    max_input_tokens: int
    max_output_tokens: int
    repair_errors: tuple[str, ...] = ()
    cell_id: str = ""


@dataclass(frozen=True, slots=True)
class ModelResult:
    proposal: Mapping[str, Any]
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_tokens: int | None = None
    raw_response: str | None = None


class Infer(Protocol):
    """The shape of `appsec_review.inference.infer`, and of a test double that replaces it."""

    def __call__(self, request: ModelRequest | ReviewModelRequest, *,
                 timeout_seconds: int) -> ModelResult: ...


def review_prompt(request: ReviewModelRequest, *, include_guidance: bool) -> dict[str, Any]:
    """The review-turn message every transport sends: task input, transcript, and limits.

    Guidance travels here only for a transport without a separate system channel.
    """
    prompt: dict[str, Any] = {
        "response_schema": request.schema,
        "role": request.role, "persona": request.persona, "stack_profile": request.stack_profile,
        "guidance_bundle_sha256": request.guidance_bundle_sha256,
        "task_input": dict(request.task_input),
        "transcript": [dict(turn) for turn in request.transcript],
        "limits": {"max_input_tokens": request.max_input_tokens,
                   "max_output_tokens": request.max_output_tokens},
    }
    if include_guidance:
        prompt["guidance"] = request.guidance_text
    if request.repair_errors:
        prompt["repair"] = {"validation_errors": list(request.repair_errors),
                            "instruction": ("Return only one corrected JSON object. Its top-level "
                                            f"schema must be exactly {request.schema}.")}
    return prompt
