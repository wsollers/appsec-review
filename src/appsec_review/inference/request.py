from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping, Protocol


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
    capability_artifact_card: Mapping[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        from appsec_review.guidance.cards import request_card
        object.__setattr__(self, "capability_artifact_card", request_card(self))


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
    capability_artifact_card: Mapping[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        from appsec_review.guidance.cards import request_card
        object.__setattr__(self, "capability_artifact_card", request_card(self))


@dataclass(frozen=True, slots=True)
class ModelResult:
    proposal: Mapping[str, Any]
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_tokens: int | None = None
    raw_response: str | None = None
    served_model: str | None = None
    served_provider: str | None = None
    usage_source: Literal["provider", "replay"] = "provider"
    usage_unavailable_reason: str | None = None


class Infer(Protocol):
    """The shape of `appsec_review.inference.infer`, and of a test double that replaces it."""

    def __call__(self, request: ModelRequest | ReviewModelRequest, *,
                 timeout_seconds: int) -> ModelResult: ...


def review_prompt(request: ReviewModelRequest, *, include_guidance: bool) -> dict[str, Any]:
    """The review-turn message every transport sends: task input, transcript, and limits.

    Guidance travels here only for a transport without a separate system channel.
    """
    from appsec_review.guidance.cards import verify_card
    prompt: dict[str, Any] = {
        "response_schema": request.schema,
        "role": request.role, "persona": request.persona, "stack_profile": request.stack_profile,
        "guidance_bundle_sha256": request.guidance_bundle_sha256,
        "task_input": {key: value for key, value in request.task_input.items() if key != "artifact_admission"},
        "transcript": [dict(turn) for turn in request.transcript],
        "capability_artifact_card": verify_card(request.capability_artifact_card),
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


def plan_prompt(request: ModelRequest, *, include_persona: bool = True) -> dict[str, Any]:
    """One renderer for all specialized transports, with the same generated card."""
    from appsec_review.guidance.cards import verify_card
    prompt: dict[str, Any] = {
        "task": request.guidance, "response_schema": request.schema,
        "catalog_summary": request.summary,
        "capability_artifact_card": verify_card(request.capability_artifact_card),
        "allowlists": {"scanners": request.allowed_scanners, "build_systems": request.allowed_build_systems,
                      "components": request.allowed_components, "paths": request.allowed_paths,
                      "build_units": request.allowed_build_units, "image_profiles": request.allowed_image_profiles},
        "limits": {"max_input_tokens": request.max_input_tokens, "max_output_tokens": request.max_output_tokens},
    }
    if include_persona:
        prompt.update(persona=request.persona, role=request.role)
    if request.repair_errors:
        prompt["repair"] = {"validation_errors": request.repair_errors,
                            "rejected_response": request.prior_response,
                            "instruction": ("Return only one corrected JSON object. Its top-level "
                                            f"schema must be exactly {request.schema}.")}
    return prompt
