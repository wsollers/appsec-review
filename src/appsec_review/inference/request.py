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


def _parameter_type(schema: Mapping[str, Any]) -> str:
    """Compact rendering of the closed retrieval schema vocabulary (not used for validation)."""
    if "oneOf" in schema or "anyOf" in schema:
        return " | ".join(_parameter_type(option) for option in schema.get("oneOf", schema.get("anyOf")))
    kind = schema.get("type", "string")
    if kind == "object":
        return "{" + ", ".join(f"{k}{'' if k in schema.get('required', ()) else '?'}:{_parameter_type(v)}"
                                for k, v in schema["properties"].items()) + "}"
    if kind == "array":
        return f"[{_parameter_type(schema['items'])}]"
    if "enum" in schema:
        return kind + "(" + "|".join(map(str, schema["enum"])) + ")"
    if "pattern" in schema:
        return f"{kind}/{schema['pattern']}/"
    if "minimum" in schema or "maximum" in schema:
        return f"{kind}[{schema.get('minimum', '')}..{schema.get('maximum', '')}]"
    return str(kind)


# Some application-enforced alternatives are not expressible as ordinary required properties.
_SELECTORS = {
    "expand": "exactly one of label, ref, files; offset pages files",
    "query_codeql_neighborhood": "database plus exactly one of seed, symbol, observation",
    "query_debug_symbols": "exact subject or artifact_identity; coverage and address require artifact_identity",
    "query_cfg_function": "subject, function_name or locator",
    "query_guard_dominators": "subject, locator or node_id; line identifies a site",
    "query_cpg_slice": "criterion_node_id, locator, line or function_name",
}


def _signature(operation: Mapping[str, Any]) -> dict[str, Any]:
    from appsec_review.review.capability import FORBIDDEN_PARAMETERS
    schema = operation["parameters"]
    signature = {"name": operation["name"], "required": schema.get("required", []),
                 "fields": {name: _parameter_type(prop) for name, prop in schema["properties"].items()
                            if name not in FORBIDDEN_PARAMETERS}}
    if alternatives := _SELECTORS.get(operation["name"]):
        signature["selectors"] = alternatives
    return signature


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
    card = prompt["capability_artifact_card"]
    if "catalog_sha256" in card:
        from appsec_review.guidance.cards import catalog_digest
        from appsec_review.guidance.fragments import GuidanceError
        task = prompt["task_input"]
        protocol = dict(task.get("turn_protocol", {}))
        catalog = protocol.get("tool_catalog", ())
        if catalog_digest(catalog) != card["catalog_sha256"]:
            raise GuidanceError("review catalog changed after admission")
        previous = request.task_input.get("artifact_admission", {}).get("previous_catalog_sha256")
        if request.transcript and previous == card["catalog_sha256"]:
            protocol["tool_catalog"] = [_signature(op) for op in catalog]
            protocol["catalog_format"] = "typed_signatures"
        else:
            protocol["catalog_format"] = "full_schemas"
        task["turn_protocol"] = protocol
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
