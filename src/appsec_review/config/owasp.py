"""Closed execution and budget settings for the OWASP lane."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping


class AssessmentMode(StrEnum):
    QUALIFICATION = "qualification"
    ASSESSMENT = "assessment"


@dataclass(frozen=True, slots=True)
class OwaspSettings:
    enabled: bool
    mode: AssessmentMode
    reviewer_profile: str
    max_evidence_per_component: int
    max_source_lines: int
    max_subjects_per_control: int
    max_batches: int
    max_turns: int
    max_queries: int


def parse_settings(value: Mapping[str, Any]) -> OwaspSettings:
    required = {
        "enabled", "mode", "reviewer_profile", "max_evidence_per_component", "max_source_lines",
        "max_subjects_per_control", "max_batches", "max_turns", "max_queries", "asvs_level",
        "masvs_profile", "max_batch_size", "max_components_per_batch", "max_components",
        "dynamic_authorized", "model", "models", "standards", "parser_versions",
    }
    if set(value) != required:
        raise ValueError(f"OWASP settings missing={sorted(required - set(value))}, "
                         f"unknown={sorted(set(value) - required)}")
    for key in ("enabled", "dynamic_authorized"):
        if type(value[key]) is not bool:
            raise ValueError(f"OWASP {key} must be Boolean")
    mode = AssessmentMode(value["mode"])
    models = value["models"]
    profile = value["reviewer_profile"]
    if not isinstance(models, Mapping) or not isinstance(profile, str) or profile not in models:
        raise ValueError("OWASP reviewer_profile must name a configured models profile")
    # Unselected profiles remain visible to the repository's model preflight.
    for model in (value["model"], models[profile]):
        fields = {"enabled", "provider", "model", "reasoning", "max_input_tokens", "max_output_tokens",
                  "timeout_seconds", "retries"}
        if not isinstance(model, Mapping) or set(model) != fields:
            raise ValueError("OWASP selected model profile is incomplete or has unknown settings")
        if type(model["enabled"]) is not bool:
            raise ValueError("OWASP model enabled must be Boolean")
        for key in ("provider", "model", "reasoning"):
            if not isinstance(model[key], str) or not model[key].strip():
                raise ValueError(f"OWASP model {key} must be a nonempty string")
        for key in ("max_input_tokens", "max_output_tokens", "timeout_seconds", "retries"):
            low = 0 if key == "retries" else 1
            if type(model[key]) is not int or not low <= model[key] <= 10_000_000:
                raise ValueError(f"OWASP model {key} is outside its bound")
        if value["enabled"] and model["enabled"] != (mode is AssessmentMode.ASSESSMENT):
            raise ValueError("OWASP assessment requires enabled worker/reviewer; qualification forbids inference")
    bounds = {
        "max_evidence_per_component": 200, "max_source_lines": 500,
        "max_subjects_per_control": 32, "max_batches": 10000, "max_turns": 16, "max_queries": 100,
        "max_batch_size": 64, "max_components_per_batch": 16, "max_components": 128,
    }
    for key, maximum in bounds.items():
        if type(value[key]) is not int or not 1 <= value[key] <= maximum:
            raise ValueError(f"OWASP {key} must be between 1 and {maximum}")
    if type(value["asvs_level"]) is not int or value["asvs_level"] not in {1, 2, 3}:
        raise ValueError("OWASP asvs_level must be 1, 2 or 3")
    if value["masvs_profile"] not in {"L1", "L2"}:
        raise ValueError("OWASP masvs_profile must be L1 or L2")
    return OwaspSettings(value["enabled"], mode, profile, **{key: value[key] for key in (
        "max_evidence_per_component", "max_source_lines", "max_subjects_per_control",
        "max_batches", "max_turns", "max_queries")})
