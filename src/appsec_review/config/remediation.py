"""Closed central settings for the nonexecuting remediation producers."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from typing import Any, Mapping

from appsec_review.storage import canonical_json


def exact(value: Any, keys: set[str], where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{where} must contain exactly {sorted(keys)}")
    return value


def integer(value: Any, where: str, high: int, low: int = 1) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{where} must be an integer in [{low}, {high}]")
    return value


def boolean(value: Any, where: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{where} must be a boolean")
    return value


@dataclass(frozen=True, slots=True)
class RemediationModel:
    provider: str
    model: str
    reasoning: str
    max_input_tokens: int
    max_output_tokens: int
    max_turns: int
    max_queries: int
    timeout_seconds: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RemediationModel:
        body = exact(value, set(cls.__dataclass_fields__), "remediation model")
        for key in ("provider", "model", "reasoning"):
            if not isinstance(body[key], str) or not body[key].strip() or len(body[key]) > 200:
                raise ValueError(f"remediation model.{key} must be a nonempty bounded string")
        return cls(*(body[key] for key in ("provider", "model", "reasoning")),
                   integer(body["max_input_tokens"], "max_input_tokens", 1_000_000),
                   integer(body["max_output_tokens"], "max_output_tokens", 100_000),
                   integer(body["max_turns"], "max_turns", 20),
                   integer(body["max_queries"], "max_queries", 100, low=0),
                   integer(body["timeout_seconds"], "timeout_seconds", 7200))


@dataclass(frozen=True, slots=True)
class RemediationBounds:
    max_candidates: int
    max_packages: int
    max_source_files: int
    max_source_bytes: int
    max_patch_files: int
    max_patch_bytes: int
    max_file_bytes: int
    max_edits: int
    max_list_items: int
    max_text_chars: int
    max_workspace_files: int
    max_workspace_bytes: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RemediationBounds:
        body = exact(value, set(cls.__dataclass_fields__), "remediation bounds")
        ceilings = (1000, 100000, 32, 2**20, 32, 2**20, 2**24, 256, 100, 16000, 1_000_000, 2**40)
        result = cls(*(integer(body[key], key, ceiling)
                       for key, ceiling in zip(cls.__dataclass_fields__, ceilings, strict=True)))
        if result.max_candidates > result.max_packages:
            raise ValueError("max_candidates cannot exceed max_packages")
        return result


@dataclass(frozen=True, slots=True)
class RemediationPlanningSettings:
    enabled: bool
    bounds: RemediationBounds
    writer: RemediationModel

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RemediationPlanningSettings:
        body = exact(value, {"enabled", "bounds", "writer"}, "remediation planning settings")
        return cls(boolean(body["enabled"], "enabled"), RemediationBounds.from_mapping(body["bounds"]),
                   RemediationModel.from_mapping(body["writer"]))

    def settings_sha256(self) -> str:
        return hashlib.sha256(canonical_json(asdict(self))).hexdigest()


@dataclass(frozen=True, slots=True)
class RemediationValidationSettings:
    enabled: bool
    bounds: RemediationBounds
    reviewer: RemediationModel
    adapters: tuple[str, ...]
    command_timeout_seconds: int
    output_bytes: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RemediationValidationSettings:
        body = exact(value, {"enabled", "bounds", "reviewer", "adapters", "command_timeout_seconds",
                             "output_bytes"}, "remediation validation settings")
        adapters = body["adapters"]
        if not isinstance(adapters, list) or adapters not in ([], ["native_syntax"]):
            raise ValueError("remediation adapters must be [] or ['native_syntax']")
        return cls(boolean(body["enabled"], "enabled"), RemediationBounds.from_mapping(body["bounds"]),
                   RemediationModel.from_mapping(body["reviewer"]), tuple(adapters),
                   integer(body["command_timeout_seconds"], "command_timeout_seconds", 7200),
                   integer(body["output_bytes"], "output_bytes", 2**20))

    def settings_sha256(self) -> str:
        return hashlib.sha256(canonical_json(asdict(self))).hexdigest()
