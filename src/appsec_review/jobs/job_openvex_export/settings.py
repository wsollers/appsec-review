"""Frozen automatic local export defaults and explicit operator overrides."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import re
from typing import Any

from .contracts import (
    AuthorKind, MAX_ACTION_BYTES, MAX_ARTIFACT_BYTES, MAX_BINDINGS, MAX_DOCUMENT_BYTES,
    MAX_IDENTIFIER_BYTES, MAX_MANIFEST_BYTES, MAX_PACKAGES, MAX_TIMEOUT_SECONDS,
    MAX_TOTAL_INPUT_BYTES, domain_sha256, validate_repository_iri, validate_text,
)

_BOUNDS = {
    "max_packages": MAX_PACKAGES, "max_bindings": MAX_BINDINGS,
    "max_artifact_bytes": MAX_ARTIFACT_BYTES, "max_total_input_bytes": MAX_TOTAL_INPUT_BYTES,
    "max_document_bytes": MAX_DOCUMENT_BYTES, "max_manifest_bytes": MAX_MANIFEST_BYTES,
    "max_action_bytes": MAX_ACTION_BYTES, "max_identifier_bytes": MAX_IDENTIFIER_BYTES,
    "timeout_seconds": MAX_TIMEOUT_SECONDS,
}
_KEYS = frozenset({"enabled", "author_kind", "author", "role", "action_statement", "repository_iri", *_BOUNDS})
_TOOL_AUTHOR = re.compile(
    r"(?:tool|bot|automation|automated(?: tool)?|appsec[- ]review|github actions|dependabot|github copilot|copilot|"
    r"chatgpt|claude|gemini|gpt(?:[- .]\S*)?)(?:\s*(?:bot|agent|tool|app))?", re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class OpenVexExportSettings:
    enabled: bool = True
    author_kind: AuthorKind = AuthorKind.TOOL
    author: str = "AppSec Review"
    role: str = "Automated local application-security review"
    action_statement: str = (
        "Review and remediate the confirmed findings using the accompanying evidence; "
        "validate any fix before relying on it."
    )
    repository_iri: str = ""
    max_packages: int = MAX_PACKAGES
    max_bindings: int = MAX_BINDINGS
    max_artifact_bytes: int = MAX_ARTIFACT_BYTES
    max_total_input_bytes: int = MAX_TOTAL_INPUT_BYTES
    max_document_bytes: int = MAX_DOCUMENT_BYTES
    max_manifest_bytes: int = MAX_MANIFEST_BYTES
    max_action_bytes: int = MAX_ACTION_BYTES
    max_identifier_bytes: int = MAX_IDENTIFIER_BYTES
    timeout_seconds: int = MAX_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("jobs.job_openvex_export.settings.enabled must be a boolean")
        object.__setattr__(self, "author_kind", AuthorKind(self.author_kind))
        for name, high in _BOUNDS.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= high:
                raise ValueError(f"jobs.job_openvex_export.settings.{name} must be an integer in [1, {high}]")
        if self.max_artifact_bytes > self.max_total_input_bytes:
            raise ValueError("max_artifact_bytes must not exceed max_total_input_bytes")
        for name in ("author", "role", "action_statement", "repository_iri"):
            value = getattr(self, name)
            validate_text(value, max_bytes=self.max_action_bytes if name == "action_statement"
                          else self.max_identifier_bytes, field=name,
                          empty=name in {"role", "repository_iri"} or not self.enabled,
                          multiline=name == "action_statement")
        if self.repository_iri:
            validate_repository_iri(self.repository_iri, max_bytes=self.max_identifier_bytes)
        if (self.author_kind != AuthorKind.TOOL and self.author
                and (_TOOL_AUTHOR.fullmatch(self.author.strip()) or self.author.strip().lower().endswith("[bot]"))):
            raise ValueError("author must identify the issuing individual or organization, not tooling")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> OpenVexExportSettings:
        if not isinstance(value, Mapping) or set(value) != _KEYS:
            raise ValueError("jobs.job_openvex_export.settings must define exactly its documented keys")
        return cls(**dict(value))

    def to_mapping(self) -> dict[str, Any]:
        return {**asdict(self), "author_kind": self.author_kind.value}

    def settings_sha256(self) -> str:
        """All frozen policy and bound fields, including disabled state; never a config-file hash."""
        return domain_sha256("openvex-settings/1", self.to_mapping())

    def require_enabled(self) -> None:
        if not self.enabled:
            raise ValueError("job_openvex_export is disabled in this run's frozen configuration")

    def validate_prerequisites(self, *, gate_enabled: bool, review_enabled: bool) -> None:
        if type(gate_enabled) is not bool or type(review_enabled) is not bool:
            raise ValueError("export prerequisite states must be booleans")
        if self.enabled and not (gate_enabled and review_enabled):
            raise ValueError("enabled OpenVEX export requires gate and inference review enabled")
