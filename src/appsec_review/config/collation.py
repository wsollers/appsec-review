"""Typed settings of the collation pass (``jobs.job_security_tagging.settings.collation``, T-5008).

The deterministic pass classifies first-party files and components by closed facet tags
(``docs/architecture/collation-pass.md``). Its settings are semantic: they change which tags exist,
so they are part of the run's frozen configuration identity. The ``source_dispositions`` table is
the T-165 table of the inference review; the loader resolves that table into this one so there is
one source of truth, and a literal table here must equal it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from appsec_review.review.dispositions import SourceDispositions

_MODEL_FIELDS = frozenset({"enabled", "provider", "model", "reasoning", "max_input_tokens", "max_output_tokens",
                           "timeout_seconds", "retries"})
_PREFIX = "jobs.job_security_tagging.settings.collation"


def _bounded_int(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{_PREFIX}.{name} must be an integer between {low} and {high}")
    return value


@dataclass(frozen=True, slots=True)
class ModelPassSettings:
    """The optional recorded model pass; ``enabled`` is false in every shipped profile."""

    enabled: bool = False
    max_components: int = 64
    max_excerpt_lines: int = 400
    model: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError(f"{_PREFIX}.model_pass.enabled must be Boolean")
        _bounded_int(self.max_components, "model_pass.max_components", 1, 4096)
        _bounded_int(self.max_excerpt_lines, "model_pass.max_excerpt_lines", 1, 10_000)
        if self.model is not None:
            if not isinstance(self.model, Mapping) or set(self.model) != _MODEL_FIELDS:
                raise ValueError(f"{_PREFIX}.model_pass.model must be a complete model profile")
            if type(self.model["enabled"]) is not bool:
                raise ValueError(f"{_PREFIX}.model_pass.model.enabled must be Boolean")
            for key in ("provider", "model", "reasoning"):
                if not isinstance(self.model[key], str) or not self.model[key].strip():
                    raise ValueError(f"{_PREFIX}.model_pass.model.{key} must be a nonempty string")
            for key in ("max_input_tokens", "max_output_tokens", "timeout_seconds"):
                _bounded_int(self.model[key], f"model_pass.model.{key}", 1, 100_000_000)
            _bounded_int(self.model["retries"], "model_pass.model.retries", 0, 16)
        if self.enabled and (self.model is None or self.model["enabled"] is not True):
            raise ValueError(f"{_PREFIX}.model_pass.enabled requires an enabled model profile")

    @classmethod
    def from_mapping(cls, value: object) -> "ModelPassSettings":
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError(f"{_PREFIX}.model_pass must be a table")
        known = {"enabled", "max_components", "max_excerpt_lines", "model"}
        unknown = sorted(str(key) for key in set(value) - known)
        if unknown:
            raise ValueError(f"{_PREFIX}.model_pass has unknown settings: {', '.join(unknown)}")
        return cls(**{key: value[key] for key in value})

    def record(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "max_components": self.max_components,
                "max_excerpt_lines": self.max_excerpt_lines,
                "model": dict(self.model) if self.model is not None else None}


@dataclass(frozen=True, slots=True)
class CollationSettings:
    max_source_bytes_per_file: int = 262_144
    max_files_per_component: int = 4096
    source_dispositions: SourceDispositions = field(default_factory=SourceDispositions)
    model_pass: ModelPassSettings = field(default_factory=ModelPassSettings)

    def __post_init__(self) -> None:
        _bounded_int(self.max_source_bytes_per_file, "max_source_bytes_per_file", 1, 16 * 1024 * 1024)
        _bounded_int(self.max_files_per_component, "max_files_per_component", 1, 1_000_000)
        if not isinstance(self.source_dispositions, SourceDispositions):
            raise ValueError(f"{_PREFIX}.source_dispositions must be SourceDispositions")
        if not isinstance(self.model_pass, ModelPassSettings):
            raise ValueError(f"{_PREFIX}.model_pass must be ModelPassSettings")

    def record(self) -> dict[str, Any]:
        return {"max_source_bytes_per_file": self.max_source_bytes_per_file,
                "max_files_per_component": self.max_files_per_component,
                "source_dispositions": self.source_dispositions.record(),
                "model_pass": self.model_pass.record()}


def parse_collation_settings(value: object, *, inherited_dispositions: object = None) -> CollationSettings:
    """Typed collation settings from the TOML table.

    ``inherited_dispositions`` is the raw ``jobs.job_inference_security_review.settings.source_dispositions``
    table. When the collation table names no ``source_dispositions`` it inherits that table; when it
    names one, the two must classify identically or loading fails. Without either, every path is
    first-party.
    """
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{_PREFIX} must be a table")
    known = {"max_source_bytes_per_file", "max_files_per_component", "source_dispositions", "model_pass"}
    unknown = sorted(str(key) for key in set(value) - known)
    if unknown:
        raise ValueError(f"{_PREFIX} has unknown settings: {', '.join(unknown)}")
    inherited = (SourceDispositions.from_mapping(inherited_dispositions,
                                                "jobs.job_inference_security_review.settings.source_dispositions")
                 if inherited_dispositions is not None else None)
    if "source_dispositions" in value:
        dispositions = SourceDispositions.from_mapping(value["source_dispositions"], f"{_PREFIX}.source_dispositions")
        if inherited is not None and dispositions != inherited:
            raise ValueError(f"{_PREFIX}.source_dispositions must equal "
                             "jobs.job_inference_security_review.settings.source_dispositions")
    else:
        dispositions = inherited if inherited is not None else SourceDispositions()
    return CollationSettings(
        max_source_bytes_per_file=value.get("max_source_bytes_per_file", 262_144),
        max_files_per_component=value.get("max_files_per_component", 4096),
        source_dispositions=dispositions,
        model_pass=ModelPassSettings.from_mapping(value.get("model_pass")))


__all__ = ["CollationSettings", "ModelPassSettings", "parse_collation_settings"]
