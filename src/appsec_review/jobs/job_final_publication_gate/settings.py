"""Typed configuration for ``job_final_publication_gate``.

The gate calls no model, so there is no provider, model, reasoning or budget setting here. The one
tunable is a bound on how many finding packages one gate will account for, which must not exceed
the schema's own bound.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

SCHEMA_MAX_PACKAGES = 10000
_KEYS = frozenset({"enabled", "max_packages"})


@dataclass(frozen=True, slots=True)
class FinalPublicationGateSettings:
    enabled: bool
    max_packages: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FinalPublicationGateSettings":
        if not isinstance(value, Mapping) or set(value) != _KEYS:
            unknown = sorted(set(value) - _KEYS) if isinstance(value, Mapping) else []
            missing = sorted(_KEYS - set(value)) if isinstance(value, Mapping) else sorted(_KEYS)
            raise ValueError("jobs.job_final_publication_gate.settings must define exactly its documented keys"
                             f" (unknown: {unknown}, missing: {missing})")
        if not isinstance(value["enabled"], bool):
            raise ValueError("jobs.job_final_publication_gate.settings.enabled must be a boolean")
        limit = value["max_packages"]
        if type(limit) is not int or not 1 <= limit <= SCHEMA_MAX_PACKAGES:
            raise ValueError("jobs.job_final_publication_gate.settings.max_packages must be an integer in "
                             f"[1, {SCHEMA_MAX_PACKAGES}]")
        return cls(value["enabled"], limit)
