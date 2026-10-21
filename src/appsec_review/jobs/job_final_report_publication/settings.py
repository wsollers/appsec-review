"""Typed configuration for ``job_final_report_publication``.

The report calls no model, so there is no provider, model or budget setting. The two tunables only
shorten identifier lists in the human-readable Markdown; ``final-report.json`` always carries every
identifier.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

_KEYS = frozenset({"enabled", "markdown_evidence_ids", "markdown_gap_ids"})


@dataclass(frozen=True, slots=True)
class FinalReportSettings:
    enabled: bool
    markdown_evidence_ids: int
    markdown_gap_ids: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FinalReportSettings":
        if not isinstance(value, Mapping) or set(value) != _KEYS:
            unknown = sorted(set(value) - _KEYS) if isinstance(value, Mapping) else []
            missing = sorted(_KEYS - set(value)) if isinstance(value, Mapping) else sorted(_KEYS)
            raise ValueError("jobs.job_final_report_publication.settings must define exactly its documented keys"
                             f" (unknown: {unknown}, missing: {missing})")
        if not isinstance(value["enabled"], bool):
            raise ValueError("jobs.job_final_report_publication.settings.enabled must be a boolean")
        for key in ("markdown_evidence_ids", "markdown_gap_ids"):
            if type(value[key]) is not int or not 0 <= value[key] <= 256:
                raise ValueError(f"jobs.job_final_report_publication.settings.{key} must be an integer in [0, 256]")
        return cls(value["enabled"], value["markdown_evidence_ids"], value["markdown_gap_ids"])

    def identity(self) -> dict[str, int]:
        """The settings that change the bytes of ``final-report.md``."""
        return {"markdown_evidence_ids": self.markdown_evidence_ids, "markdown_gap_ids": self.markdown_gap_ids}
