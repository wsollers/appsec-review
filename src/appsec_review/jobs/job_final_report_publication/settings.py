"""Typed configuration for ``job_final_report_publication``.

The report calls no model, so there is no provider, model or budget setting. Two tunables shorten
identifier lists in the human-readable Markdown (``final-report.json`` always carries every
identifier); the rest pin the executive PDF renderer: whether to run it, the ``tool-report-latex``
image tag and its immutable id (bound from the host pins at configuration load), the container
timeout and the byte bound for the LaTeX, the PDF and the retained renderer logs.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import re
from typing import Any

from appsec_review.storage import canonical_json

_KEYS = frozenset({"enabled", "markdown_evidence_ids", "markdown_gap_ids", "render_pdf", "image_tag", "image_id",
                   "render_timeout_seconds", "max_pdf_bytes"})
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_BOUNDS = {"render_timeout_seconds": (1, 600), "max_pdf_bytes": (1, 67108864)}


@dataclass(frozen=True, slots=True)
class FinalReportSettings:
    enabled: bool
    markdown_evidence_ids: int
    markdown_gap_ids: int
    render_pdf: bool
    image_tag: str
    image_id: str
    render_timeout_seconds: int
    max_pdf_bytes: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "FinalReportSettings":
        prefix = "jobs.job_final_report_publication.settings"
        if not isinstance(value, Mapping) or set(value) != _KEYS:
            unknown = sorted(set(value) - _KEYS) if isinstance(value, Mapping) else []
            missing = sorted(_KEYS - set(value)) if isinstance(value, Mapping) else sorted(_KEYS)
            raise ValueError(f"{prefix} must define exactly its documented keys (unknown: {unknown}, missing: {missing})")
        for key in ("enabled", "render_pdf"):
            if not isinstance(value[key], bool):
                raise ValueError(f"{prefix}.{key} must be a boolean")
        for key in ("markdown_evidence_ids", "markdown_gap_ids"):
            if type(value[key]) is not int or not 0 <= value[key] <= 256:
                raise ValueError(f"{prefix}.{key} must be an integer in [0, 256]")
        for key, (low, high) in _BOUNDS.items():
            if type(value[key]) is not int or not low <= value[key] <= high:
                raise ValueError(f"{prefix}.{key} must be an integer in [{low}, {high}]")
        tag = value["image_tag"]
        if not isinstance(tag, str) or not tag or any(c.isspace() for c in tag) or tag.startswith("-"):
            raise ValueError(f"{prefix}.image_tag must be a nonempty image tag")
        if not isinstance(value["image_id"], str) or not _IMAGE_ID.fullmatch(value["image_id"]):
            raise ValueError(f"{prefix}.image_id must be an immutable sha256 image identity")
        return cls(value["enabled"], value["markdown_evidence_ids"], value["markdown_gap_ids"], value["render_pdf"],
                   tag, value["image_id"], value["render_timeout_seconds"], value["max_pdf_bytes"])

    def identity(self) -> dict[str, int]:
        """The settings that change the bytes of ``final-report.md``."""
        return {"markdown_evidence_ids": self.markdown_evidence_ids, "markdown_gap_ids": self.markdown_gap_ids}

    def pdf_identity(self) -> dict[str, Any]:
        """The settings that govern the executive PDF rendering."""
        return {"render_pdf": self.render_pdf, "image_tag": self.image_tag, "image_id": self.image_id,
                "render_timeout_seconds": self.render_timeout_seconds, "max_pdf_bytes": self.max_pdf_bytes}

    def settings_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.pdf_identity())).hexdigest()
