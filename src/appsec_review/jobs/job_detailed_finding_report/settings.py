"""Typed configuration for ``job_detailed_finding_report``."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import re
from typing import Any

from appsec_review.storage import canonical_json

DEFAULT_IMAGE_TAG = "appsec-review/tool-report-latex:1.0.0"
DEFAULT_IMAGE_ID = "sha256:" + "0" * 64

_REQUIRED_KEYS = frozenset({
    "enabled",
    "include_backlog",
    "max_fanout_nodes",
    "max_cfg_nodes",
    "render_pdf",
    "image_tag",
    "render_timeout_seconds",
    "max_pdf_bytes",
})
_ALLOWED_KEYS = _REQUIRED_KEYS | {"image_id"}
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_BOUNDS = {
    "max_fanout_nodes": (3, 64),
    "max_cfg_nodes": (3, 64),
    "render_timeout_seconds": (1, 600),
    "max_pdf_bytes": (1, 67108864),
}


@dataclass(frozen=True, slots=True)
class DetailedFindingReportSettings:
    enabled: bool
    include_backlog: bool
    max_fanout_nodes: int
    max_cfg_nodes: int
    render_pdf: bool
    image_tag: str
    image_id: str
    render_timeout_seconds: int
    max_pdf_bytes: int

    @classmethod
    def defaults(cls) -> "DetailedFindingReportSettings":
        """Fallback settings used only when synthetic unit harnesses omit ``settings``."""
        return cls(
            enabled=True,
            include_backlog=False,
            max_fanout_nodes=12,
            max_cfg_nodes=14,
            render_pdf=False,
            image_tag=DEFAULT_IMAGE_TAG,
            image_id=DEFAULT_IMAGE_ID,
            render_timeout_seconds=600,
            max_pdf_bytes=33554432,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "DetailedFindingReportSettings":
        prefix = "jobs.job_detailed_finding_report.settings"
        if not isinstance(value, Mapping):
            raise ValueError(
                f"{prefix} must define its documented keys (unknown: [], missing: {sorted(_REQUIRED_KEYS)})"
            )
        unknown = sorted(set(value) - _ALLOWED_KEYS)
        missing = sorted(_REQUIRED_KEYS - set(value))
        if unknown or missing:
            raise ValueError(
                f"{prefix} must define its documented keys (unknown: {unknown}, missing: {missing})"
            )
        for key in ("enabled", "include_backlog", "render_pdf"):
            if not isinstance(value[key], bool):
                raise ValueError(f"{prefix}.{key} must be a boolean")
        for key, (low, high) in _BOUNDS.items():
            if type(value[key]) is not int or not low <= value[key] <= high:
                raise ValueError(f"{prefix}.{key} must be an integer in [{low}, {high}]")
        tag = value["image_tag"]
        if not isinstance(tag, str) or not tag or any(c.isspace() for c in tag) or tag.startswith("-"):
            raise ValueError(f"{prefix}.image_tag must be a nonempty image tag")
        if "image_id" in value:
            raw_image_id = value["image_id"]
            if not isinstance(raw_image_id, str) or not _IMAGE_ID.fullmatch(raw_image_id):
                raise ValueError(f"{prefix}.image_id must be an immutable sha256 image identity")
            image_id = raw_image_id
        elif value["render_pdf"]:
            raise ValueError(f"{prefix}.image_id must be an immutable sha256 image identity")
        else:
            image_id = DEFAULT_IMAGE_ID
        return cls(
            enabled=value["enabled"],
            include_backlog=value["include_backlog"],
            max_fanout_nodes=value["max_fanout_nodes"],
            max_cfg_nodes=value["max_cfg_nodes"],
            render_pdf=value["render_pdf"],
            image_tag=tag,
            image_id=image_id,
            render_timeout_seconds=value["render_timeout_seconds"],
            max_pdf_bytes=value["max_pdf_bytes"],
        )

    def identity(self) -> dict[str, Any]:
        """Settings that govern deterministic report assembly and diagram slicing."""
        return {
            "include_backlog": self.include_backlog,
            "max_fanout_nodes": self.max_fanout_nodes,
            "max_cfg_nodes": self.max_cfg_nodes,
        }

    def pdf_identity(self) -> dict[str, Any]:
        """Settings that govern vector LaTeX/PDF compilation."""
        return {
            "render_pdf": self.render_pdf,
            "image_tag": self.image_tag,
            "image_id": self.image_id,
            "render_timeout_seconds": self.render_timeout_seconds,
            "max_pdf_bytes": self.max_pdf_bytes,
        }

    def settings_sha256(self) -> str:
        return hashlib.sha256(canonical_json({**self.identity(), **self.pdf_identity()})).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "include_backlog": self.include_backlog,
            "max_fanout_nodes": self.max_fanout_nodes,
            "max_cfg_nodes": self.max_cfg_nodes,
            "render_pdf": self.render_pdf,
            "image_tag": self.image_tag,
            "image_id": self.image_id,
            "render_timeout_seconds": self.render_timeout_seconds,
            "max_pdf_bytes": self.max_pdf_bytes,
        }
