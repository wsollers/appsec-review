"""Typed ``[reporting.efficacy_report]`` settings for target archival, RoR and smoke efficacy reports."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
from typing import Any, Mapping

from appsec_review.storage import canonical_json

DEFAULT_HISTORY_DIR = "runs/metadata/finding-history"
DEFAULT_SMOKE_GUIDE_DIR = "../appsec-review-smoke-guide"
_BOUNDS = {"timeout_seconds": 3600, "max_tex_bytes": 67_108_864, "max_pdf_bytes": 67_108_864}


@dataclass(frozen=True, slots=True)
class EfficacyReportSettings:
    enabled: bool = True
    render_pdf: bool = True
    auto_smoke_score: bool = True
    history_dir: str = DEFAULT_HISTORY_DIR
    smoke_guide_dir: str = DEFAULT_SMOKE_GUIDE_DIR
    timeout_seconds: int = 600
    max_tex_bytes: int = 8_388_608
    max_pdf_bytes: int = 16_777_216

    def view(self) -> dict[str, Any]:
        return asdict(self)

    def settings_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.view())).hexdigest()


def parse_efficacy_report(value: object) -> EfficacyReportSettings:
    """Validate the section; absent keys take the defaults, unknown keys are rejected."""
    if value is None:
        return EfficacyReportSettings()
    if not isinstance(value, Mapping):
        raise ValueError("[reporting.efficacy_report] must be a table")
    known = {field.name for field in fields(EfficacyReportSettings)}
    unknown = set(value) - known
    if unknown:
        raise ValueError("reporting.efficacy_report has unknown settings: " + ", ".join(sorted(unknown)))
    for key in ("enabled", "render_pdf", "auto_smoke_score"):
        if key in value and type(value[key]) is not bool:
            raise ValueError(f"reporting.efficacy_report.{key} must be a boolean")
    for key, maximum in _BOUNDS.items():
        if key in value and (type(value[key]) is not int or not 1 <= value[key] <= maximum):
            raise ValueError(f"reporting.efficacy_report.{key} must be an integer in [1, {maximum}]")
    for key in ("history_dir", "smoke_guide_dir"):
        if key in value:
            raw = value[key]
            if (not isinstance(raw, str) or not raw.strip()
                    or any(ch in raw for ch in ("\x00", "\n", "\r")) or raw.startswith("-")):
                raise ValueError(f"reporting.efficacy_report.{key} must be a nonempty path string")
    return EfficacyReportSettings(**dict(value))


__all__ = [
    "DEFAULT_HISTORY_DIR",
    "DEFAULT_SMOKE_GUIDE_DIR",
    "EfficacyReportSettings",
    "parse_efficacy_report",
]
