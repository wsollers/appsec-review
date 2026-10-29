"""Typed ``[reporting.telemetry_report]`` settings for the end-of-review telemetry PDF."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import re
from typing import Any, Mapping

from appsec_review.storage import canonical_json

# The same pinned tool-report-latex image as jobs.job_dossier_publication.settings.
DEFAULT_IMAGE_TAG = "appsec-review/tool-report-latex:1.0.0"
DEFAULT_IMAGE_ID = "sha256:1dd77c969bba00168bc3128e5ee8290328dd06c09ecd4d845618c3c6336530e4"
_BOUNDS = {"timeout_seconds": 600, "max_tex_bytes": 67108864, "max_pdf_bytes": 67108864}


@dataclass(frozen=True, slots=True)
class TelemetryReportSettings:
    enabled: bool = True
    render_pdf: bool = True
    image_tag: str = DEFAULT_IMAGE_TAG
    image_id: str = DEFAULT_IMAGE_ID
    timeout_seconds: int = 600
    max_tex_bytes: int = 8388608
    max_pdf_bytes: int = 16777216

    def view(self) -> dict[str, Any]:
        return asdict(self)

    def settings_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.view())).hexdigest()


def parse_telemetry_report(value: object) -> TelemetryReportSettings:
    """Validate the section; absent keys take the defaults, unknown keys are rejected."""
    if value is None:
        return TelemetryReportSettings()
    if not isinstance(value, Mapping):
        raise ValueError("[reporting.telemetry_report] must be a table")
    known = {field.name for field in fields(TelemetryReportSettings)}
    unknown = set(value) - known
    if unknown:
        raise ValueError("reporting.telemetry_report has unknown settings: " + ", ".join(sorted(unknown)))
    for key in ("enabled", "render_pdf"):
        if key in value and type(value[key]) is not bool:
            raise ValueError(f"reporting.telemetry_report.{key} must be a boolean")
    for key, maximum in _BOUNDS.items():
        if key in value and (type(value[key]) is not int or not 1 <= value[key] <= maximum):
            raise ValueError(f"reporting.telemetry_report.{key} must be an integer in [1, {maximum}]")
    if "image_id" in value and (not isinstance(value["image_id"], str)
                                or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"])):
        raise ValueError("reporting.telemetry_report.image_id must be an immutable sha256 image identity")
    tag = value.get("image_tag", DEFAULT_IMAGE_TAG)
    if not isinstance(tag, str) or not tag or any(c.isspace() for c in tag) or tag.startswith("-"):
        raise ValueError("reporting.telemetry_report.image_tag must be a nonempty image tag")
    return TelemetryReportSettings(**dict(value))
