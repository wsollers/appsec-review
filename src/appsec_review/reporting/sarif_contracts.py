"""Typed contracts for the final report's SARIF export."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from appsec_review.reporting.sarif import SARIF_SCHEMA_URI, SARIF_VERSION

SARIF_DOCUMENT_NAME = "findings.sarif"
SARIF_RESULT_NAME = "sarif-export-result.json"
SARIF_EXPORT_RESULT_SCHEMA = "appsec-review/sarif-export-result/1"


@dataclass(frozen=True)
class SarifExportBundle:
    sarif_log: dict[str, Any]
    sarif_bytes: bytes
    sarif_sha256: str
    result: dict[str, Any]
    telemetry: dict[str, Any]
    gaps: tuple[dict[str, Any], ...]
