"""Pinned schema digests for ``job_detailed_finding_report``."""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from appsec_review.jobs.engineering_contracts import (
    DETAILED_FINDING_REPORT_HANDOFF_SCHEMA,
    DETAILED_FINDING_REPORT_SCHEMA,
)

DETAILED_FINDING_REPORT_SCHEMA_SHA256: Mapping[str, str] = MappingProxyType({
    "detailed-finding-report-handoff.schema.json": "bd3d0fea3a6bff68ef28fd6060453106a86ca4efd80df1e64d20afc19b519a6f",
    "detailed-finding-report.schema.json": "1a62342d5a589b0841e998a8a133a9f4466c10be4baf8b4bdd3514bcccb82b36",
})

GATE_SCHEMA_SHA256: Mapping[str, str] = MappingProxyType({
    "common.schema.json": "5a81b5d22f8b55c5261e9b00b683f313a66e30f4263412815c2e22c70129add5",
    "final-publication-gate.schema.json": "14b45f53dbde7265573137bbe1b458e167f9e298953c67a4510475e9241af252",
    "final-report-pdf-receipt.schema.json": "e7251e7025f9effd79a7390a1ae6119bd101eaf69d91c31d9b3f1ef57199134a",
})

__all__ = [
    "DETAILED_FINDING_REPORT_HANDOFF_SCHEMA",
    "DETAILED_FINDING_REPORT_SCHEMA",
    "DETAILED_FINDING_REPORT_SCHEMA_SHA256",
    "GATE_SCHEMA_SHA256",
]
