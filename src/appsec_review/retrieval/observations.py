"""Versioned scanner-observation normalization shared by producers and retrieval.

Normalization reads already-indexed observation payloads; it never parses raw scanner output.
A normalized *reported* severity orders review attention only. It is not an adjudicated technical
severity, and an unmapped native label stays ``unknown`` instead of being read as low.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

from appsec_review.interchange import (
    ObservationMetadata, RecordKind, gap_id, observation_metadata_from_mapping,
)


SEVERITY_RULE = "appsec-review/reported-severity/1"
REPORTED_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_ORDER = {name: position for position, name in enumerate(REPORTED_SEVERITIES)}
OBSERVATION_CLASSES = (
    "source_sast", "secret", "dependency", "configuration", "inventory", "binary", "diagnostic", "other",
)

# ``record_kind`` of a job_artifact_security_analysis observation (schema artifact-security-record/2): one
# ``finding`` per scanner finding, one ``scan_summary`` per artifact scan (the account that a scan ran).
RECORD_KIND_FINDING, RECORD_KIND_SUMMARY = "finding", "scan_summary"

_LABELS = {
    "CRITICAL": "critical", "BLOCKER": "critical", "VERY_HIGH": "critical", "SEVERE": "critical",
    "HIGH": "high", "ERROR": "high", "MAJOR": "high",
    "MEDIUM": "medium", "MODERATE": "medium", "WARNING": "medium", "WARN": "medium",
    "LOW": "low", "MINOR": "low",
    "INFO": "info", "INFORMATIONAL": "info", "NOTE": "info", "STYLE": "info", "NONE": "info",
}
# Numeric labels are scanner specific; a bare number from an unknown scanner stays unmapped.
_SCANNER_LABELS = {
    "tool-spotbugs": {"1": "high", "2": "medium", "3": "low"},
}
# Category -> observation class. Parsers emit the true category of their scanner and never the retired generic
# ``static_analysis``, which classified as ``other`` and silently dropped those scanners from lead correlation:
#   gitleaks   secret_detection -> secret
#   shellcheck shell_lint       -> source_sast     (static analysis of shell source; inline ``shellcheck disable``)
#   psalm      source_sast      -> source_sast     (PHP type and taint analysis: the category phpstan and phpcs use)
#   hadolint   config_lint      -> configuration   (Dockerfile lint)
#   zizmor     ci_security      -> configuration   (GitHub Actions workflow audit)
# Artifact-security records (job_artifact_security_analysis, record schema artifact-security-record/2): a finding
# carries its scanner category (``binary_hardening``, ``vulnerability_matching``, ``bytecode_analysis``), a scan-run
# summary carries ``software_inventory`` (inventory scans) or ``tool_diagnostic`` (every other scan).
_CLASS_BY_CATEGORY = {
    "source_sast": "source_sast", "shell_lint": "source_sast",
    "secret": "secret", "secret_detection": "secret", "secrets": "secret",
    "vulnerability_matching": "dependency", "dependency": "dependency", "configuration": "configuration",
    "iac": "configuration", "workflow": "configuration", "config_lint": "configuration",
    "ci_security": "configuration", "software_inventory": "inventory",
    "binary": "binary", "binary_hardening": "binary", "tool_diagnostic": "diagnostic",
}

def common_of(payload: Mapping[str, Any]) -> ObservationMetadata | None:
    """Absence permits legacy semantics; a malformed common record never does."""
    return observation_metadata_from_mapping(payload["common"]) if "common" in payload else None


def scanner_of(payload: Mapping[str, Any]) -> str:
    """Return the indexed scanner/provider identity without consulting raw output."""
    common = common_of(payload)
    if common is not None:
        return common.scanner
    tool = payload.get("tool_identity")
    for value in (payload.get("tool_id"), payload.get("scanner_identity"), payload.get("producer"),
                  tool.get("id") if isinstance(tool, Mapping) else None, payload.get("tool")):
        if isinstance(value, str) and value:
            return value
    return "unknown"


def rule_of(payload: Mapping[str, Any]) -> str:
    common = common_of(payload)
    if common is not None:
        return common.rule_id
    for key in ("native_rule_id", "rule_id", "rule"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def native_severity_of(payload: Mapping[str, Any]) -> str:
    common = common_of(payload)
    if common is not None:
        return common.reported_severity["native"]
    for key in ("native_severity", "producer_level", "level", "severity"):
        value = payload.get(key)
        if value not in (None, ""):
            return str(value)[:128]
    return "UNKNOWN"


def classify(payload: Mapping[str, Any]) -> str:
    """Observation class; CodeQL results are source-SAST leads by producer identity."""
    common = common_of(payload)
    if common is not None:
        return common.observation_class
    if scanner_of(payload) == "codeql":
        return "source_sast"
    return _CLASS_BY_CATEGORY.get(str(payload.get("category") or "").lower(), "other")


def normalize_reported_severity(payload: Mapping[str, Any]) -> dict[str, str]:
    """Return ``{value, native, basis, rule}`` for one indexed observation payload."""
    common = common_of(payload)
    if common is not None:
        return dict(common.reported_severity)
    native = native_severity_of(payload)
    score = payload.get("security_severity")
    if score is not None and not isinstance(score, bool):
        try:
            number = float(score)
        except (TypeError, ValueError):
            number = math.nan
        if math.isfinite(number) and 0.0 <= number <= 10.0:
            value = ("critical" if number >= 9.0 else "high" if number >= 7.0 else
                     "medium" if number >= 4.0 else "low" if number > 0.0 else "info")
            return {"value": value, "native": native, "basis": "security-severity-cvss-band", "rule": SEVERITY_RULE}
    label = native.strip().upper().replace(" ", "_")
    scanner_labels = _SCANNER_LABELS.get(scanner_of(payload), {})
    if label in scanner_labels:
        return {"value": scanner_labels[label], "native": native, "basis": "scanner-native-label",
                "rule": SEVERITY_RULE}
    if label in _LABELS:
        return {"value": _LABELS[label], "native": native, "basis": "native-label", "rule": SEVERITY_RULE}
    return {"value": "unknown", "native": native, "basis": "unmapped-native-severity", "rule": SEVERITY_RULE}


def observation_projection(payload: Mapping[str, Any]) -> ObservationMetadata:
    """Project legacy indexed semantics without inventing native evidence provenance."""
    common = common_of(payload)
    if common is not None:
        return common
    scanner, rule = scanner_of(payload), rule_of(payload)
    return ObservationMetadata(
        classify(payload), payload.get("record_kind", RecordKind.OBSERVATION), scanner, rule,
        normalize_reported_severity(payload), (),
        (gap_id({"code": "provenance_unavailable", "scanner": scanner, "rule_id": rule}),),
        str(payload.get("schema") or "unversioned"),
    )
