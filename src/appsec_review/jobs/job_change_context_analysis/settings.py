"""Typed, closed configuration for change-context analysis.

Every threshold, weight, data-source switch, and bound comes from
``[jobs.job_change_context_analysis.settings]``.  Unknown keys, out-of-range bounds, and malformed
patterns fail validation; nothing here falls back to a silent default.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any


WEEKDAYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
REVIEW_SOURCES = ("github_enrichment", "export", "none")
PRIORITY_SIGNALS = (
    "fast_review_change_count", "stale_approval_change_count", "unapproved_mainline_change_count",
    "off_hours_change_count", "pre_deployment_change_count", "sprawling_change_count",
    "repeated_repair_peak", "fix_on_fix_event_count", "untested_production_change_count",
    "lifetime_principal_author_share", "departed_dominant_owner",
)
_TIME = re.compile(r"([01]\d|2[0-3]):([0-5]\d)")
_ZONE = re.compile(r"[A-Za-z][A-Za-z0-9_+-]{0,63}(?:/[A-Za-z0-9_+-]{1,63}){0,3}")
_PATTERN = re.compile(r"[A-Za-z0-9_.*?/{},+-]{1,256}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ExportSource:
    """An operator-supplied, hash-pinned JSON export resolved relative to the repository root."""

    enabled: bool
    export_path: str
    export_sha256: str


@dataclass(frozen=True, slots=True)
class ReviewSettings:
    source: str
    export: ExportSource
    fast_review_seconds: int


@dataclass(frozen=True, slots=True)
class ScheduleSettings:
    time_zone: str
    business_start_minute: int
    business_end_minute: int
    weekend_days: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DeploymentSettings:
    export: ExportSource
    environments: tuple[str, ...]
    pre_deployment_window_seconds: int


@dataclass(frozen=True, slots=True)
class SprawlSettings:
    min_unrelated_groups: int
    min_churn_lines: int
    min_group_entropy: float
    related_component_min_support: int


@dataclass(frozen=True, slots=True)
class RepairSettings:
    window_days: int
    min_fix_changes: int
    fix_on_fix_max_checks: int


@dataclass(frozen=True, slots=True)
class TestAssociationSettings:
    enabled: bool
    production_extensions: tuple[str, ...]
    test_patterns: tuple[str, ...]
    contract_patterns: tuple[str, ...]
    min_production_churn_lines: int


@dataclass(frozen=True, slots=True)
class OwnershipSettings:
    dominant_owner_share: float
    bus_factor_share: float
    line_attribution_max_files: int
    line_attribution_max_file_bytes: int


@dataclass(frozen=True, slots=True)
class ChangeContextSettings:
    ranking_top_files: int
    ranking_top_functions: int
    ranking_top_components: int
    supporting_change_limit: int
    review: ReviewSettings
    schedule: ScheduleSettings
    deployments: DeploymentSettings
    scope_sprawl: SprawlSettings
    repeated_repairs: RepairSettings
    test_association: TestAssociationSettings
    ownership: OwnershipSettings
    organization: ExportSource
    priority_weights: Mapping[str, float]


def _table(value: Any, field: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"change context setting must be a table: {field}")
    if set(value) != keys:
        missing, unknown = sorted(keys - set(value)), sorted(set(value) - keys)
        raise ValueError(f"change context setting {field} keys are invalid: missing={missing} unknown={unknown}")
    return value


def _int(table: Mapping[str, Any], key: str, low: int, high: int, field: str) -> int:
    value = table[key]
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"change context setting is invalid: {field}.{key}")
    return value


def _share(table: Mapping[str, Any], key: str, field: str, *, inclusive_zero: bool = False) -> float:
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"change context setting is invalid: {field}.{key}")
    if not (0 <= float(value) <= 1 if inclusive_zero else 0 < float(value) <= 1):
        raise ValueError(f"change context setting is invalid: {field}.{key}")
    return float(value)


def _strings(table: Mapping[str, Any], key: str, field: str, pattern: re.Pattern[str], *,
             allow_empty: bool = False) -> tuple[str, ...]:
    values = table[key]
    if (not isinstance(values, list) or (not values and not allow_empty) or len(values) > 256 or
            not all(isinstance(item, str) and pattern.fullmatch(item) for item in values) or
            len(set(values)) != len(values)):
        raise ValueError(f"change context setting is invalid: {field}.{key}")
    return tuple(values)


def _export(table: Mapping[str, Any], field: str, *, enabled: bool) -> ExportSource:
    path, digest = table["export_path"], table["export_sha256"]
    if not isinstance(path, str) or len(path) > 1024 or "\x00" in path:
        raise ValueError(f"change context setting is invalid: {field}.export_path")
    if not isinstance(digest, str) or (digest and not _SHA256.fullmatch(digest)):
        raise ValueError(f"change context setting is invalid: {field}.export_sha256")
    if enabled and not path:
        raise ValueError(f"change context setting {field} is enabled without export_path")
    return ExportSource(enabled, path, digest)


def _clock(value: Any, field: str) -> int:
    match = _TIME.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError(f"change context setting is invalid: {field}")
    return int(match.group(1)) * 60 + int(match.group(2))


def parse_settings(raw: Mapping[str, Any]) -> ChangeContextSettings:
    top = _table(raw, "settings", {
        "ranking_top_files", "ranking_top_functions", "ranking_top_components", "supporting_change_limit",
        "review", "schedule", "deployments", "scope_sprawl", "repeated_repairs", "test_association",
        "ownership", "organization", "priority_weights"})
    review = _table(top["review"], "review", {"source", "export_path", "export_sha256", "fast_review_seconds"})
    if review["source"] not in REVIEW_SOURCES:
        raise ValueError("change context setting is invalid: review.source")
    schedule = _table(top["schedule"], "schedule", {"time_zone", "business_hours_start", "business_hours_end",
                                                    "weekend_days"})
    zone = schedule["time_zone"]
    if not isinstance(zone, str) or (zone and (not _ZONE.fullmatch(zone) or ".." in zone)):
        raise ValueError("change context setting is invalid: schedule.time_zone")
    start = _clock(schedule["business_hours_start"], "schedule.business_hours_start")
    end = _clock(schedule["business_hours_end"], "schedule.business_hours_end")
    if start >= end:
        raise ValueError("change context business hours must start before they end")
    weekend = schedule["weekend_days"]
    if (not isinstance(weekend, list) or len(set(weekend)) != len(weekend) or
            not all(item in WEEKDAYS for item in weekend) or len(weekend) > 6):
        raise ValueError("change context setting is invalid: schedule.weekend_days")
    deployments = _table(top["deployments"], "deployments", {
        "enabled", "export_path", "export_sha256", "environments", "pre_deployment_window_hours"})
    if type(deployments["enabled"]) is not bool:
        raise ValueError("change context setting is invalid: deployments.enabled")
    sprawl = _table(top["scope_sprawl"], "scope_sprawl", {
        "min_unrelated_groups", "min_churn_lines", "min_group_entropy", "related_component_min_support"})
    repairs = _table(top["repeated_repairs"], "repeated_repairs", {
        "window_days", "min_fix_changes", "fix_on_fix_max_checks"})
    tests = _table(top["test_association"], "test_association", {
        "enabled", "production_extensions", "test_patterns", "contract_patterns", "min_production_churn_lines"})
    if type(tests["enabled"]) is not bool:
        raise ValueError("change context setting is invalid: test_association.enabled")
    ownership = _table(top["ownership"], "ownership", {
        "dominant_owner_share", "bus_factor_share", "line_attribution_max_files", "line_attribution_max_file_bytes"})
    organization = _table(top["organization"], "organization", {"enabled", "export_path", "export_sha256"})
    if type(organization["enabled"]) is not bool:
        raise ValueError("change context setting is invalid: organization.enabled")
    weights = top["priority_weights"]
    if not isinstance(weights, Mapping) or not weights:
        raise ValueError("change context priority weights are required")
    for key, value in weights.items():
        if key not in PRIORITY_SIGNALS:
            raise ValueError(f"unknown change context priority signal: {key}")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ValueError(f"change context priority weight is invalid: {key}")
    if not any(float(value) > 0 for value in weights.values()):
        raise ValueError("change context priority needs at least one positive weight")
    extensions = _strings(tests, "production_extensions", "test_association", re.compile(r"\.[A-Za-z0-9+_-]{1,16}"))
    return ChangeContextSettings(
        ranking_top_files=_int(top, "ranking_top_files", 1, 10_000, "settings"),
        ranking_top_functions=_int(top, "ranking_top_functions", 0, 10_000, "settings"),
        ranking_top_components=_int(top, "ranking_top_components", 1, 10_000, "settings"),
        supporting_change_limit=_int(top, "supporting_change_limit", 1, 200, "settings"),
        review=ReviewSettings(review["source"], _export(review, "review", enabled=review["source"] == "export"),
                              _int(review, "fast_review_seconds", 1, 86_400, "review")),
        schedule=ScheduleSettings(zone, start, end, tuple(WEEKDAYS.index(item) for item in weekend)),
        deployments=DeploymentSettings(
            _export(deployments, "deployments", enabled=deployments["enabled"]),
            _strings(deployments, "environments", "deployments", re.compile(r"[A-Za-z0-9_.:/-]{1,128}")),
            _int(deployments, "pre_deployment_window_hours", 1, 24 * 30, "deployments") * 3600),
        scope_sprawl=SprawlSettings(
            _int(sprawl, "min_unrelated_groups", 2, 1000, "scope_sprawl"),
            _int(sprawl, "min_churn_lines", 0, 10_000_000, "scope_sprawl"),
            _share(sprawl, "min_group_entropy", "scope_sprawl", inclusive_zero=True),
            _int(sprawl, "related_component_min_support", 1, 10_000, "scope_sprawl")),
        repeated_repairs=RepairSettings(
            _int(repairs, "window_days", 1, 3650, "repeated_repairs"),
            _int(repairs, "min_fix_changes", 2, 1000, "repeated_repairs"),
            _int(repairs, "fix_on_fix_max_checks", 0, 10_000, "repeated_repairs")),
        test_association=TestAssociationSettings(
            tests["enabled"], tuple(item.lower() for item in extensions),
            _strings(tests, "test_patterns", "test_association", _PATTERN),
            _strings(tests, "contract_patterns", "test_association", _PATTERN, allow_empty=True),
            _int(tests, "min_production_churn_lines", 1, 10_000_000, "test_association")),
        ownership=OwnershipSettings(
            _share(ownership, "dominant_owner_share", "ownership"),
            _share(ownership, "bus_factor_share", "ownership"),
            _int(ownership, "line_attribution_max_files", 0, 10_000, "ownership"),
            _int(ownership, "line_attribution_max_file_bytes", 1, 16 * 1024 * 1024, "ownership")),
        organization=_export(organization, "organization", enabled=organization["enabled"]),
        priority_weights={key: float(weights[key]) for key in sorted(weights)},
    )
