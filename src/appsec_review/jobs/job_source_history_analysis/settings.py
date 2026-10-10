"""Typed, validated settings for ``job_source_history_analysis``.

Every bound, weight, interval, and path rule lives in central TOML; this module only parses and
rejects.  Unknown keys fail validation so a stale or misspelled setting never silently falls back.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
import re
from typing import Any

from .github import GitHubSettings


SII_METRICS = ("relative_churn", "revision_frequency", "author_entropy", "complexity")
COMPLEXITY_METRICS = ("cyclomatic", "cognitive")
FILTER_CATEGORIES = ("generated", "lockfile", "fixture", "documentation", "vendored")
_INTEGERS = {
    "history_window_months": (1, 120), "hotspot_count": (1, 100), "max_changes": (1, 200_000),
    "bulk_change_file_threshold": (1, 100_000), "recency_half_life_days": (1, 3650), "young_line_days": (1, 3650),
    "co_change_top_k": (1, 100), "co_change_min_support": (1, 10_000), "blame_max_files": (0, 10_000),
    "blame_max_file_bytes": (1, 16 * 1024 * 1024), "ranking_top_n": (1, 10_000),
}
_TABLES = {"fix_on_fix", "line_history", "symbols", "sii", "filters", "git", "github"}
_LISTS = {"fix_labels", "security_labels"}
_SCALARS = {"minor_author_share"}
_GLOB = re.compile(r"[A-Za-z0-9_.*?/@+-]{1,256}")


@dataclass(frozen=True, slots=True)
class FilterRules:
    """Path rules that exclude files from ranking; ``test`` paths only feed production-to-test churn."""

    generated: tuple[str, ...]
    lockfile: tuple[str, ...]
    fixture: tuple[str, ...]
    documentation: tuple[str, ...]
    vendored: tuple[str, ...]
    test: tuple[str, ...]
    formatting_balance_tolerance: float

    def category_patterns(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return tuple((name, getattr(self, name)) for name in FILTER_CATEGORIES)


@dataclass(frozen=True, slots=True)
class SiiSettings:
    weights: Mapping[str, float]
    complexity_metric: str
    tier_1_share: Fraction
    tier_2_share: Fraction


@dataclass(frozen=True, slots=True)
class HistorySettings:
    history_window_months: int
    hotspot_count: int
    max_changes: int
    bulk_change_file_threshold: int
    recency_half_life_days: int
    minor_author_share: float
    young_line_days: int
    co_change_top_k: int
    co_change_min_support: int
    blame_max_files: int
    blame_max_file_bytes: int
    ranking_top_n: int
    fix_labels: tuple[str, ...]
    security_labels: tuple[str, ...]
    fix_on_fix_interval_days: int
    line_history_max_files: int
    line_history_max_file_bytes: int
    symbols_enabled: bool
    symbols_max_files: int
    symbols_max_file_bytes: int
    symbols_max_nodes_per_file: int
    sii: SiiSettings
    filters: FilterRules
    git_enabled: bool
    github: Mapping[str, Any]


def _table(settings: Mapping[str, Any], name: str, keys: set[str]) -> Mapping[str, Any]:
    value = settings.get(name)
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"source history {name} settings are invalid")
    return value


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"source history setting is invalid: {name}")
    return value


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"source history setting is invalid: {name}")
    return float(value)


def _patterns(value: Any, name: str) -> tuple[str, ...]:
    # Patterns are target-relative: no absolute paths, empty segments, or dot segments.
    if not isinstance(value, list) or len(value) > 256 or not all(
            isinstance(item, str) and _GLOB.fullmatch(item) and
            all(part not in {"", ".", ".."} for part in item.split("/")) for item in value):
        raise ValueError(f"source history filter patterns are invalid: {name}")
    return tuple(value)


def parse_settings(settings: Mapping[str, Any]) -> HistorySettings:
    """Validate the job's settings table and return its typed form."""
    unknown = set(settings) - set(_INTEGERS) - _TABLES - _LISTS - _SCALARS
    if unknown:
        raise ValueError(f"unknown source history setting: {sorted(unknown)[0]}")
    integers = {key: _integer(settings.get(key), key, *bounds) for key, bounds in _INTEGERS.items()}
    share = _number(settings.get("minor_author_share"), "minor_author_share")
    if not 0 < share < 1:
        raise ValueError("source history setting is invalid: minor_author_share")
    labels = {}
    for key in sorted(_LISTS):
        values = settings.get(key)
        if not isinstance(values, list) or not all(isinstance(item, str) and 0 < len(item) <= 64 for item in values):
            raise ValueError(f"source history setting is invalid: {key}")
        labels[key] = tuple(values)
    fix_on_fix = _table(settings, "fix_on_fix", {"interval_days"})
    # The reviewed fix-on-fix cadence is two to four weeks; wider intervals stop meaning "rework".
    interval = _integer(fix_on_fix["interval_days"], "fix_on_fix.interval_days", 14, 30)
    lines = _table(settings, "line_history", {"max_files", "max_file_bytes"})
    symbols = _table(settings, "symbols", {"enabled", "max_files", "max_file_bytes", "max_nodes_per_file"})
    if type(symbols["enabled"]) is not bool:
        raise ValueError("source history setting is invalid: symbols.enabled")
    sii = _table(settings, "sii", {"weights", "complexity_metric", "tier_1_share", "tier_2_share"})
    weights = sii["weights"]
    if not isinstance(weights, Mapping) or set(weights) != set(SII_METRICS):
        raise ValueError("source history SII weights must name exactly: " + ", ".join(SII_METRICS))
    parsed_weights = {key: _number(weights[key], f"sii.weights.{key}") for key in SII_METRICS}
    if any(value < 0 for value in parsed_weights.values()) or not any(value > 0 for value in parsed_weights.values()):
        raise ValueError("source history SII weights must be non-negative with at least one positive weight")
    if sii["complexity_metric"] not in COMPLEXITY_METRICS:
        raise ValueError("source history SII complexity_metric must be cyclomatic or cognitive")
    # Fractions from the decimal text keep tier boundaries exact (0.05 * 100 is exactly 5).
    tier_1 = Fraction(str(_number(sii["tier_1_share"], "sii.tier_1_share")))
    tier_2 = Fraction(str(_number(sii["tier_2_share"], "sii.tier_2_share")))
    if not (0 < tier_1 < 1 and 0 < tier_2 < 1 and tier_1 + tier_2 < 1):
        raise ValueError("source history SII tier shares must be positive and leave a Tier 3 remainder")
    filters = _table(settings, "filters", {*FILTER_CATEGORIES, "test", "formatting_balance_tolerance"})
    tolerance = _number(filters["formatting_balance_tolerance"], "filters.formatting_balance_tolerance")
    if not 0 <= tolerance < 1:
        raise ValueError("source history setting is invalid: filters.formatting_balance_tolerance")
    git = _table(settings, "git", {"enabled"})
    if type(git["enabled"]) is not bool:
        raise ValueError("source history git settings are invalid")
    github = _table(settings, "github", {"enabled", "api_base", "repository", "token_env", "max_requests",
                                         "timeout_seconds"})
    if type(github["enabled"]) is not bool:
        raise ValueError("source history github settings are invalid")
    if github["enabled"]:
        GitHubSettings(str(github["api_base"]), str(github["repository"]), None,
                       int(github["max_requests"]), int(github["timeout_seconds"]))
        if not isinstance(github["token_env"], str) or not github["token_env"].isidentifier():
            raise ValueError("source history github token_env must name an environment variable")
    return HistorySettings(
        **integers, minor_author_share=share, fix_labels=labels["fix_labels"],
        security_labels=labels["security_labels"], fix_on_fix_interval_days=interval,
        line_history_max_files=_integer(lines["max_files"], "line_history.max_files", 0, 10_000),
        line_history_max_file_bytes=_integer(lines["max_file_bytes"], "line_history.max_file_bytes", 1, 16 * 1024 * 1024),
        symbols_enabled=symbols["enabled"],
        symbols_max_files=_integer(symbols["max_files"], "symbols.max_files", 0, 10_000),
        symbols_max_file_bytes=_integer(symbols["max_file_bytes"], "symbols.max_file_bytes", 1, 16 * 1024 * 1024),
        symbols_max_nodes_per_file=_integer(symbols["max_nodes_per_file"], "symbols.max_nodes_per_file", 1, 500_000),
        sii=SiiSettings(parsed_weights, str(sii["complexity_metric"]), tier_1, tier_2),
        filters=FilterRules(**{name: _patterns(filters[name], f"filters.{name}") for name in (*FILTER_CATEGORIES, "test")},
                            formatting_balance_tolerance=tolerance),
        git_enabled=git["enabled"], github=dict(github),
    )
