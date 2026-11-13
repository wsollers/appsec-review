from __future__ import annotations

from fractions import Fraction

import pytest

from appsec_review.jobs.job_source_history_analysis.settings import parse_settings
from .support import settings


def test_defaults_and_inclusive_settings():
    parsed = parse_settings(settings())
    assert (parsed.history_window_months, parsed.hotspot_count, parsed.fix_on_fix_interval_days) == (6, 10, 30)
    assert parsed.sii.tier_1_share == Fraction(1, 20) and parsed.sii.tier_2_share == Fraction(3, 20)
    assert parsed.git_enabled and parsed.symbols_enabled and parsed.changelog_enabled
    assert sum(parsed.sii.weights.values()) == 1
    assert parsed.filters.category_patterns()[0][0] == "generated"


@pytest.mark.parametrize("path,value,message", [
    ("unknown", 1, "unknown source history setting"),
    ("hotspot_count", True, "hotspot_count"), ("history_window_months", 121, "history_window_months"),
    ("minor_author_share", True, "minor_author_share"), ("minor_author_share", 1, "minor_author_share"),
    ("fix_labels", [""], "fix_labels"), ("security_labels", "bug", "security_labels"),
    ("fix_on_fix", None, "fix_on_fix"), ("fix_on_fix.interval_days", 13, "interval_days"),
    ("symbols.enabled", 1, "symbols.enabled"), ("sii.weights", {}, "weights must name"),
    ("sii.weights.complexity", -1, "non-negative"), ("sii.complexity_metric", "other", "complexity_metric"),
    ("sii.tier_1_share", 0.9, "tier shares"), ("sii.tier_1_share", "x", "tier_1_share"),
    ("filters.formatting_balance_tolerance", 1, "formatting_balance_tolerance"),
    ("filters.generated", ["../bad"], "filter patterns"),
    ("filters.generated", ["/absolute"], "filter patterns"),
    ("filters.generated", ["a//b"], "filter patterns"),
    ("git.enabled", "true", "git settings"),
    ("github.enabled", "yes", "github settings"), ("github.token_env", "BAD-TOKEN", "token_env"),
    ("line_history.max_files", -1, "line_history.max_files"),
    ("symbols.max_nodes_per_file", 0, "max_nodes_per_file"),
], ids=[str(i) for i in range(24)])
def test_invalid_settings_are_typed_and_name_the_setting(path, value, message):
    configured = settings()
    parts = path.split(".")
    table = configured
    for part in parts[:-1]:
        table = table[part]
    table[parts[-1]] = value
    with pytest.raises(ValueError, match=message):
        parse_settings(configured)


def test_disabled_github_does_not_require_a_credential_variable():
    configured = settings()
    configured["github"]["enabled"] = False
    configured["github"]["token_env"] = "not valid"
    assert parse_settings(configured).github["enabled"] is False
