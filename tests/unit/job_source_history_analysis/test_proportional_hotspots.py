"""Unit tests for proportional hotspot scaling and multi-module anti-starvation (T-171)."""

from __future__ import annotations

import pytest

from appsec_review.jobs.job_source_history_analysis.hotspots import (
    effective_hotspot_count,
    select_proportional_hotspots,
)
from appsec_review.jobs.job_source_history_analysis.settings import parse_settings
from .support import settings


def test_effective_hotspot_count_bounds_small_medium_and_monorepo_populations() -> None:
    # Backward-compatible fixed cap when proportional_ratio is None
    assert effective_hotspot_count(500, hotspot_count=10, proportional_ratio=None) == 10

    # Proportional 10% bounded by [50, 2000]
    assert effective_hotspot_count(20, proportional_ratio=0.10, min_hotspots=50, max_hotspots=2000) == 50
    assert effective_hotspot_count(850, proportional_ratio=0.10, min_hotspots=50, max_hotspots=2000) == 85
    assert effective_hotspot_count(30_000, proportional_ratio=0.10, min_hotspots=50, max_hotspots=2000) == 2000

    with pytest.raises(ValueError, match="min_hotspots cannot exceed max_hotspots"):
        effective_hotspot_count(100, proportional_ratio=0.10, min_hotspots=100, max_hotspots=50)


def test_multi_module_proportional_selection_prevents_small_module_starvation() -> None:
    # Module "monolith" has 18 high-churn files; "auth" and "crypto" have 1 critical file each at ranks 19 & 20
    ranked = [{"key": f"monolith/f{i}.py", "rank": i, "score": 100.0 - i} for i in range(1, 19)] + [
        {"key": "auth/token.py", "rank": 19, "score": 55.0},
        {"key": "crypto/verify.py", "rank": 20, "score": 54.0},
    ]
    modules = {
        **{f"monolith/f{i}.py": "monolith" for i in range(1, 19)},
        "auth/token.py": "auth",
        "crypto/verify.py": "crypto",
    }
    selected = select_proportional_hotspots(
        ranked,
        modules=modules,
        proportional_ratio=0.25,
        min_hotspots=5,
        max_hotspots=10,
        min_per_module=1,
    )
    selected_keys = [item["key"] for item in selected]
    assert len(selected_keys) == 5
    # Smaller security-critical modules are represented instead of being starved by monolith churn!
    assert "auth/token.py" in selected_keys
    assert "crypto/verify.py" in selected_keys
    # Returned list preserves global SII rank ordering
    assert [item["rank"] for item in selected] == sorted(item["rank"] for item in selected)


def test_parse_settings_accepts_optional_proportional_fields_and_rejects_invalid_bounds() -> None:
    cfg = settings()
    cfg["proportional_ratio"] = 0.10
    cfg["min_hotspots"] = 20
    cfg["max_hotspots"] = 500
    parsed = parse_settings(cfg)
    assert parsed.proportional_ratio == 0.10
    assert parsed.min_hotspots == 20
    assert parsed.max_hotspots == 500

    bad = settings()
    bad["proportional_ratio"] = 0.0
    with pytest.raises(ValueError, match="proportional_ratio"):
        parse_settings(bad)

    inverted = settings()
    inverted["min_hotspots"] = 100
    inverted["max_hotspots"] = 20
    with pytest.raises(ValueError, match="min_hotspots exceeds max_hotspots"):
        parse_settings(inverted)
