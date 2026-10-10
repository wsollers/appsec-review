"""Security Instability Index (SII): a deterministic 0-100 review-priority score with tiers.

For each metric in ``SII_METRICS`` the population's present values are transformed (``log1p`` for
heavy-tailed counts and ratios, identity for entropy) and min-max normalized to ``[0, 1]``.  A
metric whose transformed values are all equal cannot discriminate, so every unit gets ``0`` for it
and the metric is listed in ``constant_metrics``.  A unit missing a metric (no complexity coverage,
for example) is scored over the weights it has, and that metric is named in its ``missing_inputs``
gap with ``weight_coverage`` below 1.  The score is ``100 * sum(w * n) / sum(w)`` rounded to four
decimals.  A score is only meaningful inside its own population and window, and it is never
vulnerability evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from fractions import Fraction
import math
from typing import Any

from .settings import SII_METRICS


SII_IDENTITY = "appsec-review/security-instability-index/1"
TRANSFORMS = {"relative_churn": "log1p", "revision_frequency": "log1p", "author_entropy": "identity",
              "complexity": "log1p"}


def _transform(metric: str, value: float) -> float:
    return math.log1p(value) if TRANSFORMS[metric] == "log1p" else value


def tier_bounds(population: int, tier_1_share: Fraction, tier_2_share: Fraction) -> tuple[int, int]:
    """Return the last rank of Tier 1 and of Tier 2.

    Tier 1 holds ``ceil(P * tier_1_share)`` units and Tiers 1-2 together hold
    ``ceil(P * (tier_1_share + tier_2_share))``.  Rounding up means every non-empty population has
    at least one Tier 1 unit, and small populations favour review over omission: with defaults,
    ``P = 1..20`` gives one Tier 1 unit and ``P = 10`` gives ranks 2 in Tier 2 and 3-10 in Tier 3.
    """
    if population <= 0:
        return 0, 0
    tier_1 = math.ceil(population * tier_1_share)
    tier_2 = max(tier_1, math.ceil(population * (tier_1_share + tier_2_share)))
    return tier_1, min(tier_2, population)


def score(units: Mapping[str, Mapping[str, Any]], *, weights: Mapping[str, float], tier_1_share: Fraction,
          tier_2_share: Fraction) -> dict[str, Any]:
    """Rank ``units``; each unit maps ``SII_METRICS`` to a value or ``None`` and carries tie-break fields.

    Ties break on higher ``churn_lines``, then higher ``change_count``, then the ascending key.
    """
    normalization: dict[str, dict[str, Any]] = {}
    constant: list[str] = []
    for metric in SII_METRICS:
        present = {key: _transform(metric, float(unit[metric])) for key, unit in units.items()
                   if unit.get(metric) is not None}
        low = min(present.values(), default=None)
        high = max(present.values(), default=None)
        if present and high == low:
            constant.append(metric)
        normalization[metric] = {"transform": TRANSFORMS[metric], "min": low, "max": high, "present_count": len(present)}
    ranked = []
    for key, unit in units.items():
        inputs: dict[str, dict[str, Any]] = {}
        total = available = 0.0
        missing = []
        for metric in SII_METRICS:
            weight = float(weights[metric])
            raw = unit.get(metric)
            if raw is None:
                missing.append(metric)
                inputs[metric] = {"raw": None, "weight": weight, "status": "missing"}
                continue
            transformed = _transform(metric, float(raw))
            low, high = normalization[metric]["min"], normalization[metric]["max"]
            normalized = 0.0 if high == low else (transformed - low) / (high - low)
            inputs[metric] = {"raw": raw, "transformed": round(transformed, 6), "normalized": round(normalized, 6),
                              "weight": weight, "status": "constant" if metric in constant else "present"}
            total += weight * normalized
            available += weight
        value = round(100 * total / available, 4) if available else 0.0
        all_weight = sum(float(weights[metric]) for metric in SII_METRICS)
        ranked.append({"key": key, "score": value, "inputs": inputs, "missing_inputs": missing,
                       "weight_coverage": round(available / all_weight, 6),
                       "_order": (-value, -int(unit.get("churn_lines") or 0), -int(unit.get("change_count") or 0), key)})
    ranked.sort(key=lambda item: item["_order"])
    last_tier_1, last_tier_2 = tier_bounds(len(ranked), tier_1_share, tier_2_share)
    for position, item in enumerate(ranked, 1):
        del item["_order"]
        item["rank"] = position
        item["tier"] = 1 if position <= last_tier_1 else 2 if position <= last_tier_2 else 3
    return {"identity": SII_IDENTITY, "population": len(ranked), "weights": dict(weights),
            "normalization": {metric: {key: (round(value, 6) if isinstance(value, float) else value)
                                       for key, value in values.items()} for metric, values in normalization.items()},
            "constant_metrics": constant,
            "tiers": {"tier_1_share": str(tier_1_share), "tier_2_share": str(tier_2_share),
                      "tier_1_last_rank": last_tier_1, "tier_2_last_rank": last_tier_2, "rounding": "ceil"},
            "ranked": ranked}
