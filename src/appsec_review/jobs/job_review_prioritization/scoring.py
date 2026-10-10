"""LLM Prioritization Score: a deterministic "review first" ordering, never a finding.

Each feature is normalized to a zero-anchored mid-rank percentile over its population (all scored
items of the same scope, or of the same scope and language).  A zero value maps to 0 so that the
absence of a signal never earns rank.  The score is the weighted mean of the percentiles of the
features that are available for the item; unavailable features are excluded and the item's
``feature_coverage`` records the share of configured weight that was available.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from collections.abc import Iterable, Mapping
import math
from typing import Any


SCORE_IDENTITY = "appsec-review/llm-prioritization-score/1"
SIGNAL_FEATURES = ("ingress", "sink", "privilege_shift", "sensitive_wrapper", "state_mutation", "custom_parsing",
                   "public_api", "parser", "validator", "middleware")
FILE_FEATURES = ("cyclomatic", "cognitive", "complexity_density", "share_above_threshold", "afferent_coupling",
                 "efferent_coupling", "instability", "suppression_density", *SIGNAL_FEATURES, "semantic_path",
                 "history_hotspot")
FUNCTION_FEATURES = ("cyclomatic", "cognitive", "complexity_density", "afferent_coupling", "efferent_coupling",
                     "instability", "suppression_density", *SIGNAL_FEATURES, "semantic_path", "history_hotspot")
FEATURES = tuple(dict.fromkeys((*FILE_FEATURES, *FUNCTION_FEATURES)))
# Function items inherit these file-scoped features from the file that contains them.
INHERITED = frozenset({"afferent_coupling", "efferent_coupling", "instability", "history_hotspot"})
BOUNDARY = ("ingress", "sink", "privilege_shift", "semantic_path")


def _round(value: float) -> float:
    return round(float(value), 6)


def percentiles(values: Mapping[str, float]) -> dict[str, float]:
    ordered = sorted(values.values())
    count = len(ordered)
    result: dict[str, float] = {}
    if not count:
        return result
    for key, value in values.items():
        if value <= 0:
            result[key] = 0.0
            continue
        below = bisect.bisect_left(ordered, value)
        equal = bisect.bisect_right(ordered, value) - below
        result[key] = _round((below + 0.5 * equal) / count)
    return result


def rank(items: list[dict[str, Any]], weights: Mapping[str, float], features: Iterable[str], *,
         population: str) -> list[dict[str, Any]]:
    """Attach percentiles, score, coverage, and rank to items of one scope; return them in rank order."""
    active = [name for name in features if float(weights.get(name, 0)) > 0]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        groups[item["language"] if population == "language" else "all"].append(item)
    total_weight = sum(float(weights[name]) for name in active)
    for members in groups.values():
        tables = {name: percentiles({item["item_id"]: float(item["features"][name]) for item in members
                                     if item["features"].get(name) is not None}) for name in active}
        for item in members:
            used = {name: tables[name][item["item_id"]] for name in active if item["item_id"] in tables[name]}
            weight = sum(float(weights[name]) for name in used)
            item["percentiles"] = dict(sorted(used.items()))
            item["missing_features"] = sorted(name for name in active if name not in used)
            item["feature_coverage"] = _round(weight / total_weight) if total_weight else 0.0
            item["score"] = _round(sum(float(weights[name]) * value for name, value in used.items()) / weight) \
                if weight else 0.0
            item["boundary_total"] = sum(int(item["features"].get(name) or 0) for name in BOUNDARY)
    ordered = sorted(items, key=lambda item: (-item["score"], -item["boundary_total"], -item["feature_coverage"],
                                              item["path"], item.get("start_line") or 0, item.get("name") or ""))
    for position, item in enumerate(ordered, 1):
        item["rank"] = position
    return ordered


def selection_size(population: int, *, fraction: float, count: int, ceiling: int) -> int:
    wanted = count if count > 0 else math.ceil(fraction * population)
    return max(0, min(population, wanted, ceiling))
