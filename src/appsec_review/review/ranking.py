"""Lane B review-unit rank weights (``review-unit-rank/2``), typed and validated.

The weights turn each accepted rank signal into integer points on the 0-1000 signal scale. They are
semantic configuration (``jobs.job_inference_security_review.settings.ranking``): they change which
units are hunted, so they enter the package manifest and every fingerprint derived from the settings.
The defaults are the values ``review-unit-rank/2`` shipped with; changing a weight changes the order,
not the rule's semantics, so the rule id does not change.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any, Mapping

MAX_SIGNAL_POINTS = 1000


@dataclass(frozen=True, slots=True)
class RankWeights:
    """Points per rank signal; every weight is an integer in ``[0, MAX_SIGNAL_POINTS]``.

    - ``lps``, ``sii``, ``hotspot``: points for a full (1.0 or 100 %) producer score; a partial score
      scales linearly and is capped at the weight.
    - ``tag_density``: points when a unit carries ``tag_density_full_tags_per_file`` security tag
      assignments per member file; fewer tags scale linearly.
    - ``lead_hint_medium``/``_low``/``_info``: points per medium/low/info lead hint in the unit, the sum
      capped at ``lead_hints_max``.
    - ``advisory_kev``: points when any of the unit's advisories is CISA KEV-listed.
    - ``advisory_epss``: points for an EPSS percentile of 1.0; the unit's highest percentile scales it.
    """

    lps: int = 1000
    sii: int = 1000
    hotspot: int = 1000
    tag_density: int = 1000
    tag_density_full_tags_per_file: int = 4
    lead_hint_medium: int = 100
    lead_hint_low: int = 30
    lead_hint_info: int = 10
    lead_hints_max: int = 1000
    advisory_kev: int = 250
    advisory_epss: int = 250

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            low = 1 if item.name == "tag_density_full_tags_per_file" else 0
            high = 1000 if item.name == "tag_density_full_tags_per_file" else MAX_SIGNAL_POINTS
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"ranking.{item.name} must be an integer between {low} and {high}")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None, field: str = "ranking") -> "RankWeights":
        """Weights from a TOML table; unknown keys are rejected and absent keys keep their default."""
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be a table")
        known = {item.name for item in fields(cls)}
        unknown = sorted(str(key) for key in set(value) - known)
        if unknown:
            raise ValueError(f"{field} has unknown settings: {', '.join(unknown)}")
        try:
            return cls(**dict(value))
        except ValueError as exc:
            raise ValueError(str(exc).replace("ranking.", f"{field}.", 1)) from exc

    def record(self) -> dict[str, int]:
        return asdict(self)


DEFAULT_RANK_WEIGHTS = RankWeights()

__all__ = ["DEFAULT_RANK_WEIGHTS", "MAX_SIGNAL_POINTS", "RankWeights"]
