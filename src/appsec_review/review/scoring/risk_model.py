"""Declarative model behind ``application_risk_matrix/3``.

Two point dimensions and one lookup matrix, all configurable under
``jobs.job_inference_security_review.settings.scoring.providers.application_risk_matrix``:

- ``exploitability``: points per factor value, summed over the factors. A missing factor is
  unknown, not zero: the sum is an INTERVAL whose floor gives each missing factor its minimum
  points and whose ceiling gives it its maximum. Both ends map to ``low``/``medium``/``high`` at
  the ``bands`` thresholds, and the dimension has a rating only when both ends fall in one class.
- ``environmental``: the same for exposure, privilege and data sensitivity. It is produced only
  when at least one of its factors is present; otherwise the dimension stays ``null``.
- ``technical_severity``: impact class x exploitability rating -> severity band.

Validation makes the model monotone: points are non-negative and never decrease along a factor's
scale, and the matrix never decreases along either axis, so stronger evidence can never lower a
rating. ``impact_class`` and ``threat`` are not point factors (impact sets the matrix row; a KEV
listing raises exploitability one band by fixed rule), and EPSS is not a factor at all.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.review.scoring.factors import SCALES, FactorId, FactorSet

RATINGS = ("low", "medium", "high")
BANDS = ("low", "medium", "high", "critical")
IMPACT_CLASSES = SCALES[FactorId.IMPACT_CLASS]
MAX_POINTS = 1000
DIMENSION_FACTORS: Mapping[str, frozenset[FactorId]] = MappingProxyType({
    "exploitability": frozenset({FactorId.VERIFICATION, FactorId.TAINT_PATH, FactorId.ATTACKER_CONTROL,
                                 FactorId.GUARD_ABSENT, FactorId.EXPOSURE, FactorId.PRIVILEGE}),
    "environmental": frozenset({FactorId.EXPOSURE, FactorId.PRIVILEGE, FactorId.DATA_SENSITIVITY}),
})


def _frozen(value: Mapping[Any, Any]) -> Mapping[Any, Any]:
    return MappingProxyType({key: _frozen(item) if isinstance(item, Mapping) else item
                             for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))})


@dataclass(frozen=True, slots=True)
class PointInterval:
    """``[floor, ceiling]`` points of one dimension, with the rating class at each end."""

    known_points: int                          # points of the present factors alone
    floor: int
    ceiling: int
    floor_rating: str
    ceiling_rating: str
    contributions: Mapping[str, int]           # present factors -> points
    unknown: Mapping[str, tuple[int, int]]     # missing factor -> (minimum, maximum) points

    @property
    def complete(self) -> bool:
        return not self.unknown

    @property
    def rating(self) -> str | None:
        """The class when floor and ceiling agree; ``None`` (unrated) when missing factors could change it."""
        return self.floor_rating if self.floor_rating == self.ceiling_rating else None

    @property
    def unresolved(self) -> tuple[str, ...]:
        """Missing factors whose points range is non-empty, that is, those that widen the interval."""
        return tuple(sorted(name for name, (low, high) in self.unknown.items() if low != high))


@dataclass(frozen=True, slots=True)
class DimensionModel:
    """Points per factor value plus the ``medium``/``high`` thresholds of the summed total."""

    name: str
    points: Mapping[FactorId, Mapping[str, int]]
    bands: Mapping[str, int]

    def __post_init__(self) -> None:
        allowed = DIMENSION_FACTORS.get(self.name)
        if allowed is None:
            raise ValueError(f"unknown scoring dimension: {self.name}")
        if not isinstance(self.points, Mapping) or not self.points:
            raise ValueError(f"{self.name}.points must name at least one factor")
        points: dict[FactorId, Mapping[str, int]] = {}
        for raw, table in self.points.items():
            try:
                factor = FactorId(raw)
            except ValueError as exc:
                raise ValueError(f"{self.name}.points has an unknown factor: {raw}") from exc
            if factor not in allowed:
                raise ValueError(f"{self.name}.points may not use factor {factor.value}; allowed: "
                                 f"{', '.join(sorted(item.value for item in allowed))}")
            scale = SCALES[factor]
            if not isinstance(table, Mapping) or set(table) != set(scale):
                raise ValueError(f"{self.name}.points.{factor.value} must give points for exactly: "
                                 f"{', '.join(scale)}")
            previous = 0
            for value in scale:
                number = table[value]
                if type(number) is not int or not 0 <= number <= MAX_POINTS:
                    raise ValueError(f"{self.name}.points.{factor.value}.{value} must be an integer between 0 "
                                     f"and {MAX_POINTS}")
                if number < previous:
                    raise ValueError(f"{self.name}.points.{factor.value} must not decrease along its scale "
                                     f"({', '.join(scale)}); stronger evidence may never score lower")
                previous = number
            points[factor] = {value: table[value] for value in scale}
        if not isinstance(self.bands, Mapping) or set(self.bands) != {"medium", "high"}:
            raise ValueError(f"{self.name}.bands must give exactly medium and high thresholds")
        medium, high = self.bands["medium"], self.bands["high"]
        for key, number in (("medium", medium), ("high", high)):
            if type(number) is not int or not 1 <= number <= MAX_POINTS * len(allowed):
                raise ValueError(f"{self.name}.bands.{key} must be a positive integer")
        if not medium < high:
            raise ValueError(f"{self.name}.bands.medium must be below bands.high")
        object.__setattr__(self, "points", _frozen({factor.value: table for factor, table in points.items()}))
        object.__setattr__(self, "bands", _frozen({"medium": medium, "high": high}))

    @property
    def factors(self) -> frozenset[FactorId]:
        return frozenset(FactorId(item) for item in self.points)

    def classify(self, total: int) -> str:
        return "high" if total >= self.bands["high"] else "medium" if total >= self.bands["medium"] else "low"

    def interval(self, factors: FactorSet) -> "PointInterval":
        """Points as an interval. A missing factor is unknown: its minimum goes into the floor and its
        maximum into the ceiling (tables never decrease along a scale, so those are the first and last
        values). Removing a factor can only lower the floor and raise the ceiling."""
        known: dict[str, int] = {}
        unknown: dict[str, tuple[int, int]] = {}
        for factor in sorted(self.factors, key=lambda item: item.value):
            present = factors.get(factor)
            table = self.points[factor.value]
            if present is not None:
                known[factor.value] = table[present.value]
            else:
                scale = SCALES[factor]
                unknown[factor.value] = (table[scale[0]], table[scale[-1]])
        known_total = sum(known.values())
        floor = known_total + sum(low for low, _ in unknown.values())
        ceiling = known_total + sum(high for _, high in unknown.values())
        return PointInterval(known_total, floor, ceiling, self.classify(floor), self.classify(ceiling),
                             known, unknown)

    def present(self, factors: FactorSet) -> bool:
        return any(factors.get(factor) is not None for factor in self.factors)

    def document(self) -> dict[str, Any]:
        return {"points": {factor: dict(table) for factor, table in self.points.items()}, "bands": dict(self.bands)}


@dataclass(frozen=True, slots=True)
class RiskModel:
    exploitability: DimensionModel
    environmental: DimensionModel
    technical_severity: Mapping[str, Mapping[str, str]]

    def __post_init__(self) -> None:
        if self.exploitability.name != "exploitability" or self.environmental.name != "environmental":
            raise ValueError("risk model dimensions are misnamed")
        matrix = self.technical_severity
        if not isinstance(matrix, Mapping) or set(matrix) != set(IMPACT_CLASSES) or any(
                not isinstance(row, Mapping) or set(row) != set(RATINGS) or not set(row.values()) <= set(BANDS)
                for row in matrix.values()):
            raise ValueError("technical_severity must map every impact class (low, medium, high, critical) and "
                             "exploitability rating (low, medium, high) to a band (low, medium, high, critical)")
        for impact in IMPACT_CLASSES:
            row = [BANDS.index(matrix[impact][rating]) for rating in RATINGS]
            if row != sorted(row):
                raise ValueError(f"technical_severity.{impact} must not decrease as exploitability rises")
        for rating in RATINGS:
            column = [BANDS.index(matrix[impact][rating]) for impact in IMPACT_CLASSES]
            if column != sorted(column):
                raise ValueError(f"technical_severity must not decrease as impact class rises ({rating})")
        object.__setattr__(self, "technical_severity", _frozen(
            {impact: {rating: matrix[impact][rating] for rating in RATINGS} for impact in IMPACT_CLASSES}))

    @property
    def consumed_factors(self) -> frozenset[FactorId]:
        return (self.exploitability.factors | self.environmental.factors
                | {FactorId.VERIFICATION, FactorId.IMPACT_CLASS, FactorId.THREAT})

    def document(self) -> dict[str, Any]:
        return {"exploitability": self.exploitability.document(), "environmental": self.environmental.document(),
                "technical_severity": {impact: dict(row) for impact, row in self.technical_severity.items()}}

    @classmethod
    def from_document(cls, value: Mapping[str, Any]) -> "RiskModel":
        return cls(DimensionModel("exploitability", value["exploitability"]["points"],
                                  value["exploitability"]["bands"]),
                   DimensionModel("environmental", value["environmental"]["points"], value["environmental"]["bands"]),
                   value["technical_severity"])


# Defaults (documented in docs/operations/inference-security-review.md). Calibration: a confirmed
# claim has direct support on every required predicate, so its minimum is verification 40 + taint
# 10 + attacker control 10 + guard 15 = 75 = high, as application_risk_matrix/1 rated it; a supported
# claim reaches medium only with real path, control or guard evidence.
DEFAULT_MODEL_DOCUMENT: Mapping[str, Any] = _frozen({
    "exploitability": {
        "points": {
            "verification": {"supported": 20, "confirmed": 40},
            "taint_path": {"code_evidence": 10, "tool_observation": 15, "codeql_path_observation": 20,
                           "graph_dataflow_path": 25},
            "attacker_control": {"internal": 0, "direct_unclassified": 10, "local": 15, "remote": 25},
            "guard_absent": {"code_evidence": 15, "tool_observation": 15, "graph_fact": 20},
            "exposure": {"local": 0, "internal_network": 5, "public": 10},
        },
        "bands": {"medium": 40, "high": 75},
    },
    "environmental": {
        "points": {
            "exposure": {"local": 5, "internal_network": 10, "public": 30},
            "privilege": {"sandboxed": 0, "elevated": 25},
            "data_sensitivity": {"sensitive": 20, "secret": 30},
        },
        "bands": {"medium": 25, "high": 50},
    },
    "technical_severity": {
        "critical": {"low": "medium", "medium": "high", "high": "critical"},
        "high": {"low": "low", "medium": "medium", "high": "high"},
        "medium": {"low": "low", "medium": "low", "high": "medium"},
        "low": {"low": "low", "medium": "low", "high": "low"},
    },
})
DEFAULT_RISK_MODEL = RiskModel.from_document(DEFAULT_MODEL_DOCUMENT)

__all__ = ["BANDS", "DEFAULT_MODEL_DOCUMENT", "DEFAULT_RISK_MODEL", "DIMENSION_FACTORS", "DimensionModel",
           "PointInterval", "RATINGS", "RiskModel"]
