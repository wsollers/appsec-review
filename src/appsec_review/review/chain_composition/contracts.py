"""Typed settings and records for multi-step attack chain composition (T-173)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

DEFAULT_MAX_STEPS = 6
DEFAULT_MAX_CHAIN_STEPS = DEFAULT_MAX_STEPS

SEVERITY_RANK: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_SEVERITY: dict[int, str] = {rank: name for name, rank in SEVERITY_RANK.items()}
VALID_CROSSING_KINDS = frozenset({
    "trust_boundary",
    "cross_unit",
    "privilege_boundary",
    "spec_drift_pivot",
})


def max_severity(*values: str | None) -> str | None:
    """Return the highest severity among non-null values, or ``None``."""
    ranked = [SEVERITY_RANK[item] for item in values if item in SEVERITY_RANK]
    return _RANK_TO_SEVERITY[max(ranked)] if ranked else None


def _require_bool(mapping: Mapping[str, Any], key: str, default: bool) -> bool:
    value = mapping.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def _require_int(mapping: Mapping[str, Any], key: str, default: int, *, minimum: int, maximum: int) -> int:
    value = mapping.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not (minimum <= value <= maximum):
        raise ValueError(f"{key} must be an integer in [{minimum}, {maximum}]")
    return value


@dataclass(frozen=True)
class AttackChainCompositionSettings:
    """Bounded configuration for multi-step attack chain composition."""

    max_steps: int = DEFAULT_MAX_STEPS
    max_expansions: int = 100
    max_candidates_per_composition: int = 12
    admit_medium_cross_unit: bool = True
    admit_medium_cross_boundary: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.max_steps, bool) or not (2 <= self.max_steps <= 8):
            raise ValueError("max_steps must be an integer in [2, 8]")
        if isinstance(self.max_expansions, bool) or not (1 <= self.max_expansions <= 10_000):
            raise ValueError("max_expansions must be an integer in [1, 10000]")
        if isinstance(self.max_candidates_per_composition, bool) or not (
            1 <= self.max_candidates_per_composition <= 50
        ):
            raise ValueError("max_candidates_per_composition must be an integer in [1, 50]")

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None = None) -> "AttackChainCompositionSettings":
        table = dict(raw or {})
        unknown = sorted(set(table) - {
            "max_steps",
            "max_expansions",
            "max_candidates_per_composition",
            "admit_medium_cross_unit",
            "admit_medium_cross_boundary",
        })
        if unknown:
            raise ValueError(f"unknown attack-chain composition settings: {', '.join(unknown)}")
        return cls(
            max_steps=_require_int(table, "max_steps", DEFAULT_MAX_STEPS, minimum=2, maximum=8),
            max_expansions=_require_int(table, "max_expansions", 100, minimum=1, maximum=10_000),
            max_candidates_per_composition=_require_int(
                table, "max_candidates_per_composition", 12, minimum=1, maximum=50
            ),
            admit_medium_cross_unit=_require_bool(table, "admit_medium_cross_unit", True),
            admit_medium_cross_boundary=_require_bool(table, "admit_medium_cross_boundary", True),
        )


@dataclass(frozen=True)
class ChainStepFinding:
    """One adjudicated finding eligible to participate in a multi-step chain."""

    claim_id: str
    security_predicate: str
    standalone_severity: str | None = None
    weakness_cwe: str | None = None
    unit_key: str = ""
    trust_boundary: str = ""
    state: str = "confirmed"
    affected_entities: tuple[str, ...] = ()
    has_spec_drift: bool = False


@dataclass(frozen=True)
class BoundaryCrossing:
    """One verified unit, trust, privilege, or spec-drift boundary crossing along a chain."""

    edge_index: int
    from_claim_id: str
    to_claim_id: str
    crossing_kind: str
    from_scope: str
    to_scope: str

    def __post_init__(self) -> None:
        if self.crossing_kind not in VALID_CROSSING_KINDS:
            raise ValueError(f"invalid crossing_kind: {self.crossing_kind}")

    def to_json(self) -> dict[str, Any]:
        return {
            "edge_index": self.edge_index,
            "from_claim_id": self.from_claim_id,
            "to_claim_id": self.to_claim_id,
            "crossing_kind": self.crossing_kind,
            "from_scope": self.from_scope[:500] or "default",
            "to_scope": self.to_scope[:500] or "default",
        }


@dataclass(frozen=True)
class ComposedAttackChain:
    """Deterministic multi-step chain record with composed severity and boundary crossings."""

    chain_id: str
    step_claim_ids: tuple[str, ...]
    standalone_severities: tuple[str | None, ...]
    composed_severity: str
    chain_boundary_crossings: tuple[BoundaryCrossing, ...]
    elevated: bool
    objective: str
    rationale: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "step_claim_ids": list(self.step_claim_ids),
            "standalone_severities": list(self.standalone_severities),
            "composed_severity": self.composed_severity,
            "chain_boundary_crossings": [item.to_json() for item in self.chain_boundary_crossings],
            "elevated": self.elevated,
            "objective": self.objective,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ChainCompositionReport:
    """Bounded multi-step chain composition output and telemetry counters."""

    chains: tuple[ComposedAttackChain, ...]
    telemetry: Mapping[str, int] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "chains": [item.to_json() for item in self.chains],
            "telemetry": dict(self.telemetry),
        }
