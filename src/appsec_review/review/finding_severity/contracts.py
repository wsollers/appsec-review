"""Typed contracts for finding adjudication chain-elevated severity preservation (T-173)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

@dataclass(frozen=True)
class FindingAdjudicationSettings:
    """Settings controlling chain-elevated severity preservation during finding adjudication."""

    preserve_chain_elevated_severity: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.preserve_chain_elevated_severity, bool):
            raise ValueError("preserve_chain_elevated_severity must be a boolean")

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None = None) -> "FindingAdjudicationSettings":
        table = dict(raw or {})
        unknown = sorted(set(table) - {"preserve_chain_elevated_severity"})
        if unknown:
            raise ValueError(f"unknown finding adjudication settings: {', '.join(unknown)}")
        preserve = table.get("preserve_chain_elevated_severity", True)
        if not isinstance(preserve, bool):
            raise ValueError("preserve_chain_elevated_severity must be a boolean")
        return cls(preserve_chain_elevated_severity=preserve)


@dataclass(frozen=True)
class AdjudicatedFindingSeverity:
    """Preserves standalone technical severity alongside chain-elevated composed severity."""

    claim_id: str
    standalone_severity: str | None
    composed_severity: str | None
    effective_severity: str | None
    chain_elevated: bool
    attack_chain_ids: tuple[str, ...]
    chain_boundary_crossings: tuple[Mapping[str, Any], ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "standalone_severity": self.standalone_severity,
            "composed_severity": self.composed_severity,
            "effective_severity": self.effective_severity,
            "chain_elevated": self.chain_elevated,
            "attack_chain_ids": list(self.attack_chain_ids),
            "chain_boundary_crossings": [dict(item) for item in self.chain_boundary_crossings],
        }
