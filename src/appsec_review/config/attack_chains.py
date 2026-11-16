"""Semantic bounds for pre-publication attack-chain work."""
from __future__ import annotations

from dataclasses import dataclass, fields
import re
from typing import Any, Mapping

#: Deterministic continuity derivations the stage may count (closed vocabulary; see
#: ``review/native_continuity.py``). ``same_native_executable``: identity and privilege continuity hold
#: across an edge whose two source files the accepted native build links into one executable or shared
#: library. Every derivation reads run-owned build facts only, never model prose.
DERIVED_CONTINUITY = frozenset({"same_native_executable"})


@dataclass(frozen=True, slots=True)
class AttackChainSettings:
    max_links: int = 4
    max_expansions: int = 100
    max_candidates_per_composition: int = 8
    max_challenge_cells: int = 100
    max_queries: int = 12
    max_turns: int = 4
    max_evidence_per_obligation: int = 8
    max_result_bytes: int = 65536
    # Only commissioned deterministic producers may supply counted continuity facts.
    # Entries are exact "job_id/rule_id" identities from accepted shard provenance.
    continuity_producers: tuple[str, ...] = ()
    # Deterministic derivations from accepted build facts (``DERIVED_CONTINUITY``); empty disables them.
    derived_continuity: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        bounds = {"max_links": (2, 8), "max_expansions": (1, 10000),
                  "max_candidates_per_composition": (1, 50), "max_challenge_cells": (0, 20000),
                  "max_queries": (1, 1000), "max_turns": (1, 100),
                  "max_evidence_per_obligation": (1, 32), "max_result_bytes": (1024, 1048576)}
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"attack_chains.{name} must be an integer between {low} and {high}")
        values = self.continuity_producers
        if (not isinstance(values, tuple) or len(values) > 32
                or any(not isinstance(item, str) or len(item) > 200
                       or not re.fullmatch(r"job_[a-z0-9_]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", item)
                       for item in values)
                or len(set(values)) != len(values)):
            raise ValueError("attack_chains.continuity_producers must be distinct producer/rule identities")
        derived = self.derived_continuity
        if (not isinstance(derived, tuple) or len(set(derived)) != len(derived)
                or any(item not in DERIVED_CONTINUITY for item in derived)):
            raise ValueError("attack_chains.derived_continuity must be distinct names from "
                             + ", ".join(sorted(DERIVED_CONTINUITY)))

    @classmethod
    def from_mapping(cls, value: Any) -> "AttackChainSettings":
        if value is None:
            return cls()
        if not isinstance(value, Mapping) or set(value) - {item.name for item in fields(cls)}:
            raise ValueError("attack_chains must be a table containing only known settings")
        document = dict(value)
        for name in ("continuity_producers", "derived_continuity"):
            if isinstance(document.get(name), list):
                document[name] = tuple(document[name])
        return cls(**document)
