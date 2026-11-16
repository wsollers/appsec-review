"""Typed settings of the hunting campaign planner (``jobs.job_inference_security_review.settings.hunting``).

The first piece of review protocol v3 section 4 (T-5030): a frontier model partitions the attack surface into
areas and divides the hunters' work; the application keeps the partition honest. These settings hold the switch,
the agent budget the plan is clamped to, the area cap, the planner's model profile name and the bounds of the
attack-surface brief the planner receives. They are semantic configuration: they enter the configuration hash
and the plan fingerprint. Light on purpose (no guidance or retrieval imports): the central configuration parser
imports it.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
import re
from typing import Any, Mapping

_PROFILE = re.compile(r"[a-z][a-z0-9_]{0,63}")


@dataclass(frozen=True, slots=True)
class BriefBounds:
    """How much of the attack surface one brief lists; everything beyond a bound is counted as omitted."""

    max_functions: int = 400
    max_files: int = 120
    max_leads: int = 60

    def __post_init__(self) -> None:
        for name, low, high in (("max_functions", 1, 10_000), ("max_files", 1, 5_000), ("max_leads", 0, 2_000)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"hunting.brief_bounds.{name} must be an integer between {low} and {high}")

    @classmethod
    def from_mapping(cls, value: object, field: str) -> "BriefBounds":
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
            raise ValueError(f"{field}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class HuntingSettings:
    """``settings.hunting``. Absent from a configuration means the rank selects hunt units as before."""

    enabled: bool = False
    agents: int = 4
    max_areas: int = 8
    planner_profile: str = "planner"
    brief_bounds: BriefBounds = BriefBounds()

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("hunting.enabled must be a Boolean")
        for name, low, high in (("agents", 1, 64), ("max_areas", 1, 64)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"hunting.{name} must be an integer between {low} and {high}")
        if not isinstance(self.planner_profile, str) or not _PROFILE.fullmatch(self.planner_profile):
            raise ValueError("hunting.planner_profile is invalid")
        if not isinstance(self.brief_bounds, BriefBounds):
            raise ValueError("hunting.brief_bounds must be BriefBounds")

    @classmethod
    def from_mapping(cls, value: object, field: str) -> "HuntingSettings":
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be a table")
        known = {item.name for item in fields(cls)}
        unknown = sorted(str(key) for key in set(value) - known)
        if unknown:
            raise ValueError(f"{field} has unknown settings: {', '.join(unknown)}")
        if "enabled" not in value:
            raise ValueError(f"{field} is missing settings: enabled")
        bounds = BriefBounds.from_mapping(value.get("brief_bounds"), f"{field}.brief_bounds")
        try:
            return cls(**{**{key: item for key, item in value.items() if key != "brief_bounds"},
                          "brief_bounds": bounds})
        except ValueError as exc:
            raise ValueError(f"{field}: {exc}") from exc

    def record(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "agents": self.agents, "max_areas": self.max_areas,
                "planner_profile": self.planner_profile,
                "brief_bounds": {"max_functions": self.brief_bounds.max_functions,
                                 "max_files": self.brief_bounds.max_files, "max_leads": self.brief_bounds.max_leads}}


__all__ = ["BriefBounds", "HuntingSettings"]
