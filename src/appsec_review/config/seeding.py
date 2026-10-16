"""Run-bound seeding definition shared by every seeded producer.

The mode, depth and seed limit are defined once, by ``jobs.job_codeql_analysis.settings.export_queries``
(the reference producer), and the loader copies them into the ``seeded`` setting of each Clang-family
producer. A producer therefore cannot disagree with CodeQL about what is seeded. Each producer also
has its own named bounds in ``jobs.<job>.settings.seeded_bounds``.

Contract: ``docs/architecture/seeded-neighborhoods.md`` section 3. A job whose settings carry no
``seeded`` table (settings built by hand, never the central configuration) is ``whole_program``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .codeql import CodeQLExportSettings

# Producer jobs that receive the run-bound definition, with the bounds each one must name.
SEEDED_JOB_BOUNDS: Mapping[str, tuple[str, ...]] = {
    "job_cpp_compiled_analysis": ("function_limit", "unit_limit", "block_limit", "include_scan_files"),
    "job_clang_static_analysis": ("unit_limit", "include_scan_files"),
    "job_cpg_analysis": ("unit_limit", "include_scan_files"),
}
BOUND_NAMES = ("function_limit", "unit_limit", "block_limit", "include_scan_files")
MODES = ("seeded", "whole_program")


@dataclass(frozen=True, slots=True)
class SeededSettings:
    """What a producer needs to run from the findings outward."""

    mode: str = "whole_program"
    depth: int = 0
    seed_limit: int = 1
    function_limit: int = 0
    unit_limit: int = 0
    block_limit: int = 0
    include_scan_files: int = 0

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError("seeded.mode must be one of: " + ", ".join(MODES))
        for name in ("depth",):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"seeded.{name} must be a non-negative integer")
        for name in ("seed_limit", *BOUND_NAMES):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"seeded.{name} must be a non-negative integer")
        if self.mode == "seeded" and self.seed_limit < 1:
            raise ValueError("seeded.seed_limit must be a positive integer")

    @property
    def seeded(self) -> bool:
        return self.mode == "seeded"

    @classmethod
    def from_job_settings(cls, settings: Mapping[str, Any]) -> "SeededSettings":
        raw = settings.get("seeded")
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            raise ValueError("settings.seeded must be a table")
        unknown = set(raw) - {"mode", "depth", "seed_limit", *BOUND_NAMES}
        if unknown:
            raise ValueError("settings.seeded has unknown keys: " + ", ".join(sorted(unknown)))
        return cls(**{key: raw[key] for key in raw})

    def identity(self) -> dict[str, Any]:
        """The resume-identity binding of the definition (the seed set is added by the producer)."""
        if not self.seeded:
            return {"mode": self.mode}
        return {"mode": self.mode, "depth": self.depth, "seed_limit": self.seed_limit,
                "function_limit": self.function_limit, "unit_limit": self.unit_limit,
                "block_limit": self.block_limit, "include_scan_files": self.include_scan_files}


def resolve_seeded_settings(job_id: str, settings: Mapping[str, Any],
                            export: CodeQLExportSettings) -> dict[str, Any]:
    """The job settings with ``seeded_bounds`` folded, with the run-bound definition, into ``seeded``."""
    required = SEEDED_JOB_BOUNDS[job_id]
    bounds = settings.get("seeded_bounds")
    if not isinstance(bounds, Mapping) or set(bounds) != set(required):
        raise ValueError(f"jobs.{job_id}.settings.seeded_bounds must define exactly: " + ", ".join(required))
    result = {key: value for key, value in settings.items() if key != "seeded_bounds"}
    value = SeededSettings(mode=export.mode, depth=export.seed_depth, seed_limit=export.seed_limit,
                           **{name: bounds[name] for name in required})
    if value.seeded and any(getattr(value, name) < 1 for name in required):
        raise ValueError(f"jobs.{job_id}.settings.seeded_bounds values must be positive integers")
    result["seeded"] = {"mode": value.mode, "depth": value.depth, "seed_limit": value.seed_limit,
                        **{name: bounds[name] for name in required}}
    return result
