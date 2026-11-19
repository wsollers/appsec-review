"""Closed resource and semantic settings for finding-seeded CBMC analysis."""

from collections.abc import Mapping
from dataclasses import dataclass, fields
import re
from typing import Any


@dataclass(frozen=True, slots=True)
class CbmcSettings:
    enabled: bool = True
    tag: str = "appsec-review/tool-cbmc:6.11.0"
    image_id: str = ""
    max_scopes: int = 8
    max_seeds_per_scope: int = 32
    max_translation_units: int = 8
    max_functions: int = 16
    max_output_bytes: int = 4 * 1024 * 1024
    max_goto_bytes: int = 64 * 1024 * 1024
    max_source_bytes: int = 128 * 1024 * 1024
    max_source_files: int = 10000
    max_instructions: int = 100000
    max_properties: int = 2000
    max_property_summaries: int = 16
    max_trace_steps: int = 24
    max_trace_value_chars: int = 200
    command_timeout_seconds: int = 45
    total_timeout_seconds: int = 300
    unwind_limits: tuple[int, ...] = (8, 32)

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("CBMC enabled must be Boolean")
        if not isinstance(self.tag, str) or not self.tag or any(c.isspace() for c in self.tag):
            raise ValueError("CBMC tag must be a nonempty image reference")
        if not isinstance(self.image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
            raise ValueError("CBMC requires an immutable host image binding")
        upper = {
            "max_scopes": 64, "max_seeds_per_scope": 256, "max_translation_units": 64,
            "max_functions": 256, "max_output_bytes": 16777216, "max_goto_bytes": 268435456,
            "max_source_bytes": 1073741824, "max_source_files": 100000,
            "max_instructions": 1000000, "max_properties": 10000,
            "max_property_summaries": 64,
            "max_trace_steps": 128, "max_trace_value_chars": 1024,
            "command_timeout_seconds": 600, "total_timeout_seconds": 3600,
        }
        for name, maximum in upper.items():
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"CBMC {name} must be an integer in 1..{maximum}")
        if (not isinstance(self.unwind_limits, tuple) or not 1 <= len(self.unwind_limits) <= 3
                or any(type(v) is not int or not 1 <= v <= 256 for v in self.unwind_limits)
                or tuple(sorted(set(self.unwind_limits))) != self.unwind_limits):
            raise ValueError("CBMC unwind_limits must contain 1..3 increasing integers in 1..256")
        if self.command_timeout_seconds > self.total_timeout_seconds:
            raise ValueError("CBMC command timeout exceeds the total analysis budget")
        if self.command_timeout_seconds <= 3:
            raise ValueError("CBMC command timeout must reserve more than three seconds for execution and cleanup")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CbmcSettings":
        unknown = set(value) - {item.name for item in fields(cls)}
        if unknown:
            raise ValueError(f"unknown CBMC settings: {sorted(unknown)}")
        values = dict(value)
        if "unwind_limits" in values:
            if not isinstance(values["unwind_limits"], (tuple, list)):
                raise ValueError("CBMC unwind_limits must be an array")
            values["unwind_limits"] = tuple(values["unwind_limits"])
        return cls(**values)
