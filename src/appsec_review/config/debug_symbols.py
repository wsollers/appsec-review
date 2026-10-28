"""Closed, bounded settings for the offline debug-symbol producer."""
from __future__ import annotations

from collections.abc import Mapping
import math
import re
from typing import Any

from appsec_review.config.compiler_target import compiler_target


_READER_DEFAULTS = {
    "max_input_bytes": 536870912,
    "max_output_bytes": 16777216,
    "max_records": 100000,
    "max_depth": 128,
    "timeout_seconds": 120,
}
_BOUNDS = {"max_input_bytes": 4294967296, "max_output_bytes": 268435456,
           "max_records": 1000000, "max_depth": 256, "timeout_seconds": 1800}


def parse_debug_symbol_settings(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) - {"enabled", "max_artifacts", "compiler_target", "reader"}:
        raise ValueError("unknown debug-symbol settings")
    enabled = raw.get("enabled", True)
    maximum = raw.get("max_artifacts", 128)
    if type(enabled) is not bool or type(maximum) is not int or not 1 <= maximum <= 4096:
        raise ValueError("invalid debug-symbol enabled or max_artifacts setting")
    reader = raw.get("reader", {})
    if not isinstance(reader, Mapping) or set(reader) - {*_READER_DEFAULTS, "tools"}:
        raise ValueError("unknown debug-symbol reader settings")
    resolved = {**_READER_DEFAULTS, **reader}
    for key, upper in _BOUNDS.items():
        value = resolved[key]
        valid_type = type(value) in (int, float) if key == "timeout_seconds" else type(value) is int
        if not valid_type or not 0 < value <= upper or not math.isfinite(value):
            raise ValueError(f"invalid debug-symbol reader limit: {key}")
    tools = reader.get("tools", {})
    if not isinstance(tools, Mapping) or set(tools) - {"llvm_dwarfdump", "llvm_pdbutil"}:
        raise ValueError("unknown debug-symbol reader tools")
    resolved["tools"] = {}
    for name, tool in tools.items():
        if (not isinstance(tool, Mapping) or set(tool) != {"path", "sha256"}
                or not isinstance(tool["path"], str) or not tool["path"]
                or len(tool["path"]) > 4096 or "\x00" in tool["path"]
                or not isinstance(tool["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", tool["sha256"]) is None):
            raise ValueError(f"debug-symbol tool requires path and SHA-256 pin: {name}")
        resolved["tools"][name] = dict(tool)
    return {"enabled": enabled, "max_artifacts": maximum,
            "compiler_target": compiler_target(raw.get("compiler_target", "clang")).value,
            "reader": resolved}
