"""Deterministic number formatting shared by the telemetry report sections."""
from __future__ import annotations

from typing import Any

UNAVAILABLE = "unavailable"
NA = "n/a"  # "unavailable" in a narrow numeric table column; each such table says so


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def duration(ms: Any) -> str:
    """``850 ms``, ``4.2 s``, ``16m 52s``, ``2h 05m``; ``unavailable`` for a missing value."""
    value = _number(ms)
    if value is None or value < 0:
        return UNAVAILABLE
    if value < 1000:
        return f"{int(round(value))} ms"
    if value < 60_000:
        return f"{value / 1000:.1f} s"
    seconds = int(round(value / 1000))
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {seconds % 3600 // 60:02d}m"


def count(value: Any) -> str:
    """``7,810``; ``unavailable`` for a missing value."""
    number = _number(value)
    return UNAVAILABLE if number is None else f"{int(number):,}"


def plural(value: Any, singular: str, many: str | None = None) -> str:
    """``1 gap``, ``3 gaps``, ``1,204 steps``; ``unavailable`` for a missing value."""
    number = _number(value)
    if number is None:
        return UNAVAILABLE
    return f"{count(number)} {singular if int(number) == 1 else (many or singular + 's')}"


def compact(value: Any) -> str:
    """``950``, ``7.8k``, ``1.2M``; ``unavailable`` for a missing value."""
    number = _number(value)
    if number is None:
        return UNAVAILABLE
    for limit, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "k")):
        if abs(number) >= limit:
            return f"{number / limit:.1f}{suffix}"
    return f"{int(number)}"


def percent(ratio: Any) -> str:
    """``82.6%`` for a 0..1 ratio; ``unavailable`` for a missing value."""
    number = _number(ratio)
    return UNAVAILABLE if number is None else f"{number * 100:.1f}%"
