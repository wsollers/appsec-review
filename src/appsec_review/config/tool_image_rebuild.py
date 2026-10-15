"""Typed settings for ``job_tool_image_rebuild``.

The job rebuilds the catalog's container images through ``containers/build.py`` before review
intake. Every bound is explicit in ``appsec-review.toml``; unknown keys and wrongly typed values
fail configuration loading instead of falling back to defaults.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any


JOB_ID = "job_tool_image_rebuild"
_PREFIX = f"jobs.{JOB_ID}.settings"
_IMAGE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]*$")
# The builder itself accepts at most eight concurrent builds and per-image bounds in this range.
PARALLELISM_RANGE = (1, 8)
IMAGE_TIMEOUT_RANGE = (60, 14400)
TOTAL_TIMEOUT_RANGE = (60, 172800)
LOG_TAIL_RANGE = (256, 65536)
SETTING_KEYS = frozenset({
    "enabled", "images", "parallelism", "image_timeout_seconds", "total_timeout_seconds",
    "continue_on_error", "log_tail_bytes", "pin_mismatch",
})
# A rebuilt image whose ID differs from a configured pin either fails the run or is reported.
PIN_MISMATCH_MODES = ("fail", "report")


@dataclass(frozen=True, slots=True)
class ToolImageRebuildSettings:
    enabled: bool
    # Empty selects every enabled catalog image; dependencies (bases) are always built first.
    images: tuple[str, ...]
    parallelism: int
    image_timeout_seconds: int
    total_timeout_seconds: int
    continue_on_error: bool
    log_tail_bytes: int
    pin_mismatch: str


def _int(value: object, field: str, bounds: tuple[int, int]) -> int:
    if type(value) is not int or not bounds[0] <= value <= bounds[1]:
        raise ValueError(f"{_PREFIX}.{field} must be an integer within {bounds[0]}..{bounds[1]}")
    return value


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{_PREFIX}.{field} must be a boolean")
    return value


def _choice(value: object, field: str, choices: tuple[str, ...]) -> str:
    if value not in choices or not isinstance(value, str):
        raise ValueError(f"{_PREFIX}.{field} must be one of: " + ", ".join(choices))
    return value


def parse_tool_image_rebuild_settings(value: Mapping[str, Any]) -> ToolImageRebuildSettings:
    if not isinstance(value, Mapping):
        raise ValueError(f"{_PREFIX} must be a table")
    unknown = set(value) - SETTING_KEYS
    if unknown:
        raise ValueError(f"{_PREFIX} has unknown settings: " + ", ".join(sorted(map(str, unknown))))
    missing = SETTING_KEYS - set(value)
    if missing:
        raise ValueError(f"{_PREFIX} is missing settings: " + ", ".join(sorted(missing)))
    images = value["images"]
    if not isinstance(images, (list, tuple)) or not all(
            isinstance(item, str) and _IMAGE_ID.fullmatch(item) for item in images):
        raise ValueError(f"{_PREFIX}.images must be a list of catalog image ids")
    if len(images) != len(set(images)):
        raise ValueError(f"{_PREFIX}.images must not repeat an image id")
    image_timeout = _int(value["image_timeout_seconds"], "image_timeout_seconds", IMAGE_TIMEOUT_RANGE)
    total_timeout = _int(value["total_timeout_seconds"], "total_timeout_seconds", TOTAL_TIMEOUT_RANGE)
    if total_timeout < image_timeout:
        raise ValueError(f"{_PREFIX}.total_timeout_seconds must be at least image_timeout_seconds")
    return ToolImageRebuildSettings(
        enabled=_bool(value["enabled"], "enabled"),
        images=tuple(images),
        parallelism=_int(value["parallelism"], "parallelism", PARALLELISM_RANGE),
        image_timeout_seconds=image_timeout,
        total_timeout_seconds=total_timeout,
        continue_on_error=_bool(value["continue_on_error"], "continue_on_error"),
        log_tail_bytes=_int(value["log_tail_bytes"], "log_tail_bytes", LOG_TAIL_RANGE),
        pin_mismatch=_choice(value["pin_mismatch"], "pin_mismatch", PIN_MISMATCH_MODES),
    )
