"""Typed settings for ``job_image_pin_verification``.

The job only inspects the local Docker daemon: it verifies that every enabled catalog image and every
configured image-ID pin resolves to exactly its pinned image. Images are built on the host by the
operator, never by the pipeline, so the only setting is the dispatch switch. Unknown keys and wrongly
typed values fail configuration loading instead of falling back to defaults.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


JOB_ID = "job_image_pin_verification"
_PREFIX = f"jobs.{JOB_ID}.settings"
SETTING_KEYS = frozenset({"enabled"})


@dataclass(frozen=True, slots=True)
class ImagePinVerificationSettings:
    enabled: bool


def parse_image_pin_verification_settings(value: Mapping[str, Any]) -> ImagePinVerificationSettings:
    if not isinstance(value, Mapping):
        raise ValueError(f"{_PREFIX} must be a table")
    unknown = set(value) - SETTING_KEYS
    if unknown:
        raise ValueError(f"{_PREFIX} has unknown settings: " + ", ".join(sorted(map(str, unknown))))
    missing = SETTING_KEYS - set(value)
    if missing:
        raise ValueError(f"{_PREFIX} is missing settings: " + ", ".join(sorted(missing)))
    if not isinstance(value["enabled"], bool):
        raise ValueError(f"{_PREFIX}.enabled must be a boolean")
    return ImagePinVerificationSettings(enabled=value["enabled"])
