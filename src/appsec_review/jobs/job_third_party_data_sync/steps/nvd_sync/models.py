from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class NvdSettings:
    feed_root: Path
    api_key_env: str
    first_year: int
    page_size: int
    max_window_days: int
    request_delay_with_key_seconds: float
    request_delay_without_key_seconds: float
    max_download_bytes: int
    max_api_response_bytes: int

    @classmethod
    def from_mapping(cls, root: Path, value: Mapping[str, Any]) -> "NvdSettings":
        configured_root = Path(str(value.get("feed_root", "")))
        if not str(configured_root):
            raise ValueError("feed_root is required")
        feed_root = (root / configured_root).resolve() if not configured_root.is_absolute() else configured_root.resolve()
        settings = cls(
            feed_root=feed_root,
            api_key_env=str(value.get("api_key_env", "NVD_API_KEY")),
            first_year=int(value.get("first_year", 2002)),
            page_size=int(value.get("page_size", 2000)),
            max_window_days=int(value.get("max_window_days", 119)),
            request_delay_with_key_seconds=float(value.get("request_delay_with_key_seconds", 0.6)),
            request_delay_without_key_seconds=float(value.get("request_delay_without_key_seconds", 6.0)),
            max_download_bytes=int(value.get("max_download_bytes", 512 * 1024 * 1024)),
            max_api_response_bytes=int(value.get("max_api_response_bytes", 64 * 1024 * 1024)),
        )
        if settings.first_year < 1999:
            raise ValueError("first_year cannot precede CVE year 1999")
        if not 1 <= settings.page_size <= 2000:
            raise ValueError("page_size must be between 1 and 2000")
        if not 1 <= settings.max_window_days <= 120:
            raise ValueError("max_window_days must be between 1 and 120")
        if not settings.api_key_env or not settings.api_key_env.replace("_", "").isalnum():
            raise ValueError("api_key_env is invalid")
        if settings.request_delay_with_key_seconds < 0 or settings.request_delay_without_key_seconds < 0:
            raise ValueError("request delays cannot be negative")
        if settings.max_download_bytes < 1 or settings.max_api_response_bytes < 1:
            raise ValueError("NVD download bounds must be positive")
        return settings
