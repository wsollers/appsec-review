from __future__ import annotations

from dataclasses import dataclass
import math
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
    request_timeout_seconds: float = 120
    download_timeout_seconds: float = 90
    max_attempts: int = 6
    retry_delay_seconds: float = 5
    retry_max_delay_seconds: float = 60

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
            request_timeout_seconds=float(value.get("request_timeout_seconds", 120)),
            download_timeout_seconds=float(value.get("download_timeout_seconds", 90)),
            max_attempts=int(value.get("max_attempts", 6)),
            retry_delay_seconds=float(value.get("retry_delay_seconds", 5)),
            retry_max_delay_seconds=float(value.get("retry_max_delay_seconds", 60)),
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
        if not 1 <= settings.max_attempts <= 10:
            raise ValueError("NVD max_attempts must be between 1 and 10")
        for timeout in (settings.request_timeout_seconds, settings.download_timeout_seconds):
            if not math.isfinite(timeout) or not 0 < timeout <= 3600:
                raise ValueError("NVD timeouts must be finite and within (0, 3600] seconds")
        if not (math.isfinite(settings.retry_delay_seconds)
                and math.isfinite(settings.retry_max_delay_seconds)
                and 0 <= settings.retry_delay_seconds <= settings.retry_max_delay_seconds <= 3600):
            raise ValueError("NVD retry delays must be finite and satisfy 0 <= delay <= maximum <= 3600")
        return settings
