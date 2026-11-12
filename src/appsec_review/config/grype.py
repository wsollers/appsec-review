"""Bounded settings for the network-enabled Grype database publisher."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class GrypeSettings:
    feed_root: Path
    listing_url: str = "https://grype.anchore.io/databases/v6/latest.json"
    allowed_hosts: tuple[str, ...] = ("grype.anchore.io",)
    tool_version: str = "0.119.0"
    schema_major: int = 6
    max_listing_bytes: int = 65536
    max_archive_bytes: int = 1073741824
    max_uncompressed_bytes: int = 4294967296
    max_database_bytes: int = 4294967296
    max_archive_members: int = 8
    max_zstd_window_bytes: int = 134217728
    max_age_seconds: int = 432000
    max_future_seconds: int = 300
    download_timeout_seconds: int = 300
    run_timeout_seconds: int = 900
    memory: str = "6g"

    @classmethod
    def from_mapping(cls, root: Path, value: Mapping[str, Any]) -> "GrypeSettings":
        unknown = set(value) - {field.name for field in fields(cls)}
        if unknown:
            raise ValueError(f"unknown Grype sync settings: {sorted(unknown)}")
        feed = value.get("feed_root", "data/feeds/grype")
        if not isinstance(feed, str) or not feed.strip():
            raise ValueError("Grype feed_root must be a nonempty path")
        path = (root / feed).resolve()
        if not path.is_relative_to((root / "data").resolve()) or path == (root / "data").resolve():
            raise ValueError("Grype feed_root must be beneath repository data")
        values = dict(value)
        values["feed_root"] = path
        hosts = values.get("allowed_hosts", cls.__dataclass_fields__["allowed_hosts"].default)
        if (not isinstance(hosts, (list, tuple)) or not hosts or len(hosts) > 16
                or any(not isinstance(host, str) or not re.fullmatch(r"[a-z0-9.-]+", host) for host in hosts)
                or len(set(hosts)) != len(hosts)):
            raise ValueError("Grype allowed_hosts must be a bounded unique HTTPS hostname list")
        values["allowed_hosts"] = tuple(hosts)
        settings = cls(**values)
        for field in fields(cls):
            if field.name.startswith("max_") or field.name.endswith("_seconds"):
                limit = getattr(settings, field.name)
                if type(limit) is not int or limit < 1:
                    raise ValueError(f"Grype {field.name} must be a positive integer")
        if type(settings.schema_major) is not int or settings.schema_major != 6:
            raise ValueError("Grype sync supports only database schema major 6")
        if settings.max_zstd_window_bytes < 1024:
            raise ValueError("Grype max_zstd_window_bytes must be at least 1024")
        if not isinstance(settings.tool_version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", settings.tool_version):
            raise ValueError("Grype tool_version must be an exact release")
        if not isinstance(settings.memory, str) or not re.fullmatch(r"[1-9][0-9]{0,5}[mg]", settings.memory):
            raise ValueError("Grype memory must be a bounded container memory size")
        if not isinstance(settings.listing_url, str):
            raise ValueError("Grype listing_url must be HTTPS")
        settings.require_url(settings.listing_url)
        return settings

    def view(self, root: Path) -> dict[str, Any]:
        return {**asdict(self), "feed_root": self.feed_root.relative_to(root.resolve()).as_posix(),
                "allowed_hosts": list(self.allowed_hosts)}

    def require_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname not in self.allowed_hosts
                or parsed.username or parsed.password or parsed.port not in (None, 443)
                or parsed.fragment):
            raise ValueError("Grype source URL is outside its HTTPS allowlist")
