"""Expose a verified OSV snapshot to osv-scanner's ``--experimental-offline`` local database layout.

osv-scanner 1.9.2 reads ``$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY/osv-scanner/<ecosystem>/all.zip``.
The synchronized snapshot (job_third_party_data_sync osv_sync) publishes one
``sources/<quoted ecosystem>.zip`` per configured ecosystem. Each ecosystem an invocation's
lockfiles need is bind mounted read-only at its expected path, so nothing is copied and no
ecosystem is hardcoded. Offline mode loads every database present in that layout into memory
(npm.zip alone expands to 368 MB of JSON), so callers mount only the ecosystems they need.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path
import re
from types import MappingProxyType
import urllib.parse

from appsec_review.container_runtime import Mount


DATABASE_ROOT = "/database"
ENVIRONMENT = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
_SAFE_ECOSYSTEM = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+ -]{0,63}")


def snapshot_ecosystems(snapshot_directory: Path) -> Mapping[str, Path]:
    """Ecosystem name -> published archive for every ecosystem in a verified OSV snapshot."""
    sources = snapshot_directory / "sources"
    found: dict[str, Path] = {}
    for archive in sorted(sources.glob("*.zip")) if sources.is_dir() else ():
        name = urllib.parse.unquote(archive.stem)
        if not _SAFE_ECOSYSTEM.fullmatch(name) or not archive.is_file() or archive.is_symlink():
            raise ValueError(f"OSV snapshot archive name is unsafe: {archive.name}")
        found[name] = archive
    if not found:
        raise ValueError("verified OSV snapshot contains no ecosystem archives")
    return MappingProxyType(found)


def database_mount_target(ecosystem: str) -> str:
    """Where osv-scanner's offline mode reads one ecosystem's database."""
    return f"{DATABASE_ROOT}/osv-scanner/{ecosystem}/all.zip"


def offline_database_mounts(ecosystems: Mapping[str, Path],
                            needed: Iterable[str] | None = None) -> tuple[Mount, ...]:
    """Read-only per-ecosystem file mounts in osv-scanner's offline local-database layout.

    ``needed`` restricts the mounts to those ecosystems (names absent from the snapshot are
    ignored; callers name them as gaps before launch). ``None`` mounts every ecosystem.
    """
    wanted = None if needed is None else set(needed)
    return tuple(Mount(archive, database_mount_target(name), True)
                 for name, archive in sorted(ecosystems.items())
                 if wanted is None or name in wanted)
