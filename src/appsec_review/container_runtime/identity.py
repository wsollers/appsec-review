from __future__ import annotations

import os
from pathlib import Path
import re


_NUMERIC_USER = re.compile(r"[1-9][0-9]*:[1-9][0-9]*")


def application_runtime_user(fallback: str) -> str:
    """Return the non-root uid/gid that owns application run data."""
    if not _NUMERIC_USER.fullmatch(fallback):
        raise ValueError("container fallback user must be numeric and non-root")
    getuid = getattr(os, "geteuid", None)
    getgid = getattr(os, "getegid", None)
    if getuid is None or getgid is None:
        return fallback
    uid, gid = int(getuid()), int(getgid())
    if uid < 1 or gid < 1:
        return fallback
    return f"{uid}:{gid}"


def grant_runtime_user(root: Path, runtime_user: str, *, recursive: bool = False,
                       writable_files: bool = False) -> None:
    """Give the container's ``runtime_user`` owner-only write access to ``root``; never world access.

    A non-root application already runs its containers as its own uid/gid, so owner bits suffice. A
    root application hands the tree to the container uid/gid instead of opening it to every host user.
    """
    if not _NUMERIC_USER.fullmatch(runtime_user):
        raise ValueError("container runtime user must be numeric and non-root")
    uid, gid = (int(part) for part in runtime_user.split(":", 1))
    geteuid = getattr(os, "geteuid", None)
    hand_over = geteuid is not None and geteuid() == 0 and uid != 0
    for path in (root, *(root.rglob("*") if recursive else ())):
        if path.is_symlink():
            continue
        if hand_over:
            os.chown(path, uid, gid)
        mode = path.stat().st_mode & 0o7777
        if path.is_dir():
            path.chmod((mode & ~0o077) | 0o700)
        elif path.is_file():
            path.chmod((mode & ~0o077) | 0o600 if writable_files else (mode & 0o500) | 0o400)
