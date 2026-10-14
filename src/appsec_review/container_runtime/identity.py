from __future__ import annotations

import os
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
