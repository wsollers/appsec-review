"""Verification of run-owned artifact identities before they are reused or republished."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path, PurePosixPath
import stat
from typing import Any

from .atomic import file_sha256


class ArtifactIntegrityError(ValueError):
    """An accepted run-owned artifact is missing, moved, retyped, resized, or changed."""


def run_artifact(run_root: Path, path: Path) -> dict[str, Any]:
    """Return the ``path``/``sha256``/``size_bytes`` identity of a regular file inside ``run_root``."""
    root = Path(run_root).resolve()
    candidate = Path(path)
    resolved = candidate.resolve(strict=True)
    if root not in resolved.parents or candidate.is_symlink():
        raise ArtifactIntegrityError(f"artifact is not a run-owned file: {path}")
    return {"path": resolved.relative_to(root).as_posix(), "sha256": file_sha256(resolved),
            "size_bytes": resolved.stat().st_size}


def verify_run_artifact(run_root: Path, identity: Mapping[str, Any], *, path_key: str = "path") -> Path:
    """Check containment, type, size, and SHA-256 of one recorded run-owned artifact.

    The recorded path must be relative and normalized, no component may be a symlink, the final
    component must be a regular file, and when the identity records ``size_bytes`` it must match.
    """
    relative = identity.get(path_key)
    expected = identity.get("sha256")
    if not isinstance(relative, str) or not isinstance(expected, str) or len(expected) != 64:
        raise ArtifactIntegrityError("artifact identity is incomplete")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts) \
            or pure.as_posix() != relative:
        raise ArtifactIntegrityError(f"artifact path is not a normalized run path: {relative!r}")
    root = Path(run_root).resolve()
    current = root
    for part in pure.parts:
        current = current / part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as exc:
            raise ArtifactIntegrityError(f"accepted artifact is missing: {relative}") from exc
        if stat.S_ISLNK(mode):
            raise ArtifactIntegrityError(f"accepted artifact path contains a symlink: {relative}")
    if not stat.S_ISREG(mode):
        raise ArtifactIntegrityError(f"accepted artifact is not a regular file: {relative}")
    size = identity.get("size_bytes")
    if size is not None and current.stat().st_size != size:
        raise ArtifactIntegrityError(f"accepted artifact size changed: {relative}")
    if file_sha256(current) != expected:
        raise ArtifactIntegrityError(f"accepted artifact identity changed: {relative}")
    return current
