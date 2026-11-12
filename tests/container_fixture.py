"""Copy the container descriptors a test needs without copying a host's built tool assets.

``containers/`` holds small tracked descriptors (locks, manifests, build scripts; the largest is
under 1 MiB) next to untracked host-local material that an operator builds there: tool archives,
build environments and downloads, several gigabytes on a review host. A fixture that
``copytree``s the directory copies all of it for every test, which makes a unit test take minutes
and a parallel run saturate the disk. Descriptors are small; anything larger is host-local.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil

MAX_DESCRIPTOR_BYTES = 2 * 1024 * 1024


def _skip_large(directory: str, names: list[str]) -> list[str]:
    skipped = []
    for name in names:
        path = Path(directory, name)
        if name == "__pycache__" or name == "downloads":
            skipped.append(name)
        elif path.is_file() and not path.is_symlink() and path.stat().st_size > MAX_DESCRIPTOR_BYTES:
            skipped.append(name)
    return skipped


def copy_containers(root: Path, destination: Path) -> None:
    """Copy ``root/containers`` to ``destination/containers`` minus large host-local files."""
    shutil.copytree(os.fspath(root / "containers"), os.fspath(destination / "containers"), ignore=_skip_large)
