"""Host-portable helpers shared by the signing unit tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from appsec_review.signing import core

OPENSSL_BINARY = core.default_openssl()

POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes and FIFOs are not available on Windows")


def symlink(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    """Create ``link``; on Windows skip the test when the symlink privilege is missing."""
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except OSError as error:
        if os.name == "nt":
            pytest.skip(f"creating symbolic links requires a privilege on Windows: {error}")
        raise
