from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def atomic_bytes(path: Path, payload: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Keep the temporary leaf short: run-owned directories and hash-addressed final names can
    # already approach the legacy Windows path limit.
    descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(path, canonical_json(value))


def tool_input_json(path: Path, value: Any) -> None:
    """Atomically write JSON that a tool container reads as its non-root runtime user.

    ``atomic_json`` inherits ``mkstemp``'s owner-only ``0600`` mode, which the container user
    (uid 10001) cannot read when the run directory belongs to another host user.
    """
    atomic_json(path, value)
    Path(path).chmod(0o644)


def protected_json(path: Path, value: Any) -> None:
    """Create an immutable attempt-owned JSON artifact without a long temporary path."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical_json(value))
        stream.flush()
        os.fsync(stream.fileno())
    try:
        path.chmod(0o600)
    except OSError:
        pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
