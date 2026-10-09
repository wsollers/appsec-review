from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import time
from typing import BinaryIO


class LockUnavailable(RuntimeError):
    pass


class FileLock:
    """A non-blocking one-byte kernel lock with a visible lock file."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.stream: BinaryIO | None = None

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.stream = self.path.open("a+b")
            self.stream.seek(0, os.SEEK_END)
            if self.stream.tell() == 0:
                self.stream.write(b"\0")
                self.stream.flush()
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if self.stream is not None:
                self.stream.close()
            self.stream = None
            raise LockUnavailable(f"lock is already held: {self.path}") from exc
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.stream is None:
            return
        try:
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.stream.close()
            self.stream = None


@contextmanager
def bounded_file_lock(path: Path, timeout_seconds: int):
    """Wait for a kernel lock for at most ``timeout_seconds``."""
    lock = FileLock(path)
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            lock.__enter__()
            break
        except LockUnavailable:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    try:
        yield
    finally:
        lock.__exit__(None, None, None)
