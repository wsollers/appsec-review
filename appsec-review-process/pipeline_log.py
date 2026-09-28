"""Central pipeline log: one append-only file every job can write to and one command can tail.

    tail -F appsec-review-process/logs/pipeline.log

Callers never wait on disk. ``log()`` formats one line (capped at MAX_LINE_CHARS), appends it to an
in-memory buffer under a lock held only for that append, and returns. A background thread swaps the
buffer out under the same brief lock and does the file IO with no lock held, one batch per flush. If
the disk stalls, the buffer is bounded: further lines are dropped and counted (a single "dropped N"
line is written when the writer catches up), so logging can never block or grow without bound.

Several processes (one per Dagster step) append to the same file. Each batch is written in
line-aligned chunks with O_APPEND, so lines from different processes interleave but do not split.
Rotation at ROTATE_BYTES is best-effort and racy across processes by design (worst case: an extra
rotation). Logging never raises.

Environment: ``APPSEC_PIPELINE_LOG`` overrides the path; ``off`` (or ``0``/``false``/empty) disables.
"""
from __future__ import annotations

import atexit
import collections
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

MAX_LINE_CHARS = 1024          # whole line, prefix included
MAX_BUFFERED_LINES = 20000     # beyond this, lines are dropped and counted
FLUSH_SECONDS = 0.25           # writer wake-up interval
EAGER_FLUSH_LINES = 512        # wake the writer early once this many lines are waiting
MAX_WRITE_BYTES = 256 * 1024   # size of one os.write batch
ROTATE_BYTES = 10 * 1024 * 1024
ROTATE_KEEP = 3
DEFAULT_PATH = Path(__file__).resolve().parent / "logs" / "pipeline.log"
_OFF = {"", "off", "0", "false", "no"}

_lock = threading.Lock()
_buffer: collections.deque[str] = collections.deque()
_dropped = 0
_wake = threading.Event()
_writer: threading.Thread | None = None
_writer_pid: int | None = None


def _target() -> Path | None:
    value = os.environ.get("APPSEC_PIPELINE_LOG")
    if value is None:
        return DEFAULT_PATH
    return None if value.strip().lower() in _OFF else Path(value)


def _format(message: object, run_id: object = None, job: object = None) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    prefix = f"{stamp} pid={os.getpid()}"
    if run_id:
        prefix += f" run={run_id}"
    if job:
        prefix += f" job={job}"
    text = str(message).replace("\r", " ").replace("\n", "\\n")
    line = f"{prefix} {text}"
    if len(line) > MAX_LINE_CHARS:
        cut = len(line) - MAX_LINE_CHARS
        suffix = f"...[+{cut + 12} chars]"
        line = line[:MAX_LINE_CHARS - len(suffix)] + suffix
    return line


def _rotate(path: Path) -> None:
    try:
        if path.stat().st_size < ROTATE_BYTES:
            return
        for index in range(ROTATE_KEEP - 1, 0, -1):
            source = path.with_name(f"{path.name}.{index}")
            if source.exists():
                os.replace(source, path.with_name(f"{path.name}.{index + 1}"))
        os.replace(path, path.with_name(f"{path.name}.1"))
    except OSError:
        pass


def _write(path: Path, lines: list[str]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _rotate(path)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    except OSError:
        return
    try:
        batch: list[bytes] = []
        size = 0
        for line in lines:
            data = (line + "\n").encode("utf-8", "replace")
            if batch and size + len(data) > MAX_WRITE_BYTES:
                _write_all(fd, b"".join(batch))
                batch, size = [], 0
            batch.append(data)
            size += len(data)
        if batch:
            _write_all(fd, b"".join(batch))
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def flush() -> None:
    """Write everything buffered now. The writer thread calls this; tests and exit hooks may too."""
    global _dropped
    with _lock:                       # brief: swap the buffer out, no IO here
        lines = list(_buffer)
        _buffer.clear()
        dropped, _dropped = _dropped, 0
    if dropped:
        lines.append(_format(f"pipeline-log dropped {dropped} line(s): buffer full"))
    path = _target()
    if lines and path is not None:
        _write(path, lines)           # all IO happens with no lock held


def _run() -> None:
    while True:
        _wake.wait(FLUSH_SECONDS)
        _wake.clear()
        try:
            flush()
        except Exception:
            pass


def _reset_after_fork() -> None:
    global _lock, _writer, _writer_pid, _dropped
    _lock = threading.Lock()          # the parent's lock may have been held mid-fork
    _buffer.clear()
    _dropped = 0
    _writer = _writer_pid = None


def _ensure_writer() -> None:
    global _writer, _writer_pid
    if _writer is not None and _writer_pid == os.getpid() and _writer.is_alive():
        return
    with _lock:
        if _writer is not None and _writer_pid == os.getpid() and _writer.is_alive():
            return
        _writer = threading.Thread(target=_run, name="pipeline-log-writer", daemon=True)
        _writer_pid = os.getpid()
        _writer.start()


def log(message: object, *, run_id: object = None, job: object = None) -> None:
    """Queue one line. Returns immediately; never raises; never waits on disk."""
    global _dropped
    try:
        if _target() is None:
            return
        line = _format(message, run_id, job)
        _ensure_writer()
        with _lock:
            if len(_buffer) >= MAX_BUFFERED_LINES:
                _dropped += 1
                pending = 0
            else:
                _buffer.append(line)
                pending = len(_buffer)
        if pending >= EAGER_FLUSH_LINES:
            _wake.set()
    except Exception:
        pass


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)
atexit.register(lambda: flush())
