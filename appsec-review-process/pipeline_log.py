"""Pipeline log: one JSON-lines file per run, written by every job and process, tailed with one command.

    orchestrator/tail-run-log.sh <run-id>

Where: ``runs/<run_id>/data/logs/pipeline.log`` for a run that has a directory; the global
``logs/pipeline.log`` otherwise (daemons and persistent processes have no run). One file per run: it is
appended to at intake and at each resume, and each of those sessions opens with three lines of ``#``
and a ``banner`` record.

Each line is a JSON object: ts, run, job, step, pid, proc, who (the id of the thing logging: reviewer-03,
a claude pid, a pool instance), attempt, level, msg (capped at MAX_MSG_CHARS). Context comes from
``set_context`` / ``context`` or the ``APPSEC_LOG_{RUN,JOB,STEP,WHO,ATTEMPT,PROC}`` environment, which child
processes inherit. Query with ``jq -R 'fromjson? | select(.level=="warn")'`` or ripgrep.

Callers never wait on disk. ``log()`` builds one record, appends it to an in-memory buffer under a lock
held only for that append, and returns. A background thread swaps the buffer out under the same brief
lock and does the file IO with no lock held. If the disk stalls the buffer is bounded: further lines are
dropped and counted (a single "dropped N" line is written when the writer catches up). Several processes
append to the same file; each batch is written in line-aligned chunks with O_APPEND, so lines from
different processes interleave but do not split. Logging never raises.

Environment: ``APPSEC_PIPELINE_LOG`` forces every line to one file; ``off`` (or ``0``/``false``/empty)
disables; ``APPSEC_RUNS_ROOT`` locates the runs directory.
"""
from __future__ import annotations

import atexit
import collections
import contextlib
import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

MAX_MSG_CHARS = 1024           # the msg field; the record adds its own small envelope
MAX_BUFFERED_LINES = 20000     # beyond this, lines are dropped and counted
FLUSH_SECONDS = 0.25           # writer wake-up interval
EAGER_FLUSH_LINES = 512        # wake the writer early once this many lines are waiting
MAX_WRITE_BYTES = 256 * 1024   # size of one os.write batch
ROTATE_BYTES = 10 * 1024 * 1024   # global file only; a run's log is one file per run and is not rotated
ROTATE_KEEP = 3
ROOT = Path(__file__).resolve().parent
DEFAULT_PATH = ROOT / "logs" / "pipeline.log"
BANNER_LINE = "#" * 80
CONTEXT_KEYS = ("run", "job", "step", "who", "attempt")
_OFF = {"", "off", "0", "false", "no"}

_lock = threading.Lock()
_io_lock = threading.Lock()    # serialises flushers (writer thread, exit hook, tests); log() never takes it
_buffer: collections.deque[tuple[Path | None, str]] = collections.deque()
_dropped = 0
_wake = threading.Event()
_writer: threading.Thread | None = None
_writer_pid: int | None = None
_ctx: dict[str, str] = {}


def _runs_root() -> Path:
    return Path(os.environ.get("APPSEC_RUNS_ROOT") or ROOT / "runs")


def run_log_path(run_id: str) -> Path:
    """Where one run's log lives: ``runs/<run_id>/data/logs/pipeline.log``."""
    return _runs_root() / str(run_id) / "data" / "logs" / "pipeline.log"


def _override() -> tuple[bool, Path | None]:
    """(overridden, path). ``APPSEC_PIPELINE_LOG`` forces one file for everything; off disables."""
    value = os.environ.get("APPSEC_PIPELINE_LOG")
    if value is None:
        return False, None
    return True, (None if value.strip().lower() in _OFF else Path(value))


def _destination(run: str | None) -> tuple[bool, Path | None]:
    """(enabled, path); path None = the global file. A run without a directory falls back to global."""
    overridden, path = _override()
    if overridden:
        return path is not None, path
    if run:
        try:
            if (_runs_root() / str(run)).is_dir():
                return True, run_log_path(run)
        except OSError:
            pass
    return True, None


# ---- context: which job / step / process / thing is logging -------------------------------------

def set_context(**values: object) -> None:
    """Set run/job/step/who/attempt for this process (and, through the environment, its children)."""
    for key, value in values.items():
        if key not in CONTEXT_KEYS:
            continue
        env = "APPSEC_LOG_" + key.upper()
        if value in (None, ""):
            _ctx.pop(key, None)
            os.environ.pop(env, None)
        else:
            _ctx[key] = str(value)
            os.environ[env] = str(value)


def get_context() -> dict[str, str]:
    values = {key: os.environ["APPSEC_LOG_" + key.upper()] for key in CONTEXT_KEYS
              if os.environ.get("APPSEC_LOG_" + key.upper())}
    values.update(_ctx)
    return values


@contextlib.contextmanager
def context(**values: object):
    """Temporarily narrow the context (for example ``who='reviewer-03'``)."""
    saved = get_context()
    set_context(**{key: values[key] for key in values if key in CONTEXT_KEYS})
    try:
        yield
    finally:
        set_context(**{key: saved.get(key) for key in CONTEXT_KEYS})


def _proc() -> str:
    name = os.environ.get("APPSEC_LOG_PROC")
    if name:
        return name
    argv0 = Path(sys.argv[0]).name if sys.argv and sys.argv[0] else ""
    return argv0 if argv0 and argv0 != "-c" else "python"


# ---- formatting ---------------------------------------------------------------------------------

def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _cap(message: object) -> str:
    text = str(message).replace("\r", " ").replace("\n", "\\n")
    if len(text) > MAX_MSG_CHARS:
        cut = len(text) - MAX_MSG_CHARS
        suffix = f"...[+{cut + 12} chars]"
        text = text[:MAX_MSG_CHARS - len(suffix)] + suffix
    return text


def _record(message: object, level: str, fields: dict[str, object]) -> tuple[str | None, str]:
    values = get_context()
    for key in CONTEXT_KEYS:
        given = fields.get(key)
        if given not in (None, ""):
            values[key] = str(given)
    record: dict[str, object] = {"ts": _stamp(), "run": values.get("run"), "job": values.get("job"),
        "step": values.get("step"), "pid": os.getpid(), "proc": _proc(), "who": values.get("who"),
        "attempt": values.get("attempt"), "level": level, "msg": _cap(message)}
    record = {key: value for key, value in record.items() if value is not None}
    return values.get("run"), json.dumps(record, ensure_ascii=False, separators=(",", ":"))


# ---- writer (unchanged discipline: brief lock, IO outside it, line-aligned O_APPEND batches) ----

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


def _write(path: Path, lines: list[str], rotate: bool) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if rotate:
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
    """Write everything buffered now. The writer thread calls this; tests and exit hooks may too.
    Returns only after this and any concurrent flush have finished their IO."""
    with _io_lock:
        _flush_locked()


def _flush_locked() -> None:
    global _dropped
    with _lock:                       # brief: swap the buffer out, no IO here
        items = list(_buffer)
        _buffer.clear()
        dropped, _dropped = _dropped, 0
    if dropped:
        items.append((None, _record(f"pipeline-log dropped {dropped} line(s): buffer full", "warn", {})[1]))
    grouped: dict[Path | None, list[str]] = {}
    for path, line in items:
        grouped.setdefault(path, []).append(line)
    for path, lines in grouped.items():          # all IO happens with no lock held
        target = path
        if target is None:
            overridden, forced = _override()
            if overridden and forced is None:
                continue
            target = forced or DEFAULT_PATH
        _write(target, lines, rotate=path is None)


def _run() -> None:
    while True:
        _wake.wait(FLUSH_SECONDS)
        _wake.clear()
        try:
            flush()
        except Exception:
            pass


def _reset_after_fork() -> None:
    global _lock, _io_lock, _writer, _writer_pid, _dropped
    _lock = threading.Lock()
    _io_lock = threading.Lock()          # the parent's lock may have been held mid-fork
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


def _enqueue(items: list[tuple[Path | None, str]]) -> None:
    global _dropped
    _ensure_writer()
    with _lock:
        if len(_buffer) + len(items) > MAX_BUFFERED_LINES:
            _dropped += len(items)
            pending = 0
        else:
            _buffer.extend(items)
            pending = len(_buffer)
    if pending >= EAGER_FLUSH_LINES:
        _wake.set()


# ---- public API ---------------------------------------------------------------------------------

def log(message: object, *, level: str = "info", run_id: object = None, job: object = None,
        step: object = None, who: object = None, attempt: object = None) -> None:
    """Queue one JSON line. Returns immediately; never raises; never waits on disk."""
    try:
        run, line = _record(message, level, {"run": run_id, "job": job, "step": step, "who": who, "attempt": attempt})
        enabled, path = _destination(run)
        if not enabled:
            return
        _enqueue([(path, line)])
    except Exception:
        pass


def banner(run_id: object, reason: str, **info: object) -> None:
    """Start of a new append session for a run: three lines of ``#`` then one JSON marker line.

    Written once at intake and once per resume (see ``banner_once``). jq -R 'fromjson?' skips the
    ``#`` lines; ripgrep finds them with ``^#{80}$``."""
    try:
        detail = " ".join(f"{key}={value}" for key, value in sorted(info.items()))
        run, marker = _record(f"session start: {reason}" + (f" ({detail})" if detail else ""), "banner",
                              {"run": run_id})
        enabled, path = _destination(run)
        if not enabled:
            return
        _enqueue([(path, BANNER_LINE)] * 3 + [(path, marker)])
    except Exception:
        pass


def banner_once(run_id: object, key: str, reason: str, **info: object) -> bool:
    """``banner`` at most once per ``key`` (for example the Dagster run id): the first process wins."""
    try:
        enabled, path = _destination(str(run_id))
        if not enabled or path is None:
            banner(run_id, reason, **info)
            return True
        path.parent.mkdir(parents=True, exist_ok=True)
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(key))[:80]
        fd = os.open(path.parent / f".banner-{safe}", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(fd)
    except FileExistsError:
        return False
    except OSError:
        return False
    banner(run_id, reason, **info)
    return True


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)
atexit.register(lambda: flush())
