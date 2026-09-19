#!/usr/bin/env python3
"""Narrow, argv-only execution contract for an adopted deterministic child.

This module is deliberately not a general worker controller.  It launches one explicitly
constructed argv array, rejects shell executables, drains both diagnostic streams concurrently,
bounds the retained log bytes, and tears down the complete child tree on every exit path.
"""
from __future__ import annotations

from dataclasses import dataclass
import contextlib
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Callable, Mapping

from execution_state import (ProcessTree, atomic_json, beneath, emergency, event, now,
                             redact_argv)

CONTRACT = "appsec-review/deterministic-child/1.0"
MAX_CONFIGURED_LOG_BYTES = 16 * 1024 * 1024
SHELL_EXECUTABLES = {
    "bash", "bash.exe", "cmd", "cmd.exe", "command.com", "dash", "fish", "ksh", "pwsh",
    "pwsh.exe", "powershell", "powershell.exe", "sh", "sh.exe", "zsh",
}


@dataclass(frozen=True)
class ChildExecutionSpec:
    argv: tuple[str, ...]
    argv_prefix: tuple[str, ...]
    executable: Path
    cwd: Path
    owner_root: Path
    log_dir: Path
    timeout_seconds: float
    stdout_limit_bytes: int
    stderr_limit_bytes: int
    env: Mapping[str, str]


def _absolute(path: Path, label: str, *, must_exist: bool = True) -> Path:
    value = Path(path)
    if not value.is_absolute():
        raise ValueError(f"{label} must be absolute")
    if must_exist and not value.exists():
        raise ValueError(f"{label} does not exist")
    if value.is_symlink() or (hasattr(value, "is_junction") and value.is_junction()):
        raise ValueError(f"{label} may not be a link")
    return value


def validate_spec(spec: ChildExecutionSpec) -> None:
    if not isinstance(spec, ChildExecutionSpec):
        raise TypeError("child execution requires ChildExecutionSpec")
    if not spec.argv or any(not isinstance(value, str) or not value or "\x00" in value
                            for value in spec.argv):
        raise ValueError("argv must be a nonempty tuple of nonempty strings")
    if not spec.argv_prefix or spec.argv[:len(spec.argv_prefix)] != spec.argv_prefix:
        raise ValueError("argv does not match its fixed deterministic prefix")
    executable = _absolute(spec.executable, "executable")
    if executable.is_dir():
        raise ValueError("executable must be a file")
    requested = Path(spec.argv[0])
    if requested.name.lower() in SHELL_EXECUTABLES:
        raise ValueError("shell executables are forbidden by the deterministic-child contract")
    if not requested.is_absolute() or requested.resolve() != executable.resolve():
        raise ValueError("argv[0] must be the declared absolute executable")
    cwd = _absolute(spec.cwd, "cwd")
    if not cwd.is_dir():
        raise ValueError("cwd must be a directory")
    owner = _absolute(spec.owner_root, "owner_root")
    if not owner.is_dir():
        raise ValueError("owner_root must be a directory")
    log_dir = beneath(owner, spec.log_dir)
    if log_dir == owner:
        raise ValueError("log_dir must be beneath owner_root")
    if spec.timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    for label, limit in (("stdout", spec.stdout_limit_bytes),
                         ("stderr", spec.stderr_limit_bytes)):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 0 < limit <= MAX_CONFIGURED_LOG_BYTES:
            raise ValueError(f"{label} log limit must be within 1..{MAX_CONFIGURED_LOG_BYTES}")
    if not isinstance(spec.env, Mapping) or any(
            not isinstance(key, str) or not isinstance(value, str) or "\x00" in key + value
            for key, value in spec.env.items()):
        raise ValueError("env must contain only string keys and values")


def _write_log_chunk(stream, chunk: bytes) -> None:
    """Small fault-injection seam; production writes remain direct binary writes."""
    stream.write(chunk)


def execute_child(spec: ChildExecutionSpec, *, cancel: threading.Event | None = None,
                  observer: Callable[[str, int], None] | None = None) -> dict:
    """Execute one fixed argv and return durable, bounded diagnostic metadata.

    Operational failures are returned in ``error`` after tree cleanup and metadata persistence.
    ``KeyboardInterrupt``/``SystemExit`` are re-raised after the same cleanup so the lifecycle
    coordinator retains the original cancellation type.
    """
    validate_spec(spec)
    log_dir = beneath(spec.owner_root, spec.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    metadata = {
        "schema": CONTRACT,
        "argv": redact_argv(list(spec.argv)),
        "argv_prefix": redact_argv(list(spec.argv_prefix)),
        "cwd": str(spec.cwd),
        "started_at": now(),
        "timeout_seconds": spec.timeout_seconds,
        "log_limits": {"stdout": spec.stdout_limit_bytes, "stderr": spec.stderr_limit_bytes},
        "environment_keys": sorted(spec.env),
        "exit_code": None,
        "signal": None,
        "timed_out": False,
        "cancelled": False,
    }
    stats = {
        "stdout": {"observed_bytes": 0, "written_bytes": 0, "dropped_bytes": 0,
                   "truncated": False},
        "stderr": {"observed_bytes": 0, "written_bytes": 0, "dropped_bytes": 0,
                   "truncated": False},
    }
    limits = {"stdout": spec.stdout_limit_bytes, "stderr": spec.stderr_limit_bytes}
    errors: list[BaseException] = []
    failed = threading.Event()
    threads: list[threading.Thread] = []
    proc: subprocess.Popen | None = None
    tree = ProcessTree()
    streams = {}
    write_lock = threading.Lock()
    raised: BaseException | None = None

    def drain(pipe, name: str) -> None:
        record = stats[name]
        stream = streams[name]
        try:
            while chunk := pipe.read1(65536):
                record["observed_bytes"] += len(chunk)
                remaining = limits[name] - record["written_bytes"]
                if remaining > 0:
                    retained = chunk[:remaining]
                    _write_log_chunk(stream, retained)
                    stream.flush()
                    record["written_bytes"] += len(retained)
                record["dropped_bytes"] = record["observed_bytes"] - record["written_bytes"]
                record["truncated"] = record["dropped_bytes"] > 0
                if observer:
                    observer(name, len(chunk))
            os.fsync(stream.fileno())
        except BaseException as exc:
            errors.append(exc)
            failed.set()
            emergency(exc)
        finally:
            with contextlib.suppress(BaseException):
                pipe.close()

    try:
        for name in ("stdout", "stderr"):
            streams[name] = (log_dir / f"{name}.log").open("wb")
        event(log_dir / "events.jsonl", "START", **metadata)
        gate = Path(__file__).with_name("process_gate.py")
        command = [sys.executable, "-B", str(gate), *spec.argv]
        proc = subprocess.Popen(command, cwd=spec.cwd, env=dict(spec.env), stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=os.name != "nt")
        tree.assign(proc)
        proc.stdin.write(b"1")
        proc.stdin.flush()
        for pipe, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            thread = threading.Thread(target=drain, args=(pipe, name), daemon=True)
            thread.start()
            threads.append(thread)
        while proc.poll() is None:
            if failed.is_set():
                raise OSError("diagnostic stream logging failed")
            if cancel is not None and cancel.is_set():
                metadata["cancelled"] = True
                raise InterruptedError("child execution cancelled")
            if time.monotonic() - start > spec.timeout_seconds:
                metadata["timed_out"] = True
                raise TimeoutError(f"child process timeout after {spec.timeout_seconds}s")
            time.sleep(0.025)
        metadata["exit_code"] = proc.returncode
        metadata["signal"] = -proc.returncode if proc.returncode < 0 else None
    except BaseException as exc:
        raised = exc
        metadata["error"] = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            metadata["cancelled"] = True
    finally:
        tree.close()
        if proc is not None:
            if proc.stdin:
                with contextlib.suppress(BaseException):
                    proc.stdin.close()
            try:
                proc.wait(timeout=10)
                metadata["exit_code"] = proc.returncode
                metadata["signal"] = -proc.returncode if proc.returncode < 0 else None
            except BaseException as exc:
                errors.append(exc)
                metadata["error"] = "child process did not terminate after tree cleanup"
                emergency(exc)
        for thread in threads:
            thread.join(timeout=10)
        if errors or any(thread.is_alive() for thread in threads):
            first = errors[0] if errors else RuntimeError("diagnostic drain thread did not close")
            metadata["error"] = f"diagnostic stream failure: {type(first).__name__}: {first}"
        for stream in streams.values():
            with contextlib.suppress(BaseException):
                stream.close()
        metadata["streams"] = stats
        metadata["ended_at"] = now()
        metadata["duration_seconds"] = time.monotonic() - start
        try:
            for name in ("stdout", "stderr"):
                (log_dir / f"{name}.log").touch(exist_ok=True)
            event(log_dir / "events.jsonl", "END", **metadata)
            atomic_json(log_dir / "command.json", metadata)
        except BaseException as exc:
            emergency(exc)
            raise
    if isinstance(raised, (KeyboardInterrupt, SystemExit)):
        raise raised
    return metadata
