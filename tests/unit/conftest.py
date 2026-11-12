"""The unit tier: code-level tests that never reach an engine, a model, a network or Dagster.

Everything under ``tests/unit/`` runs under these rules, enforced here rather than by review:

- **Ten seconds.** Setup, call and teardown together must finish within the ``unit`` tier budget
  (``unit_time_budget_seconds`` in pyproject.toml, 10 s). The root harness fails the test when it
  crosses the line; see ``tests/time_budgets.py``.
- **No real engines or clients.** Starting ``docker``, ``podman``, ``claude``, ``codex``, ``gh``
  or a Dagster process is refused. A fake executable created under the session's scratch root is
  allowed, because that is how a test proves the argv a job would pass.
- **No network.** A socket may connect to loopback only; everything else is refused.
- **No Dagster execution.** ``execute_job``, ``materialize`` and ``execute_in_process`` are refused
  once ``dagster`` is imported. Dagster graphs belong to the acceptance tier.

A refused call fails the test with ``UnitTierViolation``. The fix is a fake at the boundary, a
canned fixture, or moving the test to ``tests/integration/`` or ``tests/acceptance/``.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket
import subprocess
import sys
from typing import Any

import pytest


class UnitTierViolation(RuntimeError):
    """A unit test reached something outside the unit tier."""


BLOCKED_EXECUTABLES = frozenset({
    "docker", "podman", "nerdctl",
    "claude", "codex", "copilot", "gh",
    "dagster", "dagster-daemon", "dagster-webserver", "dagster-graphql",
})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0", "::"})

_SCRATCH_ROOT = pytest.StashKey[Path]()


def executable_name(args: Any, shell: bool = False) -> tuple[str, str | None]:
    """The program a ``Popen`` call starts: its basename and, when given as a path, that path."""
    if shell:
        command = os.fsdecode(args) if isinstance(args, (str, bytes, os.PathLike)) else ""
        first = command.split(maxsplit=1)[0] if command.strip() else ""
    elif isinstance(args, (str, bytes, os.PathLike)):
        first = os.fsdecode(args)
    else:
        try:
            head = args[0] if args else ""
        except (TypeError, KeyError, IndexError):
            head = ""
        first = os.fsdecode(head) if isinstance(head, (bytes, os.PathLike)) else str(head)
    name = os.path.basename(first)
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return name, (first if os.sep in first or (os.altsep and os.altsep in first) else None)


def blocked_executable(args: Any, shell: bool, scratch_root: Path | None) -> str | None:
    """The blocked program this call would start, or ``None`` when the call is allowed."""
    name, path = executable_name(args, shell)
    if name not in BLOCKED_EXECUTABLES:
        return None
    if path is not None and scratch_root is not None:
        try:
            Path(path).resolve().relative_to(scratch_root.resolve())
            return None  # a fake created by the test itself
        except ValueError:
            pass
    return name


def is_loopback(address: Any) -> bool:
    if isinstance(address, (str, bytes)):
        return True  # AF_UNIX
    try:
        host = address[0]
    except (TypeError, IndexError, KeyError):
        return False
    return isinstance(host, str) and (host in LOOPBACK_HOSTS or host.startswith("127."))


def _scratch_root(config: pytest.Config) -> Path | None:
    """The session's pytest base temp, resolved lazily (the tmpdir plugin configures after us)."""
    cached = config.stash.get(_SCRATCH_ROOT, None)
    if cached is not None:
        return cached
    factory = getattr(config, "_tmp_path_factory", None)
    if factory is None:
        return None
    try:
        root = Path(factory.getbasetemp())
    except Exception:  # pragma: no cover - base temp unavailable in exotic invocations
        return None
    config.stash[_SCRATCH_ROOT] = root
    return root


def _install_guards(config: pytest.Config) -> None:
    real_popen_init = subprocess.Popen.__init__

    def guarded_popen_init(self, args, *positional, **keywords):  # type: ignore[no-untyped-def]
        shell = bool(keywords.get("shell", positional[7] if len(positional) > 7 else False))
        name = blocked_executable(args, shell, _scratch_root(config))
        if name is not None:
            raise UnitTierViolation(
                f"unit tests never launch {name!r}: fake the executor at its boundary, or move the test "
                "to tests/integration or tests/acceptance")
        real_popen_init(self, args, *positional, **keywords)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def guarded_connect(self, address):  # type: ignore[no-untyped-def]
        if not is_loopback(address):
            raise UnitTierViolation(f"unit tests never open network connections: {address!r}")
        return real_connect(self, address)

    def guarded_connect_ex(self, address):  # type: ignore[no-untyped-def]
        if not is_loopback(address):
            raise UnitTierViolation(f"unit tests never open network connections: {address!r}")
        return real_connect_ex(self, address)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(subprocess.Popen, "__init__", guarded_popen_init)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    config.add_cleanup(monkeypatch.undo)


_DAGSTER_PATCHED = "_appsec_unit_tier_dagster_guard"


def _refuse_dagster(*args: Any, **kwargs: Any) -> None:
    raise UnitTierViolation("unit tests never execute Dagster jobs; Dagster graphs are acceptance tests")


def guard_dagster_if_imported() -> bool:
    """Refuse Dagster execution entry points once the package is imported; idempotent."""
    module = sys.modules.get("dagster")
    if module is None or getattr(module, _DAGSTER_PATCHED, False):
        return module is not None
    for name in ("execute_job", "materialize", "materialize_to_memory"):
        if hasattr(module, name):
            setattr(module, name, _refuse_dagster)
    for class_name in ("JobDefinition", "GraphDefinition"):
        definition = getattr(module, class_name, None)
        if definition is not None and hasattr(definition, "execute_in_process"):
            setattr(definition, "execute_in_process", _refuse_dagster)
    setattr(module, _DAGSTER_PATCHED, True)
    return True


def pytest_configure(config: pytest.Config) -> None:
    _install_guards(config)


@pytest.fixture(autouse=True)
def _no_disk_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    """Durability is not what a unit test checks: ``os.fsync`` is a no-op in this tier.

    Atomic writes and SQLite snapshots call it on every publication; under a parallel run those
    flushes alone pushed correct tests past the ten-second line (T-107 faked it per test first).
    """
    monkeypatch.setattr(os, "fsync", lambda descriptor: None)


def pytest_runtest_setup(item: pytest.Item) -> None:
    guard_dagster_if_imported()


def pytest_runtest_call(item: pytest.Item) -> None:
    guard_dagster_if_imported()
