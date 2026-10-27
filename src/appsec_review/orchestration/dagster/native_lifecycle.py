"""Foreground native app supervisor; root engine provisioning is deliberately separate."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import time
from typing import Protocol

from appsec_review.config.native_dagster import NativeDagsterConfig, load_native_dagster_config
from appsec_review.container_runtime.buildkit_worker import private_path, process_token
from appsec_review.orchestration.dagster.native import child_environment, _sync_directory
from appsec_review.storage import atomic_json, bounded_file_lock


class NativeReadiness(Protocol):
    def before_start(self) -> None: ...
    def connected(self) -> bool: ...
    def before_stop(self) -> None: ...
    def shutdown_complete(self) -> bool: ...


_DATABASE_DEADLINE: ContextVar[float | None] = ContextVar("native_database_deadline", default=None)


@contextmanager
def database_deadline(seconds: int = 5):
    deadline = time.monotonic() + seconds
    current = _DATABASE_DEADLINE.get()
    token = _DATABASE_DEADLINE.set(min(current, deadline) if current is not None else deadline)
    try:
        yield
    finally:
        _DATABASE_DEADLINE.reset(token)


def _wait_for_postgres(connection) -> None:
    from psycopg2.extensions import POLL_OK, POLL_READ, POLL_WRITE

    deadline = min(_DATABASE_DEADLINE.get() or float("inf"), time.monotonic() + 5)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            connection.close()
            raise TimeoutError("native PostgreSQL client deadline exceeded")
        state = connection.poll()
        if state == POLL_OK:
            return
        if state not in {POLL_READ, POLL_WRITE}:
            connection.close()
            raise RuntimeError("native PostgreSQL polling state is invalid")
        descriptor = connection.fileno()
        readable, writable, _ = select.select(
            [descriptor] if state == POLL_READ else [],
            [descriptor] if state == POLL_WRITE else [], [], remaining)
        if not readable and not writable:
            connection.close()
            raise TimeoutError("native PostgreSQL socket did not respond before its deadline")


@contextmanager
def bounded_postgres():
    from psycopg2.extensions import get_wait_callback, set_wait_callback

    previous = get_wait_callback()
    set_wait_callback(_wait_for_postgres)
    try:
        yield
    finally:
        set_wait_callback(previous)


@contextmanager
def scheduler_ownership(config: NativeDagsterConfig):
    """Hold a database-scoped lock, not merely a local PID file, for the whole scheduler lifetime."""
    import psycopg2

    password = os.environ.get(config.postgres_password_env)
    if not password:
        raise ValueError("native PostgreSQL password environment is unavailable")
    connection = psycopg2.connect(
        host=config.postgres_host, port=config.postgres_port, dbname=config.postgres_database,
        user=config.postgres_user, password=password, **config.postgres_parameters())
    connection.autocommit = True
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_try_advisory_lock(%s)", (0x415050534543,))
            if cursor.fetchone() != (True,):
                raise RuntimeError("native database already has a scheduler owner")
        yield connection
    finally:
        connection.close()


def active_runs(instance) -> bool:
    from dagster import DagsterRunStatus, RunsFilter

    statuses = [status for status in DagsterRunStatus if status not in {
        DagsterRunStatus.SUCCESS, DagsterRunStatus.FAILURE, DagsterRunStatus.CANCELED}]
    with database_deadline():
        return bool(instance.get_runs(filters=RunsFilter(statuses=statuses), limit=1))


def _terminate_owned(pid: int, token: str, signum: int) -> None:
    descriptor = os.pidfd_open(pid)
    try:
        if process_token(pid) != token:
            raise RuntimeError("native process generation changed before signaling")
        signal.pidfd_send_signal(descriptor, signum)
    finally:
        os.close(descriptor)


class NativeSupervisor:
    """Only operates processes this exact native instance durably recorded."""

    def __init__(self, config_path: Path, readiness: NativeReadiness, *,
                 spawn=subprocess.Popen, identity=process_token, clock=time.monotonic,
                 sleep=time.sleep, terminate=_terminate_owned, ownership=scheduler_ownership):
        self.config_path = config_path
        self.config = load_native_dagster_config(config_path)
        self.home = Path(self.config.dagster_home)
        self.readiness, self.spawn, self.identity = readiness, spawn, identity
        self.clock, self.sleep, self.terminate = clock, sleep, terminate
        self.path = self.home / "native-processes.json"
        self.handles = {}
        self.ownership = ownership
        self.database_guard = None
        self.database = None

    def _layout(self):
        if os.geteuid() != self.config.client_uid:
            raise PermissionError("native application lifecycle requires its configured non-root UID")
        private_path(self.home, uid=self.config.client_uid)
        marker = self.home / "native-instance.json"
        private_path(marker, uid=self.config.client_uid, directory=False)
        if marker.stat().st_size > 65536:
            raise ValueError("native instance identity exceeds its bound")
        expected = {"schema": "appsec-review/native-instance/1", "configuration": asdict(self.config)}
        if json.loads(marker.read_bytes()) != expected:
            raise ValueError("native instance was prepared for a different configuration")
        for name, expected in (("dagster.yaml", self.config.instance_config()),
                               ("workspace.yaml", self.config.workspace_config())):
            path = self.home / name
            private_path(path, uid=self.config.client_uid, directory=False)
            if path.stat().st_size > 65536 or json.loads(path.read_bytes()) != expected:
                raise ValueError("native instance storage or workspace configuration drift")

    def _state(self):
        if not self.path.exists():
            return None
        private_path(self.path, uid=self.config.client_uid, directory=False)
        if self.path.stat().st_size > 65536:
            raise ValueError("native process journal exceeds its bound")
        state = json.loads(self.path.read_bytes())
        if (state.get("schema") != "appsec-review/native-processes/1"
                or state.get("configuration") != asdict(self.config)):
            raise ValueError("native process ownership/configuration changed")
        return state

    def _save(self, state):
        atomic_json(self.path, state)
        _sync_directory(self.home)

    def start(self, *, timeout_seconds: int = 60) -> dict:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("native startup deadline must be finite")
        self._layout()
        environment = child_environment(self.config_path, os.environ)
        with bounded_file_lock(self.home / "native-processes.lock", 5):
            previous = self._state()
            if previous is not None and previous["state"] != "STOPPED":
                raise RuntimeError("native process ownership is retained; reconcile before another start")
            self.readiness.before_start()
            self.database_guard = self.ownership(self.config)
            self.database = self.database_guard.__enter__()
            controller_token = self.identity(os.getpid())
            if controller_token is None:
                raise RuntimeError("native controller process generation is unavailable")
            state = {"schema": "appsec-review/native-processes/1", "configuration": asdict(self.config),
                     "state": "STARTING", "processes": {}, "pending": None,
                     "controller": {"pid": os.getpid(), "start_token": controller_token},
                     "health_at": self.clock()}
            self._save(state)
            try:
                for role, command in self.config.commands().items():
                    state["pending"] = role
                    self._save(state)
                    process = self.spawn(
                        command, cwd=self.config.repository_root, env=environment,
                        stdin=subprocess.DEVNULL, stdout=None, stderr=None,
                        close_fds=True)
                    token = self.identity(process.pid)
                    if token is None:
                        raise RuntimeError("native child generation cannot be established")
                    self.handles[role] = process
                    state["processes"][role] = {"pid": process.pid, "start_token": token}
                    state["pending"] = None
                    self._save(state)
                deadline = self.clock() + timeout_seconds
                while True:
                    if any(process.poll() is not None for process in self.handles.values()):
                        raise RuntimeError("native service exited before readiness")
                    if self.readiness.connected():
                        break
                    if self.clock() >= deadline:
                        raise TimeoutError("native service readiness deadline exceeded")
                    self.sleep(0.1)
                state["state"] = "RUNNING"
                self._save(state)
                return state
            except BaseException:
                state["state"] = "UNKNOWN"
                self._save(state)
                raise

    def heartbeat(self) -> dict:
        with bounded_file_lock(self.home / "native-processes.lock", 5):
            state = self._state()
            if state is None or state["state"] != "RUNNING":
                raise RuntimeError("native supervisor is not running")
            try:
                if self.database is None:
                    raise RuntimeError("native scheduler database ownership is unavailable")
                with database_deadline(), self.database.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    if cursor.fetchone() != (1,):
                        raise RuntimeError("native scheduler database ownership is unresponsive")
                if any(self.identity(owner["pid"]) != owner["start_token"]
                       for owner in state["processes"].values()):
                    raise RuntimeError("native service generation is no longer live")
                if not self.readiness.connected():
                    raise RuntimeError("native code-location or storage readiness was lost")
            except Exception:
                state["state"] = "UNKNOWN"
                self._save(state)
                scheduler = state["processes"].get("scheduler")
                if scheduler and self.identity(scheduler["pid"]) == scheduler["start_token"]:
                    self.terminate(scheduler["pid"], scheduler["start_token"], signal.SIGTERM)
                raise
            state["health_at"] = self.clock()
            self._save(state)
            return state

    def status(self) -> dict:
        self._layout()
        state = self._state()
        if state is None:
            return {"state": "NOT_STARTED"}
        observed = {}
        for role, owner in state["processes"].items():
            token = self.identity(owner["pid"])
            observed[role] = "RUNNING" if token == owner["start_token"] else (
                "ABSENT" if token is None else "REPLACED")
        return {**state, "observed": observed}

    def stop(self, *, timeout_seconds: int = 60) -> dict:
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("native shutdown deadline must be finite")
        self._layout()
        with bounded_file_lock(self.home / "native-processes.lock", 5):
            state = self._state()
            if state is None or state["state"] == "STOPPED":
                return {"state": "STOPPED"} if state is None else state
            self.readiness.before_stop()
            if state["pending"] is not None:
                raise RuntimeError("native pending spawn is unknown; independent reconciliation required")
            # Verify every identity before sending even one signal.
            for owner in state["processes"].values():
                if self.identity(owner["pid"]) not in {None, owner["start_token"]}:
                    raise RuntimeError("native PID was replaced; refusing to signal unrelated work")
            state["state"] = "STOPPING"
            self._save(state)
            deadline = self.clock() + timeout_seconds
            for role in ("scheduler", "webserver", "code-location"):
                if role != "scheduler":
                    self.readiness.before_stop()
                owner = state["processes"].get(role)
                if owner is None:
                    continue
                if self.identity(owner["pid"]) == owner["start_token"]:
                    self.terminate(owner["pid"], owner["start_token"], signal.SIGTERM)
                while self.identity(owner["pid"]) is not None:
                    if self.identity(owner["pid"]) != owner["start_token"]:
                        raise RuntimeError("native PID changed during shutdown")
                    process = self.handles.get(role)
                    if process is not None:
                        process.poll()
                    if self.clock() >= deadline:
                        state["state"] = "UNKNOWN"
                        self._save(state)
                        raise TimeoutError("native shutdown is incomplete; ownership remains reserved")
                    self.sleep(0.1)
            if not self.readiness.shutdown_complete():
                state["state"] = "UNKNOWN"
                self._save(state)
                raise RuntimeError("native descendants or resources remain; shutdown is unconfirmed")
            state["state"] = "STOPPED"
            self._save(state)
            if self.database_guard is not None:
                self.database_guard.__exit__(None, None, None)
                self.database_guard = None
                self.database = None
            return state
