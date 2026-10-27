"""Opt-in, run-owned admission; a lost controller never grants another permit."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time
from typing import Any, Iterator, Mapping
from uuid import UUID, uuid4

from appsec_review.storage import atomic_json


SCHEMA = "appsec-review/execution-safety/1"
MODE = "first-error-no-retry"
_LIMIT = 1024 * 1024
_ACTIVE: ContextVar[SafetyClient | None] = ContextVar("execution_safety", default=None)
_CLEANUP: ContextVar[bool] = ContextVar("execution_safety_cleanup", default=False)
_PERMIT: ContextVar[str | None] = ContextVar("execution_safety_permit", default=None)


class ReviewStopped(BaseException):
    """Cancellation control flow, not a producer exception that may become a gap."""


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def identity(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def policy(run_id: str, submission: Mapping[str, Any]) -> dict[str, Any]:
    if str(UUID(run_id)) != run_id:
        raise ValueError("safety policy requires a canonical Dagster UUID")
    for key in ("source_commit", "target_commit"):
        value = submission.get(key)
        if (not isinstance(value, str) or len(value) not in {40, 64}
                or any(char not in "0123456789abcdef" for char in value)):
            raise ValueError(f"safety policy requires {key}")
    if not isinstance(submission.get("configuration"), dict):
        raise ValueError("safety policy requires frozen configuration identities")
    return {"schema": SCHEMA, "mode": MODE, "dagster_run_id": run_id,
            "submission": json.loads(json.dumps(submission))}


def validate(value: Mapping[str, Any]) -> dict[str, Any]:
    expected = policy(str(value.get("dagster_run_id", "")), value.get("submission", {}))
    if dict(value) != expected:
        raise ValueError("invalid execution safety envelope")
    return expected


def _address(value: Mapping[str, Any]) -> str:
    # Abstract sockets avoid the 108-byte pathname limit for deeply nested run roots.
    # SO_PEERCRED below restricts access to the application uid in this network namespace.
    return "\0appsec-stop-" + str(value["dagster_run_id"])


def _receive(connection: socket.socket) -> dict[str, Any]:
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = connection.recv(min(65536, _LIMIT + 1 - len(data)))
        if not chunk:
            raise ValueError("incomplete admission message")
        data.extend(chunk)
        if len(data) > _LIMIT:
            raise ValueError("admission message exceeds its bound")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("admission message must be an object")
    return value


def _send(connection: socket.socket, value: Mapping[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True).encode() + b"\n"
    if len(data) > _LIMIT:
        raise ValueError("admission message exceeds its bound")
    connection.sendall(data)


class SafetyClient:
    def __init__(self, envelope: Mapping[str, Any]):
        self.policy = validate(envelope)
        self.digest = identity(self.policy)

    def request(self, command: str, **fields: Any) -> dict[str, Any]:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(_address(self.policy))
                _send(connection, {"policy_sha256": self.digest, "command": command, **fields})
                response = _receive(connection)
            if response.get("ok") is not True:
                raise ReviewStopped(str(response.get("reason", "admission refused")))
            return response
        except (OSError, ValueError) as exc:
            raise ReviewStopped(f"admission controller unavailable: {type(exc).__name__}") from exc


class AdmissionGuardian:
    """The existing Dagster run worker owns this serialized, non-restarting controller."""

    def __init__(self, envelope: Mapping[str, Any], metadata_root: Path,
                 *, resolved_config_sha256: str):
        self.policy = validate(envelope)
        self.client = SafetyClient(self.policy)
        self.root = metadata_root / "dagster-safety"
        self.path = self.root / f"{self.policy['dagster_run_id']}.json"
        self.events = self.path.with_suffix(".jsonl")
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.closed = threading.Event()
        self.state: dict[str, Any] = {
            "schema": SCHEMA, "policy": self.policy, "policy_sha256": self.client.digest,
            "resolved_config_sha256": resolved_config_sha256, "status": "RUNNING",
            "owner_pid": os.getpid(), "started_at": _stamp(), "sequence": 0,
            "application_run_id": None, "first_error": None, "active": {},
            "cancellation": "NOT_REQUESTED",
        }
        self.socket: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.on_stop = None

    def _persist(self, event: Mapping[str, Any]) -> None:
        self.state["sequence"] += 1
        with self.events.open("ab") as stream:
            stream.write(json.dumps({"at": _stamp(), "sequence": self.state["sequence"],
                                     **event}, sort_keys=True).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        atomic_json(self.path, self.state)
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def fail(self, reason: str, *, action: str = "dagster", expected: bool = False) -> None:
        with self.lock:
            self.stopped.set()
            self.state["status"] = "STOPPED"
            cause = {"at": _stamp(), "action": action, "reason": reason[:4096],
                     "expected_policy_stop": expected}
            if self.state["first_error"] is None:
                self.state["first_error"] = cause
            self._persist({"event": "STOP", **cause})

    def cancellation(self, status: str) -> None:
        with self.lock:
            self.state["cancellation"] = status
            self._persist({"event": "CANCELLATION", "status": status})

    def _dispatch(self, message: Mapping[str, Any]) -> dict[str, Any]:
        with self.lock:
            if message.get("policy_sha256") != self.client.digest:
                raise ValueError("admission policy identity mismatch")
            command = message.get("command")
            if command == "failure":
                self.fail(str(message.get("reason", "operation failed")),
                          action=str(message.get("action", "unknown")),
                          expected=message.get("expected") is True)
                return {"ok": True}
            if command == "finish":
                permit = message.get("permit")
                if permit not in self.state["active"]:
                    raise ValueError("unknown or already consumed admission permit")
                entry = self.state["active"][permit]
                if message.get("succeeded") is True:
                    del self.state["active"][permit]
                else:
                    entry["status"] = "CLEANUP_UNCONFIRMED"
                self._persist({"event": "FINISH", "permit": permit, **entry,
                               "duration_ms": message.get("duration_ms"),
                               "succeeded": message.get("succeeded") is True})
                return {"ok": True}
            if command == "process":
                permit = message.get("permit")
                if permit not in self.state["active"]:
                    raise ValueError("process does not belong to an active permit")
                self.state["active"][permit].setdefault("processes", []).append(message["process"])
                self._persist({"event": "PROCESS", "permit": permit, "process": message["process"]})
                return {"ok": True}
            if self.stopped.is_set():
                return {"ok": False, "reason": "run admission is permanently stopped"}
            if command == "check":
                return {"ok": True}
            if command == "bind":
                run_id = message.get("application_run_id")
                if not isinstance(run_id, str) or not run_id:
                    raise ValueError("application run identity is missing")
                if self.state["application_run_id"] not in (None, run_id):
                    raise ValueError("application run identity changed")
                self.state["application_run_id"] = run_id
                self._persist({"event": "BIND", "application_run_id": run_id})
                return {"ok": True}
            if command == "admit":
                permit = uuid4().hex
                entry = {"action": str(message.get("action", ""))[:512],
                         "pid": message.get("pid"), "process_identity": message.get("process_identity"),
                         "started_at": _stamp(), "status": "ADMITTED"}
                self.state["active"][permit] = entry
                self._persist({"event": "ADMIT", "permit": permit, **entry})
                return {"ok": True, "permit": permit}
            raise ValueError("unknown admission operation")

    def _serve(self) -> None:
        assert self.socket is not None
        while not self.closed.is_set():
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.closed.is_set():
                    return
                self.stopped.set()
                raise
            with connection:
                connection.settimeout(5)
                try:
                    credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                    _pid, uid, _gid = struct.unpack("3i", credentials)
                    if uid != os.getuid():
                        raise ValueError("admission peer uid differs")
                    response = self._dispatch(_receive(connection))
                    _send(connection, response)
                except (OSError, ValueError, TypeError, KeyError) as exc:
                    # Including a lost grant response: never continue from uncertain admission.
                    self.stopped.set()
                    self.state["status"] = "STOPPED"
                    try:
                        self.fail(f"controller failure: {type(exc).__name__}")
                    except OSError:
                        # The in-memory gate remains closed even if storage cannot record STOP.
                        self.state["journal_failure"] = type(exc).__name__
                    try:
                        _send(connection, {"ok": False, "reason": "controller failed closed"})
                    except OSError:
                        pass
            if self.stopped.is_set() and self.on_stop is not None:
                self.on_stop()

    def __enter__(self) -> AdmissionGuardian:
        if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
            raise ValueError("execution safety requires Linux peer-authenticated Unix sockets")
        self.root.mkdir(parents=True, exist_ok=True)
        # A previous journal, including an uncertain startup, cannot be adopted automatically.
        with self.path.open("x") as stream:
            stream.write(json.dumps(self.state))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            self._persist({"event": "START"})
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.settimeout(0.1)
            self.socket.bind(_address(self.policy))
            self.socket.listen(128)
            self.thread = threading.Thread(target=self._serve, name="run-admission", daemon=True)
            self.thread.start()
        except BaseException:
            if self.socket is not None:
                self.socket.close()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.closed.set()
        if self.thread is not None:
            self.thread.join(timeout=6)
            if self.thread.is_alive():
                self.stopped.set()
                raise RuntimeError("run admission controller did not stop")
        if self.socket is not None:
            self.socket.close()
        with self.lock:
            self.state["status"] = ("STOPPED" if self.stopped.is_set() or exc is not None
                                    else "COMPLETED")
            self.state["completed_at"] = _stamp()
            self._persist({"event": "CONTROLLER_CLOSED"})


def active() -> bool:
    return _ACTIVE.get() is not None


def current_policy() -> dict[str, Any] | None:
    current = _ACTIVE.get()
    return current.policy if current is not None else None


@contextmanager
def safety_scope(envelope: Mapping[str, Any] | None) -> Iterator[None]:
    client = SafetyClient(envelope) if envelope is not None else None
    current = _ACTIVE.get()
    if current is not None and (client is None or client.digest != current.digest):
        raise ReviewStopped("nested scope changed execution safety identity")
    token = _ACTIVE.set(client)
    try:
        check_running()
        yield
    finally:
        _ACTIVE.reset(token)


def check_running() -> None:
    current = _ACTIVE.get()
    if current is not None and not _CLEANUP.get():
        current.request("check")


def bind_run(run_id: str) -> None:
    current = _ACTIVE.get()
    if current is not None:
        current.request("bind", application_run_id=run_id)


def latch(reason: str, *, action: str = "operation", expected: bool = False) -> None:
    current = _ACTIVE.get()
    if current is not None:
        current.request("failure", reason=reason, action=action, expected=expected)


def fail(reason: str, *, action: str = "operation", expected: bool = False) -> None:
    if active():
        latch(reason, action=action, expected=expected)
        raise ReviewStopped(reason)


def failed_result(failed: bool, reason: str, *, action: str = "operation") -> None:
    if failed:
        fail(reason, action=action)


def retain_failure(action: str, exc: BaseException, **details: Any) -> None:
    if not active():
        return
    from appsec_review.storage.shared import current
    owner = current()
    if owner is not None:
        raw = getattr(exc, "raw_response", None)
        atomic_json(owner.run_root / "data/execution-failures" / f"{uuid4().hex}.json", {
            "schema": SCHEMA, "at": _stamp(), "action": action,
            "error_type": type(exc).__name__, "message": str(exc)[:4096],
            "raw_response": raw[:2 * 1024 * 1024] if isinstance(raw, str) else None,
            **details})


@contextmanager
def operation(action: str) -> Iterator[None]:
    current = _ACTIVE.get()
    if current is None or _CLEANUP.get():
        yield
        return
    from appsec_review.runtime.resources import process_identity
    granted = current.request("admit", action=action, pid=os.getpid(),
                              process_identity=process_identity(os.getpid()))
    token = _PERMIT.set(granted["permit"])
    succeeded = False
    started = time.monotonic()
    try:
        yield
        check_running()
        succeeded = True
    except ReviewStopped:
        raise
    except BaseException as exc:
        fail(f"{type(exc).__name__}: {exc}", action=action)
        raise
    finally:
        _PERMIT.reset(token)
        current.request("finish", permit=granted["permit"], succeeded=succeeded,
                        duration_ms=max(0, int((time.monotonic() - started) * 1000)))


def guarded(action: str):
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            with operation(action):
                return function(*args, **kwargs)
        return call
    return decorate


@contextmanager
def cleanup_scope() -> Iterator[None]:
    """Internal exact-resource cleanup only; never wrap new analysis in this scope."""
    token = _CLEANUP.set(True)
    try:
        yield
    finally:
        _CLEANUP.reset(token)


def run_process(argv, timeout: int, *, stdout=None, stderr=None):
    """Bound a local CLI process group; callers retain streams before classifying its exit."""
    from appsec_review.config.native_dagster import native_execution_requested
    from appsec_review.runtime.resources import process_identity, quarantine_resources
    if native_execution_requested():
        fail("native broker cancellation is not commissioned for this safety policy",
             action="native_execution")
    check_running()
    process = subprocess.Popen(
        list(argv), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if stdout is None else stdout,
        stderr=subprocess.PIPE if stderr is None else stderr, start_new_session=True)
    generation = process_identity(process.pid)
    deadline = time.monotonic() + timeout
    stopped = False
    out = err = b""
    try:
        current = _ACTIVE.get()
        if current is not None and not _CLEANUP.get():
            current.request("process", permit=_PERMIT.get(), process={
                "pid": process.pid, "process_identity": generation, "process_group": process.pid})
        while True:
            try:
                check_running()
            except ReviewStopped:
                stopped = True
            remaining = deadline - time.monotonic()
            if stopped or remaining <= 0:
                break
            try:
                out, err = process.communicate(timeout=min(0.1, remaining))
                return process.returncode, out or b"", err or b"", False
            except subprocess.TimeoutExpired:
                continue
        if process_identity(process.pid) != generation or generation is None:
            quarantine_resources("local_process_generation_unconfirmed")
            raise ReviewStopped("local process generation cannot be confirmed for cancellation")
        os.killpg(process.pid, signal.SIGKILL)
        try:
            out, err = process.communicate(timeout=5)
        except subprocess.TimeoutExpired as exc:
            quarantine_resources("local_descendant_death_unconfirmed")
            out, err = exc.stdout or b"", exc.stderr or b""
            raise ReviewStopped("local descendants remain unconfirmed after cancellation") from exc
        return None, out or b"", err or b"", True
    finally:
        if process.poll() is None:
            if generation is not None and process_identity(process.pid) == generation:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    quarantine_resources("local_process_death_unconfirmed")
                    raise ReviewStopped("local process death remains unconfirmed")
            else:
                quarantine_resources("local_process_generation_unconfirmed")
                raise ReviewStopped("local process identity changed during cleanup")
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
