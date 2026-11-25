from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import threading
import time
from typing import Any
import urllib.parse
import uuid

from appsec_review.container_runtime.catalog import ContainerCatalog, ToolImage
from appsec_review.container_runtime.identity import application_runtime_user, grant_runtime_user
from appsec_review.container_runtime.measurement import (
    InvocationMeasurement, SUPERVISOR_PATH, TreeSitterInvocation,
)
from appsec_review.config.native_dagster import native_execution_requested
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.runtime.resources import reserve_execution, review_resources_active, tracked_container
from appsec_review.runtime import execution_safety as safety
from appsec_review.runtime._process_capture import PipeCapture
from appsec_review.signing.core import SignatureVerificationError
from appsec_review.signing.images import ImageSignatureVerifier
from appsec_review.signing.policy import default_image_verifier


@dataclass(frozen=True, slots=True)
class Mount:
    source: Path
    target: str
    read_only: bool = True
    supplied_platform: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    tool_id: str
    argv: tuple[str, ...]
    target_root: Path
    scratch_root: Path
    extra_mounts: tuple[Mount, ...] = ()
    environment: Mapping[str, str] | None = None
    working_directory: str = "/target"
    # Execution-level RLIMIT_FSIZE (bytes) for every file the scanner writes. The kernel refuses
    # writes past it (SIGXFSZ, or EFBIG where the signal is ignored), so a producer cannot grow a
    # run-owned artifact beyond its configured bound before the application inspects it.
    file_size_limit_bytes: int | None = None
    # Container memory limit for this one execution instead of the catalog tool's policy value,
    # for a tool whose data set (osv-scanner's offline databases) needs more than the uniform
    # scanner limit. Isolation settings are never overridable.
    memory: str | None = None
    accepted_exit_codes: frozenset[int] = frozenset({0})
    expected_nonzero: Callable[[int | None, bytes, bytes], bool] | None = None
    measurement: TreeSitterInvocation | None = None


@dataclass(frozen=True, slots=True)
class CommandOutcome:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    oom_killed: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    schema: str
    tool_id: str
    image_tag: str
    image_id: str
    image_digest: str
    argv_identity: str
    mounts: tuple[Mapping[str, Any], ...]
    limits: Mapping[str, Any]
    started_at: str
    completed_at: str
    exit_code: int | None
    timed_out: bool
    oom_killed: bool
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_path: str
    stderr_path: str
    receipt_path: str
    file_size_limit_bytes: int | None = None
    file_size_limit_reached: bool = False
    environment_sha256: Mapping[str, str] = field(default_factory=dict)
    # The effective argv as executed, so a receipt shows a configured scanner profile (T-5018) and not
    # only its hash.
    argv: tuple[str, ...] = ()

    @property
    def terminal_status(self) -> str:
        if self.timed_out:
            return "TIMEOUT"
        if self.oom_killed:
            return "OOM"
        if self.file_size_limit_reached:
            return "FILE_SIZE_LIMIT"
        return "COMPLETED"


Runner = Callable[[Sequence[str], int], CommandOutcome]
# ``docker run`` reports a process killed by a signal as 128 + signal number.
FILE_SIZE_SIGNAL_EXIT = 128 + int(getattr(signal, "SIGXFSZ", 25))
_MEMORY_LIMIT = re.compile(r"[1-9][0-9]{0,5}[mg]")


class ImageUnavailableError(RuntimeError):
    """The requested immutable image is absent, not a failed scanner invocation."""


_DEFAULT_CGROUP_ROOT = Path("/sys/fs/cgroup")
_DEFAULT_DOCKER_SOCKET = Path("/var/run/docker.sock")


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _docker_run_name(argv: Sequence[str]) -> str | None:
    if len(argv) < 4 or argv[0] != "docker" or argv[1] != "run":
        return None
    for index in range(2, len(argv)):
        token = argv[index]
        if token in {"--", "--entrypoint"}:
            break
        if token == "--name" and index + 1 < len(argv):
            return argv[index + 1] or None
        if token.startswith("--name="):
            return token.split("=", 1)[1] or None
    return None


def _memory_events_oom_kills(path: Path) -> int | None:
    if path.is_symlink() or not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "oom_kill":
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


def _cgroup_oom_killed(name: str, *, container_id: str | None = None,
                       cgroup_root: Path = _DEFAULT_CGROUP_ROOT) -> bool:
    identifiers = tuple(dict.fromkeys(item for item in (container_id, name) if item))
    if not identifiers or cgroup_root.is_symlink() or not cgroup_root.is_dir():
        return False
    candidates: list[Path] = []
    for ident in identifiers:
        candidates.extend((
            cgroup_root / "system.slice" / f"docker-{ident}.scope" / "memory.events",
            cgroup_root / "docker" / ident / "memory.events",
            cgroup_root / f"docker-{ident}.scope" / "memory.events",
            cgroup_root / ident / "memory.events",
        ))
    try:
        children = tuple(cgroup_root.iterdir())
    except OSError:
        children = ()
    for child in children:
        if child.is_symlink() or not child.is_dir():
            continue
        for ident in identifiers:
            candidates.extend((
                child / f"docker-{ident}.scope" / "memory.events",
                child / ident / "memory.events",
            ))
    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        oom_kills = _memory_events_oom_kills(candidate)
        if oom_kills is not None and oom_kills > 0:
            return True
    return False


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, *, timeout: float = 1.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = str(socket_path)

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def _docker_socket_get(docker_socket: Path, path: str, *, timeout: float = 1.0,
                       max_bytes: int = 65536) -> tuple[int, str] | None:
    if not hasattr(socket, "AF_UNIX"):
        return None
    try:
        if not docker_socket.is_socket():
            return None
    except OSError:
        return None
    connection = _UnixHTTPConnection(docker_socket, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Host": "localhost", "Connection": "close"})
        response = connection.getresponse()
        body = response.read(max_bytes).decode("utf-8", "replace")
        return response.status, body
    except (OSError, ValueError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def _inspect_docker_container(docker_socket: Path, ref: str) -> tuple[str | None, bool]:
    if not ref:
        return None, False
    quoted = urllib.parse.quote(ref, safe="")
    fetched = _docker_socket_get(docker_socket, f"/containers/{quoted}/json", timeout=0.5)
    if fetched is None or fetched[0] != 200:
        return None, False
    try:
        payload = json.loads(fetched[1])
    except json.JSONDecodeError:
        return None, False
    if not isinstance(payload, Mapping):
        return None, False
    raw_id = payload.get("Id")
    container_id = raw_id if isinstance(raw_id, str) and raw_id else None
    state = payload.get("State")
    state_oom = bool(state.get("OOMKilled")) if isinstance(state, Mapping) else False
    return container_id, state_oom


def _docker_oom_event_recorded(docker_socket: Path, refs: Sequence[str], *,
                               since: float, until: float) -> bool:
    unique_refs = tuple(dict.fromkeys(item for item in refs if item))
    if not unique_refs:
        return False
    effective_until = min(until, time.time())
    effective_since = min(since, effective_until)
    filters = json.dumps({"type": ["container"], "event": ["oom"]}, separators=(",", ":"))
    query = urllib.parse.urlencode({
        "since": f"{effective_since:.6f}",
        "until": f"{effective_until:.6f}",
        "filters": filters,
    })
    fetched = _docker_socket_get(docker_socket, f"/events?{query}", timeout=1.0)
    if fetched is None or fetched[0] != 200:
        return False
    for line in fetched[1].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, Mapping):
            continue
        if event.get("Action") != "oom" and event.get("status") != "oom":
            continue
        actor = event.get("Actor") if isinstance(event.get("Actor"), Mapping) else {}
        attrs = actor.get("Attributes") if isinstance(actor.get("Attributes"), Mapping) else {}
        actor_id = str(actor.get("ID") or event.get("id") or "")
        actor_name = str(attrs.get("name") or "")
        if any(
            ref == actor_name or ref == actor_id or (len(ref) >= 12 and actor_id.startswith(ref))
            for ref in unique_refs
        ):
            return True
    return False


class _ContainerOomMonitor:
    def __init__(self, name: str, *, cgroup_root: Path = _DEFAULT_CGROUP_ROOT,
                 docker_socket: Path = _DEFAULT_DOCKER_SOCKET, poll_interval: float = 0.05) -> None:
        self.name = name
        self.cgroup_root = cgroup_root
        self.docker_socket = docker_socket
        self.poll_interval = poll_interval
        self._started_at = max(0.0, time.time() - 1.0)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._container_id: str | None = None
        self._oom_detected = False

    def _sample_once(self) -> bool:
        if self._oom_detected:
            return True
        if self._container_id is None:
            container_id, state_oom = _inspect_docker_container(self.docker_socket, self.name)
            if container_id is not None:
                self._container_id = container_id
            if state_oom:
                self._oom_detected = True
                return True
        if _cgroup_oom_killed(self.name, container_id=self._container_id, cgroup_root=self.cgroup_root):
            self._oom_detected = True
            return True
        return False

    def _loop(self) -> None:
        while not self._stop.is_set():
            if self._sample_once():
                return
            self._stop.wait(self.poll_interval)

    def start(self) -> None:
        self._started_at = max(0.0, time.time() - 1.0)
        self._thread = threading.Thread(target=self._loop, name=f"oom-watch-{self.name}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def finish(self) -> bool:
        self.stop()
        if self._oom_detected or self._sample_once():
            return True
        if self._container_id is not None:
            _, state_oom = _inspect_docker_container(self.docker_socket, self._container_id)
            if state_oom:
                self._oom_detected = True
                return True
        refs = [self.name, *([self._container_id] if self._container_id is not None else [])]
        if _docker_oom_event_recorded(self.docker_socket, refs, since=self._started_at, until=time.time()):
            self._oom_detected = True
            return True
        return False


def _default_runner(argv: Sequence[str], timeout: int, *, output_bytes: int | None = None,
                    cgroup_root: Path = _DEFAULT_CGROUP_ROOT,
                    docker_socket: Path = _DEFAULT_DOCKER_SOCKET) -> CommandOutcome:
    container_name = _docker_run_name(argv)
    monitor = (_ContainerOomMonitor(container_name, cgroup_root=cgroup_root, docker_socket=docker_socket)
               if container_name is not None else None)
    if monitor is not None:
        monitor.start()
    try:
        if safety.active():
            code, stdout, stderr, timed_out = safety.run_process(argv, timeout, output_bytes=output_bytes)
            oom_killed = code == 137 or (monitor.finish() if monitor is not None else False)
            return CommandOutcome(code, stdout, stderr, timed_out, oom_killed=oom_killed)
        from .native_client import native_run
        native = native_run(argv, timeout)
        if native is not None:
            oom_killed = native[0] == 137 or (monitor.finish() if monitor is not None else False)
            return CommandOutcome(native[0], native[1], native[2], native[3],
                                  oom_killed=oom_killed)
        process = subprocess.Popen(
            list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        capture = None
        try:
            capture = PipeCapture(process, output_bytes)
            try:
                capture.wait(timeout)
            except subprocess.TimeoutExpired as timeout_error:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    capture.wait(5)
                except subprocess.TimeoutExpired as drain_error:
                    timeout_error.output, timeout_error.stderr = drain_error.output, drain_error.stderr
                    raise timeout_error from drain_error
                oom_killed = monitor.finish() if monitor is not None else False
                return CommandOutcome(None, *capture.output(), timed_out=True, oom_killed=oom_killed)
            oom_killed = process.returncode == 137 or (monitor.finish() if monitor is not None else False)
            return CommandOutcome(process.returncode, *capture.output(),
                                  oom_killed=oom_killed)
        finally:
            if capture is not None:
                capture.close()
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
    finally:
        if monitor is not None:
            monitor.stop()


class ContainerExecutor:
    """Execute only enabled catalog images under the repository runtime policy."""

    def __init__(self, catalog: ContainerCatalog, run_root: Path, *, runner: Runner | None = None,
                 image_verifier: ImageSignatureVerifier | None = None,
                 cgroup_root: Path = _DEFAULT_CGROUP_ROOT,
                 docker_socket: Path = _DEFAULT_DOCKER_SOCKET):
        self.catalog = catalog
        self.run_root = run_root.resolve()
        self.runner = runner or _default_runner
        # None defers to the process-wide default, resolved at first use rather than construction.
        self._image_verifier = image_verifier
        self.cgroup_root = cgroup_root
        self.docker_socket = docker_socket

    def _run_control(self, argv: Sequence[str]) -> CommandOutcome:
        return self.runner(argv, 60)

    def resolve_image(self, tool: ToolImage) -> str:
        """Return the pinned image's immutable ID once its identity and signature are verified."""
        outcome = self._run_control(("docker", "image", "inspect", tool.tag, "--format", "{{.Id}}"))
        if outcome.exit_code != 0 or outcome.timed_out:
            raise ImageUnavailableError(f"cataloged image is not locally available: {tool.tool_id}")
        image_id = outcome.stdout.decode("utf-8", "replace").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError(f"Docker returned a non-immutable image id for {tool.tool_id}")
        if tool.expected_image_id is not None and image_id != tool.expected_image_id:
            raise ValueError(f"local image digest mismatch for {tool.tool_id}")
        verifier = self._image_verifier if self._image_verifier is not None else default_image_verifier()
        try:
            verifier.verify(image_id, reference=tool.tag)
        except SignatureVerificationError as error:
            raise SignatureVerificationError(
                f"refusing to launch {tool.tool_id} image {tool.tag} ({image_id}): {error}") from error
        return image_id

    def _validate(self, request: ExecutionRequest, tool: ToolImage) -> tuple[Path, tuple[Mount, ...]]:
        target = request.target_root.resolve(strict=True)
        scratch = request.scratch_root.resolve()
        if scratch != self.run_root and self.run_root not in scratch.parents:
            raise ValueError("scanner scratch must be run-owned")
        scratch.mkdir(parents=True, exist_ok=True)
        # The scanner runs as the application uid/gid (or is handed the scratch when the application is
        # root). Keep the writable boundary owner-only; target, rules, and database mounts are read-only.
        grant_runtime_user(scratch, application_runtime_user(tool.user))
        if not request.argv or request.argv[0] not in (tool.executable, *tool.additional_executables):
            raise ValueError(f"argv must begin with the cataloged executable for {tool.tool_id}")
        if any(not isinstance(arg, str) or "\0" in arg for arg in request.argv):
            raise ValueError("argv contains an unsafe value")
        if request.environment and any(not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) for key in request.environment):
            raise ValueError("environment key is invalid")
        limit = request.file_size_limit_bytes
        if limit is not None and (type(limit) is not int or limit < 1):
            raise ValueError("file size limit must be a positive byte count")
        if request.memory is not None and (not isinstance(request.memory, str)
                                           or not _MEMORY_LIMIT.fullmatch(request.memory)):
            raise ValueError("memory override must look like 512m or 3g")
        mounts = (Mount(target, "/target", True), Mount(scratch, "/scratch", False), *request.extra_mounts)
        seen: set[str] = set()
        for mount in mounts:
            source = mount.source.resolve(strict=True)
            if mount.target in seen or not mount.target.startswith("/") or ".." in Path(mount.target).parts:
                raise ValueError(f"unsafe or duplicate mount target: {mount.target}")
            if "docker.sock" in source.name.lower() or mount.target.endswith("docker.sock"):
                raise ValueError("the Docker socket may not be mounted into a scanner")
            if mount.target.startswith("/scratch/"):
                # Docker would create the mount point inside the run-owned scratch bind as root.
                raise ValueError(f"extra mounts may not nest inside /scratch: {mount.target}")
            if mount.target == "/target" and not mount.read_only:
                raise ValueError("target mount must be read-only")
            if not mount.read_only and mount.target != "/scratch":
                raise ValueError("only run-owned scratch may be writable")
            seen.add(mount.target)
        return target, mounts

    def _docker_bind_source(self, path: Path) -> Path:
        """Translate a path inside the Dagster code-location container to its host bind source."""
        if native_execution_requested():
            if Path("/.dockerenv").exists():
                raise ValueError("native execution cannot translate a container filesystem")
            return path
        hostname = os.environ.get("HOSTNAME")
        if not hostname or not Path("/.dockerenv").exists():
            return path
        inspected = self._run_control(("docker", "inspect", hostname, "--format", "{{json .Mounts}}"))
        if inspected.exit_code != 0:
            raise RuntimeError("could not resolve scanner bind mounts from the code-location container")
        mounts = json.loads(inspected.stdout.decode("utf-8", "replace"))
        candidates: list[tuple[int, Path]] = []
        for mount in mounts:
            destination = Path(str(mount.get("Destination", "")))
            try:
                relative = path.relative_to(destination)
            except ValueError:
                continue
            candidates.append((len(destination.parts), Path(str(mount["Source"])) / relative))
        if not candidates:
            raise RuntimeError(f"scanner bind source is not backed by a host mount: {path}")
        return max(candidates, key=lambda item: item[0])[1]

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        tool = self.catalog.tool(request.tool_id)
        with reserve_execution(cpu=tool.cpus, memory=request.memory or tool.memory,
                               action=f"scanner.{tool.tool_id}",
                               timeout_seconds=self.catalog.admission_timeout_seconds):
            return self._execute(request)

    def _container_control(self, argv: Sequence[str], timeout: int):
        outcome = self.runner(argv, timeout)
        return outcome.exit_code, outcome.stdout, outcome.stderr, outcome.timed_out

    def _execute(self, request: ExecutionRequest) -> ExecutionResult:
        tool = self.catalog.tool(request.tool_id)
        runtime_user = application_runtime_user(tool.user)
        _, mounts = self._validate(request, tool)
        measurement = None
        if request.measurement is not None:
            if request.tool_id != "tool-tree-sitter" or request.argv[:2] != ("/opt/appsec/parser.py", "parse"):
                raise ValueError("resource measurement is restricted to Tree-sitter parsing")
            if any(mount.target == SUPERVISOR_PATH for mount in mounts):
                raise ValueError("Tree-sitter supervisor mount conflicts with supplied mounts")
            measurement = InvocationMeasurement(self.run_root, request.scratch_root, request.measurement)
            mounts = (*mounts, Mount(measurement.supervisor, SUPERVISOR_PATH, True, supplied_platform=True))
        memory = request.memory or tool.memory
        image_id = self.resolve_image(tool)
        raw = request.scratch_root / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        stdout_path, stderr_path = raw / "stdout.bin", raw / "stderr.bin"
        receipt_path = request.scratch_root / "execution.json"
        name = "appsec-" + uuid.uuid4().hex[:20]
        command = [
            "docker", "run", "--rm", "--name", name,
            "--network", "none", "--read-only", "--user", runtime_user,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cpus", tool.cpus, "--memory", memory,
            "--pids-limit", str(tool.pids_limit),
            "--tmpfs", str(self.catalog.policy["tmpfs"][0]),
            "--workdir", request.working_directory,
        ]
        if request.file_size_limit_bytes is not None:
            command.extend(("--ulimit", f"fsize={request.file_size_limit_bytes}:{request.file_size_limit_bytes}"))
        effective_sources: dict[str, Path] = {}
        for mount in mounts:
            effective = self._docker_bind_source(mount.source.resolve())
            effective_sources[mount.target] = effective
            spec = f"type=bind,src={effective},dst={mount.target}"
            if mount.read_only:
                spec += ",readonly"
            command.extend(("--mount", spec))
        for key, value in sorted((request.environment or {}).items()):
            command.extend(("--env", f"{key}={value}"))
        if measurement is not None:
            command.extend(("--entrypoint", "/usr/local/bin/python", image_id, SUPERVISOR_PATH,
                            "--output", f"/scratch/{measurement.output.name}", "--", *request.argv))
        else:
            command.extend(("--entrypoint", request.argv[0], image_id, *request.argv[1:]))
        limits = {
            "network": "none", "user": runtime_user, "root_filesystem": "read-only",
            "cap_drop": ["ALL"], "no_new_privileges": True, "cpus": tool.cpus,
            "memory": memory, "memory_source": "request" if request.memory else "catalog",
            "pids": tool.pids_limit,
            "tmpfs": list(self.catalog.policy["tmpfs"]),
            "timeout_seconds": tool.timeout_seconds,
            "admission_timeout_seconds": self.catalog.admission_timeout_seconds,
            "stdout_bytes": tool.output_bytes,
            "stderr_bytes": tool.output_bytes, "file_size_bytes": request.file_size_limit_bytes,
        }
        started = _stamp()
        if measurement is not None:
            measurement.start(started, image_id=image_id, container_name=name, limits=limits)

        def terminate_measured() -> Mapping[str, Any]:
            with safety.cleanup_scope():
                stopped = self.runner(("docker", "stop", "--time", "2", name), 5)
            return {"requested": True, "exit_code": stopped.exit_code, "timed_out": stopped.timed_out,
                    "snapshot_may_be_incomplete": stopped.exit_code != 0 or stopped.timed_out}

        try:
            lifecycle = (tracked_container(name, self._container_control, label="Scanner")
                         if review_resources_active() or safety.active() or measurement is not None else nullcontext())
            with lifecycle:
                started_epoch = max(0.0, time.time() - 1.0)
                try:
                    outcome = (_default_runner(command, tool.timeout_seconds, output_bytes=tool.output_bytes,
                                               cgroup_root=self.cgroup_root, docker_socket=self.docker_socket)
                               if self.runner is _default_runner else self.runner(command, tool.timeout_seconds))
                except BaseException as exc:
                    timeout_error = (exc if isinstance(exc, subprocess.TimeoutExpired)
                                     else exc.__cause__ if isinstance(exc, safety.ReviewStopped)
                                     and isinstance(exc.__cause__, subprocess.TimeoutExpired) else None)
                    partial = {
                        "schema": "appsec-review/container-execution-partial/1",
                        "tool_id": tool.tool_id, "image_id": image_id, "container_name": name,
                        "started_at": started, "completed_at": _stamp(), "error_type": type(exc).__name__,
                        "exit_code": None, "cleanup": "PENDING",
                    }
                    failed_outcome = None
                    if timeout_error is not None:
                        stdout, stderr = timeout_error.output or b"", timeout_error.stderr or b""
                        stdout_path.write_bytes(stdout[:tool.output_bytes])
                        stderr_path.write_bytes(stderr[:tool.output_bytes])
                        partial.update(
                            cleanup="UNCONFIRMED", capture_complete=False,
                            stdout_path=stdout_path.relative_to(self.run_root).as_posix(),
                            stderr_path=stderr_path.relative_to(self.run_root).as_posix(),
                            stdout_sha256=file_sha256(stdout_path), stderr_sha256=file_sha256(stderr_path),
                            stdout_truncated=len(stdout) > tool.output_bytes,
                            stderr_truncated=len(stderr) > tool.output_bytes)
                        if exc is timeout_error:
                            partial.update(timed_out=True, timeout_seconds=timeout_error.timeout)
                            failed_outcome = CommandOutcome(None, stdout, stderr, timed_out=True)
                        else:
                            # A safety stop can be external cancellation, not the execution deadline.
                            partial.update(timed_out=None, capture_timeout_seconds=timeout_error.timeout)
                        atomic_json(receipt_path, partial)
                    if measurement is not None:
                        termination = terminate_measured()
                        reference = measurement.finish(failed_outcome, error=exc, cleanup=termination)
                        atomic_json(receipt_path, {**partial, "metrics_receipt": reference})
                    raise
                if not outcome.oom_killed:
                    container_id, state_oom = (
                        _inspect_docker_container(self.docker_socket, name)
                        if self.docker_socket != _DEFAULT_DOCKER_SOCKET else (None, False)
                    )
                    socket_oom = (
                        state_oom or _docker_oom_event_recorded(
                            self.docker_socket,
                            [name, *([container_id] if container_id is not None else [])],
                            since=started_epoch,
                            until=time.time(),
                        )
                        if self.docker_socket != _DEFAULT_DOCKER_SOCKET else False
                    )
                    measured_oom = None
                    if (measurement is not None and not measurement.output.is_symlink()
                            and measurement.output.is_file()):
                        try:
                            measured_oom = json.loads(
                                measurement.output.read_text(encoding="utf-8")
                            ).get("oom_kill_events")
                        except (OSError, json.JSONDecodeError, AttributeError):
                            measured_oom = None
                    if (socket_oom
                            or (type(measured_oom) is int and measured_oom > 0)
                            or _cgroup_oom_killed(name, container_id=container_id,
                                                  cgroup_root=self.cgroup_root)):
                        outcome = replace(outcome, oom_killed=True)
                if measurement is not None:
                    termination = terminate_measured() if outcome.timed_out else None
                    measurement.finish(outcome, cleanup=termination)
                if safety.active():
                    stdout_path.write_bytes(outcome.stdout[:tool.output_bytes])
                    stderr_path.write_bytes(outcome.stderr[:tool.output_bytes])
                    atomic_json(receipt_path, {
                        "schema": "appsec-review/container-execution-partial/1",
                        "tool_id": tool.tool_id, "image_id": image_id, "container_name": name,
                        "started_at": started, "completed_at": _stamp(),
                        "duration_ms": max(0, int((datetime.now(timezone.utc) -
                            datetime.fromisoformat(started)).total_seconds() * 1000)),
                        "exit_code": outcome.exit_code, "timed_out": outcome.timed_out,
                        "oom_killed": outcome.oom_killed, "cleanup": "PENDING",
                        "stdout_truncated": len(outcome.stdout) > tool.output_bytes,
                        "stderr_truncated": len(outcome.stderr) > tool.output_bytes,
                        "stdout_sha256": file_sha256(stdout_path),
                        "stderr_sha256": file_sha256(stderr_path),
                        **({"metrics_receipt": measurement.receipt} if measurement is not None else {}),
                    })
                    expected = (outcome.exit_code in request.accepted_exit_codes
                                or request.expected_nonzero is not None
                                and request.expected_nonzero(outcome.exit_code, outcome.stdout, outcome.stderr))
                    safety.failed_result(outcome.timed_out or outcome.oom_killed or not expected,
                                         f"{tool.tool_id} execution failed; evidence: {receipt_path}",
                                         action=f"scanner.{tool.tool_id}")
                if outcome.timed_out and not safety.active() and measurement is None:
                    self._run_control(("docker", "kill", name))
        finally:
            # The scanner's write window has closed: retained scratch evidence is not world-writable.
            request.scratch_root.resolve().chmod(0o755)
        completed = _stamp()
        stdout = outcome.stdout[:tool.output_bytes]
        stderr = outcome.stderr[:tool.output_bytes]
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        mount_receipts = tuple({
            "source": str(mount.source.resolve()), "target": mount.target,
            "runtime_source": str(effective_sources[mount.target]), "read_only": mount.read_only,
        } for mount in mounts)
        argv_identity = hashlib.sha256(json.dumps(request.argv, separators=(",", ":")).encode()).hexdigest()
        result = ExecutionResult(
            schema="appsec-review/container-execution/1", tool_id=tool.tool_id,
            image_tag=tool.tag, image_id=image_id, image_digest=image_id,
            argv_identity=argv_identity, mounts=mount_receipts, limits=limits,
            started_at=started, completed_at=completed, exit_code=outcome.exit_code,
            timed_out=outcome.timed_out, oom_killed=outcome.oom_killed,
            stdout_truncated=len(outcome.stdout) > tool.output_bytes,
            stderr_truncated=len(outcome.stderr) > tool.output_bytes,
            stdout_path=stdout_path.relative_to(self.run_root).as_posix(),
            stderr_path=stderr_path.relative_to(self.run_root).as_posix(),
            receipt_path=receipt_path.relative_to(self.run_root).as_posix(),
            file_size_limit_bytes=request.file_size_limit_bytes,
            file_size_limit_reached=(request.file_size_limit_bytes is not None
                                     and outcome.exit_code == FILE_SIZE_SIGNAL_EXIT),
            environment_sha256={key: hashlib.sha256(value.encode("utf-8")).hexdigest()
                                for key, value in sorted((request.environment or {}).items())},
            argv=tuple(request.argv),
        )
        receipt = asdict(result)
        receipt["terminal_status"] = result.terminal_status
        receipt["stdout_sha256"] = file_sha256(stdout_path)
        receipt["stderr_sha256"] = file_sha256(stderr_path)
        if measurement is not None:
            receipt["metrics_receipt"] = measurement.receipt
        atomic_json(receipt_path, receipt)
        return result
