"""Native Linux, rootless-in-container BuildKit driver.

No Docker Desktop, remote daemon, privileged worker, host socket mount, tag-only
success, or unenforced-resource fallback is supported. The operator must provision
the two capped cgroup-v2 subtrees, local images and declared host tools beforehand.
BuildKit/skopeo may compute content addresses as part of image transport; this
module never fingerprints recipes, generated sources or installed platform files.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import struct
import subprocess
import time
from typing import Callable
from urllib.parse import urlsplit

from appsec_review.config.image_builder_service import IMAGE_ID, ImageBuilderServiceConfig


MAX_LOG_BYTES = 64 * 1024
MAX_METADATA_BYTES = 1024 * 1024


class EnforcementUnavailable(RuntimeError):
    pass


class OutcomeUnknown(RuntimeError):
    pass


def bounded_json(path: Path, maximum: int = MAX_METADATA_BYTES):
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("metadata exceeds its bound")
    return json.loads(data)


def private_path(path: Path, *, uid: int | None = None, directory: bool = True) -> None:
    """Reject symlinks and writable ancestors, including operator tool ancestors."""
    owner = os.geteuid() if uid is None else uid
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid not in {0, owner}
                or info.st_mode & 0o022):
            raise EnforcementUnavailable("path custody is not private")
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise EnforcementUnavailable("path ancestor is not a directory")
    if directory and not path.is_dir():
        raise EnforcementUnavailable("private directory is missing")


def process_token(pid: int) -> str | None:
    try:
        value = Path(f"/proc/{pid}/stat").read_text()
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() + ":" + (
            value[value.rfind(")") + 2:].split()[19])
    except FileNotFoundError:
        return None


@dataclass
class Command:
    process: subprocess.Popen
    selector: selectors.BaseSelector
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    output: object = None
    output_size: int = 0
    output_limit: int = MAX_METADATA_BYTES
    truncated: bool = False
    finished: bool = False
    capture_limit: int = MAX_METADATA_BYTES


class CommandRunner:
    """Bounded pipe draining: no communicate(), shell, or unbounded log files."""

    def __init__(self, scratch: Path):
        self.scratch = scratch

    def start(self, argv: list[str], *, output: Path | None = None,
              output_limit: int = MAX_METADATA_BYTES, capture_limit: int = MAX_METADATA_BYTES) -> Command:
        self.scratch.mkdir(parents=True, mode=0o700, exist_ok=True)
        sink = output.open("xb") if output is not None else None
        try:
            process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, close_fds=True,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(self.scratch),
                     "TMPDIR": str(self.scratch), "XDG_RUNTIME_DIR": str(self.scratch),
                     "XDG_CACHE_HOME": str(self.scratch / "cache"),
                     "LANG": "C.UTF-8", "DOCKER_CONFIG": str(self.scratch / "docker")},
            )
        except BaseException:
            if sink is not None:
                sink.close()
            raise
        selector = selectors.DefaultSelector()
        for channel, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(channel.fileno(), False)
            selector.register(channel, selectors.EVENT_READ, name)
        return Command(process, selector, output=sink, output_limit=output_limit, capture_limit=capture_limit)

    def poll(self, command: Command) -> int | None:
        for key, _ in command.selector.select(timeout=0):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                command.selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            if key.data == "stdout":
                command.output_size += len(chunk)
                if command.output_size > command.output_limit:
                    command.truncated = True
                    if command.output is not None:
                        self.stop(command)
                        raise OutcomeUnknown("export exceeded its bounded destination")
                if command.output is not None:
                    command.output.write(chunk)
            target = command.stdout if key.data == "stdout" else command.stderr
            if key.data != "stdout" or command.output is None:
                target.extend(chunk[:max(0, command.capture_limit - len(target))])
        code = command.process.poll()
        if code is not None and not command.selector.get_map():
            command.selector.close()
            command.finished = True
            if command.output is not None:
                command.output.flush()
                os.fsync(command.output.fileno())
                command.output.close()
                command.output = None
            return code
        return None

    def launcher(self, command: Command) -> dict:
        token = process_token(command.process.pid)
        if token is None:
            raise OutcomeUnknown("build launcher identity could not be persisted")
        return {"pid": command.process.pid, "start_token": token}

    def stop(self, command: Command) -> None:
        if command.finished:
            return
        try:
            os.killpg(command.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        command.process.wait(timeout=5)
        for key in list((command.selector.get_map() or {}).values()):
            key.fileobj.close()
        command.selector.close()
        if command.output is not None:
            command.output.close()
            command.output = None
        command.finished = True

    def run(self, argv: list[str], timeout: float, *, output: Path | None = None,
            output_limit: int = MAX_METADATA_BYTES) -> tuple[int, bytes, bytes]:
        command = self.start(argv, output=output, output_limit=output_limit)
        deadline = time.monotonic() + timeout
        try:
            while True:
                code = self.poll(command)
                if code is not None:
                    if command.truncated and output is None:
                        raise OutcomeUnknown("command response exceeded its bound")
                    return code, bytes(command.stdout), bytes(command.stderr[:MAX_LOG_BYTES])
                if time.monotonic() >= deadline:
                    raise OutcomeUnknown("command deadline; daemon work may remain")
                command.selector.select(timeout=0.005)
        except BaseException:
            self.stop(command)
            raise


class KernelProof:
    """Read actual kernel limits and local daemon identity, never requested flags."""

    def __init__(self, config: ImageBuilderServiceConfig):
        self.config = config

    def limits(self, root: Path, cpu: int, memory: int) -> dict:
        if root.resolve(strict=True) != root:
            raise EnforcementUnavailable("cgroup path is not canonical")
        private_path(root)
        quota, period = (root / "cpu.max").read_text().split()
        value = (root / "memory.max").read_text().strip()
        if (not quota.isdecimal() or not period.isdecimal() or not value.isdecimal()
                or not 0 < int(quota) <= cpu * int(period) or int(period) <= 0
                or not 0 < int(value) <= memory
                or (root / "memory.swap.max").read_text().strip() != "0"):
            raise EnforcementUnavailable("CPU, memory or swap enforcement is missing or excessive")
        return {"cpu_quota_us": int(quota), "cpu_period_us": int(period), "memory_max": int(value)}

    def builder_limits(self, root: Path, cpu: int, memory: int) -> dict:
        if self.config.resource_mode == "bounded":
            return self.limits(root, cpu, memory)
        if root.resolve(strict=True) != root:
            raise EnforcementUnavailable("cgroup path is not canonical")
        private_path(root)
        quota, period = (root / "cpu.max").read_text().split()
        if (quota != "max" or not period.isdecimal() or int(period) <= 0
                or (root / "memory.max").read_text().strip() != "max"):
            raise EnforcementUnavailable("concurrency-only builder has a builder-specific CPU/RAM cap")
        inherited = []
        swap_stopped = (root / "memory.swap.max").read_text().strip() == "0"
        for parent in root.parents:
            if not (parent / "cpu.max").is_file():
                break
            cpu_value = (parent / "cpu.max").read_text().strip()
            memory_value = (parent / "memory.max").read_text().strip()
            swap_value = (parent / "memory.swap.max").read_text().strip()
            swap_stopped = swap_stopped or swap_value == "0"
            inherited.append({"path": str(parent), "cpu_max": cpu_value,
                              "memory_max": memory_value, "swap_max": swap_value})
        if not swap_stopped:
            raise EnforcementUnavailable("concurrency-only builder zero-swap policy is unverified")
        return {"resource_mode": "concurrency_only", "cpu_quota_us": None,
                "cpu_period_us": int(period), "memory_max": None, "swap_max": 0,
                "inherited_limits": inherited}

    def process_cgroup(self, pid: int) -> Path:
        values = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        if len(values) != 1 or not values[0].startswith("0::/"):
            raise EnforcementUnavailable("unified native cgroup-v2 topology required")
        return Path("/sys/fs/cgroup") / values[0][4:]

    def _same_host(self, pid: int):
        for name in ("mnt", "pid", "user"):
            if os.readlink(f"/proc/{pid}/ns/{name}") != os.readlink(f"/proc/self/ns/{name}"):
                raise EnforcementUnavailable("daemon is not in the service's native host namespaces")
        actual, expected = os.stat(f"/proc/{pid}/root"), os.stat("/proc/self/root")
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise EnforcementUnavailable("daemon host root does not match")

    def _helper_group(self, executable: str, group: Path) -> None:
        config = self.config
        if group.is_relative_to(config.host_cgroup) or group.is_relative_to(config.worker_cgroup_parent):
            return
        native = getattr(config, "native_engine", None)
        if (native is not None and executable in {"containerd-shim-runc-v2", "runc"}
                and group.is_relative_to(native.execution_cgroup_parent)):
            self.limits(Path(native.execution_cgroup_parent), native.cpu, native.memory_mb * 1024**2)
            return
        raise EnforcementUnavailable("an engine helper escapes the bounded topology")

    def _process(self, pid: int) -> tuple[int, list[str]]:
        root = Path("/proc") / str(pid)
        status = (root / "stat").read_text()
        parent = int(status[status.rfind(")") + 2:].split()[1])
        with (root / "cmdline").open("rb") as stream:
            data = stream.read(32769)
        if len(data) > 32768:
            raise EnforcementUnavailable("engine helper arguments exceed the custody bound")
        return parent, [os.fsdecode(value) for value in data.rstrip(b"\0").split(b"\0")]

    @staticmethod
    def _option(arguments: list[str], name: str) -> str | None:
        values = []
        for index, value in enumerate(arguments):
            if value == name and index + 1 < len(arguments):
                values.append(arguments[index + 1])
            elif value.startswith(name + "="):
                values.append(value[len(name) + 1:])
        if len(values) > 1:
            raise EnforcementUnavailable("engine helper has ambiguous custody arguments")
        return values[0] if values else None

    def _owned_helper(self, executable: str, pid: int, daemon: int, group: Path) -> bool:
        scope = self.config.docker_helper_scope
        if scope is None or pid == daemon:
            return True
        roots = [self.config.host_cgroup, self.config.worker_cgroup_parent]
        if self.config.native_engine is not None:
            roots.append(self.config.native_engine.execution_cgroup_parent)
        if any(group.is_relative_to(root) for root in roots):
            return True
        parent, arguments = self._process(pid)
        flags = {"dockerd": ("--data-root", "--exec-root"),
                 "containerd": ("--config", "-c", "--state", "--root"),
                 "containerd-shim-runc-v2": ("-address", "--address"),
                 "runc": ("--root",)}.get(executable, ())
        for flag in flags:
            value = self._option(arguments, flag)
            if value is not None and Path(value).is_absolute() and any(
                    Path(value).is_relative_to(root) for root in (scope.exec_root, scope.data_root)):
                return True
        # Also retain live descendants before they acquire their runtime-root
        # arguments. Private root arguments identify reparented helpers.
        seen = {pid}
        for _ in range(64):
            if parent == daemon:
                return True
            if parent <= 1 or parent in seen:
                return False
            seen.add(parent)
            parent_group = self.process_cgroup(parent)
            if any(parent_group.is_relative_to(root) for root in roots):
                return True
            parent, parent_arguments = self._process(parent)
            for flag in ("--root", "--config", "--state", "-address", "--address", "--exec-root"):
                value = self._option(parent_arguments, flag)
                if value is not None and Path(value).is_absolute() and any(
                        Path(value).is_relative_to(root) for root in (scope.exec_root, scope.data_root)):
                    return True
        raise EnforcementUnavailable("engine helper ancestry exceeds its custody bound")

    def owned_helper_groups(self, daemon: int = -1):
        for entry in Path("/proc").iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                executable = Path(os.readlink(entry / "exe")).name
                if executable not in {"dockerd", "containerd", "containerd-shim-runc-v2", "runc"}:
                    continue
                pid = int(entry.name)
                group = self.process_cgroup(pid)
                owned = self._owned_helper(executable, pid, daemon, group)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if owned:
                yield executable, group

    def host(self) -> dict:
        config = self.config
        if not any(" - cgroup2 " in line and line.split()[4] == "/sys/fs/cgroup"
                   for line in Path("/proc/self/mountinfo").read_text().splitlines()):
            raise EnforcementUnavailable("native cgroup-v2 mount is unproved")
        host = Path(config.host_cgroup)
        if not self.process_cgroup(os.getpid()).is_relative_to(host):
            raise EnforcementUnavailable("service overhead is outside its capped host cgroup")
        limits = self.builder_limits(host, config.host_cpu, config.host_overhead_mb * 1024 * 1024)
        self.builder_limits(Path(config.worker_cgroup_parent), config.cpu, config.memory_mb * 1024 * 1024)
        endpoint = Path(config.docker_endpoint)
        private_path(endpoint, directory=False)
        if not stat.S_ISSOCK(endpoint.lstat().st_mode):
            raise EnforcementUnavailable("local Docker endpoint is not a socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(config.command_timeout_seconds)
            channel.connect(str(endpoint))
            pid, uid, _ = struct.unpack(
                "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0 or not self.process_cgroup(pid).is_relative_to(host):
            raise EnforcementUnavailable("Docker daemon overhead is not locally capped")
        self._same_host(pid)
        generation = process_token(pid)
        if generation is None:
            raise EnforcementUnavailable("Docker daemon generation is missing")
        if config.docker_helper_scope is not None:
            scope = config.docker_helper_scope
            for root in (scope.data_root, scope.exec_root):
                private_path(Path(root))
            _, arguments = self._process(pid)
            if (Path(os.readlink(f"/proc/{pid}/exe")).name != "dockerd"
                    or self._option(arguments, "--data-root") != scope.data_root
                    or self._option(arguments, "--exec-root") != scope.exec_root):
                raise EnforcementUnavailable("Docker daemon does not own the declared private roots")
        listening = set()
        for table in ("tcp", "tcp6"):
            for line in Path(f"/proc/{pid}/net/{table}").read_text().splitlines()[1:]:
                columns = line.split()
                if columns[3] == "0A":
                    listening.add("socket:[" + columns[9] + "]")
        for descriptor in Path(f"/proc/{pid}/fd").iterdir():
            try:
                if os.readlink(descriptor) in listening:
                    raise EnforcementUnavailable("Docker control is exposed on a TCP listener")
            except FileNotFoundError:
                continue
        # Dedicated-engine scope excludes unrelated infrastructure, not escaped
        # descendants or reparented helpers with this engine's private roots.
        for executable, group in self.owned_helper_groups(pid):
            self._helper_group(executable, group)
        if process_token(pid) != generation:
            raise EnforcementUnavailable("Docker daemon generation changed during helper inventory")
        result = {f"host_{key}": value for key, value in limits.items()}
        if config.engine_domain is not None:
            from appsec_review.container_runtime.engine_admission import EngineDomainProof
            result["engine_domain"] = EngineDomainProof(config).live()
        return result

    def worker(self, inspection: dict, record: dict) -> dict:
        config = self.config
        cid = record["driver"]["container_id"]
        if inspection.get("Id") != cid or inspection.get("Image") != config.worker_image_id:
            raise EnforcementUnavailable("worker immutable identity changed")
        settings, host = inspection["Config"], inspection["HostConfig"]
        if (settings.get("User") != f"{config.worker_uid}:{config.worker_uid}"
                or host.get("Privileged") or host.get("PidMode") == "host"
                or host.get("IpcMode") != "private"
                or host.get("NetworkMode") != (config.network_id or "none")
                or set(host.get("CapAdd") or []) != {"SETUID", "SETGID"} or host.get("CapDrop") != ["ALL"]
                or not host.get("ReadonlyRootfs")):
            raise EnforcementUnavailable("worker isolation differs from the requested sandbox")
        if settings.get("Labels", {}).get("appsec.builder.token") != record["worker"]["start_token"]:
            raise EnforcementUnavailable("worker generation label changed")
        pid = inspection.get("State", {}).get("Pid")
        if type(pid) is not int or pid <= 0:
            raise EnforcementUnavailable("worker has no resolving native process")
        group = self.process_cgroup(pid)
        expected = Path(config.worker_cgroup_parent) / cid
        if group != expected:
            raise EnforcementUnavailable("worker PID does not resolve to its exact local cgroup")
        pids = (group / "pids.max").read_text().strip()
        if not pids.isdecimal() or not 0 < int(pids) <= 512:
            raise EnforcementUnavailable("worker process count is not enforced")
        if os.readlink(f"/proc/{pid}/ns/pid") == os.readlink("/proc/self/ns/pid"):
            raise EnforcementUnavailable("worker shares the host PID namespace")
        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                      if ":" in line)
        if ([int(value) for value in status.get("Uid", "").split()] != [config.worker_uid] * 4
                or int(status.get("CapEff", "ffffffff"), 16) != 0
                or int(status.get("CapBnd", "ffffffff"), 16) != ((1 << 6) | (1 << 7))):
            raise EnforcementUnavailable("worker UID or kernel capabilities differ from its rootless envelope")
        expected_mounts = {
            (str(Path(record["directory"]) / "context"), "/context", False),
            (str(Path(record["directory"]) / "inputs"), "/inputs", False),
            (str(Path(record["directory"]) / "policy"), "/policy", False),
        }
        actual = {(m["Source"], m["Destination"], m["RW"])
                  for m in inspection.get("Mounts", []) if m.get("Type") == "bind"}
        if actual != expected_mounts or any(
                m.get("Type") not in {"bind", "tmpfs"} for m in inspection.get("Mounts", [])):
            raise EnforcementUnavailable("worker mounts are not the isolated run-owned mapping")
        return self.builder_limits(group, config.cpu, config.memory_mb * 1024 * 1024)

    def stopped(self, cid: str) -> bool:
        root = Path(self.config.worker_cgroup_parent) / cid
        if not root.exists():
            return True
        values = dict(line.split() for line in (root / "cgroup.events").read_text().splitlines())
        return values.get("populated") == "0"

    def stop_launcher(self, handle: dict, timeout: float) -> bool:
        pid = handle["pid"]
        token = process_token(pid)
        if token is not None and token != handle["start_token"]:
            # Never signal a reused PID. A live group keeps its old PID reserved.
            return True
        if token is not None:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + timeout
        while True:
            running = False
            for entry in Path("/proc").iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    value = (entry / "stat").read_text()
                    fields = value[value.rfind(")") + 2:].split()
                    if int(fields[2]) == pid and fields[0] not in {"Z", "X"}:
                        running = True
                        break
                except (FileNotFoundError, ProcessLookupError):
                    continue
            if not running:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)


class BuildKitWorker:
    def __init__(self, config: ImageBuilderServiceConfig, *, runner=None, proof=None):
        self.config = config
        self.runner = runner or CommandRunner(Path(config.state_root) / "host-scratch")
        self.proof = proof or KernelProof(config)
        self.jobs: dict[str, Command] = {}
        self.deadline: float | None = None

    def _begin(self, record: dict):
        self.deadline = time.monotonic() + self.config.cleanup_timeout_seconds
        self.runner.scratch = Path(record["directory"]) / "host-scratch"

    def _docker(self, *args: str) -> list[str]:
        return [self.config.docker_binary, "--host", f"unix://{self.config.docker_endpoint}", *args]

    def _run(self, argv: list[str], *, timeout: float | None = None, **kwargs) -> bytes:
        remaining = (self.deadline - time.monotonic()) if self.deadline is not None else float("inf")
        if remaining <= 0:
            raise OutcomeUnknown("bounded driver operation deadline exceeded")
        code, stdout, stderr = self.runner.run(
            argv, min(timeout or self.config.command_timeout_seconds, remaining), **kwargs)
        if code:
            raise RuntimeError("bounded worker command failed: " + stderr.decode("utf-8", "replace")[:2048])
        return stdout

    def _inspect(self, record: dict) -> dict | None:
        name = record["driver"].get("container_id", record["worker"]["id"])
        # A successful list, rather than parsing localized error text, proves
        # absence. An unresolved create intent still cannot be cleared by absence.
        listing = json.loads(self._run(self._docker(
            "container", "ls", "--all", "--no-trunc", "--filter", f"name=^/{name}$",
            "--format", "{{json .ID}}")).decode() or '""')
        if not listing and "container_id" in record["driver"]:
            ids = self._run(self._docker("container", "ls", "--all", "--no-trunc", "--quiet")).decode().split()
            if record["driver"]["container_id"] not in ids:
                return None
            listing = record["driver"]["container_id"]
        if not listing:
            return None
        value = json.loads(self._run(self._docker("container", "inspect", listing)))
        if not isinstance(value, list) or len(value) != 1:
            raise OutcomeUnknown("worker inspection is ambiguous")
        item = value[0]
        labels = item.get("Config", {}).get("Labels", {})
        if (labels.get("appsec.builder.token") != record["worker"]["start_token"]
                or labels.get("appsec.builder.build") != record["binding"]["build_id"]):
            raise OutcomeUnknown("worker ownership is not bound to durable intent")
        if "container_id" in record["driver"] and item.get("Id") != record["driver"]["container_id"]:
            raise OutcomeUnknown("worker was replaced")
        if (record["driver"].get("container_started_at") is not None
                and item.get("State", {}).get("StartedAt") != record["driver"]["container_started_at"]):
            raise OutcomeUnknown("worker container was restarted or replaced")
        return item

    def _inventory(self, record: dict | None = None):
        allowed = {self.config.proxy_container_id} if self.config.proxy_container_id is not None else set()
        if record is not None:
            allowed.add(record["driver"]["container_id"])
        present = set(self._run(self._docker("container", "ls", "--all", "--no-trunc", "--quiet")).decode().split())
        if present - allowed:
            raise EnforcementUnavailable("Docker daemon contains work outside the dedicated builder reservation")

    def prepare(self, record: dict, save: Callable[[], None]) -> dict:
        self._begin(record)
        config = self.config
        for binary in (config.docker_binary, config.skopeo_binary):
            private_path(Path(binary), directory=False)
        host_limits = self.proof.host()
        info = json.loads(self._run(self._docker("info", "--format", "{{json .}}")))
        if (info.get("CgroupDriver") != "cgroupfs" or str(info.get("CgroupVersion")) != "2"
                or info.get("OSType") != "linux" or "desktop" in str(info).lower()):
            raise EnforcementUnavailable("native local cgroupfs/v2 Docker is required")
        image = json.loads(self._run(self._docker("image", "inspect", config.worker_image_id)))[0]
        if image.get("Id") != config.worker_image_id:
            raise EnforcementUnavailable("declared BuildKit image is not installed")
        if set(image.get("Config", {}).get("Volumes") or {}) - {"/home/user/.local/share/buildkit"}:
            raise EnforcementUnavailable("worker image declares unbounded implicit data volumes")
        self._inventory()
        self._network()
        directory = Path(record["directory"])
        for name in ("context", "inputs", "policy"):
            (directory / name).mkdir(mode=0o755)
            (directory / name).chmod(0o755)
        policy = {"version": 1, "rules": [
            {"action": "DENY", "selector": {"identifier": scheme + "://*"}}
            for scheme in ("docker-image", "http", "https", "git")
        ]}
        (directory / "policy" / "sources.json").write_text(json.dumps(policy))
        (directory / "policy" / "sources.json").chmod(0o444)
        args = self._docker(
            "container", "create", "--pull=never", "--name", record["worker"]["id"],
            "--label", f"appsec.builder.token={record['worker']['start_token']}",
            "--label", f"appsec.builder.build={record['binding']['build_id']}",
            "--cgroup-parent", "/" + str(Path(config.worker_cgroup_parent).relative_to("/sys/fs/cgroup")),
            *(() if config.resource_mode == "concurrency_only" else (
                "--cpu-period", "100000", "--cpu-quota", str(config.cpu * 100000),
                "--memory", str(config.memory_mb * 1024 * 1024),
                "--memory-swap", str(config.memory_mb * 1024 * 1024))),
            "--pids-limit", "512", "--cap-drop=ALL", "--cap-add=SETUID", "--cap-add=SETGID",
            "--read-only", "--ipc=private",
            "--user", f"{config.worker_uid}:{config.worker_uid}",
            "--network", config.network_id or "none",
            "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined",
            "--security-opt", "systempaths=unconfined",
            "--mount", f"type=bind,src={directory / 'context'},dst=/context,readonly",
            "--mount", f"type=bind,src={directory / 'inputs'},dst=/inputs,readonly",
            "--mount", f"type=bind,src={directory / 'policy'},dst=/policy,readonly",
            "--tmpfs", f"/home/user:rw,uid={config.worker_uid},gid={config.worker_uid},mode=0700",
            "--tmpfs", f"/home/user/.local/share/buildkit:rw,uid={config.worker_uid},gid={config.worker_uid},mode=0700",
            "--tmpfs", f"/run/user/{config.worker_uid}:rw,uid={config.worker_uid},gid={config.worker_uid},mode=0700",
            "--tmpfs", f"/output:rw,uid={config.worker_uid},gid={config.worker_uid},mode=0700,size={config.max_export_bytes}",
            "--tmpfs", "/scratch:rw,nosuid,nodev,mode=1777,size=64m", "--env", "TMPDIR=/scratch",
            "--entrypoint", "rootlesskit", config.worker_image_id,
            "buildkitd", "--addr", f"unix:///run/user/{config.worker_uid}/buildkit/buildkitd.sock",
            "--oci-worker=true", "--containerd-worker=false", "--oci-worker-snapshotter=native",
        )
        record["driver"].update(create_pending=True, host_operation_pending=True)
        save()
        cid = self._run(args).decode().strip()
        if not re_container_id(cid):
            raise OutcomeUnknown("Docker create did not return an immutable container ID")
        record["driver"].update(container_id=cid, create_pending=False, host_operation_pending=False)
        save()
        record["driver"]["host_operation_pending"] = True
        save()
        self._run(self._docker("container", "start", cid))
        record["driver"]["host_operation_pending"] = False
        save()
        inspection = self._inspect(record)
        if inspection is None:
            raise OutcomeUnknown("new worker disappeared")
        started = inspection.get("State", {}).get("StartedAt")
        if not isinstance(started, str) or not started:
            raise OutcomeUnknown("worker start generation is missing")
        record["driver"]["container_started_at"] = started
        save()
        worker_limits = self.proof.worker(inspection, record)
        deadline = time.monotonic() + config.command_timeout_seconds
        while True:
            try:
                record["driver"]["buildkit_worker_id"] = self._worker_identity(record)
                save()
                break
            except EnforcementUnavailable:
                raise
            except (RuntimeError, ValueError):
                if time.monotonic() >= deadline:
                    raise EnforcementUnavailable("BuildKit readiness is unproved")
                time.sleep(0.1)
        return {**worker_limits, **host_limits}

    def _worker_identity(self, record: dict) -> str:
        workers = json.loads(self._run(self._exec(record, "buildctl", "--addr", self._address(),
                                                 "debug", "workers", "--format", "{{json .}}")))
        if not isinstance(workers, list) or len(workers) != 1:
            raise EnforcementUnavailable("expected one resolving BuildKit worker")
        labels = workers[0].get("labels", workers[0].get("Labels", {}))
        if (labels.get("org.mobyproject.buildkit.worker.oci.process-mode") != "sandbox"
                or labels.get("org.mobyproject.buildkit.worker.snapshotter") != "native"):
            raise EnforcementUnavailable("BuildKit process sandbox is not verified")
        identity = workers[0].get("id", workers[0].get("ID"))
        if not isinstance(identity, str) or not identity:
            raise EnforcementUnavailable("BuildKit worker identity is missing")
        if record["driver"].get("buildkit_worker_id", identity) != identity:
            raise OutcomeUnknown("BuildKit worker generation changed")
        return identity

    def _address(self) -> str:
        return f"unix:///run/user/{self.config.worker_uid}/buildkit/buildkitd.sock"

    def _exec(self, record: dict, *args: str) -> list[str]:
        return self._docker("exec", record["driver"]["container_id"], *args)

    def _network(self, record: dict | None = None):
        config = self.config
        if config.network_id is None:
            return
        network = json.loads(self._run(self._docker("network", "inspect", config.network_id)))[0]
        options = network.get("Options", {})
        expected_peers = {config.proxy_container_id}
        if record is not None:
            expected_peers.add(record["driver"]["container_id"])
        if (network.get("Id") != config.network_id or network.get("Driver") != "bridge"
                or network.get("Internal") is not True or network.get("EnableIPv6")
                or options.get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated"
                or set(network.get("Containers", {})) != expected_peers):
            raise EnforcementUnavailable("package egress network is not isolated to worker and operator proxy")
        bridge = options.get("com.docker.network.bridge.name", "br-" + config.network_id[:12])
        private_path(Path(config.ip_binary), directory=False)
        addresses = json.loads(self._run([config.ip_binary, "-json", "address", "show", "dev", bridge]))
        if len(addresses) != 1 or addresses[0].get("addr_info"):
            raise EnforcementUnavailable("isolated worker bridge still exposes host addresses")
        proxy = json.loads(self._run(self._docker("container", "inspect", config.proxy_container_id)))[0]
        proxy_host = proxy.get("HostConfig", {})
        if (proxy.get("Id") != config.proxy_container_id or proxy.get("Image") != config.proxy_image_id
                or proxy.get("State", {}).get("Running") is not True
                or proxy.get("Config", {}).get("Labels", {}).get("appsec.egress.release") != config.proxy_release_id
                or proxy_host.get("Privileged") or proxy_host.get("NetworkMode") == "host"
                or proxy_host.get("PidMode") == "host" or proxy_host.get("CapAdd")
                or proxy_host.get("CapDrop") != ["ALL"] or not proxy_host.get("ReadonlyRootfs")
                or any(mount.get("Type") != "tmpfs" for mount in proxy.get("Mounts", []))):
            raise EnforcementUnavailable("allowlisted egress proxy release is unproved")
        # The proxy is an operator dependency, not uncharged background work.
        proxy_pid = proxy.get("State", {}).get("Pid")
        if not self.proof.process_cgroup(proxy_pid).is_relative_to(config.host_cgroup):
            raise EnforcementUnavailable("egress proxy overhead escapes the host reservation")
        endpoint = network["Containers"][config.proxy_container_id]["IPv4Address"].split("/")[0]
        if urlsplit(config.proxy_url).hostname != endpoint:
            raise EnforcementUnavailable("proxy URL is not bound to the isolated network endpoint")

    def _inputs(self, record: dict, save: Callable[[], None]) -> tuple[dict[str, str], list[str]]:
        config = self.config
        aliases = record["start"]["authorized_inputs"]
        locations, stores = {}, []
        for index, image_id in enumerate(sorted(set(aliases.values()))):
            image = json.loads(self._run(self._docker("image", "inspect", image_id)))[0]
            if image.get("Id") != image_id or image.get("Config", {}).get("OnBuild"):
                raise EnforcementUnavailable("input image is missing or contains implicit ONBUILD work")
            destination = Path(record["directory"]) / "inputs" / str(index)
            record["driver"]["host_operation_pending"] = True
            save()
            self._run([
                config.skopeo_binary, "copy", "--src-daemon-host", f"unix://{config.docker_endpoint}",
                f"docker-daemon:{image_id}", f"oci:{destination}:input",
            ])
            record["driver"]["host_operation_pending"] = False
            save()
            index_value = bounded_json(destination / "index.json")
            manifests = index_value.get("manifests", [])
            if len(manifests) != 1 or not IMAGE_ID.fullmatch(manifests[0].get("digest", "")):
                raise EnforcementUnavailable("image input lacks one immutable OCI manifest")
            digest = manifests[0]["digest"]
            manifest = bounded_json(destination / "blobs" / "sha256" / digest.split(":")[1])
            if manifest.get("config", {}).get("digest") != image_id:
                raise EnforcementUnavailable("transported image input differs from its authorized immutable ID")
            # This is transport metadata, never a fingerprint of platform payloads.
            locations[image_id] = f"oci-layout://input{index}@{digest}"
            stores.extend(("--oci-layout", f"input{index}=/inputs/{index}"))
            for root, directories, files in os.walk(destination):
                Path(root).chmod(0o755)
                for name in files:
                    (Path(root) / name).chmod(0o644)
        return {alias: locations[image_id] for alias, image_id in aliases.items()}, stores

    def start(self, record: dict, save: Callable[[], None]) -> None:
        self._begin(record)
        self.proof.host()
        inspection = self._inspect(record)
        if inspection is None:
            raise OutcomeUnknown("prepared worker disappeared")
        self.proof.worker(inspection, record)
        self._inventory(record)
        self._worker_identity(record)
        self._network(record)
        aliases, stores = self._inputs(record, save)
        args = self._exec(
            record, "buildctl", "--addr", self._address(), "build",
            "--frontend", "dockerfile.v0", "--local", "context=/context",
            "--local", "dockerfile=/context", "--opt", "filename=Dockerfile",
            "--opt", f"force-network-mode={record['start']['network']}",
            "--no-cache", "--source-policy-file", "/policy/sources.json",
            "--metadata-file", "/output/result.json",
            "--output", f"type=docker,name={record['binding']['output_tag']},dest=/output/image.tar",
        )
        for name, value in sorted(record["start"]["build_args"].items()):
            args.extend(("--opt", f"build-arg:{name}={value}"))
        if record["start"]["network"] == "default":
            if self.config.proxy_url is None:
                raise EnforcementUnavailable("package egress is not commissioned")
            for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                args.extend(("--opt", f"build-arg:{name}={self.config.proxy_url}"))
        for alias, location in sorted(aliases.items()):
            args.extend(("--opt", f"context:{alias}={location}"))
        args.extend(stores)
        record["driver"]["launch_pending"] = True
        save()
        job = self.runner.start(args, capture_limit=MAX_LOG_BYTES)
        self.jobs[record["binding"]["build_id"]] = job
        record["driver"].update(launcher=self.runner.launcher(job), launch_pending=False)
        save()

    def status(self, record: dict, save: Callable[[], None]) -> dict:
        self._begin(record)
        self.proof.host()
        inspection = self._inspect(record)
        if inspection is None:
            raise OutcomeUnknown("running worker disappeared")
        self.proof.worker(inspection, record)
        self._inventory(record)
        self._worker_identity(record)
        self._network(record)
        job = self.jobs.get(record["binding"]["build_id"])
        if job is None:
            raise OutcomeUnknown("build process owner was lost")
        code = self.runner.poll(job)
        if code is None:
            return {"state": "RUNNING"}
        logs = {name: base64.b64encode(bytes(getattr(job, name)[:MAX_LOG_BYTES])).decode()
                for name in ("stdout", "stderr")}
        if code != 0:
            return {"state": "FAILED", "exit_code": code, **logs}
        metadata = json.loads(self._run(self._exec(record, "cat", "/output/result.json")))
        image_id = metadata.get("containerimage.config.digest")
        if not isinstance(image_id, str) or not IMAGE_ID.fullmatch(image_id):
            raise OutcomeUnknown("fresh BuildKit solve has no immutable output config ID")
        archive = Path(record["directory"]) / "image.tar"
        self._run(self._exec(record, "cat", "/output/image.tar"), output=archive,
                  output_limit=self.config.max_export_bytes)
        # An interrupted load can keep working in dockerd after its CLI dies.
        # Never release the reservation based on a failed/absent CLI alone.
        record["driver"]["host_operation_pending"] = True
        save()
        self._run(self._docker("image", "load", "--input", str(archive)))
        record["driver"]["host_operation_pending"] = False
        save()
        value = json.loads(self._run(self._docker("image", "inspect", image_id)))[0]
        tagged = json.loads(self._run(self._docker("image", "inspect", record["binding"]["output_tag"])))[0]
        if value.get("Id") != image_id or tagged.get("Id") != image_id:
            raise OutcomeUnknown("fresh solve output is not the published immutable image")
        return {"state": "SUCCEEDED", "exit_code": 0, "image_id": image_id, **logs}

    def cancel(self, record: dict, save: Callable[[], None]) -> bool:
        self._begin(record)
        job = self.jobs.get(record["binding"]["build_id"])
        if job is not None:
            self.runner.stop(job)
            del self.jobs[record["binding"]["build_id"]]
        launcher = record["driver"].get("launcher")
        launcher_stopped = (not record["driver"].get("launch_pending")
                            and (launcher is None or self.proof.stop_launcher(launcher, 5)))
        inspection = self._inspect(record)
        if inspection is None:
            return launcher_stopped and not (
                record["driver"].get("create_pending") or record["driver"].get("host_operation_pending")) and (
                not record["driver"].get("container_id")
                or self.proof.stopped(record["driver"]["container_id"]))
        cid = inspection["Id"]
        record["driver"]["container_id"] = cid
        save()
        self._run(self._docker("container", "rm", "--force", cid),
                  timeout=self.config.cleanup_timeout_seconds)
        gone = self._inspect(record) is None and self.proof.stopped(cid)
        if gone:
            record["driver"]["create_pending"] = False
            save()
        return gone and launcher_stopped and not record["driver"].get("host_operation_pending")

    def cleanup(self, record: dict, save: Callable[[], None]) -> bool:
        return self.cancel(record, save)


def re_container_id(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
