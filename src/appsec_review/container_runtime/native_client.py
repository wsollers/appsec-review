"""Non-root client for the restricted native broker; never falls back to Docker."""
from __future__ import annotations

import base64
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from decimal import Decimal
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time
from typing import Mapping, Sequence
from uuid import uuid4

from appsec_review.config.assurance import ResourceBudget
from appsec_review.config.native_dagster import native_execution_requested
from appsec_review.container_runtime.buildkit_worker import private_path, process_token
from appsec_review.container_runtime.native_commands import NativeControl, NativeRun, parse_native_command
from appsec_review.runtime import resources
from appsec_review.storage import atomic_json, bounded_file_lock


SCHEMA = "appsec-review/native-engine/1"
MAX_RESPONSE = 256 * 1024
MAX_CAPTURE = 8 * 1024 * 1024
BINDING_FIELDS = frozenset({
    "tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id",
    "service_generation", "engine_id", "engine_generation",
})


def _json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate broker JSON field")
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=pairs,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    if not isinstance(result, dict):
        raise ValueError("broker document must be an object")
    return result


@dataclass(frozen=True)
class NativeClientContract:
    endpoint: str
    metadata_root: str
    run_root: str
    target_root: str
    uid: int
    gid: int
    broker_pid: int
    broker_start_token: str
    binding: Mapping[str, str]
    resources: ResourceBudget
    mounts: tuple[Mapping[str, object], ...]
    executables: Mapping[str, str]
    image_ids: tuple[str, ...] = ()
    host_cgroup: str | None = None
    host_cpu: int = 1
    host_memory_mb: int = 512
    host_namespaces: Mapping[str, str] | None = None

    @classmethod
    def load(cls, path: Path) -> "NativeClientContract":
        private_path(path, uid=0, directory=False)
        if path.stat().st_size > 65536:
            raise ValueError("native client contract exceeds its bound")
        document = _json(path.read_bytes())
        fields = set(cls.__dataclass_fields__)
        if set(document) != fields:
            raise ValueError("native client contract fields are incomplete or unknown")
        document["resources"] = ResourceBudget.from_view(document["resources"])
        document["mounts"] = tuple(document["mounts"])
        document["image_ids"] = tuple(document["image_ids"])
        return cls(**document)

    def __post_init__(self):
        from appsec_review.config.image_builder_service import absolute
        import re

        for name in ("endpoint", "metadata_root", "run_root", "target_root"):
            absolute(getattr(self, name))
        if any(type(getattr(self, name)) is not int or getattr(self, name) < 1
               for name in ("uid", "gid", "broker_pid")):
            raise ValueError("native client requires exact non-root identity and broker PID")
        if (not isinstance(self.broker_start_token, str) or not self.broker_start_token
                or len(self.broker_start_token) > 200
                or not isinstance(self.binding, Mapping) or set(self.binding) != BINDING_FIELDS
                or any(not isinstance(value, str) or not 1 <= len(value) <= 200
                       for value in self.binding.values())):
            raise ValueError("native client requires exact immutable run/service/engine binding")
        if self.binding["run_id"] != Path(self.run_root).name:
            raise ValueError("native client run path differs from its grant")
        if not isinstance(self.resources, ResourceBudget):
            raise ValueError("native client requires typed resource budget")
        if (not isinstance(self.image_ids, tuple) or len(self.image_ids) > 128
                or any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                       for value in self.image_ids)):
            raise ValueError("native image preflight identities are invalid")
        if self.host_cgroup is not None:
            absolute(self.host_cgroup)
            if not Path(self.host_cgroup).is_relative_to("/sys/fs/cgroup"):
                raise ValueError("native host reservation requires a cgroup-v2 path")
        if any(type(value) is not int or value < 1 for value in (self.host_cpu, self.host_memory_mb)):
            raise ValueError("native host reservation limits are invalid")
        if self.host_namespaces is not None and (
                not isinstance(self.host_namespaces, Mapping)
                or set(self.host_namespaces) != {"mnt", "pid", "user"}
                or any(not isinstance(value, str) or not re.fullmatch(rf"{name}:\[[0-9]+\]", value)
                       for name, value in self.host_namespaces.items())):
            raise ValueError("native host namespace identities are incomplete or invalid")
        if not isinstance(self.mounts, tuple) or len(self.mounts) > 64:
            raise ValueError("native client mount map is unbounded")
        ids = set()
        for mount in self.mounts:
            if (not isinstance(mount, Mapping)
                    or set(mount) != {"mount_id", "source_root", "destination", "read_only"}
                    or not isinstance(mount["mount_id"], str)
                    or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", mount["mount_id"])
                    or mount["mount_id"] in ids or type(mount["read_only"]) is not bool):
                raise ValueError("native client mount mapping is invalid")
            absolute(mount["source_root"])
            absolute(mount["destination"])
            ids.add(mount["mount_id"])
        if not isinstance(self.executables, Mapping) or len(self.executables) > 128:
            raise ValueError("native executable mapping is unbounded")
        for alias, executable in self.executables.items():
            if not isinstance(alias, str) or not 1 <= len(alias) <= 4096 or "\0" in alias:
                raise ValueError("invalid native executable alias")
            absolute(executable)
        for root in (self.run_root, self.target_root):
            if Path(self.endpoint).is_relative_to(root):
                raise ValueError("native broker endpoint cannot be within worker custody")


class NativeClient:
    def __init__(self, contract: NativeClientContract):
        self.contract = contract
        self.executions: dict[str, dict] = {}
        self.cleanup_nonces: dict[tuple[str, str], str] = {}

    def binding(self) -> dict:
        active = resources._ACTIVE.get()
        if (active is None or active.closed or active.admission.budget != self.contract.resources
                or active.admission.root != Path(self.contract.metadata_root) / "resource-admission"
                or not active.admission.require_container_removal):
            raise RuntimeError("native engine requires its exact active removed-only resource lease")
        binding = {**self.contract.binding, "lease_id": active.lease_id}
        with bounded_file_lock(active.admission.root / "admission.lock", 30):
            path = active.admission.root / "leases.json"
            state = _json(path.read_bytes())
            entry = state["leases"][active.lease_id]
            expected = {**binding, "resource_budget": self.contract.resources.view()}
            if entry.get("native_engine_scope", expected) != expected:
                raise ValueError("native resource lease scope changed")
            if (entry["pid"] != os.getpid() or entry["process_identity"] != process_token(os.getpid())
                    or entry.get("owner_finished")):
                raise ValueError("native resource lease belongs to a different process generation")
            if "native_engine_scope" not in entry:
                entry["native_engine_scope"] = expected
                atomic_json(path, state)
        return binding

    def request(self, action: str, payload: dict, *, timeout: float = 60,
                request_id: str | None = None) -> dict:
        binding = self.binding()
        request_id = uuid4().hex if request_id is None else request_id
        data = json.dumps({"schema": SCHEMA, "request_id": request_id, "action": action,
                           "binding": binding, "payload": payload}, separators=(",", ":")).encode() + b"\n"
        if len(data) > 65536 or not 0 < timeout <= 120:
            raise ValueError("native request exceeds its message/deadline bound")
        endpoint = Path(self.contract.endpoint)
        private_path(endpoint.parent, uid=0)
        info = endpoint.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.contract.uid
                or stat.S_IMODE(info.st_mode) != 0o600
                or (os.geteuid(), os.getegid()) != (self.contract.uid, self.contract.gid)):
            raise PermissionError("native broker endpoint lacks its exact private application custody")
        deadline = time.monotonic() + timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(timeout)
            channel.connect(str(endpoint))
            pid, uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if (uid != 0 or pid != self.contract.broker_pid
                    or process_token(pid) != self.contract.broker_start_token):
                raise PermissionError("native broker peer was replaced or changed namespaces")
            for name in ("mnt", "pid", "user"):
                expected = (self.contract.host_namespaces[name] if self.contract.host_namespaces is not None
                            else os.readlink(f"/proc/{pid}/ns/{name}"))
                if expected != os.readlink(f"/proc/self/ns/{name}"):
                    raise PermissionError("native broker peer was replaced or changed namespaces")
            current = endpoint.lstat()
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise PermissionError("native broker socket changed during connection")
            channel.sendall(data)
            response = bytearray()
            while not response.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("native broker response deadline exceeded")
                channel.settimeout(remaining)
                chunk = channel.recv(min(65536, MAX_RESPONSE + 1 - len(response)))
                if not chunk:
                    raise RuntimeError("native broker closed without a complete response")
                response.extend(chunk)
                if len(response) > MAX_RESPONSE:
                    raise ValueError("native broker response exceeds its bound")
        result = _json(bytes(response))
        if (set(result) != {"schema", "request_id", "action", "binding", "result"}
                or result["schema"] != SCHEMA or result["request_id"] != request_id
                or result["action"] != action or result["binding"] != binding
                or not isinstance(result["result"], dict)):
            raise ValueError("native broker response does not bind this request")
        body = result["result"]
        if (not self.contract.resources.matches(body.get("resource_budget"))
                or body.get("broker_process") != {
                    "pid": self.contract.broker_pid, "start_token": self.contract.broker_start_token}):
            raise PermissionError("native broker lifetime or budget changed")
        if body.get("quarantine") or body.get("state") == "UNKNOWN":
            resources.quarantine_resources("native_broker_outcome_unknown")
            raise RuntimeError("native broker outcome is quarantined")
        return body

    def _create(self, command: NativeRun) -> dict:
        if command.user != f"{self.contract.uid}:{self.contract.gid}":
            raise PermissionError("native worker identity differs from its application custody")
        cpu = Decimal(command.cpu)
        if cpu != int(cpu):
            raise ValueError("native broker currently requires whole-CPU execution caps")
        mounts = []
        for mount in command.mounts:
            matches = [policy for policy in self.contract.mounts
                       if policy["destination"] == mount.target
                       and policy["read_only"] == mount.read_only
                       and Path(mount.source).is_relative_to(policy["source_root"])]
            if len(matches) != 1:
                raise PermissionError("native mount does not select one exact operator mapping")
            policy = matches[0]
            mounts.append({"mount_id": policy["mount_id"],
                           "relative_path": str(Path(mount.source).relative_to(policy["source_root"]))})
        executable = self.contract.executables.get(command.executable)
        if executable is None:
            raise PermissionError("native executable is not in the operator alias map")
        size = command.tmpfs.rsplit("size=", 1)[1]
        return {
            "execution_id": uuid4().hex, "name": command.name, "image_id": command.image_id,
            "executable": executable, "arguments": list(command.arguments), "cpu": int(cpu),
            "memory_mb": command.memory_mb, "pids": command.pids,
            "network": "isolated" if command.network == "bridge" else "none",
            "workdir": command.working_directory, "mounts": mounts,
            "environment": dict(command.environment),
            "tmpfs": [{"destination": "/tmp", "size_mb": int(size[:-1]) * (1024 if size[-1] == "g" else 1),
                       "executable": ",exec," in command.tmpfs}],
            "fsize_bytes": command.file_size_limit_bytes,
        }

    def _control(self, name: str) -> dict:
        if name not in self.executions:
            raise PermissionError("native execution is not owned by this client")
        return {key: self.executions[name][key] for key in ("execution_id", "execution_token")}

    def _until(self, action: str, payload: dict, deadline: float) -> dict:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("native operation deadline exceeded")
        return self.request(action, payload, timeout=min(60, remaining))

    def _logs(self, name: str, stream: str, deadline: float) -> bytes:
        output = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("native capture did not close before its deadline")
            result = self._until("execution.logs", {
                **self._control(name), "stream": stream, "offset": len(output), "max_bytes": 65536}, deadline)
            data = base64.b64decode(result["data_b64"], validate=True)
            if (result["stream"] != stream or result["offset"] != len(output) or len(data) > 65536
                    or result["next_offset"] != len(output) + len(data)
                    or len(output) + len(data) > MAX_CAPTURE or result["truncated"]):
                raise RuntimeError("native capture is truncated or its cursor changed")
            output.extend(data)
            if result["eof"]:
                if not result["complete"] or result["total_bytes"] != len(output):
                    raise RuntimeError("native capture is not complete")
                return bytes(output)
            if not data:
                time.sleep(0.01)

    def run(self, argv: Sequence[str], timeout: int) -> tuple[int | None, bytes, bytes, bool]:
        if type(timeout) is not int or timeout < 1:
            raise ValueError("native execution requires a positive finite timeout")
        command = parse_native_command(argv)
        deadline = time.monotonic() + timeout
        if isinstance(command, NativeControl):
            if command.operation == "image.inspect":
                result = self._until(command.operation, {"reference": command.reference}, deadline)
                if result.get("state") != "PRESENT":
                    raise RuntimeError("native approved image is unavailable")
                return 0, (result["image_id"] + "\n").encode(), b"", False
            control = self._control(command.reference)
            if self.executions[command.reference]["state"] == "REMOVED":
                if command.operation == "execution.remove":
                    return 0, b"", b"", False
                return 1, b"", f"Error: No such container: {command.reference}".encode(), False
            if command.operation in {"execution.cancel", "execution.remove"}:
                nonce = self.cleanup_nonces.setdefault((command.reference, command.operation), uuid4().hex)
                result = self.request(command.operation, control, timeout=min(60, timeout), request_id=nonce)
            else:
                result = self._until(command.operation, control, deadline)
            state = result["state"]
            if command.operation == "execution.remove":
                if state != "REMOVED":
                    raise RuntimeError("native removal is unconfirmed")
                self.executions[command.reference]["state"] = state
                return 0, b"", b"", False
            if state == "REMOVED":
                return 1, b"", f"Error: No such container: {command.reference}".encode(), False
            if command.operation == "execution.cancel":
                if state != "STOPPED":
                    raise RuntimeError("native cancellation is unconfirmed")
                return 0, b"", b"", False
            return 0, b"true" if state == "RUNNING" else b"false", b"", False
        if command.name in self.executions:
            raise ValueError("native execution name is already owned")
        payload = self._create(command)
        resources.track_container(command.name)
        created = self._until("execution.create", payload, deadline)
        if created.get("state") != "CREATED" or created.get("execution_id") != payload["execution_id"]:
            raise RuntimeError("native create was not confirmed")
        self.executions[command.name] = created
        started = self._until("execution.start", self._control(command.name), deadline)
        if started["state"] != "RUNNING":
            raise RuntimeError("native start was not confirmed")
        while time.monotonic() < deadline:
            status = self._until("execution.wait", {
                **self._control(command.name), "timeout_seconds": 5}, deadline)
            if status["state"] == "EXITED":
                code = status.get("exit_code")
                if type(code) is not int:
                    raise RuntimeError("native exit code is unavailable")
                return code, self._logs(command.name, "stdout", deadline), self._logs(
                    command.name, "stderr", deadline), False
            if status["state"] != "RUNNING":
                raise RuntimeError("native execution entered an unexpected state")
        self.run(("docker", "kill", command.name), 60)
        return None, b"", b"", True


_CLIENT: ContextVar[NativeClient | None] = ContextVar("native_engine_client", default=None)


@contextmanager
def native_engine_scope(context):
    if not native_execution_requested():
        yield
        return
    path = Path(os.environ["APPSEC_NATIVE_ENGINE_CONTRACT"])
    contract = NativeClientContract.load(path)
    manifest = _json((context.run_root / "data/configuration/manifest.json").read_bytes())
    if (Path(contract.run_root) != context.run_root.resolve()
            or Path(contract.metadata_root) != context.metadata_root.resolve()
            or contract.binding["configuration_id"] != manifest.get("resolved_sha256")
            or contract.resources != context.review_policy.resources
            or contract.binding["project_id"] != context.review_policy.project_id
            or context.source_fingerprint not in {"none", contract.binding["target_snapshot"]}
            or (context.target_root is not None and Path(contract.target_root) != context.target_root.resolve())):
        raise ValueError("native client contract differs from the frozen application context")
    token = _CLIENT.set(NativeClient(contract))
    try:
        yield
    finally:
        _CLIENT.reset(token)


def native_run(argv: Sequence[str], timeout: int):
    if not native_execution_requested():
        return None
    client = _CLIENT.get()
    if client is None:
        raise RuntimeError("native engine operation lacks its application-owned scope")
    try:
        if tuple(argv[:3]) == ("docker", "image", "inspect") and resources._ACTIVE.get() is None:
            with resources.reserve_execution(cpu="1", memory="1m", action="native.image.inspect",
                                             timeout_seconds=timeout):
                return client.run(argv, timeout)
        return client.run(argv, timeout)
    except (OSError, ValueError, RuntimeError):
        resources.quarantine_resources("native_client_operation_unconfirmed")
        raise
