"""Restricted native-engine/1 server and driver; hosted by the bounded builder.

No argv/HTTP relay, volumes, exec, image loading, tagging, or caller-selected
output paths. Operator policy and the removed-only admission ledger jointly
authorize every request. Unknown generations remain fenced until removal is
independently observed. The operator provisions the static gate below and a
commissioned cgroup-v2 execution parent with delegated controllers.
"""
from __future__ import annotations

import base64
from dataclasses import asdict
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import sqlite3
import stat
import struct
import time
from uuid import uuid4

from appsec_review.config.native_engine import absolute
from appsec_review.container_runtime.buildkit_worker import (
    BuildKitWorker, CommandRunner, EnforcementUnavailable, KernelProof, OutcomeUnknown,
    native_docker_topology, private_path, process_token,
)
from appsec_review.container_runtime.builder_admission import service_contract
from appsec_review.storage import atomic_json


SCHEMA = "appsec-review/native-engine/1"
MAX_REQUEST_BYTES = 65536
MAX_RESPONSE_BYTES = 256 * 1024
MAX_LOG_PAGE = 65536
BINDING_FIELDS = frozenset({
    "tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id",
    "service_generation", "engine_id", "engine_generation", "lease_id",
})
CREATE_FIELDS = frozenset({
    "execution_id", "name", "image_id", "executable", "arguments", "cpu", "memory_mb",
    "pids", "network", "workdir", "mounts", "environment", "tmpfs", "fsize_bytes",
})
CONTROL_FIELDS = frozenset({"execution_id", "execution_token"})
ACTION_FIELDS = {
    "image.inspect": frozenset({"reference"}),
    "execution.create": CREATE_FIELDS,
    **{f"execution.{name}": CONTROL_FIELDS for name in ("start", "status", "cancel", "remove")},
    "execution.wait": CONTROL_FIELDS | {"timeout_seconds"},
    "execution.logs": CONTROL_FIELDS | {"stream", "offset", "max_bytes"},
}
CAPTURE_BYTES = 8 * 1024 * 1024
GATE_SOURCE = r'''/* Operator builds with -static -no-pie; no image interpreter/loader is trusted. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static unsigned char data[65536];
static char *args[50], *env[129];
int main(void) {
    int fd = open("/run/appsec-gate/launch.bin", O_RDONLY | O_NOFOLLOW);
    size_t length = 0;
    ssize_t got;
    if (fd < 0) return 125;
    while (length < sizeof(data)) {
        got = read(fd, data + length, sizeof(data) - length);
        if (got < 0) { if (errno == EINTR) continue; return 125; }
        if (!got) break;
        length += (size_t)got;
    }
    close(fd);
    if (length < 40 || length == sizeof(data)) return 125;
    uint32_t argc, envc;
    memcpy(&argc, data, 4); memcpy(&envc, data + 4, 4);
    if (!argc || argc > 49 || envc > 128) return 125;
    size_t cursor = 40;
    for (uint32_t i = 0; i < argc + envc; i++) {
        if (cursor >= length) return 125;
        char *start = (char *)data + cursor;
        char *end = memchr(start, 0, length - cursor);
        if (!end) return 125;
        if (i < argc) args[i] = start; else env[i - argc] = start;
        cursor = (size_t)(end - (char *)data) + 1;
    }
    if (cursor != length || args[0][0] != '/') return 125;
    struct timespec start, now, delay = {0, 20000000};
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 125;
    for (;;) {
        fd = open("/run/appsec-gate/release.token", O_RDONLY | O_NOFOLLOW);
        if (fd >= 0) {
            unsigned char token[33];
            got = read(fd, token, sizeof(token)); close(fd);
            if (got != 32 || memcmp(token, data + 8, 32)) return 125;
            break;
        }
        if (errno != ENOENT || clock_gettime(CLOCK_MONOTONIC, &now) ||
            now.tv_sec - start.tv_sec >= 60) return 125;
        nanosleep(&delay, 0);
    }
    execve(args[0], args, env);
    return 125;
}
'''


def static_gate(config):
    path = Path(config.native_engine.gate_binary)
    private_path(path, directory=False)
    if not 64 <= path.stat().st_size <= 2 * 1024**2 or not path.stat().st_mode & 0o111:
        raise EnforcementUnavailable("operator gate executable is missing or unbounded")
    # Static linking and architecture are commissioned release properties, not per-review scans.
    if not config.native_engine.gate_release_id:
        raise EnforcementUnavailable("operator gate requires its commissioned static release declaration")
    return path


def _installed_module_path(name: str, path: Path, root: Path, stdlib: Path) -> bool:
    return (path.is_relative_to(root) or path.is_relative_to(stdlib)
            or (name == "__main__" and path == root.parent / "root_entrypoint.py"))


def verify_runtime(config):
    """Defense in depth, not a replacement for the operator's isolated trusted bootstrap."""
    import importlib.metadata
    import sys
    import sysconfig

    native = config.native_engine
    if native is None:
        return
    if not all(getattr(sys.flags, flag) for flag in ("isolated", "ignore_environment", "no_user_site", "no_site")):
        raise EnforcementUnavailable("native service requires an isolated no-site operator bootstrap")
    root, python = Path(native.runtime_root), Path(native.runtime_python)
    private_path(root)
    private_path(python, directory=False)
    if Path(sys.executable) != python:
        raise EnforcementUnavailable("native service Python differs from its declared installed release")
    stdlib = Path(sysconfig.get_path("stdlib"))
    private_path(stdlib)
    for binary in (config.docker_binary, config.skopeo_binary, native.gate_binary):
        private_path(Path(binary), directory=False)
    if config.network_id is not None:
        private_path(Path(config.ip_binary), directory=False)
    distribution = importlib.metadata.distribution("appsec-review")
    if Path(distribution.locate_file("")) != root:
        raise EnforcementUnavailable("native service distribution is outside its declared release")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    if direct.get("dir_info", {}).get("editable"):
        raise EnforcementUnavailable("editable native service installation is forbidden")
    if not Path(__file__).is_relative_to(root):
        raise EnforcementUnavailable("native service imported from outside its installed release")
    for item in sys.path:
        path = Path(item)
        if (not item or not path.is_absolute() or path == Path.cwd()
                or not (path.is_relative_to(root) or path.is_relative_to(stdlib))):
            # CPython's optional stdlib zip may be absent, but cannot resolve via a writable parent.
            expected_zip = stdlib.parent / f"python{sys.version_info.major}{sys.version_info.minor}.zip"
            if path != expected_zip:
                raise EnforcementUnavailable("native import search path escapes the trusted release")
        private_path(path if path.exists() else path.parent, directory=not path.is_file())
    for name, module in tuple(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if origin is None:
            continue
        path = Path(origin)
        if not _installed_module_path(name, path, root, stdlib):
            raise EnforcementUnavailable("loaded native service module escapes the installed closure")
        private_path(path, directory=False)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def execution_seccomp(native, command, network):
    syscalls = [{"names": [name for name in native.syscall_allowlist if name != "clone"],
                 "action": "SCMP_ACT_ALLOW"},
                {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}]
    if "clone" in native.syscall_allowlist:
        syscalls.append({"names": ["clone"], "action": "SCMP_ACT_ALLOW",
                         "args": [{"index": 0, "value": 0x7E020000, "valueTwo": 0,
                                   "op": "SCMP_CMP_MASKED_EQ"}]})
    if command["allow_process_tree_trace"]:
        # The static gate stays closed until kernel proof establishes private PID custody.
        syscalls.append({"names": ["ptrace"], "action": "SCMP_ACT_ALLOW"})
    if network == "isolated":
        for family in (2, 10):
            syscalls.append({"names": ["socket"], "action": "SCMP_ACT_ALLOW",
                             "args": [{"index": 0, "value": family, "op": "SCMP_CMP_EQ"}]})
    return {
        "defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 1,
        "architectures": [{"x86_64": "SCMP_ARCH_X86_64", "aarch64": "SCMP_ARCH_AARCH64"}[
            native.architecture]], "syscalls": syscalls,
    }


def uuid(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def decode_request(data):
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate native request field")
            value[key] = item
        return value
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("native request exceeds bound")
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite native value")))
    if (not isinstance(value, dict) or set(value) != {"schema", "request_id", "action", "binding", "payload"}
            or value["schema"] != SCHEMA or not uuid(value["request_id"])
            or not isinstance(value["action"], str) or value["action"] not in ACTION_FIELDS
            or not isinstance(value["binding"], dict) or set(value["binding"]) != BINDING_FIELDS
            or not isinstance(value["payload"], dict) or set(value["payload"]) != ACTION_FIELDS[value["action"]]):
        raise ValueError("invalid exact native request")
    return value


class EngineInterlock:
    """A durable ownership fence, separate from I/O admission and process lifetime."""
    def __init__(self, store, contract):
        self.store, self.contract = store, contract

    def owner(self):
        row = self.store.connection.execute("SELECT owner FROM engine_interlock WHERE slot=1").fetchone()
        return json.loads(row[0]) if row else None

    def identity(self, kind, key, token):
        return {"kind": kind, "id": key, "token": token, "service_contract": self.contract}

    def claim(self, owner):
        existing = self.owner()
        if existing is not None and existing != owner:
            raise EnforcementUnavailable("native engine has another retained owner")
        self.store.connection.execute(
            "INSERT OR IGNORE INTO engine_interlock VALUES (1,?)", (encoded(owner).decode(),))

    def release(self, owner):
        if self.owner() != owner:
            raise OutcomeUnknown("engine ownership generation changed")
        self.store.connection.execute("DELETE FROM engine_interlock WHERE slot=1")


class NativeProof(KernelProof):
    def host(self):
        limits = super().host()
        native = self.config.native_engine
        parent = Path(native.execution_cgroup_parent)
        private_path(parent)
        if (parent / "cgroup.type").read_text().strip() != "domain" or not {
                "cpu", "memory", "pids"} <= set((parent / "cgroup.subtree_control").read_text().split()):
            raise EnforcementUnavailable("native execution controllers are not delegated")
        self.limits(Path(native.execution_cgroup_parent), native.cpu, native.memory_mb * 1024**2)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(self.config.command_timeout_seconds)
            channel.connect(self.config.docker_endpoint)
            pid, uid, _ = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != 0 or f"{pid}:{process_token(pid)}" != native.engine_generation:
            raise EnforcementUnavailable("native daemon generation changed")
        return limits

    def execution(self, inspection, record):
        pid = inspection["State"].get("Pid")
        if type(pid) is not int or pid < 1:
            raise OutcomeUnknown("native gate has no resolving PID")
        parent = Path(record["driver"]["cgroup"])
        group = self.process_cgroup(pid)
        if group != parent / record["driver"]["container_id"]:
            raise EnforcementUnavailable("native PID escaped its exact delegated cgroup")
        requested = record["payload"]
        limits = self.limits(parent, requested["cpu"], requested["memory_mb"] * 1024**2)
        self.limits(group, requested["cpu"], requested["memory_mb"] * 1024**2)
        for path in (parent, group):
            value = (path / "pids.max").read_text().strip()
            if not value.isdecimal() or not 0 < int(value) <= requested["pids"]:
                raise EnforcementUnavailable("native PID limit is unproved")
        for name in ("pid", "mnt", "ipc", "uts", "net", "cgroup"):
            if os.readlink(f"/proc/{pid}/ns/{name}") == os.readlink(f"/proc/self/ns/{name}"):
                raise EnforcementUnavailable("native process shares a host namespace")
        values = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                      if ":" in line)
        tracing = record["command_policy"]["allow_process_tree_trace"]
        namespace_pids = values.get("NSpid", "").split()
        if tracing and (len(namespace_pids) < 2 or namespace_pids[-1] != "1"
                        or any(not value.isdecimal() for value in namespace_pids)
                        or namespace_pids[0] != str(pid)):
            raise EnforcementUnavailable("process-tree tracing requires a proved private PID namespace init")
        uid, gid = map(int, record["image_policy"]["user"].split(":"))
        if (list(map(int, values.get("Uid", "").split())) != [uid] * 4
                or list(map(int, values.get("Gid", "").split())) != [gid] * 4
                or any(int(values.get(name, "ffffffff"), 16) for name in ("CapEff", "CapPrm", "CapBnd"))
                or values.get("NoNewPrivs", "").strip() != "1"
                or values.get("Seccomp", "").strip() != "2"):
            raise EnforcementUnavailable("native UID, capabilities, NNP or seccomp are unproved")
        for mount in record["driver"]["mounts"]:
            observed = os.stat(f"/proc/{pid}/root{mount['destination']}")
            if [observed.st_dev, observed.st_ino] != mount["identity"]:
                raise EnforcementUnavailable("native bind mount identity changed")
        if requested["fsize_bytes"] is not None:
            line = next((line for line in Path(f"/proc/{pid}/limits").read_text().splitlines()
                         if line.startswith("Max file size")), "")
            if line.split()[3:5] != [str(requested["fsize_bytes"])] * 2:
                raise EnforcementUnavailable("native kernel file-size bound is unproved")
        return {**limits, "pids_max": requested["pids"], "pid": pid, "start_token": process_token(pid),
                "process_tree_trace": tracing, "pid_namespace": os.readlink(f"/proc/{pid}/ns/pid")}


class NativeExecutionDriver(BuildKitWorker):
    def __init__(self, config, *, runner=None, proof=None):
        super().__init__(config, runner=runner, proof=proof or NativeProof(config))
        self.handles, self.captures = {}, {}

    def check_host(self):
        self.deadline = time.monotonic() + self.config.cleanup_timeout_seconds
        self.proof.host()
        static_gate(self.config)
        private_path(Path(self.config.docker_binary), directory=False)
        info = json.loads(self._run(self._docker("info", "--format", "{{json .}}")))
        if (not native_docker_topology(info) or info.get("ID") != self.config.native_engine.engine_id
                or info.get("Architecture") not in {
                    self.config.native_engine.architecture,
                    {"x86_64": "amd64", "aarch64": "arm64"}[self.config.native_engine.architecture]}):
            raise EnforcementUnavailable("native engine identity or topology differs")

    def inventory(self, record=None):
        self.check_host()
        self._inventory(record)

    def image(self, image_id, reference=None):
        self.check_host()
        value = json.loads(self._run(self._docker("image", "inspect", reference or image_id)))
        if (not isinstance(value, list) or len(value) != 1 or value[0].get("Id") != image_id
                or value[0].get("Config", {}).get("OnBuild")
                or value[0].get("Config", {}).get("Volumes")):
            raise EnforcementUnavailable("native image is missing, rebound or declares implicit work/storage")
        if (value[0].get("Os") != "linux"
                or value[0].get("Architecture") != {"x86_64": "amd64", "aarch64": "arm64"}[
                    self.config.native_engine.architecture]):
            raise EnforcementUnavailable("native image reference is missing, rebound or has implicit work")
        return value[0]

    def _inspect_native(self, record):
        listing = self._run(self._docker(
            "container", "ls", "--all", "--no-trunc", "--filter", f"name=^/{record['payload']['name']}$",
            "--format", "{{.ID}}")).decode().split()
        if not listing:
            if record["driver"].get("container_id"):
                all_ids = self._run(self._docker("container", "ls", "--all", "--no-trunc", "--quiet")).decode().split()
                if record["driver"]["container_id"] in all_ids:
                    raise OutcomeUnknown("native container was renamed")
            return None
        if len(listing) != 1:
            raise OutcomeUnknown("native container lookup is ambiguous")
        inspection = json.loads(self._run(self._docker("container", "inspect", listing[0])))[0]
        labels = inspection.get("Config", {}).get("Labels", {})
        if (labels.get("appsec.native.execution") != record["execution_id"]
                or labels.get("appsec.native.token") != record["execution_token"]
                or labels.get("appsec.native.service") != record["binding"]["service_generation"]
                or inspection.get("Image") != record["payload"]["image_id"]
                or (record["driver"].get("container_id") is not None
                    and inspection["Id"] != record["driver"]["container_id"])):
            raise OutcomeUnknown("native container ownership or immutable image changed")
        if record["driver"].get("started_at") is not None and (
                inspection["State"].get("StartedAt") != record["driver"]["started_at"]):
            raise OutcomeUnknown("native container restarted")
        host, settings = inspection.get("HostConfig", {}), inspection.get("Config", {})
        network = self.config.network_id if record["payload"]["network"] == "isolated" else "none"
        expected_binds = {(m["source"], m["destination"], not m["read_only"])
                          for m in record["driver"]["mounts"]}
        actual_binds = {(m["Source"], m["Destination"], m["RW"])
                        for m in inspection.get("Mounts", []) if m.get("Type") == "bind"}
        expected_tmpfs = {m["destination"]: f"rw,nosuid,nodev,size={m['size_mb']}m" +
                          ("" if m["executable"] else ",noexec") for m in record["payload"]["tmpfs"]}
        fsize = record["payload"]["fsize_bytes"]
        observed_fsize = [item for item in host.get("Ulimits") or [] if item.get("Name") == "fsize"]
        if (host.get("Privileged") or host.get("Devices") or host.get("DeviceRequests")
                or host.get("CapAdd") or host.get("CapDrop") != ["ALL"]
                or not host.get("ReadonlyRootfs") or host.get("PidMode") not in {"", "private"}
                or host.get("IpcMode") != "private" or host.get("NetworkMode") != network
                or host.get("CgroupnsMode") != "private"
                or host.get("UTSMode") not in {"", "private"} or host.get("UsernsMode") not in {"", "private"}
                or host.get("Sysctls") or host.get("ExtraHosts") or host.get("Links")
                or host.get("PortBindings") or host.get("PublishAllPorts")
                or (host.get("Tmpfs") or {}) != expected_tmpfs
                or any(m.get("Propagation") not in {None, "", "rprivate"}
                       for m in inspection.get("Mounts", []) if m.get("Type") == "bind")
                or (fsize is not None and observed_fsize != [{"Name": "fsize", "Hard": fsize, "Soft": fsize}])
                or settings.get("User") != record["image_policy"]["user"] or settings.get("Tty")
                or settings.get("Entrypoint") != ["/run/appsec-gate/gate"]
                or settings.get("Cmd") not in (None, [])
                or settings.get("WorkingDir") != record["payload"]["workdir"]
                or actual_binds != expected_binds
                or any(m.get("Type") not in {"bind", "tmpfs"} for m in inspection.get("Mounts", []))
                or host.get("LogConfig", {}).get("Type") != "none"
                or set(host.get("SecurityOpt") or []) != {
                    "no-new-privileges:true", "seccomp=" + record["driver"]["seccomp"]}):
            raise EnforcementUnavailable("native isolation or mounts differ from approved policy")
        return inspection

    def _pin_mount(self, policy, relative, uid):
        root = Path(policy["source_root"])
        private_path(root, uid=0 if policy["kind"] == "platform" else uid)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parts = PurePosixPath(relative).parts if relative != "." else ()
            for index, part in enumerate(parts):
                child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY |
                                (os.O_DIRECTORY if index < len(parts) - 1 else 0), dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            value = os.fstat(descriptor)
            if not (stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode)):
                raise EnforcementUnavailable("native source is a socket or special file")
            if stat.S_ISREG(value.st_mode) and value.st_nlink != 1:
                raise EnforcementUnavailable("native file source has external hard links")
            return descriptor, [value.st_dev, value.st_ino]
        except BaseException:
            os.close(descriptor)
            raise

    def create(self, record, save):
        directory = Path(record["directory"])
        directory.mkdir(mode=0o700)
        self._begin(record)
        self.inventory()
        image = self.image(record["payload"]["image_id"])
        group = Path(self.config.native_engine.execution_cgroup_parent) / record["execution_id"]
        record["driver"].update(cgroup=str(group), cgroup_pending=True)
        save()
        group.mkdir()
        info = group.stat()
        record["driver"]["cgroup_identity"] = [info.st_dev, info.st_ino]
        requested = record["payload"]
        for name, value in {
            "cpu.max": f"{requested['cpu'] * 100000} 100000",
            "memory.max": str(requested["memory_mb"] * 1024**2), "memory.swap.max": "0",
            "pids.max": str(requested["pids"]), "cgroup.subtree_control": "+cpu +memory +pids",
        }.items():
            (group / name).write_text(value)
        self.proof.limits(group, requested["cpu"], requested["memory_mb"] * 1024**2)
        if (group / "pids.max").read_text().strip() != str(requested["pids"]):
            raise EnforcementUnavailable("native parent PID bound is not enforced")
        record["driver"]["cgroup_pending"] = False
        gate = directory / "gate"
        gate.mkdir(mode=0o755)
        shutil.copyfile(static_gate(self.config), gate / "gate")
        (gate / "gate").chmod(0o555)
        command = record["command_policy"]
        image_env = image.get("Config", {}).get("Env") or []
        if (not isinstance(image_env, list) or len(image_env) > 128 or any(
                not isinstance(value, str) or "=" not in value or "\x00" in value for value in image_env)):
            raise EnforcementUnavailable("native image environment is invalid")
        environment = dict(value.split("=", 1) for value in image_env)
        environment.update(requested["environment"])
        argv = [command["executable"], *requested["arguments"]]
        values = [*argv, *(f"{key}={value}" for key, value in environment.items())]
        launch = (struct.pack("<II", len(argv), len(environment)) + record["execution_token"].encode()
                  + b"".join(value.encode() + b"\0" for value in values))
        if len(environment) > 128 or len(launch) >= 65536:
            raise EnforcementUnavailable("native gate inputs exceed bounds")
        (gate / "launch.bin").write_bytes(launch)
        (gate / "launch.bin").chmod(0o444)
        seccomp = directory / "seccomp.json"
        atomic_json(seccomp, execution_seccomp(self.config.native_engine, command, requested["network"]))
        info = gate.stat()
        mounts = [{"source": str(gate), "destination": "/run/appsec-gate",
                   "read_only": True, "identity": [info.st_dev, info.st_ino]}]
        handles = self.handles.setdefault(record["execution_id"], [])
        for mount in record["mount_policies"]:
            descriptor, identity = self._pin_mount(mount, mount["relative_path"], record["peer"]["uid"])
            handles.append(descriptor)
            mounts.append({"source": f"/proc/{os.getpid()}/fd/{descriptor}", "destination": mount["destination"],
                           "read_only": mount["read_only"], "identity": identity})
        record["driver"].update(mounts=mounts, seccomp=str(seccomp), create_pending=True)
        save()
        argv = self._docker(
            "container", "create", "--pull=never", "--name", requested["name"],
            "--label", f"appsec.native.execution={record['execution_id']}",
            "--label", f"appsec.native.token={record['execution_token']}",
            "--label", f"appsec.native.service={record['binding']['service_generation']}",
            "--user", record["image_policy"]["user"], "--entrypoint", "/run/appsec-gate/gate",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
            "--security-opt", "seccomp=" + str(seccomp), "--network",
            self.config.network_id if requested["network"] == "isolated" else "none",
            "--pid", "private", "--ipc", "private", "--cgroupns", "private",
            "--cgroup-parent", str(group)[len("/sys/fs/cgroup/"):],
            "--cpus", str(requested["cpu"]), "--memory", f"{requested['memory_mb']}m",
            "--memory-swap", f"{requested['memory_mb']}m", "--pids-limit", str(requested["pids"]),
            "--log-driver", "none", "--workdir", requested["workdir"],
        )
        for mount in mounts:
            argv.extend(("--mount", f"type=bind,source={mount['source']},target={mount['destination']}" +
                         (",readonly" if mount["read_only"] else "")))
        for mount in requested["tmpfs"]:
            options = f"rw,nosuid,nodev,size={mount['size_mb']}m" + ("" if mount["executable"] else ",noexec")
            argv.extend(("--tmpfs", mount["destination"] + ":" + options))
        if requested["fsize_bytes"] is not None:
            argv.extend(("--ulimit", f"fsize={requested['fsize_bytes']}:{requested['fsize_bytes']}"))
        argv.append(requested["image_id"])
        cid = self._run(argv).decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise OutcomeUnknown("native create returned no immutable container ID")
        record["driver"]["container_id"] = cid
        self._inspect_native(record)
        record["driver"]["create_pending"] = False
        save()

    def _drain(self, record, save):
        capture = self.captures.get(record["execution_id"])
        if capture is None or "command" not in capture:
            raise OutcomeUnknown("native capture owner was lost")
        command = capture["command"]
        if command.finished:
            return
        for _ in range(16):
            ready = list((command.selector.get_map() or {}).values())
            ready_keys = {key.fd for key, _ in command.selector.select(0)}
            if not ready_keys:
                break
            for key in ready:
                if key.fd not in ready_keys:
                    continue
                data = os.read(key.fileobj.fileno(), 65536)
                stream = record["logs"][key.data]
                if not data:
                    command.selector.unregister(key.fileobj)
                    key.fileobj.close()
                    capture[key.data].flush()
                    os.fsync(capture[key.data].fileno())
                    stream["source_eof"] = True
                    continue
                stream["observed_bytes"] += len(data)
                kept = data[:max(0, CAPTURE_BYTES - stream["captured_bytes"])]
                capture[key.data].write(kept)
                capture[key.data].flush()
                stream["captured_bytes"] += len(kept)
                stream["truncated"] = stream["observed_bytes"] > stream["captured_bytes"]
        if not command.selector.get_map() and command.process.poll() is not None:
            command.finished = True
            command.selector.close()
            for name in ("stdout", "stderr"):
                capture[name].flush()
                os.fsync(capture[name].fileno())
                capture[name].close()
        save()

    def start(self, record, save):
        self._begin(record)
        self.inventory(record)
        self._inspect_native(record)
        record["driver"]["launch_pending"] = True
        record["logs"] = {name: {"captured_bytes": 0, "observed_bytes": 0,
                                "truncated": False, "source_eof": False} for name in ("stdout", "stderr")}
        save()
        capture = {}
        self.captures[record["execution_id"]] = capture
        for name in ("stdout", "stderr"):
            capture[name] = (Path(record["directory"]) / name).open("xb")
        command = self.runner.start(self._docker("container", "start", "--attach",
                                                 record["driver"]["container_id"]), capture_limit=0)
        capture["command"] = command
        record["driver"]["launcher"] = self.runner.launcher(command)
        record["driver"]["launch_pending"] = False
        save()
        while True:
            self._drain(record, save)
            inspection = self._inspect_native(record)
            if inspection is not None and inspection["State"].get("Running"):
                break
            if time.monotonic() >= self.deadline:
                raise OutcomeUnknown("native pre-execution gate did not become observable")
            time.sleep(0.01)
        record["driver"]["started_at"] = inspection["State"]["StartedAt"]
        record["enforcement"] = self.proof.execution(inspection, record)
        self._network(record if record["payload"]["network"] == "isolated" else None)
        record["driver"]["release_pending"] = True
        save()
        release = Path(record["directory"]) / "gate" / "release.token"
        pending = release.with_suffix(".pending")
        pending.write_text(record["execution_token"])
        pending.chmod(0o444)
        pending.replace(release)
        release.chmod(0o444)
        record["driver"].update(released=True, release_pending=False)
        save()

    def status(self, record, save):
        self._begin(record)
        self.inventory(record)
        self._drain(record, save)
        inspection = self._inspect_native(record)
        if inspection is None or not record["driver"].get("released") or not record.get("enforcement"):
            raise OutcomeUnknown("native execution result lacks its released, verified generation")
        if inspection["State"].get("Running"):
            self.proof.execution(inspection, record)
            self._network(record if record["payload"]["network"] == "isolated" else None)
            return {"state": "RUNNING"}
        if not self._empty_group(record):
            raise OutcomeUnknown("native process group is not independently stopped")
        code = inspection["State"].get("ExitCode")
        if type(code) is not int:
            raise OutcomeUnknown("native exit status is unavailable")
        return {"state": "EXITED", "exit_code": code}

    def _empty_group(self, record):
        if "cgroup" not in record["driver"]:
            return not any(record["driver"].get(key) for key in (
                "create_pending", "container_id", "launch_pending", "launcher"))
        group = Path(record["driver"]["cgroup"])
        try:
            info = group.stat()
        except FileNotFoundError:
            return not record["driver"].get("cgroup_pending")
        if [info.st_dev, info.st_ino] != record["driver"].get("cgroup_identity"):
            raise OutcomeUnknown("native cgroup generation changed")
        return dict(line.split() for line in (group / "cgroup.events").read_text().splitlines()).get("populated") == "0"

    def cancel(self, record, save):
        self._begin(record)
        self.check_host()
        inspection = self._inspect_native(record)
        if inspection is not None and inspection["State"].get("Running"):
            self._run(self._docker("container", "kill", "--signal", "KILL", inspection["Id"]))
        inspection = self._inspect_native(record)
        return (inspection is not None and not inspection["State"].get("Running")
                and self._empty_group(record))

    def remove(self, record, save):
        self._begin(record)
        self.check_host()
        inspection = self._inspect_native(record)
        if inspection is None and record["driver"].get("create_pending"):
            return False
        if inspection is not None:
            record["driver"].update(container_id=inspection["Id"], create_pending=False)
            save()
            self._run(self._docker("container", "rm", "--force", inspection["Id"]))
        if self._inspect_native(record) is not None or not self._empty_group(record):
            return False
        launcher = record["driver"].get("launcher")
        if record["driver"].get("launch_pending"):
            return False
        if launcher is not None:
            if record["execution_id"] in self.captures and "command" in self.captures[record["execution_id"]]:
                self._drain(record, save)
            token = process_token(launcher["pid"])
            if token not in {None, launcher["start_token"]} or not self.proof.stop_launcher(launcher, 5):
                return False
        capture = self.captures.pop(record["execution_id"], None)
        if capture:
            for name in ("stdout", "stderr"):
                if name in capture:
                    capture[name].close()
            command = capture.get("command")
            if command is not None and not command.finished:
                self.runner.stop(command)
        self.inventory()
        group = Path(record["driver"]["cgroup"]) if "cgroup" in record["driver"] else None
        if group is not None and group.exists():
            for child in group.iterdir():
                if child.is_dir():
                    if child.name != record["driver"].get("container_id"):
                        return False
                    child.rmdir()
            group.rmdir()
        for descriptor in self.handles.pop(record["execution_id"], []):
            os.close(descriptor)
        return True

    def logs(self, record, stream, offset, maximum, save):
        if record["execution_id"] in self.captures:
            self._drain(record, save)
        metadata = record.get("logs", {}).get(stream)
        if metadata is None:
            raise OutcomeUnknown("native logs were never captured")
        path = Path(record["directory"]) / stream
        private_path(path, directory=False)
        if path.stat().st_size != metadata["captured_bytes"]:
            raise OutcomeUnknown("native capture length differs from its durable counters")
        if offset > metadata["captured_bytes"]:
            raise ValueError("native log cursor exceeds captured bytes")
        with path.open("rb") as source:
            source.seek(offset)
            data = source.read(min(maximum, metadata["captured_bytes"] - offset))
        source_eof = metadata["source_eof"]
        return {
            "stream": stream, "offset": offset, "next_offset": offset + len(data),
            "data_b64": base64.b64encode(data).decode(), **{key: metadata[key] for key in (
                "captured_bytes", "observed_bytes", "truncated")},
            "total_bytes": metadata["observed_bytes"] if source_eof else None,
            "eof": source_eof and offset + len(data) == metadata["captured_bytes"],
            "complete": source_eof and not metadata["truncated"],
        }


class EngineBroker:
    def __init__(self, builder_service, *, driver=None, clock=time.monotonic, alive=process_token):
        self.builder = builder_service
        self.config, self.store, self.admission = (
            builder_service.config, builder_service.store, builder_service.admission)
        if self.config.native_engine is None:
            raise ValueError("native engine policy is not configured")
        self.native = self.config.native_engine
        self.contract = service_contract(self.config)
        self.interlock = EngineInterlock(self.store, self.contract)
        self.driver = driver or NativeExecutionDriver(self.config)
        self.clock, self.alive = clock, alive
        self.process = {"pid": os.getpid(), "start_token": process_token(os.getpid())}

    def records(self):
        return [json.loads(row[0]) for row in self.store.connection.execute("SELECT record FROM engine_executions")]

    def get(self, key):
        row = self.store.connection.execute("SELECT record FROM engine_executions WHERE id=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def save(self, record):
        with self.store.connection:
            self.store.connection.execute(
                "INSERT INTO engine_executions VALUES (?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record",
                (record["execution_id"], encoded(record).decode()))

    def _owner(self, record):
        return self.interlock.identity("execution", record["execution_id"], record["execution_token"])

    def claim_builder(self, record):
        owner = self.interlock.identity("builder", record["binding"]["build_id"], record["worker"]["start_token"])
        with self.store.connection:
            self.interlock.claim(owner)
            self.store.connection.execute(
                "INSERT INTO builds VALUES (?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record",
                (record["binding"]["build_id"], encoded(record).decode()))

    def release_builder(self, record):
        owner = self.interlock.identity("builder", record["binding"]["build_id"], record["worker"]["start_token"])
        if self.interlock.owner() != owner:
            return
        if record.get("state") != "CLEANED" or record.get("service_contract") != self.contract:
            raise OutcomeUnknown("builder engine reservation is not confirmed cleaned")
        self.driver.inventory()
        with self.store.connection:
            self.interlock.release(owner)

    def _grant(self, binding, peer):
        if (any(not isinstance(value, str) or len(value) > 200 for value in binding.values())
                or not uuid(binding["lease_id"]) or peer.uid != self.config.admission.uid
                or peer.gid != self.config.admission.gid or self.alive(peer.pid) != peer.start_token
                or any(binding[name] != getattr(self.native, name) for name in (
                    "service_generation", "engine_id", "engine_generation"))):
            raise PermissionError("native peer, engine or service generation is not authorized")
        matches = [grant for grant in self.native.grants if grant.uid == peer.uid and all(
            binding[name] == getattr(grant, name) for name in (
                "tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id"))]
        if len(matches) != 1:
            raise PermissionError("native run/configuration grant is not exact")
        return matches[0]

    def _outputs(self, grant):
        builder_grant = next(item for item in self.config.grants if (
            item.uid, item.tenant_id, item.project_id, item.run_id, item.target_snapshot
        ) == (grant.uid, grant.tenant_id, grant.project_id, grant.run_id, grant.target_snapshot))
        allowed = self.builder._prior_output_ids(builder_grant)
        return {record["execution"]["image_id"]: record for record in self.builder.store.records()
                if record.get("execution", {}).get("image_id") in allowed
                and record.get("grant") == asdict(builder_grant)}

    def _image_policies(self, image_id, grant):
        outputs = self._outputs(grant)
        ancestry, pending = set(), [image_id]
        for _ in range(self.native.max_records):
            if not pending:
                break
            current = pending.pop()
            if current in ancestry:
                continue
            ancestry.add(current)
            if current in outputs:
                pending.extend(outputs[current]["start"]["authorized_inputs"].values())
        if pending:
            raise EnforcementUnavailable("native image ancestry exceeds its bound")
        return [image for image in self.native.images if image.image_id in grant.image_ids and (
            image.image_id == image_id or (
                image.allow_derived and image_id in outputs and image.image_id in ancestry))]

    def _reference(self, reference, grant):
        if not isinstance(reference, str) or not 1 <= len(reference) <= 200:
            raise ValueError("invalid native image reference")
        matches = {image.image_id for image in self.native.images if image.image_id in grant.image_ids
                   and reference in (image.image_id, *image.aliases)}
        for image_id, record in self._outputs(grant).items():
            if reference in {image_id, record["binding"]["output_tag"]} and self._image_policies(image_id, grant):
                matches.add(image_id)
        if len(matches) != 1:
            raise PermissionError("native image reference is absent or ambiguous in operator policy")
        return matches.pop()

    def _create_policy(self, payload, grant):
        if (not uuid(payload["execution_id"]) or not isinstance(payload["name"], str)
                or not re.fullmatch(r"(appsec-[0-9a-f]{20}|appsec-review-[a-zA-Z0-9_-]{1,120})", payload["name"])
                or not isinstance(payload["image_id"], str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", payload["image_id"])
                or (payload["executable"] is not None and not isinstance(payload["executable"], str))
                or not isinstance(payload["arguments"], list) or len(payload["arguments"]) > 48
                or any(not isinstance(arg, str) or "\x00" in arg or len(arg.encode()) > 4096
                       for arg in payload["arguments"])
                or sum(len(arg.encode()) for arg in payload["arguments"]) > 16384):
            raise ValueError("native execution identity or argument bound is invalid")
        for key in ("cpu", "memory_mb", "pids"):
            if type(payload[key]) is not int or not 1 <= payload[key] <= getattr(self.native, key):
                raise PermissionError("native requested resource exceeds operator envelope")
        absolute(payload["workdir"])
        if not isinstance(payload["network"], str) or payload["network"] not in {"none", "isolated"}:
            raise PermissionError("native network must be none or operator-isolated egress")
        env = payload["environment"]
        if (not isinstance(env, dict) or len(env) > 32 or any(
                not isinstance(key, str) or not isinstance(value, str) or "\x00" in value
                or len(value.encode()) > 4096 for key, value in env.items())
                or sum(len(value.encode()) for value in env.values()) > 16384):
            raise ValueError("native environment is unbounded")
        candidates = []
        for image in self._image_policies(payload["image_id"], grant):
            for command in self.native.commands:
                if command.command_id not in image.command_ids:
                    continue
                prefix = list(command.prefix)
                args = payload["arguments"]
                if (payload["executable"] not in {None, command.executable} or args[:len(prefix)] != prefix
                        or len(args) != len(prefix) + len(command.arguments)
                        or not all(rule.accepts(arg) for rule, arg in zip(command.arguments, args[len(prefix):]))
                        or set(env) - set(command.environment_keys)
                        or not any(PurePosixPath(payload["workdir"]).is_relative_to(root)
                                   for root in command.workdir_roots)
                        or (payload["network"] == "isolated" and not image.allow_isolated_network)):
                    continue
                candidates.append((image, command))
        if len(candidates) != 1:
            raise PermissionError("native executable/arguments/image do not select one operator command")
        if not isinstance(payload["mounts"], list) or len(payload["mounts"]) > 16:
            raise ValueError("native mounts exceed their bound")
        mounts = []
        for value in payload["mounts"]:
            if (not isinstance(value, dict) or set(value) != {"mount_id", "relative_path"}
                    or value["mount_id"] not in grant.mount_ids or not isinstance(value["relative_path"], str)):
                raise PermissionError("native mount is not granted")
            relative = value["relative_path"]
            path = PurePosixPath(relative)
            if (not relative or len(relative) > 1024 or "\x00" in relative or path.is_absolute()
                    or ".." in path.parts or str(path) != relative):
                raise PermissionError("native mount subpath is not normalized")
            policy = next(m for m in self.native.mounts if m.mount_id == value["mount_id"])
            mounts.append({**asdict(policy), "relative_path": relative})
        if not isinstance(payload["tmpfs"], list) or len(payload["tmpfs"]) > 8:
            raise ValueError("native tmpfs mounts exceed bound")
        destinations = [mount["destination"] for mount in mounts]
        for value in payload["tmpfs"]:
            if not isinstance(value, dict) or set(value) != {"destination", "size_mb", "executable"}:
                raise ValueError("invalid native tmpfs fields")
            policies = [p for p in self.native.tmpfs if p.destination == value["destination"]]
            if (len(policies) != 1 or type(value["size_mb"]) is not int
                    or not 1 <= value["size_mb"] <= policies[0].max_size_mb
                    or type(value["executable"]) is not bool
                    or (value["executable"] and not policies[0].allow_exec)):
                raise PermissionError("native tmpfs execution or size is not authorized")
            destinations.append(value["destination"])
        if sum(m["size_mb"] for m in payload["tmpfs"]) > payload["memory_mb"]:
            raise PermissionError("native tmpfs exceeds its memory reservation")
        if len(destinations) != len(set(destinations)):
            raise PermissionError("native mount destinations repeat")
        # Nested binds are permitted only where both exact destinations are operator-declared.
        # Tmpfs may never hide a bind or a nested operator mount.
        if any(PurePosixPath(tmp["destination"]).is_relative_to(mount["destination"])
               or PurePosixPath(mount["destination"]).is_relative_to(tmp["destination"])
               for tmp in payload["tmpfs"] for mount in mounts):
            raise PermissionError("native tmpfs overlaps an operator mount")
        limit = payload["fsize_bytes"]
        if limit is not None and (type(limit) is not int or not 1 <= limit <= self.native.max_fsize_bytes):
            raise PermissionError("native file-size limit exceeds policy")
        return candidates[0], mounts

    def _result(self, record):
        result = {
            "execution_id": record["execution_id"], "execution_token": record["execution_token"],
            "name": record["payload"]["name"], "container_id": record["driver"].get("container_id"),
            "state": record["state"], "enforcement": record.get("enforcement"),
        }
        if record.get("exit_code") is not None:
            result["exit_code"] = record["exit_code"]
        if record.get("quarantine"):
            result["quarantine"] = record["quarantine"]
        return result

    def dispatch(self, data, peer):
        request = decode_request(data)
        binding, payload, action = request["binding"], request["payload"], request["action"]
        grant = self._grant(binding, peer)
        if action != "image.inspect" and not uuid(payload["execution_id"]):
            raise ValueError("invalid native execution UUID")
        record = None if action == "image.inspect" else self.get(payload["execution_id"])
        if record is not None:
            if (record["binding"] != binding or record["peer"] != asdict(peer)
                    or record["service_contract"] != self.contract):
                raise PermissionError("native execution belongs to another lease, peer or generation")
            if action == "execution.create":
                if record["payload"] != payload:
                    raise ValueError("native create replay changed immutable inputs")
            elif payload["execution_token"] != record["execution_token"]:
                raise PermissionError("native execution token changed")
        elif action not in {"image.inspect", "execution.create"}:
            raise ValueError("native execution intent is missing")
        if action == "execution.wait" and (
                type(payload["timeout_seconds"]) is not int or not 1 <= payload["timeout_seconds"] <= 5):
            raise ValueError("native wait is bounded to five seconds per request")
        if action == "execution.logs" and (
                not isinstance(payload["stream"], str) or payload["stream"] not in {"stdout", "stderr"}
                or type(payload["offset"]) is not int or not 0 <= payload["offset"] <= CAPTURE_BYTES
                or type(payload["max_bytes"]) is not int or not 1 <= payload["max_bytes"] <= MAX_LOG_PAGE):
            raise ValueError("invalid native log cursor or page size")
        actual = record["payload"] if record is not None else payload
        name = actual.get("name") if action != "image.inspect" else None
        self.admission.verify()
        self.admission.verify_native_execution(
            binding, asdict(peer), name=name, cpu=actual.get("cpu", 1), memory_mb=actual.get("memory_mb", 1),
            allow_quarantine=action in {"execution.cancel", "execution.remove"})
        self.driver.check_host()
        owner = encoded(asdict(peer)).decode()
        previous = self.store.connection.execute(
            "SELECT owner,request,response FROM engine_requests WHERE nonce=?", (request["request_id"],)).fetchone()
        if previous is not None:
            if previous[:2] != (owner, encoded(request).decode()):
                raise ValueError("native nonce was rebound")
            if record is not None and record["state"] == "UNKNOWN":
                return self._reply(request, self._result(record))
            if record is not None and (record["state"] == "REMOVED" or record.get("quarantine")):
                return self._reply(request, self._result(record))
            if previous[2] is None:
                raise OutcomeUnknown("native request intent has no confirmed response")
            return previous[2].encode()
        count = self.store.connection.execute("SELECT COUNT(*) FROM engine_requests").fetchone()[0]
        cleanup = action in {"execution.cancel", "execution.remove"}
        extra = 2 if cleanup else 0
        if count >= self.native.max_records * (self.native.max_requests_per_execution + extra):
            raise EnforcementUnavailable("native request journal requires stopped operator rotation")
        if cleanup and action in record.get("cleanup_requests", {}):
            raise EnforcementUnavailable("native cleanup retry requires its original request nonce")
        if (not cleanup and record is not None
                and record.get("request_count", 0) >= self.native.max_requests_per_execution):
            raise EnforcementUnavailable("native execution message bound exhausted")
        if action == "execution.create" and record is None:
            (image, command), mounts = self._create_policy(payload, grant)
            if len(self.records()) >= self.native.max_records:
                raise EnforcementUnavailable("native execution journal is full")
            if any(item["payload"]["name"] == payload["name"] for item in self.records()):
                raise PermissionError("native container names cannot be reused across execution generations")
            record = {
                "execution_id": payload["execution_id"], "execution_token": uuid4().hex,
                "binding": binding, "peer": asdict(peer), "broker_process": self.process,
                "service_contract": self.contract, "payload": payload,
                "image_policy": asdict(image), "command_policy": asdict(command), "mount_policies": mounts,
                "state": "CREATING", "driver": {}, "created_at": self.clock(), "last_seen": self.clock(),
                "directory": str(Path(self.config.state_root) / ("native-" + payload["execution_id"])),
            }
            with self.store.connection:
                self.interlock.claim(self._owner(record))
                self.store.connection.execute("INSERT INTO engine_executions VALUES (?,?)",
                                              (record["execution_id"], encoded(record).decode()))
        if record is not None:
            record["last_seen"] = self.clock()
            if cleanup:
                record.setdefault("cleanup_requests", {})[action] = request["request_id"]
            else:
                record["request_count"] = record.get("request_count", 0) + 1
        with self.store.connection:
            self.store.connection.execute("INSERT INTO engine_requests VALUES (?,?,?,NULL)",
                                          (request["request_id"], owner, encoded(request).decode()))
            if record is not None:
                self.store.connection.execute("UPDATE engine_executions SET record=? WHERE id=?",
                                              (encoded(record).decode(), record["execution_id"]))
        try:
            if action == "image.inspect":
                if self.interlock.owner() is not None:
                    raise EnforcementUnavailable("image inspection is blocked by retained engine ownership")
                image_id = self._reference(payload["reference"], grant)
                self.driver.image(image_id, payload["reference"])
                result = {"state": "PRESENT", "image_id": image_id}
            else:
                if record["state"] != "REMOVED" and self.interlock.owner() != self._owner(record):
                    raise OutcomeUnknown("native engine interlock was replaced")
                save = lambda: self.save(record)
                if action == "execution.create" and record["state"] == "CREATING":
                    if record.get("create_dispatched"):
                        raise OutcomeUnknown("native create dispatch is unresolved")
                    record["create_dispatched"] = True
                    save()
                    self.driver.create(record, save)
                    record["state"] = "CREATED"
                elif action == "execution.start" and record["state"] == "CREATED":
                    record["state"] = "STARTING"
                    save()
                    self.driver.start(record, save)
                    record["state"] = "RUNNING"
                elif action in {"execution.status", "execution.wait"} and record["state"] in {"RUNNING", "EXITED"}:
                    deadline = self.clock() + (payload["timeout_seconds"] if action == "execution.wait" else 0)
                    while True:
                        record.update(self.driver.status(record, save))
                        if record["state"] != "RUNNING" or self.clock() >= deadline:
                            break
                        time.sleep(0.01)
                elif action == "execution.cancel" and record["state"] != "REMOVED":
                    record["state"] = "CANCELLING"
                    save()
                    if not self.driver.cancel(record, save):
                        raise OutcomeUnknown("native cancellation is not independently confirmed")
                    record["state"] = "STOPPED"
                elif action == "execution.remove" and record["state"] != "REMOVED":
                    self._remove(record)
                result = self._result(record)
                if action == "execution.logs":
                    result.update(self.driver.logs(
                        record, payload["stream"], payload["offset"], payload["max_bytes"], save))
                if action == "execution.wait":
                    result["wait_expired"] = record["state"] == "RUNNING"
                save()
        except (OSError, ValueError, RuntimeError) as exc:
            if record is None:
                raise
            record.update(state="REMOVED" if record["state"] == "REMOVED" else "UNKNOWN",
                          quarantine="native_operation_unconfirmed",
                          error_type=type(exc).__name__[:64])
            self.save(record)
            result = self._result(record)
        reply = self._reply(request, result)
        with self.store.connection:
            self.store.connection.execute("UPDATE engine_requests SET response=? WHERE nonce=?",
                                          (reply.decode(), request["request_id"]))
        return reply

    def _reply(self, request, result):
        response = encoded({
            "schema": SCHEMA, "request_id": request["request_id"], "action": request["action"],
            "binding": request["binding"], "result": {
                **result, "resource_budget": self.config.resources.view(), "broker_process": self.process,
            },
        })
        if len(response) > MAX_RESPONSE_BYTES:
            raise ValueError("native response exceeds bound")
        return response

    def _remove(self, record):
        record["state"] = "REMOVING"
        self.save(record)
        if not self.driver.remove(record, lambda: self.save(record)):
            raise OutcomeUnknown("native removal is not independently confirmed")
        record["state"] = "REMOVED"
        if record.get("quarantine"):
            record["resolved_quarantine"] = record.pop("quarantine")
        record["removal"] = {
            "confirmed_removed": True, "binding": record["binding"], "peer": record["peer"],
            "execution_id": record["execution_id"], "execution_token": record["execution_token"],
            "name": record["payload"]["name"], "service_contract": self.contract,
        }
        with self.store.connection:
            self.store.connection.execute("UPDATE engine_executions SET record=? WHERE id=?",
                                          (encoded(record).decode(), record["execution_id"]))
            self.interlock.release(self._owner(record))

    def reconcile(self, *, restart=False):
        for record in self.records():
            if record["state"] == "REMOVED":
                continue
            expired = (self.clock() - record["last_seen"] >= self.native.owner_idle_seconds
                       or self.clock() - record["created_at"] >= self.native.max_execution_seconds)
            dead = self.alive(record["peer"]["pid"]) != record["peer"]["start_token"]
            try:
                if record["service_contract"] != self.contract:
                    raise OutcomeUnknown("native recovery requires the original service contract")
                if self.interlock.owner() != self._owner(record):
                    raise OutcomeUnknown("native recovery interlock generation changed")
                if restart or expired or dead or record.get("quarantine"):
                    record["quarantine"] = record.get("quarantine", "native_owner_or_deadline_lost")
                    self.save(record)
                    self._remove(record)
                elif record["state"] in {"RUNNING", "EXITED"}:
                    record.update(self.driver.status(record, lambda: self.save(record)))
                    self.save(record)
            except (OSError, ValueError, RuntimeError) as exc:
                record.update(state="UNKNOWN", quarantine="native_operation_unconfirmed",
                              error_type=type(exc).__name__[:64])
                self.save(record)

    def disconnected(self, request):
        if request is None or request["action"] == "image.inspect":
            return
        record = self.get(request["payload"].get("execution_id"))
        if record is not None and record["state"] != "REMOVED":
            record.update(state="UNKNOWN", quarantine="native_response_lost")
            self.save(record)


def _operator_records(config):
    path = Path(config.state_root) / "intents.sqlite3"
    private_path(path, directory=False)
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        rows = connection.execute("SELECT record FROM engine_executions").fetchmany(config.native_engine.max_records + 1)
        if len(rows) > config.native_engine.max_records or any(len(row[0]) > MAX_RESPONSE_BYTES for row in rows):
            raise EnforcementUnavailable("native operator journal exceeds bounds")
        return [json.loads(row[0]) for row in rows], connection.execute("SELECT COUNT(*) FROM engine_interlock").fetchone()[0]
    finally:
        connection.close()


class EngineCleanupConfirmation:
    """Construct as operator; use all three callbacks together for native-only reconciliation."""
    def __init__(self, config, *, retired=False):
        self.config, self.contract = config, service_contract(config)
        self.records = {}
        records, owners = _operator_records(config)
        self.known_names = {record["payload"]["name"] for record in records}
        self.retired_empty = False
        for record in records:
            expected = {
                "confirmed_removed": True, "binding": record["binding"], "peer": record["peer"],
                "execution_id": record["execution_id"], "execution_token": record["execution_token"],
                "name": record["payload"]["name"], "service_contract": self.contract,
            }
            if (record.get("state") == "REMOVED" and record.get("removal") == expected
                    and record.get("service_contract") == self.contract
                    and all(record["binding"].get(key) == getattr(config.native_engine, key)
                            for key in ("service_generation", "engine_id", "engine_generation"))
                    and record["peer"]["uid"] == config.admission.uid
                    and record["peer"]["gid"] == config.admission.gid):
                self.records[record["payload"]["name"]] = record
        if (retired and config.docker_helper_scope is not None and not owners
                and len(self.records) == len(records)):
            # The caller has proved a RELEASED lifetime, empty cgroups, dead
            # generations and no daemon listener. Stopped containers still count.
            containers = Path(config.docker_helper_scope.data_root) / "containers"
            private_path(containers)
            self.retired_empty = next(containers.iterdir(), None) is None

    def lease_matches(self, entry):
        names = entry.get("containers", [])
        if not names or entry.get("builds") or entry.get("container_cleanup") != "removed":
            return False
        return all(name in self.records and entry.get("native_engine_scope") == {
            **self.records[name]["binding"], "resource_budget": self.config.resources.view(),
        } and entry.get("pid") == self.records[name]["peer"]["pid"]
            and entry.get("process_identity") == self.records[name]["peer"]["start_token"]
            for name in names) or self._absent_lease(entry)

    def _absent_name(self, name):
        return (self.retired_empty and isinstance(name, str) and name not in self.known_names
                and re.fullmatch(r"(appsec-[0-9a-f]{20}|appsec-review-[a-zA-Z0-9_-]{1,120})", name)
                is not None)

    def _absent_lease(self, entry):
        scope = entry.get("native_engine_scope")
        if (not self.retired_empty or "persistent" in entry
                or type(entry.get("pid")) is not int or entry["pid"] <= 0
                or not isinstance(entry.get("process_identity"), str) or not entry["process_identity"]
                or process_token(entry["pid"]) == entry["process_identity"]
                or not isinstance(scope, dict) or set(scope) != BINDING_FIELDS | {"resource_budget"}
                or not uuid(scope.get("lease_id"))
                or scope["resource_budget"] != self.config.resources.view()
                or entry.get("limits") != {key: getattr(self.config.resources, key)
                                           for key in ("cpu", "memory_mb", "io_slots")}
                or any(scope.get(key) != getattr(self.config.native_engine, key)
                       for key in ("service_generation", "engine_id", "engine_generation"))):
            return False
        grants = [grant for grant in self.config.native_engine.grants
                  if grant.uid == self.config.admission.uid and all(
                      scope[key] == getattr(grant, key) for key in (
                          "tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id"))]
        return len(grants) == 1 and all(self._absent_name(name) for name in entry["containers"])

    def confirmed_removed(self, name):
        return name in self.records or self._absent_name(name)

    def confirmed_cleanup(self, entry):
        return (entry.get("quarantine") in {None, "native_engine_removal_unconfirmed", "container_death_unconfirmed"}
                and self.lease_matches(entry))


def assert_engine_retired(config):
    records, owners = _operator_records(config)
    confirmation = EngineCleanupConfirmation(config)
    if owners or len(confirmation.records) != len(records):
        raise EnforcementUnavailable("native engine intents or ownership remain unresolved")


def main():
    import sys
    if sys.argv[1:] == ["--gate-source"]:
        print(GATE_SOURCE)
        return
    from appsec_review.container_runtime.image_builder_service import main as serve_builder
    serve_builder()


if __name__ == "__main__":
    main()
