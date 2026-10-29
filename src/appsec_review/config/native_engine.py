"""Operator policy for the restricted native engine broker, never Docker CLI forwarding."""
from dataclasses import dataclass, fields
from pathlib import PurePosixPath
import re


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,199}", value):
        raise ValueError("invalid native policy identifier")


def absolute(value):
    if (not isinstance(value, str) or not value.startswith("/") or "\x00" in value
            or str(PurePosixPath(value)) != value or ".." in PurePosixPath(value).parts):
        raise ValueError("native paths must be canonical absolute paths")


def bounded(value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("native bound is outside its authorized envelope")


def identifiers(values):
    if not isinstance(values, tuple) or len(values) > 128 or len(values) != len(set(values)):
        raise ValueError("native policy references must be unique tuples")
    for value in values:
        identifier(value)


@dataclass(frozen=True)
class NativeArgument:
    kind: str
    max_bytes: int = 1024
    values: tuple[str, ...] = ()

    def __post_init__(self):
        if self.kind not in {"text", "identifier", "integer", "path", "literal"}:
            raise ValueError("unsupported native argument kind")
        bounded(self.max_bytes, 4096)
        if not isinstance(self.values, tuple) or len(self.values) > 64:
            raise ValueError("invalid native argument alternatives")
        if self.kind == "literal" and not self.values:
            raise ValueError("literal arguments require operator alternatives")
        for value in self.values:
            if not isinstance(value, str) or "\x00" in value or len(value.encode()) > self.max_bytes:
                raise ValueError("invalid native argument alternative")

    def accepts(self, value):
        if not isinstance(value, str) or "\x00" in value or len(value.encode()) > self.max_bytes:
            return False
        if self.values and value not in self.values:
            return False
        if self.kind == "identifier":
            return re.fullmatch(r"[A-Za-z0-9_./:@,+-]{1,1024}", value) is not None
        if self.kind == "integer":
            return re.fullmatch(r"[0-9]{1,20}", value) is not None
        if self.kind == "path":
            try:
                absolute(value)
            except ValueError:
                return False
        return True


@dataclass(frozen=True)
class NativeCommand:
    command_id: str
    executable: str
    prefix: tuple[str, ...] = ()
    arguments: tuple[NativeArgument, ...] = ()
    environment_keys: tuple[str, ...] = ()
    workdir_roots: tuple[str, ...] = ("/scratch",)

    def __post_init__(self):
        identifier(self.command_id)
        absolute(self.executable)
        if (not isinstance(self.prefix, tuple) or len(self.prefix) > 16
                or any(not isinstance(value, str) or "\x00" in value or len(value.encode()) > 1024
                       for value in self.prefix)
                or not isinstance(self.arguments, tuple) or len(self.arguments) > 32
                or any(not isinstance(value, NativeArgument) for value in self.arguments)):
            raise ValueError("invalid fixed command or bounded argument policy")
        identifiers(self.environment_keys)
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) for value in self.environment_keys):
            raise ValueError("invalid environment key")
        if not isinstance(self.workdir_roots, tuple) or not self.workdir_roots:
            raise ValueError("working directories require operator roots")
        for root in self.workdir_roots:
            absolute(root)


@dataclass(frozen=True)
class NativeImage:
    image_id: str
    release_id: str
    user: str
    command_ids: tuple[str, ...]
    allow_isolated_network: bool = False
    aliases: tuple[str, ...] = ()
    allow_derived: bool = False

    def __post_init__(self):
        if not isinstance(self.image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
            raise ValueError("native images require pre-provisioned immutable IDs")
        identifier(self.release_id)
        if not isinstance(self.user, str) or not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", self.user):
            raise ValueError("native images require a fixed non-root UID:GID")
        identifiers(self.command_ids)
        identifiers(self.aliases)
        if (not self.command_ids or type(self.allow_isolated_network) is not bool
                or type(self.allow_derived) is not bool):
            raise ValueError("native image commands/network require explicit policy")


@dataclass(frozen=True)
class NativeMount:
    mount_id: str
    source_root: str
    destination: str
    kind: str
    read_only: bool = True

    def __post_init__(self):
        identifier(self.mount_id)
        absolute(self.source_root)
        absolute(self.destination)
        if self.kind not in {"target", "run", "platform"} or type(self.read_only) is not bool:
            raise ValueError("invalid native mount policy")
        if self.kind != "run" and not self.read_only:
            raise ValueError("target and platform mounts must remain read-only")
        if self.destination == "/" or any(
                PurePosixPath(self.destination).is_relative_to(root)
                for root in ("/proc", "/sys", "/dev", "/run", "/var/run", "/etc")):
            raise ValueError("native mount overlaps control or host namespace paths")


@dataclass(frozen=True)
class NativeTmpfs:
    destination: str
    max_size_mb: int = 64
    allow_exec: bool = False

    def __post_init__(self):
        absolute(self.destination)
        bounded(self.max_size_mb, 4096)
        if type(self.allow_exec) is not bool:
            raise ValueError("tmpfs execution needs explicit operator permission")
        if self.destination == "/" or any(PurePosixPath(self.destination).is_relative_to(root)
                for root in ("/proc", "/sys", "/dev", "/run/appsec-gate", "/etc")):
            raise ValueError("tmpfs overlaps native control paths")


@dataclass(frozen=True)
class NativeGrant:
    uid: int
    tenant_id: str
    project_id: str
    run_id: str
    target_snapshot: str
    configuration_id: str
    run_root: str
    target_root: str
    image_ids: tuple[str, ...]
    mount_ids: tuple[str, ...] = ()

    def __post_init__(self):
        bounded(self.uid, 2**31 - 1)
        for name in ("tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id"):
            identifier(getattr(self, name))
        absolute(self.run_root)
        absolute(self.target_root)
        identifiers(self.image_ids)
        identifiers(self.mount_ids)
        if not self.image_ids or PurePosixPath(self.run_root).name != self.run_id:
            raise ValueError("native grant requires exact run and image authorization")


@dataclass(frozen=True)
class NativeEngineConfig:
    endpoint: str
    service_generation: str
    engine_id: str
    engine_generation: str
    execution_cgroup_parent: str
    gate_binary: str
    gate_release_id: str
    runtime_python: str
    runtime_root: str
    runtime_release_id: str
    syscall_allowlist: tuple[str, ...]
    images: tuple[NativeImage, ...]
    commands: tuple[NativeCommand, ...]
    grants: tuple[NativeGrant, ...]
    client_contract_root: str | None = None
    mounts: tuple[NativeMount, ...] = ()
    tmpfs: tuple[NativeTmpfs, ...] = ()
    architecture: str = "x86_64"
    cpu: int = 8
    memory_mb: int = 9216
    pids: int = 2048
    max_execution_seconds: int = 3600
    owner_idle_seconds: int = 120
    max_records: int = 256
    max_requests_per_execution: int = 1024
    max_fsize_bytes: int = 1024 * 1024 * 1024
    application_cgroup: str | None = None
    application_cpu: int = 4
    application_memory_mb: int = 5120

    def __post_init__(self):
        absolute(self.endpoint)
        absolute(self.execution_cgroup_parent)
        absolute(self.gate_binary)
        identifier(self.gate_release_id)
        absolute(self.runtime_python)
        absolute(self.runtime_root)
        if self.client_contract_root is not None:
            absolute(self.client_contract_root)
        if self.application_cgroup is not None:
            absolute(self.application_cgroup)
            if not self.application_cgroup.startswith("/sys/fs/cgroup/"):
                raise ValueError("native application requires a canonical cgroup-v2 parent")
        identifier(self.runtime_release_id)
        if not self.execution_cgroup_parent.startswith("/sys/fs/cgroup/"):
            raise ValueError("native executions require a canonical cgroup-v2 parent")
        if not isinstance(self.service_generation, str) or not re.fullmatch(r"[0-9a-f]{32}", self.service_generation):
            raise ValueError("native broker requires an operator generation UUID")
        identifier(self.engine_id)
        identifier(self.engine_generation)
        if self.architecture not in {"x86_64", "aarch64"}:
            raise ValueError("native seccomp architecture is unsupported")
        for name, maximum in (("cpu", 8), ("memory_mb", 9216), ("pids", 65536),
                              ("max_execution_seconds", 86400), ("owner_idle_seconds", 3600),
                              ("max_records", 256), ("max_requests_per_execution", 1024),
                              ("application_cpu", 4), ("application_memory_mb", 5120),
                              ("max_fsize_bytes", 4 * 1024**3)):
            bounded(getattr(self, name), maximum)
        identifiers(self.syscall_allowlist)
        forbidden = {
            "socket", "socketcall", "clone3", "ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd",
            "mount", "umount2", "pivot_root", "setns", "unshare", "bpf", "perf_event_open",
            "open_by_handle_at", "init_module", "finit_module", "delete_module", "kexec_load",
            "kexec_file_load", "keyctl", "add_key", "request_key", "userfaultfd", "io_uring_setup",
        }
        if not self.syscall_allowlist or set(self.syscall_allowlist) & forbidden:
            raise ValueError("native syscall allowlist cannot bypass isolation or expose host Unix sockets")
        for name, cls, key in (
                ("images", NativeImage, "image_id"), ("commands", NativeCommand, "command_id"),
                ("mounts", NativeMount, "mount_id"), ("tmpfs", NativeTmpfs, "destination")):
            items = getattr(self, name)
            if (not isinstance(items, tuple) or any(not isinstance(item, cls) for item in items)
                    or len(items) > 128 or len({getattr(item, key) for item in items}) != len(items)):
                raise ValueError("native policies must be bounded typed unique declarations")
        if not isinstance(self.grants, tuple) or not self.grants or any(
                not isinstance(grant, NativeGrant) for grant in self.grants):
            raise ValueError("native engine requires typed grants")
        if len(self.grants) > 128 or len({
                (g.uid, g.tenant_id, g.project_id, g.run_id, g.configuration_id) for g in self.grants
        }) != len(self.grants):
            raise ValueError("native grants are excessive or ambiguous")
        image_ids, command_ids = {i.image_id for i in self.images}, {c.command_id for c in self.commands}
        mount_ids = {m.mount_id for m in self.mounts}
        if any(set(i.command_ids) - command_ids for i in self.images) or any(
                set(g.image_ids) - image_ids or set(g.mount_ids) - mount_ids for g in self.grants):
            raise ValueError("native policy contains unknown image/command/mount references")
        for grant in self.grants:
            if self.client_contract_root is not None and any(
                    PurePosixPath(self.client_contract_root).is_relative_to(root)
                    for root in (grant.run_root, grant.target_root)):
                raise ValueError("native client contract publication must be outside worker custody")
            for mount in self.mounts:
                if mount.mount_id not in grant.mount_ids:
                    continue
                root = {"target": grant.target_root, "run": grant.run_root}.get(mount.kind)
                if root is not None and not PurePosixPath(mount.source_root).is_relative_to(root):
                    raise ValueError("native mount escapes its run or target grant")


def parse_native_engine(value):
    def typed(cls, document):
        if not isinstance(document, dict) or set(document) - {field.name for field in fields(cls)}:
            raise ValueError("unknown native policy settings")
        converted = dict(document)
        for key, item in converted.items():
            if isinstance(item, list):
                converted[key] = tuple(item)
        try:
            return cls(**converted)
        except TypeError as exc:
            raise ValueError("missing native policy settings") from exc

    if not isinstance(value, dict):
        raise ValueError("native_engine must be an operator policy table")
    table = dict(value)
    for name, cls in (("images", NativeImage), ("grants", NativeGrant),
                      ("mounts", NativeMount), ("tmpfs", NativeTmpfs)):
        table[name] = tuple(typed(cls, item) for item in table.get(name, ()))
    commands = []
    for item in table.get("commands", ()):
        if not isinstance(item, dict):
            raise ValueError("native command must be a table")
        command = dict(item)
        command["arguments"] = tuple(typed(NativeArgument, value) for value in command.get("arguments", ()))
        commands.append(typed(NativeCommand, command))
    table["commands"] = tuple(commands)
    return typed(NativeEngineConfig, table)
