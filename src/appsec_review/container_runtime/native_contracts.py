"""Root-authored, nonsecret client contracts derived solely from installed operator policy."""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import stat
from uuid import uuid4

from appsec_review.container_runtime.buildkit_worker import private_path, process_token
from appsec_review.container_runtime.native_client import NativeClientContract


def client_contracts(config) -> tuple[NativeClientContract, ...]:
    native = config.native_engine
    if native is None:
        raise ValueError("client contracts require an explicit native engine policy")
    process = process_token(os.getpid())
    if process is None:
        raise RuntimeError("broker generation cannot be resolved")
    result = []
    for grant in native.grants:
        commands = {command_id for image in native.images if image.image_id in grant.image_ids
                    for command_id in image.command_ids}
        aliases = {}
        for command in native.commands:
            if command.command_id not in commands:
                continue
            for alias in (command.command_id, command.executable, Path(command.executable).name):
                if alias in aliases and aliases[alias] != command.executable:
                    raise ValueError("native executable aliases are ambiguous within a run grant")
                aliases[alias] = command.executable
        binding = {name: getattr(grant, name) for name in (
            "tenant_id", "project_id", "run_id", "target_snapshot", "configuration_id")}
        binding.update({name: getattr(native, name) for name in (
            "service_generation", "engine_id", "engine_generation")})
        result.append(NativeClientContract(
            native.endpoint, config.admission.metadata_root, grant.run_root, grant.target_root,
            grant.uid, config.admission.gid, os.getpid(), process, binding, config.resources,
            tuple({name: getattr(mount, name) for name in (
                "mount_id", "source_root", "destination", "read_only")}
                for mount in native.mounts if mount.mount_id in grant.mount_ids), aliases,
            grant.image_ids, native.application_cgroup or config.host_cgroup,
            native.application_cpu if native.application_cgroup else config.host_cpu,
            native.application_memory_mb if native.application_cgroup else config.host_overhead_mb,
            {name: os.readlink(f"/proc/self/ns/{name}") for name in ("mnt", "pid", "user")}))
    return tuple(result)


def contract_path(config, index: int) -> Path:
    native = config.native_engine
    if native is None or native.client_contract_root is None:
        raise ValueError("native service requires an operator-selected client contract directory")
    if type(index) is not int or not 0 <= index < len(native.grants):
        raise ValueError("native client grant index is invalid")
    return Path(native.client_contract_root) / f"grant-{index}.json"


def publish_client_contracts(config) -> tuple[Path, ...]:
    """Called only by the reserved, proof-checked broker after binding its private listeners."""
    if os.geteuid() != 0:
        raise PermissionError("only the root broker publishes native client contracts")
    contracts = client_contracts(config)
    paths = tuple(contract_path(config, index) for index in range(len(contracts)))
    root = paths[0].parent
    private_path(root, uid=0)
    if root.stat().st_uid != 0:
        raise PermissionError("native contract directory must remain root-owned")
    for parent in (root, *root.parents):
        metadata = parent.stat()
        traversal = stat.S_IXGRP if metadata.st_gid == config.admission.gid else stat.S_IXOTH
        if not metadata.st_mode & traversal:
            raise PermissionError("native client cannot traverse its contract directory")
    for path, contract in zip(paths, contracts, strict=True):
        document = asdict(contract)
        document["resources"] = contract.resources.view()
        data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(data) > 65536:
            raise ValueError("native client contract exceeds its publication bound")
        if path.exists() or path.is_symlink():
            previous = NativeClientContract.load(path)
            old, current = asdict(previous), asdict(contract)
            for key in ("broker_pid", "broker_start_token"):
                old.pop(key)
                current.pop(key)
            if old != current:
                raise RuntimeError("native client contract drift requires explicit operator reconciliation")
        temporary = root / f".grant-{uuid4().hex}.tmp"
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
    return paths
