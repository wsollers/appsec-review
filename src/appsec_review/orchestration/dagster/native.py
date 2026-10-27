"""Preparation and inherited-process checks for the explicit native deployment."""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import time
from typing import Mapping

from appsec_review.config.native_dagster import NativeDagsterConfig, load_native_dagster_config
from appsec_review.container_runtime.buildkit_worker import private_path, process_token


CONFIG_ENV = "APPSEC_NATIVE_DEPLOYMENT_CONFIG"
IDENTITY_ENV = "APPSEC_NATIVE_PROCESS_IDENTITY"


def _encoded(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_new(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def prepare_instance(config_path: Path) -> dict[str, object]:
    """Create a new private instance layout; never overwrite or operate an existing instance."""
    private_path(config_path.absolute(), directory=False)
    config = load_native_dagster_config(config_path)
    if os.geteuid() != config.client_uid:
        raise PermissionError("native instance preparation requires the configured application UID")
    home = Path(config.dagster_home)
    private_path(home.parent, uid=config.client_uid)
    if home.is_symlink():
        raise ValueError("native instance directory is indirect")
    home.mkdir(mode=0o700, exist_ok=True)
    private_path(home, uid=config.client_uid)
    if home.stat().st_mode & 0o077:
        raise PermissionError("native instance directory must be application-private")
    expected = {
        "dagster.yaml": _encoded(config.instance_config()),
        "workspace.yaml": _encoded(config.workspace_config()),
        "native-instance.json": _encoded({"schema": "appsec-review/native-instance/1",
                                          "configuration": asdict(config)}),
    }
    marker = home / "native-instance.json"
    if any(home.iterdir()):
        if not marker.is_file():
            raise RuntimeError("native instance is occupied or incompletely prepared; inspection is required")
        for name, payload in expected.items():
            path = home / name
            private_path(path, uid=config.client_uid, directory=False)
            if not path.is_file() or path.stat().st_mode & 0o077 or path.read_bytes() != payload:
                raise RuntimeError("native instance configuration drift; refusing replacement")
    else:
        for name in ("dagster.yaml", "workspace.yaml"):
            _publish_new(home / name, expected[name])
        _sync_directory(home)
        _publish_new(marker, expected[marker.name])
        _sync_directory(home)
        _sync_directory(home.parent)
    return {"deployment_id": config.deployment_id, "dagster_home": str(home),
            "state": "PREPARED", "configuration": asdict(config)}


def _process_identity() -> dict[str, object]:
    root = Path("/").stat()
    return {
        "namespaces": {name: os.readlink(f"/proc/self/ns/{name}") for name in ("mnt", "pid", "user")},
        "root": [root.st_dev, root.st_ino],
    }


def child_environment(config_path: Path, inherited: Mapping[str, str]) -> dict[str, str]:
    """Bind code-location descendants to the same native paths and kernel namespaces."""
    if any(key.startswith("DOCKER_") for key in inherited):
        raise ValueError("native processes cannot inherit an ambient Docker endpoint or credentials")
    config_path = config_path.absolute()
    config = load_native_dagster_config(config_path)
    private_path(config_path, uid=config.client_uid, directory=False)
    if config_path.resolve() != config_path or os.geteuid() != config.client_uid:
        raise ValueError("native deployment configuration must have a canonical path")
    environment = dict(inherited)
    expected = config.environment()
    for name, value in expected.items():
        if name in inherited and inherited[name] != value:
            raise ValueError(f"native inherited setting conflicts with the frozen configuration: {name}")
    expected[CONFIG_ENV] = str(config_path)
    expected[IDENTITY_ENV] = json.dumps(_process_identity(), sort_keys=True, separators=(",", ":"))
    for name, value in inherited.items():
        if name.startswith("APPSEC_NATIVE_") and (name not in expected or expected[name] != value):
            raise ValueError(f"native inherited identity is unknown or changed: {name}")
    environment.update(expected)
    return environment


def validate_child_environment() -> NativeDagsterConfig:
    """Check actual code-server/run-child state, not an assumed scheduler environment."""
    if any(key.startswith("DOCKER_") for key in os.environ):
        raise ValueError("native child inherited an ambient Docker endpoint or credentials")
    config_path = Path(os.environ.get(CONFIG_ENV, ""))
    if not config_path.is_absolute():
        raise ValueError("native child lacks its explicit deployment configuration")
    config = load_native_dagster_config(config_path)
    private_path(config_path, uid=config.client_uid, directory=False)
    if os.geteuid() != config.client_uid or os.getegid() < 1:
        raise PermissionError("native child identity is not the configured non-root application")
    for name, value in config.environment().items():
        if os.environ.get(name) != value:
            raise ValueError(f"native child lost its frozen setting: {name}")
    identity = os.environ.get(IDENTITY_ENV, "")
    if len(identity) > 4096 or json.loads(identity) != _process_identity():
        raise ValueError("native child changed its mount, PID, user namespace or root")
    if str(Path(sys.executable).absolute()) != config.python_executable:
        raise ValueError("native child is using a different Python environment")
    repository = Path(config.repository_root)
    if repository.resolve() != repository or Path.cwd().resolve() != repository:
        raise ValueError("native child changed its canonical repository root")
    import appsec_review

    if not Path(appsec_review.__file__).resolve().is_relative_to(repository / "src"):
        raise ValueError("native child imported a different checkout")
    return config


def validate_native_launch(*, definitions: bool = False):
    """Admit only children of the explicit, live, healthy native operator lifecycle."""
    from appsec_review.container_runtime.native_client import NativeClientContract
    from appsec_review.orchestration.dagster.native_operator import verify_application_cgroup

    config = validate_child_environment()
    path = Path(config.dagster_home) / "native-processes.json"
    private_path(path, uid=config.client_uid, directory=False)
    if path.stat().st_size > 65536:
        raise ValueError("native ownership record exceeds its bound")
    state = json.loads(path.read_bytes())
    allowed = {"STARTING", "RUNNING"} if definitions else {"RUNNING"}
    owner = state.get("controller", {})
    age = time.monotonic() - state.get("health_at", 0)
    if (state.get("schema") != "appsec-review/native-processes/1"
            or state.get("configuration") != asdict(config) or state.get("state") not in allowed
            or type(owner.get("pid")) is not int or owner["pid"] < 1
            or not owner.get("start_token") or process_token(owner["pid"]) != owner["start_token"]
            or not 0 <= age <= (120 if state["state"] == "STARTING" else 15)):
        raise RuntimeError("native launch has no live healthy instance owner")
    contract = NativeClientContract.load(Path(config.engine_contract))
    verify_application_cgroup(contract)
    if contract.uid != config.client_uid or process_token(contract.broker_pid) != contract.broker_start_token:
        raise RuntimeError("native launch broker or client identity changed")
    return contract
