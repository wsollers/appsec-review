"""Prepared native Dagster configuration; rendering never starts services."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
from typing import Any, Mapping
import tomllib


def native_execution_requested() -> bool:
    return any(name.startswith("APPSEC_NATIVE_") for name in os.environ)


def reject_uncommissioned_native_execution(*, definitions: bool = False) -> None:
    if native_execution_requested():
        from appsec_review.orchestration.dagster.native import validate_native_launch
        try:
            validate_native_launch(definitions=definitions)
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            raise RuntimeError(
                "native execution is unavailable: no valid live native lifecycle/engine contract; "
                "ambient Docker fallback is prohibited") from error


@dataclass(frozen=True, slots=True)
class NativeDagsterConfig:
    deployment_id: str
    repository_root: str
    python_executable: str
    dagster_home: str
    review_config: str
    runtime_profile: str
    engine_contract: str
    client_uid: int
    postgres_host: str
    postgres_port: int
    postgres_database: str
    postgres_user: str
    postgres_password_env: str
    grpc_port: int
    webserver_port: int
    location_name: str = "appsec_review"

    def __post_init__(self) -> None:
        for name in ("deployment_id", "postgres_database", "postgres_user", "location_name", "runtime_profile"):
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,79}", value):
                raise ValueError(f"native Dagster {name} must be an explicit bounded identifier")
        for name in ("repository_root", "python_executable", "dagster_home", "review_config", "engine_contract"):
            value = getattr(self, name)
            if (not isinstance(value, str) or not Path(value).is_absolute()
                    or len(value) > 4096 or ".." in Path(value).parts or "\\" in value
                    or any(ord(character) < 32 for character in value) or str(Path(value)) != value):
                raise ValueError(f"native Dagster {name} must be an absolute native path")
        if type(self.client_uid) is not int or self.client_uid < 1:
            raise ValueError("native Dagster requires an explicit non-root client UID")
        for name in ("postgres_port", "grpc_port", "webserver_port"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 65535:
                raise ValueError(f"native Dagster {name} is invalid")
        if len({self.postgres_port, self.grpc_port, self.webserver_port}) != 3:
            raise ValueError("native service ports must be distinct")
        if not isinstance(self.postgres_host, str) or len(self.postgres_host) > 80:
            raise ValueError("native Postgres host must be an explicit IP string")
        try:
            address = ipaddress.ip_address(self.postgres_host)
        except ValueError as error:
            raise ValueError("native Postgres requires an explicit reachable IP, not Compose DNS") from error
        if address.is_unspecified or address.is_multicast:
            raise ValueError("native Postgres address is not a connectable endpoint")
        if not isinstance(self.postgres_password_env, str) or not re.fullmatch(
                r"[A-Z][A-Z0-9_]{0,79}", self.postgres_password_env):
            raise ValueError("native Postgres password must name an environment variable")
        if self.dagster_home in {self.repository_root, "/var/dagster", "/opt/dagster/home"}:
            raise ValueError("native Dagster requires its own explicit instance directory")

    def instance_config(self) -> dict[str, Any]:
        home = Path(self.dagster_home)
        return {
            "storage": {"postgres": {"postgres_db": {
                "hostname": self.postgres_host, "port": self.postgres_port,
                "db_name": self.postgres_database, "username": self.postgres_user,
                "password": {"env": self.postgres_password_env},
                "params": self.postgres_parameters(),
            }}},
            "compute_logs": {
                "module": "dagster.core.storage.local_compute_log_manager",
                "class": "LocalComputeLogManager",
                "config": {"base_dir": str(home / "compute-logs")},
            },
            "local_artifact_storage": {
                "module": "dagster._core.storage.root", "class": "LocalArtifactStorage",
                "config": {"base_dir": str(home / "artifacts")},
            },
            "run_coordinator": {
                "module": "dagster._core.run_coordinator", "class": "QueuedRunCoordinator",
                "config": {"max_concurrent_runs": 1},
            },
            "run_launcher": {
                "module": "dagster._core.launcher", "class": "DefaultRunLauncher",
            },
            "telemetry": {"enabled": False},
            "run_monitoring": {"enabled": True},
        }

    def postgres_parameters(self) -> dict[str, str]:
        return {"connect_timeout": "5", "options": "-c statement_timeout=5000 -c lock_timeout=5000",
                "keepalives": "1", "keepalives_idle": "2", "keepalives_interval": "1",
                "keepalives_count": "3", "tcp_user_timeout": "5000"}

    def workspace_config(self) -> dict[str, Any]:
        return {"load_from": [{"grpc_server": {
            "host": "127.0.0.1", "port": self.grpc_port, "location_name": self.location_name,
        }}]}

    def environment(self) -> dict[str, str]:
        return {
            "DAGSTER_HOME": self.dagster_home,
            "APPSEC_REVIEW_CONFIG": self.review_config,
            "APPSEC_REVIEW_PROFILE": self.runtime_profile,
            "APPSEC_NATIVE_ENGINE_CONTRACT": self.engine_contract,
            "APPSEC_NATIVE_DEPLOYMENT_ID": self.deployment_id,
        }

    def commands(self) -> Mapping[str, tuple[str, ...]]:
        python = self.python_executable
        binaries = Path(python).parent
        workspace = str(Path(self.dagster_home) / "workspace.yaml")
        return {
            "code-location": (python, "-m", "dagster", "code-server", "start",
                              "-m", "appsec_review.orchestration.dagster.definitions",
                              "-h", "127.0.0.1", "-p", str(self.grpc_port),
                              "-d", self.repository_root),
            "scheduler": (str(binaries / "dagster-daemon"), "run", "-w", workspace),
            "webserver": (str(binaries / "dagster-webserver"), "-w", workspace,
                          "-h", "127.0.0.1", "-p", str(self.webserver_port)),
        }


def load_native_dagster_config(path: Path) -> NativeDagsterConfig:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"native_dagster"} or not isinstance(document["native_dagster"], dict):
        raise ValueError("expected exactly one native_dagster table")
    value = document["native_dagster"]
    unknown = set(value) - NativeDagsterConfig.__dataclass_fields__.keys()
    if unknown:
        raise ValueError("unknown native Dagster settings: " + ", ".join(sorted(unknown)))
    try:
        return NativeDagsterConfig(**value)
    except TypeError as error:
        raise ValueError("native Dagster configuration is incomplete") from error
