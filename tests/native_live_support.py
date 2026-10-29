"""Shared gates and helpers for tests that drive a real commissioned native broker.

These tiers never start, commission or configure anything. They act only as the broker's granted
non-root client, through the public ``NativeClient``, inside the services slice named by the
published client contract. Every unmet precondition is a named skip reason, never a pass.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import stat
from typing import Iterator, Sequence
import uuid

import appsec_review.container_runtime.native_client as native_client_module
import appsec_review.container_runtime.native_commands as native_commands_module
from appsec_review.container_runtime.native_client import NativeClient, NativeClientContract
from appsec_review.observability.events import EventLog
from appsec_review.runtime import resources
from appsec_review.runtime.resources import Reservation, ResourceAdmission


CONTRACT_ENV = "APPSEC_NATIVE_CLIENT_CONTRACT"
DEFAULT_CONTRACT = "/run/appsec-review-f370/client-v9/contracts/grant-0.json"
RELEASE_ENV = "APPSEC_NATIVE_RELEASE"
DEFAULT_RELEASE = "/opt/appsec-review/releases/a78696b8-native19"
INTEGRATION_ENV = "APPSEC_NATIVE_INTEGRATION"
ACCEPTANCE_ENV = "APPSEC_NATIVE_ACCEPTANCE"
# Modules whose wire behaviour must equal the installed release the broker runs.
_PROTOCOL_MODULES = {
    "appsec_review/container_runtime/native_client.py": native_client_module,
    "appsec_review/container_runtime/native_commands.py": native_commands_module,
    "appsec_review/runtime/resources.py": resources,
}
CONTAINER_ENVIRONMENT = (("HOME", "/tmp"), ("TMPDIR", "/tmp"), ("PATH", "/usr/local/bin:/usr/bin:/bin"))
BUILD_DRIVER_PREFIX = ("/scratch/build-driver.sh", "/scratch/capture", "4096", "256", "/scratch/wrappers", "0")


def contract_path() -> Path:
    return Path(os.environ.get(CONTRACT_ENV, DEFAULT_CONTRACT))


def skip_reason(*flags: str) -> str | None:
    """Return why the real broker cannot be driven from this process, or None when it can."""

    for flag in flags:
        if os.environ.get(flag) != "1":
            return f"set {flag}=1 to drive the real commissioned native broker"
    if os.geteuid() == 0:
        return "run as the contract's non-root client uid (1000), not root"
    path = contract_path()
    if not path.is_file():
        return f"native client contract is absent: {path} (broker not commissioned/running; set {CONTRACT_ENV})"
    try:
        contract = NativeClientContract.load(path)
    except (OSError, ValueError, TypeError) as error:
        return f"native client contract {path} does not load: {error}"
    if (os.geteuid(), os.getegid()) != (contract.uid, contract.gid):
        return (f"process identity {os.geteuid()}:{os.getegid()} differs from the contract's "
                f"{contract.uid}:{contract.gid}")
    try:
        endpoint = Path(contract.endpoint).lstat()
    except OSError as error:
        return f"native broker socket is unavailable: {contract.endpoint} ({error})"
    if not stat.S_ISSOCK(endpoint.st_mode):
        return f"native broker endpoint is not a socket: {contract.endpoint}"
    if contract.host_cgroup is not None:
        line = Path("/proc/self/cgroup").read_text().strip()
        group = Path("/sys/fs/cgroup") / line.split("::", 1)[-1].lstrip("/")
        if not group.is_relative_to(Path(contract.host_cgroup)):
            return (f"process cgroup {group} is not under the contract's host cgroup "
                    f"{contract.host_cgroup}; launch inside the services slice")
    release = Path(os.environ.get(RELEASE_ENV, DEFAULT_RELEASE)) / "lib"
    for relative, module in _PROTOCOL_MODULES.items():
        installed = release / relative
        if not installed.is_file():
            return f"installed release module is absent: {installed} (set {RELEASE_ENV})"
        if installed.read_bytes() != Path(module.__file__).read_bytes():
            return f"client module {module.__file__} differs from the broker's release copy {installed}"
    if not Path(contract.run_root).is_dir():
        return f"granted run root is absent: {contract.run_root}"
    return None


def capture_staging_reason() -> str | None:
    """Name the missing build-driver staging that the process-tree capture command requires."""

    run_root = Path(NativeClientContract.load(contract_path()).run_root)
    if not (run_root / "build-driver.sh").is_file():
        return f"stage containers/build-capture/build-driver.sh at {run_root / 'build-driver.sh'} (0500)"
    for directory in ("capture", "wrappers"):
        if not (run_root / directory).is_dir():
            return f"stage the capture directory {run_root / directory} (0700)"
    return None


@dataclass(frozen=True)
class NativeSession:
    contract: NativeClientContract
    client: NativeClient
    run_root: Path
    admission: ResourceAdmission
    events: EventLog

    @contextmanager
    def reserved(self, label: str, *, cpu: int = 2, memory_mb: int = 1024) -> Iterator[str]:
        """Reserve container memory plus the 512 MiB native staging, as the commissioning probe does."""

        with self.admission.reserve(Reservation(cpu, memory_mb + 512), events=self.events,
                                    action="native-test." + label, timeout_seconds=0) as lease_id:
            yield lease_id

    def run_argv(self, name: str, executable: str, arguments: Sequence[str], *, source: Path,
                 cpu: int = 2, memory_mb: int = 1024,
                 environment: Sequence[tuple[str, str]] = ()) -> list[str]:
        argv = ["docker", "run", "--rm", "--name", name, "--network", "none",
                "--read-only", "--user", f"{self.contract.uid}:{self.contract.gid}", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--cpus", str(cpu), "--memory", f"{memory_mb}m",
                "--pids-limit", "1024", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
                "--workdir", "/scratch", "--mount", f"type=bind,src={source},dst=/scratch",
                "--entrypoint", executable]
        for key, value in environment:
            argv.extend(("--env", f"{key}={value}"))
        argv.extend((self.contract.image_ids[0], *arguments))
        return argv

    def remove(self, name: str) -> None:
        """Remove an owned execution and independently confirm the container no longer exists."""

        assert self.client.run(("docker", "rm", "--force", name), 45)[0] == 0
        status = self.client.run(("docker", "container", "inspect", name, "--format", "{{.State.Running}}"), 15)
        assert status[0] == 1 and status[2] == f"Error: No such container: {name}".encode(), status
        resources.container_stopped(name)

    def remove_if_owned(self, name: str) -> None:
        if name in self.client.executions:
            self.remove(name)


def new_name() -> str:
    return "appsec-" + uuid.uuid4().hex[:20]


def open_session(events: Path) -> NativeSession:
    contract = NativeClientContract.load(contract_path())
    return NativeSession(
        contract=contract, client=NativeClient(contract), run_root=Path(contract.run_root),
        admission=ResourceAdmission(Path(contract.metadata_root), contract.resources,
                                    require_container_removal=True),
        events=EventLog(events))
