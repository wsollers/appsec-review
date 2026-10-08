from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any
import uuid

from appsec_review.container_runtime.catalog import ContainerCatalog, ToolImage
from appsec_review.storage import atomic_json, file_sha256


@dataclass(frozen=True, slots=True)
class Mount:
    source: Path
    target: str
    read_only: bool = True


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    tool_id: str
    argv: tuple[str, ...]
    target_root: Path
    scratch_root: Path
    extra_mounts: tuple[Mount, ...] = ()
    environment: Mapping[str, str] | None = None
    working_directory: str = "/target"


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

    @property
    def terminal_status(self) -> str:
        if self.timed_out:
            return "TIMEOUT"
        if self.oom_killed:
            return "OOM"
        return "COMPLETED"


Runner = Callable[[Sequence[str], int], CommandOutcome]


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _default_runner(argv: Sequence[str], timeout: int) -> CommandOutcome:
    try:
        completed = subprocess.run(
            list(argv), stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=timeout
        )
        return CommandOutcome(completed.returncode, completed.stdout, completed.stderr,
                              oom_killed=completed.returncode == 137)
    except subprocess.TimeoutExpired as exc:
        return CommandOutcome(None, exc.stdout or b"", exc.stderr or b"", timed_out=True)


class ContainerExecutor:
    """Execute only enabled catalog images under the repository runtime policy."""

    def __init__(self, catalog: ContainerCatalog, run_root: Path, *, runner: Runner | None = None):
        self.catalog = catalog
        self.run_root = run_root.resolve()
        self.runner = runner or _default_runner

    def _run_control(self, argv: Sequence[str]) -> CommandOutcome:
        return self.runner(argv, 60)

    def resolve_image(self, tool: ToolImage) -> str:
        outcome = self._run_control(("docker", "image", "inspect", tool.tag, "--format", "{{.Id}}"))
        if outcome.exit_code != 0:
            raise RuntimeError(f"cataloged image is not locally available: {tool.tool_id}")
        image_id = outcome.stdout.decode("utf-8", "replace").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError(f"Docker returned a non-immutable image id for {tool.tool_id}")
        if tool.expected_image_id is not None and image_id != tool.expected_image_id:
            raise ValueError(f"local image digest mismatch for {tool.tool_id}")
        return image_id

    def _validate(self, request: ExecutionRequest, tool: ToolImage) -> tuple[Path, tuple[Mount, ...]]:
        target = request.target_root.resolve(strict=True)
        scratch = request.scratch_root.resolve()
        if scratch != self.run_root and self.run_root not in scratch.parents:
            raise ValueError("scanner scratch must be run-owned")
        scratch.mkdir(parents=True, exist_ok=True)
        # The application/Dagster uid and fixed scanner uid intentionally differ. Grant write only
        # on this run-owned scratch boundary; target, rules, and database mounts remain read-only.
        scratch.chmod(0o777)
        if not request.argv or request.argv[0] != tool.executable:
            raise ValueError(f"argv must begin with the cataloged executable for {tool.tool_id}")
        if any(not isinstance(arg, str) or "\0" in arg for arg in request.argv):
            raise ValueError("argv contains an unsafe value")
        if request.environment and any(not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) for key in request.environment):
            raise ValueError("environment key is invalid")
        mounts = (Mount(target, "/target", True), Mount(scratch, "/scratch", False), *request.extra_mounts)
        seen: set[str] = set()
        for mount in mounts:
            source = mount.source.resolve(strict=True)
            if mount.target in seen or not mount.target.startswith("/") or ".." in Path(mount.target).parts:
                raise ValueError(f"unsafe or duplicate mount target: {mount.target}")
            if "docker.sock" in source.name.lower() or mount.target.endswith("docker.sock"):
                raise ValueError("the Docker socket may not be mounted into a scanner")
            if mount.target == "/target" and not mount.read_only:
                raise ValueError("target mount must be read-only")
            if not mount.read_only and mount.target != "/scratch":
                raise ValueError("only run-owned scratch may be writable")
            seen.add(mount.target)
        return target, mounts

    def _docker_bind_source(self, path: Path) -> Path:
        """Translate a path inside the Dagster code-location container to its host bind source."""
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
        _, mounts = self._validate(request, tool)
        image_id = self.resolve_image(tool)
        raw = request.scratch_root / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        stdout_path, stderr_path = raw / "stdout.bin", raw / "stderr.bin"
        receipt_path = request.scratch_root / "execution.json"
        name = "appsec-" + uuid.uuid4().hex[:20]
        command = [
            "docker", "run", "--rm", "--name", name,
            "--network", "none", "--read-only", "--user", tool.user,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--cpus", tool.cpus, "--memory", tool.memory,
            "--pids-limit", str(tool.pids_limit),
            "--tmpfs", str(self.catalog.policy["tmpfs"][0]),
            "--workdir", request.working_directory,
        ]
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
        command.extend(("--entrypoint", tool.executable, image_id, *request.argv[1:]))
        started = _stamp()
        outcome = self.runner(command, tool.timeout_seconds)
        if outcome.timed_out:
            self._run_control(("docker", "kill", name))
        completed = _stamp()
        stdout = outcome.stdout[:tool.output_bytes]
        stderr = outcome.stderr[:tool.output_bytes]
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        mount_receipts = tuple({
            "source": str(mount.source.resolve()), "target": mount.target,
            "runtime_source": str(effective_sources[mount.target]), "read_only": mount.read_only,
        } for mount in mounts)
        limits = {
            "network": "none", "user": tool.user, "root_filesystem": "read-only",
            "cap_drop": ["ALL"], "no_new_privileges": True, "cpus": tool.cpus,
            "memory": tool.memory, "pids": tool.pids_limit,
            "tmpfs": list(self.catalog.policy["tmpfs"]),
            "timeout_seconds": tool.timeout_seconds, "stdout_bytes": tool.output_bytes,
            "stderr_bytes": tool.output_bytes,
        }
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
        )
        receipt = asdict(result)
        receipt["terminal_status"] = result.terminal_status
        receipt["stdout_sha256"] = file_sha256(stdout_path)
        receipt["stderr_sha256"] = file_sha256(stderr_path)
        atomic_json(receipt_path, receipt)
        return result
