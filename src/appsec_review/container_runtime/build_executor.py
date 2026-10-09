from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
from typing import Any

from appsec_review.config import BuildCaptureConfig
from .build_capture import BuildExecutionRecorder, CaptureScope, record_strace_files


@dataclass(frozen=True, slots=True)
class BuildProfile:
    name: str
    tag: str
    image_id: str
    user: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id):
            raise ValueError(f"build profile image id is invalid: {self.name}")
        if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", self.user):
            raise ValueError(f"build profile user must be numeric non-root: {self.name}")
        if not self.tag or any(char.isspace() for char in self.tag):
            raise ValueError(f"build profile tag is invalid: {self.name}")


@dataclass(frozen=True, slots=True)
class BuildCommandResult:
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    stdout_tail: bytes = b""
    stderr_tail: bytes = b""
    capture_record: Path | None = None


Runner = Callable[[Sequence[str], int], tuple[int | None, bytes, bytes, bool]]


def _run(argv: Sequence[str], timeout: int) -> tuple[int | None, bytes, bytes, bool]:
    process = subprocess.Popen(
        list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr, False
    except subprocess.TimeoutExpired as exc:
        # Killing only the CLI can leave a descendant holding the capture pipes open forever.
        # Build commands run in their own POSIX session so timeout cleanup releases the whole
        # bounded command tree and `communicate` cannot wedge a Dagster worker.
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
        return None, stdout or exc.stdout or b"", stderr or exc.stderr or b"", True


def resolve_host_bind_path(path: Path, runner: Runner) -> Path:
    """Resolve a path through the current container's bind mounts for sibling Docker runs."""
    hostname = os.environ.get("HOSTNAME")
    if not hostname or not Path("/.dockerenv").exists():
        return path
    code, stdout, _stderr, timed_out = runner(
        ("docker", "inspect", hostname, "--format", "{{json .Mounts}}"), 60)
    if timed_out or code != 0:
        raise RuntimeError("could not resolve build workspace host mount")
    candidates: list[tuple[int, Path]] = []
    for mount in json.loads(stdout.decode("utf-8", "replace")):
        destination = Path(str(mount.get("Destination", "")))
        try:
            relative = path.relative_to(destination)
        except ValueError:
            continue
        candidates.append((len(destination.parts), Path(str(mount["Source"])) / relative))
    if not candidates:
        raise RuntimeError("build workspace is not backed by a host mount")
    return max(candidates, key=lambda item: item[0])[1]


class BuildContainerExecutor:
    """Run already-validated argv in an immutable build image with dependency egress."""

    CAPTURED_TOOLS = (
        "ar", "c++", "cargo", "cc", "clang", "clang++", "cmake", "composer", "dotnet", "g++", "gcc",
        "go", "jar", "java", "javac", "kotlinc", "ld", "make", "mvn", "ninja", "npm",
        "php", "python", "python3", "rustc",
    )

    def __init__(self, profile: BuildProfile, *, timeout_seconds: int, output_bytes: int,
                 runner: Runner | None = None) -> None:
        self.profile = profile
        self.timeout_seconds = timeout_seconds
        self.output_bytes = output_bytes
        self.runner = runner or _run

    def resolve(self) -> None:
        code, stdout, _stderr, timed_out = self.runner(
            ("docker", "image", "inspect", self.profile.tag, "--format", "{{.Id}}"), 60)
        if timed_out or code != 0:
            raise RuntimeError(f"build image is unavailable: {self.profile.name}")
        if stdout.decode("utf-8", "replace").strip() != self.profile.image_id:
            raise ValueError(f"build image identity changed: {self.profile.name}")

    def _bind_source(self, path: Path) -> Path:
        return resolve_host_bind_path(path, self.runner)

    def _prepare(self, *, workspace: Path, working_directory: str,
                 environment: Mapping[str, str]) -> tuple[Path, list[str]]:
        root = workspace.resolve(strict=True)
        relative_workdir = Path(*working_directory.split("/"))
        resolved_workdir = (root / relative_workdir).resolve(strict=True)
        if root != resolved_workdir and root not in resolved_workdir.parents:
            raise ValueError("build working directory escaped the run-owned workspace")
        bind_source = self._bind_source(root)
        command = [
            "docker", "run", "--rm", "--network", "bridge", "--read-only",
            "--user", self.profile.user, "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "4g",
            "--pids-limit", "1024", "--tmpfs", "/tmp:rw,noexec,nosuid,size=1g",
            "--workdir", f"/workspace/{working_directory}", "--mount",
            f"type=bind,src={bind_source},dst=/workspace",
            "--env", "HOME=/tmp", "--env", "LANG=C.UTF-8", "--env", "LC_ALL=C.UTF-8",
            "--env", "TZ=UTC",
        ]
        for key, value in sorted(environment.items()):
            command.extend(("--env", f"{key}={value}"))
        return root, command

    def execute(self, argv: Sequence[str], *, workspace: Path, working_directory: str,
                environment: Mapping[str, str]) -> BuildCommandResult:
        if not argv or any(not isinstance(value, str) or "\0" in value for value in argv):
            raise ValueError("build command argv is invalid")
        _root, command = self._prepare(
            workspace=workspace, working_directory=working_directory, environment=environment)
        command.extend(("--entrypoint", argv[0], self.profile.image_id, *argv[1:]))
        code, stdout, stderr, timed_out = self.runner(command, self.timeout_seconds)
        stdout_truncated, stderr_truncated = len(stdout) > self.output_bytes, len(stderr) > self.output_bytes
        tail_bytes = min(32768, self.output_bytes)
        return BuildCommandResult(
            tuple(argv), code, stdout[:self.output_bytes], stderr[:self.output_bytes], timed_out,
            stdout_bytes=len(stdout), stderr_bytes=len(stderr),
            stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
            stdout_tail=stdout[-tail_bytes:] if stdout_truncated else b"",
            stderr_tail=stderr[-tail_bytes:] if stderr_truncated else b"",
        )

    def execute_captured(self, argv: Sequence[str], *, workspace: Path,
                         working_directory: str, environment: Mapping[str, str],
                         capture_directory: Path, capture_config: BuildCaptureConfig,
                         scope: CaptureScope) -> BuildCommandResult:
        """Run a build under a process-tree-local syscall catcher and emit its JSON record."""
        if capture_config.backend != "ptrace":
            raise ValueError("this executor supports the ptrace build-capture backend")
        if not argv or any(not isinstance(value, str) or "\0" in value for value in argv):
            raise ValueError("build command argv is invalid")
        capture_environment = dict(environment)
        if scope.family == "dotnet":
            # Persistent MSBuild/Roslyn servers outlive the requested command and would keep a
            # process-tree tracer attached after a successful build.
            capture_environment.setdefault("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
            capture_environment.setdefault("MSBUILDDISABLENODEREUSE", "1")
            capture_environment.setdefault("UseSharedCompilation", "false")
        root, command = self._prepare(
            workspace=workspace, working_directory=working_directory,
            environment=capture_environment)
        capture_root = capture_directory.resolve()
        try:
            relative_capture = capture_root.relative_to(root)
        except ValueError as exc:
            raise ValueError("capture directory must be inside the run-owned workspace") from exc
        recorder = BuildExecutionRecorder(
            capture_root, scope, capture_config,
            {"backend": "ptrace", "tool": "strace", "image_id": self.profile.image_id,
             "event_kinds": sorted(("process_fork", "process_exec", "process_exit",
                                    "file_open", "connect"))},
        )
        driver = capture_root / "build-driver.sh"
        source_driver = Path(__file__).resolve().parents[3] / "containers" / "build-capture" / "build-driver.sh"
        driver.write_bytes(source_driver.read_bytes())
        wrapper = capture_root / "tool-wrapper.py"
        source_wrapper = source_driver.with_name("tool-wrapper.py")
        wrapper.write_bytes(source_wrapper.read_bytes())
        wrapper_root = capture_root / "wrappers"
        wrapper_root.mkdir()
        for tool in self.CAPTURED_TOOLS:
            launcher = wrapper_root / tool
            launcher.write_text(
                "#!/bin/sh\nexec \"$APPSEC_CAPTURE_PYTHON\" \"$APPSEC_CAPTURE_ROOT/tool-wrapper.py\" " +
                tool + " \"$@\"\n", encoding="utf-8", newline="\n")
            launcher.chmod(0o755)
        logical_capture = "/workspace/" + relative_capture.as_posix()
        logical_driver = logical_capture + "/build-driver.sh"
        logical_wrappers = logical_capture + "/wrappers"
        command.extend(("--entrypoint", "/bin/sh", self.profile.image_id, logical_driver,
                        logical_capture, str(capture_config.argument_bytes_limit),
                        str(capture_config.tool_call_count_limit),
                        str(capture_config.tool_stream_bytes_limit), logical_wrappers, *argv))
        code, stdout, stderr, timed_out = self.runner(command, self.timeout_seconds)
        stdout_path, stderr_path = capture_root / "stdout", capture_root / "stderr"
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        parse_errors = record_strace_files(capture_root.glob("trace*"), recorder)
        record = recorder.finish(
            argv=argv, working_directory=working_directory, exit_code=code, timed_out=timed_out,
            stdout_path=stdout_path, stderr_path=stderr_path, collector_errors=parse_errors)
        stdout_truncated, stderr_truncated = len(stdout) > self.output_bytes, len(stderr) > self.output_bytes
        tail_bytes = min(32768, self.output_bytes)
        return BuildCommandResult(
            tuple(argv), code, stdout[:self.output_bytes], stderr[:self.output_bytes], timed_out,
            stdout_bytes=len(stdout), stderr_bytes=len(stderr),
            stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
            stdout_tail=stdout[-tail_bytes:] if stdout_truncated else b"",
            stderr_tail=stderr[-tail_bytes:] if stderr_truncated else b"",
            capture_record=record,
        )

    def prepare_node_dependencies(self, *, workspace: Path, source_dir: str) -> None:
        """Expose image-owned node_modules at the writable target source root."""
        logical = PurePosixPath(source_dir)
        if source_dir != "." and (logical.is_absolute() or ".." in logical.parts):
            raise ValueError("Node source directory is not normalized")
        dependency_root = "/opt/project/node_modules" if source_dir == "." else (
            f"/opt/project/{logical.as_posix()}/node_modules")
        result = self.execute(("ln", "-s", dependency_root, "node_modules"),
                              workspace=workspace, working_directory=source_dir, environment={})
        if result.timed_out or result.exit_code != 0:
            raise RuntimeError("could not expose image-owned Node dependencies to the build workspace")


def profiles_from_settings(value: Any) -> dict[str, BuildProfile]:
    if not isinstance(value, Mapping):
        raise ValueError("project-build profiles configuration is required")
    profiles: dict[str, BuildProfile] = {}
    for name, item in value.items():
        if not isinstance(item, Mapping) or set(item) != {"tag", "image_id", "user"}:
            raise ValueError(f"project-build profile is invalid: {name}")
        profiles[str(name)] = BuildProfile(str(name), str(item["tag"]),
                                           str(item["image_id"]), str(item["user"]))
    return profiles
