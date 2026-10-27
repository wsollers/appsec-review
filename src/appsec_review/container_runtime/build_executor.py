from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import uuid
from typing import Any

from appsec_review.application_paths import application_root as _application_root
from appsec_review.config import BuildCaptureConfig
from appsec_review.config.native_dagster import native_execution_requested
from appsec_review.runtime.resources import (
    bounded_execution, reserve_execution, review_resources_active, tracked_container,
)
from appsec_review.storage import atomic_json, canonical_json
from .catalog import load_catalog
from .identity import application_runtime_user
from .build_capture import (
    PATH_FIELDS, REQUIRED_EVENT_KINDS, BuildExecutionRecorder, CaptureScope, record_strace_files,
)
from .capture_files import CaptureRoots, build_file_inventory, read_events, snapshot_response_files
from .raw_traces import reference_raw_traces, retain_raw_traces


def repository_root() -> Path:
    """Return the deployment root that owns the container asset catalog."""
    return _application_root("containers/catalog.toml")


def _capture_asset(name: str) -> Path:
    """Resolve capture assets in both a source checkout and the installed Dagster image."""
    relative = f"containers/build-capture/{name}"
    return _application_root(relative) / relative


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
    stdout_file: Path | None = None
    stderr_file: Path | None = None


Runner = Callable[[Sequence[str], int], tuple[int | None, bytes, bytes, bool]]


def _run(argv: Sequence[str], timeout: int) -> tuple[int | None, bytes, bytes, bool]:
    from .native_client import native_run
    native = native_run(argv, timeout)
    if native is not None:
        return native
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


def _container_name() -> str:
    return f"appsec-review-build-{uuid.uuid4().hex}"


def _run_to_files(argv: Sequence[str], timeout: int, stdout_path: Path,
                  stderr_path: Path) -> tuple[int | None, bool]:
    """Run without pipe buffering and retain both diagnostic streams in full."""
    from .native_client import native_run
    native = native_run(argv, timeout)
    if native is not None:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_bytes(native[1])
        stderr_path.write_bytes(native[2])
        return native[0], native[3]
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            list(argv), stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            start_new_session=os.name == "posix",
        )
        try:
            return process.wait(timeout=timeout), False
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            return None, True


def resolve_host_bind_path(path: Path, runner: Runner) -> Path:
    """Resolve a path through the current container's bind mounts for sibling Docker runs."""
    if native_execution_requested():
        if Path("/.dockerenv").exists():
            raise ValueError("native execution cannot translate a container filesystem")
        return path
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
        "aapt2", "apksigner", "ar", "c++", "cargo", "cc", "clang", "clang++", "cmake", "composer",
        "d8", "dotnet", "g++", "gcc", "go", "gradle", "jar", "java", "javac", "kotlinc", "ld",
        "make", "mvn", "ninja", "npm", "php", "python", "python3", "r8", "rustc", "zipalign",
    )

    def __init__(self, profile: BuildProfile, *, timeout_seconds: int, output_bytes: int,
                 runner: Runner | None = None, network: str = "bridge") -> None:
        if network not in {"bridge", "none"}:
            raise ValueError("build container network must be bridge or none")
        self.profile = profile
        self.timeout_seconds = timeout_seconds
        self.output_bytes = output_bytes
        self.runner = runner or _run
        # Dependency downloads need egress; a job that only compiles already-fetched source asks for none.
        self.network = network

    def resolve(self) -> None:
        code, stdout, _stderr, timed_out = self.runner(
            ("docker", "image", "inspect", self.profile.tag, "--format", "{{.Id}}"), 60)
        if timed_out or code != 0:
            raise RuntimeError(f"build image is unavailable: {self.profile.name}")
        if stdout.decode("utf-8", "replace").strip() != self.profile.image_id:
            raise ValueError(f"build image identity changed: {self.profile.name}")

    def _bind_source(self, path: Path) -> Path:
        return resolve_host_bind_path(path, self.runner)

    def _stop_on_timeout(self, command: Sequence[str], timed_out: bool) -> None:
        """Remove a timed-out container; killing the docker client leaves the container running."""

        if timed_out and "--name" in command:
            self.runner(("docker", "rm", "--force", command[command.index("--name") + 1]), 60)

    def _make_workspace_writable(self, root: Path) -> None:
        """Ensure the application identity can update its run-owned source copy."""
        container_uid = int(application_runtime_user(self.profile.user).split(":", 1)[0])
        for path in (root, *root.rglob("*")):
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            try:
                if path.is_dir():
                    path.chmod(((mode & ~0o022) | 0o700) if native_execution_requested() else mode | 0o007)
                elif path.is_file():
                    path.chmod(((mode & ~0o022) | 0o600) if native_execution_requested() else mode | 0o006)
            except PermissionError:
                if path.stat().st_uid != container_uid:
                    raise

    def _restrict_workspace(self, root: Path) -> None:
        """Close the build container's write window: no group- or world-writable workspace entry."""
        uid = os.geteuid() if hasattr(os, "geteuid") else None
        for path in (root, *root.rglob("*")):
            try:
                if path.is_symlink() or (uid is not None and path.lstat().st_uid != uid):
                    continue
                mode = path.stat().st_mode
                if mode & 0o022:
                    path.chmod(mode & ~0o022)
            except OSError:
                continue  # a container-owned entry the host cannot change; the audit names it

    def _prepare(self, *, workspace: Path, working_directory: str,
                 environment: Mapping[str, str]) -> tuple[Path, list[str]]:
        root = workspace.resolve(strict=True)
        relative_workdir = Path(*working_directory.split("/"))
        resolved_workdir = (root / relative_workdir).resolve(strict=True)
        if root != resolved_workdir and root not in resolved_workdir.parents:
            raise ValueError("build working directory escaped the run-owned workspace")
        self._make_workspace_writable(root)
        bind_source = self._bind_source(root)
        runtime_user = application_runtime_user(self.profile.user)
        command = [
            "docker", "run", "--rm", "--name", _container_name(), "--network", self.network, "--read-only",
            "--user", runtime_user, "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "4g",
            "--pids-limit", "1024", "--tmpfs",
            "/tmp:rw,exec,nosuid,size=2g" if self.profile.name == "android"
            else "/tmp:rw,noexec,nosuid,size=1g",
            "--workdir", f"/workspace/{working_directory}", "--mount",
            f"type=bind,src={bind_source},dst=/workspace",
            "--env", "HOME=/tmp", "--env", "LANG=C.UTF-8", "--env", "LC_ALL=C.UTF-8",
            "--env", "TZ=UTC",
        ]
        if self.profile.name == "android":
            command.extend((
                "--env", "GRADLE_USER_HOME=/tmp/gradle",
                "--env", "ANDROID_USER_HOME=/tmp/android",
            ))
        for key, value in sorted(environment.items()):
            command.extend(("--env", f"{key}={value}"))
        return root, command

    @bounded_execution(cpu="2", memory="4g", action="build.execute")
    def execute(self, argv: Sequence[str], *, workspace: Path, working_directory: str,
                environment: Mapping[str, str], instrumentation_root: Path | None = None,
                instrumentation_evidence_root: Path | None = None) -> BuildCommandResult:
        if not argv or any(not isinstance(value, str) or "\0" in value for value in argv):
            raise ValueError("build command argv is invalid")
        if (instrumentation_root is None) != (instrumentation_evidence_root is None):
            raise ValueError("instrumentation and evidence roots must be supplied together")
        _root = workspace.resolve(strict=True)
        instrumentation = evidence = None
        if instrumentation_root is not None and instrumentation_evidence_root is not None:
            instrumentation = instrumentation_root.resolve(strict=True)
            evidence = instrumentation_evidence_root.resolve(strict=True)
            roots = (_root, instrumentation, evidence)
            if (instrumentation_root.is_symlink() or instrumentation_evidence_root.is_symlink()
                    or not instrumentation.is_dir() or not evidence.is_dir()
                    or any(left.is_relative_to(right) or right.is_relative_to(left)
                           for index, left in enumerate(roots) for right in roots[index + 1:])):
                raise ValueError("instrumentation and evidence require separate roots outside the workspace")
        try:
            _root, command = self._prepare(
                workspace=workspace, working_directory=working_directory, environment=environment)
            if instrumentation is not None and evidence is not None:
                self._make_workspace_writable(evidence)
                command.extend((
                    "--mount", f"type=bind,src={self._bind_source(instrumentation)},dst=/appsec-jvm,readonly",
                    "--mount", f"type=bind,src={self._bind_source(evidence)},dst=/appsec-jvm-evidence",
                ))
            command.extend(("--entrypoint", argv[0], self.profile.image_id, *argv[1:]))
            with self._container(command):
                code, stdout, stderr, timed_out = self.runner(command, self.timeout_seconds)
                self._stop_on_timeout(command, timed_out)
        finally:
            self._restrict_workspace(_root)
            if evidence is not None:
                self._restrict_workspace(evidence)
        stdout_truncated, stderr_truncated = len(stdout) > self.output_bytes, len(stderr) > self.output_bytes
        tail_bytes = min(32768, self.output_bytes)
        return BuildCommandResult(
            tuple(argv), code, stdout[:self.output_bytes], stderr[:self.output_bytes], timed_out,
            stdout_bytes=len(stdout), stderr_bytes=len(stderr),
            stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
            stdout_tail=stdout[-tail_bytes:] if stdout_truncated else b"",
            stderr_tail=stderr[-tail_bytes:] if stderr_truncated else b"",
        )

    def _container(self, command: Sequence[str]):
        return (tracked_container(command[command.index("--name") + 1], self.runner, label="Build")
                if review_resources_active() else nullcontext())

    @bounded_execution(cpu="2", memory="4g", action="build.capture")
    def execute_captured(self, argv: Sequence[str], *, workspace: Path,
                         working_directory: str, environment: Mapping[str, str],
                         capture_directory: Path, capture_config: BuildCaptureConfig,
                         scope: CaptureScope,
                         snapshot_files: Mapping[str, Mapping[str, Any]] | None = None,
                         ) -> BuildCommandResult:
        """Run a build under a process-tree-local syscall catcher and emit its JSON record.

        ``snapshot_files`` maps workspace-relative paths to pre-build ``sha256``, ``size_bytes``
        and ``mtime_ns``; unchanged files reuse those hashes in the post-build file inventory.
        """
        if capture_config.backend != "ptrace":
            raise ValueError("this executor supports the ptrace build-capture backend")
        if not argv or any(not isinstance(value, str) or "\0" in value for value in argv):
            raise ValueError("build command argv is invalid")
        capture_environment = dict(environment)
        if scope.family == "dotnet":
            # Persistent MSBuild/Roslyn servers outlive the requested command and would keep a
            # process-tree tracer attached after a successful build.  Workload advertising and
            # telemetry also start optional background work whose detached threads would make
            # the syscall capture incomplete even though compilation itself finished.
            capture_environment.setdefault("DOTNET_CLI_USE_MSBUILD_SERVER", "0")
            capture_environment.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
            capture_environment.setdefault("DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE", "true")
            capture_environment.setdefault("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
            capture_environment.setdefault("MSBUILDDISABLENODEREUSE", "1")
            capture_environment.setdefault("UseSharedCompilation", "false")
        root, command = self._prepare(
            workspace=workspace, working_directory=working_directory,
            environment=capture_environment)
        capture_root = capture_directory.resolve()
        recorder = BuildExecutionRecorder(
            capture_root, scope, capture_config,
            {"backend": "ptrace", "tool": "strace", "image_id": self.profile.image_id,
             "event_kinds": sorted(REQUIRED_EVENT_KINDS),
             "trace_options": ["--seccomp-bpf", "-y"]},
        )
        driver = capture_root / "build-driver.sh"
        # The build container shares the application identity and writes only to this run-owned leaf.
        capture_root.chmod(0o733)

        source_driver = _capture_asset("build-driver.sh")
        driver.write_bytes(source_driver.read_bytes())
        wrapper = capture_root / "tool-wrapper.py"
        source_wrapper = _capture_asset("tool-wrapper.py")
        wrapper.write_bytes(source_wrapper.read_bytes())
        redaction_config = capture_root / "envp-redact-names.json"
        atomic_json(redaction_config, list(capture_config.envp_redact_names))
        redaction_config.chmod(0o644)
        wrapper_root = capture_root / "wrappers"
        wrapper_root.mkdir()
        for tool in self.CAPTURED_TOOLS:
            launcher = wrapper_root / tool
            launcher.write_text(
                "#!/bin/sh\nexec \"$APPSEC_CAPTURE_PYTHON\" \"$APPSEC_CAPTURE_ROOT/tool-wrapper.py\" " +
                tool + " \"$@\"\n", encoding="utf-8", newline="\n")
            launcher.chmod(0o755)
        try:
            relative_capture = capture_root.relative_to(root)
        except ValueError:
            command.extend(("--mount",
                            f"type=bind,src={self._bind_source(capture_root)},dst=/capture"))
            logical_capture = "/capture"
        else:
            logical_capture = "/workspace/" + relative_capture.as_posix()
        logical_driver = logical_capture + "/build-driver.sh"
        logical_wrappers = logical_capture + "/wrappers"
        command.extend(("--entrypoint", "/bin/sh", self.profile.image_id, logical_driver,
                        logical_capture, str(capture_config.argument_bytes_limit),
                        str(capture_config.tool_call_count_limit), logical_wrappers,
                        "1" if capture_config.capture_envp else "0", *argv))
        stdout_path, stderr_path = capture_root / "stdout", capture_root / "stderr"
        try:
            with self._container(command):
                if self.runner is _run:
                    code, timed_out = _run_to_files(
                        command, self.timeout_seconds, stdout_path, stderr_path)
                    self._stop_on_timeout(command, timed_out)
                else:
                    code, stdout, stderr, timed_out = self.runner(command, self.timeout_seconds)
                    self._stop_on_timeout(command, timed_out)
                    stdout_path.write_bytes(stdout)
                    stderr_path.write_bytes(stderr)
        finally:
            self._restrict_workspace(root)
            capture_root.chmod(0o755)  # the build container's write window into the capture closed
        self._take_tool_call_ownership(capture_root)
        trace_paths = tuple(capture_root.glob("trace*"))
        parse_errors = record_strace_files(trace_paths, recorder)
        raw_traces = (retain_raw_traces(capture_root, trace_paths,
                                        bytes_limit=capture_config.raw_trace_bytes_limit,
                                        envp_redact_names=capture_config.envp_redact_names)
                      if capture_config.retain_raw_traces else None)
        parse_errors = reference_raw_traces(parse_errors, raw_traces)
        recorder.flush()
        roots = CaptureRoots("/workspace", root, logical_capture, self.profile.image_id,
                             posixpath.normpath(f"/workspace/{working_directory}"))
        # Response files are copied before the secret scan so the scan covers their contents.
        response_files, response_gaps = snapshot_response_files(
            list(read_events(capture_root / "events.jsonl")), roots, capture_root,
            count_limit=capture_config.response_file_count_limit,
            bytes_limit=capture_config.response_file_bytes_limit)
        secret_scan = self._scan_capture_secrets(
            capture_root, trace_paths=trace_paths,
            finding_limit=capture_config.secret_finding_count_limit,
            argv=argv, environment=capture_environment, raw_traces=raw_traces)
        record_argv = (["<redacted: secret detected by gitleaks>"]
                       if secret_scan.pop("redact_invocation", False) else argv)
        # The inventory reads the sanitized events, so redacted paths never reach it.
        current_snapshot = None
        if snapshot_files is not None:
            current_snapshot = {}
            for relative, known in snapshot_files.items():
                host = root / Path(*PurePosixPath(relative).parts)
                try:
                    stat = host.stat()
                except OSError:
                    continue
                if stat.st_size == known.get("size_bytes") and stat.st_mtime_ns == known.get("mtime_ns"):
                    current_snapshot[relative] = known
        inventory = build_file_inventory(
            read_events(capture_root / "events.jsonl"), roots, capture_root / "files.jsonl",
            snapshot=current_snapshot, count_limit=capture_config.file_inventory_count_limit)
        record = recorder.finish(
            argv=record_argv, working_directory=working_directory, exit_code=code, timed_out=timed_out,
            stdout_path=stdout_path, stderr_path=stderr_path, collector_errors=parse_errors,
            secret_scan=secret_scan, file_inventory=inventory,
            response_files=(response_files, response_gaps),
            raw_traces=raw_traces if raw_traces is not None else {"enabled": False})
        # The driver's TMPDIR only had to outlive the response-file snapshot taken above.
        for scratch in (root / Path(*PurePosixPath(working_directory).parts)).glob(
                ".appsec-review-build-scratch.*"):
            if scratch.is_dir() and not scratch.is_symlink():
                shutil.rmtree(scratch, ignore_errors=True)
        stdout_size, stderr_size = stdout_path.stat().st_size, stderr_path.stat().st_size
        with stdout_path.open("rb") as stream:
            retained_stdout = stream.read(self.output_bytes)
        with stderr_path.open("rb") as stream:
            retained_stderr = stream.read(self.output_bytes)
        stdout_truncated, stderr_truncated = stdout_size > len(retained_stdout), stderr_size > len(retained_stderr)
        tail_bytes = min(32768, self.output_bytes)
        def tail(path: Path, size: int) -> bytes:
            if size <= 0:
                return b""
            with path.open("rb") as stream:
                stream.seek(max(0, path.stat().st_size - size))
                return stream.read()
        return BuildCommandResult(
            tuple(argv), code, retained_stdout, retained_stderr, timed_out,
            stdout_bytes=stdout_size, stderr_bytes=stderr_size,
            stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
            stdout_tail=tail(stdout_path, tail_bytes) if stdout_truncated else b"",
            stderr_tail=tail(stderr_path, tail_bytes) if stderr_truncated else b"",
            capture_record=record, stdout_file=stdout_path, stderr_file=stderr_path,
        )

    @staticmethod
    def _take_tool_call_ownership(capture_root: Path) -> None:
        """Replace the completed container-owned wrapper subtree with a host-owned copy."""
        tool_root = capture_root / "tool-calls"
        if not tool_root.is_dir():
            return
        # This copy is disposable and can live above the deep command directory. Keeping it
        # here also leaves enough path budget for compiler names on Windows hosts.
        staging = capture_root.parent.parent / f".host-{capture_root.name}"
        shutil.copytree(tool_root, staging)
        shutil.rmtree(tool_root)
        staging.chmod(0o700)
        shutil.copytree(staging, tool_root)
        shutil.rmtree(staging)
        for path in (tool_root, *tool_root.rglob("*")):
            path.chmod(0o700 if path.is_dir() else 0o600)

    @staticmethod
    def _digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def _scan_capture_secrets(self, capture_root: Path, *, trace_paths: Sequence[Path],
                              finding_limit: int, argv: Sequence[str],
                              environment: Mapping[str, str],
                              raw_traces: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Scan raw argv/envp and retained streams, then remove raw syscall material."""
        # Keep the disposable mirror beside ``execution-capture`` rather than beneath the
        # already-deep command directory.  Language-build paths can otherwise cross the
        # legacy Windows MAX_PATH limit before a tool-call filename is appended.
        scan_input = capture_root.parent.parent / f".scan-{capture_root.name}"
        scan_root = capture_root / "secret-scan"
        scan_input.mkdir()
        scan_root.mkdir()
        persistent: dict[str, Path] = {}

        def retain(source: Path, relative: str, *, sanitize: bool) -> None:
            target = scan_input / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o644)
            if sanitize:
                persistent[relative] = source

        for trace in trace_paths:
            if trace.is_file():
                retain(trace, f"syscalls/{trace.name}", sanitize=False)
        # Retained raw traces are scanned in full above; a finding anywhere in a trace redacts
        # its retained (possibly truncated) copy through the same disposition path.
        for item in (raw_traces or {}).get("records", ()):
            if item.get("retained"):
                persistent[f"syscalls/{item['source']}"] = capture_root / str(item["uri"])
        for name in ("stdout", "stderr"):
            retain(capture_root / name, f"streams/{name}", sanitize=True)
        retain(capture_root / "events.jsonl", "events.jsonl", sanitize=True)
        atomic_json(scan_input / "invocation.json",
                    {"argv": list(argv), "environment": dict(environment)})
        (scan_input / "invocation.json").chmod(0o644)
        response_root = capture_root / "response-files"
        if response_root.is_dir():
            for source in sorted(response_root.iterdir()):
                if source.is_file():
                    retain(source, f"response-files/{source.name}", sanitize=True)
        tool_root = capture_root / "tool-calls"
        if tool_root.is_dir():
            for source in tool_root.rglob("*"):
                if source.is_file():
                    relative = "tool-calls/" + source.relative_to(tool_root).as_posix()
                    retain(source, relative, sanitize=True)

        repository_root = _application_root("containers/catalog.toml")
        tool = load_catalog(repository_root).tool("tool-gitleaks")
        report = scan_root / "gitleaks.json"
        stdout_path, stderr_path = scan_root / "stdout", scan_root / "stderr"
        execution_path, findings_path = scan_root / "execution.json", scan_root / "findings.json"
        gap: str | None = None
        findings: list[dict[str, Any]] = []
        capped = False
        redact_invocation = False
        scan_code: int | None = None
        scan_timed_out = False

        def redact_source(source: Path, line_number: int | None = None) -> None:
            if source.name == "events.jsonl":
                rows = source.read_text(encoding="utf-8").splitlines()
                selected = ([line_number - 1] if line_number is not None and 0 < line_number <= len(rows)
                            else range(len(rows)))
                for index in selected:
                    event = json.loads(rows[index])
                    if event.get("kind") != "process_exec":
                        for name in PATH_FIELDS:
                            if name in event:
                                event[name] = "<redacted: secret scan disposition>"
                        rows[index] = canonical_json(event).decode().rstrip("\n")
                        continue
                    if event.get("kind") != "process_exec":
                        continue
                    event["argv"] = ["<redacted: secret scan disposition>"]
                    if "executable" in event:
                        event["executable"] = "<redacted: secret scan disposition>"
                    for entry in event.get("envp", []):
                        entry["value"] = "<redacted: secret scan disposition>"
                        entry["redacted"] = True
                    rows[index] = canonical_json(event).decode().rstrip("\n")
                source.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
                return
            if source.name == "record.json":
                document = json.loads(source.read_text(encoding="utf-8"))
                document["argv"] = ["<redacted: secret scan disposition>"]
                document["environment"] = {
                    key: "<redacted: secret scan disposition>"
                    for key in document.get("environment", {})}
                atomic_json(source, document)
                return
            source.write_text("<redacted: secret scan disposition>\n", encoding="utf-8")
            if source.name not in {"stdout", "stderr"} or source.parent == capture_root:
                return
            tool_record = source.parent / "record.json"
            if not tool_record.is_file():
                return
            document = json.loads(tool_record.read_text(encoding="utf-8"))
            stream = document.get(source.name)
            if isinstance(stream, dict):
                stream.update({"sha256": self._digest(source),
                               "retained_bytes": source.stat().st_size,
                               "redacted": True})
                atomic_json(tool_record, document)

        try:
            code, image_stdout, image_stderr, inspect_timeout = self.runner(
                ("docker", "image", "inspect", tool.tag, "--format", "{{.Id}}"), 60)
            image_id = image_stdout.decode("utf-8", "replace").strip()
            if (inspect_timeout or code != 0 or
                    not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or
                    (tool.expected_image_id is not None and image_id != tool.expected_image_id)):
                raise RuntimeError("pinned gitleaks image is unavailable or changed")
            scan_root.chmod(0o777)
            runtime_user = application_runtime_user(tool.user)
            command = [
                "docker", "run", "--rm", "--name", _container_name(), "--network", "none", "--read-only",
                "--user", runtime_user, "--cap-drop", "ALL", "--security-opt",
                "no-new-privileges", "--cpus", tool.cpus, "--memory", tool.memory,
                "--pids-limit", str(tool.pids_limit), "--tmpfs", "/tmp:rw,noexec,nosuid,size=1g",
                "--workdir", "/target", "--mount",
                f"type=bind,src={self._bind_source(scan_input)},dst=/target,readonly", "--mount",
                f"type=bind,src={self._bind_source(scan_root)},dst=/scratch",
                "--entrypoint", tool.executable, image_id, "dir", "/target", "--no-banner",
                "--redact=100", "--report-format", "json", "--report-path",
                "/scratch/gitleaks.json", "--exit-code", "1",
            ]
            try:
                with reserve_execution(cpu=tool.cpus, memory=tool.memory, action="build.capture_secret_scan",
                                       timeout_seconds=tool.timeout_seconds), self._container(command):
                    code, stdout, stderr, timed_out = self.runner(command, tool.timeout_seconds)
                    self._stop_on_timeout(command, timed_out)
            finally:
                scan_root.chmod(0o755)  # gitleaks wrote its report; close its write window
            scan_code, scan_timed_out = code, timed_out
            stdout_path.write_bytes(stdout[:tool.output_bytes])
            stderr_path.write_bytes(stderr[:tool.output_bytes])
            if timed_out or code not in {0, 1} or not report.is_file():
                # No trustworthy result set exists, so nothing below may be retained unredacted.
                raise RuntimeError("scanner timed out" if timed_out else
                                   f"scanner exited {code}" if code not in {0, 1} else
                                   "scanner wrote no report")
            loaded = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(loaded, list):
                raise ValueError("gitleaks report is not an array")
            raw_findings: list[object] = loaded
            capped = len(raw_findings) > finding_limit
            for item in raw_findings:
                if not isinstance(item, Mapping):
                    continue
                relative = str(item.get("File", "")).removeprefix("/target/")
                identity = str(item.get("Fingerprint") or hashlib.sha256(
                    json.dumps([item.get("RuleID"), relative, item.get("StartLine")],
                               separators=(",", ":")).encode()).hexdigest())
                if len(findings) < finding_limit:
                    findings.append({
                        "finding_id": identity, "rule_id": str(item.get("RuleID", "gitleaks")),
                        "description": str(item.get("Description", "potential secret")),
                        "source": relative, "start_line": int(item.get("StartLine") or 1),
                        "end_line": int(item.get("EndLine") or item.get("StartLine") or 1),
                        "secret_redacted": True,
                    })
                source = persistent.get(relative)
                if relative == "invocation.json":
                    redact_invocation = True
                if source is None:
                    continue
                redact_source(source, max(1, int(item.get("StartLine") or 1)))
            if capped:
                gap = "gitleaks capture finding retention limit reached"
            # The scanner's native report is not itself trusted to honor redaction flags.
            # Retain only the bounded, normalized finding metadata below.
            atomic_json(report, findings)
            atomic_json(findings_path, {
                "schema": "appsec-review/build-capture-secret-findings/1",
                "scanner": {"tool_id": tool.tool_id, "version": tool.version,
                            "image_id": image_id},
                "observed": len(raw_findings), "retained": len(findings), "capped": capped,
                "findings": findings,
            })
            atomic_json(execution_path, {
                "schema": "appsec-review/build-capture-secret-scan-execution/1",
                "tool_id": tool.tool_id, "version": tool.version, "image_id": image_id,
                "exit_code": code, "timed_out": timed_out,
                "stdout": {"uri": "stdout", "sha256": self._digest(stdout_path)},
                "stderr": {"uri": "stderr", "sha256": self._digest(stderr_path)},
                "report": {"uri": "gitleaks.json", "sha256": self._digest(report)}
                if report.is_file() else None,
            })
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            gap = f"gitleaks capture scan failed: {exc}"
            redact_invocation = True
            for source in sorted(set(persistent.values()),
                                 key=lambda path: path.name == "record.json"):
                redact_source(source)
            stdout_path.touch(exist_ok=True)
            stderr_path.touch(exist_ok=True)
            if report.exists():
                atomic_json(report, [])
            atomic_json(findings_path, {
                "schema": "appsec-review/build-capture-secret-findings/1",
                "scanner": {"tool_id": "tool-gitleaks"}, "observed": 0,
                "retained": 0, "capped": False, "findings": [],
            })
            atomic_json(execution_path, {
                "schema": "appsec-review/build-capture-secret-scan-execution/1",
                "tool_id": "tool-gitleaks", "exit_code": scan_code, "timed_out": scan_timed_out,
                "stdout": {"uri": "stdout", "sha256": self._digest(stdout_path)},
                "stderr": {"uri": "stderr", "sha256": self._digest(stderr_path)},
                "report": None,
            })
        finally:
            shutil.rmtree(scan_input, ignore_errors=True)
            for trace in trace_paths:
                trace.unlink(missing_ok=True)
        result = {
            "scanner": "tool-gitleaks",
            "findings": {"uri": findings_path.relative_to(capture_root).as_posix(),
                         "sha256": self._digest(findings_path), "count": len(findings),
                         "capped": capped},
            "execution": {"uri": execution_path.relative_to(capture_root).as_posix(),
                          "sha256": self._digest(execution_path)},
        }
        if gap:
            result["coverage_gap"] = gap
        result["redact_invocation"] = redact_invocation
        return result

    def prepare_node_dependencies(self, *, workspace: Path, source_dir: str,
                                  dependency_root: str | None = None) -> None:
        """Expose image-owned node_modules at the writable target source root."""
        logical = PurePosixPath(source_dir)
        if source_dir != "." and (logical.is_absolute() or ".." in logical.parts):
            raise ValueError("Node source directory is not normalized")
        dependency_logical = PurePosixPath(dependency_root or source_dir)
        if dependency_logical.is_absolute() or ".." in dependency_logical.parts:
            raise ValueError("Node dependency root is not normalized")
        image_dependency_root = ("/opt/project/node_modules" if dependency_logical.as_posix() == "." else
                                 f"/opt/project/{dependency_logical.as_posix()}/node_modules")
        links = [(source_dir, image_dependency_root)]
        if dependency_logical.as_posix() != logical.as_posix():
            # A workspace (or ancestor-locked) unit: the restore installed one tree at the
            # dependency root. Mirror its layout so Node resolution walks the unit's own
            # node_modules (pnpm and non-hoisted members keep dependencies there; the image
            # layout step creates it) and then the root's hoisted node_modules.
            links = [(dependency_logical.as_posix(), image_dependency_root),
                     (source_dir, "/opt/project/node_modules" if logical.as_posix() == "." else
                      f"/opt/project/{logical.as_posix()}/node_modules")]
        for directory, image_path in links:
            result = self.execute(("ln", "-s", image_path, "node_modules"),
                                  workspace=workspace, working_directory=directory, environment={})
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
