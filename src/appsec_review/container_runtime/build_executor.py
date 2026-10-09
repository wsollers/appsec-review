from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
from typing import Any

from appsec_review.config import BuildCaptureConfig
from appsec_review.storage import atomic_json, canonical_json
from .catalog import load_catalog
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

    def _make_workspace_writable(self, root: Path) -> None:
        """Grant the fixed non-root container identity access to the run-owned source copy."""
        container_uid = int(self.profile.user.split(":", 1)[0])
        for path in (root, *root.rglob("*")):
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            try:
                if path.is_dir():
                    path.chmod(mode | 0o007)
                elif path.is_file():
                    path.chmod(mode | 0o006)
            except PermissionError:
                if path.stat().st_uid != container_uid:
                    raise

    def _prepare(self, *, workspace: Path, working_directory: str,
                 environment: Mapping[str, str]) -> tuple[Path, list[str]]:
        root = workspace.resolve(strict=True)
        relative_workdir = Path(*working_directory.split("/"))
        resolved_workdir = (root / relative_workdir).resolve(strict=True)
        if root != resolved_workdir and root not in resolved_workdir.parents:
            raise ValueError("build working directory escaped the run-owned workspace")
        self._make_workspace_writable(root)
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
        recorder = BuildExecutionRecorder(
            capture_root, scope, capture_config,
            {"backend": "ptrace", "tool": "strace", "image_id": self.profile.image_id,
             "event_kinds": sorted(("process_fork", "process_exec", "process_exit",
                                    "file_open", "connect"))},
        )
        driver = capture_root / "build-driver.sh"
        # Host and non-root container IDs differ; only this new run-owned leaf is shared.
        capture_root.chmod(0o733)

        source_driver = Path(__file__).resolve().parents[3] / "containers" / "build-capture" / "build-driver.sh"
        driver.write_bytes(source_driver.read_bytes())
        wrapper = capture_root / "tool-wrapper.py"
        source_wrapper = source_driver.with_name("tool-wrapper.py")
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
                        str(capture_config.tool_call_count_limit),
                        str(capture_config.tool_stream_bytes_limit), logical_wrappers,
                        "1" if capture_config.capture_envp else "0", *argv))
        code, stdout, stderr, timed_out = self.runner(command, self.timeout_seconds)
        stdout_path, stderr_path = capture_root / "stdout", capture_root / "stderr"
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        trace_paths = tuple(capture_root.glob("trace*"))
        parse_errors = record_strace_files(trace_paths, recorder)
        recorder.flush()
        secret_scan = self._scan_capture_secrets(
            capture_root, trace_paths=trace_paths,
            finding_limit=capture_config.secret_finding_count_limit,
            argv=argv, environment=capture_environment)
        record_argv = (["<redacted: secret detected by gitleaks>"]
                       if secret_scan.pop("redact_invocation", False) else argv)
        record = recorder.finish(
            argv=record_argv, working_directory=working_directory, exit_code=code, timed_out=timed_out,
            stdout_path=stdout_path, stderr_path=stderr_path, collector_errors=parse_errors,
            secret_scan=secret_scan)
        retained_stdout, retained_stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
        stdout_truncated, stderr_truncated = len(stdout) > self.output_bytes, len(stderr) > self.output_bytes
        tail_bytes = min(32768, self.output_bytes)
        return BuildCommandResult(
            tuple(argv), code, retained_stdout[:self.output_bytes], retained_stderr[:self.output_bytes], timed_out,
            stdout_bytes=len(stdout), stderr_bytes=len(stderr),
            stdout_truncated=stdout_truncated, stderr_truncated=stderr_truncated,
            stdout_tail=retained_stdout[-tail_bytes:] if stdout_truncated else b"",
            stderr_tail=retained_stderr[-tail_bytes:] if stderr_truncated else b"",
            capture_record=record,
        )

    @staticmethod
    def _digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def _scan_capture_secrets(self, capture_root: Path, *, trace_paths: Sequence[Path],
                              finding_limit: int, argv: Sequence[str],
                              environment: Mapping[str, str]) -> dict[str, Any]:
        """Scan raw argv/envp and retained streams, then remove raw syscall material."""
        scan_input = capture_root / ".secret-scan-input"
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
        for name in ("stdout", "stderr"):
            retain(capture_root / name, f"streams/{name}", sanitize=True)
        retain(capture_root / "events.jsonl", "events.jsonl", sanitize=True)
        atomic_json(scan_input / "invocation.json",
                    {"argv": list(argv), "environment": dict(environment)})
        (scan_input / "invocation.json").chmod(0o644)
        tool_root = capture_root / "tool-calls"
        if tool_root.is_dir():
            for source in tool_root.rglob("*"):
                if source.is_file():
                    relative = "tool-calls/" + source.relative_to(tool_root).as_posix()
                    retain(source, relative, sanitize=True)

        repository_root = Path(__file__).resolve().parents[3]
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
                    if event.get("kind") == "file_open":
                        event["path"] = "<redacted: secret scan disposition>"
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
            command = [
                "docker", "run", "--rm", "--network", "none", "--read-only",
                "--user", tool.user, "--cap-drop", "ALL", "--security-opt",
                "no-new-privileges", "--cpus", tool.cpus, "--memory", tool.memory,
                "--pids-limit", str(tool.pids_limit), "--tmpfs", "/tmp:rw,noexec,nosuid,size=1g",
                "--workdir", "/target", "--mount",
                f"type=bind,src={self._bind_source(scan_input)},dst=/target,readonly", "--mount",
                f"type=bind,src={self._bind_source(scan_root)},dst=/scratch",
                "--entrypoint", tool.executable, image_id, "dir", "/target", "--no-banner",
                "--redact=100", "--report-format", "json", "--report-path",
                "/scratch/gitleaks.json", "--exit-code", "1",
            ]
            code, stdout, stderr, timed_out = self.runner(command, tool.timeout_seconds)
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
