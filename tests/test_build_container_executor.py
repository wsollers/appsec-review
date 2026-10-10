from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from appsec_review.config import BuildCaptureConfig
from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile, CaptureScope
from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.container_runtime.build_executor import _application_root, _capture_asset, _run
from tests.capture_fakes import SYNTHETIC_SECRET, secret_scanner, simulated_executor


def test_tool_wrapper_retains_complete_stream_files_beyond_legacy_limit(
        tmp_path: Path) -> None:
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "envp-redact-names.json").write_text("[]\n", encoding="utf-8")
    tools = tmp_path / "tools"
    tools.mkdir()
    noisy = tools / "noisy"
    noisy.write_text(
        "#!/bin/sh\nprintf 'abcdefghijklmnop'\nprintf 'qrstuvwxyz' >&2\n",
        encoding="utf-8",
    )
    noisy.chmod(0o755)
    wrapper = Path(__file__).parents[1] / "containers" / "build-capture" / "tool-wrapper.py"
    environment = {
        **os.environ,
        "APPSEC_CAPTURE_ROOT": str(capture),
        "APPSEC_CAPTURE_CALL_LIMIT": "10",
        "APPSEC_CAPTURE_STREAM_LIMIT": "8",
        "APPSEC_CAPTURE_REAL_PATH": str(tools),
        "APPSEC_CAPTURE_ENVP": "1",
    }

    completed = subprocess.run(
        [sys.executable, str(wrapper), "noisy"], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )

    call = capture / "tool-calls" / "00000001-noisy"
    assert completed.stdout == (call / "stdout").read_bytes() == b"abcdefghijklmnop"
    assert completed.stderr == (call / "stderr").read_bytes() == b"qrstuvwxyz"
    record = json.loads((call / "record.json").read_text(encoding="utf-8"))
    assert record["stdout"]["retained_bytes"] == record["stdout"]["bytes"] == 16
    assert record["stderr"]["retained_bytes"] == record["stderr"]["bytes"] == 10
    assert record["stdout"]["storage"] == record["stderr"]["storage"] == "complete-file"
    assert record["stdout"]["truncated"] is record["stderr"]["truncated"] is False


def test_capture_assets_resolve_from_configured_installed_application_root(
        tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "installed-app"
    asset = root / "containers" / "build-capture" / "build-driver.sh"
    asset.parent.mkdir(parents=True)
    asset.write_text("#!/bin/sh\n", encoding="utf-8")
    config = root / "appsec-review.toml"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(config))
    assert _capture_asset("build-driver.sh") == asset


def test_container_catalog_resolves_from_configured_installed_application_root(
        tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "installed-app"
    catalog = root / "containers" / "catalog.toml"
    catalog.parent.mkdir(parents=True)
    catalog.write_text("schema_version = 1\n", encoding="utf-8")
    config = root / "appsec-review.toml"
    config.write_text("", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(config))
    assert _application_root("containers/catalog.toml") == root


def test_build_executor_pins_image_and_runs_argv_without_shell(tmp_path: Path) -> None:
    image_id = "sha256:" + "a" * 64
    calls = []

    def runner(argv, timeout):
        calls.append((tuple(argv), timeout))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, image_id.encode(), b"", False
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        return 0, b"built", b"", False

    profile = BuildProfile("rust", "build-rust:local", image_id, "10001:10001")
    executor = BuildContainerExecutor(profile, timeout_seconds=90, output_bytes=1024, runner=runner)
    executor.resolve()
    project = tmp_path / "project"
    project.mkdir()
    result = executor.execute(("cargo", "build", "--locked"), workspace=tmp_path,
                              working_directory="project",
                              environment={"RUSTFLAGS": "-C debuginfo=2"})
    command = calls[-1][0]
    assert ("--network", "bridge") == command[command.index("--network"):command.index("--network") + 2]
    assert command[command.index("--entrypoint") + 1:] == (
        "cargo", image_id, "build", "--locked")
    assert command[command.index("--workdir") + 1] == "/workspace/project"
    assert not {"sh", "bash", "cmd", "powershell"} & set(command)
    assert result.exit_code == 0 and result.stdout == b"built"


def test_build_executor_exposes_image_owned_node_modules(tmp_path: Path) -> None:
    image_id = "sha256:" + "b" * 64
    calls = []

    def runner(argv, timeout):
        calls.append((tuple(argv), timeout))
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        return 0, b"", b"", False

    workspace = tmp_path / "workspace"
    (workspace / "projects" / "typescript" / "sample").mkdir(parents=True)
    executor = BuildContainerExecutor(
        BuildProfile("node", "build-node:local", image_id, "10001:10001"),
        timeout_seconds=90, output_bytes=1024, runner=runner)
    executor.prepare_node_dependencies(
        workspace=workspace, source_dir="projects/typescript/sample")
    command = calls[-1][0]
    assert command[command.index("--entrypoint") + 1:] == (
        "ln", image_id, "-s", "/opt/project/projects/typescript/sample/node_modules",
        "node_modules")
    assert "--read-only" in command
    assert command[command.index("--network") + 1] == "bridge"


def test_build_executor_uses_in_container_driver_for_bounded_syscall_capture(tmp_path: Path) -> None:
    image_id = "sha256:" + "c" * 64
    synthetic_secret = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"
    gitleaks_image_id = load_catalog(Path(__file__).parents[1]).tool("tool-gitleaks").expected_image_id
    workspace = tmp_path / "workspace"
    (workspace / "native").mkdir(parents=True)
    capture = workspace / ".capture" / "command-1"
    calls = []

    def runner(argv, timeout):
        calls.append((tuple(argv), timeout))
        if argv[:3] == ("docker", "image", "inspect"):
            resolved = (gitleaks_image_id or "sha256:" + "d" * 64) if "gitleaks" in argv[3] else image_id
            return 0, str(resolved).encode(), b"", False
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        if "--report-path" in argv:
            scratch_spec = argv[argv.index("--mount", argv.index("--mount") + 1) + 1]
            scratch = Path(scratch_spec.split("src=", 1)[1].split(",dst=", 1)[0])
            (scratch / "gitleaks.json").write_text(json.dumps([
                {"RuleID": "discord-api-token", "Description": "synthetic secret",
                 "File": "/target/events.jsonl", "StartLine": 1, "EndLine": 1,
                 "Match": "REDACTED", "Secret": "REDACTED", "Fingerprint": "events:1"},
                {"RuleID": "discord-api-token", "Description": "synthetic secret",
                 "File": "/target/invocation.json", "StartLine": 1, "EndLine": 1,
                 "Match": "REDACTED", "Secret": "REDACTED", "Fingerprint": "invocation:1"},
            ]) + "\n", encoding="utf-8")
            return 1, b"", b"", False
        (capture / "trace.7").write_text(
            f'1700000000.0 execve("/usr/bin/clang++", ["clang++"], '
            f'["SECRET_INPUT={synthetic_secret}"]) = 0\n'
            '1700000000.1 exit_group(0) = ?\n', encoding="utf-8")
        return 0, b"b" * 2048, b"", False

    executor = BuildContainerExecutor(
        BuildProfile("native", "build-native:local", image_id, "10001:10001"),
        timeout_seconds=90, output_bytes=1024, runner=runner)
    result = executor.execute_captured(
        ("clang++", "main.cpp", "-o", "app"), workspace=workspace,
        working_directory="native", environment={"SECRET_INPUT": synthetic_secret},
        capture_directory=capture,
        capture_config=BuildCaptureConfig(
            "ptrace", 100, 32, 4096, True, 128, 16384, (), 1024, 100, 100),
        scope=CaptureScope("2026-10-09-0001", "job_project_build", "attempt_0001",
                           "build-unit-cpp", "native"))
    command = next(call[0] for call in calls if "/bin/sh" in call[0])
    assert command[command.index("--network") + 1] == "bridge"
    assert command[command.index("--entrypoint") + 1] == "/bin/sh"
    assert command[-4:] == ("clang++", "main.cpp", "-o", "app")
    assert result.capture_record == capture / "record.json"
    assert result.stdout == b"b" * 1024 and result.stdout_truncated is True
    assert result.stdout_file == capture / "stdout"
    assert result.stdout_file.read_bytes() == b"b" * 2048
    record = json.loads(result.capture_record.read_text())
    assert record["collector"]["backend"] == "ptrace"
    assert record["secret_scan"]["scanner"] == "tool-gitleaks"
    assert record["coverage"] == {"complete": True, "gaps": []}
    assert record["secret_scan"]["findings"]["count"] == 2
    assert record["command"]["argv"] == ["<redacted: secret detected by gitleaks>"]
    assert synthetic_secret not in "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in capture.rglob("*") if path.is_file())
    assert not tuple(capture.glob("trace*"))


def test_capture_secret_scan_failure_redacts_retained_inputs_and_records_gap(tmp_path: Path) -> None:
    synthetic_secret = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"
    capture = tmp_path / "capture"
    tool_call = capture / "tool-calls" / "00000001-clang"
    tool_call.mkdir(parents=True)
    trace = capture / "trace.7"
    trace.write_text(f'DISCORD_PUBLIC_KEY={synthetic_secret}\n', encoding="utf-8")
    (capture / "stdout").write_text(synthetic_secret, encoding="utf-8")
    (capture / "stderr").write_bytes(b"")
    (capture / "events.jsonl").write_text(json.dumps({
        "kind": "process_exec", "argv": [synthetic_secret],
        "envp": [{"name": "DISCORD_PUBLIC_KEY", "value": synthetic_secret,
                  "redacted": False}],
    }) + "\n", encoding="utf-8")
    (tool_call / "stdout").write_text(synthetic_secret, encoding="utf-8")
    (tool_call / "stderr").write_bytes(b"")
    (tool_call / "record.json").write_text(json.dumps({
        "schema": "appsec-review/build-tool-call/1", "argv": [synthetic_secret],
        "environment": {"DISCORD_PUBLIC_KEY": synthetic_secret},
        "stdout": {"uri": "stdout", "sha256": hashlib.sha256(
            synthetic_secret.encode()).hexdigest(), "retained_bytes": len(synthetic_secret)},
        "stderr": {"uri": "stderr", "sha256": hashlib.sha256(b"").hexdigest(),
                   "retained_bytes": 0},
    }) + "\n", encoding="utf-8")

    def unavailable(_argv, _timeout):
        return 1, b"", b"not available", False

    executor = BuildContainerExecutor(
        BuildProfile("native", "build-native:local", "sha256:" + "c" * 64, "10001:10001"),
        timeout_seconds=90, output_bytes=1024, runner=unavailable)
    result = executor._scan_capture_secrets(
        capture, trace_paths=(trace,), finding_limit=10, argv=("clang", synthetic_secret),
        environment={"DISCORD_PUBLIC_KEY": synthetic_secret})
    assert result["redact_invocation"] is True
    assert "gitleaks capture scan failed" in result["coverage_gap"]
    assert synthetic_secret not in "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in capture.rglob("*") if path.is_file())
    retained_call = json.loads((tool_call / "record.json").read_text(encoding="utf-8"))
    assert retained_call["stdout"]["sha256"] == hashlib.sha256(
        (tool_call / "stdout").read_bytes()).hexdigest()
    assert not trace.exists()


def _leaking_capture(tmp_path: Path, scanner, *, finding_limit: int = 100):
    workspace = tmp_path / "workspace"
    (workspace / "unit").mkdir(parents=True)

    def behavior(_argv, _workspace, _directory, environment, container):
        container.exec("/usr/bin/rustc", ["rustc", f"--cfg=key={SYNTHETIC_SECRET}"])
        container.open(f"/workspace/unit/{SYNTHETIC_SECRET}.rs")
        container.tool_call("rustc", [f"--cfg=key={SYNTHETIC_SECRET}"], executable="/usr/bin/rustc",
                            stderr=SYNTHETIC_SECRET.encode())
        return 0, SYNTHETIC_SECRET.encode(), b""

    executor = simulated_executor(
        BuildProfile("rust", "build-rust:local", "sha256:" + "c" * 64, "10001:10001"), behavior,
        scanner=scanner)
    capture = tmp_path / "capture"
    result = executor.execute_captured(
        ("cargo", "build"), workspace=workspace, working_directory="unit",
        environment={"UNLISTED_NAME": SYNTHETIC_SECRET}, capture_directory=capture,
        capture_config=BuildCaptureConfig(
            "ptrace", 100, 32, 4096, True, 128, 16384, (), 1024, 100, finding_limit),
        scope=CaptureScope("2026-10-09-0001", "job_language_build", "attempt_0001",
                           "build-unit-rust", "rust"))
    return capture, result, json.loads(result.capture_record.read_text(encoding="utf-8"))


def _capture_text(capture: Path) -> str:
    return "".join(path.read_text(encoding="utf-8", errors="replace")
                   for path in capture.rglob("*") if path.is_file())


@pytest.mark.parametrize("outcome", ["exit", "timeout", "no-report", "invalid-report"])
def test_capture_scanner_failure_modes_all_fail_closed(tmp_path: Path, outcome: str) -> None:
    def scanner(target: Path, scratch: Path):
        # Even a scanner that produced a plausible report before failing is not trusted.
        secret_scanner()(target, scratch)
        if outcome == "exit":
            return 2, b"", b"crashed", False
        if outcome == "timeout":
            return None, b"", b"", True
        if outcome == "no-report":
            (scratch / "gitleaks.json").unlink()
            return 1, b"", b"", False
        (scratch / "gitleaks.json").write_text("{}", encoding="utf-8")
        return 1, b"", b"", False

    capture, result, record = _leaking_capture(tmp_path, scanner)
    assert record["coverage"]["complete"] is False
    assert any(gap.startswith("gitleaks capture scan failed") for gap in record["coverage"]["gaps"])
    assert record["secret_scan"]["findings"]["count"] == 0
    assert record["command"]["argv"] == ["<redacted: secret detected by gitleaks>"]
    retained = _capture_text(capture)
    assert SYNTHETIC_SECRET not in retained and SYNTHETIC_SECRET.encode() not in result.stdout
    assert not tuple(capture.glob("trace*")) and not (capture / ".secret-scan-input").exists()
    execution = json.loads((capture / "secret-scan" / "execution.json").read_text(encoding="utf-8"))
    assert execution["report"] is None
    assert execution["timed_out"] is (outcome == "timeout")


def test_capture_finding_cap_limits_retained_findings_but_not_sanitization(tmp_path: Path) -> None:
    capture, result, record = _leaking_capture(tmp_path, secret_scanner(), finding_limit=1)
    findings = json.loads((capture / "secret-scan" / "findings.json").read_text(encoding="utf-8"))
    assert findings["observed"] > 1 and findings["retained"] == 1 and findings["capped"] is True
    assert record["coverage"]["gaps"] == ["gitleaks capture finding retention limit reached"]
    assert SYNTHETIC_SECRET not in _capture_text(capture)
    assert SYNTHETIC_SECRET.encode() not in result.stdout
    events = [json.loads(line) for line in (capture / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert next(event for event in events if event["kind"] == "file_open")["path"].startswith("<redacted")
    assert next(event for event in events if event["kind"] == "process_exec")["executable"].startswith(
        "<redacted")


@pytest.mark.skipif(os.name != "posix", reason="process-session cleanup is used by the Linux deployment")
def test_default_runner_timeout_releases_descendants_holding_capture_pipes() -> None:
    script = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "print('started', flush=True); time.sleep(30)"
    )
    started = time.monotonic()
    code, stdout, _stderr, timed_out = _run((sys.executable, "-c", script), 1)
    assert timed_out and code is None and b"started" in stdout
    assert time.monotonic() - started < 8
