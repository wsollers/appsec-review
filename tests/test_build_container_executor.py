from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time

import pytest

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.container_runtime.build_executor import _run


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
