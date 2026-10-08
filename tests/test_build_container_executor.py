from __future__ import annotations

import json
from pathlib import Path

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile


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
    assert ("--network", "none") == command[command.index("--network"):command.index("--network") + 2]
    assert command[command.index("--entrypoint") + 1:] == (
        "cargo", image_id, "build", "--locked")
    assert command[command.index("--workdir") + 1] == "/workspace/project"
    assert not {"sh", "bash", "cmd", "powershell"} & set(command)
    assert result.exit_code == 0 and result.stdout == b"built"
