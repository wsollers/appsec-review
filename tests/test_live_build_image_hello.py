"""Small real-container probes for every centrally configured build profile.

Run explicitly on each host with a unique ``--basetemp=test/tmp/<host>``.  The
workspace and capture are bind mounted by BuildContainerExecutor, as in a review.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import (
    BuildContainerExecutor, CaptureScope, profiles_from_settings, verify_capture_record,
)
from appsec_review.container_runtime.build_executor import _run


ROOT = Path(__file__).parents[1]
HELLO = "Hello World"


@dataclass(frozen=True)
class HelloCase:
    profile: str
    files: dict[str, str]
    commands: tuple[tuple[str, ...], ...]
    artifact: str | None = None
    output_command: tuple[str, ...] | None = None
    environment: tuple[tuple[str, str], ...] = ()


CASES = (
    HelloCase("native", {"hello.cpp": '#include <iostream>\nint main() { std::cout << "Hello World\\n"; }\n'},
              (("c++", "hello.cpp", "-o", "hello"),), "hello", ("./hello",)),
    HelloCase("rust", {"hello.rs": 'fn main() { println!("Hello World"); }\n'},
              (("rustc", "hello.rs", "-o", "hello"),), "hello", ("./hello",)),
    HelloCase("go", {"hello.go": 'package main\nimport "fmt"\nfunc main() { fmt.Println("Hello World") }\n'},
              (("go", "build", "-o", "hello", "hello.go"),), "hello", ("./hello",),
              (("GOCACHE", "/tmp/go-cache"),)),
    HelloCase("java", {"Hello.java": 'class Hello { public static void main(String[] a) { System.out.println("Hello World"); } }\n'},
              (("javac", "Hello.java"),), "Hello.class", ("java", "Hello")),
    HelloCase("node", {"hello.js": 'console.log("Hello World");\n',
                       "package.json": '{"name":"hello-capture","version":"1.0.0","scripts":{"hello":"node hello.js"}}\n'},
              (("npm", "run", "hello"),)),
    HelloCase("dotnet", {"hello.csproj": '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net9.0</TargetFramework><UseAppHost>false</UseAppHost></PropertyGroup></Project>\n',
                         "Program.cs": 'System.Console.WriteLine("Hello World");\n'},
              (("dotnet", "build", "hello.csproj", "-p:NuGetAudit=false", "--verbosity", "quiet"),),
              "bin/Debug/net9.0/hello.dll", ("dotnet", "bin/Debug/net9.0/hello.dll"),
              (("DOTNET_CLI_HOME", "/tmp/dotnet"), ("NUGET_PACKAGES", "/tmp/nuget"))),
    HelloCase("python", {"hello.py": 'print("Hello World")\n'}, (("python", "hello.py"),)),
    HelloCase("php", {"hello.php": '<?php echo "Hello World\\n";\n'}, (("php", "hello.php"),)),
    HelloCase("wasm", {"hello.rs": 'fn main() { println!("Hello World"); }\n'},
              (("rustc", "--target", "wasm32-wasip1", "hello.rs", "-o", "hello.wasm"),
               ("rustc", "--target", "wasm32-unknown-unknown", "hello.rs", "-o", "hello-unknown.wasm")),
              "hello.wasm"),
)


def _result_detail(result) -> str:
    return (result.stdout_tail or result.stdout).decode("utf-8", "replace")[-3000:] + "\n" + (
        result.stderr_tail or result.stderr).decode("utf-8", "replace")[-3000:]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.profile)
def test_configured_build_image_captures_hello_world(tmp_path: Path, case: HelloCase) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job = config.job("job_project_build")
    profiles = profiles_from_settings(job.settings["profiles"])
    assert {case.profile for case in CASES} == set(profiles)
    inspected = subprocess.run(["docker", "image", "inspect", profiles[case.profile].tag],
                               capture_output=True, timeout=60, check=False)
    if inspected.returncode != 0:
        pytest.skip(f"live build image is unavailable: {profiles[case.profile].tag}")
    assert job.build_capture is not None

    run_root = tmp_path / "run"
    project = run_root / "workspace" / case.profile
    project.mkdir(parents=True)
    for name, content in case.files.items():
        (project / name).write_text(content, encoding="utf-8")
    build_runs: list[tuple[str, ...]] = []

    def observed_runner(argv, timeout):
        if tuple(argv[:2]) == ("docker", "run") and profiles[case.profile].image_id in argv:
            build_runs.append(tuple(argv))
        return _run(argv, timeout)

    executor = BuildContainerExecutor(profiles[case.profile], timeout_seconds=300,
                                      output_bytes=256 * 1024, runner=observed_runner)
    try:
        executor.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        pytest.fail(f"environment/image failure [{case.profile}]: {exc}")

    environment = dict(case.environment)
    capture_gaps: list[str] = []
    for ordinal, command in enumerate((*case.commands, *((case.output_command,) if case.output_command else ())), 1):
        scope = CaptureScope("hello-world", "job_project_build", "attempt_0001",
                             f"hello-{case.profile}-{ordinal}", case.profile)
        try:
            result = executor.execute_captured(
                command, workspace=run_root / "workspace", working_directory=case.profile,
                environment=environment,
                capture_directory=run_root / "capture" / f"{case.profile}-{ordinal}",
                capture_config=job.build_capture, scope=scope)
        except (OSError, RuntimeError, ValueError) as exc:
            pytest.fail(f"environment/capture process failure [{case.profile} {command[0]}]: {exc}")
        assert not result.timed_out, f"environment/process timeout [{case.profile} {command[0]}]"
        assert result.capture_record is not None, f"capture process failure [{case.profile} {command[0]}]"
        docker_run = build_runs[-1]
        assert docker_run[docker_run.index("--user") + 1] == profiles[case.profile].user
        assert docker_run.count("--mount") == 2
        assert any(value.endswith(",dst=/workspace") for value in docker_run)
        assert any(value.endswith(",dst=/capture") for value in docker_run)
        verified = verify_capture_record(result.capture_record, run_root=run_root, scope=scope)
        capture_gaps.extend(verified.gaps)
        if ordinal <= len(case.commands):
            assert verified.tool_calls, f"capture wrapper failure [{case.profile} {command[0]}]"
        assert verified.document["collector"]["image_id"] == profiles[case.profile].image_id
        assert result.exit_code == 0, f"target program failure [{case.profile} {command[0]}]: {_result_detail(result)}"
        if ordinal == len(case.commands) + int(case.output_command is not None):
            if case.profile != "wasm":
                assert HELLO in result.stdout.decode("utf-8", "replace"), (
                    f"target output failure [{case.profile}]: {_result_detail(result)}")
    if case.artifact:
        artifact = project / case.artifact
        assert artifact.is_file() and artifact.stat().st_size > 0, (
            f"target artifact failure [{case.profile}]: {case.artifact}")
        if case.profile == "wasm":
            assert artifact.read_bytes()[:4] == b"\0asm"
            assert (project / "hello-unknown.wasm").read_bytes()[:4] == b"\0asm"
    if capture_gaps:
        if (case.profile == "dotnet" and all(
                gap.startswith("unparsed openat row:") or
                gap.startswith("response file outside the workspace was not retained: /tmp/MSBuildTemp")
                for gap in capture_gaps)):
            pytest.xfail(".NET temporary response files and openat rows remain capture gaps")
        pytest.fail(f"capture coverage failure [{case.profile}]: {capture_gaps}")
