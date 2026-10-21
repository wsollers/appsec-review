"""Live tier for ``job_sanitizer_build`` (docs/operations/sanitizer-build.md, operator-run).

Skipped unless Docker and the local project build image (``audit-buildenv-cpp:local``) are present.
With them, ``targets/cpp-multivuln`` (or the checkout named by ``APPSEC_SANITIZER_TARGET``, since
targets are not part of a git worktree) is built twice by the real ``BuildContainerExecutor`` (the same
hardened ``docker run`` the pipeline uses): once plain and once with the job's sanitizer
environment. The ELF reader must find the AddressSanitizer and UBSan runtime in the instrumented
``relay`` and in nothing the plain build produced. Nothing is executed: no produced binary is run,
only the CMake/compiler/linker build tools.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.job_sanitizer_build.evidence import runtime_evidence
from appsec_review.jobs.job_sanitizer_build.settings import SanitizerBuildSettings, instrumented_environment


ROOT = Path(__file__).parents[2]
TARGET = Path(os.environ.get("APPSEC_SANITIZER_TARGET", ROOT / "targets" / "cpp-multivuln"))
IMAGE = "audit-buildenv-cpp:local"
SETTINGS = SanitizerBuildSettings.from_mapping({
    "enabled": True, "workers": 1, "sanitizers": ["address", "undefined"],
    "extra_flags": ["-fno-omit-frame-pointer", "-g", "-O1"], "required_evidence": ["address"],
    "build_systems": ["cmake"], "build_environment": {"ASAN_OPTIONS": "detect_leaks=0"},
    "command_timeout_seconds": 600, "output_bytes": 1_000_000, "artifact_count_limit": 1000, "max_units": 1,
})
COMMANDS = (("cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
             "-DCMAKE_BUILD_TYPE=RelWithDebInfo"), ("cmake", "--build", "build", "--parallel", "2"))


@pytest.fixture(scope="module")
def profile() -> BuildProfile:
    if shutil.which("docker") is None:
        pytest.skip("docker is unavailable")
    if not (TARGET / "CMakeLists.txt").is_file():
        pytest.skip(f"{TARGET} is not present (set APPSEC_SANITIZER_TARGET)")
    try:
        image_id = subprocess.run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"],
                                  capture_output=True, text=True, timeout=60, check=False).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("docker is unavailable")
    if not image_id.startswith("sha256:"):
        pytest.skip(f"the project build image {IMAGE} is not built locally")
    return BuildProfile("native", IMAGE, image_id, "10001:10001")


def _build(profile: BuildProfile, workspace: Path, *, sanitized: bool) -> Path:
    shutil.copytree(TARGET, workspace, ignore=shutil.ignore_patterns(".git", "build"))
    executor = BuildContainerExecutor(profile, timeout_seconds=600, output_bytes=1_000_000)
    executor.resolve()
    environment = instrumented_environment(SETTINGS, {})[0] if sanitized else {}
    for argv in COMMANDS:
        result = executor.execute(argv, workspace=workspace, working_directory=".", environment=environment)
        assert result.exit_code == 0, result.stderr.decode("utf-8", "replace")[-2000:]
    return workspace / "build" / "relay"


def test_relay_references_the_sanitizer_runtime_only_when_built_with_the_flags(
        profile: BuildProfile, tmp_path_factory: pytest.TempPathFactory) -> None:
    # Workspaces sit directly under the base temp: Docker Desktop rejects deep bind-mount sources.
    base = tmp_path_factory.getbasetemp()
    plain = runtime_evidence(_build(profile, base / "sanitizer-plain", sanitized=False), "executable")
    instrumented = runtime_evidence(_build(profile, base / "sanitizer-asan", sanitized=True), "executable")

    assert plain["evidence_status"] == instrumented["evidence_status"] == "resolved"
    assert not any(item["runtime_referenced"] for item in plain["sanitizers"].values())
    address, undefined = instrumented["sanitizers"]["address"], instrumented["sanitizers"]["undefined"]
    assert address["runtime_referenced"] and address["imports_runtime"]
    assert any(name.startswith("__asan_") for name in address["symbols"])
    assert undefined["runtime_referenced"] and (undefined["symbol_count"] or undefined["runtime_libraries"])
