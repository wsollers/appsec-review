from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import (
    BuildContainerExecutor,
    BuildProfile,
    ProjectImageResolver,
    profiles_from_settings,
)
from appsec_review.jobs.job_language_build import dotnet, jvm, node, php, python, rust, wasm
from appsec_review.jobs.job_language_build.job import _catalog, _kind


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "build_toolchains"


@dataclass(frozen=True)
class LiveBuildCase:
    family: str
    profile: str
    commands: tuple[tuple[str, ...], ...]
    environment: dict[str, str]
    expected: tuple[str, ...]


CASES = (
    LiveBuildCase("native", "native", (
        ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug"),
        ("cmake", "--build", "build", "--verbose"),
        ("clang++", "-S", "-emit-llvm", "main.cpp", "-o", "build/main.ll"),
    ), {}, ("build/compile_commands.json", "build/libfixture_helper.a", "build/fixture_native", "build/main.ll")),
    LiveBuildCase("rust", "rust", (("cargo", "build", "--verbose"),),
                  {"CARGO_HOME": "/tmp/cargo"},
                  ("target/debug/appsec-fixture-rust", "Cargo.lock")),
    LiveBuildCase("go", "go", (("go", "build", "-x", "-o", "build/appsec-fixture-go", "."),),
                  {"GOCACHE": "/tmp/go-cache", "GOMODCACHE": "/tmp/go-mod"},
                  ("build/appsec-fixture-go",)),
    LiveBuildCase("java", "java", ((
        "mvn", "-Dmaven.repo.local=/tmp/m2", "-DskipTests", "package",
    ),), {}, ("target/classes/Main.class", "target/appsec-fixture-java-0.1.0.jar")),
    LiveBuildCase("typescript", "node", (
        ("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"),
        ("npm", "run", "build"),
    ), {"NPM_CONFIG_CACHE": "/tmp/npm-cache"}, ("dist/index.js", "dist/index.js.map", "package-lock.json")),
    LiveBuildCase("dotnet", "dotnet", (
        ("dotnet", "restore", "appsec-fixture.csproj"),
        ("dotnet", "build", "appsec-fixture.csproj", "--no-restore", "--verbosity", "diagnostic"),
    ), {"DOTNET_CLI_HOME": "/tmp/dotnet", "NUGET_PACKAGES": "/workspace/dotnet/.nuget/packages"}, (
        "bin/Debug/net8.0/appsec-fixture.dll", "bin/Debug/net8.0/appsec-fixture.pdb",
        "bin/Debug/net8.0/appsec-fixture.deps.json",
    )),
    LiveBuildCase("python", "python", ((
        "python", "-m", "pip", "wheel", ".", "--wheel-dir", "dist",
    ),), {"PIP_CACHE_DIR": "/tmp/pip-cache", "PIP_DISABLE_PIP_VERSION_CHECK": "1"},
        ("dist/appsec_fixture_python-0.1.0-py3-none-any.whl",)),
    LiveBuildCase("php", "php", ((
        "composer", "install", "--no-interaction", "--no-scripts", "--no-plugins",
        "--prefer-dist", "--no-progress",
    ),), {"COMPOSER_HOME": "/tmp/composer"}, ("composer.lock", "vendor/autoload.php")),
    LiveBuildCase("wasm", "node", (
        ("npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"),
        ("npm", "run", "build"),
    ), {"NPM_CONFIG_CACHE": "/tmp/npm-cache"},
        ("build/fixture.wasm", "build/fixture.wat", "build/fixture.wasm.map")),
)


def _profile(name: str):
    config = load_config(ROOT / "appsec-review.toml")
    profiles = profiles_from_settings(config.job("job_project_build").settings["profiles"])
    profile = profiles[name]
    inspected = subprocess.run(
        ["docker", "image", "inspect", profile.tag, "--format", "{{.Id}}"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if inspected.returncode != 0:
        pytest.skip(f"live build image is unavailable: {profile.tag}")
    assert inspected.stdout.strip() == profile.image_id, f"configured image identity changed: {profile.tag}"
    return profile


def _assert_catalog_contract(case: LiveBuildCase, root: Path) -> None:
    build_unit_id = "build-unit-livefixture000"
    if case.family == "native":
        assert _kind(root / "build/compile_commands.json") == "compile-database"
        assert _kind(root / "build/libfixture_helper.a") == "static-library"
        assert _kind(root / "build/fixture_native") == "executable"
        assert _kind(root / "build/main.ll") == "llvm-bitcode"
        artifacts, _gaps = _catalog(root, root, {}, 10000, build_unit_id)
        assert {item["kind"] for item in artifacts} >= {
            "compile-database", "static-library", "executable", "llvm-bitcode"}
    elif case.family == "rust":
        executable = root / "target/debug/appsec-fixture-rust"
        assert rust.artifact_kind(executable, executable.relative_to(root).as_posix(), {}) == "executable"
        artifacts, _gaps = _catalog(root, root, {}, 10000, build_unit_id, "rust")
        assert "executable" in {item["kind"] for item in artifacts}
    elif case.family == "go":
        assert _kind(root / "build/appsec-fixture-go", "go") == "executable"
        artifacts, _gaps = _catalog(root, root, {}, 10000, build_unit_id, "go")
        assert "executable" in {item["kind"] for item in artifacts}
    elif case.family == "java":
        assert jvm._artifact_kind(root / "target/classes/Main.class") == "jvm-class"
        assert jvm._artifact_kind(root / "target/appsec-fixture-java-0.1.0.jar") == "jar"
        artifacts, gaps = jvm._catalog(root, root, {}, 10000, build_unit_id)
        assert not gaps and {item["kind"] for item in artifacts} >= {"jvm-class", "jar"}
    elif case.family == "typescript":
        assert node.artifact_kind(root / "dist/index.js") == "generated-code"
        assert node.artifact_kind(root / "dist/index.js.map") == "source-map"
        artifacts, gaps = node.catalog(root, root, {}, 10000, build_unit_id)
        assert not gaps and {item["kind"] for item in artifacts} >= {"generated-code", "source-map"}
    elif case.family == "dotnet":
        assert dotnet.artifact_kind(root / "bin/Debug/net8.0/appsec-fixture.dll") == "managed-assembly"
        assert dotnet.artifact_kind(root / "bin/Debug/net8.0/appsec-fixture.pdb") == "debug-information"
        assert dotnet.artifact_kind(root / "bin/Debug/net8.0/appsec-fixture.deps.json") == "dependency-manifest"
        artifacts, _gaps = _catalog(root, root, {}, 10000, build_unit_id, "dotnet")
        assert {item["kind"] for item in artifacts} >= {
            "managed-assembly", "debug-information", "dependency-manifest"}
    elif case.family == "python":
        wheel = root / "dist/appsec_fixture_python-0.1.0-py3-none-any.whl"
        assert python.artifact_kind(wheel, wheel.relative_to(root).as_posix(), {}) == "wheel"
        artifacts, _gaps = _catalog(root, root, {}, 10000, build_unit_id, "python")
        assert "wheel" in {item["kind"] for item in artifacts}
    elif case.family == "php":
        metadata, gaps = php.composer_metadata(root.parent, root.name)
        assert not gaps and any(item["name"] == "psr/log" for item in metadata["packages"])
        autoload = root / "vendor/autoload.php"
        assert php.artifact_kind(autoload, autoload.relative_to(root.parent).as_posix(), {}) == "generated-autoload"
        artifacts, gaps = php.catalog(root, root, {}, 10000, build_unit_id)
        assert not gaps and {item["kind"] for item in artifacts} >= {"package-metadata", "generated-autoload"}
    elif case.family == "wasm":
        module = root / "build/fixture.wasm"
        assert module.read_bytes()[:4] == b"\x00asm"
        artifacts, gaps = wasm._catalog(root, root, {}, 10000, build_unit_id)
        assert not gaps
        assert {item["kind"] for item in artifacts} >= {"wasm-module", "wasm-text", "debug-metadata"}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.family)
def test_live_build_container_compiles_fixture_and_emits_cataloged_artifacts(
        tmp_path: Path, case: LiveBuildCase) -> None:
    workspace = tmp_path / "workspace"
    shutil.copytree(FIXTURE, workspace)
    project = workspace / case.family
    if case.family == "go":
        (project / "build").mkdir()
    executor = BuildContainerExecutor(_profile(case.profile), timeout_seconds=900,
                                      output_bytes=8 * 1024 * 1024)
    executor.resolve()
    for command in case.commands:
        result = executor.execute(command, workspace=workspace, working_directory=case.family,
                                  environment=case.environment)
        detail = ((result.stdout_tail or result.stdout) + b"\n" +
                  (result.stderr_tail or result.stderr)).decode("utf-8", "replace")[-12000:]
        assert not result.timed_out, f"{case.family} command timed out: {command}"
        assert result.exit_code == 0, f"{case.family} command failed: {command}\n{detail}"
    for relative in case.expected:
        artifact = project / relative
        assert artifact.is_file() and artifact.stat().st_size > 0, f"missing {case.family} artifact: {relative}"
    _assert_catalog_contract(case, project)


def test_live_typescript_project_image_dependencies_are_visible_in_clean_workspace(
        tmp_path: Path) -> None:
    target = tmp_path / "target"
    source_dir = "projects/typescript/case"
    project = target / source_dir
    shutil.copytree(FIXTURE / "typescript", project)
    recipe = {
        "schema": "appsec-review/build-recipe/1",
        "build_unit_id": "build-unit-live-typescript",
        "image_profile": "node",
        "source_dir": source_dir,
        "build_dir": f"{source_dir}/dist",
        "system_packages": [],
        "environment": {},
        "dependency_files": [f"{source_dir}/package.json"],
        "configure_commands": [],
        "build_commands": [["npm", "run", "build"]],
        "expected_outputs": [f"{source_dir}/dist/index.js"],
        "network_required": True,
        "reason": "live dependency-image visibility fixture",
        "build_system": "node",
    }
    base = _profile("node")
    image, _stdout, _stderr = ProjectImageResolver(
        metadata_root=tmp_path / "metadata", target_root=target, timeout_seconds=900,
    ).resolve(recipe, base)
    workspace = tmp_path / "workspace"
    shutil.copytree(target, workspace)
    executor = BuildContainerExecutor(
        BuildProfile("node", image.image_tag, image.image_id, base.user),
        timeout_seconds=900, output_bytes=8 * 1024 * 1024)
    executor.resolve()
    executor.prepare_node_dependencies(workspace=workspace, source_dir=source_dir)
    result = executor.execute(("npm", "run", "build"), workspace=workspace,
                              working_directory=source_dir, environment={})
    detail = ((result.stdout_tail or result.stdout) + b"\n" +
              (result.stderr_tail or result.stderr)).decode("utf-8", "replace")[-12000:]
    assert not result.timed_out and result.exit_code == 0, detail
    assert (workspace / source_dir / "dist" / "index.js").is_file()
