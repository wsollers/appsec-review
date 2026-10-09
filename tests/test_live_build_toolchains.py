from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import json
import re

from appsec_review.config import load_config
from appsec_review.container_runtime import (
    BuildContainerExecutor, CaptureScope,
    BuildProfile,
    ProjectImage,
    ProjectImageResolver,
    profiles_from_settings,
)
from appsec_review.container_runtime.catalog import load_catalog
from appsec_review.jobs.job_language_build import (
    build_job as build_language, dotnet, jvm, load_accepted_language_build, node, php, python, rust, wasm,
)
from appsec_review.jobs.job_language_build.job import _catalog, _kind
from appsec_review.jobs.job_project_build.job import _probe_environment
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.inference import ModelResult, check_models, infer
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256



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
                  {"CARGO_HOME": "/tmp/cargo", "CARGO_INCREMENTAL": "0"},
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


def test_live_cpp_build_syscalls_are_captured_in_standard_records(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    capture_config = config.job("job_project_build").build_capture
    assert capture_config is not None and capture_config.backend == "ptrace"
    workspace = tmp_path / "workspace"
    shutil.copytree(FIXTURE / "native", workspace / "native")
    executor = BuildContainerExecutor(_profile("native"), timeout_seconds=900,
                                      output_bytes=8 * 1024 * 1024)
    executor.resolve()
    commands = (
        ("configure", ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug")),
        ("compile", ("cmake", "--build", "build", "--verbose")),
    )
    for ordinal, (name, command) in enumerate(commands, 1):
        result = executor.execute_captured(
            command, workspace=workspace, working_directory="native", environment={},
            capture_directory=workspace / ".capture" / name, capture_config=capture_config,
            scope=CaptureScope("live-cpp-capture", "job_project_build", "attempt_0001",
                               f"build-unit-cpp-{ordinal}", "native"))
        detail = (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")[-12000:]
        assert not result.timed_out and result.exit_code == 0, detail
        assert result.capture_record is not None
        record = json.loads(result.capture_record.read_text(encoding="utf-8"))
        assert record["schema"] == "appsec-review/build-execution-record/1"
        assert record["coverage"]["complete"] is True, record["coverage"]["gaps"]
        assert {"process_exec", "file_open", "connect"} <= set(record["collector"]["event_kinds"])
        assert record["events"]["counts"]["process_exec"] > 0
        assert record["events"]["counts"]["file_open"] > 0
        assert record["tool_calls"]["retained"] > 0
        assert record["tool_calls"]["capped"] is False
        assert record["secret_scan"]["scanner"] == "tool-gitleaks"
        findings = record["secret_scan"]["findings"]
        assert (result.capture_record.parent / findings["uri"]).is_file()
        assert not tuple(result.capture_record.parent.glob("trace*"))
    assert (workspace / "native" / "build" / "fixture_native").is_file()


def test_live_cpp_capture_scans_and_redacts_envp_secrets(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    capture_config = config.job("job_project_build").build_capture
    assert capture_config is not None
    capture_config = replace(
        capture_config,
        envp_redact_names=(*capture_config.envp_redact_names, "DISCORD_PUBLIC_KEY"))
    synthetic_secret = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"
    workspace = tmp_path / "workspace"
    shutil.copytree(FIXTURE / "native", workspace / "native")
    capture = workspace / ".capture" / "secret-envp"
    executor = BuildContainerExecutor(_profile("native"), timeout_seconds=900,
                                      output_bytes=8 * 1024 * 1024)
    executor.resolve()
    result = executor.execute_captured(
        ("cmake", "-S", ".", "-B", "build"), workspace=workspace,
        working_directory="native", environment={"DISCORD_PUBLIC_KEY": synthetic_secret},
        capture_directory=capture, capture_config=capture_config,
        scope=CaptureScope("live-cpp-secret", "job_project_build", "attempt_0001",
                           "build-unit-cpp-secret", "native"))
    assert not result.timed_out and result.exit_code == 0
    assert result.capture_record is not None
    record = json.loads(result.capture_record.read_text(encoding="utf-8"))
    assert record["coverage"] == {"complete": True, "gaps": []}
    assert record["secret_scan"]["findings"]["count"] >= 1
    events = (capture / record["events"]["uri"]).read_text(encoding="utf-8")
    assert '"name":"DISCORD_PUBLIC_KEY"' in events
    assert synthetic_secret not in "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in capture.rglob("*") if path.is_file())
    assert not tuple(capture.glob("trace*"))


class _PinnedBaseImageResolver:
    def resolve(self, recipe, profile):
        identity = hashlib.sha256(
            json.dumps(recipe, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return ProjectImage(
            "appsec-review/project-build-image/1", identity, profile.name, profile.image_id,
            profile.tag, profile.image_id, None, False, True, {}), b"", b""


def test_live_cpp_project_build_accepts_hash_verified_execution_capture(tmp_path: Path) -> None:
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"),
                           encoding="utf-8")
    config = load_config(config_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURE / "native", target / "native")
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan()]).run(
        target_root=target, source_fingerprint=fingerprint)
    outcome = GraphRunner(config, [build_projects(
        image_resolver_factory=lambda _unit: _PinnedBaseImageResolver())]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "SUCCEEDED"

    run_root = config.runtime.runs_dir / upstream["run_id"]
    accepted = load_accepted_builds(run_root)
    receipt = next(item for item in accepted["probe_receipts"] if item["family"] == "native")
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert len(receipt["commands"]) == 2
    assert all(command["execution_capture"]["complete"] for command in receipt["commands"])
    assert all("execution-capture" not in artifact["path"] for artifact in receipt["artifacts"])
    assert any(artifact["path"].endswith("build/fixture_native")
               for artifact in receipt["artifacts"])

    compiler_seen = False
    for command in receipt["commands"]:
        identity = command["execution_capture"]
        record_path = run_root / identity["path"]
        assert record_path.is_file() and file_sha256(record_path) == identity["sha256"]
        record = json.loads(record_path.read_text(encoding="utf-8"))
        assert record["coverage"] == {"complete": True, "gaps": []}
        assert "connect" in record["collector"]["event_kinds"]
        assert record["events"]["counts"]["process_exec"] > 0
        assert record["events"]["counts"]["file_open"] > 0
        assert record["tool_calls"]["retained"] > 0
        findings_identity = identity["secret_findings"]
        findings_path = run_root / findings_identity["path"]
        assert file_sha256(findings_path) == findings_identity["sha256"]
        events_path = record_path.parent / record["events"]["uri"]
        assert file_sha256(events_path) == record["events"]["sha256"]
        for line in events_path.read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            if event["kind"] == "process_exec" and event.get("argv") and any(
                    name in Path(event["argv"][0]).name
                    for name in ("clang", "c++", "g++")):
                compiler_seen = True
    assert compiler_seen, "no C++ compiler argv was retained in syscall evidence"


@pytest.mark.parametrize("case", CASES[1:], ids=lambda case: f"captured-{case.family}")
def test_live_language_build_syscalls_are_captured_in_standard_records(
        tmp_path: Path, case: LiveBuildCase) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    capture_config = config.job("job_language_build").build_capture
    assert capture_config is not None and capture_config.backend == "ptrace"
    workspace = tmp_path / "workspace"
    shutil.copytree(FIXTURE / case.family, workspace / case.family)
    project = workspace / case.family
    if case.family == "go":
        (project / "build").mkdir()
    executor = BuildContainerExecutor(_profile(case.profile), timeout_seconds=900,
                                      output_bytes=8 * 1024 * 1024)
    executor.resolve()
    for ordinal, command in enumerate(case.commands, 1):
        result = executor.execute_captured(
            command, workspace=workspace, working_directory=case.family,
            environment=case.environment,
            capture_directory=workspace / ".capture" / f"command-{ordinal}",
            capture_config=capture_config,
            scope=CaptureScope("live-language-capture", "job_language_build", "attempt_0001",
                               f"build-unit-{case.family}-{ordinal}", case.family))
        detail = ((result.stdout_tail or result.stdout) + b"\n" +
                  (result.stderr_tail or result.stderr)).decode("utf-8", "replace")[-12000:]
        assert not result.timed_out and result.exit_code == 0, detail
        assert result.capture_record is not None
        record = json.loads(result.capture_record.read_text(encoding="utf-8"))
        assert record["coverage"]["complete"] is True, record["coverage"]["gaps"]
        assert "connect" in record["collector"]["event_kinds"]
        assert record["events"]["counts"]["process_exec"] > 0
        assert record["tool_calls"]["retained"] > 0
        assert record["tool_calls"]["capped"] is False
        if case.family == "dotnet" and ordinal == 1:
            assert record["events"]["counts"]["connect"] > 0
    for relative in case.expected:
        artifact = project / relative
        assert artifact.is_file() and artifact.stat().st_size > 0
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


def test_live_maven_project_image_can_fill_old_plugin_gaps_in_writable_runtime_cache(
        tmp_path: Path) -> None:
    target = tmp_path / "target"
    source_dir = "projects/java/case"
    project = target / source_dir
    shutil.copytree(FIXTURE / "java", project)
    recipe = {
        "schema": "appsec-review/build-recipe/1",
        "build_unit_id": "build-unit-live-maven",
        "image_profile": "java",
        "source_dir": source_dir,
        "build_dir": f"{source_dir}/target",
        "system_packages": [],
        "environment": {},
        "dependency_files": [f"{source_dir}/pom.xml"],
        "configure_commands": [],
        "build_commands": [["mvn", "-B", "-DskipTests", "package"]],
        "expected_outputs": [f"{source_dir}/target/appsec-fixture-java-0.1.0.jar"],
        "network_required": True,
        "reason": "live old Maven plugin runtime-cache fixture",
        "build_system": "maven",
    }
    base = _profile("java")
    image, _stdout, _stderr = ProjectImageResolver(
        metadata_root=tmp_path / "metadata", target_root=target, timeout_seconds=900,
    ).resolve(recipe, base)
    workspace = tmp_path / "workspace"
    shutil.copytree(target, workspace)
    executor = BuildContainerExecutor(
        BuildProfile("java", image.image_tag, image.image_id, base.user),
        timeout_seconds=900, output_bytes=8 * 1024 * 1024)
    executor.resolve()
    result = executor.execute(("mvn", "-B", "-DskipTests", "package"), workspace=workspace,
                              working_directory=source_dir,
                              environment=_probe_environment(recipe))
    detail = ((result.stdout_tail or result.stdout) + b"\n" +
              (result.stderr_tail or result.stderr)).decode("utf-8", "replace")[-12000:]
    assert not result.timed_out and result.exit_code == 0, detail
    assert (workspace / source_dir / "target" / "appsec-fixture-java-0.1.0.jar").is_file()


SYNTHETIC_SECRET = "e7322523fb86ed64c836a979cf8465fbd436378c653c1db38f9ae87bc62a6fd5"


class _DotnetFixtureRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            if unit["family"] != "dotnet":
                continue
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "dotnet", "source_dir": root, "build_dir": f"{root}/obj",
                "system_packages": [], "environment": {"DOTNET_NOLOGO": "1"},
                "dependency_files": [f"{root}/appsec-fixture.csproj"],
                "configure_commands": [["dotnet", "restore", "appsec-fixture.csproj"]],
                "build_commands": [["dotnet", "build", "appsec-fixture.csproj", "--no-restore",
                                    "--verbosity", "diagnostic"]],
                "expected_outputs": [f"{root}/bin", f"{root}/obj"], "network_required": True,
                "reason": "fixed live .NET capture fixture recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


@pytest.mark.skipif(
    os.environ.get("APPSEC_RUN_LIVE_INFERENCE") != "1",
    reason="requires the configured authenticated model transport",
)
def test_live_configured_model_infers_valid_dotnet_recipe_that_builds(tmp_path: Path) -> None:
    """Keep recipe inference independent from build interception and language capture."""
    _profile("dotnet")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    config = load_config(config_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURE / "dotnet", target / "dotnet")
    fingerprint = source_fingerprint(target)

    planned = GraphRunner(
        config,
        [build_intake(check_models=check_models), build_catalog(), build_plan(infer=infer)],
    ).run(
        target_root=target, source_fingerprint=fingerprint)
    assert planned["status"] == "SUCCEEDED", planned
    run_id = planned["run_id"]
    plan_path = config.runtime.runs_dir / run_id
    from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
    plan = load_accepted_plan(plan_path)
    assert plan["model"]["status"] == "ACCEPTED", plan["coverage_gaps"]
    actions = [item for item in plan["build_topology"]["build_actions"]
               if item["family"] == "dotnet"]
    assert len(actions) == 1
    # Planning publishes a validated recipe but never grants execution authority itself.
    assert actions[0]["executable"] is False and actions[0]["requires_inference"] is False
    recipe = actions[0]["recipe"]
    assert recipe["image_profile"] == "dotnet" and recipe["network_required"] is True
    assert recipe["build_commands"] and all(command[0] == "dotnet"
                                               for command in recipe["build_commands"])

    built = GraphRunner(config, [build_projects()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert built["status"] == "SUCCEEDED", built
    accepted = load_accepted_builds(plan_path)
    receipt = next(item for item in accepted["probe_receipts"] if item["family"] == "dotnet")
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["gaps"] == []
    assert receipt["probe_disposition"] == "PROBED"
    dispatch = next(item for item in accepted["build_dispatches"] if item["family"] == "dotnet")
    assert dispatch["recipe_provenance"] == "accepted-inference-default-image"
    assert any(item["path"].endswith("appsec-fixture.dll") for item in receipt["artifacts"])


def test_live_dotnet_language_build_accepts_syscall_authoritative_capture(tmp_path: Path) -> None:
    _profile("dotnet")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    config = load_config(config_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURE / "dotnet", target / "dotnet")
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(
        infer=_DotnetFixtureRecipeModel().complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    run_id = upstream["run_id"]
    project = GraphRunner(config, [build_projects()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert project["status"] == "SUCCEEDED", project
    outcome = GraphRunner(config, [build_language()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "SUCCEEDED", outcome

    run_root = config.runtime.runs_dir / run_id
    receipt = next(item for item in load_accepted_language_build(run_root)["receipts"]
                   if item["family"] == "dotnet")
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["gaps"] == []
    assert receipt["capture_identity"] == dotnet.CAPTURE_IDENTITY
    assert receipt["capture_provenance"]["complete"] is True
    assert receipt["capture_provenance"]["unreconciled_tool_calls"] == 0
    assert receipt["capture_provenance"]["envp_events"] > 0
    assert set(receipt["capture_provenance"]["observed_tool_kinds"]) >= {"build-driver", "compiler"}
    assert receipt["project_topology"][0]["package_references"] == [
        {"name": "Newtonsoft.Json", "version": "12.0.1"}]

    artifacts = {item["workspace_path"]: item for item in receipt["artifacts"]}
    for relative, kind in (
        ("dotnet/bin/Debug/net8.0/appsec-fixture.dll", "managed-assembly"),
        ("dotnet/bin/Debug/net8.0/appsec-fixture.pdb", "debug-information"),
        ("dotnet/bin/Debug/net8.0/appsec-fixture.deps.json", "dependency-manifest"),
        ("dotnet/bin/Debug/net8.0/appsec-fixture.runtimeconfig.json", "runtime-configuration"),
    ):
        assert artifacts[relative]["kind"] == kind
        assert file_sha256(run_root / artifacts[relative]["path"]) == artifacts[relative]["sha256"]
    assert any(item["kind"] == "generated-source" for item in receipt["artifacts"])
    assert not any("execution-capture" in item["path"] for item in receipt["artifacts"])

    compiler_events = []
    gitleaks = load_catalog(ROOT).tool("tool-gitleaks")
    for ordinal, command in enumerate(receipt["commands"], 1):
        assert command["exit_code"] == 0 and command["timed_out"] is False
        identity = command["execution_capture"]
        assert identity["complete"] is True and identity["envp_captured"] is True
        assert identity["scope"]["family"] == "dotnet"
        assert identity["path"].endswith(f"execution-capture/command-{ordinal:03d}/record.json")
        for member in (identity, identity["events"], identity["secret_findings"],
                       identity["secret_scan"]["execution"], identity["secret_scan"]["report"]):
            assert file_sha256(run_root / member["path"]) == member["sha256"]
        execution = json.loads((run_root / identity["secret_scan"]["execution"]["path"]).read_text())
        assert execution["tool_id"] == "tool-gitleaks" and execution["version"] == gitleaks.version
        record_path = run_root / identity["path"]
        assert json.loads(record_path.read_text())["coverage"] == {"complete": True, "gaps": []}
        assert not tuple(record_path.parent.glob("trace*"))
        for stream_name in ("stdout", "stderr"):
            stream = command[stream_name]
            retained = run_root / stream["path"]
            assert stream["storage"] == "complete-file" and stream["truncated"] is False
            assert stream["capture_limit_bytes"] is None
            assert stream["captured_bytes"] == stream["total_bytes"] == retained.stat().st_size
            assert file_sha256(retained) == stream["sha256"]
            assert retained.read_bytes() == (record_path.parent / stream_name).read_bytes()
        compiler_events.extend(event for event in _capture_events(run_root, command)
                               if event["kind"] == "process_exec" and event["result"] == 0 and
                               any(Path(value).name.lower() == "csc.dll"
                                   for value in event.get("argv", ())))
    assert compiler_events and all(event["envp_captured"] and event["envp"] for event in compiler_events)
    rows = receipt["tool_invocations"]
    assert {item["tool_kind"] for item in rows} >= {"build-driver", "compiler"}
    assert all(item["mapping"].startswith("syscall-process-exec") for item in rows)
    assert all(item["evidence"]["process_exec"]["count"] >= 1 for item in rows)
    assert all("argv" not in item and len(item["argv_sha256"]) == 64 for item in rows)
    assert not tuple(run_root.rglob("trace.[0-9]*"))


class _RustFixtureRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "rust", "source_dir": root, "build_dir": f"{root}/target",
                "system_packages": [], "environment": {"CARGO_TERM_COLOR": "never"},
                "dependency_files": [f"{root}/Cargo.toml", f"{root}/Cargo.lock"],
                "configure_commands": [], "build_commands": [["cargo", "build", "--locked"]],
                "expected_outputs": [f"{root}/target"], "network_required": True,
                "reason": "live Rust capture fixture recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class _SecretEnvironmentExecutor(BuildContainerExecutor):
    """The real executor, started with one extra variable the accepted recipe never named."""

    def execute_captured(self, argv, *, environment, **options):
        return super().execute_captured(
            argv, environment={**environment, "DISCORD_PUBLIC_KEY": SYNTHETIC_SECRET}, **options)


def _live_rust_language_build(tmp_path: Path, *, secret: bool):
    _profile("rust")
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if secret:
        names = '  "PIP_INDEX_URL",\n]'
        assert text.count(names) == 1
        text = text.replace(names, '  "PIP_INDEX_URL",\n  "DISCORD_PUBLIC_KEY",\n]')
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(text, encoding="utf-8")
    config = load_config(config_path)
    target = tmp_path / "target"
    shutil.copytree(FIXTURE / "rust", target / "rust")
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(
        infer=_RustFixtureRecipeModel().complete)]).run(target_root=target, source_fingerprint=fingerprint)
    run_id = upstream["run_id"]
    # The default resolver derives the real dependency-bearing project image from the pinned
    # Rust profile, so Cargo downloads through the allowed build environment only.
    project = GraphRunner(config, [build_projects()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert project["status"] == "SUCCEEDED"
    settings = config.job("job_language_build").settings
    factory = (lambda unit, profile: _SecretEnvironmentExecutor(
        profile, timeout_seconds=int(settings["command_timeout_seconds"]),
        output_bytes=int(settings["output_bytes"]))) if secret else None
    outcome = GraphRunner(config, [build_language(executor_factory=factory)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    run_root = config.runtime.runs_dir / run_id
    receipt = next(item for item in load_accepted_language_build(run_root)["receipts"]
                   if item["family"] == "rust")
    return config, run_root, outcome, receipt


def _capture_events(run_root: Path, command) -> list[dict]:
    path = run_root / command["execution_capture"]["events"]["path"]
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _assert_live_rust_capture(config, run_root: Path, receipt) -> None:
    """Every Rust command carries a complete, hash-valid standardized capture with a real scan."""
    assert receipt["terminal_status"] == "SUCCEEDED", receipt["gaps"]
    assert receipt["gaps"] == []
    assert [command["role"] for command in receipt["commands"]] == ["metadata", "build"]
    gitleaks = load_catalog(ROOT).tool("tool-gitleaks")
    for ordinal, command in enumerate(receipt["commands"], 1):
        assert command["exit_code"] == 0 and command["timed_out"] is False
        identity = command["execution_capture"]
        assert identity["scope"]["job_id"] == "job_language_build"
        assert identity["scope"]["run_id"] == run_root.name
        assert identity["scope"]["build_unit_id"] == receipt["build_unit_id"]
        assert identity["scope"]["family"] == "rust"
        assert identity["path"].endswith(f"execution-capture/command-{ordinal:03d}/record.json")
        assert identity["path"].startswith(f"data/build/rust/units/{receipt['build_unit_id']}/attempts/")
        assert identity["complete"] is True and identity["envp_captured"] is True
        assert "connect" in identity["collector"]["event_kinds"]
        assert identity["events"]["capped"] is False and identity["tool_calls"]["capped"] is False
        assert identity["events"]["counts"]["process_exec"] > 0
        assert identity["events"]["counts"]["file_open"] > 0
        assert identity["tool_calls"]["retained"] > 0
        for member in (identity, identity["events"], identity["secret_findings"],
                       identity["secret_scan"]["execution"], identity["secret_scan"]["report"]):
            assert file_sha256(run_root / member["path"]) == member["sha256"]
        record_path = run_root / identity["path"]
        record = json.loads(record_path.read_text(encoding="utf-8"))
        assert record["coverage"] == {"complete": True, "gaps": []}
        for call in record["tool_calls"]["records"]:
            assert file_sha256(record_path.parent / call["uri"]) == call["sha256"]
        # gitleaks really ran from the cataloged image and left a parseable report.
        execution = json.loads((run_root / identity["secret_scan"]["execution"]["path"]).read_text())
        assert execution["tool_id"] == "tool-gitleaks" and execution["version"] == gitleaks.version
        assert execution["exit_code"] in {0, 1} and execution["timed_out"] is False
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", execution["image_id"])
        assert gitleaks.expected_image_id in {None, execution["image_id"]}
        assert isinstance(json.loads((run_root / identity["secret_scan"]["report"]["path"]).read_text()), list)
        capture_root = record_path.parent
        assert not tuple(capture_root.glob("trace*")) and not (capture_root / ".secret-scan-input").exists()
    assert not tuple(run_root.rglob("trace.[0-9]*"))


def test_live_rust_language_build_accepts_hash_verified_execution_capture(tmp_path: Path) -> None:
    config, run_root, outcome, receipt = _live_rust_language_build(tmp_path, secret=False)
    assert outcome["status"] == "SUCCEEDED", outcome
    _assert_live_rust_capture(config, run_root, receipt)

    # The dependency-bearing build produced the executable and Rust intermediates.
    artifacts = {item["workspace_path"]: item for item in receipt["artifacts"]}
    executable = artifacts["rust/target/debug/appsec-fixture-rust"]
    assert executable["kind"] == "executable"
    assert file_sha256(run_root / executable["path"]) == executable["sha256"]
    assert executable["loader_dependency_status"] == "resolved"
    assert "libc.so.6" in executable["loader_dependencies"] and executable["loader_interpreter"]
    assert all(item["loader_dependency_status"] == "resolved" for item in receipt["artifacts"]
               if item["kind"] in {"executable", "shared-library"})
    kinds = {item["kind"] for item in receipt["artifacts"]}
    assert kinds >= {"executable", "rust-library", "rust-metadata", "dependency-metadata"}
    assert any(path.startswith("rust/target/debug/deps/libtime-") and path.endswith(".rlib")
               for path in artifacts)
    assert not any("execution-capture" in item["path"] for item in receipt["artifacts"])
    assert {package["name"] for package in receipt["cargo_metadata"]["packages"]} >= {
        "appsec-fixture-rust", "time", "libc"}
    assert receipt["cargo_metadata"]["relationships"]

    # rustc and the linker driver are observed directly as successful execve events, including
    # the toolchain compiler Cargo starts by absolute path.
    build = receipt["commands"][1]
    executed = [event for event in _capture_events(run_root, build)
                if event["kind"] == "process_exec" and event["result"] == 0]
    compilers = [event for event in executed if Path(event["executable"]).name == "rustc"]
    assert any("--crate-name" in event["argv"] and "appsec_fixture_rust" in event["argv"]
               for event in compilers)
    assert any(event["executable"].startswith("/usr/local/rustup/toolchains/") for event in compilers)
    assert any(Path(event["executable"]).name == "cc" for event in executed)
    assert all(event["envp_captured"] and event["envp"] for event in compilers)
    rows = receipt["tool_invocations"]
    row_kinds = {item["tool_kind"] for item in rows}
    assert row_kinds >= {"compiler", "linker-driver", "code-generator"}
    assert all(item["mapping"].startswith("syscall-process-exec") for item in rows)
    assert all(item["evidence"]["process_exec"]["count"] >= 1 for item in rows)
    assert all("argv" not in item and len(item["argv_sha256"]) == 64 for item in rows)
    assert receipt["link_database"]["relationship_count"] >= 1
    provenance = receipt["capture_provenance"]
    # rustc writes rlib archives in-process: the complete capture shows that no archiver ran.
    assert provenance["observed_tool_kinds"] == sorted(row_kinds) and "archiver" not in row_kinds
    assert provenance["complete"] is True and provenance["redacted_exec_events"] == 0
    assert provenance["envp_events"] > 0 and provenance["unreconciled_tool_calls"] == 0
    assert not any(command["tool"] != "cargo" for command in receipt["commands"])


def test_live_rust_language_build_detects_and_removes_an_envp_secret(tmp_path: Path) -> None:
    config, run_root, outcome, receipt = _live_rust_language_build(tmp_path, secret=True)
    assert outcome["status"] == "SUCCEEDED", outcome
    _assert_live_rust_capture(config, run_root, receipt)
    for command in receipt["commands"]:
        identity = command["execution_capture"]
        assert identity["secret_findings"]["count"] >= 1
        assert identity["secret_scan"]["exit_code"] == 1
        findings = json.loads((run_root / identity["secret_findings"]["path"]).read_text(encoding="utf-8"))
        assert findings["scanner"]["tool_id"] == "tool-gitleaks"
        assert all(item["secret_redacted"] for item in findings["findings"])
        assert {item["source"].split("/")[0] for item in findings["findings"]} & {"syscalls", "invocation.json"}
        # Envp was captured on every exec; the configured exact name removed the value.
        executed = [event for event in _capture_events(run_root, command) if event["kind"] == "process_exec"]
        assert any({"name": "DISCORD_PUBLIC_KEY", "redacted": True, "value": "<redacted>"} in event["envp"]
                   for event in executed)
        exact = json.loads((run_root / command["protected_argv"]["path"]).read_text(encoding="utf-8"))
        assert SYNTHETIC_SECRET not in json.dumps(exact)
    assert "DISCORD_PUBLIC_KEY" in receipt["capture_provenance"]["envp_redacted_names"]
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} >= {"compiler", "linker-driver"}
    leaked = [path for path in run_root.rglob("*")
              if path.is_file() and SYNTHETIC_SECRET.encode() in path.read_bytes()]
    assert not leaked, leaked
    assert (run_root / "data/build/rust/units" / receipt["build_unit_id"] / "workspace/rust/target/debug"
            / "appsec-fixture-rust").is_file()
