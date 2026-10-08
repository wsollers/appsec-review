from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
import time

import pytest

from appsec_review.container_runtime import (
    BuildProfile,
    ProjectImageBuildError,
    ProjectImageResolver,
    project_recipe_identity,
)


def test_project_image_is_derived_from_recipe_and_reused(tmp_path: Path) -> None:
    target = tmp_path / "target"
    project = target / "web"
    project.mkdir(parents=True)
    (project / "package.json").write_text('{"scripts":{"build":"tsc"}}', encoding="utf-8")
    (project / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
    base_id, derived_id = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    built = False
    calls = []

    def runner(argv, timeout):
        nonlocal built
        calls.append(tuple(argv))
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        if argv[:3] == ("docker", "image", "inspect"):
            reference = argv[3]
            if reference == "node-base:local":
                return 0, base_id.encode(), b"", False
            return (0, derived_id.encode(), b"", False) if built else (1, b"", b"missing", False)
        if argv[:3] == ("docker", "buildx", "build"):
            built = True
            return 0, b"built", b"", False
        raise AssertionError(argv)

    recipe = {
        "schema": "appsec-review/build-recipe/1", "build_unit_id": "build-unit-" + "1" * 20,
        "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
        "system_packages": [], "environment": {},
        "dependency_files": ["web/package.json", "web/package-lock.json"],
        "configure_commands": [], "build_commands": [["npm", "run", "build"]],
        "expected_outputs": ["web/dist"], "network_required": True,
        "reason": "fixture", "build_system": "node",
    }
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=target, runner=runner)
    profile = BuildProfile("node", "node-base:local", base_id, "10001:10001")
    first, _, _ = resolver.resolve(recipe, profile)
    second, _, _ = resolver.resolve(recipe, profile)

    assert first.customized and not first.reused
    assert second.reused and second.image_id == derived_id
    dockerfile = next((tmp_path / "metadata" / "project-images").glob("*/context/Dockerfile")).read_text()
    assert "FROM node-base:local" in dockerfile
    assert '["npm","ci","--ignore-scripts"]' in dockerfile
    assert "ENV NPM_CONFIG_CACHE=/opt/project-deps/npm-cache" in dockerfile
    assert "ENV NODE_PATH=/opt/project/web/node_modules" in dockerfile
    assert "ENV PATH=/opt/project/web/node_modules/.bin:$PATH" in dockerfile
    assert sum(call[:3] == ("docker", "buildx", "build") for call in calls) == 1
    build_call = next(call for call in calls if call[:3] == ("docker", "buildx", "build"))
    assert build_call[-1] == str(next((tmp_path / "metadata" / "project-images").glob("*/context")).resolve())


def test_project_image_failure_retains_bounded_diagnostics(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "Cargo.toml").write_text("[package]\nname='fixture'\nversion='0.1.0'\n", encoding="utf-8")
    base_id = "sha256:" + "a" * 64

    def runner(argv, _timeout):
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, base_id.encode(), b"", False
        if argv[:3] == ("docker", "buildx", "build"):
            return 1, b"build output", b"specific failure", False
        raise AssertionError(argv)

    recipe = {
        "schema": "appsec-review/build-recipe/1", "build_unit_id": "build-unit-" + "1" * 20,
        "image_profile": "rust", "source_dir": ".", "build_dir": "target",
        "system_packages": ["libssl-dev"], "environment": {}, "dependency_files": ["Cargo.toml"],
        "configure_commands": [], "build_commands": [["cargo", "build"]],
        "expected_outputs": ["target/debug/fixture"], "network_required": False,
        "reason": "fixture", "build_system": "cargo",
    }
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=target, runner=runner)
    with pytest.raises(ProjectImageBuildError) as raised:
        resolver.resolve(recipe, BuildProfile("rust", "rust-base:local", base_id, "10001:10001"))
    assert raised.value.stdout == b"build output"
    assert raised.value.stderr == b"specific failure"


def test_project_image_identity_ignores_explanatory_reason() -> None:
    profile = BuildProfile("native", "native-base:local", "sha256:" + "a" * 64, "10001:10001")
    recipe = {"schema": "appsec-review/build-recipe/1", "build_unit_id": "build-unit-" + "1" * 20,
              "image_profile": "native", "source_dir": ".", "build_dir": "build",
              "system_packages": [], "environment": {}, "dependency_files": ["CMakeLists.txt"],
              "configure_commands": [["cmake", "-S", ".", "-B", "build"]],
              "build_commands": [["cmake", "--build", "build"]],
              "expected_outputs": ["build/app"], "network_required": False,
              "reason": "first explanation", "build_system": "cmake"}
    first = project_recipe_identity(recipe, profile, {"CMakeLists.txt": "f" * 64})
    second = project_recipe_identity({**recipe, "reason": "different prose"}, profile,
                                     {"CMakeLists.txt": "f" * 64})
    assert first == second


def test_project_image_builds_wait_for_shared_docker_mutation_lock(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "CMakeLists.txt").write_text("project(fixture)\n", encoding="utf-8")
    base_id, derived_id = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    built: set[str] = set()
    guard, active, maximum = threading.Lock(), 0, 0

    def runner(argv, _timeout):
        nonlocal active, maximum
        if argv[:3] == ("docker", "image", "inspect"):
            reference = argv[3]
            if reference == "native-base:local":
                return 0, base_id.encode(), b"", False
            return (0, derived_id.encode(), b"", False) if reference in built else (1, b"", b"", False)
        if argv[:3] == ("docker", "buildx", "build"):
            tag = argv[argv.index("--tag") + 1]
            with guard:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.05)
            with guard:
                active -= 1
                built.add(tag)
            return 0, b"built", b"", False
        raise AssertionError(argv)

    base_recipe = {"schema": "appsec-review/build-recipe/1", "image_profile": "native",
                   "source_dir": ".", "build_dir": "build", "system_packages": ["cmake"],
                   "environment": {}, "dependency_files": ["CMakeLists.txt"],
                   "configure_commands": [["cmake", "-S", ".", "-B", "build"]],
                   "build_commands": [["cmake", "--build", "build"]],
                   "expected_outputs": ["build/app"], "network_required": False,
                   "reason": "fixture", "build_system": "cmake"}
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=target, runner=runner)
    profile = BuildProfile("native", "native-base:local", base_id, "10001:10001")
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda ordinal: resolver.resolve(
            {**base_recipe, "build_unit_id": "build-unit-" + str(ordinal) * 20}, profile), (1, 2)))
    assert maximum == 1
