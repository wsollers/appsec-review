from __future__ import annotations

import hashlib
from pathlib import Path

from appsec_review.jobs.build_discovery import (
    BUILD_RECIPE_SCHEMA, descriptor_package, discover_build_units, normalize_build_recipe,
    validate_build_recipe,
)


def _file(path: str, content: str = "x") -> dict[str, object]:
    value = content.encode()
    return {"path": path, "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}


def test_discovery_groups_descriptors_without_repository_specific_names() -> None:
    files = [
        _file("native/CMakeLists.txt"), _file("native/CMakePresets.json"),
        _file("native/Makefile"), _file("native/src/main.cpp"),
        _file("rust/member/Cargo.toml"), _file("go/service/go.mod"),
        _file("java/app/pom.xml"), _file("unrelated/README.md"),
    ]
    units = discover_build_units(files)
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        ("go/service", "go", "go"), ("java/app", "java", "maven"),
        ("native", "native", "cmake"), ("rust/member", "rust", "cargo"),
    ]
    native = next(item for item in units if item["family"] == "native")
    assert {item["path"] for item in native["markers"]} == {
        "native/CMakeLists.txt", "native/CMakePresets.json",
    }


def test_source_only_compiled_tree_becomes_one_direct_build_unit() -> None:
    units = discover_build_units([
        _file("service/src/com/example/Main.java"),
        _file("service/src/com/example/Helper.java"),
        _file("native/CMakeLists.txt"), _file("native/src/main.cpp"),
    ])
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        ("native", "native", "cmake"), ("service", "java", "javac"),
    ]
    assert {item["path"] for item in units[1]["markers"]} == {
        "service/src/com/example/Main.java", "service/src/com/example/Helper.java",
    }


def test_dotnet_project_suffixes_cover_csharp_visual_basic_and_fsharp() -> None:
    units = discover_build_units([
        _file("csharp/App.csproj"), _file("visual-basic/App.vbproj"), _file("fsharp/App.fsproj"),
    ])
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        ("csharp", "dotnet", "dotnet"), ("fsharp", "dotnet", "dotnet"),
        ("visual-basic", "dotnet", "dotnet"),
    ]


def test_descriptor_package_is_bounded_and_hash_identified(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    values = {"native/CMakeLists.txt": "project(sample)\n", "native/README.md": "build notes\n"}
    files = []
    for relative, content in values.items():
        (target / relative).write_text(content, encoding="utf-8")
        files.append(_file(relative, content))
    unit = discover_build_units(files)[0]
    package = descriptor_package(target, unit, files)
    assert [item["path"] for item in package["documents"]] == sorted(values)
    assert package["bounds"]["actual_bytes"] == sum(len(value.encode()) for value in values.values())
    assert package["gaps"] == []


def _recipe(unit: dict[str, object]) -> dict[str, object]:
    return {
        "schema": BUILD_RECIPE_SCHEMA, "build_unit_id": unit["build_unit_id"],
        "image_profile": "native", "source_dir": "native", "build_dir": "native/build",
        "system_packages": ["libssl-dev"], "environment": {"CFLAGS": "-O2"},
        "dependency_files": [item["path"] for item in unit["markers"]],
        "configure_commands": [["cmake", "-S", "native", "-B", "native/build"]],
        "build_commands": [["cmake", "--build", "native/build"]],
        "expected_outputs": ["native/build"], "network_required": False,
        "reason": "CMake descriptor declares a native build",
    }


def test_recipe_validation_accepts_argv_and_rejects_model_escape_routes() -> None:
    unit = discover_build_units([_file("native/CMakeLists.txt")])[0]
    assert validate_build_recipe(_recipe(unit), unit) == []

    bad = _recipe(unit)
    bad["environment"] = {"API_TOKEN": "secret"}
    bad["build_commands"] = [["cmake", "--build", "native/build", "&&", "curl"]]
    bad["expected_outputs"] = ["../../host"]
    bad["source_dir"] = "another-project"
    errors = validate_build_recipe(bad, unit)
    assert any("environment key is unsafe" in error for error in errors)
    assert any("shell syntax" in error for error in errors)
    assert any("expected_outputs" in error for error in errors)
    assert any("source_dir must" in error for error in errors)


def test_recipe_validation_forbids_target_execution_and_tool_installation() -> None:
    unit = discover_build_units([_file("rust/Cargo.toml")])[0]
    recipe = {
        "schema": BUILD_RECIPE_SCHEMA, "build_unit_id": unit["build_unit_id"],
        "image_profile": "rust", "source_dir": "rust", "build_dir": "rust/target",
        "system_packages": [], "environment": {}, "dependency_files": ["rust/Cargo.toml"],
        "configure_commands": [], "build_commands": [["cargo", "run"]],
        "expected_outputs": ["rust/target"], "network_required": False, "reason": "bad",
    }
    assert any("execution, tests, or tool installation" in error
               for error in validate_build_recipe(recipe, unit))


def test_lockless_node_recipe_normalizes_npm_ci_before_acceptance() -> None:
    unit = discover_build_units([_file("web/package.json")])[0]
    recipe = {
        "schema": BUILD_RECIPE_SCHEMA, "build_unit_id": unit["build_unit_id"],
        "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
        "system_packages": [], "environment": {}, "dependency_files": ["web/package.json"],
        "configure_commands": [["npm", "ci"]], "build_commands": [["npm", "run", "build"]],
        "expected_outputs": [], "network_required": True, "reason": "inferred fixture",
    }
    assert any("npm ci only" in error for error in validate_build_recipe(recipe, unit))
    normalized = normalize_build_recipe(recipe)
    assert normalized["configure_commands"] == []
    assert validate_build_recipe(normalized, unit) == []


def test_java_recipe_normalization_removes_host_specific_java_home() -> None:
    recipe = {
        "image_profile": "java",
        "environment": {
            "JAVA_HOME": "/usr/lib/jvm/java-11-openjdk-amd64",
            "MAVEN_OPTS": "-Xmx1g",
        },
    }
    normalized = normalize_build_recipe(recipe)
    assert normalized["environment"] == {"MAVEN_OPTS": "-Xmx1g"}


def test_teamcity_kotlin_dsl_is_not_a_java_build_unit() -> None:
    units = discover_build_units([
        _file(".teamcity/settings.kts"),
        _file("projects/java/sample/src/Main.java"),
    ])
    assert [(unit["root"], unit["family"]) for unit in units] == [
        ("projects/java/sample", "java")]


def test_dotnet_recipe_normalization_regenerates_workspace_restore_outputs() -> None:
    recipe = {
        "image_profile": "dotnet",
        "configure_commands": [],
        "build_commands": [[
            "dotnet", "build", "--configuration", "Release", "--no-restore",
            "-p:TreatWarningsAsErrors=true",
        ]],
    }
    normalized = normalize_build_recipe(recipe)
    assert normalized["build_commands"] == [[
        "dotnet", "build", "--configuration", "Release", "-p:TreatWarningsAsErrors=true",
    ]]
