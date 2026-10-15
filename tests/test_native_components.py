"""Routing of mixed C/C++ units, source-only scopes, and the Go command contract.

Every layout here is synthetic: the rules come from descriptors, build files and catalog data,
never from a particular review target.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from appsec_review.applicability import (
    ApplicabilityAction, ProcessingDisposition, ProcessingFeature, ReasonCode,
    evaluate_applicability, source_only_facts,
)
from appsec_review.jobs.build_discovery import (
    BUILD_RECIPE_SCHEMA, GO_MOD_SUBCOMMANDS, GO_SUBCOMMANDS, build_recipe_inference_policy,
    descriptor_package, discover_build_units, go_recipe_errors, source_only_scopes,
    validate_build_recipe,
)
from appsec_review.jobs.job_language_build import go as go_adapter


def _file(path: str, content: str = "x") -> dict[str, object]:
    value = content.encode()
    return {"path": path, "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}


def test_mixed_c_sources_route_to_the_owning_package_family_without_native_duplicates() -> None:
    """A synthetic monorepo: several C-extension packages, a phpize extension, a node addon, a
    wasm build script, a standalone C tree, and a CMake library next to a cargo crate."""
    scripts = {
        "web/wasm-codec/build.sh": "#!/bin/sh\nclang --target=wasm32 -nostdlib -o out.wasm src/codec.c\n",
        "tools/native-cli/build.sh": "#!/bin/sh\ncc -o cli main.c\n",
    }
    files = [
        _file("pkgs/alpha/pyproject.toml"), _file("pkgs/alpha/src/alpha/_speed.c"),
        _file("pkgs/alpha/requirements-build.txt"),
        _file("pkgs/beta/setup.py"), _file("pkgs/beta/ext/beta.cc"), _file("pkgs/beta/ext/nested/util.c"),
        _file("ext/php-hash/config.m4"), _file("ext/php-hash/hash.c"),
        _file("addons/fast/package.json"), _file("addons/fast/binding.gyp"), _file("addons/fast/src/fast.cc"),
        _file("web/wasm-codec/build.sh", scripts["web/wasm-codec/build.sh"]),
        _file("web/wasm-codec/src/codec.c"),
        _file("tools/native-cli/build.sh", scripts["tools/native-cli/build.sh"]),
        _file("tools/native-cli/main.c"),
        _file("libs/zstd/CMakeLists.txt"), _file("libs/zstd/src/zstd.c"),
        _file("crates/zstd-sys/Cargo.toml"), _file("crates/zstd-sys/csrc/shim.c"),
    ]
    units = discover_build_units(files, read_text=scripts.get)
    by_root = {item["root"]: item for item in units}
    assert sorted((item["root"], item["family"], item["build_system"]) for item in units) == [
        ("addons/fast", "node", "node"),
        ("crates/zstd-sys", "rust", "cargo"),
        # Rust/Go/JVM builds do not own C sources: a standalone C tree stays direct-native.
        ("crates/zstd-sys/csrc", "native", "direct-native"),
        ("ext/php-hash", "php", "phpize"),
        ("libs/zstd", "native", "cmake"),
        ("pkgs/alpha", "python", "python"),
        ("pkgs/beta", "python", "python"),
        ("tools/native-cli", "native", "direct-native"),
        ("web/wasm-codec", "wasm", "clang"),
    ]
    components = {root: [value["path"] for value in item.get("native_components", ())]
                  for root, item in by_root.items()}
    assert components["pkgs/alpha"] == ["pkgs/alpha/src/alpha/_speed.c"]
    assert components["pkgs/beta"] == ["pkgs/beta/ext/beta.cc", "pkgs/beta/ext/nested/util.c"]
    assert components["ext/php-hash"] == ["ext/php-hash/hash.c"]
    assert components["addons/fast"] == ["addons/fast/src/fast.cc"]
    assert components["web/wasm-codec"] == ["web/wasm-codec/src/codec.c"]
    assert components["libs/zstd"] == [] and components["tools/native-cli"] == []
    assert [value["path"] for value in by_root["web/wasm-codec"]["markers"]] == ["web/wasm-codec/build.sh"]
    # Without a bounded script reader the wasm intent is unknown and the C tree stays native.
    plain = {(item["root"], item["family"]) for item in discover_build_units(files)}
    assert ("web/wasm-codec", "native") in plain and ("web/wasm-codec", "wasm") not in plain


def test_family_descriptor_package_carries_markers_requirements_and_native_components(tmp_path: Path) -> None:
    contents = {
        "pkg/pyproject.toml": "[build-system]\nrequires=['setuptools==75.6.0']\n",
        "pkg/setup.py": "from setuptools import Extension, setup\nsetup(ext_modules=[Extension('m', ['src/m.c'])])\n",
        "pkg/requirements-build.txt": "setuptools==75.6.0\n",
        "pkg/src/m.c": "int m(void) { return 0; }\n",
    }
    for relative, text in contents.items():
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative).write_text(text, encoding="utf-8")
    files = [_file(path, text) for path, text in contents.items()]
    units = discover_build_units(files)
    assert [(item["root"], item["family"]) for item in units] == [("pkg", "python")]
    package = descriptor_package(tmp_path, units[0], files)
    assert {item["path"] for item in package["documents"]} == set(contents)
    policy = build_recipe_inference_policy({**units[0], "descriptor_package": package})
    assert policy["required_image_profile"] == "python"
    assert {"pip", "python"} <= set(policy["allowed_executables"])
    assert policy["native_components"]["sources"] == ["pkg/src/m.c"]


def test_source_only_scopes_are_recorded_not_applicable_for_build_processing() -> None:
    files = [_file("svc/api/app.py"), _file("svc/api/routes/users.py"), _file("svc/worker/main.py"),
             _file("site/index.php"), _file("site/pages/home.php"),
             _file("lib/pyproject.toml"), _file("lib/src/lib/__init__.py")]
    units = discover_build_units(files)
    scopes = source_only_scopes(files, units)
    assert [(item["root"], item["language"], item["source_count"]) for item in scopes] == [
        ("site", "php", 2), ("svc/api", "python", 2), ("svc/worker", "python", 1)]
    scope = scopes[0]
    facts = source_only_facts(project_id=scope["scope_id"], language=scope["language"],
                              root=scope["root"], sources=scope["sources"])
    for feature, reason in ((ProcessingFeature.BUILD_CAPTURE, ReasonCode.MATERIAL_BUILD_ABSENT),
                            (ProcessingFeature.COMPILER_ARTIFACTS, ReasonCode.ARTIFACT_CAPABILITY_ABSENT)):
        for policy in ("required", "auto"):
            decision = evaluate_applicability(feature=feature, policy=policy, facts=facts,
                                              configuration_sha256="0" * 64)
            assert decision.action is ApplicabilityAction.SKIP
            assert decision.disposition is ProcessingDisposition.SKIPPED_NA
            assert decision.reason_code is reason


def test_phpize_recipe_may_run_only_its_generated_configure_script() -> None:
    unit = {"build_unit_id": "build-unit-" + "1" * 20, "family": "php", "root": "ext/a",
            "build_system": "phpize", "markers": [{"path": "ext/a/config.m4"}],
            "descriptor_package": {"documents": [{"path": "ext/a/config.m4"}]}}
    recipe = {"schema": BUILD_RECIPE_SCHEMA, "build_unit_id": unit["build_unit_id"],
              "image_profile": "php", "source_dir": "ext/a", "build_dir": "ext/a",
              "system_packages": [], "environment": {}, "dependency_files": ["ext/a/config.m4"],
              "configure_commands": [["phpize"], ["./configure", "--enable-a"]],
              "build_commands": [["make", "-j1"]], "expected_outputs": ["ext/a/modules/a.so"],
              "network_required": False, "reason": "phpize lifecycle"}
    assert validate_build_recipe(recipe, unit) == []
    assert any("allowlisted" in error
               for error in validate_build_recipe(recipe, {**unit, "build_system": "composer"}))
    other = {**recipe, "configure_commands": [["phpize"], ["./other-script"]]}
    assert any("allowlisted" in error for error in validate_build_recipe(other, unit))


@pytest.mark.parametrize("argv", [
    ["go", "mod", subcommand] for subcommand in sorted(GO_MOD_SUBCOMMANDS)
] + [["go", "build", "./..."], ["go", "build", "-o", "bin/", "./cmd/..."], ["go", "generate", "./..."]])
def test_every_go_command_the_recipe_contract_accepts_is_executable_by_language_build(argv) -> None:
    """The planner/probe contract and the language-build executor share one allowlist."""
    recipe = {"configure_commands": [], "build_commands": [argv, ["go", "build", "./..."]],
              "environment": {}}
    assert go_recipe_errors(recipe) == ()
    executed = go_adapter.build_argv(argv)
    assert executed[:2] == tuple(argv[:2])
    if argv[1] == "mod":
        assert executed == tuple(argv)  # dependency preparation runs unchanged


def test_go_contract_rejects_what_the_executor_rejects() -> None:
    assert GO_SUBCOMMANDS == {"build", "generate", "mod"}
    for argv in (["go", "run", "."], ["go", "mod", "tidy"], ["go", "test", "./..."]):
        assert go_recipe_errors({"build_commands": [argv, ["go", "build", "."]],
                                 "configure_commands": [], "environment": {}})
        with pytest.raises(ValueError):
            go_adapter.build_argv(argv)


def test_go_workspace_with_several_modules_gets_one_unit_per_module() -> None:
    files = [_file("go.work"), _file("svc/a/go.mod"), _file("svc/a/main.go"),
             _file("svc/b/go.mod"), _file("svc/b/cmd/b/main.go"), _file("lib/go.mod"), _file("lib/lib.go")]
    shape = sorted((item["root"], item["family"]) for item in discover_build_units(files))
    assert shape == [(".", "go"), ("lib", "go"), ("svc/a", "go"), ("svc/b", "go")]
