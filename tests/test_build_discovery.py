from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath

import pytest

from appsec_review.jobs.build_discovery import (
    BUILD_RECIPE_SCHEMA, android_descriptor_facts, build_recipe_inference_policy,
    descriptor_inventory_paths, descriptor_package, discover_build_inventory, discover_build_units, is_build_descriptor,
    make_default_build_commands, native_build_capability_gap, node_manifest_declares_dependencies,
    node_workspace, normalize_build_recipe, required_image_profile,
    recipe_execution_cwd, unsupported_build_gaps, validate_build_recipe,
)
from appsec_review.jobs.discovery_assignment import assign_paths
from appsec_review.storage import canonical_json


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
    # The Makefile beside the CMake project only invokes cmake: it is that unit's context, not a unit
    # (plan §2.1 decision 2 — read, never dropped by position).
    texts = {"native/Makefile": "all:\n\tcmake -S . -B build && cmake --build build\n",
             "native/CMakeLists.txt": "project(native CXX)\nadd_executable(native src/main.cpp)\n"}
    inventory = discover_build_inventory(files, read_text=texts.get)
    units = inventory["units"]
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        ("go/service", "go", "go"), ("java/app", "java", "maven"),
        ("native", "native", "cmake"), ("rust/member", "rust", "cargo"),
    ]
    native = next(item for item in units if item["family"] == "native")
    # A preset is context the project reads, never a marker (job pass 05 / T-056.2).
    assert {item["path"] for item in native["markers"]} == {"native/CMakeLists.txt"}
    assert "parallel_with" not in native
    assert [(d["markers"], d["role"], d.get("unit")) for d in inventory["demoted_markers"]] == [
        (["native/Makefile"], "context", "native|cmake")]
    assert assign_paths(files, inventory)["native/Makefile"] == "context:native|cmake"
    # Without descriptor text the Makefile cannot be read: both units stand, CMake holding capture authority.
    blind = {(u["root"], u["build_system"]): u for u in discover_build_units(files)}
    assert blind[("native", "make")]["capture_authority"] == "secondary"
    assert blind[("native", "make")]["parallel_with"] == ["native|cmake"]
    assert blind[("native", "cmake")]["capture_authority"] == "primary"


def test_compiled_sources_without_a_build_point_are_orphaned_findings_not_units() -> None:
    """A tree of .java files with no build descriptor is reported, never guessed into a javac unit
    (decision 2026-11-08: orphaned sources are knowledge — dead code, build drift, an abandoned port,
    or a build we did not understand)."""
    inventory = discover_build_inventory([
        _file("service/src/com/example/Main.java"),
        _file("service/src/com/example/Helper.java"),
        _file("native/CMakeLists.txt"), _file("native/src/main.cpp"),
        _file("native/tools/gen.rs"),
    ])
    assert [(item["root"], item["family"], item["build_system"]) for item in inventory["units"]] == [
        ("native", "native", "cmake")]
    orphans = {item["path"]: item for item in inventory["orphaned_sources"]}
    assert set(orphans) == {"service/src/com/example/Main.java", "service/src/com/example/Helper.java",
                            "native/tools/gen.rs"}
    assert orphans["service/src/com/example/Main.java"]["language"] == "java"
    assert orphans["service/src/com/example/Main.java"]["reason"] == "no_build_point"
    assert orphans["service/src/com/example/Main.java"]["nearest_unit"] is None
    # A Rust file under a CMake root is still orphaned: the nearest unit is named, and why it did not claim it.
    assert orphans["native/tools/gen.rs"]["nearest_unit"] == {
        "root": "native", "family": "native", "build_system": "cmake", "why_not": "different family"}
    assert discover_build_units([_file("x/src/a.c")]) == []


def test_dotnet_project_suffixes_cover_csharp_visual_basic_and_fsharp() -> None:
    units = discover_build_units([
        _file("csharp/App.csproj"), _file("visual-basic/App.vbproj"), _file("fsharp/App.fsproj"),
    ])
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        ("csharp", "dotnet", "dotnet"), ("fsharp", "dotnet", "dotnet"),
        ("visual-basic", "dotnet", "dotnet"),
    ]


def test_native_project_and_makefile_variants_are_discovered() -> None:
    units = discover_build_units([
        _file("modern/App.VCXPROJ"), _file("legacy/App.vcproj"),
        _file("make/makefile"), _file("gnu/GNUmakefile"),
    ])
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        ("gnu", "native", "make"), ("legacy", "native", "vcbuild"),
        ("make", "native", "make"), ("modern", "native", "msbuild"),
    ]


def test_bundler_is_a_precise_execution_gap_not_a_false_build_unit() -> None:
    files = [_file("ruby/Gemfile", "source 'https://rubygems.org'\n"),
             _file("ruby/Gemfile.lock", "GEM\n")]
    units = discover_build_units(files)
    assert units == []
    assert unsupported_build_gaps(files, units) == [
        "ruby/Gemfile: Bundler build unavailable: no pinned Ruby build profile or executor; "
        "gem installation, lifecycle hooks, packaging, and native extensions were not run"]


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


def test_descriptor_authority_preserves_crlf_bytes_and_refuses_changed_hash(tmp_path: Path) -> None:
    content = b"project(sample)\r\nadd_library(A STATIC a.c)\r\n"
    path = tmp_path / "CMakeLists.txt"
    path.write_bytes(content)
    files = [{"path": path.name, "sha256": hashlib.sha256(content).hexdigest(),
              "size_bytes": len(content)}]
    unit = discover_build_units(files)[0]
    package = descriptor_package(tmp_path, unit, files)
    assert package["documents"][0]["content"].encode() == content
    path.write_bytes(content.replace(b"\r\n", b"\n"))
    with pytest.raises(ValueError, match="descriptor identity changed"):
        descriptor_package(tmp_path, unit, files)


def test_own_make_authority_precedes_nested_context_without_widening_bounds(tmp_path: Path) -> None:
    values = {f"wrapper/AA/{index}/README.md": "nested context" for index in range(25)}
    values["wrapper/Makefile"] = "all:\n\t$(MSBUILD) native.sln\n"
    files = []
    for relative, content in values.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        files.append(_file(relative, content))
    unit = discover_build_units(files)[0]
    package = descriptor_package(tmp_path, unit, files)
    assert any(document["path"] == "wrapper/Makefile" for document in package["documents"])
    assert package["bounds"] == {
        "max_files": 24, "max_file_bytes": 65536, "max_total_bytes": 262144,
        "actual_files": 24, "actual_bytes": len(values["wrapper/Makefile"].encode()) + 23 * len("nested context"),
    }
    assert [document["path"] for document in package["documents"]] == sorted(
        document["path"] for document in package["documents"])
    assert "descriptor file-count bound reached" in package["gaps"]


def test_node_workspace_member_receives_bounded_ancestor_descriptors(tmp_path: Path) -> None:
    target = tmp_path / "target"
    values = {
        "package.json": '{"private":true,"workspaces":["apps/*"]}\n',
        "package-lock.json": '{"lockfileVersion":3}\n',
        "tsconfig.base.json": '{"compilerOptions":{"target":"ES2022"}}\n',
        "apps/web/package.json": '{"scripts":{"build":"tsc"}}\n',
        "apps/web/tsconfig.json": '{"extends":"../../tsconfig.base.json"}\n',
        "apps/other/package.json": '{}\n',
    }
    files = []
    for relative, content in values.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        files.append(_file(relative, content))
    unit = next(item for item in discover_build_units(files) if item["root"] == "apps/web")
    package = descriptor_package(target, unit, files)
    assert {item["path"] for item in package["documents"]} == {
        "package.json", "package-lock.json", "tsconfig.base.json",
        "apps/web/package.json", "apps/web/tsconfig.json",
    }
    recipe = {
        "image_profile": "node", "dependency_files": ["apps/web/package.json"],
        "configure_commands": [], "build_commands": [["npm", "run", "build"]],
    }
    normalized = normalize_build_recipe(recipe, {**unit, "descriptor_package": package})
    # The workspace installs as one tree: every member manifest travels with the root lockfile.
    assert normalized["dependency_files"] == [
        "apps/web/package.json", "apps/other/package.json", "package-lock.json", "package.json",
        "tsconfig.base.json"]


def test_go_checksum_files_are_accepted_dependency_descriptors(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "svc").mkdir(parents=True)
    values = {"svc/go.mod": "module example.test/svc\n", "svc/go.sum": "example.test/dep v1.0.0 h1:x=\n",
              "svc/go.work.sum": "example.test/dep v1.0.0/go.mod h1:y=\n", "svc/main.go": "package main\n"}
    files = []
    for relative, content in values.items():
        (target / relative).write_text(content, encoding="utf-8")
        files.append(_file(relative, content))
    unit = next(item for item in discover_build_units(files) if item["family"] == "go")
    package = descriptor_package(target, unit, files)
    # Without go.sum a recipe cannot pin the module checksums its dependency image restores.
    assert [item["path"] for item in package["documents"]] == ["svc/go.mod", "svc/go.sum", "svc/go.work.sum"]


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


def test_execution_cwd_omission_preserves_legacy_recipe_shape_hash_and_defaults() -> None:
    unit = discover_build_units([_file("native/CMakeLists.txt")])[0]
    recipe = _recipe(unit)
    original = copy.deepcopy(recipe)
    original_bytes = canonical_json(recipe)
    assert recipe_execution_cwd(recipe, "configure") == "native"
    assert recipe_execution_cwd(recipe, "build") == "native"
    assert validate_build_recipe(recipe, unit) == []
    normalized = normalize_build_recipe(recipe, unit)
    assert normalized == original == recipe
    assert "execution_cwd" not in normalized
    assert canonical_json(normalized) == original_bytes
    assert hashlib.sha256(canonical_json(normalized)).digest() == hashlib.sha256(original_bytes).digest()


@pytest.mark.parametrize("overrides,configure,build", [
    ({"configure": "native"}, "native", "native"),
    ({"build": "native/build"}, "native", "native/build"),
    ({"configure": "native/configure", "build": "native/build/subdir"}, "native/configure", "native/build/subdir"),
])
def test_execution_cwd_explicit_phase_paths_validate_without_mutating_origin(overrides, configure, build) -> None:
    unit = discover_build_units([_file("native/CMakeLists.txt")])[0]
    legacy = _recipe(unit)
    recipe = {**copy.deepcopy(legacy), "execution_cwd": overrides}
    original = copy.deepcopy(recipe)
    assert validate_build_recipe(recipe, unit) == []
    assert recipe_execution_cwd(recipe, "configure") == configure
    assert recipe_execution_cwd(recipe, "build") == build
    assert normalize_build_recipe(recipe, unit) == original == recipe
    assert recipe["source_dir"] == legacy["source_dir"] == unit["root"]
    assert hashlib.sha256(canonical_json(recipe)).digest() != hashlib.sha256(canonical_json(legacy)).digest()


@pytest.mark.parametrize("value", [
    None, [], {}, "native/build", {"export": "native/build"}, {"build": "native", "unknown": "native"},
    {"build": ""}, {"build": 1}, {"build": None}, {"build": []},
    {"build": "/tmp"}, {"build": "/workspace/native"}, {"build": "../native"},
    {"build": "native/../sibling"}, {"build": "sibling"}, {"build": "native-other"},
    {"build": "native\\build"}, {"build": "C:/host"}, {"build": "native/C:drive"},
    {"build": "//host/path"}, {"build": "./native"}, {"build": "native//build"},
    {"build": "native/./build"}, {"build": "native/build/"},
    {"build": "native/\0"}, {"build": "native/\n"}, {"build": "native/\r"}, {"build": "native/\x7f"},
    {"build": "native/" + "x" * 512},
])
def test_execution_cwd_rejects_unsafe_unknown_and_malformed_overrides(value) -> None:
    unit = discover_build_units([_file("native/CMakeLists.txt")])[0]
    recipe = {**_recipe(unit), "execution_cwd": value}
    assert any("execution_cwd" in error for error in validate_build_recipe(recipe, unit))
    with pytest.raises(ValueError, match="execution_cwd"):
        recipe_execution_cwd(recipe, "build")


def test_execution_cwd_does_not_override_origin_profile_or_unit_validation() -> None:
    unit = discover_build_units([_file("native/CMakeLists.txt")])[0]
    recipe = {**_recipe(unit), "source_dir": "sibling", "execution_cwd": {"build": "native/build"},
              "image_profile": "java", "build_unit_id": "unaccepted"}
    errors = validate_build_recipe(recipe, unit)
    assert "source_dir must equal the accepted build-unit root" in errors
    assert any("required profile native" in error for error in errors)
    assert any("build_unit_id does not match" in error for error in errors)
    with pytest.raises(ValueError, match="accepted build-unit root"):
        recipe_execution_cwd(recipe, "build")
    with pytest.raises(ValueError, match="phase must"):
        recipe_execution_cwd(_recipe(unit), "export")


def test_execution_cwd_root_project_is_target_relative_not_host_relative() -> None:
    unit = discover_build_units([_file("CMakeLists.txt")])[0]
    recipe = {**_recipe(unit), "source_dir": ".", "build_dir": "build",
              "expected_outputs": ["build"], "execution_cwd": {"configure": ".", "build": "build"}}
    assert validate_build_recipe(recipe, unit) == []
    assert recipe_execution_cwd(recipe, "configure") == "."
    assert recipe_execution_cwd(recipe, "build") == "build"


def test_execution_cwd_recipe_schema_matches_runtime_contract() -> None:
    import jsonschema

    schema = json.loads((Path(__file__).parents[1] / "docs/schemas/build-recipe.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema)
    validator.check_schema(schema)
    unit = discover_build_units([_file("native/CMakeLists.txt")])[0]
    legacy = _recipe(unit)
    validator.validate(legacy)
    for overrides in ({"configure": "native"}, {"build": "native/build"},
                      {"configure": "native", "build": "native/build"}):
        recipe = {**legacy, "execution_cwd": overrides}
        validator.validate(recipe)
        assert validate_build_recipe(recipe, unit) == []
    for overrides in (None, {}, {"export": "native"}, {"build": "/host"}, {"build": "native/../host"},
                      {"build": "native//build"}, {"build": "native/\n"}, {"build": "C:/host"},
                      {"build": "native/build/"}, {"build": "native/./build"}):
        recipe = {**legacy, "execution_cwd": overrides}
        assert list(validator.iter_errors(recipe))
        assert validate_build_recipe(recipe, unit)


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


@pytest.mark.parametrize("system,command", (
    ("autotools", ["make", "--version"]),
    ("autotools", ["autoreconf", "-fi"]),
    ("make", ["make", "-n"]),
    ("make", ["make", "-Bn"]),
    ("make", ["make", "--dry-run"]),
    ("make", ["make", "--question"]),
    ("cmake", ["cmake", "--version"]),
))
def test_native_version_dry_run_and_bootstrap_are_not_compilation(system, command) -> None:
    markers = {"autotools": ["configure.ac", "Makefile.am"], "make": ["Makefile"],
               "cmake": ["CMakeLists.txt"]}[system]
    unit = discover_build_units([_file("native/" + marker) for marker in markers])[0]
    recipe = {**_recipe(unit), "configure_commands": [], "build_commands": [command], "expected_outputs": []}
    assert any("no compilation or build step" in error for error in validate_build_recipe(recipe, unit))


def test_autotools_fragment_is_not_a_standalone_make_project() -> None:
    # A Makefile.am under a configure.ac is a marker (plan §2.1 item 8); the fragment's own directory is
    # still not a standalone build the recipe may run ``make`` in.
    units = discover_build_units([_file("native/configure.ac"), _file("native/include/Makefile.am")])
    unit = next(u for u in units if u["root"] == "native/include")
    recipe = {**_recipe(unit), "source_dir": unit["root"], "build_dir": unit["root"],
              "configure_commands": [], "build_commands": [["make"]], "expected_outputs": []}
    assert any("nonstandalone_autotools_fragment" in error for error in validate_build_recipe(recipe, unit))


def test_standalone_native_bootstrap_is_preserved_before_a_real_build() -> None:
    unit = discover_build_units([_file("native/configure.ac"), _file("native/Makefile.am")])[0]
    recipe = {**_recipe(unit), "configure_commands": [],
              "build_commands": [["autoreconf", "-fi"], ["make", "-j2"]]}
    normalized = normalize_build_recipe(recipe, unit)
    assert normalized["configure_commands"] == [["autoreconf", "-fi"]]
    assert normalized["build_commands"] == [["make", "-j2"]]
    assert validate_build_recipe(normalized, unit) == []


@pytest.mark.parametrize("kind", ("windows", "orchestration", "portable"))
def test_make_default_authority_distinguishes_native_wrappers_from_portable_builds(kind) -> None:
    windows = "\tif not exist bin mkdir bin\n\tpowershell build.ps1\n\t$(MSBUILD) native.sln\n"
    text = {
        "windows": "all: native\nnative:\n" + windows,
        "orchestration": "db-docker:\n\tdocker build -f Dockerfile .\n",
        "portable": "all:\n\tg++ source.cpp -o sample1_unittest\ncheck: all\n\t./sample1_unittest\nwindows:\n" + windows,
    }[kind]
    unit = discover_build_units([_file("native/Makefile", text)])[0]
    unit["descriptor_package"] = {"documents": [{"path": "native/Makefile", "content": text}]}
    recipe = {**_recipe(unit), "configure_commands": [], "build_commands": [["make"]]}
    errors = validate_build_recipe(recipe, unit)
    if kind == "portable":
        assert errors == []
        assert any("execution, tests" in error for error in validate_build_recipe(
            {**recipe, "build_commands": [["make", "check"]]}, unit))
    else:
        assert any(("unavailable_native_windows_toolchain" if kind == "windows"
                    else "unsupported_native_orchestration") in error for error in errors)


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


@pytest.mark.parametrize("script", ("build", "minify"))
@pytest.mark.parametrize("commands", (
    [], [["npm", "ci", "--ignore-scripts"]],
    [["npm", "run", "build", "--if-present"]],
    [["npm", "--if-present", "run", "build"]],
    [["npm", "run", "build", "--if-present=true"]],
))
def test_node_recipe_uses_declared_build_script_not_empty_restore_only_or_optional_commands(script, commands) -> None:
    unit = discover_build_units([_file("web/package.json")])[0]
    unit["descriptor_package"] = {"documents": [{
        "path": "web/package.json", "content": json.dumps({"scripts": {script: "fixture-build"}}),
    }]}
    recipe = {
        **_recipe(unit), "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
        "system_packages": [], "environment": {}, "configure_commands": [],
        "build_commands": commands, "expected_outputs": [],
    }
    normalized = normalize_build_recipe(recipe, unit)
    assert normalized["build_commands"] == [["npm", "run", script]]
    assert validate_build_recipe(normalized, unit) == []


@pytest.mark.parametrize("command", (
    ["npm", "run", "build", "--if-present"],
    ["npm", "--if-present", "run", "build"],
    ["npm", "run", "build", "--if-present=true"],
    ["pnpm", "run", "--if-present", "build"],
    ["yarn", "run", "--if-present", "build"],
))
@pytest.mark.parametrize("field", ("configure_commands", "build_commands"))
def test_node_optional_commands_are_rejected_without_build_authority(command, field) -> None:
    unit = discover_build_units([_file("web/package.json")])[0]
    unit["descriptor_package"] = {"documents": [{
        "path": "web/package.json",
        "content": '{"scripts":{"start":"server","test":"test-runner"}}',
    }]}
    recipe = {
        **_recipe(unit), "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
        "system_packages": [], "environment": {}, "configure_commands": [],
        "build_commands": [["npm", "run", "build"]], "expected_outputs": [],
        field: [command],
    }
    normalized = normalize_build_recipe(recipe, unit)
    assert normalized[field] == [command]
    assert any("optional" in error and "--if-present" in error
               for error in validate_build_recipe(normalized, unit))


@pytest.mark.parametrize("command", (
    ["npm", "run", "build"],
    ["npm", "--prefix", "web", "run", "build"],
    ["npm", "run", "build", "--", "--if-present"],
))
def test_node_mandatory_declared_build_commands_are_preserved(command) -> None:
    unit = discover_build_units([_file("web/package.json")])[0]
    unit["descriptor_package"] = {"documents": [{
        "path": "web/package.json", "content": '{"scripts":{"build":"fixture-build"}}',
    }]}
    recipe = {
        **_recipe(unit), "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
        "system_packages": [], "environment": {}, "configure_commands": [],
        "build_commands": [command], "expected_outputs": [],
    }
    assert normalize_build_recipe(recipe, unit)["build_commands"] == [command]
    assert validate_build_recipe(recipe, unit) == []
    optional = {**recipe, "build_commands": [["npm", "run", "build", "--if-present"]]}
    assert any("optional" in error for error in validate_build_recipe(optional, unit))


@pytest.mark.parametrize("extra_task", (None, "serve", "watch", "test", "commented", "string"))
def test_node_grunt_authority_is_retained_and_only_literal_build_tasks_are_executable(tmp_path, extra_task) -> None:
    tasks = ["clean:dist", "concat", "uglify"]
    if extra_task not in {None, "commented", "string"}:
        tasks.append(extra_task)
    grunt_text = "grunt.registerTask('buildApp', " + json.dumps(tasks) + ");"
    if extra_task == "commented":
        grunt_text = "/* " + grunt_text + " */"
    elif extra_task == "string":
        grunt_text = "var example = " + json.dumps(grunt_text) + ";"
    files = [
        _file("web/package.json", '{"devDependencies":{"grunt":"0.4.5"}}'),
        _file("web/Gruntfile.js", grunt_text),
        _file("web/gulpfile.js", "gulp.task('build', function () {});"),
    ]
    for item in files:
        path = tmp_path / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        content = {
            "package.json": '{"devDependencies":{"grunt":"0.4.5"}}',
            "Gruntfile.js": grunt_text,
            "gulpfile.js": "gulp.task('build', function () {});",
        }[path.name]
        path.write_text(content, encoding="utf-8")
    assert is_build_descriptor(PurePosixPath("web/Gruntfile.js"))
    assert is_build_descriptor(PurePosixPath("web/gulpfile.js"))
    unit = discover_build_units(files)[0]
    unit["descriptor_package"] = descriptor_package(tmp_path, unit, files)
    assert {Path(x["path"]).name for x in unit["descriptor_package"]["documents"]} == {
        "package.json", "Gruntfile.js", "gulpfile.js",
    }
    recipe = {
        **_recipe(unit), "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
        "system_packages": [], "environment": {}, "configure_commands": [],
        "build_commands": [], "expected_outputs": [],
    }
    normalized = normalize_build_recipe(recipe, unit)
    if extra_task is None:
        assert normalized["build_commands"] == [["npx", "--no-install", "grunt", "buildApp"]]
        assert "web/Gruntfile.js" in normalized["dependency_files"]
        assert validate_build_recipe(normalized, unit) == []
    else:
        assert normalized["build_commands"] == []
        unsafe = {**normalized, "build_commands": [["npx", "--no-install", "grunt", "buildApp"]]}
        assert any("literal build-only Grunt" in error for error in validate_build_recipe(unsafe, unit))


def test_node_recipe_does_not_invent_builds_from_start_test_or_grunt_dependency() -> None:
    unit = discover_build_units([_file("web/package.json")])[0]
    unit["descriptor_package"] = {"documents": [{
        "path": "web/package.json", "content": json.dumps({
            "scripts": {"start": "server", "test": "test-runner"}, "devDependencies": {"grunt": "0.4.5"},
        }),
    }]}
    recipe = {
        **_recipe(unit), "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
        "system_packages": [], "environment": {}, "configure_commands": [],
        "build_commands": [], "expected_outputs": [],
    }
    normalized = normalize_build_recipe(recipe, unit)
    assert normalized["build_commands"] == []
    assert "build_commands must contain at least one build command" in validate_build_recipe(normalized, unit)


@pytest.mark.parametrize("properties", (
    "<Platform>Win32</Platform>",
    "<Platform>x64</Platform><PlatformToolset>v142</PlatformToolset>",
))
def test_native_windows_authority_rejects_linux_placeholder_recipe(properties) -> None:
    unit = discover_build_units([_file("native/project.vcxproj")])[0]
    unit["descriptor_package"] = {"documents": [{
        "path": "native/project.vcxproj", "content": f"<Project><PropertyGroup>{properties}</PropertyGroup></Project>",
    }]}
    recipe = {**_recipe(unit), "configure_commands": [], "build_commands": [["make", "-k"]]}
    assert any("unavailable_native_windows_toolchain" in error for error in validate_build_recipe(recipe, unit))


def test_cross_platform_dotnet_msbuild_is_not_windows_native_authority() -> None:
    unit = discover_build_units([_file("native/project.csproj")])[0]
    unit["descriptor_package"] = {"documents": [{
        "path": "native/project.csproj", "content": "<Project><TargetFramework>net8.0</TargetFramework></Project>",
    }]}
    recipe = {
        **_recipe(unit), "image_profile": "dotnet", "configure_commands": [],
        "build_commands": [["dotnet", "build", "project.csproj"]],
    }
    assert validate_build_recipe(recipe, unit) == []


@pytest.mark.parametrize("extension", ("vcxproj", "vcproj", "csproj"))
@pytest.mark.parametrize("own_solution", (False, True))
def test_solution_native_members_require_own_accepted_authority(extension, own_solution) -> None:
    project_type = ("8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942" if extension != "csproj"
                    else "FAE04EC0-301F-11D3-BF4B-00C04F79EFBC")
    text = (f'Project("{{{project_type}}}") = "app", "app\\app.{extension}", '
            '"{00000000-0000-0000-0000-000000000001}"\nEndProject\n')
    unit = discover_build_units([_file("native/msvc10.sln", text)])[0]
    path = "native/msvc10.sln" if own_solution else "native/neighbor/msvc10.sln"
    unit["descriptor_package"] = {"documents": [{"path": path, "content": text}]}
    recipe = {
        **_recipe(unit), "image_profile": "dotnet", "configure_commands": [],
        "build_commands": [["dotnet", "build", "msvc10.sln"]],
    }
    errors = validate_build_recipe(recipe, unit)
    if own_solution and extension != "csproj":
        assert any("unavailable_native_project_toolchain" in error and
                   f"native/msvc10.sln@{unit['markers'][0]['sha256']}" in error and
                   "Visual C++" in error for error in errors)
        assert not any("unavailable_native_windows_toolchain" in error for error in errors)
    else:
        assert errors == []


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


def test_teamcity_kotlin_dsl_is_neither_a_java_build_unit_nor_an_orphan() -> None:
    inventory = discover_build_inventory([
        _file(".teamcity/settings.kts"),
        _file("projects/java/sample/src/Main.java"),
    ])
    assert inventory["units"] == []
    # CI configuration is cataloged by the CI lanes; the loose Java source is the orphan.
    assert [item["path"] for item in inventory["orphaned_sources"]] == ["projects/java/sample/src/Main.java"]


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


def test_dotnet_recipe_with_package_reference_requires_dependency_egress() -> None:
    unit = discover_build_units([_file("dotnet/App.csproj")])[0]
    unit["descriptor_package"] = {"documents": [{
        "path": "dotnet/App.csproj",
        "content": "<Project><ItemGroup><PackageReference Include=\"Example\" /></ItemGroup></Project>",
    }]}
    recipe = {
        "schema": BUILD_RECIPE_SCHEMA, "build_unit_id": unit["build_unit_id"],
        "image_profile": "dotnet", "source_dir": "dotnet", "build_dir": "dotnet/obj",
        "system_packages": [], "environment": {}, "dependency_files": ["dotnet/App.csproj"],
        "configure_commands": [["dotnet", "restore", "App.csproj"]],
        "build_commands": [["dotnet", "build", "App.csproj"]],
        "expected_outputs": ["dotnet/bin"], "network_required": False,
        "reason": "invalid offline proposal",
    }
    assert ".NET recipes with accepted package references require dependency egress" in validate_build_recipe(
        recipe, unit)
    recipe["network_required"] = True
    assert validate_build_recipe(recipe, unit) == []


def test_android_gradle_application_is_one_descriptor_backed_build_unit(tmp_path: Path) -> None:
    target = tmp_path / "target"
    documents = {
        "build.gradle.kts": 'plugins { id("com.android.application") version "8.7.3" apply false }\n',
        "settings.gradle.kts": 'rootProject.name = "fixture"\ninclude(":app")\n',
        "app/build.gradle.kts": """plugins { id(\"com.android.application\") }
android {
    compileSdk = 35
    buildToolsVersion = \"35.0.0\"
    defaultConfig { targetSdk = 35 }
}
""",
        "gradle.properties": "org.gradle.daemon=false\n",
    }
    files = []
    for relative, content in documents.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        files.append(_file(relative, content))

    # The settings file's include(":app") is the literal evidence that folds the module into the root
    # (plan §2.1 decision 1); discovery reads it through read_text.
    units = discover_build_units(files, read_text=documents.get)
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        (".", "java", "gradle")]
    unit = units[0]
    assert [(p["name"], p["kind"], p["descriptor"]) for p in unit["build_points"]] == [("app", "project", "app/build.gradle.kts")]
    package = descriptor_package(target, unit, files)
    facts = android_descriptor_facts(package)
    application = next(document for document in package["documents"]
                       if document["path"] == "app/build.gradle.kts")
    # Facts stay in their physical declaring document: the root `apply false` version is not
    # attributed to the module that applies the plugin without one.
    assert facts == {
        "kind": "android-gradle-application", "plugin_id": "com.android.application",
        "plugin_version": None, "compile_sdk": "35", "target_sdk": "35",
        "build_tools": "35.0.0",
        "declarations": [{
            "path": "app/build.gradle.kts", "sha256": application["sha256"],
            "plugin_id": "com.android.application", "plugin_version": None,
            "compile_sdk": "35", "target_sdk": "35", "build_tools": "35.0.0",
        }],
    }
    unit["descriptor_package"] = package
    unit["descriptor_facts"] = facts
    assert required_image_profile(unit) == "android"
    assert build_recipe_inference_policy(unit) == {
        "required_image_profile": "android",
        "allowed_executables": ["gradle", "gradlew"],
        "gradle": {
            "allowed_executables": ["gradle", "gradlew"],
            "allowed_task_suffixes": ["assemble", "assembleDebug"],
            "module_qualification": "an allowed task may be qualified by a module from settings.gradle",
            "forbidden_task_classes": ["test", "connected-test", "install", "run"],
        },
    }
    recipe = {
        "schema": BUILD_RECIPE_SCHEMA, "build_unit_id": unit["build_unit_id"],
        "image_profile": "android", "source_dir": ".", "build_dir": "app/build",
        "system_packages": [], "environment": {},
        "dependency_files": sorted(item["path"] for item in package["documents"]),
        "configure_commands": [],
        "build_commands": [["gradle", "--no-daemon", ":app:assembleDebug"]],
        "expected_outputs": ["app/build/outputs/apk/debug/app-debug.apk"],
        "network_required": True, "reason": "descriptor-backed Android application",
    }
    assert validate_build_recipe(recipe, unit) == []
    assert "recipe image_profile must equal required profile android" in validate_build_recipe(
        {**recipe, "image_profile": "java"}, unit)

    unit["descriptor_facts"] = {}
    assert "recipe image_profile must equal required profile java" in validate_build_recipe(
        recipe, unit)


def test_planning_registers_every_build_system_discovery_emits() -> None:
    # A unit discovery assigns (phpize for config.m4, clang for a wasm32 build.sh) must never be
    # rejected by the plan validator as an unregistered build system.
    from appsec_review.jobs.build_discovery import DISCOVERED_BUILD_SYSTEMS
    from appsec_review.jobs.job_target_analysis_plan.planning import BUILD_SYSTEMS

    assert {"phpize", "clang"} <= DISCOVERED_BUILD_SYSTEMS <= BUILD_SYSTEMS


def _tree(root: Path, values: dict[str, str]) -> list[dict[str, object]]:
    files = []
    for relative, content in values.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        files.append(_file(relative, content))
    return files


def test_node_workspace_root_inventory_names_every_member_and_root_lockfile(tmp_path: Path) -> None:
    files = _tree(tmp_path, {
        "package.json": '{"private":true,"workspaces":["packages/*","!packages/skip"]}\n',
        "package-lock.json": '{"lockfileVersion":3}\n',
        "packages/a/package.json": "{}\n", "packages/b/package.json": "{}\n",
        "packages/skip/package.json": "{}\n", "tools/other/package.json": "{}\n",
    })
    workspace, gaps = node_workspace(tmp_path, {"family": "node", "root": "."}, files)
    assert gaps == []
    assert workspace == {
        "root": ".", "role": "root", "manager": "npm", "declaration": "package.json",
        "lockfile": "package-lock.json", "members": ["packages/a", "packages/b"],
        "inventory": ["package-lock.json", "package.json", "packages/a/package.json",
                      "packages/b/package.json"],
    }
    member, member_gaps = node_workspace(tmp_path, {"family": "node", "root": "packages/b"}, files)
    assert member_gaps == [] and member["role"] == "member" and member["lockfile"] == "package-lock.json"
    # A nested project the workspace does not claim, and a non-Node unit, install on their own.
    assert node_workspace(tmp_path, {"family": "node", "root": "packages/skip"}, files) == (None, [])
    assert node_workspace(tmp_path, {"family": "native", "root": "."}, files) == (None, [])


def test_node_workspace_names_missing_member_and_missing_or_ambiguous_lockfiles(tmp_path: Path) -> None:
    declaration = '{"workspaces":["apps/web","apps/missing"]}\n'
    files = _tree(tmp_path, {"package.json": declaration, "apps/web/package.json": "{}\n"})
    workspace, gaps = node_workspace(tmp_path, {"family": "node", "root": "apps/web"}, files)
    assert workspace["role"] == "member" and workspace["lockfile"] is None
    assert gaps == [
        "apps/missing: declared workspace member has no accepted package.json",
        ".: workspace dependency inventory unavailable: no package-lock.json, pnpm-lock.yaml, "
        "or yarn.lock at the workspace root",
    ]
    ambiguous = files + _tree(tmp_path, {"package-lock.json": "{}\n", "yarn.lock": "# yarn\n"})
    workspace, gaps = node_workspace(tmp_path, {"family": "node", "root": "apps/web"}, ambiguous)
    assert workspace["lockfile"] is None
    assert gaps[-1] == ".: workspace dependency inventory is ambiguous: package-lock.json, yarn.lock"
    unreadable = _tree(tmp_path / "bad", {"package.json": '{"workspaces":{"packages":"apps/*"}}\n'})
    assert node_workspace(tmp_path / "bad", {"family": "node", "root": "."}, unreadable) == (None, [
        "package.json: workspace declaration could not be read; "
        "the workspace dependency inventory is unavailable"])


def test_pnpm_workspace_prefers_its_own_lockfile_and_honors_exclusions(tmp_path: Path) -> None:
    files = _tree(tmp_path, {
        "pnpm-workspace.yaml": "packages:\n  - 'libs/*'\n  - '!libs/skip'\n",
        "package.json": "{}\n", "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
        "package-lock.json": "{}\n",
        "libs/a/package.json": "{}\n", "libs/skip/package.json": "{}\n",
    })
    workspace, gaps = node_workspace(tmp_path, {"family": "node", "root": "."}, files)
    assert gaps == []
    assert (workspace["manager"], workspace["declaration"], workspace["lockfile"], workspace["members"]) == (
        "pnpm", "pnpm-workspace.yaml", "pnpm-lock.yaml", ["libs/a"])


def test_descriptor_inventory_paths_merge_documents_and_identity_inventory() -> None:
    unit = {"descriptor_package": {
        "documents": [{"path": "web/package.json"}, {"path": "web/tsconfig.json"}],
        "inventory": [{"path": "package-lock.json"}, {"path": "web/package.json"}, "malformed", {}],
    }}
    assert descriptor_inventory_paths(unit) == ["package-lock.json", "web/package.json", "web/tsconfig.json"]
    assert descriptor_inventory_paths({}) == []
    assert descriptor_inventory_paths({"descriptor_package": ["web/package.json"]}) == []


@pytest.mark.parametrize("content,expected", [
    ('{"dependencies":{"left-pad":"1.3.0"}}', True),
    ('{"devDependencies":{"typescript":"5.4.0"}}', True),
    ('{"optionalDependencies":{"fsevents":"2.3.3"}}', True),
    ('{"dependencies":{},"peerDependencies":{"react":"18"}}', False),
    ('{"dependencies":["left-pad"]}', False),
    ("not json", False),
])
def test_node_manifest_dependencies_come_only_from_the_units_own_manifest(content, expected) -> None:
    unit = {"root": "web", "descriptor_package": {"documents": [
        {"path": "web/package.json", "content": content},
        {"path": "package.json", "content": '{"dependencies":{"root-only":"1.0.0"}}'},
    ]}}
    assert node_manifest_declares_dependencies(unit) is expected
    assert node_manifest_declares_dependencies({"root": "web", "descriptor_package": {"documents": [
        {"path": "package.json", "content": '{"dependencies":{"root-only":"1.0.0"}}'}]}}) is False


def test_make_default_goal_closure_honors_declared_default_and_excludes_other_targets() -> None:
    text = ("all:\n\techo not-the-default\n"
            "build: lib app\n\tcc -o app app.o lib.a\n"
            "lib:\n\tar rcs lib.a lib.o\n"
            "app: ; cc -c app.c\n"
            "clean:\n\trm -f app\n"
            ".DEFAULT_GOAL := build\n")
    unit = discover_build_units([_file("native/Makefile", text)])[0]
    assert make_default_build_commands(unit) is None
    unit["descriptor_package"] = {"documents": [{"path": "native/Makefile", "content": text}]}
    marker, body = make_default_build_commands(unit)
    assert marker["path"] == "native/Makefile"
    assert [line.strip() for line in body.splitlines()] == [
        "cc -o app app.o lib.a", "cc -c app.c", "ar rcs lib.a lib.o"]
    assert native_build_capability_gap(unit) is None


_VC_SOLUTION = ('Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "Native", '
                '"Native\\Native.vcxproj", "{11111111-1111-1111-1111-111111111111}"\n')
_CS_SOLUTION = ('Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "App", '
                '"App\\App.csproj", "{22222222-2222-2222-2222-222222222222}"\n')
_VCXPROJ = ("<Project><ItemGroup><ProjectConfiguration><Platform>Win32</Platform>"
            "</ProjectConfiguration></ItemGroup><PropertyGroup><PlatformToolset>v143</PlatformToolset>"
            "</PropertyGroup></Project>")


@pytest.mark.parametrize("unit,expected", [
    ({"family": "dotnet", "root": "win", "markers": [{"path": "win/App.sln", "sha256": "s"}],
      "descriptor_package": {"documents": [{"path": "win/App.sln", "content": _VC_SOLUTION}]}},
     "unavailable_native_project_toolchain: win/App.sln@s: accepted solution declares Visual C++"),
    ({"family": "dotnet", "root": "win", "markers": [{"path": "win/App.sln", "sha256": "s"}],
      "descriptor_package": {"documents": [{"path": "win/App.sln", "content": _CS_SOLUTION}]}}, None),
    ({"family": "native", "build_system": "autotools", "root": "native",
      "markers": [{"path": "native/include/Makefile.am"}]}, "nonstandalone_autotools_fragment: "),
    ({"family": "native", "build_system": "autotools", "root": "native",
      "markers": [{"path": "native/configure.ac"}, {"path": "native/Makefile.am"}]}, None),
    ({"family": "native", "build_system": "make", "root": "native",
      "markers": [{"path": "native/Makefile", "sha256": "m"}],
      "descriptor_package": {"documents": [{"path": "native/Makefile",
                                            "content": "image:\n\tdocker build -t x .\n"}]}},
     "unsupported_native_orchestration: native/Makefile@m: "),
    ({"family": "native", "build_system": "msbuild", "root": "modern",
      "markers": [{"path": "modern/App.vcxproj", "sha256": "v"}],
      "descriptor_package": {"documents": [{"path": "modern/App.vcxproj", "content": _VCXPROJ}]}},
     "unavailable_native_windows_toolchain: modern/App.vcxproj@v: MSVC toolset v143, Win32 platform"),
    ({"family": "native", "build_system": "msbuild", "root": "modern",
      "markers": [{"path": "modern/App.vcxproj", "sha256": "v"}],
      "descriptor_package": {"documents": [{"path": "modern/App.vcxproj", "content": "<Project>"}]}},
     "unavailable_native_project_toolchain: modern/App.vcxproj: descriptor XML cannot be resolved"),
    ({"family": "native", "build_system": "msbuild", "root": "modern",
      "markers": [{"path": "modern/App.vcxproj", "sha256": "v"}], "descriptor_package": {"documents": []}},
     "unavailable_native_project_toolchain: accepted Visual C++ descriptor requires"),
    ({"family": "native", "build_system": "cmake", "root": "native",
      "markers": [{"path": "native/CMakeLists.txt"}]}, None),
    ({"family": "go", "root": "svc", "markers": [{"path": "svc/go.mod"}]}, None),
])
def test_native_build_capability_gap_names_each_unavailable_native_authority(unit, expected) -> None:
    gap = native_build_capability_gap(unit)
    if expected is None:
        assert gap is None
    else:
        assert gap is not None and gap.startswith(expected)

# ---------------------------------------------------------------- job pass 05: monorepo shapes

def _reader(texts: dict[str, str]):
    return lambda path: texts.get(path)


def test_a_settings_only_gradle_root_folds_the_projects_it_includes() -> None:
    settings = "include ':app', ':lib'\n"
    files = [_file("client-android/settings.gradle", settings),
             _file("client-android/app/build.gradle", "plugins { id 'com.android.application' }\n"),
             _file("client-android/lib/build.gradle", "plugins { id 'com.android.library' }\n"),
             _file("client-android/app/src/main/java/A.kt"), _file("client-android/lib/src/main/java/B.kt")]
    inventory = discover_build_inventory(files, read_text=_reader({"client-android/settings.gradle": settings}))
    units = {unit["root"]: unit for unit in inventory["units"]}
    # One unit: the settings root. The included projects are its build points (plan §2.1 decision 1).
    assert set(units) == {"client-android"}
    root = units["client-android"]
    assert (root["family"], root["build_system"]) == ("java", "gradle")
    assert [m["path"] for m in root["markers"]] == ["client-android/settings.gradle"]
    assert [(p["name"], p["kind"], p["evidence"], p["descriptor"]) for p in root["build_points"]] == [
        ("app", "project", "client-android/settings.gradle:1", "client-android/app/build.gradle"),
        ("lib", "project", "client-android/settings.gradle:1", "client-android/lib/build.gradle")]
    assert [(d["path"], d["via"]) for d in root["drives"]] == [("client-android/app", "settings_include"),
                                                               ("client-android/lib", "settings_include")]
    assert [(f["root"], f["folded_into"]) for f in inventory["folded_roots"]] == [
        ("client-android/app", "client-android|gradle"), ("client-android/lib", "client-android|gradle")]
    assert "workspace" not in root
    assignment = assign_paths(files, inventory)
    assert assignment["client-android/app/build.gradle"] == "evidence_of:client-android|gradle#app"
    assert assignment["client-android/app/src/main/java/A.kt"] == "evidence_of:client-android|gradle#app"
    assert assignment["client-android/lib/src/main/java/B.kt"] == "evidence_of:client-android|gradle#lib"
    assert inventory["orphaned_sources"] == []


def test_a_gradle_module_nothing_includes_stays_a_unit_of_its_own() -> None:
    files = [_file("app/settings.gradle", "include ':core'\n"), _file("app/build.gradle"),
             _file("app/core/build.gradle"), _file("app/extra/build.gradle")]
    units = discover_build_units(files, read_text=_reader({"app/settings.gradle": "include ':core'\n"}))
    # core is included (folded); extra is not named by any include and so is a root of its own.
    assert [unit["root"] for unit in units] == ["app", "app/extra"]
    assert "workspace" not in units[0]


def test_an_xcode_project_is_a_swift_unit_rooted_at_the_bundles_parent_under_the_swift_policy() -> None:
    files = [_file("client-ios/App.xcodeproj/project.pbxproj", "// !$*UTF8*$!\n"),
             _file("client-ios/App/AppMain.swift"), _file("stray/project.pbxproj")]
    units = discover_build_units(files)
    [unit] = [unit for unit in units if unit["build_system"] == "xcodebuild"]
    assert unit["root"] == "client-ios" and unit["family"] == "swift" and unit["language"] == "swift"
    assert unit["descriptor_facts"] == {"kind": "xcode-project", "platform": "apple", "bundles": ["App.xcodeproj"]}
    assert required_image_profile(unit) == "swift"
    # A project.pbxproj outside an .xcodeproj bundle is not a marker.
    assert not any(unit["root"] == "stray" for unit in units)
    from appsec_review.swift_policy import contains_swift_derived
    assert contains_swift_derived(unit)


def test_a_source_a_sibling_descriptor_names_is_evidence_of_that_units_rule_not_a_new_root() -> None:
    makefile = "packer: main.c ../../common/src/util.c\n\t$(CC) -I../../common/include main.c ../../common/src/util.c -o packer\n"
    files = [_file("tools/packer/Makefile", makefile), _file("tools/packer/main.c"),
             _file("common/src/util.c"), _file("common/include/util.h"),
             _file("lonely/src/alone.c")]
    inventory = discover_build_inventory(files, read_text=_reader({"tools/packer/Makefile": makefile}))
    units = {unit["root"]: unit for unit in inventory["units"]}
    assert "common" not in units, "no manufactured root for a referenced sibling source"
    [packer] = units["tools/packer"]["build_points"]
    assert packer["sources"] == ["common/src/util.c", "tools/packer/main.c"] and packer["headers"] == ["common/include/util.h"]
    assert "native_components" not in units["tools/packer"], "retired: the rule's sources are the evidence (T-056.2)"
    assert assign_paths(files, inventory)["common/src/util.c"] == "evidence_of:tools/packer|make#packer"
    # A source nothing references is orphaned, with the nearest unit it was not claimed by.
    [orphan] = inventory["orphaned_sources"]
    assert orphan["path"] == "lonely/src/alone.c" and orphan["nearest_unit"] is None
    # Without descriptor text there is no evidence of the reference, so util.c is orphaned too —
    # reported against the packer unit, never attached to it on proximity.
    blind = discover_build_inventory(files)
    assert "common" not in {unit["root"] for unit in blind["units"]}
    assert [o["path"] for o in blind["orphaned_sources"]] == ["common/src/util.c", "lonely/src/alone.c"]


def test_a_wildcard_reference_in_a_vendored_test_makefile_binds_the_sources_it_globs() -> None:
    makefile = "SRCS := $(wildcard ../src/*.c)\ncheck: check.c $(SRCS)\n\t$(CC) -I../include check.c $(SRCS) -o check\n"
    cmake = "project(lib C)\nadd_library(lib STATIC src/lib.c)\n"
    files = [_file("lib/CMakeLists.txt", cmake), _file("lib/src/lib.c"), _file("lib/include/lib.h"),
             _file("lib/test/Makefile", makefile), _file("lib/test/check.c")]
    units = {unit["root"]: unit for unit in discover_build_units(
        files, read_text=_reader({"lib/test/Makefile": makefile, "lib/CMakeLists.txt": cmake}))}
    # lib/src/lib.c is under the CMake root, so it stays with that unit (matching root wins first).
    assert set(units) == {"lib", "lib/test"}
    assert "native_components" not in units["lib/test"]
    [check] = units["lib/test"]["build_points"]
    assert check["sources"] == ["lib/src/lib.c", "lib/test/check.c"], "the wildcard binds the sibling sources to the rule"
    assert check["headers"] == ["lib/include/lib.h"]


def test_cargo_and_go_workspace_members_are_build_points_of_the_workspace_root() -> None:
    cargo = '[workspace]\nmembers = ["core", "cli", "tools/*"]\nexclude = ["tools/skip"]\n'
    core = '[package]\nname = "core"\nversion = "0.1.0"\n'
    cli = '[package]\nname = "cli"\nversion = "0.1.0"\n'
    work = "go 1.24\n\nuse (\n\t./shared\n\t./svc // service\n)\n"
    texts = {"rust/Cargo.toml": cargo, "rust/core/Cargo.toml": core, "rust/cli/Cargo.toml": cli,
             "rust/tools/gen/Cargo.toml": '[package]\nname = "gen"\n', "rust/tools/skip/Cargo.toml": '[package]\nname = "skip"\n',
             "rust/other/Cargo.toml": '[package]\nname = "other"\n',
             "go/go.work": work, "go/shared/go.mod": "module example.com/shared\n", "go/svc/go.mod": "module example.com/svc\n",
             "go/extra/go.mod": "module example.com/extra\n", "go/svc/main.go": "package main\n"}
    files = [_file(path, text) for path, text in texts.items()] + [_file("rust/core/src/lib.rs"), _file("rust/cli/src/main.rs")]
    inventory = discover_build_inventory(files, read_text=_reader(texts))
    units = {unit["root"]: unit for unit in inventory["units"]}
    # Members are folded into the root (plan §2.1 decision 1); an excluded or unlisted crate stays a unit.
    assert set(units) == {"rust", "rust/tools/skip", "rust/other", "go", "go/extra"}
    rust = units["rust"]
    assert [(d["path"], d["via"], d["evidence"]) for d in rust["drives"]] == [
        ("rust/core", "workspace_member", "rust/Cargo.toml:1"), ("rust/cli", "workspace_member", "rust/Cargo.toml:1"),
        ("rust/tools/gen", "workspace_member", "rust/Cargo.toml:1")]
    assert [(p["name"], p["kind"]) for p in rust["build_points"]] == [
        ("cli", "package"), ("cli", "bin"), ("core", "package"), ("core", "lib"), ("gen", "package")]
    assert "workspace" not in rust and all("workspace" not in unit for unit in units.values())
    go = units["go"]
    assert [(d["path"], d["via"]) for d in go["drives"]] == [("go/shared", "go_work_use"), ("go/svc", "go_work_use")]
    assert [(p["name"], p["kind"], p["evidence"]) for p in go["build_points"]] == [
        ("example.com/shared", "module", "go/shared/go.mod:1"), ("example.com/svc", "module", "go/svc/go.mod:1"),
        ("svc", "main_package", "go/svc/main.go:1")]
    assignment = assign_paths(files, inventory)
    assert assignment["rust/core/Cargo.toml"] == "evidence_of:rust|cargo#core"
    assert assignment["rust/core/src/lib.rs"] == "evidence_of:rust|cargo#core"
    assert assignment["go/svc/go.mod"] == "evidence_of:go|go#example.com/svc"
    assert assignment["go/svc/main.go"] == "evidence_of:go|go#svc"


def test_installed_build_logic_and_fixture_trees_are_never_units_and_take_their_owners_role() -> None:
    """Plan §2.1 decision 4: node_modules, a Cargo/Go/Composer vendor/, CocoaPods Pods/ are installed
    dependencies (context of the unit that installs them); buildSrc is Gradle build logic (context of the
    root); Go testdata is fixture data (inert). A vendor/ under a Make root is none of these."""
    texts = {"app/Cargo.toml": '[package]\nname = "app"\n', "svc/go.mod": "module example.com/svc\n",
             "web/package.json": '{"name": "web", "scripts": {"build": "tsc"}}\n',
             "tools/Makefile": "all: vendor/lib/lib.c\n\t$(CC) vendor/lib/lib.c -o tool\n",
             "ios/App.xcodeproj/project.pbxproj": "// !$*UTF8*$!\n", "ios/Podfile": "pod 'X'\n",
             "jvm/settings.gradle": "include ':core'\n", "jvm/core/build.gradle": "", "jvm/buildSrc/build.gradle": ""}
    files = [_file(path, text) for path, text in texts.items()] + [
        _file("app/vendor/tiny/Cargo.toml", '[package]\nname = "tiny"\n'), _file("app/vendor/tiny/.cargo-checksum.json"),
        _file("app/vendor/tiny/src/lib.rs"), _file("svc/vendor/modules.txt"), _file("svc/vendor/dep/dep.go"),
        _file("svc/testdata/mod/go.mod", "module fixture\n"), _file("svc/testdata/mod/x.go"), _file("svc/main.go", "package main\n"),
        _file("web/node_modules/left-pad/package.json", '{"name": "left-pad"}'), _file("web/node_modules/left-pad/index.js"),
        _file("tools/vendor/lib/lib.c"), _file("ios/Pods/Pods.xcodeproj/project.pbxproj"), _file("ios/Pods/dummy.m"),
        _file("jvm/buildSrc/src/main/kotlin/Conventions.kt")]
    inventory = discover_build_inventory(files, read_text=lambda path: texts.get(path, ""))
    assert sorted((u["root"], u["build_system"]) for u in inventory["units"]) == [
        ("app", "cargo"), ("ios", "xcodebuild"), ("jvm", "gradle"), ("svc", "go"), ("tools", "make"), ("web", "node")]
    assert [(t["path"], t["kind"], t["manager"], t["role"], t.get("unit")) for t in inventory["installed_trees"]] == [
        ("app/vendor", "installed", "cargo", "context", "app|cargo"),
        ("ios/Pods", "installed", "cocoapods", "context", "ios|xcodebuild"),
        ("jvm/buildSrc", "build_logic", "gradle", "context", "jvm|gradle"),
        ("svc/testdata", "fixture", "go", "inert", None),
        ("svc/vendor", "installed", "go", "context", "svc|go"),
        ("web/node_modules", "installed", "node", "context", "web|node")]
    assert inventory["orphaned_sources"] == [], "nothing under an installed or fixture tree is an orphan"
    assignment = assign_paths(files, inventory)
    assert assignment["app/vendor/tiny/src/lib.rs"] == "context:app|cargo"
    assert assignment["svc/vendor/dep/dep.go"] == "context:svc|go"
    assert assignment["svc/testdata/mod/go.mod"] == "inert" and assignment["svc/testdata/mod/x.go"] == "inert"
    assert assignment["web/node_modules/left-pad/index.js"] == "context:web|node"
    assert assignment["ios/Pods/dummy.m"] == "context:ios|xcodebuild"
    assert assignment["jvm/buildSrc/src/main/kotlin/Conventions.kt"] == "context:jvm|gradle"
    # A Make rule that compiles a vendored library's source: vendor/ here is source the rule names.
    assert assignment["tools/vendor/lib/lib.c"] == "evidence_of:tools|make#all"
