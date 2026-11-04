from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

import pytest

from appsec_review.jobs.build_discovery import (
    BUILD_RECIPE_SCHEMA, android_descriptor_facts, build_recipe_inference_policy,
    descriptor_package, discover_build_units, is_build_descriptor, normalize_build_recipe, required_image_profile,
    unsupported_build_gaps, validate_build_recipe,
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
    unit = discover_build_units([_file("native/include/Makefile.am")])[0]
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

    units = discover_build_units(files)
    assert [(item["root"], item["family"], item["build_system"]) for item in units] == [
        (".", "java", "gradle")]
    unit = units[0]
    package = descriptor_package(target, unit, files)
    facts = android_descriptor_facts(package)
    assert facts == {
        "kind": "android-gradle-application", "plugin_id": "com.android.application",
        "plugin_version": "8.7.3", "compile_sdk": "35", "target_sdk": "35",
        "build_tools": "35.0.0",
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
