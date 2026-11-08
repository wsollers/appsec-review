"""Build points: the atom of discovery (T-056.2).

A unit is a root that drives named build points — CMake targets, Make rules, `.sln` projects,
Cargo packages, Gradle modules, Go main packages, npm scripts. Each point names the sources it
compiles with `path:line` evidence; a compiled source no point names is orphaned, a descriptor
with no point is demoted. These tests drive the extractors through `discover_build_inventory`
and the total assignment, never the private tables.
"""
from __future__ import annotations

import hashlib

import pytest

from appsec_review.jobs.build_discovery import discover_build_inventory
from appsec_review.jobs.build_points import EXTRACTORS, cmake_build_points, make_build_points
from appsec_review.jobs.discovery_assignment import assign_paths


def _file(path: str, content: str = "x") -> dict[str, object]:
    value = content.encode()
    return {"path": path, "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}


def _inventory(texts: dict[str, str], *extra: str) -> tuple[list[dict[str, object]], dict]:
    files = [_file(path, text) for path, text in texts.items()] + [_file(path) for path in extra]
    return files, discover_build_inventory(files, read_text=lambda path: texts.get(str(path)))


def _unit(inventory: dict, root: str, system: str) -> dict:
    return next(u for u in inventory["units"] if u["root"] == root and u["build_system"] == system)


def _points(unit: dict) -> dict[str, dict]:
    return {p["name"]: p for p in unit.get("build_points", ())}


# --- CMake -------------------------------------------------------------------------------------

def test_cmake_targets_are_build_points_with_kind_sources_headers_and_line_evidence() -> None:
    cmake = ("cmake_minimum_required(VERSION 3.20)\nproject(demo C CXX)\n"
             "set(CORE_SRCS src/core.c src/util.c)\n"
             "add_library(core STATIC ${CORE_SRCS})\n"
             "target_include_directories(core PUBLIC include)\n"
             "add_executable(demo src/main.c)\n"
             "target_sources(demo PRIVATE src/args.c)\n"
             "add_library(iface INTERFACE)\n"
             "add_custom_target(docs COMMAND doxygen)\n")
    files, inventory = _inventory({"CMakeLists.txt": cmake}, "src/core.c", "src/util.c", "src/main.c", "src/args.c",
                                  "include/core.h", "README.md")
    unit = _unit(inventory, ".", "cmake")
    points = _points(unit)
    assert {name: p["kind"] for name, p in points.items()} == {
        "core": "static_library", "demo": "executable", "iface": "interface_library", "docs": "custom_target"}
    assert points["core"]["sources"] == ["src/core.c", "src/util.c"], "set() variables expand into sources"
    assert points["core"]["headers"] == ["include/core.h"], "include directories bind their headers"
    assert points["core"]["evidence"] == "CMakeLists.txt:4"
    assert points["demo"]["sources"] == ["src/args.c", "src/main.c"], "target_sources adds to the target (sorted)"
    assert unit["source_resolution"] == "complete"
    assert inventory["orphaned_sources"] == []
    assignment = assign_paths(files, inventory)
    assert assignment["src/core.c"] == "evidence_of:.|cmake#core"
    assert assignment["src/args.c"] == "evidence_of:.|cmake#demo"
    assert assignment["include/core.h"] == "evidence_of:.|cmake#core"
    assert assignment["README.md"] == "inert"


def test_cmake_glob_and_conditions_and_subdirectories_are_recorded() -> None:
    cmake = ("project(app C)\nfile(GLOB APP_SRCS src/*.c)\n"
             "if(WIN32)\n  add_executable(app WIN32 ${APP_SRCS} win/entry.c)\nelse()\n  add_executable(app ${APP_SRCS})\nendif()\n"
             "add_subdirectory(vendor/lib)\ninclude(cmake/flags.cmake)\n")
    lib = "project(lib C)\nadd_library(lib STATIC lib.c)\n"
    files, inventory = _inventory({"CMakeLists.txt": cmake, "vendor/lib/CMakeLists.txt": lib},
                                  "src/a.c", "src/b.c", "win/entry.c", "vendor/lib/lib.c", "cmake/flags.cmake",
                                  "cmake/unused.cmake")
    app = _unit(inventory, ".", "cmake")
    [point] = [p for p in app["build_points"] if p["name"] == "app" and "win/entry.c" in p["sources"]]
    assert set(point["sources"]) == {"src/a.c", "src/b.c", "win/entry.c"}, "file(GLOB) expands against the tree"
    assert point["condition"] == "WIN32"
    assert [(d["path"], d["via"], d["evidence"]) for d in app["drives"]] == [("vendor/lib", "add_subdirectory", "CMakeLists.txt:8")]
    assert app["includes"] == ["cmake/flags.cmake"]
    assignment = assign_paths(files, inventory)
    assert assignment["cmake/flags.cmake"] == "context:.|cmake"
    assert assignment["cmake/unused.cmake"] == "inert", "a module nothing includes is inert"
    assert assignment["vendor/lib/lib.c"] == "evidence_of:vendor/lib|cmake#lib"


def test_cmake_generator_expressions_leave_the_point_unresolved_not_orphaning_its_sources() -> None:
    cmake = "project(x C)\nadd_executable(x $<$<PLATFORM_ID:Linux>:src/linux.c> src/main.c)\n"
    files, inventory = _inventory({"CMakeLists.txt": cmake}, "src/main.c", "src/linux.c")
    unit = _unit(inventory, ".", "cmake")
    assert unit["unresolved"], "a generator expression is recorded, not silently dropped"
    assert unit["source_resolution"] == "containment"
    assert inventory["orphaned_sources"] == [], "containment resolution does not orphan sibling sources"


def test_a_cmakelists_with_no_target_is_demoted_and_its_sources_orphaned() -> None:
    cmake = "cmake_minimum_required(VERSION 3.20)\nproject(nothing C)\ninclude(CTest)\n"
    files, inventory = _inventory({"CMakeLists.txt": cmake}, "src/lonely.c")
    assert inventory["units"] == []
    assert [d["markers"] for d in inventory["demoted_markers"]] == [["CMakeLists.txt"]]
    [orphan] = inventory["orphaned_sources"]
    assert (orphan["path"], orphan["reason"], orphan["nearest_unit"]) == ("src/lonely.c", "no_build_point", None)
    assignment = assign_paths(files, inventory)
    assert assignment == {"CMakeLists.txt": "inert", "src/lonely.c": "orphaned:no_build_point"}


def test_cmake_extractor_reports_each_target_once_per_definition_line() -> None:
    points = cmake_build_points(".", {"CMakeLists.txt": "add_library(a a.c)\nadd_library(a_shared SHARED a.c)\nadd_executable(t t.c)\n"},
                                ["a.c", "t.c"])["build_points"]
    assert [(p["name"], p["kind"], p["evidence"]) for p in points] == [
        ("a", "library", "CMakeLists.txt:1"), ("a_shared", "shared_library", "CMakeLists.txt:2"),
        ("t", "executable", "CMakeLists.txt:3")]


# --- Make --------------------------------------------------------------------------------------

def test_make_rules_are_build_points_and_a_recursive_make_drives_the_subdirectory() -> None:
    makefile = ("CC ?= cc\nSRCS = main.c util.c\nOBJS = $(SRCS:.c=.o)\n"
                "all: tool\n\n"
                "tool: $(OBJS)\n\t$(CC) -Iinclude $(OBJS) -o tool\n\n"
                "%.o: %.c\n\t$(CC) -Iinclude -c $< -o $@\n\n"
                "vendor:\n\t$(MAKE) -C vendor/lib\n\n"
                ".PHONY: all clean vendor\nclean:\n\trm -f *.o tool\n")
    lib = "lib.a: lib.c\n\t$(CC) -c lib.c -o lib.o && ar rcs lib.a lib.o\n"
    files, inventory = _inventory({"Makefile": makefile, "vendor/lib/Makefile": lib},
                                  "main.c", "util.c", "include/util.h", "vendor/lib/lib.c", "docs/notes.md")
    unit = _unit(inventory, ".", "make")
    points = _points(unit)
    assert points["tool"]["kind"] == "rule"
    assert points["tool"]["sources"] == ["main.c", "util.c"], "$(SRCS:.c=.o) prerequisites resolve back to sources"
    assert points["tool"]["headers"] == ["include/util.h"], "-I directories bind headers"
    assert points["vendor"]["kind"] == "delegating"
    assert points["all"]["kind"] == "phony_or_aggregate"
    assert [(d["path"], d["via"], d["evidence"]) for d in unit["drives"]] == [("vendor/lib", "recursive_make", "Makefile:12")]
    assignment = assign_paths(files, inventory)
    assert assignment["main.c"] == "evidence_of:.|make#tool"
    assert assignment["include/util.h"] == "evidence_of:.|make#tool"
    assert assignment["vendor/lib/lib.c"] == "evidence_of:vendor/lib|make#lib.a"
    assert assignment["docs/notes.md"] == "inert"
    assert inventory["orphaned_sources"] == []


def test_make_wildcard_and_conditions_resolve_and_a_sibling_source_is_claimed_by_reference_only() -> None:
    makefile = ("SRCS := $(wildcard src/*.c) ../common/shared.c\n"
                "ifeq ($(OS),Windows_NT)\nbin: $(SRCS) win/compat.c\n\t$(CC) -I../common $^ -o bin\nelse\nbin: $(SRCS)\n\t$(CC) -I../common $^ -o bin\nendif\n")
    files, inventory = _inventory({"app/Makefile": makefile}, "app/src/one.c", "app/src/two.c", "app/win/compat.c",
                                  "common/shared.c", "common/shared.h", "common/unused.c")
    unit = _unit(inventory, "app", "make")
    bins = [p for p in unit["build_points"] if p["name"] == "bin"]
    assert {p.get("condition") for p in bins} == {"ifeq ($(OS),Windows_NT)", "NOT(ifeq ($(OS),Windows_NT))"}
    assert all("common/shared.c" in p["sources"] for p in bins), "a referenced sibling source binds to the rule"
    assert all("common/shared.h" in p["headers"] for p in bins)
    assert [o["path"] for o in inventory["orphaned_sources"]] == ["common/unused.c"]
    assert inventory["orphaned_sources"][0]["nearest_unit"] is None, "proximity never claims a source"
    assignment = assign_paths(files, inventory)
    assert assignment["common/shared.c"] == "evidence_of:app|make#bin"
    assert assignment["common/unused.c"] == "orphaned:no_build_point"


def test_make_rule_regex_does_not_swallow_the_next_line_into_prerequisites() -> None:
    points = make_build_points(".", {"Makefile": "a: a.c\n\t$(CC) a.c\nb: b.c\n\t$(CC) b.c\n"}, ["a.c", "b.c"])["build_points"]
    by_name = {p["name"]: p for p in points}
    assert by_name["a"]["sources"] == ["a.c"] and by_name["b"]["sources"] == ["b.c"]


def test_a_makefile_with_only_a_delegating_rule_is_a_unit_that_drives_without_compiling() -> None:
    makefile = "all:\n\t$(MAKE) -C core\n\t$(MAKE) -C tools\n"
    core = "core: core.c\n\t$(CC) core.c -o core\n"
    files, inventory = _inventory({"Makefile": makefile, "core/Makefile": core}, "core/core.c", "tools/stray.c")
    root = _unit(inventory, ".", "make")
    assert [p["kind"] for p in root["build_points"]] == ["delegating"]
    assert [(d["path"], d["via"]) for d in root["drives"]] == [("core", "recursive_make"), ("tools", "recursive_make")]
    # tools/ has no Makefile: the delegation is unresolved at discovery time and the source is orphaned.
    assert [o["path"] for o in inventory["orphaned_sources"]] == ["tools/stray.c"]


def test_a_path_mentioned_only_in_a_comment_does_not_bind_a_sibling_source() -> None:
    makefile = "# previously built ../common/old.c too\napp: main.c\n\t$(CC) main.c -o app\n"
    files, inventory = _inventory({"app/Makefile": makefile}, "app/main.c", "common/old.c")
    assert [o["path"] for o in inventory["orphaned_sources"]] == ["common/old.c"]
    assert "native_components" not in _unit(inventory, "app", "make")


# --- Other systems -----------------------------------------------------------------------------

def test_every_build_system_a_marker_can_produce_has_an_extractor() -> None:
    from appsec_review.jobs.build_discovery import _MARKERS, _SUFFIX_MARKERS
    systems = {system for _family, system in (*_MARKERS.values(), *_SUFFIX_MARKERS.values())}
    missing = systems - set(EXTRACTORS)
    assert not missing, f"marker build systems without a build-point extractor: {sorted(missing)}"


def test_cargo_package_and_bins_are_build_points_with_their_sources() -> None:
    cargo = '[package]\nname = "tool"\nversion = "0.1.0"\n\n[[bin]]\nname = "tool-cli"\npath = "src/bin/cli.rs"\n\n[lib]\npath = "src/lib.rs"\n'
    files, inventory = _inventory({"Cargo.toml": cargo}, "src/lib.rs", "src/bin/cli.rs", "src/main.rs", "build.rs")
    points = _unit(inventory, ".", "cargo")["build_points"]
    assert {(p["name"], p["kind"]) for p in points} == {("tool", "lib"), ("tool", "bin"), ("tool-cli", "bin"), ("build-script", "build_script")}
    cli = next(p for p in points if p["name"] == "tool-cli")
    assert cli["sources"] == ["src/bin/cli.rs"] and cli["evidence"] == "Cargo.toml:5"


def test_go_main_packages_are_build_points_of_the_module() -> None:
    gomod = "module example.com/svc\n\ngo 1.24\n"
    files, inventory = _inventory({"go.mod": gomod, "cmd/api/main.go": "package main\n\nfunc main() {}\n",
                                   "cmd/worker/main.go": "package main\n\nfunc main() {}\n",
                                   "internal/core/core.go": "package core\n"})
    points = _points(_unit(inventory, ".", "go"))
    assert {name: p["kind"] for name, p in points.items() if p["kind"] == "main_package"} == {
        "cmd/api": "main_package", "cmd/worker": "main_package"}
    assert points["cmd/api"]["sources"] == ["cmd/api/main.go"]


def test_npm_scripts_are_build_points_and_lockfiles_are_context() -> None:
    pkg = '{\n  "name": "web",\n  "scripts": {\n    "build": "tsc -p .",\n    "test": "vitest"\n  }\n}\n'
    files, inventory = _inventory({"package.json": pkg}, "package-lock.json", "tsconfig.json", "src/index.ts", "README.md")
    points = _points(_unit(inventory, ".", "node"))
    assert points["build"]["kind"] == "script" and points["build"]["evidence"] == "package.json:4"
    assignment = assign_paths(files, inventory)
    assert assignment["package-lock.json"] == "context:.|node"
    assert assignment["tsconfig.json"] == "context:.|node"
    assert assignment["README.md"] == "inert"
    assert assignment["src/index.ts"] == "evidence_of:.|node"


def test_a_solution_lists_projects_as_build_points_and_a_vcxproj_names_its_sources() -> None:
    sln = ('Microsoft Visual Studio Solution File, Format Version 12.00\n'
           'Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "engine", "engine\\engine.vcxproj", "{AAAA}"\nEndProject\n'
           'Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "ghost", "ghost\\ghost.vcxproj", "{BBBB}"\nEndProject\n')
    vcx = ('<Project>\n  <ItemGroup>\n    <ClCompile Include="src\\engine.cpp" />\n    <ClCompile Include="src\\io.cpp" />\n'
           '  </ItemGroup>\n</Project>\n')
    files, inventory = _inventory({"win.sln": sln, "engine/engine.vcxproj": vcx}, "engine/src/engine.cpp", "engine/src/io.cpp",
                                  "engine/engine.vcxproj.filters")
    msbuild = [u for u in inventory["units"] if u["build_system"] in {"msbuild", "dotnet"}]
    all_points = [p for u in msbuild for p in u.get("build_points", ())]
    assert ("engine", "solution_project", "win.sln:2") in {(p["name"], p["kind"], p["evidence"]) for p in all_points}
    [sln] = [u for u in msbuild if any(str(m["path"]).endswith(".sln") for m in u["markers"])]
    assert [u["reason"] for u in sln["unresolved"]] == ["solution lists a project that is not in the target: ghost\\ghost.vcxproj"]
    assert sln["source_resolution"] == "containment", "a solution with a missing project is not read completely"
    vcx_points = [p for p in all_points if "engine/src/engine.cpp" in p.get("sources", ())]
    assert vcx_points, "ClCompile items are the project's sources"
    assert inventory["orphaned_sources"] == []


@pytest.mark.parametrize("marker, text, expected_kind", [
    ("meson.build", "project('x', 'c')\nexecutable('x', 'main.c')\nstatic_library('core', 'core.c')\n", "executable"),
    ("Makefile.am", "bin_PROGRAMS = x\nx_SOURCES = main.c core.c\n", "program"),
    ("build.gradle", "plugins { id 'java' }\n", "project"),
    ("pom.xml", "<project><artifactId>core</artifactId></project>\n", "project"),
])
def test_other_descriptors_yield_at_least_one_typed_build_point(marker: str, text: str, expected_kind: str) -> None:
    files, inventory = _inventory({marker: text}, "main.c", "core.c")
    kinds = {p["kind"] for u in inventory["units"] for p in u.get("build_points", ())}
    assert expected_kind in kinds, f"{marker}: kinds seen {sorted(kinds)}"


# --- Orphans and the total assignment ----------------------------------------------------------

@pytest.mark.parametrize("path, language", [
    ("Loose.cs", "c#"), ("Loose.swift", "swift"), ("loose.m", "objective-c"), ("loose.mm", "objective-c++"),
    ("loose.kt", "kotlin"), ("loose.rs", "rust"), ("loose.go", "go"), ("loose.java", "java"), ("kernel.cu", "cuda"),
])
def test_every_compiled_language_source_outside_any_unit_is_an_orphan_never_unclaimed(path: str, language: str) -> None:
    files = [_file(f"stray/{path}")]
    inventory = discover_build_inventory(files)
    [orphan] = inventory["orphaned_sources"]
    assert (orphan["path"], orphan["language"], orphan["reason"]) == (f"stray/{path}", language, "no_build_point")
    assert assign_paths(files, inventory)[f"stray/{path}"] == "orphaned:no_build_point"


def test_readme_and_license_files_are_inert_even_under_a_unit_root() -> None:
    cmake = "project(x C)\nadd_executable(x main.c)\n"
    files, inventory = _inventory({"CMakeLists.txt": cmake}, "main.c", "README.md", "LICENSE", "docs/README")
    assignment = assign_paths(files, inventory)
    assert assignment["README.md"] == "inert" and assignment["LICENSE"] == "inert" and assignment["docs/README"] == "inert"


def test_build_point_evidence_is_closed_over_the_tree_and_deterministic() -> None:
    cmake = "project(x C)\nadd_executable(x b.c a.c)\n"
    files, inventory = _inventory({"CMakeLists.txt": cmake}, "a.c", "b.c")
    again = discover_build_inventory(list(reversed(files)), read_text=lambda p: {"CMakeLists.txt": cmake}.get(str(p)))
    assert inventory == again, "input order never changes the result"
    [point] = _unit(inventory, ".", "cmake")["build_points"]
    assert point["sources"] == ["a.c", "b.c"], "sources are sorted so two runs compare equal"
