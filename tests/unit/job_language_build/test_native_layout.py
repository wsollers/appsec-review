from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config.build_outputs import BuildOutputDiscovery
from appsec_review.jobs.job_language_build import native_layout
from appsec_review.jobs.job_language_build.native_layout import (
    DEPENDENCY_BOOKKEEPING, DEPENDENCY_OUTPUT, DEPENDENCY_SOURCE, GENERATOR_OUTPUT, TARGET_SUBPROJECT,
    Preexisting, SourceReader, cmake_roots, discover, heuristic_roots, read_cmake_cache, read_cmake_file_api,
    read_conan_generators, read_meson_info, read_msbuild_dirs, read_ninja, read_vcpkg_installed,
    workspace_relative, write_cmake_file_api_query,
)


def _write(path: Path, text: str | bytes = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


def _reader(workspace: Path, **bounds: int) -> SourceReader:
    return SourceReader(workspace, BuildOutputDiscovery(**bounds))


_CACHE = """# This is the CMakeCache file.
//Directory under which to collect all populated content
FETCHCONTENT_BASE_DIR:PATH=/workspace/build/_deps
FETCHCONTENT_SOURCE_DIR_FMT:PATH=
CMAKE_HOME_DIRECTORY:INTERNAL=/workspace
CMAKE_CACHEFILE_DIR:INTERNAL=/workspace/build
app_SOURCE_DIR:STATIC=/workspace
app_BINARY_DIR:STATIC=/workspace/build
app_IS_TOP_LEVEL:STATIC=ON
fmt_SOURCE_DIR:STATIC=/workspace/build/_deps/fmt-src
fmt_BINARY_DIR:STATIC=/workspace/build/_deps/fmt-build
fmt_IS_TOP_LEVEL:STATIC=OFF
inner_SOURCE_DIR:STATIC=/workspace/lib/inner
inner_BINARY_DIR:STATIC=/workspace/build/lib/inner
inner_IS_TOP_LEVEL:STATIC=OFF
"""


def _fetchcontent(workspace: Path) -> None:
    _write(workspace / "CMakeLists.txt", "project(app)\n")
    _write(workspace / "lib/inner/CMakeLists.txt", "project(inner)\n")
    _write(workspace / "build/CMakeCache.txt", _CACHE)
    _write(workspace / "build/_deps/fmt-src/CMakeLists.txt", "project(fmt)\n")
    _write(workspace / "build/_deps/fmt-build/libfmt.a", b"!<arch>\n")
    _write(workspace / "build/_deps/fmt-subbuild/CMakeLists.txt", "")


def test_workspace_relative_maps_container_host_and_relative_paths_only_inside_the_workspace(tmp_path: Path) -> None:
    assert workspace_relative("/workspace/build/_deps") == "build/_deps"
    assert workspace_relative("/workspace") == ""
    assert workspace_relative("lib/../src/a.c", "build") == "build/src/a.c"
    assert workspace_relative(str(tmp_path.resolve() / "x" / "y"), workspace=tmp_path) == "x/y"
    for value in ("/usr/include", "../escape", "build/../../x", "C:/x", "", None, "a\0b"):
        assert workspace_relative(value) is None, value
    assert workspace_relative("../x", "build") == "x"


def test_cmake_cache_yields_fetchcontent_source_output_and_subbuild_roots_only(tmp_path: Path) -> None:
    _fetchcontent(tmp_path)
    reader = _reader(tmp_path)
    cache = read_cmake_cache(reader, "build")
    assert cache is not None and cache.fetch_base == "build/_deps" and cache.home == ""
    by_name = {project.name: project for project in cache.projects}
    assert by_name["app"].top_level and not by_name["fmt"].top_level
    assert by_name["fmt"].source == "build/_deps/fmt-src"

    roots = cmake_roots(cache, None, Preexisting(["CMakeLists.txt", "lib/inner/CMakeLists.txt"]))

    assert [(root.root, root.role, root.name) for root in roots] == [
        ("build/_deps/fmt-build", DEPENDENCY_OUTPUT, "fmt"),
        ("build/_deps/fmt-src", DEPENDENCY_SOURCE, "fmt"),
        ("build/_deps/fmt-subbuild", DEPENDENCY_BOOKKEEPING, "fmt"),
    ]
    assert all(root.basis == "build-system-fact" and root.confidence == "fact" for root in roots)
    assert roots[1].evidence_ref == "build/CMakeCache.txt#fmt_SOURCE_DIR"
    assert roots[0].evidence_ref == "build/CMakeCache.txt#fmt_BINARY_DIR"
    assert [(source.kind, source.path) for source in reader.sources] == [("cmake-cache", "build/CMakeCache.txt")]


def test_cmake_dependency_already_in_the_snapshot_is_never_reclassified(tmp_path: Path) -> None:
    _fetchcontent(tmp_path)
    cache = read_cmake_cache(_reader(tmp_path), "build")
    committed = Preexisting(["CMakeLists.txt", "build/_deps/fmt-src/CMakeLists.txt"])

    assert [root.root for root in cmake_roots(cache, None, committed)] == []


def test_cmake_file_api_query_and_codemodel_reply(tmp_path: Path) -> None:
    query = write_cmake_file_api_query(tmp_path, "build")
    assert query == "build/.cmake/api/v1/query/client-appsec-review/query.json"
    assert json.loads((tmp_path / query).read_text())["requests"] == [
        {"kind": "codemodel", "version": 2}, {"kind": "cmakeFiles", "version": 1}]

    reply = tmp_path / "build/.cmake/api/v1/reply"
    _write(reply / "index-2026-01-01T00-00-00-0000.json", json.dumps({
        "objects": [], "reply": {"client-appsec-review": {"query.json": {"responses": [
            {"kind": "codemodel", "version": {"major": 2, "minor": 6}, "jsonFile": "codemodel-v2-1.json"}]}}}}))
    _write(reply / "codemodel-v2-1.json", json.dumps({
        "paths": {"source": "/workspace", "build": "/workspace/build"},
        "configurations": [{
            "directories": [{"source": ".", "build": "."},
                            {"source": "build/_deps/fmt-src", "build": "_deps/fmt-build"}],
            "projects": [{"name": "app", "directoryIndexes": [0]},
                         {"name": "fmt", "parentIndex": 0, "directoryIndexes": [1]}]}]}))
    _write(tmp_path / "build/_deps/fmt-src/CMakeLists.txt")
    _write(tmp_path / "build/_deps/fmt-build/libfmt.a")
    reader = _reader(tmp_path)

    projects = read_cmake_file_api(reader, "build")

    assert projects is not None
    assert [(project.name, project.source, project.binary, project.top_level) for project in projects] == [
        ("app", "", "build", True), ("fmt", "build/_deps/fmt-src", "build/_deps/fmt-build", False)]
    roots = cmake_roots(None, projects, Preexisting(["CMakeLists.txt"]))
    assert {(root.root, root.role) for root in roots} == {
        ("build/_deps/fmt-src", DEPENDENCY_SOURCE), ("build/_deps/fmt-build", DEPENDENCY_OUTPUT),
        ("build/_deps/fmt-subbuild", DEPENDENCY_BOOKKEEPING)}
    assert roots[1].evidence_ref.startswith("build/.cmake/api/v1/reply/codemodel-v2-1.json#projects/fmt")
    assert [source.kind for source in reader.sources] == ["cmake-file-api-index", "cmake-file-api-codemodel"]


def test_missing_file_api_reply_falls_back_to_the_cache_with_a_named_gap(tmp_path: Path) -> None:
    _fetchcontent(tmp_path)
    query = write_cmake_file_api_query(tmp_path, "build")

    facts = discover(tmp_path, build_dir="build", source_dir=".", build_system="cmake",
                     preexisting=Preexisting(["CMakeLists.txt", "lib/inner/CMakeLists.txt", query]),
                     discovery=BuildOutputDiscovery(), file_api_query=query)

    assert any(gap.startswith("cmake-file-api-reply-missing: build/.cmake/api/v1/reply") for gap in facts.gaps)
    assert {root.root for root in facts.roots} == {
        "build/_deps/fmt-src", "build/_deps/fmt-build", "build/_deps/fmt-subbuild"}


def test_malformed_codemodel_reply_is_a_gap_not_an_exception(tmp_path: Path) -> None:
    reply = tmp_path / "build/.cmake/api/v1/reply"
    _write(reply / "index-1.json", json.dumps({"objects": [{"kind": "codemodel", "jsonFile": "cm.json"}]}))
    _write(reply / "cm.json", "{not json")
    reader = _reader(tmp_path)

    assert read_cmake_file_api(reader, "build") == ()
    assert reader.gaps and reader.gaps[0].startswith("build-output-layout-source-malformed: build/.cmake/api/v1/reply/cm.json")


def test_oversized_cache_is_a_bound_gap_and_classifies_nothing(tmp_path: Path) -> None:
    _fetchcontent(tmp_path)

    facts = discover(tmp_path, build_dir="build", source_dir=".", build_system="cmake",
                     preexisting=Preexisting(["CMakeLists.txt"]),
                     discovery=BuildOutputDiscovery(max_layout_source_bytes=64))

    assert facts.roots == []
    assert any(gap.startswith("build-output-layout-source-bound-exceeded: build/CMakeCache.txt") for gap in facts.gaps)


def test_layout_source_count_limit_is_one_aggregated_gap(tmp_path: Path) -> None:
    for index in range(3):
        _write(tmp_path / f"m{index}.json", "{}")
    reader = _reader(tmp_path, max_layout_sources=1)

    assert reader.json("m0.json", "x") == {}
    assert reader.json("m1.json", "x") is None and reader.json("m2.json", "x") is None
    assert reader.finish() == [
        "build-output-layout-source-limit: 2 metadata files beyond max_layout_sources 1 were not read; "
        "the trees they describe stay per-file target content"]


def _meson(workspace: Path, subproject_dir_name: str = "zlib-1.3.1") -> None:
    info = workspace / "builddir/meson-info"
    _write(info / "meson-info.json", json.dumps({"directories": {"source": "/workspace", "build": "/workspace/builddir"}}))
    _write(info / "intro-projects.json", json.dumps({
        "descriptive_name": "app", "subproject_dir": "subprojects",
        "subprojects": [{"name": "zlib", "version": "1.3.1", "descriptive_name": "zlib"}]}))
    _write(info / "intro-targets.json", json.dumps([
        {"name": "app", "type": "executable", "subproject": None, "defined_in": "/workspace/meson.build",
         "filename": ["/workspace/builddir/app"]},
        {"name": "z", "type": "static library", "subproject": "zlib",
         "defined_in": f"/workspace/subprojects/{subproject_dir_name}/meson.build",
         "filename": [f"/workspace/builddir/subprojects/{subproject_dir_name}/libz.a"]}]))
    _write(workspace / f"subprojects/{subproject_dir_name}/meson.build", "project('zlib', 'c')\n")
    _write(workspace / f"builddir/subprojects/{subproject_dir_name}/libz.a", b"!<arch>\n")


def test_meson_wrap_subproject_is_dependency_source_and_output(tmp_path: Path) -> None:
    _meson(tmp_path)
    reader = _reader(tmp_path)

    roots = read_meson_info(reader, "builddir", Preexisting(["meson.build", "subprojects/zlib.wrap"]))

    assert [(root.root, root.role, root.name, root.basis) for root in roots or ()] == [
        ("subprojects/zlib-1.3.1", DEPENDENCY_SOURCE, "zlib", "build-system-fact"),
        ("builddir/subprojects/zlib-1.3.1", DEPENDENCY_OUTPUT, "zlib", "build-system-fact")]
    assert [source.kind for source in reader.sources] == ["meson-info", "meson-intro-projects", "meson-intro-targets"]


def test_committed_meson_subproject_stays_target_and_is_annotated(tmp_path: Path) -> None:
    _meson(tmp_path)

    roots = read_meson_info(_reader(tmp_path), "builddir",
                            Preexisting(["meson.build", "subprojects/zlib-1.3.1/meson.build"]))

    assert {root.role for root in roots or ()} == {TARGET_SUBPROJECT}
    assert all("committed Meson subproject zlib" in root.reason for root in roots or ())


def test_no_meson_info_is_silence(tmp_path: Path) -> None:
    assert read_meson_info(_reader(tmp_path), "builddir", Preexisting([])) is None


def test_static_ninja_parse_follows_subninja_and_respects_escapes(tmp_path: Path) -> None:
    _write(tmp_path / "out/build.ninja",
           "rule cc\n  command = cc -c $in -o $out\n"
           "build obj/a.o: cc ../src/a.c | ../src/a.h || gen_stamp\n"
           "build obj/b$ c.o: cc ../src/b$ c.c $\n    ../src/extra.c\n"
           "build all: phony obj/a.o\n"
           "build ${builddir}/x.o: cc ../src/x.c\n"
           "subninja sub/sub.ninja\n")
    _write(tmp_path / "out/sub/sub.ninja", "build libdep.a: ar dep/x.o\n")
    reader = _reader(tmp_path)

    edges = read_ninja(reader, "out")

    assert edges == [
        (("out/obj/a.o",), ("src/a.c", "src/a.h")),
        (("out/obj/b c.o",), ("src/b c.c", "src/extra.c")),
        ((), ("src/x.c",)),
        (("out/libdep.a",), ("out/dep/x.o",)),
    ]
    assert [source.path for source in reader.sources] == ["out/build.ninja", "out/sub/sub.ninja"]


def test_ninja_edge_bound_is_a_gap_and_disables_ninja_attribution(tmp_path: Path) -> None:
    _write(tmp_path / "build.ninja", "".join(f"build o{index}.o: cc s{index}.c\n" for index in range(5)))
    reader = _reader(tmp_path, max_ninja_edges=3)

    assert read_ninja(reader, "") is None
    assert reader.gaps[0].startswith("build-output-ninja-edge-bound-exceeded: build.ninja")


def _vcpkg(workspace: Path) -> None:
    root = workspace / "build/vcpkg_installed"
    _write(root / "vcpkg/status",
           "Package: zlib\nVersion: 1.3.1\nArchitecture: x64-linux\nStatus: install ok installed\n\n"
           "Package: openssl\nVersion: 3.2.0\nArchitecture: x64-linux\nStatus: install ok installed\n\n"
           "Package: openssl\nFeature: tools\nArchitecture: x64-linux\nStatus: install ok installed\n")
    _write(root / "vcpkg/info/zlib_1.3.1_x64-linux.list",
           "x64-linux/\nx64-linux/include/\nx64-linux/include/zlib.h\nx64-linux/lib/libz.a\n")
    _write(root / "vcpkg/info/openssl_3.2.0_x64-linux.list", "x64-linux/lib/libssl.so\n")
    _write(root / "x64-linux/include/zlib.h")
    _write(root / "x64-linux/lib/libz.a")


def test_vcpkg_installed_tree_is_an_installer_record_root(tmp_path: Path) -> None:
    _vcpkg(tmp_path)
    reader = _reader(tmp_path)

    root = read_vcpkg_installed(reader, "build/vcpkg_installed", Preexisting(["vcpkg.json"]))

    assert root is not None and root.root == "build/vcpkg_installed" and root.role == DEPENDENCY_OUTPUT
    assert root.basis == "installer-record" and root.name == "vcpkg"
    assert "2 ports (openssl, zlib); 3 files recorded" in root.reason
    assert [source.kind for source in reader.sources] == ["vcpkg-status", "vcpkg-info", "vcpkg-info"]


def test_vcpkg_ownership_record_over_a_bound_falls_back_to_per_file(tmp_path: Path) -> None:
    _vcpkg(tmp_path)
    _write(tmp_path / "build/vcpkg_installed/vcpkg/info/big_1_x64-linux.list", "x" * 2000)
    reader = _reader(tmp_path, max_layout_source_bytes=1000)

    assert read_vcpkg_installed(reader, "build/vcpkg_installed", Preexisting([])) is None
    assert any(gap.startswith("build-output-layout-source-bound-exceeded: build/vcpkg_installed/vcpkg/info/big")
               for gap in reader.gaps)


def test_msbuild_directories_expand_only_recipe_stated_macros(tmp_path: Path) -> None:
    _write(tmp_path / "proj/app.vcxproj",
           '<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><PropertyGroup>'
           "<OutDir>$(SolutionDir)bin\\$(Configuration)\\</OutDir>"
           "<IntDir>obj\\$(Platform)\\</IntDir>"
           "<OutDir>$(UserRootDir)\\x</OutDir>"
           "</PropertyGroup></Project>")
    reader = _reader(tmp_path)

    directories = read_msbuild_dirs(reader, ["proj/app.vcxproj"],
                                    {"Configuration": "Release", "Platform": "x64", "SolutionDir": "/workspace/"})

    assert directories == ["bin/Release", "proj/obj/x64"]
    assert reader.gaps == ["build-output-msbuild-directory-unresolved: proj/app.vcxproj OutDir "
                           "'$(UserRootDir)\\\\x' uses UserRootDir the recipe does not state"]


def test_conan_generators_directory_is_generator_output(tmp_path: Path) -> None:
    _write(tmp_path / "build/Release/generators/conan_toolchain.cmake", "set(X 1)\n")
    _write(tmp_path / "build/conanbuildinfo.txt", "")

    roots = read_conan_generators(_reader(tmp_path), "build", Preexisting(["conanfile.txt"]))

    assert [(root.root, root.role, root.evidence_ref) for root in roots] == [
        ("build/Release/generators", GENERATOR_OUTPUT, "build/Release/generators/conan_toolchain.cmake")]


def test_heuristic_roots_need_a_build_created_child_of_a_dependency_name(tmp_path: Path) -> None:
    _write(tmp_path / "third_party/foo/CMakeLists.txt")
    _write(tmp_path / "third_party/bar/bar.c")
    _write(tmp_path / "third_party/kept/CMakeLists.txt")
    _write(tmp_path / "build/_deps/fmt-src/CMakeLists.txt")
    _write(tmp_path / "src/vendor/x/meson.build")

    roots = heuristic_roots(tmp_path, Preexisting(["third_party/kept/CMakeLists.txt", "src/main.c"]),
                            covered=["build/_deps/fmt-src"])

    assert [(root.root, root.confidence, root.basis) for root in roots] == [
        ("src/vendor/x", "medium", "heuristic"),
        ("third_party/bar", "low", "heuristic"),
        ("third_party/foo", "medium", "heuristic"),
    ]


def test_role_dispositions_cover_every_role() -> None:
    assert set(native_layout.ROLE_DISPOSITIONS) == {
        DEPENDENCY_SOURCE, DEPENDENCY_OUTPUT, DEPENDENCY_BOOKKEEPING, GENERATOR_OUTPUT, TARGET_SUBPROJECT}
    assert native_layout.ROLE_DISPOSITIONS[DEPENDENCY_BOOKKEEPING] == ("evidence", False)


@pytest.mark.parametrize("build_dir", ["", "."])
def test_in_source_builds_use_the_workspace_root(tmp_path: Path, build_dir: str) -> None:
    _write(tmp_path / "build.ninja", "build a.o: cc a.c\n")

    facts = discover(tmp_path, build_dir=build_dir, source_dir=".", build_system="ninja",
                     preexisting=Preexisting(["a.c"]), discovery=BuildOutputDiscovery())

    assert facts.ninja_edges == [(("a.o",), ("a.c",))]
