from __future__ import annotations

from typing import Any

from appsec_review.jobs.job_language_build.native_layout import (
    DEPENDENCY_BOOKKEEPING, DEPENDENCY_OUTPUT, DEPENDENCY_SOURCE, Preexisting,
)
from appsec_review.jobs.job_language_build.output_attribution import (
    CAPTURE_INCOMPLETE_GAP, attribute, created_writers, dependency_outputs, is_fetcher,
)


class _Events:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self._ordinal = 0

    def _add(self, **event: Any) -> None:
        self._ordinal += 1
        self.events.append({"timestamp_ns": self._ordinal, "ordinal": self._ordinal, **event})

    def exec(self, pid: int, executable: str, *argv: str) -> None:
        self._add(kind="process_exec", pid=pid, executable=executable,
                  argv=[executable.rsplit("/", 1)[-1], *argv], result=0)

    def fork(self, pid: int, child: int) -> None:
        self._add(kind="process_fork", pid=pid, child_pid=child)

    def create(self, pid: int, path: str) -> None:
        self._add(kind="file_open", pid=pid, access="write", creates=True, path=path, result=3)


def _row(inputs: list[str], outputs: list[str], origin: str = "execution-capture:command-002") -> dict[str, Any]:
    return {"inputs": [{"workspace_path": path} for path in inputs],
            "outputs": [{"workspace_path": path} for path in outputs], "origin": origin}


def test_fetcher_images_are_download_and_unpack_tools_not_compilers() -> None:
    assert is_fetcher("/usr/bin/git", ["git", "clone"])
    assert is_fetcher("/usr/lib/git-core/git-remote-https", ["git-remote-https"])
    assert is_fetcher("/usr/bin/cmake", ["cmake", "-E", "tar", "xzf", "fmt.tar.gz"])
    assert is_fetcher("/usr/bin/cmake", ["cmake", "-P", "fmt-subbuild/download.cmake"])
    assert is_fetcher("/usr/bin/python3", ["python3", "/usr/bin/meson", "subprojects", "download"])
    assert not is_fetcher("/usr/bin/cmake", ["cmake", "--build", "build"])
    assert not is_fetcher("/usr/bin/cc", ["cc", "-c", "a.c"])
    assert not is_fetcher("/usr/bin/python3", ["python3", "/usr/bin/meson", "setup", "build"])


def _fetchcontent_capture() -> _Events:
    events = _Events()
    events.exec(10, "/usr/bin/cmake", "-S", ".", "-B", "build")
    events.create(10, "/workspace/build/CMakeCache.txt")
    events.create(10, "/workspace/build/_deps/fmt-subbuild/CMakeLists.txt")
    events.fork(10, 11)
    events.exec(11, "/usr/bin/git", "clone", "fmt")
    for name in ("CMakeLists.txt", "include/fmt/core.h", "src/format.cc", "test/CMakeLists.txt"):
        events.create(11, f"/workspace/build/_deps/fmt-src/{name}")
    events.fork(10, 12)
    events.exec(12, "/usr/bin/cmake", "-E", "touch", "x")
    events.create(12, "/workspace/build/_deps/fmt-src/.stamp")
    return events


def test_git_written_tree_with_its_own_build_file_is_a_fetched_root() -> None:
    preexisting = Preexisting(["CMakeLists.txt", "main.cc"])

    result = attribute([_fetchcontent_capture().events], [], capture_complete=True, preexisting=preexisting,
                       initial_directory="/workspace", build_dir="build", dependency_sources={},
                       evidence_ref="execution-capture:command-001")

    assert [(root.root, root.role, root.basis, root.confidence, root.name) for root in result.roots] == [
        ("build/_deps/fmt-src", DEPENDENCY_SOURCE, "execution-capture", "high", "fmt")]
    assert "4 of 5 created files written by a fetcher" in result.roots[0].reason
    assert result.gaps == []


def test_cmake_tar_extraction_is_a_fetcher_and_writer_follows_exec_not_argv0() -> None:
    events = _Events()
    events.exec(20, "/usr/bin/cmake", "-E", "tar", "xzf", "zlib.tgz")
    events.create(20, "/workspace/deps/zlib/CMakeLists.txt")
    events.create(20, "/workspace/deps/zlib/zlib.h")
    events.exec(21, "/usr/bin/cc", "-c", "zlib.c")
    events.create(21, "/workspace/deps/zlib/CMakeLists.txt.bak")

    writers = created_writers([events.events], initial_directory="/workspace", preexisting=Preexisting([]))

    assert writers == {"deps/zlib/CMakeLists.txt": True, "deps/zlib/zlib.h": True,
                       "deps/zlib/CMakeLists.txt.bak": False}


def test_a_tree_mostly_written_by_the_compiler_is_not_fetched() -> None:
    events = _Events()
    events.exec(30, "/usr/bin/git", "clone")
    events.create(30, "/workspace/gen/CMakeLists.txt")
    events.exec(31, "/usr/bin/cc")
    for index in range(3):
        events.create(31, f"/workspace/gen/o{index}.o")

    result = attribute([events.events], [], capture_complete=True, preexisting=Preexisting([]),
                       initial_directory="/workspace", build_dir="build", dependency_sources={})

    assert result.roots == []


def test_committed_tree_is_never_fetched_even_when_git_rewrites_it() -> None:
    events = _Events()
    events.exec(40, "/usr/bin/git", "checkout")
    events.create(40, "/workspace/third_party/foo/CMakeLists.txt")
    events.create(40, "/workspace/third_party/foo/foo.c")

    result = attribute([events.events], [], capture_complete=True,
                       preexisting=Preexisting(["third_party/foo/README"]),
                       initial_directory="/workspace", build_dir="build", dependency_sources={})

    assert result.roots == []


def test_external_project_layout_registers_build_stamp_and_tmp() -> None:
    events = _Events()
    events.exec(50, "/usr/bin/curl")
    events.create(50, "/workspace/build/zlib-prefix/src/zlib.tar.gz")
    events.exec(51, "/usr/bin/tar", "xf")
    events.create(51, "/workspace/build/zlib-prefix/src/zlib/CMakeLists.txt")
    events.create(51, "/workspace/build/zlib-prefix/src/zlib/zlib.c")
    events.exec(52, "/usr/bin/cmake", "-E", "touch")
    events.create(52, "/workspace/build/zlib-prefix/src/zlib-stamp/zlib-download")
    events.create(52, "/workspace/build/zlib-prefix/tmp/zlib-cfgcmd.txt")
    events.exec(53, "/usr/bin/cc")
    events.create(53, "/workspace/build/zlib-prefix/src/zlib-build/libz.a")

    result = attribute([events.events], [], capture_complete=True, preexisting=Preexisting(["CMakeLists.txt"]),
                       initial_directory="/workspace", build_dir="build", dependency_sources={})

    assert {(root.root, root.role, root.name) for root in result.roots} == {
        ("build/zlib-prefix/src/zlib", DEPENDENCY_SOURCE, "zlib"),
        ("build/zlib-prefix/src/zlib-build", DEPENDENCY_OUTPUT, "zlib"),
        ("build/zlib-prefix/src/zlib-stamp", DEPENDENCY_BOOKKEEPING, "zlib"),
        ("build/zlib-prefix/tmp", DEPENDENCY_BOOKKEEPING, "zlib")}


def test_compiler_output_from_dependency_sources_gives_a_dependency_output_root() -> None:
    rows = [
        _row(["build/_deps/fmt-src/src/format.cc"], ["build/_deps/fmt-build/CMakeFiles/fmt.dir/src/format.cc.o"]),
        _row(["build/_deps/fmt-build/CMakeFiles/fmt.dir/src/format.cc.o"], ["build/_deps/fmt-build/libfmt.a"]),
        _row(["main.cc"], ["build/CMakeFiles/app.dir/main.cc.o"]),
        _row(["build/CMakeFiles/app.dir/main.cc.o"], ["build/app"]),
    ]

    roots, tagged = dependency_outputs(rows, {"build/_deps/fmt-src": "fmt"}, build_dir="build",
                                       preexisting=Preexisting(["main.cc", "CMakeLists.txt"]))

    assert [(root.root, root.role, root.basis, root.confidence, root.name, root.evidence_ref) for root in roots] == [
        ("build/_deps/fmt-build", DEPENDENCY_OUTPUT, "execution-capture", "fact", "fmt",
         "execution-capture:command-002")]
    assert tagged == ()


def test_mixed_directory_is_not_reclassified_and_dependency_outputs_are_tagged() -> None:
    rows = [
        _row(["deps/fmt/format.cc"], ["build/format.o"]),
        _row(["build/format.o"], ["build/libfmt.so"]),
        _row(["main.cc"], ["build/main.o"]),
        _row(["build/main.o"], ["build/app"]),
    ]

    roots, tagged = dependency_outputs(rows, {"deps/fmt": "fmt"}, build_dir="build",
                                       preexisting=Preexisting(["main.cc"]))

    assert roots == []
    assert tagged == ("build/format.o", "build/libfmt.so")


def test_output_mixing_target_and_dependency_inputs_stays_target() -> None:
    rows = [_row(["deps/fmt/format.cc"], ["out/dep/format.o"]),
            _row(["out/dep/format.o", "main.o"], ["out/dep/app"])]

    roots, tagged = dependency_outputs(rows, {"deps/fmt": "fmt"}, build_dir="out",
                                       preexisting=Preexisting(["main.o"]))

    assert roots == [] and tagged == ("out/dep/format.o",)


def test_dependency_built_inside_its_own_source_root_needs_no_output_root() -> None:
    rows = [_row(["subprojects/z/z.c"], ["subprojects/z/z.o"])]

    assert dependency_outputs(rows, {"subprojects/z": "z"}, build_dir="build",
                              preexisting=Preexisting([])) == ([], ())


def test_incomplete_capture_disables_classification_with_a_named_gap() -> None:
    result = attribute([_fetchcontent_capture().events],
                       [_row(["build/_deps/fmt-src/a.cc"], ["build/_deps/fmt-build/a.o"])],
                       capture_complete=False, preexisting=Preexisting([]), initial_directory="/workspace",
                       build_dir="build", dependency_sources={"build/_deps/fmt-src": "fmt"})

    assert result.roots == [] and result.tagged_outputs == ()
    assert len(result.gaps) == 1 and result.gaps[0].startswith(CAPTURE_INCOMPLETE_GAP + ": ")


def test_fetched_roots_seed_the_dependency_output_pass() -> None:
    rows = [_row(["build/_deps/fmt-src/src/format.cc"], ["build/_deps/fmt-build/format.o"])]

    result = attribute([_fetchcontent_capture().events], rows, capture_complete=True,
                       preexisting=Preexisting(["CMakeLists.txt"]), initial_directory="/workspace",
                       build_dir="build", dependency_sources={})

    assert {(root.root, root.role) for root in result.roots} == {
        ("build/_deps/fmt-src", DEPENDENCY_SOURCE), ("build/_deps/fmt-build", DEPENDENCY_OUTPUT)}
