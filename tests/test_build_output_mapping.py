"""Produced-artifact catalogs exclude build bookkeeping, and captured tools name their outputs.

Every layout here is synthetic: a CMake project with a configure-time probe tree, a Cargo
workspace with several crates, and a javac tree with packages, nested and anonymous classes,
and an @argfile.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import os
from pathlib import Path
import shutil
import struct
import subprocess
from typing import Any

import pytest

from appsec_review.jobs.artifact_kinds import ARTIFACT_KINDS, ArtifactKind, binary_role
from appsec_review.jobs.build_bookkeeping import (
    BookkeepingExclusions, BookkeepingReason, bookkeeping_reason,
)
from appsec_review.jobs.job_language_build import jvm, native_components, rust
from appsec_review.jobs.job_language_build.capture import reconcile_captured_build
from appsec_review.jobs.job_language_build.job import _attribute_captured_rows, _catalog
from appsec_review.jobs.job_project_build.job import _outputs as probe_outputs
from appsec_review.storage import file_sha256


HASH_A, HASH_B, HASH_C = "0123456789abcdef", "fedcba9876543210", "00112233aabbccdd"


def _elf(e_type: int, *, interpreter: bool = False) -> bytes:
    """A little-endian ELF64 header with zero or one program header."""
    count = 1 if interpreter else 0
    header = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    header += struct.pack("<HHIQQQIHHHHHH", e_type, 62, 1, 0, 64 if count else 0, 0, 0, 64, 56, count, 0, 0, 0)
    if interpreter:
        header += struct.pack("<IIQQQQQQ", 3, 4, 120, 120, 120, 28, 28, 1)
        header += b"/lib64/ld-linux-x86-64.so.2\0"
    return header


def _write(root: Path, relative: str, content: bytes | str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    return path


class Capture:
    """A verified capture as the reconciler reads it."""

    def __init__(self, events: Sequence[Mapping[str, Any]]) -> None:
        self._events = tuple(events)
        self.tool_calls = ()
        self.gaps = ()
        self.identity = {"sha256": "a" * 64}
        self.document = {"events": {"observed": len(events), "retained": len(events)},
                         "tool_calls": {"observed": 0, "retained": 0}}

    def events(self):
        yield from self._events


def _exec(ordinal: int, executable: str, argv: Sequence[str], *, pid: int = 10) -> dict[str, Any]:
    return {"kind": "process_exec", "ordinal": ordinal, "pid": pid, "timestamp_ns": ordinal,
            "executable": executable, "argv": list(argv), "argv_truncated": False, "result": 0}


def _chdir(ordinal: int, path: str, *, pid: int = 10) -> dict[str, Any]:
    return {"kind": "directory_change", "ordinal": ordinal, "pid": pid, "timestamp_ns": ordinal,
            "path": path, "result": 0}


# --- Build bookkeeping -------------------------------------------------------------------------

def _cmake_project(workspace: Path) -> None:
    probe = _elf(3, interpreter=True)
    _write(workspace, "build/CMakeFiles/3.28.3/CompilerIdC/a.out", probe)
    _write(workspace, "build/CMakeFiles/3.28.3/CompilerIdCXX/a.out", probe)
    _write(workspace, "build/CMakeFiles/3.28.3/CompilerIdC/tmp/CMakeCCompilerId.o", _elf(1))
    _write(workspace, "build/CMakeFiles/3.28.3/CMakeDetermineCompilerABI_C.bin", probe)
    _write(workspace, "build/CMakeFiles/CMakeScratch/TryCompile-x1y2/cmTC_5b3c1", probe)
    _write(workspace, "build/CMakeFiles/CMakeScratch/TryCompile-x1y2/CMakeFiles/cmTC_5b3c1.dir/src.c.o", _elf(1))
    _write(workspace, "build/CMakeFiles/CMakeTmp/cmTC_old.dir/check.c.o", _elf(1))
    _write(workspace, "build/CMakeFiles/FindOpenMP/ompver_C.bin", probe)
    # Real outputs: a target's objects live in CMakeFiles/<target>.dir/.
    _write(workspace, "build/CMakeFiles/app.dir/src/main.c.o", _elf(1))
    _write(workspace, "build/CMakeFiles/codec.dir/src/codec.c.o", _elf(1))
    _write(workspace, "build/app", _elf(3, interpreter=True))
    _write(workspace, "build/libcodec.so.1", _elf(3))
    _write(workspace, "build/libstatic.a", b"!<arch>\nmember")


def _cargo_workspace(workspace: Path) -> None:
    profile = "target/debug"
    for crate, digest in (("core_lib", HASH_A), ("macros", HASH_B), ("app", HASH_C)):
        _write(workspace, f"{profile}/.fingerprint/{crate}-{digest}/lib-{crate}", digest)
        _write(workspace, f"{profile}/.fingerprint/{crate}-{digest}/lib-{crate}.json", "{}")
        _write(workspace, f"{profile}/deps/{crate}-{digest}.d", f"{crate}: src/lib.rs\n")
        _write(workspace, f"{profile}/incremental/{crate}-{digest}/s-abc-def/work-products.o", _elf(1))
    _write(workspace, f"{profile}/build/sys-{HASH_A}/output", "cargo:rustc-link-lib=z\n")
    _write(workspace, f"{profile}/build/sys-{HASH_A}/root-output", "/workspace/target/debug/build\n")
    _write(workspace, f"{profile}/build/sys-{HASH_A}/out/build/CMakeFiles/3.27.0/CompilerIdC/a.out",
           _elf(3, interpreter=True))
    _write(workspace, f"{profile}/app.d", "/workspace/target/debug/app: src/main.rs\n")
    # Real outputs.
    _write(workspace, f"{profile}/deps/libcore_lib-{HASH_A}.rlib", b"!<arch>\nrlib")
    _write(workspace, f"{profile}/deps/libcore_lib-{HASH_A}.rmeta", b"rmeta")
    _write(workspace, f"{profile}/deps/libmacros-{HASH_B}.so", _elf(3))
    _write(workspace, f"{profile}/deps/app-{HASH_C}", _elf(3, interpreter=True))
    _write(workspace, f"{profile}/app", _elf(3, interpreter=True) + b"stale uplift")
    _write(workspace, f"{profile}/build/sys-{HASH_A}/build-script-build", _elf(3, interpreter=True))


def test_cmake_probe_tree_is_counted_by_reason_and_target_outputs_keep_role_kinds(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _cmake_project(workspace)
    exclusions = BookkeepingExclusions()
    artifacts, gaps = _catalog(tmp_path, workspace, {}, 100, "unit", "native", exclusions)

    kinds = {item["workspace_path"]: item["kind"] for item in artifacts}
    assert kinds == {
        "build/CMakeFiles/app.dir/src/main.c.o": "object",
        "build/CMakeFiles/codec.dir/src/codec.c.o": "object",
        "build/app": "executable",
        "build/libcodec.so.1": "shared-library",
        "build/libstatic.a": "static-library",
    }
    document = exclusions.document()
    assert document["counts"] == {"cmake-compiler-identification": 4, "cmake-find-module-probe": 1,
                                  "cmake-try-compile": 3}
    assert document["total"] == 8
    assert "build/CMakeFiles/3.28.3/CompilerIdC/a.out" in document["examples"]["cmake-compiler-identification"]
    assert not any("CMakeFiles/3.28.3" in gap or "CMakeScratch" in gap for gap in gaps)


def test_cargo_bookkeeping_is_excluded_by_reason_and_crate_outputs_remain(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _cargo_workspace(workspace)
    exclusions = BookkeepingExclusions()
    artifacts, _gaps = _catalog(tmp_path, workspace, {}, 100, "unit", "rust", exclusions)

    kinds = {item["workspace_path"]: item["kind"] for item in artifacts}
    assert kinds == {
        f"target/debug/deps/libcore_lib-{HASH_A}.rlib": "rust-library",
        f"target/debug/deps/libcore_lib-{HASH_A}.rmeta": "rust-metadata",
        f"target/debug/deps/libmacros-{HASH_B}.so": "shared-library",
        f"target/debug/deps/app-{HASH_C}": "executable",
        "target/debug/app": "executable",
        f"target/debug/build/sys-{HASH_A}/build-script-build": "executable",
    }
    counts = exclusions.document()["counts"]
    # Fingerprint hashes and build-script `output` are never catalogued kinds, so only files the
    # catalog would have listed are counted: dep-info, incremental objects, and the probe binary.
    assert counts == {"cargo-dependency-info": 4, "cargo-incremental-cache": 3,
                      "cmake-compiler-identification": 1}


def test_cargo_rules_do_not_apply_outside_rust_and_real_paths_are_never_bookkeeping() -> None:
    assert bookkeeping_reason(f"target/debug/incremental/app-{HASH_A}/s-1/x.o") is None
    assert bookkeeping_reason(f"target/debug/incremental/app-{HASH_A}/s-1/x.o", cargo=True) is \
        BookkeepingReason.CARGO_INCREMENTAL
    for real in ("build/CMakeFiles/app.dir/main.c.o", "CMakeFiles/app.dir/x.o", "build/app",
                 "target/debug/deps/libx-0123456789abcdef.rlib", "src/incremental/x.o"):
        assert bookkeeping_reason(real, cargo=True) is None, real
    assert bookkeeping_reason("build/CMakeFiles/CMakeOutput.log") is None
    assert bookkeeping_reason("target/debug/app.d", cargo=True) is None  # Profile unknown.
    assert bookkeeping_reason("target/debug/app.d", cargo=True,
                              cargo_profile_directories=frozenset({"target/debug"})) is \
        BookkeepingReason.CARGO_DEPENDENCY_INFO


def test_project_build_probe_outputs_use_role_kinds_and_record_exclusions(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _cmake_project(workspace)
    _write(workspace, "out/Main.class", b"\xca\xfe\xba\xbe\0\0\0\x34")
    _write(workspace, "out/tool.exe", b"MZ" + bytes(58) + struct.pack("<I", 64) + b"PE\0\0" + bytes(20))
    exclusions = BookkeepingExclusions()
    values = probe_outputs(tmp_path, workspace, {}, 100, exclusions)

    by_path = {item["workspace_path"]: (item["kind"], item["format"]) for item in values}
    assert by_path == {
        "build/CMakeFiles/app.dir/src/main.c.o": ("object", "elf"),
        "build/CMakeFiles/codec.dir/src/codec.c.o": ("object", "elf"),
        "build/app": ("executable", "elf"),
        "build/libcodec.so.1": ("shared-library", "elf"),
        "build/libstatic.a": ("static-library", "ar"),
        "out/Main.class": ("jvm-class", "class"),
        "out/tool.exe": ("executable", "pe"),
    }
    assert {kind for kind, _format in by_path.values()} <= ARTIFACT_KINDS
    assert exclusions.total == 8


@pytest.mark.parametrize(("content", "name", "expected"), [
    (_elf(1), "x.o", ("object", "elf")),
    (_elf(2), "app", ("executable", "elf")),
    (_elf(3, interpreter=True), "app", ("executable", "elf")),
    (_elf(3), "libx.so.1.2", ("shared-library", "elf")),
    (_elf(3), "static-pie-app", ("executable", "elf")),
    (b"!<arch>\n", "libx.a", ("static-library", "ar")),
    (b"\0asm\1\0\0\0", "m.wasm", ("wasm-module", "wasm")),
    (b"\xcf\xfa\xed\xfe" + struct.pack("<III", 7, 3, 6), "libx.dylib", ("shared-library", "macho")),
    (b"plain text", "notes", (None, None)),
])
def test_binary_role_reads_the_header_not_the_extension(tmp_path: Path, content: bytes, name: str,
                                                         expected: tuple[str | None, str | None]) -> None:
    assert binary_role(_write(tmp_path, name, content)) == expected


def test_every_family_catalog_kind_is_in_the_typed_vocabulary() -> None:
    from appsec_review.jobs.job_language_build import jvm as jvm_module
    from appsec_review.jobs.job_language_build import rust as rust_module
    values = {*jvm_module._KIND_BY_SUFFIX.values(), *rust_module._RUST_ARTIFACTS.values()}
    assert values <= ARTIFACT_KINDS
    assert ArtifactKind("object") is ArtifactKind.OBJECT
    with pytest.raises(ValueError):
        from appsec_review.jobs.artifact_kinds import require_artifact_kind
        require_artifact_kind("elf")


def test_cmake_probe_compiles_stay_out_of_the_native_compile_database() -> None:
    cc = "/usr/bin/cc"
    capture = Capture([
        _exec(1, cc, ["cc", "-c", "/workspace/pkg/build/CMakeFiles/3.28.3/CompilerIdC/CMakeCCompilerId.c"]),
        _chdir(2, "/workspace/pkg/build/CMakeFiles/CMakeScratch/TryCompile-ab12"),
        _exec(3, cc, ["cc", "-c", "src.c", "-o", "CMakeFiles/cmTC_1.dir/src.c.o"]),
        _chdir(4, "/workspace/pkg"),
        _exec(5, cc, ["cc", "-c", "ext/module.c", "-o", "build/module.o"]),
    ])
    exclusions = BookkeepingExclusions()
    entries, gaps = native_components.compile_entries([(1, capture)], initial_directory="/workspace/pkg",
                                                       exclusions=exclusions)
    assert [entry["file"] for entry in entries] == ["/workspace/pkg/ext/module.c"]
    assert exclusions.document()["counts"] == {"cmake-compiler-identification": 1, "cmake-try-compile": 1}
    assert gaps == []


# --- rustc outputs -----------------------------------------------------------------------------

@pytest.mark.parametrize(("argv", "expected"), [
    (["rustc", "--crate-name", "core_lib", "--edition=2021", "src/lib.rs", "--crate-type", "lib",
      "--emit=dep-info,metadata,link", "-C", f"extra-filename=-{HASH_A}", "--out-dir", "/workspace/t/deps"],
     [f"/workspace/t/deps/libcore_lib-{HASH_A}.rlib", f"/workspace/t/deps/core_lib-{HASH_A}.d",
      f"/workspace/t/deps/libcore_lib-{HASH_A}.rmeta"]),
    (["rustc", "--crate-name", "macros", "--crate-type", "proc-macro", "--emit=link",
      f"-Cextra-filename=-{HASH_B}", "--out-dir=/workspace/t/deps"],
     [f"/workspace/t/deps/libmacros-{HASH_B}.so"]),
    (["rustc", "--crate-name", "app", "--crate-type", "bin", "--emit=dep-info,link",
      "-C", f"extra-filename=-{HASH_C}", "--out-dir", "/workspace/t/deps"],
     [f"/workspace/t/deps/app-{HASH_C}", f"/workspace/t/deps/app-{HASH_C}.d"]),
    (["rustc", "--crate-name", "ffi", "--crate-type=cdylib,staticlib", "--out-dir", "o"],
     ["o/libffi.so", "o/libffi.a"]),
    (["rustc", "--crate-name", "ffi", "--crate-type", "cdylib", "--target", "x86_64-pc-windows-msvc",
      "--out-dir", "o"], ["o/ffi.dll"]),
    (["rustc", "--crate-name", "tool", "src/main.rs", "-o", "/workspace/bin/tool"], ["/workspace/bin/tool"]),
    (["rustc", "-vV"], []),
    (["rustc", "--crate-name", "check_only", "--crate-type", "lib", "--emit=metadata",
      "--out-dir", "o"], ["o/libcheck_only.rmeta"]),
])
def test_rustc_outputs_follow_crate_name_type_emit_and_extra_filename(argv: list[str], expected: list[str]) -> None:
    assert rust.rustc_outputs(argv) == expected


def test_captured_rustc_execs_name_their_outputs_and_their_producing_command(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _cargo_workspace(workspace)
    toolchain = "/usr/local/rustup/toolchains/stable/bin/rustc"
    deps = "/workspace/target/debug/deps"
    common = ["--emit=dep-info,metadata,link", "--out-dir", deps]
    capture = Capture([
        _exec(1, toolchain, ["rustc", "-vV"]),
        _chdir(2, "/workspace/crates/core_lib"),
        _exec(3, toolchain, ["rustc", "--crate-name", "core_lib", "src/lib.rs", "--crate-type", "lib",
                             *common, "-C", f"extra-filename=-{HASH_A}"]),
        _exec(4, toolchain, ["rustc", "--crate-name", "macros", "src/lib.rs", "--crate-type", "proc-macro",
                             "--emit=dep-info,link", "--out-dir", deps, "-C", f"extra-filename=-{HASH_B}"]),
        _exec(5, toolchain, ["rustc", "--crate-name", "app", "src/main.rs", "--crate-type", "bin",
                             "--emit=dep-info,link", "--out-dir", deps, "-C", f"extra-filename=-{HASH_C}"]),
    ])
    result = reconcile_captured_build([(2, capture)], workspace, ".", rust.CAPTURE_DESCRIPTOR)
    rows = [dict(row) for row in result.rows]
    _attribute_captured_rows(rows, [{"ordinal": 1, "command_id": "metadata"},
                                    {"ordinal": 2, "command_id": "cargo-build"}])
    assert {row["parent_command_id"] for row in rows} == {"cargo-build"}

    named = {item["workspace_path"]: item for row in rows for item in row["outputs"] if item.get("sha256")}
    for relative in (f"target/debug/deps/libcore_lib-{HASH_A}.rlib",
                     f"target/debug/deps/libcore_lib-{HASH_A}.rmeta",
                     f"target/debug/deps/libmacros-{HASH_B}.so",
                     f"target/debug/deps/app-{HASH_C}"):
        assert named[relative]["sha256"] == file_sha256(workspace / relative), relative
    # The uplifted copy is named only because its bytes are identical to rustc's output.
    assert "target/debug/app" not in named  # A stale copy with different bytes is not rustc's.
    shutil.copyfile(workspace / f"target/debug/deps/app-{HASH_C}", workspace / "target/debug/app")
    _write(workspace, "target/debug/libmacros.so", b"different bytes")
    rows = [dict(row) for row in reconcile_captured_build(
        [(2, capture)], workspace, ".", rust.CAPTURE_DESCRIPTOR).rows]
    uplifts = {item["workspace_path"]: item["mapping"] for row in rows for item in row["outputs"]
               if item.get("mapping") == "cargo-uplift-identical-digest"}
    assert uplifts == {"target/debug/app": "cargo-uplift-identical-digest"}


def test_captured_relative_outputs_resolve_against_the_process_working_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _cmake_project(workspace)
    from appsec_review.jobs.job_language_build import native
    capture = Capture([
        _chdir(1, "/workspace/build"),
        _exec(2, "/usr/bin/cc", ["cc", "-c", "../src/main.c", "-o", "CMakeFiles/app.dir/src/main.c.o"]),
    ])
    rows = reconcile_captured_build([(1, capture)], workspace, ".", native.CAPTURE_DESCRIPTOR).rows
    assert [item["workspace_path"] for item in rows[0]["outputs"]] == ["build/CMakeFiles/app.dir/src/main.c.o"]
    assert rows[0]["outputs"][0]["mapping_confidence"] == 1.0


# --- javac outputs -----------------------------------------------------------------------------

_MAIN = """// package wrong.comment;
/* class Decoy {} */
package com.example.app;

import java.util.function.Supplier;

public class Main {
    static class Inner { class Deeper {} }
    Supplier<String> supplier = new Supplier<>() { public String get() { return "class Fake {"; } };
}

final class Helper {}
"""
_UTIL = "package com.example.util;\n\npublic interface Codec { enum Mode { A } }\n"


def _javac_tree(workspace: Path) -> None:
    _write(workspace, "module/src/main/java/com/example/app/Main.java", _MAIN)
    _write(workspace, "module/src/main/java/com/example/util/Codec.java", _UTIL)
    _write(workspace, "module/src/main/java/com/example/app/package-info.java",
           "@Deprecated\npackage com.example.app;\n")
    classes = "module/target/classes"
    for name in ("app/Main.class", "app/Main$1.class", "app/Main$Inner.class", "app/Main$Inner$Deeper.class",
                 "app/Helper.class", "app/package-info.class", "util/Codec.class", "util/Codec$Mode.class",
                 # Written by something other than javac: it must stay unattributed.
                 "app/Orphan.class", "app/MainHelper.class"):
        _write(workspace, f"{classes}/com/example/{name}", b"\xca\xfe\xba\xbe" + name.encode())


def _record(tool: str, parent: str, *arguments: str) -> list[str]:
    return [tool, parent, str(len(arguments)), *arguments]


def _trace(path: Path, *records: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(field.encode() + b"\0" for record in records for field in record))
    return path


EXPECTED_CLASSES = {f"module/target/classes/com/example/{name}" for name in (
    "app/Main.class", "app/Main$1.class", "app/Main$Inner.class", "app/Main$Inner$Deeper.class",
    "app/Helper.class", "app/package-info.class", "util/Codec.class", "util/Codec$Mode.class")}


def test_javac_maps_package_inner_and_anonymous_classes_from_direct_arguments(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _javac_tree(workspace)
    trace = _trace(tmp_path / "trace.bin", _record(
        "javac", "mvn-compile", "-encoding", "UTF-8", "-classpath", "lib/a.jar", "-d", "target/classes",
        "src/main/java/com/example/app/Main.java", "src/main/java/com/example/util/Codec.java",
        "src/main/java/com/example/app/package-info.java"))
    rows, gaps = jvm._trace_rows(trace, workspace, 100, 1 << 20, "module")
    assert gaps == []
    classes = {item["workspace_path"] for item in rows[0]["outputs"] if item.get("mapping") == "javac-derived-class"}
    assert classes == EXPECTED_CLASSES
    assert all(item["sha256"] == file_sha256(workspace / item["workspace_path"])
               for item in rows[0]["outputs"] if item.get("sha256"))


def test_javac_argfile_is_expanded_and_its_contents_stay_protected(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _javac_tree(workspace)
    argfile = "/workspace/module/target/org.codehaus.plexus.compiler.javac.JavacCompiler123arguments"
    contents = ('# generated by the compiler plugin\n"-d"\n"/workspace/module/target/classes"\n'
                '-classpath "/workspace/module/lib/a b.jar"\n'
                '"/workspace/module/src/main/java/com/example/app/Main.java"\n'
                "'/workspace/module/src/main/java/com/example/util/Codec.java'\n"
                "/workspace/module/src/main/java/com/example/app/package-info.java\n")
    trace = _trace(tmp_path / "trace.bin",
                   _record("javac", "mvn-compile", f"@{argfile}"),
                   _record("@argfile", "mvn-compile", argfile, "/workspace/module", contents),
                   _record("jar", "mvn-package", "cf", "target/app.jar", "target/classes"))
    rows, gaps = jvm._trace_rows(trace, workspace, 100, 1 << 20, "module")
    assert gaps == [] and [row["tool"] for row in rows] == ["javac", "jar"]
    assert [row["ordinal"] for row in rows] == [1, 2]
    classes = {item["workspace_path"] for item in rows[0]["outputs"] if item.get("mapping") == "javac-derived-class"}
    assert classes == EXPECTED_CLASSES
    assert rows[0]["argfiles"][0]["arguments"][:4] == [
        "-d", "/workspace/module/target/classes", "-classpath", "/workspace/module/lib/a b.jar"]


def test_unrecorded_argfile_and_unreadable_source_leave_classes_unattributed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _javac_tree(workspace)
    trace = _trace(tmp_path / "trace.bin",
                   _record("javac", "mvn-compile", "@/workspace/module/target/missing-args"),
                   _record("javac", "mvn-compile", "-d", "target/classes", "src/main/java/Gone.java"))
    rows, gaps = jvm._trace_rows(trace, workspace, 100, 1 << 20, "module")
    assert gaps == ["javac argfile contents were not recorded: /workspace/module/target/missing-args"]
    assert not [item for row in rows for item in row["outputs"] if item.get("mapping") == "javac-derived-class"]
    assert rows[1]["class_mapping_gaps"] == [
        "javac source was unreadable; its class outputs were not mapped: module/src/main/java/Gone.java"]


def test_argfile_record_without_its_invocation_is_a_gap(tmp_path: Path) -> None:
    trace = _trace(tmp_path / "trace.bin", _record("@argfile", "p", "/workspace/a", "/workspace", "-d x"))
    rows, gaps = jvm._trace_rows(trace, tmp_path, 100, 1 << 20, ".")
    assert rows == [] and gaps == ["JVM argfile record did not follow the invocation that named it"]


@pytest.mark.skipif(shutil.which("sh") is None or shutil.which("head") is None or shutil.which("tr") is None,
                    reason="the JVM wrapper needs a POSIX shell, head, and tr")
def test_jvm_wrapper_records_argfile_contents_beside_the_invocation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    _javac_tree(workspace)
    settings = {"tool_paths": {tool: shutil.which("true") or "/bin/true" for tool in jvm._TOOLS}}
    trace, _logical = jvm._instrumentation(workspace, "module", settings)
    argfile = workspace / "module" / "target" / "javac.args"
    argfile.write_text('-d "target/classes"\nsrc/main/java/com/example/app/Main.java\n', encoding="utf-8")
    environment = {**os.environ, "APPSEC_JVM_TRACE": str(trace), "APPSEC_JVM_PARENT_COMMAND": "cmd-1"}
    wrapper = trace.parent / "bin" / "javac"
    subprocess.run([str(wrapper), f"@{argfile}"], cwd=workspace / "module", env=environment, check=True)
    fields = trace.read_bytes().split(b"\0")
    assert fields[:4] == [b"javac", b"cmd-1", b"1", f"@{argfile}".encode()]
    assert fields[4:8] == [b"@argfile", b"cmd-1", b"3", str(argfile).encode()]
    assert fields[8] == str(workspace / "module").encode()
    assert fields[9] == argfile.read_bytes()
