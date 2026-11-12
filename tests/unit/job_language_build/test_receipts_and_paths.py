"""job_language_build: the pure receipt builders, path mappers and stream retention helpers of
job.py, and the consumer-side reader of the accepted language-build handoff, against fixtures each
test writes. Nothing here runs a build."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_language_build.job import (
    EXECUTOR_IDENTITY, RECEIPT_SCHEMA, SCHEMA, _attribute_captured_rows, _copy_source, _dotnet_argv,
    _has_build_output, _interface_environment, _kind, _mapped_files, _normalized_links, _snapshot,
    _stream_artifact, _workspace_path, load_accepted_language_build, upstream_build_failure_receipt,
)
from appsec_review.runtime import consume
from appsec_review.storage import canonical_json, file_sha256


# --- receipts ----------------------------------------------------------------------------------------

def test_upstream_build_failure_receipt_names_the_unit_the_failing_job_and_the_first_reason() -> None:
    probe = {"build_unit_id": "build-unit-" + "a" * 20, "family": "go", "root": "svc", "build_system": "go",
             "terminal_status": "FAILED", "gaps": ["build-unit-" + "a" * 20 + ": build-unit-" + "a" * 20 + ": go build exited 2",
                                                  "second reason"]}
    receipt = upstream_build_failure_receipt(probe, {"project_build_handoff_sha256": "6" * 64})
    assert receipt["schema"] == RECEIPT_SCHEMA and receipt["terminal_status"] == "BLOCKED"
    assert receipt["upstream_failure"] == {"job_id": "job_project_build", "terminal_status": "FAILED",
                                           "reason": "go build exited 2"}
    assert receipt["gaps"] == ["go build unit at svc was not built: job_project_build reported FAILED: go build exited 2"]
    assert receipt["upstream_handoff_sha256"] == "6" * 64 and receipt["workspace"] is None
    assert (receipt["artifacts"], receipt["commands"], receipt["processing_decisions"]) == ([], [], [])
    bare = upstream_build_failure_receipt({"build_unit_id": "build-unit-" + "b" * 20, "family": "native"}, {})
    assert bare["upstream_failure"] == {"job_id": "job_project_build", "terminal_status": "UNKNOWN",
                                        "reason": "no reason recorded"}
    assert bare["root"] == "." and bare["upstream_handoff_sha256"] is None


def test_has_build_output_ignores_retained_accepted_inputs() -> None:
    assert _has_build_output({"artifacts": [{"workspace_path": "a.o", "artifact_origin": "accepted-input"},
                                            {"workspace_path": "app", "artifact_origin": "build-output"}]}) is True
    assert _has_build_output({"artifacts": [{"workspace_path": "a.o", "artifact_origin": "accepted-input"}]}) is False
    assert _has_build_output({"artifacts": ["not-a-mapping"]}) is False and _has_build_output({}) is False


# --- argv and environment ---------------------------------------------------------------------------

@pytest.mark.parametrize(("argv", "expected"), [
    (("dotnet", "build", "app.csproj"), ("dotnet", "build", "app.csproj", "--verbosity", "diagnostic")),
    (("dotnet", "publish", "-c", "Release"), ("dotnet", "publish", "-c", "Release", "--verbosity", "diagnostic")),
    (("dotnet", "build", "-v:q"), ("dotnet", "build", "-v:q")),
    (("dotnet", "build", "--verbosity", "minimal"), ("dotnet", "build", "--verbosity", "minimal")),
    (("dotnet", "restore", "app.csproj"), ("dotnet", "restore", "app.csproj")),
    (("/usr/bin/MSBuild", "app.sln"), ("/usr/bin/MSBuild", "app.sln", "/v:diag")),
    (("msbuild", "app.sln", "-v:diag"), ("msbuild", "app.sln", "-v:diag")),
    (("make",), ("make",)), ((), ()),
], ids=["build", "publish", "short-verbosity", "long-verbosity", "restore", "msbuild", "msbuild-set", "other", "empty"])
def test_dotnet_argv_forces_diagnostic_verbosity_on_build_verbs_only(argv, expected) -> None:
    assert _dotnet_argv(argv) == expected


def test_interface_environment_exposes_product_directories_ahead_of_the_image_defaults() -> None:
    interfaces = [{"path": "/install/lib/libfoo.so", "kind": "library"},
                  {"path": "/install/include", "kind": "headers"},
                  {"path": "/install/include/foo.h", "kind": "headers"},
                  {"path": "/install/bin/foo", "kind": "executable"},
                  {"path": "/install/lib/pkgconfig/foo.pc", "kind": "package_metadata"},
                  {"path": "/install/share/doc", "kind": "documentation"}]
    env = _interface_environment(interfaces, {"PATH": "/usr/bin", "CPATH": "/opt/include"})
    assert env == {"LIBRARY_PATH": "/install/lib", "CPATH": "/install/include:/opt/include",
                   "PATH": "/install/bin:/usr/bin", "PKG_CONFIG_PATH": "/install/lib/pkgconfig",
                   "CMAKE_PREFIX_PATH": "/install"}
    default_path = _interface_environment([{"path": "/products/bin/tool", "kind": "executable"}], {})
    assert default_path == {"PATH": "/products/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    assert _interface_environment([], {"PATH": "/usr/bin"}) == {}


# --- captured rows and links -------------------------------------------------------------------------

def test_captured_rows_are_attributed_to_the_protected_command_of_their_capture_ordinal() -> None:
    commands = [{"command_id": "cmd-1", "ordinal": 1}, {"command_id": "cmd-2", "ordinal": 2},
                {"command_id": "", "ordinal": 3}, {"command_id": "cmd-4", "ordinal": "4"}, "junk"]
    rows = [{"origin": "execution-capture:command-2:event-7"}, {"origin": "execution-capture:command-1"},
            {"origin": "execution-capture:command-9"}, {"origin": "compile-database"},
            {"origin": "execution-capture:command-2", "parent_command_id": "kept"},
            {"origin": "execution-capture:command-3"}, {"origin": "execution-capture:command-4"},
            {"origin": "execution-capture:command-10:x"}]
    _attribute_captured_rows(rows, commands)
    assert [row.get("parent_command_id") for row in rows] == ["cmd-2", "cmd-1", None, None, "kept", None, None, None]


def test_normalized_links_keep_single_output_rows_inside_the_build_directory() -> None:
    rows = [{"argv": ["ld", "a.o", "b.o", "-o", "app"], "origin": "capture:1",
             "outputs": [{"workspace_path": "out/app"}], "inputs": [{"workspace_path": "out/b.o"}, {"workspace_path": "out/a.o"},
                                                                     {"workspace_path": "out/b.o"}, {"workspace_path": "src/x.c"}]},
            {"argv": ["ld"], "origin": "capture:2", "outputs": [{"workspace_path": "out/a"}, {"workspace_path": "out/b"}],
             "inputs": [{"workspace_path": "out/a.o"}]},
            {"argv": ["ld"], "origin": "capture:3", "outputs": [{"workspace_path": "out/c"}], "inputs": []},
            {"argv": ["ar"], "origin": "capture:4", "outputs": [{"workspace_path": "out"}], "inputs": [{"workspace_path": "out/d.o"}]}]
    links = _normalized_links(rows, "./out/")
    assert links == [
        {"output_path": "build/app", "input_paths": ["build/a.o", "build/b.o"], "receipt": "capture:1",
         "command_sha256": hashlib.sha256(canonical_json(["ld", "a.o", "b.o", "-o", "app"])).hexdigest()},
        {"output_path": "build", "input_paths": ["build/d.o"], "receipt": "capture:4",
         "command_sha256": hashlib.sha256(canonical_json(["ar"])).hexdigest()}]


# --- workspace paths ----------------------------------------------------------------------------------

def test_workspace_path_maps_container_host_and_relative_paths_into_the_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "build").mkdir(parents=True)
    host = workspace.resolve()
    assert _workspace_path(workspace, "/workspace", "/workspace") == host
    assert _workspace_path(workspace, "/workspace", "/workspace/build/app.o") == host / "build" / "app.o"
    assert _workspace_path(workspace, "/workspace/build", "app.o") == host / "build" / "app.o"
    assert _workspace_path(workspace, "/workspace", str(host / "build" / "y")) == host / "build" / "y"
    for directory, value in (("/workspace", "../escape"), ("/workspace", "build/../build/x"),
                             ("/workspace", "/etc/passwd"), ("/opt", "x"),
                             ("/workspace", str(tmp_path / "outside")), ("/workspace", ""), ("/workspace", 7),
                             ("/workspace", "a\0b")):
        assert _workspace_path(workspace, directory, value) is None, (directory, value)


def test_mapped_files_hash_existing_regular_files_and_mark_unresolved_declared_paths(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "build").mkdir(parents=True)
    (workspace / "build" / "app.o").write_bytes(b"obj")
    rows = _mapped_files(workspace, "/workspace", ["build/app.o", "build/missing.o", "/etc/passwd", "../x"])
    assert rows == [
        {"workspace_path": "build/app.o", "sha256": file_sha256(workspace / "build" / "app.o"), "size_bytes": 3,
         "mapping": "exact-workspace-path", "mapping_confidence": 1.0},
        {"workspace_path": "build/missing.o", "mapping": "declared-path-unresolved", "mapping_confidence": 0.5}]


def test_snapshot_hashes_regular_files_skips_symlinks_and_bounds_the_count(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("b", encoding="utf-8")
    (tmp_path / "link.txt").symlink_to(tmp_path / "a.txt")
    snapshot = _snapshot(tmp_path, 10)
    assert snapshot == {"a.txt": file_sha256(tmp_path / "a.txt"), "sub/b.txt": file_sha256(tmp_path / "sub" / "b.txt")}
    with pytest.raises(ValueError, match="workspace file-count bound exceeded"):
        _snapshot(tmp_path, 1)


@pytest.mark.parametrize(("relative", "family", "expected"), [
    ("build/compile_commands.json", "native", "compile-database"),
    ("gen/parser.cc", "native", "generated-source"), ("gen/asm.s", "go", "generated-source"),
    ("out/mod.bc", "native", "llvm-bitcode"), ("out/x.ast", "native", "clang-ast"),
    ("out/app.pdb", "native", "debug-information"), ("out/app.map", "native", "link-map"),
    ("out/app.o", "native", "object"), ("out/libx.a", "native", "static-library"),
    ("out/libx.so", "native", "shared-library"), ("out/libx.dylib", "go", "shared-library"),
    ("README.md", "native", None), ("coverage.xml", "native", "test-coverage"),
    ("profiles/hot.folded", "go", "execution-profile"),
], ids=["compile-db", "cc", "asm", "bitcode", "ast", "pdb", "map", "object", "static", "shared", "dylib", "doc",
        "coverage", "profile"])
def test_kind_classifies_native_and_go_outputs_by_suffix_when_the_header_is_not_a_binary(
        tmp_path: Path, relative, family, expected) -> None:
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"not an elf header")
    assert _kind(path, family, relative=relative) == expected


# --- streams ------------------------------------------------------------------------------------------

def test_stream_artifact_retains_the_preview_and_the_diagnostic_tail_when_truncated(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    path = run_root / "logs" / "001.stderr"
    result = SimpleNamespace(stderr=b"head", stderr_bytes=4096, stderr_truncated=True, stderr_tail=b"tail")
    value = _stream_artifact(run_root, path, result=result, stream="stderr", limit=4)
    assert value == {"path": "logs/001.stderr", "sha256": file_sha256(path), "byte_count": 4096,
                     "retained_byte_count": 4, "capture_limit": 4, "truncated": True,
                     "diagnostic_tail": {"path": "logs/001.stderr.tail", "sha256": file_sha256(path.with_name("001.stderr.tail")),
                                         "byte_count": 4}}
    assert path.read_bytes() == b"head" and path.with_name("001.stderr.tail").read_bytes() == b"tail"
    complete = _stream_artifact(run_root, run_root / "logs" / "002.stdout", result=SimpleNamespace(stdout=b"all"),
                                stream="stdout", limit=8)
    assert (complete["byte_count"], complete["retained_byte_count"], complete["truncated"]) == (3, 3, False)
    assert "diagnostic_tail" not in complete


# --- source copies --------------------------------------------------------------------------------------

def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    (target / "svc" / "src").mkdir(parents=True)
    (target / "svc" / "src" / "main.c").write_text("int main(){}", encoding="utf-8")
    (target / "svc" / ".git").mkdir()
    (target / "svc" / ".git" / "HEAD").write_text("ref", encoding="utf-8")
    (target / "shared" / "deps").mkdir(parents=True)
    (target / "shared" / "deps" / "lock.txt").write_text("pinned", encoding="utf-8")
    return target


def test_copy_source_copies_the_unit_root_without_vcs_metadata_and_retains_dependency_files(tmp_path: Path) -> None:
    target = _target(tmp_path)
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target))
    workspace = tmp_path / "ws"
    (workspace / "stale").mkdir(parents=True)
    recipe = {"source_dir": "svc", "build_dir": "svc/build", "dependency_files": ["shared/deps/lock.txt", "svc/src/main.c"]}
    _copy_source(unit, {"root": "svc", "recipe": recipe}, workspace)
    assert (workspace / "svc" / "src" / "main.c").read_text(encoding="utf-8") == "int main(){}"
    assert not (workspace / "svc" / ".git").exists() and not (workspace / "stale").exists()
    assert (workspace / "shared" / "deps" / "lock.txt").read_text(encoding="utf-8") == "pinned"
    assert (workspace / "svc" / "build").is_dir(), "the declared build directory is created"
    whole = tmp_path / "whole"
    _copy_source(unit, {"root": ".", "recipe": {"source_dir": ".", "build_dir": "build", "dependency_files": []}}, whole)
    assert (whole / "svc" / "src" / "main.c").is_file() and (whole / "shared" / "deps" / "lock.txt").is_file()


def test_copy_source_refuses_symlinked_sources_and_dependency_files_outside_the_target(tmp_path: Path) -> None:
    target = _target(tmp_path)
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target))
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    recipe = {"source_dir": "svc", "build_dir": "svc/build", "dependency_files": ["../outside.txt"]}
    with pytest.raises((ValueError, FileNotFoundError)):
        _copy_source(unit, {"root": "svc", "recipe": recipe}, tmp_path / "ws1")
    (target / "svc" / "link").symlink_to(outside)
    with pytest.raises(ValueError, match="unsupported symlink"):
        _copy_source(unit, {"root": "svc", "recipe": {**recipe, "dependency_files": []}}, tmp_path / "ws2")


# --- the consumer-side reader -------------------------------------------------------------------------

def _published(tmp_path: Path, document: dict, monkeypatch) -> Path:
    run_root = tmp_path / "run"
    path = run_root / "data/jobs/job_language_build/attempts/attempt_0001/artifacts/language-build/accepted-language-builds.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    identity = {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path)}
    handoff = {"outputs": {"acceptance.publish_handoff": {"artifact": identity}}}
    monkeypatch.setattr(consume, "accepted_upstream", lambda root, job_id: SimpleNamespace(
        job_id=job_id, handoff=handoff, sha256="h" * 64, path="x", pinned=True))
    return run_root


def test_load_accepted_language_build_returns_the_verified_document_with_its_handoff_identity(
        tmp_path: Path, monkeypatch) -> None:
    document = {"schema": SCHEMA, "receipts": [{"build_unit_id": "build-unit-" + "a" * 20, "terminal_status": "FAILED"}],
                "gaps": ["x"]}
    run_root = _published(tmp_path, document, monkeypatch)
    loaded = load_accepted_language_build(run_root)
    assert loaded == {**document, "language_build_handoff_sha256": "h" * 64}
    with pytest.raises(ValueError, match="execution reader mode must be explicit"):
        load_accepted_language_build(run_root, for_execution=1)


def test_load_accepted_language_build_refuses_a_changed_or_foreign_document(tmp_path: Path, monkeypatch) -> None:
    run_root = _published(tmp_path, {"schema": "appsec-review/other/1", "receipts": []}, monkeypatch)
    with pytest.raises(ValueError, match="schema is unsupported"):
        load_accepted_language_build(run_root)
    run_root = _published(tmp_path / "second", {"schema": SCHEMA, "receipts": []}, monkeypatch)
    artifact = next((run_root / "data").rglob("accepted-language-builds.json"))
    artifact.write_text(json.dumps({"schema": SCHEMA, "receipts": [], "extra": 1}), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact identity changed"):
        load_accepted_language_build(run_root)
    monkeypatch.setattr(consume, "accepted_upstream", lambda root, job_id: SimpleNamespace(
        handoff={"outputs": {"acceptance.publish_handoff": {}}}, sha256="h" * 64))
    with pytest.raises(ValueError, match="does not publish its receipt set"):
        load_accepted_language_build(run_root)


def test_executor_identity_binds_the_delivery_policy() -> None:
    from appsec_review.jobs.delivery_scope import POLICY_IDENTITY
    assert EXECUTOR_IDENTITY == "appsec-review/generic-language-build-executor/4+" + POLICY_IDENTITY
