from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review.config.build_workspaces import BuildWorkspacePolicy, parse_build_workspaces
from appsec_review.jobs.build_workspace import (
    BuildWorkspace, NodeBinding, ProductSpec, WorkspaceError,
)
from appsec_review.storage.lock import LockUnavailable


def binding(node: str = "A", upstreams: tuple[str, ...] = ()) -> NodeBinding:
    return NodeBinding(node, "pinned-source", "structural-topology", "release-config",
                       f"recipe-{node}", "sha256:prepared-image", "release-toolchain", upstreams,
                       "capture-contract", "expected-products")


def product(path: str, kind: str) -> ProductSpec:
    return ProductSpec(path, kind, path, f"test:{path}",
                       {"configuration": "release", "target_arch": "x86_64", "execution_role": "target",
                        "linkage": "shared", "toolchain": "release-toolchain", "abi": "test-abi"})


def make_workspace(tmp_path: Path, name: str = "run-1") -> tuple[BuildWorkspace, Path, str]:
    source = tmp_path / "source"
    if not source.exists():
        (source / "gtest" / "make").mkdir(parents=True)
        (source / "gtest" / "scripts" / "test").mkdir(parents=True)
        (source / "gtest" / "samples").mkdir()
        (source / "gtest" / "samples" / "sample1.cc").write_bytes(b"int main() { return 0; }\n")
        (source / "make.conf").write_bytes(b"CC=cc\n")
    run = tmp_path / "runs" / name
    run.mkdir(parents=True)
    workspace = BuildWorkspace(run)
    generation = workspace.materialize(source, "pinned-source")
    return workspace, source, generation


def build_a(workspace: BuildWorkspace, generation: str):
    with workspace.writer() as writer:
        writer.begin_attempt(binding(), "A-attempt-1", generation)
        install = writer.paths.install
        (install / "lib").mkdir()
        library = install / "lib" / "liba.so.1.2"
        library.write_bytes(b"verified-A-library")
        library.chmod(0o755)
        (install / "lib" / "liba.so.1").symlink_to("liba.so.1.2")
        (install / "lib" / "liba.so").symlink_to("liba.so.1")
        (install / "a.h").write_bytes(b"int a(void);\n")
        (writer.paths.target / "make.conf").write_bytes(b"CC=prepared-cc\n")
        (writer.paths.target / "generated.h").write_bytes(b"#define A 1\n")
        (writer.paths.target / "removed-by-A").write_bytes(b"temporary")
        (writer.paths.target / "removed-by-A").unlink()
        record = writer.commit([product("install/lib/liba.so", "library"),
                                product("install/a.h", "headers")])
        return record, writer.state()["generation"]


def test_full_target_relative_layout_and_original_bytes_unchanged(tmp_path):
    source = tmp_path / "source"
    for folder in ("gtest/make", "gtest/scripts/test", "gtest/samples", "build", "bin", "obj", "target"):
        (source / folder).mkdir(parents=True, exist_ok=True)
    sample = source / "gtest" / "samples" / "sample1.cc"
    sample.write_bytes(b"int main(){}\n")
    for folder in ("build", "bin", "obj", "target"):
        (source / folder / "checked-in").write_bytes(folder.encode())
    (source / "make.conf").write_bytes(b"keep-original\r\n")
    (source / ".git").write_text("gitdir: /host/private-metadata\n")
    (source / "sample-link").symlink_to("gtest/samples/sample1.cc")
    original = {p.relative_to(source).as_posix(): p.read_bytes()
                for p in source.rglob("*") if p.is_file()}
    run = tmp_path / "runs" / "one"
    run.mkdir(parents=True)
    workspace = BuildWorkspace(run)
    workspace.materialize(source, "source-revision")
    target = workspace.paths.target
    assert (target / "gtest/make/../samples/sample1.cc").read_bytes() == sample.read_bytes()
    assert (target / "gtest/scripts/test/../../samples/sample1.cc").read_bytes() == sample.read_bytes()
    for folder in ("build", "bin", "obj", "target"):
        assert (target / folder / "checked-in").read_bytes() == folder.encode()
    assert (target / "sample-link").is_symlink()
    assert not (target / ".git").exists()
    (target / "make.conf").write_bytes(b"mutable-copy")
    assert {p.relative_to(source).as_posix(): p.read_bytes()
            for p in source.rglob("*") if p.is_file()} == original
    assert workspace.paths.target_container == "/workspace"
    assert workspace.paths.install_container == "/install"
    assert product("target/generator", "executable").container_path == "/workspace/generator"


@pytest.mark.parametrize("link", ["../private", "/etc/passwd", "missing", "loop"])
def test_source_symlink_escape_broken_or_cycle_refused(tmp_path, link):
    source = tmp_path / "source"
    source.mkdir()
    (tmp_path / "private").write_bytes(b"not-reviewed")
    (source / "loop").symlink_to(link)
    run = tmp_path / "runs" / "one"
    run.mkdir(parents=True)
    workspace = BuildWorkspace(run)
    with pytest.raises(WorkspaceError, match="symlink"):
        workspace.materialize(source, "source")
    assert not workspace.root.exists()


def test_materialize_once_and_no_overlapping_target(tmp_path):
    workspace, source, _ = make_workspace(tmp_path)
    with pytest.raises(WorkspaceError, match="already exists"):
        workspace.materialize(source, "pinned-source")
    with pytest.raises(WorkspaceError, match="disjoint"):
        workspace.materialize(workspace.run_dir, "pinned-source")


def test_writer_is_exclusive_and_cannot_outlive_claim(tmp_path):
    workspace, _, _ = make_workspace(tmp_path)
    with workspace.writer() as writer:
        with pytest.raises(LockUnavailable):
            with workspace.writer():
                pytest.fail("second writer acquired the shared tree")
        assert writer.state()["condition"] == "clean"
    with pytest.raises(WorkspaceError, match="released"):
        writer.state()


@pytest.mark.parametrize("field", [
    "source_identity", "graph_identity", "configuration_identity", "recipe_identity",
    "image_identity", "toolchain_identity", "execution_identity", "output_policy_identity",
])
def test_incomplete_binding_fails_closed(field):
    with pytest.raises(ValueError, match=field):
        replace(binding(), **{field: ""})


@pytest.mark.parametrize("value", [True, -1, 10001, "3", 3.0])
def test_retention_rejects_bad_types_and_range(value):
    with pytest.raises(ValueError, match="integer"):
        parse_build_workspaces({"build_workspace_retention_runs": value})


def test_retention_defaults_disable_and_unknown_fields():
    assert parse_build_workspaces(None) == BuildWorkspacePolicy(3)
    assert parse_build_workspaces({"build_workspace_retention_runs": 0}).view() == {
        "build_workspace_retention_runs": 0}
    with pytest.raises(ValueError, match="unknown"):
        parse_build_workspaces({"retention": 3})
    with pytest.raises(ValueError, match="table"):
        parse_build_workspaces([])
