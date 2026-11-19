"""Physical native product roles survive both commit and content-addressed rereads."""
from __future__ import annotations

import struct
from dataclasses import replace

import pytest

from appsec_review.jobs.build_workspace import (
    BuildWorkspace, NodeBinding, ProductSpec, WorkspaceError,
    verify_native_product, verify_retained_product,
)
from tests.unit.job_build_iteration.support import NATIVE_AXES, NATIVE_OBJECT, NATIVE_OUTPUT, VARIANT


def _archive(member):
    header = (f"{'control.o/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(member):<10}`\n").encode()
    return b"!<arch>\n" + header + member + (b"\n" if len(member) % 2 else b"")


def _bytes(role):
    if role == "static_archive":
        return _archive(NATIVE_OBJECT)
    if role == "import_library":
        return _archive(struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x8664, 0, 4, 0, 0) + b"x\0y\0")
    if role == "native_object":
        return NATIVE_OBJECT
    if role == "runtime_shared":
        data = bytearray(NATIVE_OBJECT)
        struct.pack_into("<H", data, 16, 3)
        return bytes(data)
    return NATIVE_OUTPUT


def _spec(role):
    kinds = {"static_archive": "library", "import_library": "library", "runtime_shared": "library",
             "executable": "executable", "native_object": "generated_source"}
    return ProductSpec("target/libcontrol.so" if role == "runtime_shared" else "target/control.bin",
                       kinds[role], "control", "native:control", VARIANT, role, NATIVE_AXES)


@pytest.mark.parametrize("role,actual", [
    ("static_archive", "executable"), ("import_library", "executable"),
    ("runtime_shared", "executable"), ("executable", "native_object"),
    ("native_object", "executable"), ("static_archive", "runtime_shared"),
])
def test_native_product_rejects_mismatched_physical_role(tmp_path, role, actual):
    path = tmp_path / "misleading.a"
    path.write_bytes(_bytes(actual))
    with pytest.raises(WorkspaceError, match="role"):
        verify_native_product(path, _spec(role))


@pytest.mark.parametrize("role", [
    "executable", "import_library", "native_object", "runtime_shared", "static_archive",
])
def test_native_product_commit_and_retained_reread_preserve_physical_role(tmp_path, role):
    run = tmp_path / "run"
    run.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    (source / "source.c").write_text("int control;")
    workspace = BuildWorkspace(run)
    workspace.materialize(source, "source")
    binding = NodeBinding("control", "source", "graph", "config", "recipe", "image", "toolchain",
                          (), "execution", "outputs")
    spec = _spec(role)
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "attempt", writer.state()["generation"])
        (workspace.paths.target / spec.path.removeprefix("target/")).write_bytes(_bytes(role))
        product = writer.commit([spec])
        retained = verify_retained_product(run, writer.state()["generation"], product.reference, binding)
        assert retained["products"][0]["role"] == role
        assert retained["binding"] == binding.view()


def test_static_archive_cannot_hide_linked_executable_as_member(tmp_path):
    path = tmp_path / "control.a"
    path.write_bytes(_archive(NATIVE_OUTPUT))
    with pytest.raises(WorkspaceError, match="(role|object)"):
        verify_native_product(path, _spec("static_archive"))


def test_rejected_role_cannot_be_committed(tmp_path):
    from tests.test_native_target_enforcement import _retained_native
    _, workspace, binding, spec = _retained_native(tmp_path)
    spec = replace(spec, kind="library", role="static_archive")
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "wrong-role", writer.state()["generation"])
        (workspace.paths.target / "control.o").write_bytes(NATIVE_OUTPUT)
        with pytest.raises(WorkspaceError, match="role"):
            writer.commit([spec])
        assert writer.committed_generation()["accepted"] == {}
        writer.fail_attempt("synthetic wrong-role product")


@pytest.mark.parametrize("container,role", [
    ("pe", "executable"), ("pe", "runtime_shared"),
    ("macho", "executable"), ("macho", "runtime_shared"), ("macho", "native_object"),
    ("coff", "native_object"),
])
def test_native_roles_keep_supported_pe_macho_and_coff_headers(tmp_path, container, role):
    if container == "pe":
        data = bytearray(256)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 128)
        data[128:132] = b"PE\0\0"
        struct.pack_into("<H", data, 132, 0x8664)
        struct.pack_into("<H", data, 150, 0x2000 if role == "runtime_shared" else 0)
        struct.pack_into("<H", data, 152, 0x20B)
    elif container == "macho":
        data = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x01000007, 3,
                           {"executable": 2, "runtime_shared": 6, "native_object": 1}[role], 0, 0, 0, 0)
    else:
        data = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0)
    path = tmp_path / "misleading.a"
    path.write_bytes(data)
    verify_native_product(path, _spec(role))
    with pytest.raises(WorkspaceError, match="role"):
        verify_native_product(path, _spec("native_object" if role == "executable" else "executable"))
