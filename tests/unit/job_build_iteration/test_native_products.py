"""Physical native product roles survive both commit and content-addressed rereads."""
from __future__ import annotations

import struct
from dataclasses import asdict, replace

import pytest

from appsec_review.jobs.build_workspace import (
    BuildWorkspace, NodeBinding, ProductSpec, WorkspaceError,
    verify_native_product, verify_retained_product,
)
from tests.unit.job_build_iteration.support import NATIVE_AXES, NATIVE_OBJECT, NATIVE_OUTPUT, VARIANT


def _archive(member):
    header = (f"{'control.o/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(member):<10}`\n").encode()
    return b"!<arch>\n" + header + member + (b"\n" if len(member) % 2 else b"")


def _dynamic_elf(case="shared", *, bits=64, order="<"):
    wide = bits == 64
    header_size, program_size, dynamic_size = (64, 56, 16) if wide else (52, 32, 8)
    phoff = 8192 if case in {"late-interpreter", "truncated-programs"} else header_size
    count = 0 if case == "missing-programs" else 65 if case == "many-programs" else 1
    data = bytearray(max(544, phoff + count * program_size))
    data[:7] = b"\x7fELF" + bytes((2 if wide else 1, 1 if order == "<" else 2, 1))
    struct.pack_into(order + "HHI", data, 16, 3, 62 if wide else 3, 1)
    entry = 0x1000 if case in {"static-pie", "unknown-entry"} else 0
    struct.pack_into(order + ("QQ" if wide else "II"), data, 24, entry, phoff)
    struct.pack_into(order + "HHH", data, 52 if wide else 40, header_size, program_size, count)
    dynamic_offset = 512
    dynamic_length = dynamic_size * 2
    if case == "many-dynamic-tags":
        dynamic_length = 4097 * dynamic_size
        data.extend(bytes(dynamic_offset + dynamic_length - len(data)))
    if count:
        if wide:
            struct.pack_into(order + "IIQQQQQQ", data, phoff, 3 if case == "late-interpreter" else 2,
                             0, dynamic_offset, 0, 0, dynamic_length, dynamic_length, 8)
        else:
            struct.pack_into(order + "IIIIIIII", data, phoff, 2, dynamic_offset, 0, 0,
                             dynamic_length, dynamic_length, 0, 4)
    tag_format = order + ("QQ" if wide else "II")
    struct.pack_into(tag_format, data, dynamic_offset, 0x6FFFFFFB, 0x08000000 if case == "static-pie" else 0)
    struct.pack_into(tag_format, data, dynamic_offset + dynamic_size, 1 if case == "unterminated" else 0, 0)
    if case == "truncated-programs":
        return bytes(data[:header_size])
    if case == "truncated-dynamic":
        return bytes(data[:dynamic_offset + dynamic_size])
    return bytes(data)


def _bytes(role):
    if role == "static_archive":
        return _archive(NATIVE_OBJECT)
    if role == "import_library":
        return _archive(struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x8664, 0, 4, 0, 0) + b"x\0y\0")
    if role == "native_object":
        return NATIVE_OBJECT
    if role == "runtime_shared":
        return _dynamic_elf()
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


@pytest.mark.parametrize("case", [
    "late-interpreter", "static-pie", "truncated-programs", "truncated-dynamic",
    "unterminated", "missing-programs", "unknown-entry", "many-programs", "many-dynamic-tags",
])
@pytest.mark.parametrize("boundary", ["commit", "retained"])
def test_elf_shared_admission_requires_complete_non_executable_byte_evidence(tmp_path, case, boundary):
    from appsec_review.jobs.build_workspace import _immutable
    from appsec_review.storage.atomic import canonical_json_sha256
    from tests.test_native_target_enforcement import _retained_native

    root, workspace, binding, _ = _retained_native(tmp_path)
    spec = _spec("runtime_shared")
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "role-check", writer.state()["generation"])
        (workspace.paths.target / "libcontrol.so").write_bytes(_dynamic_elf(case))
        if boundary == "commit":
            with pytest.raises(WorkspaceError, match="role"):
                writer.commit([spec])
            assert writer.committed_generation()["accepted"] == {}
            writer.fail_attempt("synthetic unresolved or executable ELF")
        else:
            # Retain bytes through the real legacy/untyped path, then publish the historical
            # typed declaration with production serializers: no byte validator is mocked.
            legacy = writer.commit([replace(spec, role=None)])
            record = writer.read_retained_record(root, legacy.reference)
            record["products"] = [asdict(spec)]
            reference = _immutable(
                root, f"artifacts/build/workspace/products/{canonical_json_sha256(record)}.json", record)
            current = writer.committed_generation()
            generation = writer._publish_generation(
                current["entries"], {binding.node_id: reference}, current["input_identity"])
            with pytest.raises(WorkspaceError, match="role"):
                verify_retained_product(root, generation, reference, binding)


@pytest.mark.parametrize("case", ["late-interpreter", "static-pie"])
def test_elf_executable_indicators_win_over_shared_library_filename(tmp_path, case):
    path = tmp_path / "libcontrol.so"
    path.write_bytes(_dynamic_elf(case))
    verify_native_product(path, replace(_spec("executable"), path="target/libcontrol.so"))


@pytest.mark.parametrize("bits,order", [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
def test_complete_shared_elf_role_does_not_depend_on_any_filename(tmp_path, bits, order):
    path = tmp_path / "content-addressed-object"
    path.write_bytes(_dynamic_elf(bits=bits, order=order))
    spec = replace(_spec("runtime_shared"), path="target/no-library-suffix",
                   axes={**NATIVE_AXES, "isa": "x86_64" if bits == 64 else "x86"})
    verify_native_product(path, spec)
