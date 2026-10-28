"""Offline format readers: genuine tool fixtures and fail-closed boundaries."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

import pytest

from appsec_review.config.compiler_target import CompilerTarget
from appsec_review.debug_symbols.contract import RecordKind
from appsec_review.debug_symbols.readers import extract_symbols


FIXTURES = Path(__file__).parent / "fixtures" / "debug_symbols"


def settings(tmp_path: Path, tool: str = "llvm_dwarfdump", **changes):
    executable = tmp_path / "approved-tool"
    executable.write_bytes(b"test executable identity, never executed")
    result = {
        "max_input_bytes": 1_000_000,
        "max_output_bytes": 2_000_000,
        "max_records": 10_000,
        "max_depth": 128,
        "timeout_seconds": 5,
        "tools": {tool: {"path": str(executable), "sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}},
    }
    result.update(changes)
    return result


def fixture_runner(name: str):
    def run(argv, *, timeout_seconds, max_output_bytes):
        assert timeout_seconds > 0 and max_output_bytes > 0
        assert all(isinstance(arg, str) for arg in argv)
        return (FIXTURES / name).read_bytes()
    return run


def test_genuine_embedded_dwarf_families(tmp_path):
    result = extract_symbols(
        FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
        settings=settings(tmp_path), runner=fixture_runner("tiny.dwarf.txt"),
    )
    kinds = {record.kind for record in result.records}
    assert {RecordKind.SYMBOL, RecordKind.TYPE_LAYOUT, RecordKind.SOURCE_RANGE,
            RecordKind.COMPILATION_UNIT} <= kinds
    pair = next(record for record in result.records if record.kind is RecordKind.TYPE_LAYOUT and record.name == "Pair")
    assert pair.data["byte_size"] == 16
    assert [(member["name"], member["offset"]) for member in pair.data["members"]] == [("left", 0), ("right", 8)]
    entry = next(record for record in result.records if record.kind is RecordKind.SYMBOL and record.name == "entry")
    assert entry.ranges and entry.data["signature"]
    assert all(record.source is None or record.data.get("source_binding") != "exact" for record in result.records)
    assert result.producer == "llvm_dwarfdump"
    again = extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path), runner=fixture_runner("tiny.dwarf.txt"))
    assert again == result


def test_genuine_native_pdb_families_and_rva(tmp_path):
    result = extract_symbols(
        FIXTURES / "tiny.exe", FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
        settings=settings(tmp_path, "llvm_pdbutil"), runner=fixture_runner("tiny.pdb.yaml"),
    )
    kinds = {record.kind for record in result.records}
    assert {RecordKind.SYMBOL, RecordKind.TYPE_LAYOUT, RecordKind.SOURCE_RANGE,
            RecordKind.COMPILATION_UNIT} <= kinds
    entry = next(record for record in result.records if record.kind is RecordKind.SYMBOL and record.name == "entry")
    assert entry.ranges[0].start >= 0x1000
    assert entry.ranges[0].end < 2**32
    pair = next(record for record in result.records if record.kind is RecordKind.TYPE_LAYOUT and record.name == "Pair")
    assert pair.data["byte_size"] == 16
    assert [member["offset"] for member in pair.data["members"]] == [0, 8]
    assert result.producer == "llvm_pdbutil"


@pytest.mark.parametrize("target,binary,debug", [
    (CompilerTarget.CLANG, "tiny.elf", None),
    (CompilerTarget.MSVC, "tiny.exe", "tiny.pdb"),
])
def test_missing_tool_is_gap_without_records(tmp_path, target, binary, debug):
    result = extract_symbols(FIXTURES / binary, FIXTURES / debug if debug else None,
                            target=target, settings={"tools": {}})
    assert result.records == ()
    assert "tool_unavailable" in result.gaps


def test_pdb_guid_mismatch_never_invokes_tool(tmp_path):
    data = bytearray((FIXTURES / "tiny.exe").read_bytes())
    rsds = data.index(b"RSDS")
    data[rsds + 4] ^= 1
    binary = tmp_path / "other.exe"
    binary.write_bytes(data)
    def forbidden(*args, **kwargs):
        pytest.fail("unverified symbols reached exporter")
    result = extract_symbols(binary, FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"), runner=forbidden)
    assert result.records == ()
    assert "pdb_identity_mismatch" in result.gaps


def test_output_limit_discards_all_records(tmp_path):
    result = extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path, max_output_bytes=16),
                            runner=fixture_runner("tiny.dwarf.txt"))
    assert not result.records
    assert "output_limit" in result.gaps


def test_pinned_executable_drift_is_refused(tmp_path):
    config = settings(tmp_path)
    Path(config["tools"]["llvm_dwarfdump"]["path"]).write_bytes(b"changed")
    result = extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                            settings=config, runner=lambda *a, **k: pytest.fail("executed unpinned tool"))
    assert result.records == ()
    assert "tool_identity_mismatch" in result.gaps


def test_compiler_selector_is_not_inferred_from_extension(tmp_path):
    with pytest.raises(ValueError):
        extract_symbols(FIXTURES / "tiny.elf", None, target="clang", settings=settings(tmp_path))


@pytest.mark.parametrize("data", [b"", b"\x7fELF", b"MZ" + bytes(63), b"garbage"])
def test_malformed_content_is_gap(tmp_path, data):
    binary = tmp_path / "pretend.elf"
    binary.write_bytes(data)
    result = extract_symbols(binary, None, target=CompilerTarget.CLANG, settings=settings(tmp_path))
    assert not result.records and result.gaps


def test_separate_dwarf_build_id_and_debuglink(tmp_path):
    result = extract_symbols(FIXTURES / "stripped.elf", FIXTURES / "tiny.debug",
                            target=CompilerTarget.CLANG, settings=settings(tmp_path),
                            runner=fixture_runner("tiny.dwarf.txt"))
    assert any(record.kind is RecordKind.SYMBOL for record in result.records)
    assert not any("mismatch" in gap for gap in result.gaps)


def test_wrong_build_id_is_not_name_pairing(tmp_path):
    result = extract_symbols(FIXTURES / "stripped.elf", FIXTURES / "optimized.elf",
                            target=CompilerTarget.CLANG, settings=settings(tmp_path),
                            runner=lambda *a, **k: pytest.fail("unverified pair exported"))
    assert result.records == () and "elf_build_id_mismatch" in result.gaps


def test_debuglink_checksum_failure_even_with_matching_build_id(tmp_path):
    debug = tmp_path / "tiny.debug"
    debug.write_bytes((FIXTURES / "tiny.debug").read_bytes() + b"changed")
    result = extract_symbols(FIXTURES / "stripped.elf", debug, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path), runner=lambda *a, **k: pytest.fail("bad CRC accepted"))
    assert result.records == () and "elf_debuglink_mismatch" in result.gaps


def test_pdb_age_mismatch_is_refused(tmp_path):
    data = bytearray((FIXTURES / "tiny.exe").read_bytes())
    struct.pack_into("<I", data, data.index(b"RSDS") + 20, 2)
    binary = tmp_path / "wrong-age.exe"
    binary.write_bytes(data)
    result = extract_symbols(binary, FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"),
                            runner=lambda *a, **k: pytest.fail("bad age accepted"))
    assert result.records == () and "pdb_identity_mismatch" in result.gaps


@pytest.mark.parametrize("target,binary,debug,output", [
    (CompilerTarget.CLANG, "inline.elf", None, "inline.dwarf.txt"),
    (CompilerTarget.MSVC, "inline.exe", "inline.pdb", "inline.pdb.yaml"),
])
def test_genuine_optimized_inline_ancestry(tmp_path, target, binary, debug, output):
    result = extract_symbols(FIXTURES / binary, FIXTURES / debug if debug else None, target=target,
                            settings=settings(tmp_path, "llvm_dwarfdump" if target is CompilerTarget.CLANG else "llvm_pdbutil"),
                            runner=fixture_runner(output))
    frames = [record for record in result.records if record.kind is RecordKind.INLINE_FRAME]
    assert len(frames) == 1 and frames[0].name == "add"
    parent = next(record for record in result.records if record.key == frames[0].parent_key)
    assert parent.name == "entry" and parent.kind is RecordKind.SYMBOL
    assert frames[0].source is not None
    if target is CompilerTarget.CLANG:
        assert frames[0].ranges
    else:
        assert not frames[0].ranges and "inline_ranges_unavailable" in result.gaps
    assert "optimized_debug_information" in result.gaps


@pytest.mark.parametrize("target,binary,debug,output,source", [
    (CompilerTarget.CLANG, "tiny.elf", None, "tiny.dwarf.txt", "tiny.c"),
    (CompilerTarget.MSVC, "tiny.exe", "tiny.pdb", "tiny.pdb.yaml", "tiny.c"),
])
def test_recorded_checksum_is_preserved_without_source_authority(tmp_path, target, binary, debug, output, source):
    result = extract_symbols(FIXTURES / binary, FIXTURES / debug if debug else None, target=target,
                            settings=settings(tmp_path, "llvm_dwarfdump" if target is CompilerTarget.CLANG else "llvm_pdbutil"),
                            runner=fixture_runner(output))
    rows = [record for record in result.records if record.kind is RecordKind.SOURCE_RANGE]
    assert rows and all(record.source.checksum_kind == "md5" for record in rows)
    assert all(record.source.checksum == hashlib.md5((FIXTURES / source).read_bytes()).hexdigest() for record in rows)
    assert all(record.data["source_binding"] == "path_only" for record in rows)


def test_recorded_external_source_path_is_never_opened(tmp_path, monkeypatch):
    output = (FIXTURES / "tiny.dwarf.txt").read_text().replace("fixture/tests/fixtures/debug_symbols/tiny.c",
                                                            "Z:/private/never-open.c")
    real_open = Path.open
    def checked_open(path, *args, **kwargs):
        assert "never-open" not in str(path)
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", checked_open)
    result = extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path), runner=lambda *a, **k: output)
    assert result.records and any(record.source and "never-open" in record.source.path for record in result.records)


def test_full_64_bit_half_open_dwarf_addresses(tmp_path):
    text = (FIXTURES / "tiny.dwarf.txt").read_text()
    text = re.sub(r"0x000000000040([0-9a-f]{4})", r"0xf00000000040\1", text)
    result = extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path), runner=lambda *a, **k: text)
    entry = next(record for record in result.records if record.name == "entry")
    assert entry.ranges[0].start == 0xf000000000401000
    assert entry.ranges[0].end == 0xf00000000040102f
    assert entry.ranges[0].end - entry.ranges[0].start == 47


@pytest.mark.parametrize("name,value,gap", [
    ("max_input_bytes", 16, "input_limit"),
    ("max_records", 1, "record_limit"),
    ("max_depth", 1, "depth_limit"),
])
def test_resource_limits_publish_no_partial_records(tmp_path, name, value, gap):
    result = extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path, **{name: value}), runner=fixture_runner("tiny.dwarf.txt"))
    assert not result.records and gap in result.gaps


@pytest.mark.parametrize("name,value", [("max_records", 0), ("max_depth", 257),
                                      ("timeout_seconds", float("nan")), ("max_output_bytes", True)])
def test_bad_central_limits_fail_validation(tmp_path, name, value):
    with pytest.raises(ValueError):
        extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                        settings=settings(tmp_path, **{name: value}))


@pytest.mark.parametrize("error,gap", [(subprocess.TimeoutExpired("private-path", 1), "tool_timeout"),
                                      (subprocess.CalledProcessError(1, "secret-path", b"secret output"), "tool_failed")])
def test_tool_failure_has_no_private_detail(tmp_path, error, gap):
    def fail(*args, **kwargs):
        raise error
    result = extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path), runner=fail)
    assert not result.records and result.gaps == (gap,)
    assert "secret" not in repr(result) and "private" not in repr(result)


def test_changed_input_during_export_is_refused(tmp_path):
    binary = tmp_path / "mutable"
    binary.write_bytes((FIXTURES / "tiny.elf").read_bytes())
    def mutate(*args, **kwargs):
        binary.write_bytes(binary.read_bytes() + b"mutation")
        return (FIXTURES / "tiny.dwarf.txt").read_bytes()
    result = extract_symbols(binary, None, target=CompilerTarget.CLANG, settings=settings(tmp_path), runner=mutate)
    assert not result.records and "input_identity_changed" in result.gaps


def test_pdb_yaml_alias_refused(tmp_path):
    output = (FIXTURES / "tiny.pdb.yaml").read_text().replace("StringTable:", "Aliased: &a [1]\nAlias: *a\nStringTable:")
    result = extract_symbols(FIXTURES / "tiny.exe", FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"), runner=lambda *a, **k: output)
    assert not result.records and "pdb_yaml_alias_refused" in result.gaps


@pytest.mark.parametrize("target,output", [
    (CompilerTarget.CLANG, "tiny.dwarf.txt"),
    (CompilerTarget.MSVC, "tiny.pdb.yaml"),
])
def test_truncated_export_is_not_partial_success(tmp_path, target, output):
    text = (FIXTURES / output).read_text()
    text = text[:len(text) // 2]
    result = extract_symbols(
        FIXTURES / ("tiny.elf" if target is CompilerTarget.CLANG else "tiny.exe"),
        None if target is CompilerTarget.CLANG else FIXTURES / "tiny.pdb", target=target,
        settings=settings(tmp_path, "llvm_dwarfdump" if target is CompilerTarget.CLANG else "llvm_pdbutil"),
        runner=lambda *a, **k: text,
    )
    assert not result.records and "malformed_tool_output" in result.gaps


def test_bounded_subprocess_runner_is_real(tmp_path):
    from appsec_review.debug_symbols.readers import _run
    assert _run([sys.executable, "-c", "print('ok')"], timeout_seconds=5, max_output_bytes=100).strip() == b"ok"
    from appsec_review.debug_symbols._reader_binary import ReaderFailure
    with pytest.raises(ReaderFailure, match="output_limit"):
        _run([sys.executable, "-c", "print('x'*1000000)"], timeout_seconds=5, max_output_bytes=100)
    with pytest.raises(ReaderFailure, match="tool_timeout"):
        _run([sys.executable, "-c", "import time; time.sleep(2)"], timeout_seconds=0.1, max_output_bytes=100)


@pytest.mark.parametrize("target,binary,debug,output", [
    (CompilerTarget.CLANG, "tiny.elf", None, "tiny.dwarf.txt"),
    (CompilerTarget.MSVC, "tiny.exe", "tiny.pdb", "tiny.pdb.yaml"),
])
def test_private_source_and_compilation_paths_stay_out_of_data(tmp_path, target, binary, debug, output):
    text = (FIXTURES / output).read_text().replace("fixture", "private-tenant-location")
    result = extract_symbols(
        FIXTURES / binary, FIXTURES / debug if debug else None, target=target,
        settings=settings(tmp_path, "llvm_dwarfdump" if target is CompilerTarget.CLANG else "llvm_pdbutil"),
        runner=lambda *a, **k: text,
    )
    assert result.records
    for record in result.records:
        assert "private-tenant-location" not in json.dumps(record.data)
        assert not record.name.startswith(("/", "\\"))
    assert any("sha256" in str(record.data) for record in result.records if record.kind is RecordKind.COMPILATION_UNIT)


def test_pdb_yaml_duplicate_identity_refused(tmp_path):
    text = (FIXTURES / "tiny.pdb.yaml").read_text().replace("  Age:             1", "  Age:             1\n  Age:             1", 1)
    result = extract_symbols(FIXTURES / "tiny.exe", FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"), runner=lambda *a, **k: text)
    assert not result.records and "malformed_tool_output" in result.gaps


def test_public_only_pdb_reports_missing_families(tmp_path):
    import yaml
    from appsec_review.debug_symbols._reader_pdb import _document
    document = _document((FIXTURES / "tiny.pdb.yaml").read_text(), {"max_records": 10000, "max_depth": 128})
    for section in ("TpiStream", "IpiStream"):
        document.pop(section)
    document["DbiStream"]["Modules"] = []
    output = yaml.safe_dump(document, explicit_start=True, explicit_end=True)
    result = extract_symbols(FIXTURES / "tiny.exe", FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"), runner=lambda *a, **k: output)
    assert len(result.records) == 1 and result.records[0].name == "entry"
    assert not result.records[0].ranges and result.records[0].data["rva"] == 0x1000
    assert {"type_layouts_unavailable", "source_ranges_unavailable",
            "compilation_units_unavailable", "function_ranges_unavailable"} <= set(result.gaps)


def test_unsupported_pdb_subsection_is_named_gap_not_evaluated(tmp_path):
    output = (FIXTURES / "tiny.pdb.yaml").read_text().replace(
        "      Subsections:", "      Subsections:\n        - !Unknown\n          Value: 'https://private/source-server?cmd=do-not-execute'", 1)
    result = extract_symbols(FIXTURES / "tiny.exe", FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"), runner=lambda *a, **k: output)
    assert result.records and "pdb_subsection_unsupported" in result.gaps
    assert "private/source" not in repr(result)


def test_optimized_out_variables_are_not_invented(tmp_path):
    result = extract_symbols(FIXTURES / "optimized.elf", None, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path), runner=fixture_runner("optimized.dwarf.txt"))
    assert result.records
    assert "location_expressions_not_evaluated" in result.gaps
    assert all(record.name != "p" for record in result.records)


@pytest.mark.parametrize("output", [
    "---\nPdbStream: []\n...\n",
    "---\nPdbStream: {Age: 1, Guid: ''}\nDbiStream: []\n...\n",
    "---\nPdbStream: {Age: 1, Guid: '{ABE8BD73-C161-3D95-4C4C-44205044422E}'}\nTpiStream: []\n...\n",
    "---\nPdbStream: {Age: 1, Guid: '{ABE8BD73-C161-3D95-4C4C-44205044422E}'}\nDbiStream: {Modules: [null]}\n...\n",
])
def test_malformed_pdb_nested_schema_cannot_escape_reader(tmp_path, output):
    result = extract_symbols(FIXTURES / "tiny.exe", FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"), runner=lambda *a, **k: output)
    assert not result.records and result.gaps


def test_malformed_dwarf_interval_is_gap(tmp_path):
    text = (FIXTURES / "inline.dwarf.txt").read_text().replace(
        "DW_AT_high_pc\t(0x000000000040100f)", "DW_AT_ranges\t(0x00\n [0x100, 0x10))", 1)
    result = extract_symbols(FIXTURES / "inline.elf", None, target=CompilerTarget.CLANG,
                            settings=settings(tmp_path), runner=lambda *a, **k: text)
    assert not result.records and "malformed_tool_output" in result.gaps


def test_name_only_elf_companion_is_not_identity(tmp_path):
    binary = tmp_path / "same-name"
    debug = tmp_path / "same-name.debug"
    binary.write_bytes((FIXTURES / "tiny.elf").read_bytes().replace(b"GNU\0", b"NONE"))
    debug.write_bytes((FIXTURES / "tiny.debug").read_bytes().replace(b"GNU\0", b"NONE"))
    result = extract_symbols(binary, debug, target=CompilerTarget.CLANG, settings=settings(tmp_path),
                            runner=lambda *a, **k: pytest.fail("name-paired symbols"))
    assert not result.records and "elf_pairing_unavailable" in result.gaps


def test_ambiguous_pe_identity_is_refused(tmp_path):
    data = bytearray((FIXTURES / "tiny.exe").read_bytes())
    header = struct.unpack_from("<I", data, 60)[0]
    optional_size = struct.unpack_from("<H", data, header + 20)[0]
    optional = header + 24
    directory = optional + 112 + 6 * 8
    original_rva, _ = struct.unpack_from("<II", data, directory)
    sections = header + 24 + optional_size
    for index in range(struct.unpack_from("<H", data, header + 6)[0]):
        base = sections + index * 40
        _, va, raw_size, raw = struct.unpack_from("<IIII", data, base + 8)
        if va <= original_rva < va + raw_size:
            original = bytes(data[raw + original_rva - va:raw + original_rva - va + 28])
            location = raw + raw_size - 56
            data[location:location + 56] = original * 2
            struct.pack_into("<II", data, directory, va + raw_size - 56, 56)
            break
    binary = tmp_path / "ambiguous.exe"
    binary.write_bytes(data)
    result = extract_symbols(binary, FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"),
                            runner=lambda *a, **k: pytest.fail("ambiguous PDB identity accepted"))
    assert not result.records and "ambiguous_codeview_identity" in result.gaps


def test_exported_pdb_identity_cannot_drift(tmp_path):
    output = (FIXTURES / "tiny.pdb.yaml").read_text().replace("ABE8BD73", "ABE8BD74")
    result = extract_symbols(FIXTURES / "tiny.exe", FIXTURES / "tiny.pdb", target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"), runner=lambda *a, **k: output)
    assert not result.records and "pdb_export_identity_mismatch" in result.gaps


def test_raw_tool_output_does_not_count_as_records(tmp_path):
    for output in (b"nothing", b"\xff", b"fatal: private source-path compiler detail"):
        result = extract_symbols(FIXTURES / "tiny.elf", None, target=CompilerTarget.CLANG,
                                settings=settings(tmp_path), runner=lambda *a, **k: output)
        assert not result.records and result.gaps == ("malformed_tool_output",)


def test_missing_pdb_is_explicit(tmp_path):
    result = extract_symbols(FIXTURES / "tiny.exe", None, target=CompilerTarget.MSVC,
                            settings=settings(tmp_path, "llvm_pdbutil"))
    assert not result.records and result.gaps == ("pdb_missing",)


def test_supplementary_dwarf_is_refused_before_any_external_lookup(tmp_path):
    binary = tmp_path / "supplementary.elf"
    binary.write_bytes((FIXTURES / "tiny.elf").read_bytes().replace(b".debug_str\0", b".debug_sup\0"))
    result = extract_symbols(binary, None, target=CompilerTarget.CLANG, settings=settings(tmp_path),
                            runner=lambda *a, **k: pytest.fail("supplementary lookup reached exporter"))
    assert not result.records and "dwarf_supplementary_unavailable" in result.gaps
