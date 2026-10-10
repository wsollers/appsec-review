from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct

import pytest

from appsec_review.jobs.job_language_build import elf, go
from tests.capture_fakes import (
    GO_BUILD_ID, GO_MODINFO_END, GO_MODINFO_START, GO_MODULE_SUM, go_build_id_note, go_build_info, go_elf,
)


def _write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "app"
    path.write_bytes(data)
    return path


def _patched(data: bytes, offset: int, fmt: str, *values: int) -> bytes:
    mutable = bytearray(data)
    struct.pack_into(fmt, mutable, offset, *values)
    return bytes(mutable)


def test_build_facts_reads_build_id_modules_and_debug_status(tmp_path: Path) -> None:
    facts = go.build_facts(_write(tmp_path, go_elf()[0]))
    assert facts["parser"] == go.BUILD_FACTS_PARSER
    assert facts["build_id_sha256"] == hashlib.sha256(GO_BUILD_ID.encode()).hexdigest()
    assert facts["go_version"] == "go1.23.12" and facts["main_package"] == "example.test/app/cmd/app"
    assert facts["main_module"] == {"path": "example.test/app", "version": "(devel)", "sum": None}
    assert facts["dependency_modules"] == [
        {"path": "github.com/google/uuid", "version": "v1.6.0", "sum": GO_MODULE_SUM}]
    # Linker flag settings can embed values; only fixed platform facts are published.
    assert facts["build_settings"] == {"-buildmode": "exe", "-compiler": "gc", "CGO_ENABLED": "1",
                                       "GOARCH": "amd64", "GOOS": "linux"}
    assert "release" not in json.dumps(facts)
    assert facts["debug_data"] == {"dwarf": "embedded", "dwarf_compressed": False,
                                   "symbol_table": False, "pc_line_table": True}
    assert go.build_facts(_write(tmp_path, go_elf(dwarf=False)[0]))["debug_data"]["dwarf"] == "absent"


def test_build_facts_rejects_a_section_that_points_outside_the_file(tmp_path: Path) -> None:
    data, layout = go_elf()
    header = layout[".go.buildinfo"]["header"]
    with pytest.raises(ValueError, match="section extends past the end of the file"):
        go.build_facts(_write(tmp_path, _patched(data, header + 0x20, "<Q", len(data))))
    with pytest.raises(ValueError, match="section extends past the end of the file"):
        go.build_facts(_write(tmp_path, _patched(data, header + 0x18, "<Q", len(data) - 4)))


def test_build_facts_never_reads_build_info_from_outside_its_declared_section(tmp_path: Path) -> None:
    # The file holds a complete, valid build-info blob, but the section header declares only its
    # first 40 bytes. The strings beyond the declared size must not be read.
    data, layout = go_elf()
    header = layout[".go.buildinfo"]["header"]
    with pytest.raises(ValueError, match="extends past its section"):
        go.build_facts(_write(tmp_path, _patched(data, header + 0x20, "<Q", 40)))


def test_build_facts_rejects_a_section_name_outside_the_name_table(tmp_path: Path) -> None:
    data, layout = go_elf()
    names = layout[".shstrtab"]
    with pytest.raises(ValueError, match="section name lies outside the section-name table"):
        go.build_facts(_write(tmp_path, _patched(data, layout[".go.buildinfo"]["header"], "<I", names["size"])))
    # A name table whose final byte is not a terminator leaves the last name unterminated.
    unterminated = bytearray(data)
    unterminated[names["offset"] + names["size"] - 1] = ord("x")
    with pytest.raises(ValueError, match="section name is unterminated"):
        go.build_facts(_write(tmp_path, bytes(unterminated)))


@pytest.mark.parametrize(("field", "fmt", "value", "message"), [
    (0x3A, "<H", 40, "section header table is invalid"),         # e_shentsize
    (0x3C, "<H", 0xFFFF, "section header table is invalid"),     # e_shnum over its bound
    (0x3E, "<H", 0, "section header table is invalid"),          # e_shstrndx names the null section
    (0x3E, "<H", 99, "section header table is invalid"),         # e_shstrndx past the table
    (0x28, "<Q", 8, "section header table is invalid"),          # e_shoff inside the ELF header
    (0x28, "<Q", 1 << 40, "past the end of the file"),           # e_shoff past the file
    (0x34, "<H", 52, "header size is inconsistent"),             # e_ehsize
    (0x06, "<B", 2, "identification is invalid"),                # EI_VERSION
], ids=["entry-size", "count-bound", "names-null", "names-range", "table-in-header", "table-past-file",
        "header-size", "ident-version"])
def test_build_facts_rejects_inconsistent_elf_and_section_headers(
        tmp_path: Path, field: int, fmt: str, value: int, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        go.build_facts(_write(tmp_path, _patched(go_elf()[0], field, fmt, value)))


def test_build_facts_rejects_wrong_types_duplicates_and_missing_sections(tmp_path: Path) -> None:
    data, layout = go_elf()
    names = layout[".shstrtab"]
    with pytest.raises(ValueError, match="section-name table is invalid"):
        go.build_facts(_write(tmp_path, _patched(data, names["header"] + 4, "<I", 1)))
    with pytest.raises(ValueError, match=r"\.note\.go\.buildid section type or size is invalid"):
        go.build_facts(_write(tmp_path, _patched(data, layout[".note.go.buildid"]["header"] + 4, "<I", 1)))
    # Two sections named `.go.buildinfo` make the embedded build information ambiguous.
    note_name, = struct.unpack_from("<I", data, layout[".go.buildinfo"]["header"])
    with pytest.raises(ValueError, match="declared more than once"):
        go.build_facts(_write(tmp_path, _patched(data, layout[".debug_info"]["header"], "<I", note_name)))
    with pytest.raises(ValueError, match="has no section header table"):
        go.build_facts(_write(tmp_path, _patched(_patched(data, 0x28, "<Q", 0), 0x3C, "<H", 0)))
    with pytest.raises(ValueError, match="extended section numbering is unsupported"):
        go.build_facts(_write(tmp_path, _patched(data, 0x3C, "<H", 0)))
    # A valid ELF that is not a Go binary is unparsed, never given invented build facts.
    renamed = data.replace(b".note.go.buildid\0", b".note.xx.buildid\0")
    with pytest.raises(ValueError, match=r"has no \.note\.go\.buildid section"):
        go.build_facts(_write(tmp_path, renamed))


@pytest.mark.parametrize(("note", "message"), [
    (go_build_id_note()[:10], "header is truncated"),
    (struct.pack("<III", 4, 4096, 4) + b"Go\0\0" + b"abc/def\0", "extends past its section"),
    (struct.pack("<III", 0xFFFFFFF0, 4, 4) + b"Go\0\0abcd", "extends past its section"),
    (struct.pack("<III", 4, 8, 3) + b"GNU\0" + bytes(8), "exactly one valid build ID"),
    (go_build_id_note() + go_build_id_note(), "exactly one valid build ID"),
    (go_build_id_note("not a build id"), "exactly one valid build ID"),
    (go_build_id_note("abc/def") + b"\x01\x02", "header is truncated"),
], ids=["short-header", "description-overrun", "name-overflow", "foreign-note", "duplicate", "format",
        "trailing-bytes"])
def test_build_id_note_rejects_malformed_notes(note: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        go.parse_build_id_note(note)


def test_build_id_note_bounds_the_section_and_rejects_non_ascii() -> None:
    assert go.parse_build_id_note(go_build_id_note("abc/def")) == "abc/def"
    with pytest.raises(ValueError, match="exceeds its bound"):
        go.parse_build_id_note(bytes(8192))
    with pytest.raises(ValueError):
        go.parse_build_id_note(struct.pack("<III", 4, 4, 4) + b"Go\0\0" + b"\xff\xfe/a")


def _info(text: str) -> bytes:
    return go_build_info(module_text=text)


@pytest.mark.parametrize(("data", "message"), [
    (go_build_info()[:20], "header is invalid"),
    (b"\xff Go buildinf;" + go_build_info()[14:], "header is invalid"),
    (go_build_info()[:14] + bytes([3]) + go_build_info()[15:], "header is invalid"),
    (go_build_info()[:15] + bytes([6]) + go_build_info()[16:], "header is invalid"),
    (go_build_info()[:16] + b"\x01" + go_build_info()[17:], "header is invalid"),
    (go_build_info()[:15] + bytes([0]) + go_build_info()[16:], "pre-1.18 pointer layout"),
    (go_build_info()[:32] + b"\xff" * 12, "length is truncated or overflows"),
    (go_build_info()[:32] + b"\x80", "length is truncated or overflows"),
    (go_build_info()[:32] + b"\x7f" + b"go1.23", "version extends past its section"),
    (go_build_info()[:32] + b"\x09go1.23.12" + b"\xff\x7f", "module data extends past its section"),
    (go_build_info() + b"\x01", "trailing data"),
    (go_build_info(version="gcc 13"), "toolchain version is invalid"),
    (go_build_info(version="go1.23\n"), "toolchain version is invalid"),
], ids=["truncated-header", "magic", "pointer-size", "flags", "reserved", "pointer-layout", "varint-overflow",
        "varint-truncated", "version-overrun", "module-overrun", "trailing", "version", "version-control"])
def test_build_info_rejects_malformed_headers_and_lengths(data: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        go.parse_build_info(data)


@pytest.mark.parametrize("text", [
    "path\texample.test/app\npath\texample.test/other\n",
    "mod\texample.test/app\t(devel)\t\nmod\texample.test/app\t(devel)\t\n",
    "dep\tgithub.com/google/uuid\n",
    "dep\tgithub.com/google/uuid\tv1.6.0\tsha1:deadbeef\n",
    "dep\tgithub.com/google/uuid\tv1.6.0\t" + GO_MODULE_SUM + "\textra\n",
    "dep\tgithub.com/go ogle\tv1.6.0\t\n",
    "=>\texample.test/replacement\tv1.0.0\t\n",
    "build\tno-separator\n",
    "exec\t/bin/sh\n",
    "path\texample.test/app",
], ids=["duplicate-path", "duplicate-mod", "short-dep", "sum-format", "extra-field", "module-path",
        "orphan-replacement", "setting", "unknown-line", "unterminated"])
def test_build_info_rejects_malformed_module_records(text: str) -> None:
    with pytest.raises(ValueError):
        go.parse_build_info(_info(text))


def test_build_info_requires_exact_module_sentinels_and_bounds_dependencies() -> None:
    text = b"path\texample.test/app\n"
    for module in (GO_MODINFO_START + text, bytes(16) + text + GO_MODINFO_END,
                   GO_MODINFO_START + text + bytes(16), b"short"):
        data = b"\xff Go buildinf:" + bytes([8, 2]) + bytes(16) + b"\x09go1.23.12" + bytes([len(module)]) + module
        with pytest.raises(ValueError, match="sentinels are invalid"):
            go.parse_build_info(data)
    many = "".join(f"dep\texample.test/m{index}\tv1.0.0\t\n" for index in range(8193))
    with pytest.raises(ValueError, match="dependency count exceeds its bound"):
        go.parse_build_info(_info(many))
    with pytest.raises(ValueError):
        go.parse_build_info(_info("path\texample.test/app\n").replace(b"/app", b"/\xff\xfe\xfd"))
    replaced = go.parse_build_info(_info(
        "dep\texample.test/a\tv1.0.0\t\n=>\texample.test/b\tv1.1.0\t" + GO_MODULE_SUM + "\n"))
    assert replaced["dependencies"][0]["replaced_by"]["path"] == "example.test/b"
    assert go.parse_build_info(go_build_info(module_text=""))["dependencies"] == []


def _catalog(*packages: dict) -> bytes:
    return "\n".join(json.dumps(item, indent=1) for item in packages).encode()


def test_package_catalog_parses_complete_output_and_keeps_directories_out_of_rows() -> None:
    rows, directories = go.parse_package_catalog(_catalog(
        {"ImportPath": "fmt", "Standard": True, "Dir": "/usr/local/go/src/fmt", "GoFiles": ["print.go"]},
        {"ImportPath": "example.test/app", "Dir": "/workspace/go", "Module": {"Path": "example.test/app"},
         "GoFiles": ["main.go"], "CgoFiles": ["native.go"], "Imports": ["fmt", "C"]}))
    assert [row["import_path"] for row in rows] == ["fmt", "example.test/app"]
    assert rows[1] == {"import_path": "example.test/app", "module_path": "example.test/app",
                       "dependencies": ["C", "fmt"], "standard": False, "cgo_files": ["native.go"],
                       "go_files": ["main.go"], "compiled_go_files": []}
    assert directories == {"fmt": "/usr/local/go/src/fmt", "example.test/app": "/workspace/go"}


@pytest.mark.parametrize("data", [
    b"",
    b"  \n",
    b'{"ImportPath": "fmt"',
    _catalog({"ImportPath": "fmt"}) + b"\n<redacted: secret scan disposition>\n",
    _catalog({"ImportPath": "fmt"}, {"ImportPath": "fmt"}),
    b'["fmt"]',
    _catalog({"Name": "fmt"}),
    _catalog({"ImportPath": "fmt\u0000x"}),
    _catalog({"ImportPath": "fmt", "Imports": "errors"}),
    _catalog({"ImportPath": "fmt", "GoFiles": [1]}),
    _catalog({"ImportPath": "fmt", "Module": "example.test/app"}),
    _catalog({"ImportPath": "fmt", "Module": {"Path": 7}}),
    _catalog({"ImportPath": "fmt", "Dir": ["/workspace"]}),
    _catalog({"ImportPath": "fmt", "Standard": "yes"}),
    _catalog({"ImportPath": "fmt", "Error": {"Err": "no Go files"}}),
    _catalog({"ImportPath": "fmt", "Incomplete": True}),
    b'{"ImportPath": "fmt"}\xff',
], ids=["empty", "blank", "truncated", "redacted-tail", "duplicate", "array", "no-path", "nul-path",
        "imports-type", "files-type", "module-type", "module-path", "dir-type", "standard-type",
        "package-error", "incomplete", "not-utf8"])
def test_package_catalog_rejects_partial_or_malformed_output(data: bytes) -> None:
    with pytest.raises(ValueError):
        go.parse_package_catalog(data)


def test_package_catalog_is_bounded() -> None:
    oversized = _catalog({"ImportPath": "fmt", "GoFiles": [f"f{index}.go" for index in range(16385)]})
    with pytest.raises(ValueError, match="field is invalid"):
        go.parse_package_catalog(oversized)
    many = "\n".join(json.dumps({"ImportPath": f"example.test/p{index}"}) for index in range(20001)).encode()
    with pytest.raises(ValueError, match="package bound"):
        go.parse_package_catalog(many)


def test_section_reader_treats_an_absent_table_as_no_sections(tmp_path: Path) -> None:
    data = _patched(_patched(go_elf()[0], 0x28, "<Q", 0), 0x3C, "<H", 0)
    with _write(tmp_path, data).open("rb") as stream:
        assert elf.read_sections(stream, elf.read_image(stream)) == ()
