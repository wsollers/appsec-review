from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import struct

import pytest

from appsec_review.jobs.job_language_build import elf
from appsec_review.jobs.job_language_build.job import _catalog
from tests.capture_fakes import minimal_elf


def test_loader_facts_reads_needed_libraries_in_declared_order(tmp_path: Path) -> None:
    path = tmp_path / "sample"
    path.write_bytes(minimal_elf(("libgcc_s.so.1", "libc.so.6")))
    assert elf.loader_facts(path) == {"needed": ["libgcc_s.so.1", "libc.so.6"], "interpreter": None,
                                      "soname": None, "run_paths": [], "linkage": "dynamic"}


def test_loader_facts_reports_a_file_without_a_dynamic_segment_as_static(tmp_path: Path) -> None:
    data = bytearray(minimal_elf(()))
    struct.pack_into("<H", data, 0x38, 1)  # keep only the PT_LOAD program header
    path = tmp_path / "static"
    path.write_bytes(bytes(data))
    assert elf.loader_facts(path)["linkage"] == "static"
    assert elf.loader_facts(path)["needed"] == []


@pytest.mark.parametrize("data", [
    b"\x7fELFrust",
    b"\x7fELF" + bytes([3, 1]) + bytes(58),
    minimal_elf()[:100],
    minimal_elf()[:-12] + b"x" * 12,
], ids=["short", "class", "truncated", "unterminated-string"])
def test_loader_facts_rejects_malformed_files(tmp_path: Path, data: bytes) -> None:
    path = tmp_path / "broken"
    path.write_bytes(data)
    with pytest.raises(ValueError):
        elf.loader_facts(path)


def _dynamic(data: bytes) -> tuple[int, int]:
    """File offset of the dynamic section and of its string table in a `minimal_elf` image."""
    count, = struct.unpack_from("<H", data, 0x38)
    start = 64 + count * 56
    index = 0
    while struct.unpack_from("<q", data, start + index * 16)[0] != 5:
        index += 1
    return start, struct.unpack_from("<Q", data, start + index * 16 + 8)[0]


def _entry(data: bytes, tag: int) -> int:
    start, _table = _dynamic(data)
    index = 0
    while struct.unpack_from("<q", data, start + index * 16)[0] != tag:
        index += 1
    return start + index * 16


def test_loader_facts_reads_the_interpreter_inside_its_segment(tmp_path: Path) -> None:
    path = tmp_path / "dynamic"
    path.write_bytes(minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2"))
    facts = elf.loader_facts(path)
    assert facts["interpreter"] == "/lib64/ld-linux-x86-64.so.2" and facts["needed"] == ["libc.so.6"]


def test_loader_facts_never_reads_a_name_from_outside_the_declared_string_table(tmp_path: Path) -> None:
    # Bytes that follow the string table hold a plausible name a lax reader would publish.
    image = minimal_elf(("libc.so.6",)) + b"libplanted.so\0"
    _start, table = _dynamic(image)
    table_size = len(b"\0libc.so.6\0")
    planted = bytearray(image)
    struct.pack_into("<Q", planted, _entry(image, 1) + 8, table_size)   # DT_NEEDED -> first byte past the table
    struct.pack_into("<Q", planted, 0x60, len(planted))                 # PT_LOAD p_filesz covers the planted bytes
    struct.pack_into("<Q", planted, 0x68, len(planted))                 # PT_LOAD p_memsz remains consistent
    path = tmp_path / "planted"
    path.write_bytes(bytes(planted))
    assert bytes(planted)[table + table_size:].startswith(b"libplanted.so")
    with pytest.raises(ValueError, match="outside its declared region"):
        elf.loader_facts(path)


def _without_string_size(image: bytearray) -> None:
    struct.pack_into("<q", image, _entry(bytes(image), 10), 0x6FFFFFFF)  # DT_STRSZ -> an ignored tag


def _oversized_string_table(image: bytearray) -> None:
    struct.pack_into("<Q", image, _entry(bytes(image), 10) + 8, 1 << 20)


def _unterminated_final_string(image: bytearray) -> None:
    image[-1] = ord("x")


def _name_straddling_the_table_end(image: bytearray) -> None:
    struct.pack_into("<Q", image, _entry(bytes(image), 10) + 8, 5)       # table ends inside "libc.so.6"


@pytest.mark.parametrize(("mutate", "message"), [
    (_without_string_size, "address or size is missing"),
    (_oversized_string_table, "not mapped by a loadable segment"),
    (_unterminated_final_string, "unterminated within its declared region"),
    (_name_straddling_the_table_end, "unterminated within its declared region"),
], ids=["no-strsz", "strsz-past-segment", "unterminated", "straddles-table-end"])
def test_loader_facts_requires_every_name_to_terminate_inside_the_string_table(
        tmp_path: Path, mutate, message: str) -> None:
    image = bytearray(minimal_elf(("libc.so.6",)))
    mutate(image)
    path = tmp_path / "bounded"
    path.write_bytes(bytes(image))
    with pytest.raises(ValueError, match=message):
        elf.loader_facts(path)


def test_loader_facts_rejects_a_trailing_terminator_outside_the_interpreter_segment(tmp_path: Path) -> None:
    image = bytearray(minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2") + b"trailing\0")
    image[len(image) - len(b"trailing\0") - 1] = ord("!")   # drop the terminator inside PT_INTERP
    path = tmp_path / "interp"
    path.write_bytes(bytes(image))
    with pytest.raises(ValueError, match="interpreter path is unterminated inside its owning structure"):
        elf.loader_facts(path)


def test_catalog_reports_an_out_of_table_dependency_as_unparsed_not_resolved(tmp_path: Path) -> None:
    image = bytearray(minimal_elf(("libc.so.6",)) + b"libplanted.so\0")
    struct.pack_into("<Q", image, _entry(bytes(image), 1) + 8, len(b"\0libc.so.6\0"))
    struct.pack_into("<Q", image, 0x60, len(image))
    (tmp_path / "app").write_bytes(bytes(image))
    artifacts, gaps = _catalog(tmp_path, tmp_path, {}, 100, "build-unit-fixture")
    assert artifacts[0]["loader_dependency_status"] == "unparsed"
    assert artifacts[0]["loader_dependencies"] == [] and "libplanted" not in str(artifacts)
    parse_gaps = [gap for gap in gaps if "loader dependencies were not parseable" in gap]
    assert len(parse_gaps) == 1 and parse_gaps[0].startswith("app: ")
    assert all("delivery_fact_unavailable" in gap for gap in gaps if gap not in parse_gaps)


def test_loader_facts_bounds_the_program_header_table(tmp_path: Path) -> None:
    data = bytearray(minimal_elf())
    struct.pack_into("<H", data, 0x38, 0xFFFF)
    path = tmp_path / "many-headers"
    path.write_bytes(bytes(data))
    with pytest.raises(ValueError, match="program header table"):
        elf.loader_facts(path)


@pytest.mark.parametrize(("mutate", "message"), [
    (lambda image: struct.pack_into("<H", image, 0x34, 16), "program header table"),
    (lambda image: struct.pack_into("<Q", image, 0x20, 32), "program header table"),
    (lambda image: struct.pack_into("<Q", image, 0x60, len(image) + 1), "segment extends"),
    (lambda image: struct.pack_into("<Q", image, 0x68, 1), "invalid size"),
    (lambda image: struct.pack_into("<Q", image, 0x98, 15), "dynamic section size"),
], ids=["short-header", "header-table-overlap", "segment-past-file", "memsz-smaller",
        "misaligned-dynamic"])
def test_loader_facts_rejects_inconsistent_structure_bounds(tmp_path: Path, mutate, message: str) -> None:
    image = bytearray(minimal_elf(("libc.so.6",)))
    mutate(image)
    path = tmp_path / "malformed-structure"
    path.write_bytes(bytes(image))
    with pytest.raises(ValueError, match=message):
        elf.loader_facts(path)


def test_loader_facts_requires_dynamic_terminator(tmp_path: Path) -> None:
    image = bytearray(minimal_elf(("libc.so.6",)))
    start, _table = _dynamic(bytes(image))
    index = 0
    while struct.unpack_from("<q", image, start + index * 16)[0] != 0:
        index += 1
    struct.pack_into("<qQ", image, start + index * 16, 1, 1)
    path = tmp_path / "unterminated-dynamic"
    path.write_bytes(bytes(image))
    with pytest.raises(ValueError, match="dynamic section is not terminated"):
        elf.loader_facts(path)


def test_catalog_resolves_loader_dependencies_and_names_unparseable_outputs(tmp_path: Path) -> None:
    (tmp_path / "app").write_bytes(minimal_elf(("libssl.so.3",)))
    (tmp_path / "broken").write_bytes(b"\x7fELFfixture")
    artifacts, gaps = _catalog(tmp_path, tmp_path, {}, 100, "build-unit-fixture")
    by_path = {item["workspace_path"]: item for item in artifacts}
    assert by_path["app"]["loader_dependencies"] == ["libssl.so.3"]
    assert by_path["app"]["loader_dependency_status"] == "resolved"
    assert by_path["app"]["loader_parser"] == elf.PARSER_IDENTITY
    assert by_path["broken"]["loader_dependency_status"] == "unparsed"
    parse_gaps = [gap for gap in gaps if "loader dependencies were not parseable" in gap]
    assert len(parse_gaps) == 1 and parse_gaps[0].startswith("broken: loader dependencies were not parseable")
    assert all("delivery_fact_unavailable" in gap for gap in gaps if gap not in parse_gaps)


# Layout of `minimal_elf(("libc.so.6",))`: ELF header, PT_LOAD and PT_DYNAMIC program headers,
# then DT_NEEDED, DT_STRTAB, DT_STRSZ, DT_NULL, then the 11-byte string table.
_LOAD, _DYNAMIC_HEADER = 64, 120
_NEEDED, _STRTAB, _STRSZ, _NULL, _STRINGS = 176, 192, 208, 224, 240


def _patched(data: bytes, *patches: tuple[int, str, int]) -> bytes:
    mutable = bytearray(data)
    for offset, fmt, value in patches:
        struct.pack_into(fmt, mutable, offset, value)
    return bytes(mutable)


def _facts(tmp_path: Path, data: bytes) -> dict:
    path = tmp_path / "candidate"
    path.write_bytes(data)
    return elf.loader_facts(path)


def test_loader_facts_rejects_a_string_outside_the_declared_string_table(tmp_path: Path) -> None:
    # The appended name is terminated, inside the file, and inside the loadable segment, but it
    # lies past DT_STRSZ: it is not part of the dynamic string table and must not be published.
    base = minimal_elf()
    data = base + b"libevil.so\0"
    data = _patched(data, (_LOAD + 32, "<Q", len(data)), (_LOAD + 40, "<Q", len(data)),
                    (_NEEDED + 8, "<Q", len(base) - _STRINGS))
    with pytest.raises(ValueError, match="lies outside DT_STRTAB/DT_STRSZ"):
        _facts(tmp_path, data)
    # The same bytes are accepted only when DT_STRSZ actually declares them.
    declared = _patched(data, (_STRSZ + 8, "<Q", len(data) - _STRINGS))
    assert _facts(tmp_path, declared)["needed"] == ["libevil.so"]


def test_loader_facts_rejects_a_string_that_runs_past_the_declared_table_size(tmp_path: Path) -> None:
    # "libc.so.6\0" continues in the file, but DT_STRSZ ends the table after "libc".
    with pytest.raises(ValueError, match="dynamic string is unterminated inside its owning structure"):
        _facts(tmp_path, _patched(minimal_elf(), (_STRSZ + 8, "<Q", 5)))


@pytest.mark.parametrize(("patches", "message"), [
    (((_STRSZ, "<q", 11),), "exactly one DT_STRTAB and one DT_STRSZ"),
    (((_STRSZ, "<q", 5),), "exactly one DT_STRTAB and one DT_STRSZ"),
    (((_STRSZ + 8, "<Q", 0),), "string table is empty"),
    (((_STRTAB + 8, "<Q", 0x10000),), "not backed by the file bytes of one loadable segment"),
    (((_STRSZ + 8, "<Q", 4096),), "not backed by the file bytes of one loadable segment"),
    (((_STRTAB + 8, "<Q", (1 << 64) - 4),), "not backed by the file bytes of one loadable segment"),
    (((_NEEDED + 8, "<Q", 0),), "library name is empty"),
    (((_NEEDED + 8, "<Q", (1 << 64) - 1),), "lies outside DT_STRTAB/DT_STRSZ"),
    (((_NULL, "<q", 21),), "no DT_NULL terminator"),
    (((_DYNAMIC_HEADER + 32, "<Q", 60),), "not a whole number of entries"),
    (((_DYNAMIC_HEADER + 32, "<Q", 0),), "not a whole number of entries"),
    (((_DYNAMIC_HEADER + 8, "<Q", 1 << 32),), "segment extends past the end of the file"),
    (((_DYNAMIC_HEADER + 8, "<Q", (1 << 64) - 8),), "segment extends past the end of the file"),
    (((_LOAD + 32, "<Q", 200),), "dynamic section is not contained in a loadable segment"),
    (((_LOAD + 40, "<Q", 1),), "file size exceeds its memory size"),
    (((_LOAD, "<I", 2),), "more than one dynamic segment"),
    (((_DYNAMIC_HEADER, "<I", 1), (_DYNAMIC_HEADER + 40, "<Q", 64)), "loadable segments overlap"),
    (((0x36, "<H", 64),), "program header table is invalid"),
    (((0x20, "<Q", 8),), "program header table is invalid"),
    (((0x20, "<Q", 1 << 40),), "past the end of the file"),
    (((0x34, "<H", 52),), "header size is inconsistent"),
    (((0x06, "<B", 0),), "identification is invalid"),
], ids=["no-strsz", "duplicate-strtab", "empty-table", "table-unmapped", "table-overruns-segment",
        "table-address-overflow", "empty-name", "offset-overflow", "no-terminator", "partial-entry",
        "empty-dynamic", "dynamic-past-file", "dynamic-offset-overflow", "dynamic-outside-load",
        "load-sizes", "duplicate-dynamic", "overlapping-loads", "entry-size", "table-in-header",
        "table-past-file", "header-size", "ident-version"])
def test_loader_facts_rejects_inconsistent_dynamic_structures(
        tmp_path: Path, patches: tuple[tuple[int, str, int], ...], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _facts(tmp_path, _patched(minimal_elf(), *patches))


def test_loader_facts_bounds_the_interpreter_to_its_segment(tmp_path: Path) -> None:
    # Re-purpose the second program header as PT_INTERP over the "libc.so.6\0" bytes.
    def interpreter(size: int) -> bytes:
        return _patched(minimal_elf(), (_DYNAMIC_HEADER, "<I", 3), (_DYNAMIC_HEADER + 8, "<Q", _STRINGS + 1),
                        (_DYNAMIC_HEADER + 32, "<Q", size))

    assert _facts(tmp_path, interpreter(10)) == {"needed": [], "interpreter": "libc.so.6", "soname": None,
                                                 "run_paths": [], "linkage": "static"}
    # One byte shorter and the terminator lies outside the segment, although it is in the file.
    with pytest.raises(ValueError, match="interpreter path is unterminated inside its owning structure"):
        _facts(tmp_path, interpreter(9))
    with pytest.raises(ValueError, match="interpreter segment size is invalid"):
        _facts(tmp_path, interpreter(1))
    with pytest.raises(ValueError, match="interpreter segment size is invalid"):
        _facts(tmp_path, _patched(interpreter(10), (_LOAD + 32, "<Q", 8192), (_LOAD + 40, "<Q", 8192),
                                  (_DYNAMIC_HEADER + 32, "<Q", 4097)) + bytes(8192))
    with pytest.raises(ValueError, match="interpreter path is empty"):
        _facts(tmp_path, _patched(interpreter(10), (_DYNAMIC_HEADER + 8, "<Q", _STRINGS)))


def test_loader_facts_reads_a_32_bit_big_endian_file(tmp_path: Path) -> None:
    strings = b"\0libz.so.1\0/opt/lib\0"
    header, program = 52, 32
    dynamic_offset = header + 2 * program
    string_offset = dynamic_offset + 5 * 8
    dynamic = (struct.pack(">iI", 1, 1) + struct.pack(">iI", 29, 11) + struct.pack(">iI", 5, string_offset) +
               struct.pack(">iI", 10, len(strings)) + struct.pack(">iI", 0, 0))
    size = string_offset + len(strings)
    ident = b"\x7fELF" + bytes([1, 2, 1, 0]) + bytes(8)
    elf_header = ident + struct.pack(">HHIIIIIHHHHHH", 3, 8, 1, 0, header, 0, 0, header, program, 2, 0, 0, 0)
    load = struct.pack(">IIIIIIII", 1, 0, 0, 0, size, size, 5, 4096)
    segment = struct.pack(">IIIIIIII", 2, dynamic_offset, dynamic_offset, dynamic_offset,
                          len(dynamic), len(dynamic), 6, 4)
    data = elf_header + load + segment + dynamic + strings
    assert _facts(tmp_path, data) == {"needed": ["libz.so.1"], "interpreter": None, "soname": None,
                                      "run_paths": ["/opt/lib"], "linkage": "dynamic"}
    with pytest.raises(ValueError, match="lies outside DT_STRTAB/DT_STRSZ"):
        _facts(tmp_path, _patched(data, (dynamic_offset + 4, ">I", len(strings))))
    with pytest.raises(ValueError):
        _facts(tmp_path, _patched(data, (string_offset + 1, ">B", 0xFF)))


def _split_load_elf(*, wide: bool = True, order: str = "<", loads: int = 2,
                    reverse_headers: bool = False, observed: bool = False,
                    boundary: str = "cross") -> tuple[bytes, dict[str, int]]:
    """Owned ELF bytes with a string table spanning constant-bias load mappings."""
    header, program, entry = (64, 56, 16) if wide else (52, 32, 8)
    count = loads + 1
    dynamic_offset = header + count * program
    string_offset = 0x5D8 if observed else dynamic_offset + 8 * entry
    names = (b"libasan.so.8", b"libc.so.6", b"libsample.so", b"$ORIGIN/lib", b"/opt/lib")
    strings = bytearray(b"\0")
    offsets = []
    if observed:
        strings = bytearray(42266)
        offsets = [1, 0x1000 - string_offset - 4, len(strings) - 64,
                   len(strings) - 48, len(strings) - 24]
        for offset, name in zip(offsets, names):
            strings[offset:offset + len(name) + 1] = name + b"\0"
    else:
        for name in names:
            offsets.append(len(strings))
            strings.extend(name + b"\0")
        strings.extend(bytes(16))
    bias = 0x3FF000
    tags = [(tag, offset) for tag, offset in zip((1, 1, 14, 15, 29), offsets)]
    tags.extend(((5, bias + string_offset), (10, len(strings)), (0, 0)))
    dynamic = b"".join(struct.pack(order + ("qQ" if wide else "iI"), *tag) for tag in tags)
    size = string_offset + len(strings)
    split = 0x1000 if observed else string_offset + 6
    if boundary == "table-ends-at-first-boundary":
        split, size = size, size + 1
    elif boundary == "table-starts-at-second-boundary":
        split = string_offset
    cuts = [0, split, *([string_offset + 18] if loads == 3 else []), size]
    extents = list(zip(cuts, cuts[1:]))
    if reverse_headers:
        extents.reverse()
    data = bytearray(size)
    data[:16] = b"\x7fELF" + bytes([2 if wide else 1, 1 if order == "<" else 2, 1, 0]) + bytes(8)
    struct.pack_into(order + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), data, 16,
                     3, 62 if wide else 3, 1, 0, header, 0, 0, header, program, count, 0, 0, 0)

    def segment(index: int, kind: int, offset: int, length: int) -> None:
        address = bias + offset
        if wide:
            struct.pack_into(order + "IIQQQQQQ", data, header + index * program,
                             kind, 5, offset, address, address, length, length, 4096)
        else:
            struct.pack_into(order + "IIIIIIII", data, header + index * program,
                             kind, offset, address, address, length, length, 5, 4096)

    for index, (start, end) in enumerate(extents):
        segment(index, 1, start, end - start)
    segment(loads, 2, dynamic_offset, len(dynamic))
    data[dynamic_offset:dynamic_offset + len(dynamic)] = dynamic
    data[string_offset:string_offset + len(strings)] = strings
    return bytes(data), {
        "first": header, "second": header + program, "split": split, "bias": bias,
        "strtab": dynamic_offset + 5 * entry + entry // 2, "strings": string_offset,
        "offset": 8 if wide else 4, "address": 16 if wide else 8,
        "filesz": 32 if wide else 16, "memsz": 40 if wide else 20,
    }


def _split_facts() -> dict:
    return {"needed": ["libasan.so.8", "libc.so.6"], "interpreter": None,
            "soname": "libsample.so", "run_paths": ["$ORIGIN/lib", "/opt/lib"], "linkage": "dynamic"}


def test_loader_facts_reads_observed_adjacent_mapping_shape(tmp_path: Path) -> None:
    data, layout = _split_load_elf(observed=True)
    assert layout["strings"] == 0x5D8 and layout["split"] == 0x1000
    assert layout["bias"] + layout["strings"] == 0x3FF5D8
    assert len(data) - layout["strings"] == 42266
    assert layout["bias"] + len(data) == 0x409AF2
    assert data[0xFFC:0x1006] == b"libc.so.6\0"
    assert _facts(tmp_path, data) == _split_facts()


@pytest.mark.parametrize(("wide", "order", "loads", "reverse"), [
    (False, "<", 2, False), (False, ">", 2, False),
    (True, "<", 2, False), (True, ">", 2, False),
    (True, "<", 3, False), (True, "<", 2, True),
], ids=["elf32-le", "elf32-be", "elf64-le", "elf64-be", "three-loads", "reordered-headers"])
def test_loader_facts_reads_string_table_across_adjacent_loads(
        tmp_path: Path, wide: bool, order: str, loads: int, reverse: bool) -> None:
    data, _layout = _split_load_elf(wide=wide, order=order, loads=loads, reverse_headers=reverse)
    assert _facts(tmp_path, data) == _split_facts()


@pytest.mark.parametrize("boundary", [
    "table-ends-at-first-boundary", "table-starts-at-second-boundary", "table-ends-at-file-end",
])
def test_loader_facts_accepts_exact_load_boundaries(tmp_path: Path, boundary: str) -> None:
    data, _layout = _split_load_elf(boundary=boundary)
    assert _facts(tmp_path, data) == _split_facts()


@pytest.mark.parametrize("defect", [
    "virtual-gap", "file-gap", "file-backward", "bss-bridge",
    "file-backed-overlap", "memory-overlap", "final-unbacked-byte", "segment-past-file",
    "request-overflow32", "request-overflow64", "load-overflow32", "load-overflow64",
])
def test_loader_facts_rejects_noncontiguous_string_table_mappings(tmp_path: Path, defect: str) -> None:
    wide = not defect.endswith("32")
    original, layout = _split_load_elf(wide=wide)
    data = bytearray(original)
    fmt = "<Q" if wide else "<I"
    first, second = layout["first"], layout["second"]

    def change(offset: int, delta: int) -> None:
        value, = struct.unpack_from(fmt, data, offset)
        struct.pack_into(fmt, data, offset, value + delta)

    message = "not mapped by a loadable segment"
    if defect == "virtual-gap":
        change(second + layout["address"], 1)
    elif defect == "file-gap":
        change(second + layout["offset"], 1)
        data.append(0)
    elif defect == "file-backward":
        change(second + layout["offset"], -1)
    elif defect == "bss-bridge":
        change(first + layout["filesz"], -1)
    elif defect == "file-backed-overlap":
        change(second + layout["address"], -1)
        message = "loadable segments overlap"
    elif defect == "memory-overlap":
        change(first + layout["memsz"], 1)
        message = "loadable segments overlap"
    elif defect == "final-unbacked-byte":
        change(second + layout["filesz"], -1)
        assert data[-16:] == bytes(16)  # Every named string still terminates before this unbacked tail.
    elif defect == "segment-past-file":
        change(second + layout["filesz"], 1)
        change(second + layout["memsz"], 1)
        message = "segment extends past the end of the file"
    else:
        limit = 1 << (64 if wide else 32)
        if defect.startswith("request-overflow"):
            struct.pack_into(fmt, data, layout["strtab"], limit - 4)
        else:
            address, = struct.unpack_from(fmt, data, second + layout["address"])
            struct.pack_into(fmt, data, second + layout["memsz"], limit - address + 1)
        message = "overflows ELF address space"
    assert data[layout["strings"]:layout["strings"] + 14] == b"\0libasan.so.8\0"
    with pytest.raises(ValueError, match=message):
        _facts(tmp_path, bytes(data))


def test_catalog_resolves_dependencies_across_adjacent_loads(tmp_path: Path) -> None:
    data, _layout = _split_load_elf()
    (tmp_path / "app").write_bytes(data)
    artifacts, gaps = _catalog(tmp_path, tmp_path, {}, 100, "build-unit-fixture")
    assert len(artifacts) == 1
    assert artifacts[0]["loader_dependencies"] == ["libasan.so.8", "libc.so.6"]
    assert artifacts[0]["loader_dependency_status"] == "resolved"
    assert artifacts[0]["loader_parser"] == elf.PARSER_IDENTITY
    assert all("delivery_fact_unavailable" in gap for gap in gaps)


def test_file_offset_separates_elf32_virtual_and_physical_bounds() -> None:
    limit = 1 << 32
    segment = elf.Segment(kind=1, offset=limit - 8, address=0x1000, file_size=32, memory_size=32)
    image = elf.Image(wide=False, order="<", file_size=limit + 24, header_size=52,
                      segments=(segment,), section_offset=0, section_entry_size=0,
                      section_count=0, section_names_index=0)
    assert elf._file_offset(image, 0x1004, 28, "test table") == limit - 4
    assert elf._file_offset(image, 0x1010, 8, "test table") == limit + 8
    with pytest.raises(ValueError, match="load file range is out of bounds"):
        elf._file_offset(replace(image, file_size=image.file_size - 1), 0x1004, 28, "test table")
    with pytest.raises(ValueError, match="requested range overflows ELF address space"):
        elf._file_offset(image, limit - 4, 8, "test table")
    overflowing = replace(image, segments=(replace(segment, address=limit - 16),))
    with pytest.raises(ValueError, match="load range overflows ELF address space"):
        elf._file_offset(overflowing, limit - 8, 4, "test table")


def test_adjacent_loads_supply_real_sanitizer_runtime_evidence(tmp_path: Path) -> None:
    from appsec_review.jobs.job_sanitizer_build.evidence import runtime_evidence

    data, _layout = _split_load_elf()
    path = tmp_path / "app"
    path.write_bytes(data)
    evidence = runtime_evidence(path, "executable")
    assert evidence["evidence_status"] == "resolved"
    assert evidence["needed_libraries"] == ["libasan.so.8", "libc.so.6"]
    assert evidence["sanitizers"]["address"]["runtime_libraries"] == ["libasan.so.8"]
    assert evidence["sanitizers"]["address"]["runtime_referenced"] is True
    assert evidence["sanitizers"]["undefined"]["runtime_referenced"] is False
