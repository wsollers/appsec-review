"""Bounded, dependency-free reader for the loader facts of one ELF file.

A build output is hostile input. Only the ELF header, the program headers, the dynamic section,
and, on request, the section header table are read. Nothing is loaded, relocated, or executed.
Every offset, size, count, and terminator is checked against the structure that owns it before a
fact is returned: a dynamic string is read from inside DT_STRTAB/DT_STRSZ, never from wherever
in the file its offset happens to land. Any violation raises ``ValueError`` so the catalog
reports the file as unparsed instead of publishing a partial reading.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import struct
from typing import Any, BinaryIO


PARSER_IDENTITY = "appsec-review/elf-loader-dependencies/2"
_PT_LOAD, _PT_DYNAMIC, _PT_INTERP = 1, 2, 3
_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_STRSZ = 0, 1, 5, 10
_DT_SONAME, _DT_RPATH, _DT_RUNPATH = 14, 15, 29
_SHT_NULL, _SHT_STRTAB, _SHT_NOBITS = 0, 3, 8
_PROGRAM_HEADER_LIMIT = 4096
_SECTION_HEADER_LIMIT = 8192
_DYNAMIC_ENTRY_LIMIT = 65536
_NEEDED_LIMIT = 1024
_STRING_LIMIT = 4096
_SECTION_NAME_LIMIT = 256


@dataclass(frozen=True, slots=True)
class Segment:
    kind: int
    offset: int
    address: int
    file_size: int
    memory_size: int


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    kind: int
    flags: int
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class Image:
    """A validated ELF header and program header table."""

    wide: bool
    order: str
    file_size: int
    header_size: int
    segments: tuple[Segment, ...]
    section_offset: int
    section_entry_size: int
    section_count: int
    section_names_index: int


def read_exact(stream: BinaryIO, offset: int, size: int, file_size: int) -> bytes:
    """Read ``size`` bytes at ``offset`` only when the whole range lies inside the file."""
    if offset < 0 or size < 0 or offset + size > file_size:
        raise ValueError("ELF structure extends past the end of the file")
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("ELF structure extends past the end of the file")
    return data


def read_image(stream: BinaryIO) -> Image:
    file_size = os.fstat(stream.fileno()).st_size
    stream.seek(0)
    ident = stream.read(16)
    if (len(ident) != 16 or ident[:4] != b"\x7fELF" or ident[4] not in (1, 2) or
            ident[5] not in (1, 2) or ident[6] != 1):
        raise ValueError("ELF identification is invalid")
    wide, order = ident[4] == 2, "<" if ident[5] == 1 else ">"
    header_size, program_size, section_size = (64, 56, 64) if wide else (52, 32, 40)
    header = read_exact(stream, 0, header_size, file_size)
    if wide:
        program_offset, section_offset = struct.unpack_from(order + "QQ", header, 0x20)
        (declared_header, program_entry, program_count, section_entry, section_count,
         names_index) = struct.unpack_from(order + "HHHHHH", header, 0x34)
    else:
        program_offset, section_offset = struct.unpack_from(order + "II", header, 0x1C)
        (declared_header, program_entry, program_count, section_entry, section_count,
         names_index) = struct.unpack_from(order + "HHHHHH", header, 0x28)
    if declared_header != header_size:
        raise ValueError("ELF program header table is invalid: header size is inconsistent with its class")
    if program_count > _PROGRAM_HEADER_LIMIT:
        raise ValueError("ELF program header table exceeds its bound")
    segments: list[Segment] = []
    if program_count:
        if program_entry != program_size or program_offset < header_size:
            raise ValueError("ELF program header table is invalid")
        table = read_exact(stream, program_offset, program_count * program_size, file_size)
        for index in range(program_count):
            if wide:
                kind, _flags, offset, address, _physical, size, memory = struct.unpack_from(
                    order + "IIQQQQQ", table, index * program_size)
            else:
                kind, offset, address, _physical, size, memory = struct.unpack_from(
                    order + "IIIIII", table, index * program_size)
            if offset + size > file_size:
                raise ValueError("ELF segment extends past the end of the file")
            if kind == _PT_LOAD and size > memory:
                raise ValueError("ELF segment has an invalid size: file size exceeds its memory size")
            segments.append(Segment(kind, offset, address, size, memory))
    loads = sorted((item.address, item.address + item.memory_size) for item in segments
                   if item.kind == _PT_LOAD and item.memory_size)
    if any(later[0] < earlier[1] for earlier, later in zip(loads, loads[1:])):
        raise ValueError("ELF loadable segments overlap")
    for kind, label in ((_PT_DYNAMIC, "dynamic"), (_PT_INTERP, "interpreter")):
        if sum(1 for item in segments if item.kind == kind) > 1:
            raise ValueError(f"ELF declares more than one {label} segment")
    return Image(wide, order, file_size, header_size, tuple(segments), section_offset,
                 section_entry, section_count, names_index)


def _terminated(data: bytes, what: str) -> str:
    end = data.find(b"\0")
    if end < 0:
        raise ValueError(
            f"ELF {what} is unterminated inside its owning structure; "
            "unterminated within its declared region"
        )
    return data[:end].decode("utf-8")


def _file_offset(image: Image, address: int, size: int, what: str) -> int:
    """Translate a virtual range to file bytes; it must lie wholly in one segment's file image."""
    for segment in image.segments:
        if (segment.kind == _PT_LOAD and segment.address <= address and
                address + size <= segment.address + segment.file_size):
            return segment.offset + address - segment.address
    raise ValueError(
        f"ELF {what} is not backed by the file bytes of one loadable segment; "
        "not mapped by a loadable segment"
    )


def loader_facts(path: Path) -> dict[str, Any]:
    """Return DT_NEEDED and related loader facts; raise ValueError for a malformed file."""
    with path.open("rb") as stream:
        image = read_image(stream)
        interpreter: str | None = None
        dynamic: Segment | None = None
        for segment in image.segments:
            if segment.kind == _PT_INTERP:
                if not 1 < segment.file_size <= _STRING_LIMIT:
                    raise ValueError("ELF interpreter segment size is invalid")
                interpreter = _terminated(read_exact(
                    stream, segment.offset, segment.file_size, image.file_size), "interpreter path")
                if not interpreter:
                    raise ValueError("ELF interpreter path is empty")
            elif segment.kind == _PT_DYNAMIC:
                dynamic = segment
        facts: dict[str, Any] = {"needed": [], "interpreter": interpreter, "soname": None,
                                 "run_paths": [], "linkage": "static" if dynamic is None else "dynamic"}
        if dynamic is None:
            return facts
        width = 16 if image.wide else 8
        if dynamic.file_size == 0 or dynamic.file_size % width:
            raise ValueError("ELF dynamic section size is not a whole number of entries")
        if dynamic.file_size // width > _DYNAMIC_ENTRY_LIMIT:
            raise ValueError("ELF dynamic section exceeds its bound")
        if not any(item.kind == _PT_LOAD and item.offset <= dynamic.offset and
                   dynamic.offset + dynamic.file_size <= item.offset + item.file_size
                   for item in image.segments):
            raise ValueError("ELF dynamic section is not contained in a loadable segment")
        raw = read_exact(stream, dynamic.offset, dynamic.file_size, image.file_size)
        tags: list[tuple[int, int]] = []
        terminated = False
        for index in range(dynamic.file_size // width):
            tag, value = struct.unpack_from(image.order + ("qQ" if image.wide else "iI"), raw, index * width)
            if tag == _DT_NULL:
                terminated = True
                break
            tags.append((tag, value))
        if not terminated:
            raise ValueError("ELF dynamic section has no DT_NULL terminator; dynamic section is not terminated")
        named = [item for item in tags if item[0] in (_DT_NEEDED, _DT_SONAME, _DT_RPATH, _DT_RUNPATH)]
        if not named:
            return facts
        tables = [value for tag, value in tags if tag == _DT_STRTAB]
        sizes = [value for tag, value in tags if tag == _DT_STRSZ]
        if len(tables) != 1 or len(sizes) != 1:
            raise ValueError(
                "ELF dynamic string table address or size is missing or inconsistent; "
                "exactly one DT_STRTAB and one DT_STRSZ is required"
            )
        table, table_size = tables[0], sizes[0]
        if table_size == 0:
            raise ValueError("ELF dynamic string table is empty")
        base = _file_offset(image, table, table_size, "dynamic string table")
        if sum(1 for tag, _value in named if tag == _DT_NEEDED) > _NEEDED_LIMIT:
            raise ValueError("ELF dependency count exceeds its bound")
        if sum(1 for tag, _value in named if tag == _DT_SONAME) > 1:
            raise ValueError("ELF dynamic section declares more than one DT_SONAME")
        for tag, value in named:
            if value >= table_size:
                raise ValueError(
                    "ELF dynamic string offset lies outside DT_STRTAB/DT_STRSZ and "
                    "outside its declared region"
                )
            text = _terminated(read_exact(stream, base + value, min(_STRING_LIMIT, table_size - value),
                                          image.file_size), "dynamic string")
            if tag in (_DT_NEEDED, _DT_SONAME) and not text:
                raise ValueError("ELF dynamic library name is empty")
            if tag == _DT_NEEDED:
                facts["needed"].append(text)
            elif tag == _DT_SONAME:
                facts["soname"] = text
            else:
                facts["run_paths"].append(text)
        return facts


def read_sections(stream: BinaryIO, image: Image) -> tuple[Section, ...]:
    """Return the validated section header table; names resolve inside the section-name table."""
    if image.section_count == 0:
        if image.section_offset:
            raise ValueError("ELF extended section numbering is unsupported")
        return ()
    entry = 64 if image.wide else 40
    if (image.section_count > _SECTION_HEADER_LIMIT or image.section_entry_size != entry or
            image.section_offset < image.header_size or
            not 0 < image.section_names_index < image.section_count):
        raise ValueError("ELF section header table is invalid")
    table = read_exact(stream, image.section_offset, image.section_count * entry, image.file_size)
    rows: list[tuple[int, int, int, int, int]] = []
    for index in range(image.section_count):
        if image.wide:
            name, kind, flags, _address, offset, size = struct.unpack_from(
                image.order + "IIQQQQ", table, index * entry)
        else:
            name, kind, flags, _address, offset, size = struct.unpack_from(
                image.order + "IIIIII", table, index * entry)
        if kind not in (_SHT_NULL, _SHT_NOBITS) and offset + size > image.file_size:
            raise ValueError("ELF section extends past the end of the file")
        rows.append((name, kind, flags, offset, size))
    _name, names_kind, _flags, names_offset, names_size = rows[image.section_names_index]
    if names_kind != _SHT_STRTAB or names_size == 0:
        raise ValueError("ELF section-name table is invalid")
    sections = []
    for name, kind, flags, offset, size in rows:
        if name >= names_size:
            raise ValueError("ELF section name lies outside the section-name table")
        text = _terminated(read_exact(stream, names_offset + name,
                                      min(_SECTION_NAME_LIMIT, names_size - name), image.file_size),
                           "section name")
        sections.append(Section(text, kind, flags, offset, size))
    return tuple(sections)
