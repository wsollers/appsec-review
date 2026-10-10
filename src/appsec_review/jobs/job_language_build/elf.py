"""Bounded, dependency-free reader for the loader facts of one ELF file.

Only the program headers and the dynamic section are read. Nothing is loaded, relocated, or
executed, and every count and string is bounded, so a hostile build output cannot make the
catalog allocate or scan without limit.
"""

from __future__ import annotations

from pathlib import Path
import struct
from typing import Any, BinaryIO


PARSER_IDENTITY = "appsec-review/elf-loader-dependencies/1"
_PT_LOAD, _PT_DYNAMIC, _PT_INTERP = 1, 2, 3
_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_STRSZ, _DT_SONAME, _DT_RPATH, _DT_RUNPATH = 0, 1, 5, 10, 14, 15, 29
_PROGRAM_HEADER_LIMIT = 4096
_DYNAMIC_ENTRY_LIMIT = 65536
_NEEDED_LIMIT = 1024
_STRING_LIMIT = 4096


def _read(stream: BinaryIO, offset: int, size: int) -> bytes:
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("ELF structure extends past the end of the file")
    return data


def _string(stream: BinaryIO, offset: int, available: int) -> str:
    """Read one NUL-terminated string that lies wholly inside `available` declared bytes."""
    if available <= 0:
        raise ValueError("ELF string lies outside its declared region")
    stream.seek(offset)
    data = stream.read(min(available, _STRING_LIMIT))
    end = data.find(b"\0")
    if end < 0:
        raise ValueError("ELF string is unterminated within its declared region or exceeds its bound")
    return data[:end].decode("utf-8", "replace")


def loader_facts(path: Path) -> dict[str, Any]:
    """Return DT_NEEDED and related loader facts; raise ValueError for a malformed file."""
    with path.open("rb") as stream:
        file_size = path.stat().st_size
        ident = stream.read(16)
        if (len(ident) != 16 or ident[:4] != b"\x7fELF" or ident[4] not in (1, 2) or
                ident[5] not in (1, 2) or ident[6] != 1):
            raise ValueError("ELF identification is invalid")
        wide, order = ident[4] == 2, "<" if ident[5] == 1 else ">"
        if wide:
            program_offset, = struct.unpack(order + "Q", _read(stream, 0x20, 8))
            header_size, = struct.unpack(order + "H", _read(stream, 0x34, 2))
            entry_size, count = struct.unpack(order + "HH", _read(stream, 0x36, 4))
            minimum, minimum_header = 56, 64
        else:
            program_offset, = struct.unpack(order + "I", _read(stream, 0x1C, 4))
            header_size, = struct.unpack(order + "H", _read(stream, 0x28, 2))
            entry_size, count = struct.unpack(order + "HH", _read(stream, 0x2A, 4))
            minimum, minimum_header = 32, 52
        table_size = count * entry_size
        table_end = program_offset + table_size
        if (header_size < minimum_header or header_size > file_size or count > _PROGRAM_HEADER_LIMIT or
                (count and entry_size < minimum) or
                (count and (program_offset < header_size or table_end > file_size))):
            raise ValueError("ELF program header table is invalid")
        loads: list[tuple[int, int, int]] = []
        dynamic: tuple[int, int] | None = None
        interpreter: str | None = None
        for index in range(count):
            raw = _read(stream, program_offset + index * entry_size, minimum)
            if wide:
                kind, _flags, offset, address, _physical, size = struct.unpack(order + "IIQQQQ", raw[:40])
            else:
                kind, offset, address, _physical, size, memory_size = struct.unpack(order + "IIIIII", raw[:24])
            if wide:
                memory_size, = struct.unpack(order + "Q", raw[40:48])
            end = offset + size
            if end > file_size or memory_size < size:
                raise ValueError("ELF segment extends past the end of the file or has an invalid size")
            if kind == _PT_LOAD:
                loads.append((address, offset, size))
            elif kind == _PT_DYNAMIC:
                if dynamic is not None:
                    raise ValueError("ELF contains multiple dynamic sections")
                if size == 0 or size % (16 if wide else 8):
                    raise ValueError("ELF dynamic section size is invalid")
                if not (end <= program_offset or offset >= table_end):
                    raise ValueError("ELF dynamic section overlaps the program header table")
                dynamic = (offset, size)
            elif kind == _PT_INTERP:
                if interpreter is not None:
                    raise ValueError("ELF contains multiple interpreter segments")
                if not (end <= program_offset or offset >= table_end):
                    raise ValueError("ELF interpreter overlaps the program header table")
                interpreter = _string(stream, offset, size)
        facts: dict[str, Any] = {"needed": [], "interpreter": interpreter, "soname": None,
                                 "run_paths": [], "linkage": "static" if dynamic is None else "dynamic"}
        if dynamic is None:
            return facts
        width = 16 if wide else 8
        entries = dynamic[1] // width
        if entries > _DYNAMIC_ENTRY_LIMIT:
            raise ValueError("ELF dynamic section exceeds its bound")
        tags: list[tuple[int, int]] = []
        terminated = False
        for index in range(entries):
            tag, value = struct.unpack(order + ("qQ" if wide else "iI"),
                                       _read(stream, dynamic[0] + index * width, width))
            if tag == _DT_NULL:
                terminated = True
                break
            tags.append((tag, value))
        if not terminated:
            raise ValueError("ELF dynamic section is not terminated")
        named = [item for item in tags if item[0] in (_DT_NEEDED, _DT_SONAME, _DT_RPATH, _DT_RUNPATH)]
        if not named:
            return facts
        tables = [value for tag, value in tags if tag == _DT_STRTAB]
        table_sizes = [value for tag, value in tags if tag == _DT_STRSZ]
        if not tables or not table_sizes:
            raise ValueError("ELF dynamic string table address or size is missing")
        if len(tables) != 1 or len(table_sizes) != 1:
            raise ValueError("ELF dynamic string table address or size is inconsistent")
        table, table_size = tables[0], table_sizes[0]
        if table is None or not table_size:
            raise ValueError("ELF dynamic string table address or size is missing")
        # The whole declared table, not just its first byte, must be file-backed by one segment.
        base = next((offset + table - address for address, offset, size in loads
                     if address <= table and table + table_size <= address + size), None)
        if base is None:
            raise ValueError("ELF dynamic string table is not mapped by a loadable segment")
        if sum(1 for tag, _value in named if tag == _DT_NEEDED) > _NEEDED_LIMIT:
            raise ValueError("ELF dependency count exceeds its bound")
        for tag, value in named:
            text = _string(stream, base + value, table_size - value)
            if tag == _DT_NEEDED:
                facts["needed"].append(text)
            elif tag == _DT_SONAME:
                facts["soname"] = text
            else:
                facts["run_paths"].append(text)
        return facts
