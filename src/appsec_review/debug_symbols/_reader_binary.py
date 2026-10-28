"""Small bounded identity readers; recorded companion/source paths are never followed."""
from __future__ import annotations

from dataclasses import dataclass
import struct
import zlib


class ReaderFailure(Exception):
    def __init__(self, gap: str):
        self.gap = gap
        super().__init__(gap)


def take(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ReaderFailure("malformed_input")
    return data[offset:offset + size]


def unpack(fmt: str, data: bytes, offset: int):
    return struct.unpack(fmt, take(data, offset, struct.calcsize(fmt)))


@dataclass(frozen=True)
class Elf:
    sections: dict[str, bytes]
    build_ids: tuple[bytes, ...]
    debug_crc: int | None


def elf(data: bytes, max_rows: int) -> Elf:
    if take(data, 0, 4) != b"\x7fELF":
        raise ReaderFailure("unsupported_binary_format")
    cls, encoding, version = take(data, 4, 3)
    if cls not in (1, 2) or encoding not in (1, 2) or version != 1:
        raise ReaderFailure("unsupported_elf_format")
    endian = "<" if encoding == 1 else ">"
    if cls == 2:
        take(data, 0, 64)
        section_offset, = unpack(endian + "Q", data, 40)
        section_size, count, string_index = unpack(endian + "HHH", data, 58)
        fmt = endian + "IIQQQQIIQQ"
    else:
        take(data, 0, 52)
        section_offset, = unpack(endian + "I", data, 32)
        section_size, count, string_index = unpack(endian + "HHH", data, 46)
        fmt = endian + "IIIIIIIIII"
    if not count or string_index == 0xffff:
        raise ReaderFailure("unsupported_elf_extended_sections")
    if count > max_rows:
        raise ReaderFailure("record_limit")
    if section_size < struct.calcsize(fmt) or string_index >= count:
        raise ReaderFailure("malformed_input")
    take(data, section_offset, section_size * count)
    headers = [unpack(fmt, data, section_offset + i * section_size) for i in range(count)]
    strings = take(data, headers[string_index][4], headers[string_index][5])
    sections: dict[str, bytes] = {}
    build_ids: list[bytes] = []
    debug_crc = None
    content_bytes = note_rows = 0
    for header in headers:
        name_offset, kind = header[:2]
        if name_offset >= len(strings):
            raise ReaderFailure("malformed_input")
        end = strings.find(b"\0", name_offset)
        if end < 0:
            raise ReaderFailure("malformed_input")
        name = strings[name_offset:end].decode("ascii", "replace")
        if kind == 8:  # SHT_NOBITS occupies no file bytes.
            continue
        content_bytes += header[5]
        if content_bytes > len(data):
            raise ReaderFailure("malformed_input")
        contents = take(data, header[4], header[5])
        if name in sections:
            raise ReaderFailure("ambiguous_elf_sections")
        sections[name] = contents
        if kind == 7:
            pos = 0
            while pos < len(contents):
                note_rows += 1
                if note_rows > max_rows:
                    raise ReaderFailure("record_limit")
                namesz, descsz, note_type = unpack(endian + "III", contents, pos)
                pos += 12
                owner = take(contents, pos, namesz)
                pos += (namesz + 3) & ~3
                description = take(contents, pos, descsz)
                pos += (descsz + 3) & ~3
                if owner.rstrip(b"\0") == b"GNU" and note_type == 3:
                    build_ids.append(description)
        if name == ".gnu_debuglink":
            end = contents.find(b"\0")
            if end < 1:
                raise ReaderFailure("malformed_input")
            debug_crc, = unpack(endian + "I", contents, (end + 4) & ~3)
    return Elf(sections, tuple(build_ids), debug_crc)


def verify_elf(binary: bytes, companion: bytes | None, max_rows: int) -> Elf:
    image = elf(binary, max_rows)
    if ".debug_sup" in image.sections or ".gnu_debugaltlink" in image.sections:
        raise ReaderFailure("dwarf_supplementary_unavailable")
    if companion is None:
        if ".debug_info.dwo" in image.sections or ".debug_cu_index" in image.sections:
            raise ReaderFailure("split_dwarf_unavailable")
        if ".debug_info" not in image.sections and ".zdebug_info" not in image.sections:
            raise ReaderFailure("dwarf_missing")
        return image
    debug = elf(companion, max_rows)
    if ".debug_sup" in debug.sections or ".gnu_debugaltlink" in debug.sections:
        raise ReaderFailure("dwarf_supplementary_unavailable")
    if len(image.build_ids) > 1 or len(debug.build_ids) > 1:
        raise ReaderFailure("ambiguous_build_id")
    verified = False
    if image.build_ids and debug.build_ids:
        if image.build_ids != debug.build_ids:
            raise ReaderFailure("elf_build_id_mismatch")
        verified = True
    if image.debug_crc is not None:
        if zlib.crc32(companion) != image.debug_crc:
            raise ReaderFailure("elf_debuglink_mismatch")
        verified = True
    if not verified:
        raise ReaderFailure("elf_pairing_unavailable")
    if ".debug_info" not in debug.sections and ".zdebug_info" not in debug.sections:
        raise ReaderFailure("dwarf_missing")
    return debug


@dataclass(frozen=True)
class Pe:
    guid: bytes
    age: int
    sections: tuple[tuple[int, int, int, int], ...]

    def rva(self, segment: int, offset: int, size: int) -> int:
        if type(segment) is not int or not 1 <= segment <= len(self.sections):
            raise ReaderFailure("pdb_invalid_section")
        va, virtual_size, _, raw_size = self.sections[segment - 1]
        if (type(offset) is not int or type(size) is not int or offset < 0 or size < 0
                or offset + size > max(virtual_size, raw_size)):
            raise ReaderFailure("pdb_invalid_address")
        result = va + offset
        if result + size > 2**64:
            raise ReaderFailure("pdb_invalid_address")
        return result


def pe(data: bytes, max_rows: int) -> Pe:
    if take(data, 0, 2) != b"MZ":
        raise ReaderFailure("unsupported_binary_format")
    pointer, = unpack("<I", data, 60)
    if take(data, pointer, 4) != b"PE\0\0":
        raise ReaderFailure("malformed_input")
    count, = unpack("<H", data, pointer + 6)
    optional_size, = unpack("<H", data, pointer + 20)
    if not 0 < count <= max_rows:
        raise ReaderFailure("record_limit")
    optional = take(data, pointer + 24, optional_size)
    magic, = unpack("<H", optional, 0)
    if magic not in (0x10b, 0x20b):
        raise ReaderFailure("unsupported_pe_format")
    directories = 96 if magic == 0x10b else 112
    directory_count, = unpack("<I", optional, directories - 4)
    if directory_count <= 6:
        raise ReaderFailure("pe_codeview_missing")
    debug_rva, debug_size = unpack("<II", optional, directories + 6 * 8)
    if not debug_rva or not debug_size:
        raise ReaderFailure("pe_codeview_missing")
    sections = []
    for i in range(count):
        header = pointer + 24 + optional_size + i * 40
        take(data, header, 40)
        virtual_size, va, raw_size, raw_pointer = unpack("<IIII", data, header + 8)
        take(data, raw_pointer, raw_size)
        sections.append((va, virtual_size, raw_pointer, raw_size))

    def file_offset(rva: int, size: int) -> int:
        matches = [raw + rva - va for va, _, raw, raw_size in sections
                   if va <= rva and rva + size <= va + raw_size]
        if len(matches) != 1:
            raise ReaderFailure("malformed_input")
        return matches[0]

    if debug_size % 28 or debug_size // 28 > max_rows:
        raise ReaderFailure("malformed_input")
    directory = file_offset(debug_rva, debug_size)
    identities = []
    for i in range(debug_size // 28):
        _, _, _, _, kind, size, address, raw = unpack("<IIHHIIII", data, directory + i * 28)
        if kind != 2:
            continue
        info = take(data, raw if raw else file_offset(address, size), size)
        if info[:4] != b"RSDS":
            raise ReaderFailure("unsupported_codeview_identity")
        if len(info) < 25 or not info.endswith(b"\0"):
            raise ReaderFailure("malformed_input")
        identities.append((take(info, 4, 16), unpack("<I", info, 20)[0]))
    if not identities:
        raise ReaderFailure("pe_codeview_missing")
    if len(identities) != 1:
        raise ReaderFailure("ambiguous_codeview_identity")
    return Pe(*identities[0], tuple(sections))


def pdb_identity(data: bytes, max_rows: int) -> tuple[bytes, int]:
    if take(data, 0, 32) != b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0":
        raise ReaderFailure("unsupported_pdb_format")
    block_size, _, block_count, directory_size, _, block_map = unpack("<IIIIII", data, 32)
    if (block_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768)
            or block_count * block_size > len(data) or directory_size > len(data)):
        raise ReaderFailure("malformed_input")
    directory_blocks = (directory_size + block_size - 1) // block_size
    # MSF's single-level directory block map must fit in one block.
    if directory_blocks * 4 > block_size:
        raise ReaderFailure("unsupported_pdb_directory")

    def block(number: int) -> bytes:
        if not 0 <= number < block_count:
            raise ReaderFailure("malformed_input")
        return take(data, number * block_size, block_size)

    indices = unpack("<" + "I" * directory_blocks, block(block_map), 0)
    directory = b"".join(block(number) for number in indices)[:directory_size]
    count, = unpack("<I", directory, 0)
    if count < 2 or count > max_rows:
        raise ReaderFailure("record_limit")
    sizes = unpack("<" + "I" * count, directory, 4)
    position = 4 + count * 4
    info = b""
    for index, size in enumerate(sizes):
        blocks = 0 if size == 0xffffffff else (size + block_size - 1) // block_size
        if blocks > block_count:
            raise ReaderFailure("malformed_input")
        stream_blocks = unpack("<" + "I" * blocks, directory, position)
        position += blocks * 4
        if index == 1:
            if size < 28 or not stream_blocks:
                raise ReaderFailure("malformed_input")
            info = block(stream_blocks[0])[:28]
    _, _, age = unpack("<III", info, 0)
    return take(info, 12, 16), age
