"""Bounded native CodeView inline annotations omitted by LLVM 18 pdb2yaml.

Format references: Microsoft's cvinfo.h (BinaryAnnotationOpcode/INLINESITESYM),
and LLVM 18's RawTypes.h, SymbolRecord.h and NativeFunctionSymbol.cpp. These
describe MSF/DBI layouts, compressed operands and procedure-relative offsets.
No names, source files, URLs, external streams or executable code are followed.
"""
from __future__ import annotations

from dataclasses import dataclass

from appsec_review.debug_symbols._reader_binary import ReaderFailure, take, unpack
from appsec_review.debug_symbols.contract import AddressRange


def decode_inline_ranges(data: bytes, *, procedure_size: int, max_records: int) -> tuple[AddressRange, ...]:
    """Decode common main-chunk annotations, retaining only complete intervals."""
    position = cursor = operations = 0
    pending = None
    ranges: list[AddressRange] = []

    def integer():
        nonlocal position
        if position >= len(data):
            raise ReaderFailure("inline_annotations_malformed")
        first = data[position]
        position += 1
        if first < 0x80:
            return first
        width = 2 if first < 0xc0 else 4 if first < 0xe0 else 0
        if not width or position + width - 1 > len(data):
            raise ReaderFailure("inline_annotations_malformed")
        value = first & (0x3f if width == 2 else 0x1f)
        for byte in data[position:position + width - 1]:
            value = (value << 8) | byte
        position += width - 1
        return value

    def emit(start, end):
        if not 0 <= start < end <= procedure_size:
            raise ReaderFailure("inline_annotation_address_invalid")
        if ranges and start < ranges[-1].end:
            raise ReaderFailure("inline_annotation_ranges_ambiguous")
        if ranges and start == ranges[-1].end:
            ranges[-1] = AddressRange(ranges[-1].start, end)
        else:
            ranges.append(AddressRange(start, end))
        if len(ranges) > max_records:
            raise ReaderFailure("record_limit")

    def advance(delta):
        nonlocal cursor, pending
        new = cursor + delta
        if new > procedure_size:
            raise ReaderFailure("inline_annotation_address_invalid")
        # Without an explicit length, the next start terminates the prior row.
        if pending is not None and pending < new:
            emit(pending, new)
        cursor = pending = new

    while position < len(data):
        start = position
        opcode = integer()
        operations += 1
        if operations > max_records:
            raise ReaderFailure("record_limit")
        if opcode == 0:
            if len(data) - start > 3 or any(data[start:]):
                raise ReaderFailure("inline_annotations_malformed")
            break
        if opcode > 13:
            raise ReaderFailure("inline_annotation_opcode_unsupported")
        operand = integer()
        if opcode in (1, 3, 11):
            if opcode == 1 and (pending is not None or cursor):
                raise ReaderFailure("inline_annotation_ranges_ambiguous")
            advance(operand & 15 if opcode == 11 else operand)
        elif opcode == 4:
            if pending is None or operand == 0:
                raise ReaderFailure("inline_annotation_ranges_ambiguous")
            emit(pending, cursor + operand)
            # ChangeCodeLength advances the cursor; the combined opcode below
            # does not. This distinction matters for disjoint inline regions.
            cursor += operand
            pending = None
        elif opcode == 12:
            delta = integer()
            advance(delta)
            if operand == 0:
                raise ReaderFailure("inline_annotation_ranges_ambiguous")
            emit(cursor, cursor + operand)
            pending = None
        elif opcode == 2:
            # Operand is a separated-code chunk index, NOT an RVA delta.
            if operand:
                raise ReaderFailure("inline_separated_code_unavailable")
            if cursor or pending is not None:
                raise ReaderFailure("inline_annotation_ranges_ambiguous")
        elif opcode == 8 and operand not in (0, 1):
            raise ReaderFailure("inline_annotations_malformed")
        # Other documented operands change file/line/column state, not address
        # membership. SourceSpan remains explicitly the inlinee's definition.
    if pending is not None or not ranges:
        raise ReaderFailure("inline_annotation_ranges_ambiguous")
    return tuple(ranges)


class _MsfStreams:
    def __init__(self, data: bytes, max_records: int):
        self.data = data
        self.block_size, _, self.block_count, directory_size, _, block_map = unpack("<IIIIII", data, 32)
        if (self.block_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768)
                or self.block_count * self.block_size > len(data) or directory_size > len(data)):
            raise ReaderFailure("inline_native_data_malformed")
        count = (directory_size + self.block_size - 1) // self.block_size
        if count * 4 > self.block_size:
            raise ReaderFailure("inline_native_format_unsupported")
        numbers = unpack("<" + "I" * count, self.block(block_map), 0)
        directory = b"".join(self.block(number) for number in numbers)[:directory_size]
        stream_count, = unpack("<I", directory, 0)
        if stream_count > max_records:
            raise ReaderFailure("record_limit")
        sizes = unpack("<" + "I" * stream_count, directory, 4)
        position = 4 + stream_count * 4
        self.streams = []
        for size in sizes:
            count = 0 if size == 0xffffffff else (size + self.block_size - 1) // self.block_size
            if count > self.block_count:
                raise ReaderFailure("inline_native_data_malformed")
            numbers = unpack("<" + "I" * count, directory, position)
            self.streams.append((size, numbers))
            position += count * 4

    def block(self, number):
        if not 0 <= number < self.block_count:
            raise ReaderFailure("inline_native_data_malformed")
        return take(self.data, number * self.block_size, self.block_size)

    def read(self, index, prefix=None):
        if not 0 <= index < len(self.streams):
            raise ReaderFailure("inline_native_data_malformed")
        size, numbers = self.streams[index]
        if size == 0xffffffff or prefix is not None and prefix > size:
            raise ReaderFailure("inline_native_data_malformed")
        size = size if prefix is None else prefix
        count = (size + self.block_size - 1) // self.block_size
        return b"".join(self.block(number) for number in numbers[:count])[:size]


@dataclass(frozen=True)
class _Record:
    index: int
    offset: int
    kind: int
    data: bytes


@dataclass(frozen=True)
class NativeInline:
    record_offset: int
    parent_index: int
    procedure_index: int
    procedure: dict[str, int]
    parent: int
    end: int
    inlinee: int
    annotations: bytes


_PROCEDURES = {0x110f, 0x1110, 0x1146, 0x1147}
_INLINES = {0x114d, 0x115d}


def native_inline_sites(data: bytes, limits) -> dict[tuple[int, int], NativeInline]:
    """Read DBI module symbol streams without trusting YAML's omitted fields."""
    streams = _MsfStreams(data, limits["max_records"])
    dbi = streams.read(3)
    signature, version = unpack("<iI", dbi, 0)
    if signature != -1 or version != 19990903:
        raise ReaderFailure("inline_native_format_unsupported")
    module_size, = unpack("<i", dbi, 24)
    modules = take(dbi, 64, module_size)
    position = module_index = record_count = 0
    scanned_bytes = len(dbi)
    result = {}
    while position < len(modules):
        take(modules, position, 64)
        stream, = unpack("<H", modules, position + 34)
        symbol_bytes, = unpack("<I", modules, position + 36)
        position += 64
        for _ in range(2):
            end = modules.find(b"\0", position)
            if end < 0:
                raise ReaderFailure("inline_native_data_malformed")
            position = end + 1
        position = (position + 3) & ~3
        if position > len(modules):
            raise ReaderFailure("inline_native_data_malformed")
        if module_index >= limits["max_records"]:
            raise ReaderFailure("record_limit")
        if stream != 0xffff and symbol_bytes:
            scanned_bytes += symbol_bytes
            if scanned_bytes > limits["max_input_bytes"]:
                raise ReaderFailure("input_limit")
            symbols = streams.read(stream, symbol_bytes)
            if unpack("<I", symbols, 0)[0] != 4:
                raise ReaderFailure("inline_native_format_unsupported")
            records = {}
            offset = 4
            while offset < len(symbols):
                length, kind = unpack("<HH", symbols, offset)
                if length < 2:
                    raise ReaderFailure("inline_native_data_malformed")
                raw = take(symbols, offset, length + 2)
                record = _Record(len(records), offset, kind, raw)
                records[offset] = record
                offset += length + 2
                record_count += 1
                if record_count > limits["max_records"]:
                    raise ReaderFailure("record_limit")
            for record in records.values():
                if record.kind not in _INLINES:
                    continue
                parent, end, inlinee = unpack("<III", record.data, 4)
                end_record = records.get(end)
                if end_record is None or end_record.kind != 0x114e or end <= record.offset:
                    raise ReaderFailure("inline_native_parent_invalid")
                ancestor = parent
                parent_index = None
                procedure_record = None
                for _ in range(limits["max_depth"]):
                    scope = records.get(ancestor)
                    if scope is None or scope.offset >= record.offset:
                        raise ReaderFailure("inline_native_parent_invalid")
                    scope_parent, scope_end = unpack("<II", scope.data, 4)
                    if not record.offset < end < scope_end or scope_end not in records:
                        raise ReaderFailure("inline_native_parent_invalid")
                    if parent_index is None and (scope.kind in _PROCEDURES or scope.kind in _INLINES):
                        parent_index = scope.index
                    if scope.kind in _PROCEDURES:
                        if records[scope_end].kind not in (0x0006, 0x114f):
                            raise ReaderFailure("inline_native_parent_invalid")
                        procedure_record = scope
                        break
                    if scope.kind not in _INLINES and scope.kind != 0x1103:
                        raise ReaderFailure("inline_native_parent_invalid")
                    expected_end = 0x114e if scope.kind in _INLINES else 0x0006
                    if records[scope_end].kind != expected_end:
                        raise ReaderFailure("inline_native_parent_invalid")
                    ancestor = scope_parent
                if procedure_record is None:
                    raise ReaderFailure("depth_limit")
                fields = unpack("<IIIIIIIIH", procedure_record.data, 4)
                procedure = {key: fields[index] for key, index in (
                    ("PtrParent", 0), ("PtrEnd", 1), ("PtrNext", 2), ("CodeSize", 3),
                    ("FunctionType", 6), ("Offset", 7), ("Segment", 8),
                )}
                annotation_offset = 16 if record.kind == 0x114d else 20
                take(record.data, 0, annotation_offset)
                result[module_index, record.index] = NativeInline(
                    record.offset, parent_index, procedure_record.index, procedure,
                    parent, end, inlinee, record.data[annotation_offset:],
                )
        module_index += 1
    return result
