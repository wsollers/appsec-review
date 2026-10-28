"""Parser for LLVM dwarfdump's bounded, resolved DWARF presentation."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any

from appsec_review.debug_symbols._reader_binary import ReaderFailure
from appsec_review.debug_symbols.contract import AddressRange, RecordKind, SourceSpan, SymbolRecord


_DIE = re.compile(r"^0x([0-9a-fA-F]+):(\s+)(DW_TAG_\w+|NULL)\s*$")
_ATTRIBUTE = re.compile(r"^\s+DW_AT_(\w+)\s+(.*)$")
_QUOTED = re.compile(r'"(?:\\.|[^"\\])*"')
_INTERVAL = re.compile(r"\[(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)")
_LINE = re.compile(r"^(0x[0-9a-fA-F]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+.*$")


def _number(value: str, default=None):
    match = re.match(r"\(?\s*(0x[0-9a-fA-F]+|\d+)(?:\s|[)\" ]|$)", value)
    if not match:
        return default
    raw = match.group(1)
    return int(raw, 16 if raw.startswith("0x") else 10)


def _string(value: str) -> str:
    match = _QUOTED.search(value)
    if not match:
        return ""
    try:
        return json.loads(match.group())
    except ValueError:
        return match.group()[1:-1]


@dataclass
class Die:
    offset: int
    tag: str
    parent: Die | None
    depth: int
    attrs: dict[str, str] = field(default_factory=dict)
    children: list[Die] = field(default_factory=list)

    @property
    def key(self):
        return f"dwarf:info:{self.offset:016x}"


def _dies(text: str, limits):
    if any(f".{section} contents:" not in text for section in
           ("debug_info", "debug_line", "debug_ranges", "debug_rnglists")):
        raise ReaderFailure("malformed_tool_output")
    dies: dict[int, Die] = {}
    stack: list[Die] = []
    current = None
    attribute = None
    active = False
    for line in text.splitlines():
        if line.startswith(".debug_info contents:"):
            active = True
            continue
        if active and re.match(r"^\.\w+ contents:", line):
            active = False
        if not active:
            continue
        if "Compile Unit:" in line and "version =" in line:
            version = re.search(r"version = (0x[0-9a-fA-F]+)", line)
            if version and not 2 <= int(version.group(1), 16) <= 5:
                raise ReaderFailure("unsupported_dwarf_version")
        match = _DIE.match(line)
        if match:
            offset, whitespace, tag = match.groups()
            depth = (len(whitespace) - 1) // 2
            if depth >= limits["max_depth"]:
                raise ReaderFailure("depth_limit")
            while stack and stack[-1].depth >= depth:
                stack.pop()
            current, attribute = None, None
            if tag == "NULL":
                continue
            if int(offset, 16) in dies or (depth and not stack):
                raise ReaderFailure("malformed_tool_output")
            current = Die(int(offset, 16), tag[7:], stack[-1] if stack else None, depth)
            if current.parent:
                current.parent.children.append(current)
            dies[current.offset] = current
            stack.append(current)
            if len(dies) > limits["max_records"]:
                raise ReaderFailure("record_limit")
            continue
        match = _ATTRIBUTE.match(line)
        if current and match:
            attribute, value = match.groups()
            if attribute in current.attrs:
                raise ReaderFailure("malformed_tool_output")
            current.attrs[attribute] = value
        elif current and attribute and line.strip():
            current.attrs[attribute] += "\n" + line.strip()
    if not any(die.tag in ("compile_unit", "skeleton_unit") for die in dies.values()):
        raise ReaderFailure("dwarf_compilation_units_unavailable")
    return dies


def _line_tables(text, limits, gaps):
    tables, records = {}, []
    active = False
    current = None
    directories, files = {}, {}
    file_index = None
    pending = None
    row_index = 0
    for line in text.splitlines():
        if line.startswith(".debug_line contents:"):
            active = True
            continue
        if not active:
            continue
        if re.match(r"^\.\w+ contents:", line):
            active = False
            continue
        match = re.match(r"debug_line\[(0x[0-9a-fA-F]+)\]", line)
        if match:
            if pending:
                gaps.add("source_ranges_unterminated_sequence")
            current = int(match.group(1), 16)
            directories, files, pending = {}, {}, None
            tables[current] = files
            row_index = 0
            continue
        match = re.match(r"include_directories\[\s*(\d+)\]\s*=\s*(.*)", line)
        if match:
            directories[int(match.group(1))] = _string(match.group(2))
            continue
        match = re.match(r"file_names\[\s*(\d+)\]:", line)
        if match:
            file_index = int(match.group(1))
            files[file_index] = {}
            continue
        match = re.match(r"\s+(name|dir_index|md5_checksum):\s*(.*)", line)
        if match and file_index is not None:
            key, value = match.groups()
            files[file_index][key] = value
            continue
        match = _LINE.match(line)
        if not match or current is None:
            continue
        address = int(match.group(1), 16)
        if address >= 2**64:
            raise ReaderFailure("malformed_tool_output")
        lineno, column, index = map(int, match.groups()[1:])
        if pending:
            start, number, col, old_index, old_row = pending
            if address < start:
                raise ReaderFailure("malformed_tool_output")
            if address > start and number:
                info = files.get(old_index)
                if not info or "name" not in info:
                    gaps.add("source_ranges_file_unavailable")
                else:
                    path = _string(info["name"])
                    directory = directories.get(_number(info.get("dir_index", ""), 0), "")
                    # Pure string composition; neither path is opened or resolved.
                    if directory and path and not path.startswith(("/", "\\")) and not re.match(r"^[A-Za-z]:", path):
                        path = directory.rstrip("/\\") + "/" + path
                    checksum = info.get("md5_checksum")
                    if checksum and not re.fullmatch(r"[a-fA-F0-9]{32}", checksum):
                        raise ReaderFailure("malformed_tool_output")
                    source = SourceSpan(path, number, col, checksum.lower() if checksum else None,
                                        "md5" if checksum else None)
                    records.append(SymbolRecord(
                        f"dwarf:line:{current:016x}:{old_row}", RecordKind.SOURCE_RANGE,
                        ranges=(AddressRange(start, address),), source=source,
                        data={"source_binding": "path_only", "address_kind": "link_virtual_address"},
                    ))
                    if len(records) > limits["max_records"]:
                        raise ReaderFailure("record_limit")
        pending = None if "end_sequence" in line else (address, lineno, column, index, row_index)
        row_index += 1
        if row_index > limits["max_records"]:
            raise ReaderFailure("record_limit")
    if pending:
        gaps.add("source_ranges_unterminated_sequence")
    return tables, records


def parse_dwarf(text: str, limits) -> tuple[list[SymbolRecord], set[str]]:
    gaps = {"variable_locations_not_indexed", "source_paths_unverified"}
    dies = _dies(text, limits)
    tables, line_records = _line_tables(text, limits, gaps)

    def inherited(die: Die, attribute: str):
        seen = set()
        for _ in range(limits["max_depth"]):
            if attribute in die.attrs:
                return die.attrs[attribute]
            reference = _number(die.attrs.get("abstract_origin", die.attrs.get("specification", "")))
            if reference is None:
                return ""
            if reference in seen:
                raise ReaderFailure("dwarf_reference_cycle")
            seen.add(reference)
            if reference not in dies:
                gaps.add("dwarf_reference_unavailable")
                return ""
            die = dies[reference]
        raise ReaderFailure("depth_limit")

    def name(die):
        return _string(inherited(die, "name"))

    def unit(die):
        while die.parent:
            die = die.parent
        return die

    def source(die, prefix="decl"):
        path = _string(inherited(die, prefix + "_file"))
        line = _number(inherited(die, prefix + "_line"), 0)
        if not path:
            file_id = _number(inherited(die, prefix + "_file"))
            table = tables.get(_number(unit(die).attrs.get("stmt_list", ""), 0), {})
            path = _string(table.get(file_id, {}).get("name", ""))
        if not path or not line:
            return None
        return SourceSpan(path, line, _number(inherited(die, prefix + "_column"), 0))

    def type_name(reference, seen=()):
        if reference is None or reference == 0:
            return "void"
        if reference in seen:
            gaps.add("types_recursive_reference")
            return f"<type@{reference:x}>"
        if len(seen) >= limits["max_depth"]:
            raise ReaderFailure("depth_limit")
        die = dies.get(reference)
        if not die:
            gaps.add("types_reference_unavailable")
            return f"<type@{reference:x}>"
        result = name(die)
        if result:
            return result
        inner = _number(inherited(die, "type"))
        wrapped = type_name(inner, (*seen, reference))
        return {
            "pointer_type": wrapped + " *", "reference_type": wrapped + " &",
            "rvalue_reference_type": wrapped + " &&", "const_type": "const " + wrapped,
            "volatile_type": "volatile " + wrapped, "restrict_type": "restrict " + wrapped,
            "array_type": wrapped + "[]",
        }.get(die.tag, f"<{die.tag}@{reference:x}>")

    def intervals(die):
        ranges = die.attrs.get("ranges", "")
        result = tuple(AddressRange(int(a, 16), int(b, 16)) for a, b in _INTERVAL.findall(ranges))
        if ranges and not result:
            gaps.add("address_ranges_unavailable")
        if not result:
            low, high = _number(die.attrs.get("low_pc", "")), _number(die.attrs.get("high_pc", ""))
            if low is not None and high is not None and high > low:
                result = (AddressRange(low, high),)
        return result

    records: list[SymbolRecord] = []
    for die in dies.values():
        metadata: dict[str, Any] = {
            "native_offset": die.offset, "source_binding": "path_only",
            "address_kind": "link_virtual_address",
        }
        if die.tag in ("compile_unit", "skeleton_unit"):
            if "dwo_name" in die.attrs or "GNU_dwo_name" in die.attrs or die.tag == "skeleton_unit":
                gaps.add("split_dwarf_unavailable")
            metadata.update({
                "producer": _string(die.attrs.get("producer", "")),
                "language": die.attrs.get("language", "").strip("()"),
                "compilation_directory_sha256": hashlib.sha256(
                    _string(die.attrs.get("comp_dir", "")).encode("utf-8")).hexdigest(),
                "source_name_sha256": hashlib.sha256(name(die).encode("utf-8")).hexdigest(),
            })
            recorded_name = name(die)
            display_name = re.split(r"[/\\]", recorded_name)[-1]
            records.append(SymbolRecord(die.key, RecordKind.COMPILATION_UNIT, display_name,
                                        intervals(die), SourceSpan(recorded_name, 1) if recorded_name else None,
                                        data=metadata))
        elif die.tag == "subprogram":
            parameters = [type_name(_number(inherited(child, "type"))) for child in die.children
                          if child.tag == "formal_parameter"]
            if any(child.tag == "unspecified_parameters" for child in die.children):
                parameters.append("...")
            metadata["signature"] = {
                "return_type": type_name(_number(inherited(die, "type"))),
                "parameter_types": parameters,
                "variadic": "..." in parameters,
            }
            metadata["linkage_name"] = _string(inherited(die, "linkage_name"))
            ranges = intervals(die)
            if not ranges:
                gaps.add("functions_without_address_ranges")
            records.append(SymbolRecord(die.key, RecordKind.SYMBOL, name(die), ranges,
                                        source(die), unit(die).key, metadata))
        elif die.tag == "inlined_subroutine":
            parent = die.parent
            while parent and parent.tag not in ("subprogram", "inlined_subroutine"):
                parent = parent.parent
            metadata["abstract_origin"] = _number(die.attrs.get("abstract_origin", ""))
            ranges = intervals(die)
            if not ranges:
                gaps.add("inline_ranges_unavailable")
            records.append(SymbolRecord(die.key, RecordKind.INLINE_FRAME, name(die), ranges,
                                        source(die, "call"), parent.key if parent else None, metadata))
        elif die.tag in ("structure_type", "class_type", "union_type", "enumeration_type",
                         "array_type", "typedef", "base_type", "pointer_type"):
            members = []
            for child in die.children:
                if child.tag not in ("member", "inheritance"):
                    continue
                location = child.attrs.get("data_member_location", "")
                offset = 0 if die.tag == "union_type" and not location else _number(location)
                if offset is None:
                    gaps.add("type_member_location_unavailable")
                members.append({
                    "name": name(child), "offset": offset,
                    "type": type_name(_number(inherited(child, "type"))),
                    "bit_size": _number(child.attrs.get("bit_size", "")),
                    "data_bit_offset": _number(child.attrs.get("data_bit_offset", "")),
                })
            metadata.update({
                "type_kind": die.tag, "byte_size": _number(die.attrs.get("byte_size", "")),
                "members": members,
            })
            if metadata["byte_size"] is None:
                gaps.add("type_size_unavailable")
            records.append(SymbolRecord(die.key, RecordKind.TYPE_LAYOUT, name(die),
                                        source=source(die), parent_key=unit(die).key, data=metadata))
        if "location" in die.attrs:
            gaps.add("location_expressions_not_evaluated")
        if any(key in die.attrs for key in ("optimized", "GNU_all_call_sites", "call_all_calls")):
            gaps.add("optimized_debug_information")
        if len(records) > limits["max_records"]:
            raise ReaderFailure("record_limit")
    if not line_records:
        gaps.add("source_ranges_unavailable")
    if any(record.source and not record.source.checksum for record in line_records):
        gaps.add("source_checksums_unavailable")
    if not any(record.kind is RecordKind.SYMBOL for record in records):
        gaps.add("functions_unavailable")
    if not any(record.kind is RecordKind.INLINE_FRAME for record in records):
        gaps.add("inline_frames_not_emitted")
    if not any(record.kind is RecordKind.TYPE_LAYOUT for record in records):
        gaps.add("type_layouts_unavailable")
    records.extend(line_records)
    return records, gaps
