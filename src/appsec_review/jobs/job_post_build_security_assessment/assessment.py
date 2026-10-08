"""Deterministic post-build provenance, binary inspection, and assessment primitives.

Target-produced files and command material are untrusted data.  This module never executes a
target artifact and never returns unredacted command or environment text for logging/indexing.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import struct
from typing import Any, Iterable, Mapping, Protocol

from appsec_review.storage import canonical_json, file_sha256


SCHEMA = "appsec-review/post-build-security-assessment/1"
PROVENANCE_SCHEMA = "appsec-review/build-command-provenance/1"
INSPECTION_SCHEMA = "appsec-review/binary-inspection/1"
RULE_VERSION = "build-security-rules/1"
PARSER_VERSION = "build-security-binary-parser/1"
NORMALIZER_VERSION = "build-security-command-normalizer/1"
GUIDANCE_IDENTITY = "build-security-inference-guidance/1"
MAX_ARGV = 4096
MAX_ARG_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024

_SECRET = re.compile(
    r"(?i)(authorization|bearer|password|passwd|secret|token|api[_-]?key|credential|private[_-]?key|sign(?:ing)?[_-]?key)"
)
_HOST_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|/home/|/Users/|/var/|/tmp/|\\\\)")
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".s", ".asm"}
_OBJECT_SUFFIXES = {".o", ".obj", ".lo", ".bc"}
_LIBRARY_SUFFIXES = {".a", ".lib", ".so", ".dylib", ".dll"}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _safe_path(value: str, *, roots: Mapping[str, str] | None = None) -> str:
    text = value.replace("\\", "/")
    for prefix, replacement in sorted((roots or {}).items(), key=lambda item: -len(item[0])):
        normalized = prefix.replace("\\", "/").rstrip("/")
        if text == normalized or text.startswith(normalized + "/"):
            return replacement.rstrip("/") + text[len(normalized):]
    unsafe = re.search(r"(?:[A-Za-z]:/|/(?:home|Users|var|tmp)/|//)", text)
    if unsafe:
        prefix = text[:unsafe.start()]
        if not prefix:
            name = PurePosixPath(text).name
            return f"<external-path>/{name}" if name else "<external-path>"
        return prefix + "<external-path>"
    return text[:8192]


def redact_argv(argv: Iterable[str], *, roots: Mapping[str, str] | None = None) -> list[str]:
    """Return a bounded normalized representation suitable for indexes and telemetry."""
    values = list(argv)
    if not values or len(values) > MAX_ARGV or sum(len(str(item)) for item in values) > MAX_ARG_BYTES:
        raise ValueError("command argv exceeds configured provenance bounds")
    if any(not isinstance(item, str) or "\0" in item for item in values):
        raise ValueError("command argv contains an invalid value")
    result: list[str] = []
    redact_next = False
    for value in values:
        if redact_next:
            result.append("<redacted>")
            redact_next = False
            continue
        if _SECRET.search(value):
            if "=" in value:
                result.append(value.split("=", 1)[0] + "=<redacted>")
            elif value.startswith(("-", "/")) and "/" not in value[1:]:
                result.append(value[:64])
                redact_next = True
            else:
                result.append("<redacted>")
            continue
        if value.startswith("@"):
            result.append("@" + _safe_path(value[1:], roots=roots))
        elif "=" in value and _SECRET.search(value.split("=", 1)[0]):
            result.append(value.split("=", 1)[0] + "=<redacted>")
        else:
            result.append(_safe_path(value, roots=roots))
    return result


def sanitize_environment(environment: Mapping[str, str]) -> Mapping[str, Any]:
    """Retain non-sensitive build facts without exposing environment values."""
    allowed = {"CC", "CXX", "AR", "AS", "LD", "RC", "CFLAGS", "CXXFLAGS", "CPPFLAGS",
               "LDFLAGS", "BUILD_TYPE", "CONFIGURATION", "TARGET", "ARCH", "SOURCE_DATE_EPOCH"}
    facts: dict[str, Any] = {}
    omitted = 0
    for key, value in sorted(environment.items()):
        if _SECRET.search(key) or _SECRET.search(str(value)):
            omitted += 1
            continue
        if key in allowed:
            normalized = redact_argv([str(value)])[0]
            facts[key] = {"value": normalized, "sha256": hashlib.sha256(str(value).encode()).hexdigest()}
        else:
            omitted += 1
    return {"facts": facts, "omitted_count": omitted}


def classify_action(argv: Iterable[str]) -> str:
    values = tuple(argv)
    if not values:
        return "unknown"
    executable = PurePosixPath(values[0].replace("\\", "/")).name.lower()
    flags = {item.lower() for item in values[1:]}
    if executable in {"ar", "llvm-ar", "gcc-ar", "ranlib", "llvm-ranlib"}:
        return "archiver"
    if executable in {"lib", "lib.exe", "llvm-lib", "llvm-lib.exe"}:
        return "librarian"
    if executable in {"rc", "rc.exe", "windres", "llvm-rc", "llvm-rc.exe"}:
        return "resource_compiler"
    if executable in {"as", "llvm-as", "ml", "ml64", "ml.exe", "ml64.exe"}:
        return "assembler"
    if executable in {"ld", "ld.lld", "lld", "lld-link", "lld-link.exe", "link", "link.exe"}:
        return "linker"
    if executable in {"strip", "llvm-strip", "objcopy", "llvm-objcopy", "install_name_tool", "codesign", "signtool"}:
        return "post_link"
    compiler = any(token in executable for token in ("clang", "gcc", "g++", "cl.exe", "clang-cl"))
    if compiler:
        if {"-c", "/c"} & flags:
            return "compiler"
        if any(item.lower().startswith(("-o", "/out:")) for item in values[1:]) or not ({"-e", "-m"} & flags):
            return "linker_driver"
    return "unknown"


def _split_command(value: Mapping[str, Any]) -> list[str]:
    raw = value.get("arguments")
    if isinstance(raw, list):
        return [str(item) for item in raw]
    command = value.get("command")
    if not isinstance(command, str) or len(command) > MAX_ARG_BYTES:
        raise ValueError("build action requires bounded arguments or command")
    return shlex.split(command, posix=True)


def _flag_values(argv: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for value in argv:
        lowered = value.lower()
        result.add(lowered)
        if lowered.startswith("-wl,"):
            result.update(part for part in lowered[4:].split(",") if part)
    return result


def discover_io(argv: Iterable[str], *, working_directory: str) -> tuple[list[str], list[str]]:
    values = tuple(argv)
    inputs: list[str] = []
    outputs: list[str] = []
    consume_output = False
    for value in values[1:]:
        lower = value.lower()
        if consume_output:
            outputs.append(value)
            consume_output = False
            continue
        if value in {"-o", "/Fo", "/Fe", "/OUT"}:
            consume_output = True
            continue
        if lower.startswith(("/fo", "/fe", "/out:")) and len(value) > 3:
            outputs.append(value.split(":", 1)[-1] if ":" in value else value[3:])
            continue
        suffix = PurePosixPath(value.replace("\\", "/")).suffix.lower()
        if suffix in _SOURCE_SUFFIXES | _OBJECT_SUFFIXES | _LIBRARY_SUFFIXES | {".res", ".rc", ".def"}:
            inputs.append(value)
    if classify_action(values) in {"archiver", "librarian"}:
        archive = next((value for value in values[1:]
                        if PurePosixPath(value.replace("\\", "/")).suffix.lower() in {".a", ".lib"}), None)
        if archive is not None:
            outputs.append(archive)
            inputs = [value for value in inputs if value != archive]
    return sorted(set(inputs)), sorted(set(outputs))


def normalize_action(
    row: Mapping[str, Any], *, action_id: str, run_id: str, target_snapshot: str,
    project: str, build_root: str, configuration: str, producer: Mapping[str, str],
    toolchain: Mapping[str, str], protected_artifact: Mapping[str, Any],
    environment: Mapping[str, str] | None = None, roots: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    argv = _split_command(row)
    normalized = redact_argv(argv, roots=roots)
    directory = _safe_path(str(row.get("directory", build_root)), roots=roots)
    inputs, outputs = discover_io(normalized, working_directory=directory)
    return {
        "schema": PROVENANCE_SCHEMA,
        "run_id": run_id,
        "target_snapshot": target_snapshot,
        "project": project,
        "build_root": build_root,
        "configuration": configuration,
        "build_action_id": action_id,
        "compile_unit_id": _sha({"action": action_id, "source": row.get("file")}) if classify_action(argv) == "compiler" else None,
        "linked_artifact_ids": [],
        "classification": classify_action(argv),
        "toolchain": dict(toolchain),
        "argv": normalized,
        "argv_sha256": _sha(argv),
        "protected_argv_artifact": dict(protected_artifact),
        "working_directory": directory,
        "environment": sanitize_environment(environment or {}),
        "declared_inputs": inputs,
        "discovered_inputs": [],
        "outputs": outputs,
        "output_hashes": {},
        "start": row.get("start"),
        "end": row.get("end"),
        "exit_status": row.get("exit_status"),
        "producer": dict(producer),
    }


def command_fingerprint(action: Mapping[str, Any]) -> str:
    return _sha({key: action.get(key) for key in (
        "target_snapshot", "project", "build_root", "configuration", "build_action_id",
        "compile_unit_id", "linked_artifact_ids", "classification", "toolchain", "argv_sha256",
        "working_directory", "environment", "declared_inputs", "discovered_inputs", "outputs",
        "output_hashes", "start", "end", "exit_status", "timing_granularity", "argv_source", "producer",
    )})


def _bounded_c_string(data: bytes, offset: int, limit: int = 8192) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    return data[offset:offset + limit].split(b"\0", 1)[0].decode("utf-8", "replace")


def _elf(path: Path, data: bytes) -> dict[str, Any]:
    bits = 64 if data[4] == 2 else 32 if data[4] == 1 else 0
    endian = "<" if data[5] == 1 else ">" if data[5] == 2 else ""
    if not bits or not endian:
        raise ValueError("invalid ELF class or byte order")
    header = ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH")
    values = struct.unpack_from(endian + header, data, 16)
    e_type, machine = values[0], values[1]
    phoff, shoff = values[4], values[5]
    phentsize, phnum, shentsize, shnum, shstrndx = values[8], values[9], values[10], values[11], values[12]
    if phnum > 65535 or shnum > 65535:
        raise ValueError("ELF table count exceeds bound")
    program_headers = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        fmt = "IIQQQQQQ" if bits == 64 else "IIIIIIII"
        size = struct.calcsize(endian + fmt)
        if offset + size > len(data):
            break
        raw = struct.unpack_from(endian + fmt, data, offset)
        if bits == 64:
            p_type, flags, p_offset, vaddr, filesz, memsz = raw[0], raw[1], raw[2], raw[3], raw[5], raw[6]
        else:
            p_type, flags, p_offset, vaddr, filesz, memsz = raw[0], raw[6], raw[1], raw[2], raw[4], raw[5]
        program_headers.append({"type": p_type, "flags": flags, "offset": p_offset,
                                "vaddr": vaddr, "filesz": filesz, "memsz": memsz})
    raw_sections = []
    shfmt = "IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII"
    shsize = struct.calcsize(endian + shfmt)
    for index in range(shnum):
        offset = shoff + index * shentsize
        if offset + shsize > len(data):
            break
        raw_sections.append(struct.unpack_from(endian + shfmt, data, offset))
    strings = b""
    if shstrndx < len(raw_sections):
        item = raw_sections[shstrndx]
        section_offset, section_size = item[4], item[5]
        strings = data[section_offset:section_offset + section_size]
    sections = []
    for item in raw_sections:
        name = _bounded_c_string(strings, item[0], 4096) if strings else ""
        sections.append({"name": name, "type": item[1], "flags": item[2], "offset": item[4], "size": item[5]})
    names = {item["name"] for item in sections}
    interpreter = None
    for item in program_headers:
        if item["type"] == 3 and item["offset"] + item["filesz"] <= len(data):
            interpreter = data[item["offset"]:item["offset"] + item["filesz"]].split(b"\0", 1)[0].decode("utf-8", "replace")
    dynamic: list[tuple[int, int]] = []
    dynamic_entry = "qQ" if bits == 64 else "iI"
    dynamic_size = struct.calcsize(endian + dynamic_entry)
    for item in program_headers:
        if item["type"] != 2:
            continue
        start, end = item["offset"], min(len(data), item["offset"] + item["filesz"])
        for offset in range(start, end - dynamic_size + 1, dynamic_size):
            tag, value = struct.unpack_from(endian + dynamic_entry, data, offset)
            if tag == 0:
                break
            dynamic.append((tag, value))
    strtab_address = next((value for tag, value in dynamic if tag == 5), None)
    strtab_size = next((value for tag, value in dynamic if tag == 10), 1024 * 1024)
    strtab_offset = None
    if strtab_address is not None:
        for item in program_headers:
            if item["type"] == 1 and item["vaddr"] <= strtab_address < item["vaddr"] + item["memsz"]:
                strtab_offset = item["offset"] + strtab_address - item["vaddr"]
                break
    dynamic_strings = b""
    if strtab_offset is not None and strtab_offset < len(data):
        dynamic_strings = data[strtab_offset:min(len(data), strtab_offset + min(strtab_size, 16 * 1024 * 1024))]
    dependencies = [_bounded_c_string(dynamic_strings, value) for tag, value in dynamic if tag == 1 and dynamic_strings]
    rpath = [_bounded_c_string(dynamic_strings, value) for tag, value in dynamic if tag == 15 and dynamic_strings]
    runpath = [_bounded_c_string(dynamic_strings, value) for tag, value in dynamic if tag == 29 and dynamic_strings]
    now = any(tag == 24 or tag == 30 and value & 8 or tag == 0x6FFFFFFB and value & 1 for tag, value in dynamic)
    symbols: list[str] = []
    imports: list[str] = []
    exports: list[str] = []
    for section in raw_sections:
        if section[1] not in {2, 11} or section[9] <= 0 or section[6] >= len(raw_sections):
            continue
        strings_section = raw_sections[section[6]]
        string_data = data[strings_section[4]:strings_section[4] + strings_section[5]]
        entry_fmt = "IBBHQQ" if bits == 64 else "IIIBBH"
        entry_size = struct.calcsize(endian + entry_fmt)
        count = min(section[5] // max(section[9], entry_size), 100000)
        for index in range(count):
            offset = section[4] + index * section[9]
            if offset + entry_size > len(data):
                break
            raw_symbol = struct.unpack_from(endian + entry_fmt, data, offset)
            name_offset = raw_symbol[0]
            shndx = raw_symbol[3] if bits == 64 else raw_symbol[5]
            name = _bounded_c_string(string_data, name_offset, 4096)
            if not name:
                continue
            symbols.append(name)
            if section[1] == 11:
                (imports if shndx == 0 else exports).append(name)
    build_id = None
    note = next((item for item in sections if item["name"] == ".note.gnu.build-id"), None)
    if note and note["offset"] + 12 <= len(data):
        namesz, descsz, note_type = struct.unpack_from(endian + "III", data, note["offset"])
        desc_offset = note["offset"] + 12 + ((namesz + 3) & ~3)
        if note_type == 3 and desc_offset + descsz <= len(data):
            build_id = data[desc_offset:desc_offset + descsz].hex()
    gaps = []
    stack_header = next((item for item in program_headers if item["type"] == 0x6474E551), None)
    artifact_kind = ("pie_executable" if interpreter else "shared_library") if e_type == 3 else {
        1: "object", 2: "executable", 4: "core"}.get(e_type, "unknown")
    if any(item["type"] == 2 for item in program_headers) and not dynamic_strings:
        gaps.append("ELF dynamic string table could not be resolved")
    return {
        "format": "ELF", "kind": artifact_kind,
        "architecture": machine, "bits": bits,
        "headers": {"type": e_type, "machine": machine, "program_header_count": phnum, "section_count": shnum},
        "sections": sections[:4096], "symbols": {"present": ".symtab" in names, "stripped": ".symtab" not in names,
                                                     "names": sorted(set(symbols))[:100000]},
        "imports": sorted(set(imports))[:100000], "exports": sorted(set(exports))[:100000],
        "relocations": [item["name"] for item in sections if item["name"].startswith((".rel", ".rela"))],
        "interpreter": interpreter, "rpath": rpath, "runpath": runpath,
        "dependencies": dependencies, "archive_members": [],
        "build_id": build_id, "debug": {"present": any(name.startswith(".debug") for name in names),
                                      "sections": sorted(name for name in names if name.startswith(".debug"))},
        "hardening": {
            "pie": True if artifact_kind == "pie_executable" else False if artifact_kind == "executable" else None,
            "relro": any(item["type"] == 0x6474E552 for item in program_headers),
            "now": now if dynamic else None,
            "nx_stack": None if stack_header is None else not bool(stack_header["flags"] & 1),
            "control_flow": None,
            "stack_canary": True if any(name == "__stack_chk_fail" for name in imports) else None,
            "fortify": True if any(name.endswith("_chk") or "_chk@" in name for name in imports) else None,
        },
        "gaps": gaps,
    }


def _pe(path: Path, data: bytes) -> dict[str, Any]:
    if len(data) < 0x40:
        raise ValueError("truncated PE header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    machine, section_count, timestamp, symbol_ptr, symbol_count, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4)
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0] if optional + 2 <= len(data) else 0
    dll_offset = optional + 70
    dll_characteristics = struct.unpack_from("<H", data, dll_offset)[0] if dll_offset + 2 <= len(data) else 0
    section_offset = optional + optional_size
    sections = []
    for index in range(min(section_count, 4096)):
        offset = section_offset + index * 40
        if offset + 40 > len(data):
            break
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset, _, _, reloc_count, _, flags = struct.unpack_from(
            "<IIIIIIHHI", data, offset + 8)
        sections.append({"name": name, "virtual_size": virtual_size, "virtual_address": virtual_address,
                         "offset": raw_offset, "size": raw_size, "relocation_count": reloc_count, "flags": flags})
    names = {item["name"] for item in sections}
    bits = 64 if magic == 0x20B else 32 if magic == 0x10B else None
    directory_offset = optional + (112 if bits == 64 else 96)
    directory_count_offset = optional + (108 if bits == 64 else 92)
    directory_count = (struct.unpack_from("<I", data, directory_count_offset)[0]
                       if bits and directory_count_offset + 4 <= len(data) else 0)
    directories = []
    for index in range(min(directory_count, 16)):
        entry = directory_offset + index * 8
        if entry + 8 > len(data):
            break
        directories.append(struct.unpack_from("<II", data, entry))

    def rva_offset(rva: int) -> int | None:
        if 0 < rva < section_offset:
            return rva
        for section in sections:
            span = max(section["virtual_size"], section["size"])
            if section["virtual_address"] <= rva < section["virtual_address"] + span:
                value = section["offset"] + rva - section["virtual_address"]
                return value if value < len(data) else None
        return None

    imports: list[str] = []
    dependencies: list[str] = []
    if len(directories) > 1 and directories[1][0]:
        descriptor = rva_offset(directories[1][0])
        for _ in range(4096):
            if descriptor is None or descriptor + 20 > len(data):
                break
            original, timestamp_value, chain, name_rva, first_thunk = struct.unpack_from("<IIIII", data, descriptor)
            if not any((original, timestamp_value, chain, name_rva, first_thunk)):
                break
            name_offset = rva_offset(name_rva)
            library = _bounded_c_string(data, name_offset or -1, 4096)
            if library:
                dependencies.append(library)
            thunk_offset = rva_offset(original or first_thunk)
            width, ordinal_mask = (8, 1 << 63) if bits == 64 else (4, 1 << 31)
            unpack = "<Q" if bits == 64 else "<I"
            for _ in range(100000):
                if thunk_offset is None or thunk_offset + width > len(data):
                    break
                thunk = struct.unpack_from(unpack, data, thunk_offset)[0]
                if thunk == 0:
                    break
                if thunk & ordinal_mask:
                    symbol = f"ordinal:{thunk & 0xffff}"
                else:
                    hint_name = rva_offset(thunk)
                    symbol = _bounded_c_string(data, (hint_name + 2) if hint_name is not None else -1, 4096)
                if symbol:
                    imports.append(f"{library}!{symbol}" if library else symbol)
                thunk_offset += width
            descriptor += 20
    exports: list[str] = []
    if directories and directories[0][0]:
        export_offset = rva_offset(directories[0][0])
        if export_offset is not None and export_offset + 40 <= len(data):
            fields = struct.unpack_from("<IIHHIIIIIII", data, export_offset)
            name_count, names_rva = fields[7], fields[9]
            names_offset = rva_offset(names_rva)
            for index in range(min(name_count, 100000)):
                if names_offset is None or names_offset + index * 4 + 4 > len(data):
                    break
                symbol_rva = struct.unpack_from("<I", data, names_offset + index * 4)[0]
                symbol_offset = rva_offset(symbol_rva)
                symbol = _bounded_c_string(data, symbol_offset or -1, 4096)
                if symbol:
                    exports.append(symbol)
    base_relocations = bool(len(directories) > 5 and directories[5][0] and directories[5][1])
    debug_directory = bool(len(directories) > 6 and directories[6][0] and directories[6][1])
    gaps = ["SAFESEH and /GS require PE load-configuration details not decoded by the bounded parser"]
    if len(directories) <= 1:
        gaps.append("PE data-directory table is unavailable or truncated")
    return {
        "format": "PE/COFF", "kind": "dll" if characteristics & 0x2000 else "executable",
        "architecture": machine, "bits": bits,
        "headers": {"machine": machine, "timestamp": timestamp, "characteristics": characteristics,
                    "dll_characteristics": dll_characteristics, "section_count": section_count},
        "sections": sections, "symbols": {"present": bool(symbol_ptr and symbol_count), "stripped": not bool(symbol_ptr and symbol_count)},
        "imports": sorted(set(imports)), "exports": sorted(set(exports)),
        "relocations": [item["name"] for item in sections if item["relocation_count"]] + (["base-relocations"] if base_relocations else []),
        "interpreter": None, "rpath": [], "runpath": [], "dependencies": sorted(set(dependencies)), "archive_members": [],
        "build_id": None, "debug": {"present": debug_directory or ".debug" in names or ".pdata" in names,
                                      "sections": sorted(names & {".debug", ".pdata"})},
        "hardening": {"dynamic_base": bool(dll_characteristics & 0x0040),
                      "high_entropy_va": bool(dll_characteristics & 0x0020),
                      "nx_compat": bool(dll_characteristics & 0x0100),
                      "guard_cf": bool(dll_characteristics & 0x4000),
                      "safe_seh": None, "gs": None, "sdl": None},
        "gaps": gaps,
    }


def _coff_object(path: Path, data: bytes) -> dict[str, Any]:
    if len(data) < 20:
        raise ValueError("truncated COFF object header")
    machine, section_count, timestamp, symbol_ptr, symbol_count, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, 0)
    if machine not in {0x14C, 0x1C0, 0x1C4, 0x8664, 0xAA64} or section_count > 4096:
        raise ValueError("unsupported COFF object machine or section count")
    offset = 20 + optional_size
    sections = []
    for index in range(section_count):
        item = offset + index * 40
        if item + 40 > len(data):
            raise ValueError("truncated COFF section table")
        name = data[item:item + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset, reloc_ptr, _, reloc_count, _, flags = struct.unpack_from(
            "<IIIIIIHHI", data, item + 8)
        sections.append({"name": name, "virtual_size": virtual_size, "virtual_address": virtual_address,
                         "offset": raw_offset, "size": raw_size, "relocation_offset": reloc_ptr,
                         "relocation_count": reloc_count, "flags": flags})
    names = {item["name"] for item in sections}
    return {
        "format": "COFF", "kind": "object", "architecture": machine, "bits": 64 if machine in {0x8664, 0xAA64} else 32,
        "headers": {"machine": machine, "timestamp": timestamp, "characteristics": characteristics,
                    "section_count": section_count},
        "sections": sections, "symbols": {"present": bool(symbol_ptr and symbol_count), "stripped": not bool(symbol_ptr and symbol_count)},
        "imports": [], "exports": [], "relocations": [item["name"] for item in sections if item["relocation_count"]],
        "interpreter": None, "rpath": [], "runpath": [], "dependencies": [], "archive_members": [],
        "build_id": None, "debug": {"present": any(name.startswith((".debug", ".drectve")) for name in names),
                                      "sections": sorted(name for name in names if name.startswith((".debug", ".drectve")))},
        "hardening": {},
        "gaps": ["COFF symbol names and directive semantics require pinned external readobj output"],
    }


_MACH_MAGICS = {b"\xfe\xed\xfa\xce": (">", 32), b"\xce\xfa\xed\xfe": ("<", 32),
                b"\xfe\xed\xfa\xcf": (">", 64), b"\xcf\xfa\xed\xfe": ("<", 64)}


def _macho(path: Path, data: bytes) -> dict[str, Any]:
    endian, bits = _MACH_MAGICS[data[:4]]
    header_fmt = "IiiIIII" + ("I" if bits == 64 else "")
    header = struct.unpack_from(endian + header_fmt, data, 0)
    _, cpu, subtype, filetype, command_count, command_size, flags = header[:7]
    offset = 32 if bits == 64 else 28
    dependencies, rpaths, sections, build_id = [], [], [], None
    for _ in range(min(command_count, 65535)):
        if offset + 8 > len(data):
            break
        command, size = struct.unpack_from(endian + "II", data, offset)
        if size < 8 or offset + size > len(data):
            break
        if command in {0xC, 0x18, 0x1F, 0x80000018, 0x8000001F} and size >= 12:
            name_offset = struct.unpack_from(endian + "I", data, offset + 8)[0]
            dependencies.append(_bounded_c_string(data, offset + name_offset, size - name_offset))
        elif command == 0x8000001C and size >= 12:
            name_offset = struct.unpack_from(endian + "I", data, offset + 8)[0]
            rpaths.append(_bounded_c_string(data, offset + name_offset, size - name_offset))
        elif command == 0x1B and size >= 24:
            build_id = data[offset + 8:offset + 24].hex()
        offset += size
    return {
        "format": "Mach-O", "kind": {1: "object", 2: "executable", 6: "dylib", 8: "bundle"}.get(filetype, "unknown"),
        "architecture": cpu, "bits": bits,
        "headers": {"cpu": cpu, "subtype": subtype, "filetype": filetype, "command_count": command_count,
                    "command_bytes": command_size, "flags": flags},
        "sections": sections, "symbols": {"present": None, "stripped": None}, "imports": [], "exports": [],
        "relocations": [], "interpreter": None, "rpath": rpaths, "runpath": [],
        "dependencies": dependencies, "archive_members": [], "build_id": build_id,
        "debug": {"present": None, "sections": []},
        "hardening": {"pie": bool(flags & 0x200000), "no_heap_execution": bool(flags & 0x1000000),
                      "app_extension_safe": bool(flags & 0x02000000)},
        "gaps": ["Mach-O symbol, relocation, and detailed section decoding requires pinned external tooling"],
    }


def _archive(path: Path, data: bytes) -> dict[str, Any]:
    members, offset = [], 8
    while offset + 60 <= len(data) and len(members) < 100000:
        header = data[offset:offset + 60]
        if header[58:60] != b"`\n":
            break
        name = header[:16].decode("utf-8", "replace").rstrip().rstrip("/")
        try:
            size = int(header[48:58].decode("ascii").strip() or "0")
        except ValueError:
            break
        members.append({"name": name[:4096], "size": size, "index": len(members)})
        offset += 60 + size + (size % 2)
    return {
        "format": "archive", "kind": "archive", "architecture": None, "bits": None,
        "headers": {"member_count": len(members)}, "sections": [],
        "symbols": {"present": None, "stripped": None}, "imports": [], "exports": [], "relocations": [],
        "interpreter": None, "rpath": [], "runpath": [], "dependencies": [], "archive_members": members,
        "build_id": None, "debug": {"present": None, "sections": []}, "hardening": {},
        "gaps": [] if members else ["archive member table was empty or unsupported"],
    }


def inspect_binary(path: Path) -> dict[str, Any]:
    """Inspect a produced artifact as bytes only; target code is never loaded or executed."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("binary inspection requires a regular non-symlink file")
    size = path.stat().st_size
    if size > MAX_BINARY_BYTES:
        return {"schema": INSPECTION_SCHEMA, "path": path.name, "sha256": file_sha256(path),
                "size_bytes": size, "format": "unsupported", "gaps": ["artifact exceeds binary inspection byte bound"]}
    data = path.read_bytes()
    base = {"schema": INSPECTION_SCHEMA, "path": path.name, "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data), "parser_identity": PARSER_VERSION, "executed": False}
    try:
        if data.startswith(b"\x7fELF"):
            result = _elf(path, data)
        elif data.startswith(b"MZ"):
            result = _pe(path, data)
        elif path.suffix.lower() in {".obj", ".o"} and len(data) >= 20:
            result = _coff_object(path, data)
        elif data[:4] in _MACH_MAGICS:
            result = _macho(path, data)
        elif data.startswith((b"!<arch>\n", b"!<thin>\n")):
            result = _archive(path, data)
        elif data.startswith(b"BC\xc0\xde"):
            result = {"format": "LLVM bitcode", "kind": "llvm_bitcode", "headers": {}, "sections": [],
                      "symbols": {"present": None, "stripped": None}, "imports": [], "exports": [],
                      "relocations": [], "interpreter": None, "rpath": [], "runpath": [], "dependencies": [],
                      "archive_members": [], "build_id": None, "debug": {"present": None, "sections": []},
                      "hardening": {}, "gaps": ["LLVM bitcode semantic inspection requires pinned llvm-readobj tooling"]}
        elif path.suffix.lower() in {".map", ".linkmap"}:
            result = {"format": "link-map", "kind": "link_map", "headers": {}, "sections": [],
                      "symbols": {"present": None, "stripped": None}, "imports": [], "exports": [],
                      "relocations": [], "interpreter": None, "rpath": [], "runpath": [], "dependencies": [],
                      "archive_members": [], "build_id": None, "debug": {"present": False, "sections": []},
                      "hardening": {}, "gaps": ["link-map dialect is retained but not semantically decoded"]}
        else:
            result = {"format": "unsupported", "kind": "unknown", "headers": {}, "sections": [],
                      "symbols": {"present": None, "stripped": None}, "imports": [], "exports": [],
                      "relocations": [], "interpreter": None, "rpath": [], "runpath": [], "dependencies": [],
                      "archive_members": [], "build_id": None, "debug": {"present": None, "sections": []},
                      "hardening": {}, "gaps": ["unsupported produced artifact format"]}
    except (IndexError, struct.error, ValueError) as exc:
        result = {"format": "malformed", "kind": "unknown", "headers": {}, "sections": [],
                  "symbols": {"present": None, "stripped": None}, "imports": [], "exports": [],
                  "relocations": [], "interpreter": None, "rpath": [], "runpath": [], "dependencies": [],
                  "archive_members": [], "build_id": None, "debug": {"present": None, "sections": []},
                  "hardening": {}, "gaps": [f"malformed artifact: {type(exc).__name__}"]}
    return {**base, **result}


def _check(check_id: str, status: str, scope: str, evidence: Iterable[str], rationale: str,
           *, applicable: bool = True) -> dict[str, Any]:
    if status not in {"PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"}:
        raise ValueError("invalid deterministic check status")
    return {"check_id": check_id, "status": status, "scope": scope,
            "evidence": sorted(set(evidence)), "rationale": rationale, "applicable": applicable}


def deterministic_checks(actions: Iterable[Mapping[str, Any]], artifacts: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    actions, artifacts = list(actions), list(artifacts)
    checks: list[dict[str, Any]] = []
    compile_actions = [item for item in actions if item.get("classification") in {"compiler", "linker_driver"}]
    for action in compile_actions:
        flags = _flag_values(action.get("argv", ()))
        scope = str(action.get("compile_unit_id") or action.get("build_action_id"))
        evidence = [str(action.get("build_action_id"))]
        executable = PurePosixPath(str(action.get("argv", [""])[0]).replace("\\", "/")).name.lower()
        windows = executable in {"cl", "cl.exe", "clang-cl", "clang-cl.exe"}
        if windows:
            checks.extend([
                _check("msvc.gs", "FAIL" if "/gs-" in flags else "PASS" if "/gs" in flags else "UNKNOWN", scope, evidence, "/GS compile protection"),
                _check("msvc.guard_cf.requested", "PASS" if "/guard:cf" in flags else "UNKNOWN", scope, evidence, "Control Flow Guard compile request"),
                _check("msvc.sdl", "PASS" if "/sdl" in flags else "UNKNOWN", scope, evidence, "SDL checks"),
            ])
        else:
            stack = "FAIL" if "-fno-stack-protector" in flags else "PASS" if flags & {
                "-fstack-protector", "-fstack-protector-strong", "-fstack-protector-all"} else "UNKNOWN"
            fortify_requested = any(item.startswith("-d_fortify_source=") and not item.endswith("=0") for item in flags)
            optimized = bool(flags & {"-o1", "-o2", "-o3", "-os", "-ofast", "-og"})
            fortify = "PASS" if fortify_requested and optimized else "FAIL" if fortify_requested and not optimized else (
                "FAIL" if "-d_fortify_source=0" in flags or "-u_fortify_source" in flags else "UNKNOWN")
            cf = "PASS" if any(item.startswith("-fcf-protection=") and not item.endswith("=none") for item in flags) else (
                "FAIL" if "-fcf-protection=none" in flags else "UNKNOWN")
            visibility = "PASS" if "-fvisibility=hidden" in flags else "UNKNOWN"
            checks.extend([
                _check("gnu.stack_protector", stack, scope, evidence, "stack protector compile posture"),
                _check("gnu.fortify", fortify, scope, evidence, "fortified libc compile posture"),
                _check("gnu.control_flow", cf, scope, evidence, "compiler control-flow protection"),
                _check("gnu.visibility", visibility, scope, evidence, "default symbol visibility"),
                _check("gnu.insecure_override", "FAIL" if flags & {"-fno-stack-protector", "-no-pie", "-fno-pie",
                       "-fno-pic", "execstack", "norelro", "lazy"} else "PASS", scope, evidence,
                       "explicit insecure compile/link overrides"),
            ])
    for artifact in artifacts:
        scope = str(artifact.get("artifact_id") or artifact.get("sha256"))
        evidence = [str(artifact.get("sha256"))]
        hardening = artifact.get("hardening", {})
        fmt, kind = artifact.get("format"), artifact.get("kind")
        if fmt == "ELF":
            executable = kind in {"executable", "pie_executable", "shared_library"}
            for check_id, key in (("elf.pie", "pie"), ("elf.relro", "relro"), ("elf.now", "now"),
                                  ("elf.nx_stack", "nx_stack"), ("elf.control_flow", "control_flow"),
                                  ("elf.stack_canary", "stack_canary"), ("elf.fortify", "fortify")):
                if ((not executable and check_id in {"elf.pie", "elf.relro", "elf.now"}) or
                        (check_id == "elf.pie" and kind == "shared_library")):
                    checks.append(_check(check_id, "NOT_APPLICABLE", scope, evidence, "not a linked executable/shared object", applicable=False))
                else:
                    value = hardening.get(key)
                    checks.append(_check(check_id, "PASS" if value is True else "FAIL" if value is False else "UNKNOWN",
                                         scope, evidence, f"observed ELF {key}"))
        elif fmt == "PE/COFF":
            for check_id, key in (("pe.dynamic_base", "dynamic_base"), ("pe.nx_compat", "nx_compat"),
                                  ("pe.high_entropy_va", "high_entropy_va"), ("pe.guard_cf", "guard_cf"),
                                  ("pe.safe_seh", "safe_seh"), ("pe.gs", "gs")):
                value = hardening.get(key)
                applicable = not (key == "safe_seh" and artifact.get("bits") == 64)
                checks.append(_check(check_id, "NOT_APPLICABLE" if not applicable else
                                     "PASS" if value is True else "FAIL" if value is False else "UNKNOWN",
                                     scope, evidence, f"observed PE {key}", applicable=applicable))
    all_flags = set().union(*(_flag_values(item.get("argv", ())) for item in actions)) if actions else set()
    for artifact in artifacts:
        hardening = artifact.get("hardening", {})
        scope = str(artifact.get("artifact_id") or artifact.get("sha256"))
        evidence = [str(artifact.get("sha256")), *(str(item.get("build_action_id")) for item in actions)]
        if artifact.get("format") == "ELF":
            requested_pie = bool(all_flags & {"-pie", "-fpie"})
            if requested_pie and hardening.get("pie") is False:
                checks.append(_check("command_binary.pie_mismatch", "FAIL", scope, evidence,
                                     "PIE was requested but the linked ELF is not position independent"))
            if "relro" in all_flags and hardening.get("relro") is False:
                checks.append(_check("command_binary.relro_mismatch", "FAIL", scope, evidence,
                                     "RELRO was requested but absent from the linked ELF"))
            if "now" in all_flags and hardening.get("now") is False:
                checks.append(_check("command_binary.now_mismatch", "FAIL", scope, evidence,
                                     "immediate binding was requested but absent from the linked ELF"))
        if artifact.get("format") == "PE/COFF":
            for flag, property_name in (("/dynamicbase", "dynamic_base"), ("/nxcompat", "nx_compat"),
                                        ("/highentropyva", "high_entropy_va"), ("/guard:cf", "guard_cf")):
                if flag in all_flags and hardening.get(property_name) is False:
                    checks.append(_check(f"command_binary.{property_name}_mismatch", "FAIL", scope, evidence,
                                         f"{flag} was requested but absent from the PE image"))
    groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for action in compile_actions:
        groups[str(action.get("project"))].append(action)
    for project, values in sorted(groups.items()):
        postures = {(check["check_id"], check["status"]) for check in checks
                    if check["scope"] in {str(item.get("compile_unit_id") or item.get("build_action_id")) for item in values}
                    and check["check_id"] in {"gnu.stack_protector", "gnu.fortify", "gnu.control_flow", "msvc.gs"}}
        by_id: dict[str, set[str]] = defaultdict(set)
        for check_id, status in postures:
            if status in {"PASS", "FAIL"}:
                by_id[check_id].add(status)
        for check_id, statuses in sorted(by_id.items()):
            if len(statuses) > 1:
                checks.append(_check("cross_tu.inconsistent." + check_id.replace(".", "_"), "FAIL", project,
                                     [str(item.get("build_action_id")) for item in values],
                                     "translation units disagree on an applicable protection"))
    return checks


def validate_inference(proposal: Mapping[str, Any], *, checks: Iterable[Mapping[str, Any]],
                       evidence_ids: Iterable[str]) -> dict[str, Any]:
    allowed = set(evidence_ids)
    by_check: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in checks:
        by_check[str(item["check_id"])].append(item)
    observations = proposal.get("observations", [])
    if not isinstance(observations, list) or len(observations) > 100:
        raise ValueError("inference observations exceed bound")
    accepted, rejected = [], []
    for index, raw in enumerate(observations):
        if not isinstance(raw, Mapping):
            rejected.append({"index": index, "reason": "observation is not an object"})
            continue
        evidence = raw.get("evidence_ids", [])
        if not isinstance(evidence, list) or not evidence or any(str(item) not in allowed for item in evidence):
            rejected.append({"index": index, "reason": "observation has unresolved evidence"})
            continue
        claim = str(raw.get("claim", ""))[:8192]
        check_id = str(raw.get("check_id", ""))
        candidates = by_check.get(check_id, [])
        requested_scope = raw.get("scope")
        if requested_scope is not None:
            candidates = [item for item in candidates if str(item.get("scope")) == str(requested_scope)]
        evidence_set = set(map(str, evidence))
        evidenced = [item for item in candidates if evidence_set & set(map(str, item.get("evidence", ())))]
        related = evidenced[0] if len(evidenced) == 1 else candidates[0] if len(candidates) == 1 else None
        if not claim or related is None:
            rejected.append({"index": index, "reason": "observation lacks a known deterministic check"})
            continue
        disposition = "CONFIRMED" if related["status"] == "FAIL" else "REFUTED" if related["status"] == "PASS" else "UNVALIDATED"
        accepted.append({"observation_id": _sha({"index": index, "claim": claim, "evidence": evidence}),
                         "claim": claim, "check_id": check_id, "evidence_ids": sorted(set(map(str, evidence))),
                         "model_status": "OBSERVATION", "validation": disposition})
    return {"observations": accepted, "rejections": rejected,
            "confirmed_count": sum(item["validation"] == "CONFIRMED" for item in accepted),
            "refuted_count": sum(item["validation"] == "REFUTED" for item in accepted),
            "unvalidated_count": sum(item["validation"] == "UNVALIDATED" for item in accepted)}


@dataclass(frozen=True, slots=True)
class InferenceResult:
    proposal: Mapping[str, Any]
    input_tokens: int = 0
    output_tokens: int = 0
    cache_tokens: int = 0


class InferenceClient(Protocol):
    def complete(self, request: Mapping[str, Any], *, timeout_seconds: int) -> InferenceResult: ...


def shard_fingerprint(*, command_artifacts: Iterable[Mapping[str, Any]], binary_hashes: Iterable[str],
                      tool_identity: Mapping[str, Any], model_identity: Mapping[str, Any],
                      upstream_manifest_sha256: str) -> str:
    return _sha({"schema": SCHEMA, "commands": sorted(command_artifacts, key=lambda item: str(item.get("sha256"))),
                 "binary_hashes": sorted(binary_hashes), "tool_identity": tool_identity,
                 "rule_version": RULE_VERSION, "parser_version": PARSER_VERSION,
                 "normalizer_version": NORMALIZER_VERSION, "model_identity": model_identity,
                 "guidance_identity": GUIDANCE_IDENTITY, "upstream_manifest_sha256": upstream_manifest_sha256})
