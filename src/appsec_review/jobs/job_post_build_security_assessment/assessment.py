"""Deterministic post-build provenance, binary inspection, and assessment primitives.

Target-produced files and command material are untrusted data.  This module never executes a
target artifact and never returns unredacted command or environment text for logging/indexing.
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import struct
from typing import Any, Iterable, Mapping

from appsec_review.storage import canonical_json, file_sha256

from .hardening import Expectation, FamilyExpectations, expectations_for, unknown_family


SCHEMA = "appsec-review/post-build-security-assessment/1"
PROVENANCE_SCHEMA = "appsec-review/build-command-provenance/1"
INSPECTION_SCHEMA = "appsec-review/binary-inspection/1"
RULE_VERSION = "build-security-rules/2"
PARSER_VERSION = "build-security-binary-parser/2"
NORMALIZER_VERSION = "build-security-command-normalizer/2"
GUIDANCE_IDENTITY = "build-security-inference-guidance/2"
INFERENCE_PROPOSAL_SCHEMA = "appsec-review/build-security-inference-proposal/1"
INFERENCE_RESPONSE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["schema", "observations"],
    "properties": {
        "schema": {"const": INFERENCE_PROPOSAL_SCHEMA},
        "observations": {"type": "array", "maxItems": 100, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["claim", "check_id", "evidence_ids"],
            "properties": {
                "claim": {"type": "string", "minLength": 1, "maxLength": 8192},
                "check_id": {"type": "string", "minLength": 1},
                "scope": {"type": "string", "minLength": 1},
                "evidence_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            },
        }},
    },
}
MAX_ARGV = 4096
MAX_ARG_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024

_SECRET = re.compile(
    r"(?i)(authorization|bearer|password|passwd|secret|token|api[_-]?key|credential|private[_-]?key|sign(?:ing)?[_-]?key)"
)
_HOST_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|/home/|/Users/|/var/|/tmp/|\\\\)")
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".s", ".asm"}
_FORTIFIABLE_ELF_IMPORTS = frozenset({
    "memcpy", "memmove", "memset", "bcopy", "bzero", "strcpy", "stpcpy", "strncpy",
    "strcat", "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf", "printf",
    "fprintf", "vprintf", "vfprintf", "gets", "fgets", "fread", "read", "pread",
    "readlink", "realpath", "getcwd", "getwd", "recv", "recvfrom", "poll", "ppoll",
    "confstr", "ttyname_r",
})
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


def _driver_argv(argv: Iterable[str]) -> tuple[str, ...]:
    values = tuple(argv)
    while values and PurePosixPath(values[0].replace("\\", "/")).name.lower() in {
        "ccache", "sccache", "distcc", "ccache.exe", "sccache.exe", "distcc.exe",
    }:
        values = values[1:]
    return values


def classify_action(argv: Iterable[str]) -> str:
    values = _driver_argv(argv)
    if not values:
        return "unknown"
    executable = PurePosixPath(values[0].replace("\\", "/")).name.lower()
    flags = {item.lower() for item in values[1:]}
    if re.fullmatch(r"(?:[\w]+-)*(?:ar|llvm-ar|gcc-ar)(?:-\d+(?:\.\d+)*)?(?:\.exe)?", executable):
        return "archiver"
    if executable in {"lib", "lib.exe"} or re.fullmatch(r"llvm-lib(?:-\d+(?:\.\d+)*)?(?:\.exe)?", executable):
        return "librarian"
    if executable in {"rc", "rc.exe"} or re.fullmatch(
        r"(?:[\w]+-)*(?:windres|llvm-rc)(?:-\d+(?:\.\d+)*)?(?:\.exe)?", executable
    ):
        return "resource_compiler"
    if executable in {"ml", "ml64", "ml.exe", "ml64.exe"} or re.fullmatch(
        r"(?:[\w]+-)*(?:as|llvm-as)(?:-\d+(?:\.\d+)*)?(?:\.exe)?", executable
    ):
        return "assembler"
    if executable in {"link", "link.exe"} or re.fullmatch(
        r"(?:[\w]+-)*(?:ld|ld\.bfd|ld\.gold|ld\.lld|lld|lld-link)(?:-\d+(?:\.\d+)*)?(?:\.exe)?", executable
    ):
        return "linker"
    if executable in {"install_name_tool", "codesign", "signtool"} or re.fullmatch(
        r"(?:[\w]+-)*(?:strip|llvm-strip|objcopy|llvm-objcopy|ranlib|llvm-ranlib|gcc-ranlib)(?:-\d+(?:\.\d+)*)?(?:\.exe)?",
        executable,
    ):
        return "post_link"
    compiler = bool(re.fullmatch(
        r"(?:(?:[\w]+-)*)(?:cc|c\+\+|gcc|g\+\+|clang|clang\+\+|clang-cl|cl)(?:-\d+(?:\.\d+)*)?(?:\.exe)?",
        executable))
    if compiler:
        if {"-cc1", "-cc1as", "-e", "/e", "/ep", "/p", "-m", "-mm", "-fsyntax-only"} & flags:
            return "unknown"
        if {"-c", "/c"} & flags:
            return "compiler"
        if any(item.lower().startswith(("-o", "/out:")) for item in values[1:]) or not ({"-e", "-m"} & flags):
            return "linker_driver"
    return "unknown"


def _split_command(value: Mapping[str, Any]) -> list[str]:
    raw = value.get("arguments")
    if not isinstance(raw, list):
        raw = value.get("argv")
    if isinstance(raw, list):
        return [str(item) for item in raw]
    command = value.get("command")
    if not isinstance(command, str) or len(command) > MAX_ARG_BYTES:
        raise ValueError("build action requires bounded arguments or command")
    return shlex.split(command, posix=True)


def _option_tokens(argv: Iterable[str]) -> list[str]:
    values = _driver_argv(argv)[1:]
    tokens = []
    index = 0
    while index < len(values):
        value = values[index]
        if value in {"-D", "-U"} and index + 1 < len(values):
            index += 1
            value += values[index]
        if value.startswith("-Wl,"):
            tokens.extend(value[4:].split(","))
        elif value != "-Xlinker":
            tokens.append(value)
        index += 1
    return tokens


def has_unexpanded_response_file(argv: Iterable[str]) -> bool:
    return any(token.startswith("@") for token in _option_tokens(argv))


def _effective_options(argv: Iterable[str]) -> dict[str, bool | None]:
    """Evaluate the supported ordered switches, not the union of every requested setting."""
    tokens = _option_tokens(argv)
    state: dict[str, bool | None] = {}
    if any(token.startswith("@") for token in tokens):
        return {"uncertain": True}
    switches = {
        "-fno-stack-protector": ("stack", False),
        "-fstack-protector": ("stack", True),
        "-fstack-protector-strong": ("stack", True),
        "-fstack-protector-all": ("stack", True),
        "-fstack-protector-explicit": ("stack", True),
        "-pie": ("pie", True), "-no-pie": ("pie", False),
        "-fpie": ("pic", True), "-fpic": ("pic", True),
        "-fno-pie": ("pic", False), "-fno-pic": ("pic", False),
        "relro": ("relro", True), "norelro": ("relro", False),
        "now": ("now", True), "lazy": ("now", False),
        "noexecstack": ("nx_stack", True), "execstack": ("nx_stack", False),
        "/gs": ("gs", True), "/gs-": ("gs", False),
        "/sdl": ("sdl", True), "/sdl-": ("sdl", False),
        "/guard:cf": ("guard_cf", True), "/guard:cf-": ("guard_cf", False),
        "/dynamicbase": ("dynamic_base", True), "/dynamicbase:no": ("dynamic_base", False),
        "/nxcompat": ("nx_compat", True), "/nxcompat:no": ("nx_compat", False),
        "/highentropyva": ("high_entropy_va", True), "/highentropyva:no": ("high_entropy_va", False),
    }
    for index, token in enumerate(tokens):
        lower = token.lower()
        if lower.startswith("-z") and len(lower) > 2:
            lower = lower[2:]
        elif lower in {"relro", "norelro", "now", "lazy", "execstack", "noexecstack"} and (
                index == 0 or tokens[index - 1] != "-z"):
            continue
        if lower in switches:
            key, enabled = switches[lower]
            state[key] = enabled
        elif re.fullmatch(r"-O(?:[0-3gsz]|fast)?", token):
            state["optimized"] = token != "-O0"
        elif token == "-D_FORTIFY_SOURCE" or token.startswith("-D_FORTIFY_SOURCE="):
            value = token.partition("=")[2] if "=" in token else "1"
            state["fortify"] = value != "0" if value in {"0", "1", "2", "3"} else None
        elif token == "-U_FORTIFY_SOURCE":
            state["fortify"] = False
        elif token == "-fcf-protection" or token.startswith("-fcf-protection="):
            value = token.partition("=")[2] or "full"
            state["control_flow"] = value != "none" if value in {"none", "full", "branch", "return"} else None
        elif token.startswith("-fvisibility="):
            state["visibility"] = token == "-fvisibility=hidden"
    return state


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
    raw_directory = row.get("directory") if row.get("directory") is not None else row.get("working_directory")
    directory = _safe_path(str(raw_directory or "<unknown-working-directory>"), roots=roots)
    inputs, outputs = discover_io(normalized, working_directory=directory)
    classification = classify_action(argv)
    source_file = row.get("file")
    if source_file is None and isinstance(row.get("inputs"), list):
        for item in row["inputs"]:
            if isinstance(item, Mapping) and isinstance(item.get("workspace_path"), str):
                if PurePosixPath(item["workspace_path"].replace("\\", "/")).suffix.lower() in _SOURCE_SUFFIXES:
                    source_file = item["workspace_path"]
                    break
    return {
        "schema": PROVENANCE_SCHEMA,
        "run_id": run_id,
        "target_snapshot": target_snapshot,
        "project": project,
        "build_root": build_root,
        "configuration": configuration,
        "build_action_id": action_id,
        "compile_unit_id": _sha({"action": action_id, "source": source_file}) if classification == "compiler" else None,
        "linked_artifact_ids": [],
        "classification": classification,
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
        "output_hashes", "resolved_outputs", "input_artifact_ids", "start", "end", "exit_status",
        "timing_granularity", "argv_source", "producer",
    )})


def _bounded_c_string(data: bytes, offset: int, limit: int = 8192) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    return data[offset:offset + limit].split(b"\0", 1)[0].decode("utf-8", "replace")


def _elf_gnu_property_control_flow(
    data: bytes, endian: str, bits: int, machine_id: int, sections: list[dict[str, Any]],
) -> bool | None:
    if machine_id not in {3, 62, 183}:
        return None
    prop_sections = [item for item in sections if item["name"] == ".note.gnu.property"]
    if not prop_sections:
        return None
    prop_align = 8 if bits == 64 else 4
    target_prop = 0xC0000000 if machine_id == 183 else 0xC0000002
    parsed_gnu_property = False
    for section in prop_sections:
        sec_start = int(section["offset"])
        sec_end = sec_start + int(section["size"])
        if sec_start < 0 or sec_end > len(data) or sec_start >= sec_end:
            return None
        cursor = sec_start
        while cursor + 12 <= sec_end:
            namesz, descsz, note_type = struct.unpack_from(endian + "III", data, cursor)
            name_start = cursor + 12
            desc_offset = (12 + namesz + prop_align - 1) & ~(prop_align - 1)
            desc_start = cursor + desc_offset
            desc_end = desc_start + descsz
            next_note = cursor + ((desc_offset + descsz + prop_align - 1) & ~(prop_align - 1))
            if name_start + namesz > desc_start or desc_end > sec_end or next_note <= cursor:
                return None
            if note_type == 5 and data[name_start:name_start + namesz] == b"GNU\x00":
                parsed_gnu_property = True
                pcur = desc_start
                while pcur + 8 <= desc_end:
                    pr_type, pr_datasz = struct.unpack_from(endian + "II", data, pcur)
                    pdata_start = pcur + 8
                    pdata_end = pdata_start + pr_datasz
                    if pdata_end > desc_end:
                        return None
                    if pr_type == target_prop and pr_datasz >= 4:
                        features = struct.unpack_from(endian + "I", data, pdata_start)[0]
                        if features & 0x3:
                            return True
                    pcur += (8 + pr_datasz + prop_align - 1) & ~(prop_align - 1)
            cursor = min(sec_end, next_note)
    return False if parsed_gnu_property else None


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
    gaps = []
    header_size = 64 if bits == 64 else 52
    phsize, shsize = (56, 64) if bits == 64 else (32, 40)

    def table_complete(offset: int, entry_size: int, count: int, minimum: int, label: str) -> bool:
        if not count:
            return True
        if offset < header_size or entry_size < minimum:
            gaps.append(f"ELF {label} table has invalid offset or entry size")
            return False
        if offset + count * entry_size > len(data):
            gaps.append(f"ELF {label} table is truncated")
            return False
        return True

    programs_complete = table_complete(phoff, phentsize, phnum, phsize, "program header")
    sections_complete = table_complete(shoff, shentsize, shnum, shsize, "section header")
    program_headers = []
    for index in range(phnum if phentsize >= phsize and phoff >= header_size else 0):
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
    for index in range(shnum if shentsize >= shsize and shoff >= header_size else 0):
        offset = shoff + index * shentsize
        if offset + shsize > len(data):
            break
        raw_sections.append(struct.unpack_from(endian + shfmt, data, offset))
    strings = b""
    names_complete = sections_complete
    if shstrndx and shstrndx < len(raw_sections):
        item = raw_sections[shstrndx]
        section_offset, section_size = item[4], item[5]
        strings = data[section_offset:section_offset + section_size]
        if section_offset + section_size > len(data):
            names_complete = False
            gaps.append("ELF section name table is truncated")
    elif shstrndx:
        names_complete = False
        gaps.append("ELF section name table is unavailable")
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
    dynamic_complete = programs_complete
    for item in program_headers:
        if item["type"] != 2:
            continue
        if item["offset"] + item["filesz"] > len(data) or item["filesz"] % dynamic_size:
            dynamic_complete = False
            gaps.append("ELF dynamic table is truncated")
        start, end = item["offset"], min(len(data), item["offset"] + item["filesz"])
        terminated = False
        for offset in range(start, end - dynamic_size + 1, dynamic_size):
            tag, value = struct.unpack_from(endian + dynamic_entry, data, offset)
            if tag == 0:
                terminated = True
                break
            dynamic.append((tag, value))
        if not terminated:
            dynamic_complete = False
            gaps.append("ELF dynamic table terminator is unavailable")
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
    stack_header = next((item for item in program_headers if item["type"] == 0x6474E551), None)
    note_gnu_stack = next((item for item in sections if item["name"] == ".note.GNU-stack"), None)
    artifact_kind = ("pie_executable" if interpreter else "shared_library" if programs_complete else "unknown") if e_type == 3 else {
        1: "object", 2: "executable", 4: "core"}.get(e_type, "unknown")
    dynstr_missing = any(item["type"] == 2 for item in program_headers) and not dynamic_strings
    if dynstr_missing:
        gaps.append("ELF dynamic string table could not be resolved")
    import_set = sorted(set(imports))[:100000]
    import_bases = {name.split("@", 1)[0] for name in import_set}
    linked_elf = artifact_kind in {"executable", "pie_executable", "shared_library"}
    nx_stack = (
        not bool(stack_header["flags"] & 1) if stack_header is not None else
        not bool(note_gnu_stack["flags"] & 0x4) if artifact_kind == "object" and note_gnu_stack is not None else
        None
    )
    stack_canary = (
        True if bool(import_bases & {"__stack_chk_fail", "__stack_chk_fail_local", "__stack_smash_handler"}) else
        False if linked_elf and bool(import_bases) and not dynstr_missing else
        None
    )
    fortify = (
        True if any(base.endswith("_chk") for base in import_bases) else
        False if linked_elf and bool(import_bases & _FORTIFIABLE_ELF_IMPORTS) and not dynstr_missing else
        None
    )
    return {
        "format": "ELF", "kind": artifact_kind,
        "architecture": machine, "bits": bits,
        "headers": {"type": e_type, "machine": machine, "program_header_count": phnum, "section_count": shnum},
        "sections": sections[:4096], "symbols": {"present": True if ".symtab" in names else False if names_complete else None,
                                                     "stripped": False if ".symtab" in names else True if names_complete else None,
                                                     "names": sorted(set(symbols))[:100000]},
        "imports": import_set, "exports": sorted(set(exports))[:100000],
        "relocations": [item["name"] for item in sections if item["name"].startswith((".rel", ".rela"))],
        "interpreter": interpreter, "rpath": rpath, "runpath": runpath,
        "dependencies": dependencies, "archive_members": [],
        "build_id": build_id, "debug": {"present": True if any(name.startswith(".debug") for name in names) else
                                      False if names_complete else None,
                                      "sections": sorted(name for name in names if name.startswith(".debug"))},
        "hardening": {
            "pie": True if artifact_kind == "pie_executable" else False if artifact_kind == "executable" else None,
            "relro": True if any(item["type"] == 0x6474E552 for item in program_headers) else
                     False if programs_complete else None,
            "now": True if now else False if dynamic and dynamic_complete else None,
            "nx_stack": nx_stack,
            "control_flow": _elf_gnu_property_control_flow(data, endian, bits, machine, sections) if linked_elf else None,
            "stack_canary": stack_canary,
            "fortify": fortify,
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
                "size_bytes": size, "format": "unsupported", "kind": "unknown",
                "parser_identity": PARSER_VERSION, "executed": False, "headers": {}, "sections": [],
                "symbols": {"present": None, "stripped": None}, "imports": [], "exports": [],
                "relocations": [], "interpreter": None, "rpath": [], "runpath": [], "dependencies": [],
                "archive_members": [], "build_id": None, "debug": {"present": None, "sections": []},
                "hardening": {}, "gaps": ["artifact exceeds binary inspection byte bound"]}
    data = path.read_bytes()
    base = {"schema": INSPECTION_SCHEMA, "path": path.name, "sha256": hashlib.sha256(data).hexdigest(),
            "size_bytes": len(data), "parser_identity": PARSER_VERSION, "executed": False}
    try:
        if data.startswith(b"\x7fELF"):
            result = _elf(path, data)
        elif data.startswith(b"MZ"):
            result = _pe(path, data)
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
        elif path.suffix.lower() in {".obj", ".o"} and len(data) >= 20:
            result = _coff_object(path, data)
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


_FLAG_DRIVEN_FAMILIES = frozenset({"native", "node", "python", "php", "wasm"})


def family_expectations(family: str, has_compile_actions: bool) -> FamilyExpectations | None:
    """``None`` when captured C/C++ flags decide; otherwise the family's documented defaults.

    Native units, and mixed units whose own build captured C/C++ compiles, are flag-driven. Every
    other family uses its typed table; a family without one assumes nothing.
    """
    if family == "native" or (family in _FLAG_DRIVEN_FAMILIES and has_compile_actions):
        return None
    return expectations_for(family) or unknown_family(family)


def _expected(table: FamilyExpectations | None, check_id: str, scope: str, evidence: Iterable[str],
              observed: Any, rationale: str) -> dict[str, Any]:
    if table is None:
        return _check(check_id, "PASS" if observed is True else "FAIL" if observed is False else "UNKNOWN",
                      scope, evidence, rationale)
    expectation = table.for_check(check_id)
    if expectation.expectation is Expectation.REQUIRED:
        value = _check(check_id, "PASS" if observed is True else "FAIL" if observed is False else "UNKNOWN",
                       scope, evidence, f"{rationale}; {expectation.reason}")
    else:
        value = _check(check_id, "NOT_APPLICABLE", scope, evidence,
                       f"{table.toolchain}: {expectation.reason}", applicable=False)
    value["expectation"] = {"family": table.family, "value": expectation.expectation.value,
                            "source": expectation.source}
    return value


def _action_compiles_source(action: Mapping[str, Any]) -> bool:
    if action.get("classification") == "compiler" or bool(action.get("compile_unit_id")):
        return True
    candidates = (*action.get("declared_inputs", ()), *_driver_argv(action.get("argv", ()))[1:])
    return any(PurePosixPath(str(item).replace("\\", "/")).suffix.lower() in _SOURCE_SUFFIXES for item in candidates)


def deterministic_checks(actions: Iterable[Mapping[str, Any]], artifacts: Iterable[Mapping[str, Any]],
                         *, family: str = "native") -> list[dict[str, Any]]:
    actions, artifacts = list(actions), list(artifacts)
    checks: list[dict[str, Any]] = []
    compile_actions = [item for item in actions if item.get("classification") in {"compiler", "linker_driver"}]
    tu_actions = [item for item in compile_actions if _action_compiles_source(item)]
    table = family_expectations(family, bool(compile_actions))
    for action in compile_actions:
        options = _effective_options(action.get("argv", ()))
        compiles_source = _action_compiles_source(action)

        def posture(key: str) -> str:
            return "PASS" if options.get(key) is True else "FAIL" if options.get(key) is False else "UNKNOWN"

        scope = str(action.get("compile_unit_id") or action.get("build_action_id"))
        evidence = [str(action.get("build_action_id"))]
        driver = _driver_argv(action.get("argv", ()))
        executable = PurePosixPath(driver[0].replace("\\", "/")).name.lower() if driver else ""
        windows = executable in {"cl", "cl.exe", "clang-cl", "clang-cl.exe"}
        if windows:
            if compiles_source:
                checks.extend([
                    _check("msvc.gs", posture("gs"), scope, evidence, "/GS compile protection"),
                    _check("msvc.guard_cf.requested", posture("guard_cf"), scope, evidence, "Control Flow Guard compile request"),
                    _check("msvc.sdl", posture("sdl"), scope, evidence, "SDL checks"),
                ])
        else:
            insecure = ("UNKNOWN" if options.get("uncertain") else
                        "FAIL" if any(options.get(key) is False for key in
                                      ("stack", "pie", "pic", "relro", "now", "nx_stack")) else "PASS")
            if compiles_source:
                fortify = ("FAIL" if options.get("fortify") is False else
                           "PASS" if options.get("fortify") is True and options.get("optimized") is True else
                           "FAIL" if options.get("fortify") is True else "UNKNOWN")
                checks.extend([
                    _check("gnu.stack_protector", posture("stack"), scope, evidence, "stack protector compile posture"),
                    _check("gnu.fortify", fortify, scope, evidence, "fortified libc compile posture"),
                    _check("gnu.control_flow", posture("control_flow"), scope, evidence, "compiler control-flow protection"),
                    _check("gnu.visibility", "PASS" if options.get("visibility") is True else "UNKNOWN",
                           scope, evidence, "default symbol visibility"),
                ])
            checks.append(
                _check("gnu.insecure_override", insecure, scope, evidence,
                       "explicit insecure compile/link overrides")
            )
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
                linked_protection = check_id in {
                    "elf.pie", "elf.relro", "elf.now", "elf.control_flow", "elf.stack_canary", "elf.fortify",
                }
                if linked_protection and not executable and kind not in {"object", "core"}:
                    checks.append(_check(check_id, "UNKNOWN", scope, evidence,
                                         "ELF linked-image applicability is unknown because artifact classification is unavailable"))
                elif ((not executable and linked_protection) or
                        (check_id == "elf.pie" and kind == "shared_library")):
                    checks.append(_check(check_id, "NOT_APPLICABLE", scope, evidence, "not a linked executable/shared object", applicable=False))
                else:
                    checks.append(_expected(table, check_id, scope, evidence, hardening.get(key),
                                            f"observed ELF {key}"))
        elif fmt == "PE/COFF":
            for check_id, key in (("pe.dynamic_base", "dynamic_base"), ("pe.nx_compat", "nx_compat"),
                                  ("pe.high_entropy_va", "high_entropy_va"), ("pe.guard_cf", "guard_cf"),
                                  ("pe.safe_seh", "safe_seh"), ("pe.gs", "gs")):
                value = hardening.get(key)
                applicable = not ((key == "safe_seh" and artifact.get("bits") == 64) or
                                  (key == "high_entropy_va" and artifact.get("bits") == 32))
                if key == "high_entropy_va" and artifact.get("bits") not in {32, 64}:
                    value = None
                if not applicable:
                    checks.append(_check(check_id, "NOT_APPLICABLE", scope, evidence, f"observed PE {key}",
                                         applicable=False))
                else:
                    checks.append(_expected(table, check_id, scope, evidence, value, f"observed PE {key}"))
    for artifact in artifacts:
        hardening = artifact.get("hardening", {})
        scope = str(artifact.get("artifact_id") or artifact.get("sha256"))
        producers = [action for action in actions
                     if artifact.get("artifact_id") in action.get("linked_artifact_ids", ())]
        if len(producers) != 1 or producers[0].get("classification") not in {"linker", "linker_driver"}:
            continue
        producer = producers[0]
        options = _effective_options(producer.get("argv", ()))
        evidence = [str(artifact.get("sha256")), str(producer.get("build_action_id"))]
        if artifact.get("format") == "ELF" and artifact.get("kind") in {"executable", "pie_executable", "shared_library"}:
            if options.get("pie") is True and artifact.get("kind") != "shared_library" and hardening.get("pie") is False:
                checks.append(_check("command_binary.pie_mismatch", "FAIL", scope, evidence,
                                     "PIE was requested but the linked ELF is not position independent"))
            if options.get("relro") is True and hardening.get("relro") is False:
                checks.append(_check("command_binary.relro_mismatch", "FAIL", scope, evidence,
                                     "RELRO was requested but absent from the linked ELF"))
            if options.get("now") is True and hardening.get("now") is False:
                checks.append(_check("command_binary.now_mismatch", "FAIL", scope, evidence,
                                     "immediate binding was requested but absent from the linked ELF"))
        if artifact.get("format") == "PE/COFF":
            for flag, property_name in (("/dynamicbase", "dynamic_base"), ("/nxcompat", "nx_compat"),
                                        ("/highentropyva", "high_entropy_va"), ("/guard:cf", "guard_cf")):
                if property_name == "high_entropy_va" and artifact.get("bits") != 64:
                    continue
                if options.get(property_name) is True and hardening.get(property_name) is False:
                    checks.append(_check(f"command_binary.{property_name}_mismatch", "FAIL", scope, evidence,
                                         f"{flag} was requested but absent from the PE image"))
    groups: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for action in tu_actions:
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
                       evidence_ids: Iterable[str],
                       evidence_aliases: Mapping[str, str] | None = None) -> dict[str, Any]:
    if (not isinstance(proposal, Mapping) or set(proposal) != {"schema", "observations"} or
            proposal.get("schema") != INFERENCE_PROPOSAL_SCHEMA):
        raise ValueError("inference proposal must match the closed response schema")
    allowed = set(evidence_ids)
    aliases = evidence_aliases or {}
    by_check: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in checks:
        by_check[str(item["check_id"])].append(item)
    observations = proposal["observations"]
    if not isinstance(observations, list) or len(observations) > 100:
        raise ValueError("inference observations exceed bound")
    accepted, rejected = [], []
    for index, raw in enumerate(observations):
        if not isinstance(raw, Mapping):
            rejected.append({"index": index, "reason": "observation is not an object"})
            continue
        if (set(raw) - {"claim", "check_id", "evidence_ids", "scope"} or
                not {"claim", "check_id", "evidence_ids"} <= set(raw) or
                not isinstance(raw["claim"], str) or len(raw["claim"]) > 8192 or
                not isinstance(raw["check_id"], str) or
                ("scope" in raw and (not isinstance(raw["scope"], str) or not raw["scope"]))):
            rejected.append({"index": index, "reason": "observation does not match the closed response schema"})
            continue
        evidence = raw.get("evidence_ids", [])
        if not isinstance(evidence, list) or not evidence or any(
                not isinstance(item, str) or item not in allowed for item in evidence):
            rejected.append({"index": index, "reason": "observation has unresolved evidence"})
            continue
        claim = raw["claim"]
        check_id = raw["check_id"]
        candidates = by_check.get(check_id, [])
        requested_scope = raw.get("scope")
        if requested_scope is not None:
            candidates = [item for item in candidates if str(item.get("scope")) == str(requested_scope)]
        evidence_set = {aliases.get(item, item) for item in evidence}
        evidenced = [item for item in candidates if evidence_set == set(item.get("evidence", ()))
                     and all(value not in aliases or value == item.get("scope") for value in evidence)]
        related = evidenced[0] if len(evidenced) == 1 else None
        if not claim or related is None:
            rejected.append({"index": index, "reason": "observation lacks a known deterministic check"})
            continue
        disposition = "CONFIRMED" if related["status"] == "FAIL" else "REFUTED" if related["status"] == "PASS" else "UNVALIDATED"
        accepted.append({"observation_id": _sha({"index": index, "claim": claim, "evidence": evidence,
                                               "check_id": check_id, "scope": related["scope"]}),
                         "claim": claim, "check_id": check_id, "scope": related["scope"],
                         "evidence_ids": sorted(set(evidence)),
                         "model_status": "OBSERVATION", "validation": disposition})
    return {"observations": accepted, "rejections": rejected,
            "confirmed_count": sum(item["validation"] == "CONFIRMED" for item in accepted),
            "refuted_count": sum(item["validation"] == "REFUTED" for item in accepted),
            "unvalidated_count": sum(item["validation"] == "UNVALIDATED" for item in accepted)}


def shard_fingerprint(*, command_artifacts: Iterable[Mapping[str, Any]], binary_hashes: Iterable[str],
                      tool_identity: Mapping[str, Any], model_identity: Mapping[str, Any],
                      upstream_manifest_sha256: str, stage_hashes: Mapping[str, str] | None = None,
                      semantic_inputs: Mapping[str, Any] | None = None) -> str:
    return _sha({"schema": SCHEMA, "commands": sorted(command_artifacts, key=lambda item: str(item.get("sha256"))),
                 "binary_hashes": sorted(binary_hashes), "tool_identity": tool_identity,
                 "rule_version": RULE_VERSION, "parser_version": PARSER_VERSION,
                 "normalizer_version": NORMALIZER_VERSION, "model_identity": model_identity,
                 "guidance_identity": GUIDANCE_IDENTITY, "upstream_manifest_sha256": upstream_manifest_sha256,
                 "stage_hashes": dict(stage_hashes or {}), "semantic_inputs": dict(semantic_inputs or {})})
