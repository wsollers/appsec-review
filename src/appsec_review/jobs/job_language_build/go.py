from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
from typing import Any

from appsec_review.config import GoBuildSettings
from appsec_review.container_runtime import VerifiedCapture
from appsec_review.jobs.build_discovery import go_recipe_errors
from appsec_review.storage import canonical_json, file_sha256

from . import elf


CAPTURE_IDENTITY = "appsec-review/go-build-capture/3"
BUILD_FACTS_PARSER = "appsec-review/go-elf-build-facts/1"
PACKAGE_CATALOG_SCHEMA = "appsec-review/go-package-catalog/1"
_LIST_VALUE_OPTIONS = {"-tags", "-mod"}
_GO_TOOLS = {"compile": "compiler", "asm": "assembler", "link": "linker", "cgo": "cgo",
             "pack": "package-builder", "buildid": "post-link"}
_GO_TOOL_PATH = re.compile(r"/(?:[^/]+/)*pkg/tool/[a-z0-9]+_[a-z0-9]+/([a-z0-9]+)")
_GO_DRIVER_PATH = re.compile(r"/(?:[^/]+/)*bin/go")
_LINK_KINDS = {"linker-driver", "linker", "archiver"}
_LINKERS = {"ld", "ld.bfd", "ld.gold", "ld.lld", "lld", "collect2", "mold"}
_ARCHIVERS = {"ar", "llvm-ar"}
_C_DRIVER = re.compile(r"(?:[a-z0-9_]+-)*(?:cc|c\+\+|gcc|g\+\+|clang|clang\+\+)(?:-[0-9.]+)?")
_NATIVE_TOOLS = {"as": "assembler", "ar": "archiver", "llvm-ar": "archiver", "ld": "linker",
                 "ld.bfd": "linker", "ld.gold": "linker", "ld.lld": "linker", "lld": "linker",
                 "collect2": "linker", "mold": "linker", "protoc": "code-generator"}
_COMPILE_ONLY = {"-c", "-E", "-S"}
# The build container's root filesystem is read-only: only these mounts are writable by the
# build, so an executable below them is target-controlled and its name proves nothing.
_WRITABLE_ROOTS = ("/workspace/", "/capture/", "/tmp/", "/dev/", "/proc/", "/run/", "/var/tmp/")
_INPUT_SUFFIXES = {".go", ".s", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".o", ".a", ".syso"}
_INVOCATION_LIMIT = 16384
_EVENT_ORDINAL_LIMIT = 8
_REDACTED = "<redacted"
_PACKAGE_LIMIT = 20000
_PACKAGE_FIELD_LIMIT = 16384
_IMPORT_PATH = re.compile(r"[A-Za-z0-9_.~/@+\-\[\] ]{1,512}")
_BUILDINFO_MAGIC = b"\xff Go buildinf:"
_BUILDINFO_HEADER = 32
_BUILDINFO_LIMIT = 16 * 1024 * 1024
_MODINFO_START = bytes.fromhex("3077af0c9274080241e1c107e6d618e6")
_MODINFO_END = bytes.fromhex("f932433186182072008242104116d8f2")
_MODULE_LIMIT = 8192
_MODULE_PATH = re.compile(r"[A-Za-z0-9_.~/+\-]{1,512}")
_MODULE_VERSION = re.compile(r"[A-Za-z0-9_.~+\-()/]{1,256}")
_MODULE_SUM = re.compile(r"h1:[A-Za-z0-9+/]{43}=")
_GO_VERSION = re.compile(r"(?:go|devel )[A-Za-z0-9_.+\- ]{1,128}")
_BUILD_ID = re.compile(r"[A-Za-z0-9_\-]{1,128}(?:/[A-Za-z0-9_\-]{1,128}){1,3}")
_BUILD_SETTINGS = {"-buildmode", "-compiler", "CGO_ENABLED", "GOARCH", "GOOS", "GOAMD64", "GOARM64"}
_NOTE_LIMIT = 4096
_SHT_PROGBITS, _SHT_NOTE = 1, 7
_SHF_COMPRESSED = 0x800


def validate_dispatch(dispatch: Mapping[str, Any], settings: GoBuildSettings | None = None) -> tuple[str, ...]:
    """Re-check the Go build-only command contract of an accepted recipe before execution."""
    recipe = dispatch.get("recipe")
    if not isinstance(recipe, Mapping) or dispatch.get("build_system", "go") != "go":
        return ("Go execution requires an accepted recipe",)
    errors = list(go_recipe_errors(recipe))
    if "dependency_files" in recipe:
        dependencies = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
        if "go.mod" not in dependencies and "go.work" not in dependencies:
            errors.append("Go recipes require go.mod or go.work in accepted dependency inputs")
    if settings is not None and settings.offline and bool(recipe.get("network_required")):
        errors.append("offline Go policy conflicts with a network-required recipe")
    return tuple(dict.fromkeys(errors))


def build_argv(argv: Sequence[str], settings: GoBuildSettings | None = None) -> tuple[str, ...]:
    """Add `-x` so the retained stderr carries the toolchain trace as a diagnostic stream.

    The trace is never parsed for provenance; process-exec syscall events are the authority.
    """
    values = [str(value) for value in argv]
    if len(values) < 2 or values[0] != "go" or values[1] not in {"build", "generate", "list"}:
        raise ValueError("Go build command is unsupported")
    if values[1] in {"build", "generate"} and "-x" not in values[2:]:
        values.insert(2, "-x")
    if (settings is not None and settings.offline and values[1] in {"build", "generate"} and
            not any(value == "-mod=vendor" or value.startswith("-mod=") for value in values[2:])):
        values.insert(2, "-mod=vendor")
    return tuple(values)


def environment(base: Mapping[str, str], workspace: Path, source_dir: str) -> dict[str, str]:
    values = dict(base)
    values.setdefault("GOCACHE", "/tmp/appsec-go-cache")
    source = workspace / Path(*PurePosixPath(source_dir).parts)
    if (source / "vendor").is_dir():
        flags = values.get("GOFLAGS", "").split()
        if not any(value.startswith("-mod=") for value in flags):
            values["GOFLAGS"] = " ".join([*flags, "-mod=vendor"]).strip()
    return values


def list_argv(commands: Sequence[Sequence[str]]) -> tuple[str, ...]:
    """The bounded package catalog for the packages and build constraints of the first build."""
    packages: list[str] = []
    forwarded: list[str] = []
    for raw in commands:
        if len(raw) < 2 or raw[0] != "go" or raw[1] != "build":
            continue
        index = 2
        while index < len(raw):
            value = str(raw[index])
            if value in _LIST_VALUE_OPTIONS and index + 1 < len(raw):
                forwarded.extend((value, str(raw[index + 1])))
                index += 2
                continue
            if value in {"-o", "-ldflags", "-gcflags", "-asmflags", "-p", "-pkgdir", "-buildmode",
                         "-installsuffix", "-compiler", "-gccgoflags", "-buildvcs", "-pgo", "-cover",
                         "-coverpkg", "-covermode"} and index + 1 < len(raw):
                index += 2
                continue
            if any(value.startswith(prefix + "=") for prefix in _LIST_VALUE_OPTIONS):
                forwarded.append(value)
            elif not value.startswith("-"):
                packages.append(value)
            index += 1
        break
    return ("go", "list", "-deps", "-json", *forwarded, *(packages or ["./..."]))


def _strings(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if (not isinstance(value, list) or len(value) > _PACKAGE_FIELD_LIMIT or
            any(not isinstance(item, str) or "\0" in item or len(item) > 1024 for item in value)):
        raise ValueError(f"go package catalog field is invalid: {field}")
    return sorted(value)


def parse_package_catalog(data: bytes) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Parse complete `go list -deps -json` output; any malformed or partial stream is rejected.

    Returns the receipt rows and, separately, each package's container directory, which is used
    only to resolve the relative file arguments of that package's observed compiler events.
    """
    text = data.decode("utf-8")
    decoder, offset = json.JSONDecoder(), 0
    rows: list[dict[str, Any]] = []
    directories: dict[str, str] = {}
    commands: list[str] = []
    while True:
        while offset < len(text) and text[offset] in " \t\r\n":
            offset += 1
        if offset >= len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, Mapping):
            raise ValueError("go package catalog entry is not an object")
        path = value.get("ImportPath")
        if not isinstance(path, str) or not _IMPORT_PATH.fullmatch(path) or path in directories:
            raise ValueError("go package catalog import path is invalid or duplicated")
        if value.get("Error") is not None or value.get("Incomplete") or value.get("DepsErrors"):
            raise ValueError(f"go package catalog reports an incomplete package: {path}")
        module, directory = value.get("Module"), value.get("Dir", "")
        if module is not None and (not isinstance(module, Mapping) or
                                   not isinstance(module.get("Path"), str) or
                                   not _MODULE_PATH.fullmatch(module["Path"])):
            raise ValueError(f"go package catalog module is invalid: {path}")
        if not isinstance(directory, str) or "\0" in directory or len(directory) > 4096:
            raise ValueError(f"go package catalog directory is invalid: {path}")
        if type(value.get("Standard", False)) is not bool:
            raise ValueError("go package catalog field is invalid: Standard")
        if len(rows) >= _PACKAGE_LIMIT:
            raise ValueError("go package catalog exceeds its package bound")
        rows.append({"import_path": path, "module_path": module["Path"] if module else None,
                     "dependencies": _strings(value.get("Imports"), "Imports"),
                     "standard": bool(value.get("Standard", False)),
                     "cgo_files": _strings(value.get("CgoFiles"), "CgoFiles"),
                     "go_files": _strings(value.get("GoFiles"), "GoFiles"),
                     "compiled_go_files": _strings(value.get("CompiledGoFiles"), "CompiledGoFiles")})
        directories[path] = directory
        if value.get("Name") == "main":
            commands.append(directory)
    if not rows:
        raise ValueError("go package catalog is empty")
    # cmd/go compiles every command package as `-p main`; that name identifies a directory
    # only when the catalog holds exactly one command.
    if len(commands) == 1:
        directories.setdefault("main", commands[0])
    return rows, directories


def module_metadata(workspace: Path, source_dir: str) -> list[dict[str, Any]]:
    root = workspace / Path(*PurePosixPath(source_dir).parts)
    names = {"go.mod", "go.sum", "go.work", "go.work.sum"}
    values = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and (
                path.name in names or path.as_posix().endswith("/vendor/modules.txt")):
            values.append({"workspace_path": path.relative_to(workspace).as_posix(),
                           "sha256": file_sha256(path), "size_bytes": path.stat().st_size,
                           "kind": "go-module-metadata"})
    return values


def _native_kind(name: str, argv: Sequence[str]) -> str | None:
    if name in _NATIVE_TOOLS:
        return _NATIVE_TOOLS[name]
    if _C_DRIVER.fullmatch(name):
        return "compiler-driver" if _COMPILE_ONLY & set(argv[1:]) else "linker-driver"
    return None


def image_owned(executable: str) -> bool:
    """Whether an exec path names a file the build could not have written."""
    if not executable.startswith("/") or "\0" in executable:
        return False
    if any(part in {"", ".", ".."} for part in executable.split("/")[1:]):
        return False  # Only a normalized path names the file the kernel started.
    return not (executable + "/").startswith(_WRITABLE_ROOTS)


def tool_identity(executable: str, argv: Sequence[str]) -> tuple[str, str] | None:
    """Classify the kernel-resolved executable of one successful process-exec event.

    `argv[0]` is caller-chosen and is never consulted. A file below a mount the build can write,
    including a capture wrapper launcher, is not evidence that a toolchain tool ran.
    """
    if not image_owned(executable):
        return None
    name = PurePosixPath(executable).name
    match = _GO_TOOL_PATH.fullmatch(executable)
    if match:
        return (name, _GO_TOOLS[name]) if name in _GO_TOOLS else None
    if name == "go":
        return ("go", "build-driver") if _GO_DRIVER_PATH.fullmatch(executable) else None
    if name in _GO_TOOLS:
        return None  # A Go toolchain tool name outside a toolchain directory.
    kind = _native_kind(name, argv)
    return (name, kind) if kind else None


def _recorded_kind(tool: str, argv: Sequence[str]) -> str | None:
    """The kind a PATH tool-call record names; it selects records to reconcile, nothing more."""
    return "build-driver" if tool == "go" else _native_kind(tool, argv)


def _option(argv: Sequence[str], name: str) -> str | None:
    for index, value in enumerate(argv[:-1]):
        if value == name:
            return argv[index + 1]
    return None


def _mapped(workspace: Path, directory: str | None, value: str) -> dict[str, Any] | None:
    normalized = value.replace("\\", "/")
    if not normalized.startswith("/"):
        if directory is None:
            return None
        normalized = directory.rstrip("/") + "/" + normalized
    if normalized != "/workspace" and not normalized.startswith("/workspace/"):
        return None
    logical = PurePosixPath(normalized[len("/workspace"):].lstrip("/"))
    if ".." in logical.parts:
        return None
    root = workspace.resolve()
    candidate = (root / Path(*logical.parts)).resolve()
    if root != candidate and root not in candidate.parents:
        return None
    result: dict[str, Any] = {"workspace_path": candidate.relative_to(root).as_posix()}
    if candidate.is_file() and not candidate.is_symlink():
        result.update(sha256=file_sha256(candidate), size_bytes=candidate.stat().st_size,
                      mapping="exact-workspace-path", mapping_confidence=1.0)
    else:
        result.update(mapping="declared-path-unresolved", mapping_confidence=0.5)
    return result


def _row(tool: str, kind: str, argv: Sequence[str], workspace: Path,
         package_directories: Mapping[str, str], origin: str) -> dict[str, Any]:
    values = [str(value) for value in argv]
    package = _option(values, "-p") if tool in {"compile", "asm"} else None
    # cmd/go starts a package's compiler and assembler in that package's directory; the
    # catalog directory only resolves the relative file arguments of an observed event.
    directory = package_directories.get(package) if package else None
    outputs = [values[index + 1] for index, value in enumerate(values[:-1]) if value == "-o"]
    inputs = [value for value in values[1:] if value not in outputs and
              PurePosixPath(value).suffix.lower() in _INPUT_SUFFIXES]
    row: dict[str, Any] = {
        "tool": tool, "tool_kind": kind, "argv": values,
        "argv_sha256": hashlib.sha256(canonical_json(values)).hexdigest(),
        "inputs": [item for item in (_mapped(workspace, directory, value) for value in inputs) if item],
        "outputs": [item for item in (_mapped(workspace, None, value) for value in outputs) if item],
        "origin": origin, "mapping_confidence": 1.0}
    if package:
        row["package"] = package
    return row


def _invocation_key(tool: str, argv: Sequence[str]) -> str:
    # A PATH wrapper and the resolved binary differ only in argv[0].
    return hashlib.sha256(canonical_json([tool, *[str(value) for value in argv[1:]]])).hexdigest()


def capture_invocations(captures: Sequence[tuple[int, VerifiedCapture]], workspace: Path,
                        package_directories: Mapping[str, str]
                        ) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Derive Go tool provenance from hash-verified standardized capture records.

    Only a successful process-exec syscall event whose kernel-resolved executable is an
    image-owned toolchain path establishes that a tool ran. A PATH tool-call record is
    reconciled onto an invocation the collector observed and adds exit and stream identities;
    a record with no such event never becomes an invocation and is reported as a gap. Events
    whose argv was truncated or redacted are counted and reported, never reconstructed.
    """
    # An invocation belongs to the one capture record whose event ordinals identify it, so the
    # same argv observed under two commands is two rows.
    rows: dict[tuple[int, str], dict[str, Any]] = {}
    facts = {"process_exec_events": 0, "failed_exec_events": 0, "redacted_exec_events": 0,
             "untrusted_location_exec_events": 0, "truncated_tool_exec_events": 0,
             "tool_call_records": 0, "redacted_tool_calls": 0, "unreconciled_tool_calls": 0,
             "connect_events": 0, "file_open_events": 0, "envp_events": 0, "envp_redacted_names": []}
    redacted_names: set[str] = set()
    truncated = False
    for ordinal, capture in captures:
        label = f"execution-capture:command-{ordinal:03d}"
        record_sha = str(capture.identity["sha256"])
        for event in capture.events():
            kind = event.get("kind")
            if kind == "connect":
                facts["connect_events"] += 1
            elif kind == "file_open":
                facts["file_open_events"] += 1
            if kind != "process_exec":
                continue
            facts["process_exec_events"] += 1
            argv = [str(value) for value in event.get("argv", ())]
            executable = event.get("executable")
            if not isinstance(executable, str) or type(event.get("result")) is not int:
                facts["failed_exec_events"] += 1  # No kernel path or result: not an observed exec.
                continue
            if executable.startswith(_REDACTED) or (argv and argv[0].startswith(_REDACTED)):
                facts["redacted_exec_events"] += 1
                continue
            if event["result"] != 0:
                facts["failed_exec_events"] += 1
                continue
            if event.get("envp_captured"):
                facts["envp_events"] += 1
                redacted_names.update(str(name) for name in event.get("envp_redacted_names", ()))
            if not image_owned(executable):
                facts["untrusted_location_exec_events"] += 1
                continue
            identity = tool_identity(executable, argv)
            if identity is None:
                continue
            if event.get("argv_truncated"):
                facts["truncated_tool_exec_events"] += 1
                continue
            tool, tool_kind = identity
            key = (ordinal, _invocation_key(tool, argv))
            row = rows.get(key)
            if row is None:
                if len(rows) >= _INVOCATION_LIMIT:
                    truncated = True
                    continue
                row = rows[key] = _row(tool, tool_kind, argv, workspace, package_directories,
                                       f"{label}:event-{event.get('ordinal')}")
                row["evidence"] = {"capture_record_sha256": record_sha, "tool_call": None,
                                   "process_exec": {"count": 0, "event_ordinals": [],
                                                    "executable": executable}}
            observed = row["evidence"]["process_exec"]
            observed["count"] += 1
            if len(observed["event_ordinals"]) < _EVENT_ORDINAL_LIMIT:
                observed["event_ordinals"].append(event.get("ordinal"))
        for call in capture.tool_calls:
            document = call["record"]
            facts["tool_call_records"] += 1
            argv = [str(value) for value in document.get("argv", ())]
            if argv and argv[0].startswith(_REDACTED):
                facts["redacted_tool_calls"] += 1
                continue
            tool = str(document.get("tool", ""))
            if _recorded_kind(tool, argv) is None:
                continue
            row = rows.get((ordinal, _invocation_key(tool, argv)))
            if row is None:
                facts["unreconciled_tool_calls"] += 1
                continue
            if row["evidence"]["tool_call"] is None:
                row["evidence"]["tool_call"] = {
                    "uri": call["uri"], "sha256": call["sha256"], "exit_code": document.get("exit_code"),
                    "stdout_sha256": document.get("stdout", {}).get("sha256"),
                    "stderr_sha256": document.get("stderr", {}).get("sha256")}
    for row in rows.values():
        row["mapping"] = ("syscall-process-exec+tool-call" if row["evidence"]["tool_call"] else
                          "syscall-process-exec")
    facts["envp_redacted_names"] = sorted(redacted_names)[:256]
    gaps: list[str] = []
    if facts["redacted_exec_events"]:
        gaps.append(f"{facts['redacted_exec_events']} process-exec events were redacted by the secret "
                    "scan; their tool provenance is unavailable")
    if facts["redacted_tool_calls"]:
        gaps.append(f"{facts['redacted_tool_calls']} tool-call records were redacted by the secret "
                    "scan and could not be reconciled")
    if facts["truncated_tool_exec_events"]:
        gaps.append(f"{facts['truncated_tool_exec_events']} toolchain process-exec events had truncated "
                    "argv; their tool provenance is unavailable")
    if facts["unreconciled_tool_calls"]:
        gaps.append(f"{facts['unreconciled_tool_calls']} tool-call records had no matching successful "
                    "process-exec event and are not claimed as tool execution")
    if truncated:
        gaps.append("Go tool invocation catalog truncated at its row bound")
    return list(rows.values()), facts, gaps


def _uvarint(data: bytes, offset: int) -> tuple[int, int]:
    value = shift = 0
    for index in range(offset, min(offset + 10, len(data))):
        byte = data[index]
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            if index - offset == 9 and byte > 1:
                break
            return value, index + 1
        shift += 7
    raise ValueError("Go build information length is truncated or overflows")


def _length_prefixed(data: bytes, offset: int, what: str) -> tuple[bytes, int]:
    size, start = _uvarint(data, offset)
    if size > len(data) - start:
        raise ValueError(f"Go build information {what} extends past its section")
    return data[start:start + size], start + size


def _module(fields: Sequence[str]) -> dict[str, Any]:
    if len(fields) not in (2, 3) or not _MODULE_PATH.fullmatch(fields[0]) or \
            not _MODULE_VERSION.fullmatch(fields[1]) or \
            (len(fields) == 3 and fields[2] and not _MODULE_SUM.fullmatch(fields[2])):
        raise ValueError("Go build information module record is invalid")
    return {"path": fields[0], "version": fields[1], "sum": fields[2] if len(fields) == 3 and fields[2] else None}


def parse_build_info(data: bytes) -> dict[str, Any]:
    """Parse one complete `.go.buildinfo` section in the Go 1.18+ inline-string layout."""
    if len(data) < _BUILDINFO_HEADER or len(data) > _BUILDINFO_LIMIT or \
            data[:len(_BUILDINFO_MAGIC)] != _BUILDINFO_MAGIC:
        raise ValueError("Go build information header is invalid")
    pointer_size, flags = data[14], data[15]
    if pointer_size not in (4, 8) or flags & ~0x3 or any(data[16:_BUILDINFO_HEADER]):
        raise ValueError("Go build information header is invalid")
    if not flags & 0x2:
        raise ValueError("Go build information uses the unsupported pre-1.18 pointer layout")
    version_bytes, offset = _length_prefixed(data, _BUILDINFO_HEADER, "version")
    module_bytes, offset = _length_prefixed(data, offset, "module data")
    if any(data[offset:]):
        raise ValueError("Go build information has trailing data after its declared strings")
    version = version_bytes.decode("utf-8")
    if not _GO_VERSION.fullmatch(version):
        raise ValueError("Go build information toolchain version is invalid")
    info: dict[str, Any] = {"go_version": version, "path": None, "main": None, "dependencies": [],
                            "settings": {}}
    if not module_bytes:
        return info
    if (len(module_bytes) < 33 or module_bytes[:16] != _MODINFO_START or
            module_bytes[-16:] != _MODINFO_END or module_bytes[-17:-16] != b"\n"):
        raise ValueError("Go build information module data sentinels are invalid")
    text = module_bytes[16:-16].decode("utf-8")
    for line in text[:-1].split("\n"):
        fields = line.split("\t")
        if fields[0] == "path" and len(fields) == 2 and info["path"] is None and \
                _MODULE_PATH.fullmatch(fields[1]):
            info["path"] = fields[1]
        elif fields[0] == "mod" and info["main"] is None:
            info["main"] = _module(fields[1:])
        elif fields[0] == "dep":
            if len(info["dependencies"]) >= _MODULE_LIMIT:
                raise ValueError("Go build information dependency count exceeds its bound")
            info["dependencies"].append(_module(fields[1:]))
        elif fields[0] == "=>" and info["dependencies"] and "replaced_by" not in info["dependencies"][-1]:
            info["dependencies"][-1]["replaced_by"] = _module(fields[1:])
        elif fields[0] == "build" and len(fields) == 2 and "=" in fields[1]:
            key, value = fields[1].split("=", 1)
            # Linker and compiler flag settings can carry embedded values; only fixed
            # platform facts are published.
            if key in _BUILD_SETTINGS and re.fullmatch(r"[A-Za-z0-9_.\-]{1,64}", value):
                info["settings"][key] = value
        else:
            raise ValueError("Go build information module line is invalid")
    return info


def parse_build_id_note(data: bytes) -> str:
    """Return the Go build ID from one complete `.note.go.buildid` section."""
    if len(data) > _NOTE_LIMIT:
        raise ValueError("Go build ID note exceeds its bound")
    identifiers: list[str] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError("Go build ID note header is truncated")
        name_size, description_size, kind = struct.unpack_from("<III", data, offset)
        name_end = offset + 12 + name_size
        description_start = (name_end + 3) & ~3
        description_end = description_start + description_size
        if name_end > len(data) or description_start > len(data) or description_end > len(data):
            raise ValueError("Go build ID note extends past its section")
        if data[offset + 12:name_end] == b"Go\0\0" and kind == 4:
            identifiers.append(data[description_start:description_end].decode("ascii"))
        offset = (description_end + 3) & ~3
    if len(identifiers) != 1 or not _BUILD_ID.fullmatch(identifiers[0]):
        raise ValueError("Go build ID note does not hold exactly one valid build ID")
    return identifiers[0]


def build_facts(path: Path) -> dict[str, Any]:
    """Read the Go build ID, embedded build information, and debug-data status of one ELF file.

    Each fact comes from a section that the validated section header table places wholly
    inside the file. A file without those sections, or with malformed ones, raises ValueError.
    """
    with path.open("rb") as stream:
        image = elf.read_image(stream)
        if image.order != "<":
            raise ValueError("Go build facts are supported for little-endian ELF files only")
        sections = elf.read_sections(stream, image)
        if not sections:
            raise ValueError("ELF file has no section header table")
        named: dict[str, elf.Section] = {}
        for section in sections:
            if section.name in named and section.name.startswith((".note.go", ".go.", ".debug_", ".zdebug_")):
                raise ValueError(f"ELF section is declared more than once: {section.name}")
            named.setdefault(section.name, section)

        def content(name: str, kind: int, limit: int) -> bytes:
            section = named.get(name)
            if section is None:
                raise ValueError(f"ELF file has no {name} section")
            if section.kind != kind or not 0 < section.size <= limit:
                raise ValueError(f"ELF {name} section type or size is invalid")
            return elf.read_exact(stream, section.offset, section.size, image.file_size)

        build_id = parse_build_id_note(content(".note.go.buildid", _SHT_NOTE, _NOTE_LIMIT))
        info = parse_build_info(content(".go.buildinfo", _SHT_PROGBITS, _BUILDINFO_LIMIT))
        dwarf = [item for name, item in named.items()
                 if name in {".debug_info", ".zdebug_info"} and item.kind == _SHT_PROGBITS and item.size]
        return {"parser": BUILD_FACTS_PARSER,
                "build_id_sha256": hashlib.sha256(build_id.encode()).hexdigest(),
                "go_version": info["go_version"], "main_package": info["path"],
                "main_module": info["main"], "dependency_modules": info["dependencies"],
                "build_settings": info["settings"],
                "debug_data": {"dwarf": "embedded" if dwarf else "absent",
                               "dwarf_compressed": any(item.name.startswith(".zdebug_") or
                                                       item.flags & _SHF_COMPRESSED for item in dwarf),
                               "symbol_table": ".symtab" in named,
                               "pc_line_table": ".gopclntab" in named}}
