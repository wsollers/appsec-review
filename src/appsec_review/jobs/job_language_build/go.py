from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.config import GoBuildSettings
from appsec_review.storage import canonical_json, file_sha256

from .capture import CapturedBuildDescriptor, ToolIdentity


CAPTURE_IDENTITY = "appsec-review/go-build-capture/2"
_GO_TOOLS = {
    "compile": "compiler",
    "asm": "assembler",
    "link": "linker",
    "cgo": "cgo",
    "pack": "package-builder",
}
_LINK_KINDS = {"linker-driver", "linker", "archiver"}
_LINKERS = {"ld", "ld.bfd", "ld.gold", "ld.lld", "lld", "collect2", "mold"}
_ARCHIVERS = {"ar", "llvm-ar"}
_C_DRIVER = re.compile(r"(?:[a-z0-9_]+-)*(?:cc|c\+\+|gcc|g\+\+|clang|clang\+\+)(?:-[0-9.]+)?")
_COMPILE_ONLY = {"-c", "-E", "-S"}
_SOURCE_SUFFIXES = {".go", ".s", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
_INPUT_SUFFIXES = _SOURCE_SUFFIXES | {".a", ".o", ".syso"}


def validate_dispatch(dispatch: Mapping[str, Any], settings: GoBuildSettings) -> tuple[str, ...]:
    recipe = dispatch.get("recipe")
    if not isinstance(recipe, Mapping) or dispatch.get("build_system") != "go":
        return ("Go execution requires an accepted Go recipe",)
    errors: list[str] = []
    builds = 0
    for raw in [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]:
        if not isinstance(raw, list) or len(raw) < 2 or raw[0] != "go":
            errors.append("Go recipes may execute Go commands only")
            continue
        subcommand = str(raw[1]).lower()
        if subcommand not in {"build", "generate"}:
            errors.append(f"Go subcommand is unsupported: {subcommand}")
        if subcommand == "build":
            builds += 1
        if any(value in {"-race", "-msan", "-asan"} for value in raw[2:]):
            errors.append("Go runtime instrumentation builds are unsupported")
    if builds < 1:
        errors.append("Go recipe must contain a go build command")
    dependencies = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
    if "go.mod" not in dependencies and "go.work" not in dependencies:
        errors.append("Go recipes require go.mod or go.work in accepted dependency inputs")
    if settings.offline and bool(recipe.get("network_required")):
        errors.append("offline Go policy conflicts with a network-required recipe")
    return tuple(dict.fromkeys(errors))


def build_argv(argv: Sequence[str], settings: GoBuildSettings) -> tuple[str, ...]:
    values = [str(value) for value in argv]
    if len(values) < 2 or values[0] != "go" or values[1] not in {"build", "generate"}:
        raise ValueError("Go build command is unsupported")
    if settings.offline and not any(value == "-mod=vendor" or value.startswith("-mod=")
                                    for value in values[2:]):
        values.insert(2, "-mod=vendor")
    return tuple(values)


def catalog_argv(commands: Sequence[Sequence[str]]) -> tuple[str, ...]:
    packages: list[str] = []
    forwarded: list[str] = []
    takes_value = {"-tags", "-mod", "-modfile", "-overlay"}
    for raw in commands:
        if len(raw) < 2 or raw[0] != "go" or raw[1] != "build":
            continue
        index = 2
        while index < len(raw):
            value = str(raw[index])
            if value == "-o" and index + 1 < len(raw):
                index += 2
                continue
            if value in takes_value and index + 1 < len(raw):
                forwarded.extend((value, str(raw[index + 1])))
                index += 2
                continue
            if any(value.startswith(prefix + "=") for prefix in takes_value):
                forwarded.append(value)
            elif not value.startswith("-"):
                packages.append(value)
            index += 1
        break
    return ("go", "list", "-deps", "-json", *forwarded, *(packages or ["./..."]))


def parse_package_catalog(data: bytes, *, package_limit: int = 20000,
                          byte_limit: int = 64 * 1024 * 1024) -> list[dict[str, Any]]:
    if len(data) > byte_limit:
        raise ValueError("Go package catalog exceeds its byte bound")
    text = data.decode("utf-8")
    decoder, offset, rows = json.JSONDecoder(), 0, []
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, Mapping) or not isinstance(value.get("ImportPath"), str):
            raise ValueError("Go package catalog entry is invalid")
        for key in ("Imports", "CgoFiles", "GoFiles", "CompiledGoFiles"):
            raw = value.get(key, [])
            if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
                raise ValueError(f"Go package catalog {key} is invalid")
        module = value.get("Module")
        if module is not None and (not isinstance(module, Mapping) or
                                   not isinstance(module.get("Path"), str)):
            raise ValueError("Go package module metadata is invalid")
        rows.append({
            "import_path": value["ImportPath"],
            "module_path": module.get("Path") if isinstance(module, Mapping) else None,
            "dependencies": sorted(value.get("Imports", [])),
            "standard": bool(value.get("Standard", False)),
            "cgo_files": sorted(value.get("CgoFiles", [])),
            "go_files": sorted(value.get("GoFiles", [])),
            "compiled_go_files": sorted(value.get("CompiledGoFiles", [])),
        })
        if len(rows) > package_limit:
            raise ValueError("Go package catalog exceeds its entry bound")
    return rows


def tool_kind(name: str, argv: Sequence[str]) -> str | None:
    if name == "go":
        subcommand = str(argv[1]) if len(argv) > 1 else ""
        if subcommand in {"build", "generate"}:
            return "build-driver"
        if subcommand == "list":
            return "package-catalog"
        if subcommand == "mod":
            return "package-manager"
        if subcommand == "tool" and len(argv) > 2 and argv[2] == "buildid":
            return "post-link"
        return None
    if name in _GO_TOOLS:
        return _GO_TOOLS[name]
    if name in _ARCHIVERS or name.endswith("-ar"):
        return "archiver"
    if name in _LINKERS:
        return "linker"
    if name == "as":
        return "assembler"
    if _C_DRIVER.fullmatch(name):
        return "compiler-driver" if _COMPILE_ONLY & set(argv[1:]) else "linker-driver"
    return None


def _mapped(workspace: Path, directory: str, value: str) -> dict[str, Any] | None:
    normalized = value.replace("\\", "/")
    if normalized.startswith("/workspace/"):
        logical = PurePosixPath(normalized[len("/workspace/"):])
    elif normalized.startswith("/"):
        return None
    else:
        logical = PurePosixPath(directory) / normalized
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


def _row(name: str, kind: str, argv: Sequence[str], workspace: Path, directory: str,
         origin: str) -> dict[str, Any]:
    values = [str(value) for value in argv]
    outputs: list[str] = []
    for index, value in enumerate(values[:-1]):
        if value in {"-o", "--output"}:
            outputs.append(values[index + 1])
    if kind == "archiver":
        outputs.extend(value for value in values[1:] if Path(value).suffix.lower() == ".a")
        outputs = outputs[:1]
    inputs = [value for value in values[1:] if Path(value).suffix.lower() in _INPUT_SUFFIXES
              and value not in outputs]
    return {
        "tool": name, "tool_kind": kind, "argv": values,
        "argv_sha256": hashlib.sha256(canonical_json(values)).hexdigest(),
        "inputs": [item for item in (_mapped(workspace, directory, value) for value in inputs) if item],
        "outputs": [item for item in (_mapped(workspace, directory, value) for value in outputs) if item],
        "origin": origin, "mapping_confidence": 1.0,
    }


def _classify_tool(name: str, argv: Sequence[str]) -> ToolIdentity | None:
    normalized = PurePosixPath(name).name
    kind = tool_kind(normalized, argv)
    return ToolIdentity(normalized, kind) if kind is not None else None


CAPTURE_DESCRIPTOR = CapturedBuildDescriptor(
    family="go",
    capture_identity=CAPTURE_IDENTITY,
    provenance_schema="appsec-review/go-capture-provenance/1",
    catalog_label="Go",
    classify_tool=_classify_tool,
    build_invocation=_row,
    link_kinds=frozenset(_LINK_KINDS),
    missing_tool_gap="Go compiler execution was not observed in the standardized capture",
)
