from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.storage import canonical_json, file_sha256

from .capture import CapturedBuildDescriptor, ToolIdentity


CAPTURE_IDENTITY = "appsec-review/native-build-capture/3"
_DRIVER = re.compile(r"(?:[a-z0-9_.+-]+-)?(?:cc|c\+\+|gcc|g\+\+|clang|clang\+\+)(?:-[0-9.]+)?")
_COMPILERS = {"clang-cl", "cl"}
_ASSEMBLERS = {"as", "llvm-as"}
_LINKERS = {"ld", "ld.bfd", "ld.gold", "ld.lld", "lld", "mold", "collect2", "wasm-ld"}
_ARCHIVERS = {"ar", "gcc-ar", "llvm-ar", "emar", "lib"}
_POST_LINK = {"ranlib", "strip", "objcopy", "llvm-objcopy", "dsymutil"}
_GENERATORS = {"bison", "flex", "moc", "protoc", "rcc", "swig", "uic"}
_BUILD_DRIVERS = {"cmake", "make", "gmake", "ninja", "meson"}
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".s"}
_INPUT_SUFFIXES = _SOURCE_SUFFIXES | {".o", ".obj", ".a", ".so", ".dylib", ".bc", ".ll"}


def tool_kind(name: str, argv: Sequence[str]) -> str | None:
    """Classify only the executable named by a successful process-exec event."""
    normalized = PurePosixPath(name).name.lower()
    arguments = {str(value).lower() for value in argv[1:]}
    if _DRIVER.fullmatch(normalized) or normalized in _COMPILERS:
        return "compiler" if arguments & {"-c", "-e", "-s", "/c"} else "linker-driver"
    if normalized in _ASSEMBLERS:
        return "assembler"
    if normalized in _LINKERS:
        return "linker"
    if normalized in _ARCHIVERS:
        return "archiver"
    if normalized in _POST_LINK:
        return "post-link"
    if normalized in _GENERATORS:
        return "code-generator"
    if normalized in _BUILD_DRIVERS:
        return "build-driver"
    return None


def _mapped(workspace: Path, directory: str, value: str) -> dict[str, Any] | None:
    normalized = value.replace("\\", "/")
    if normalized.startswith("/workspace/"):
        logical = PurePosixPath(normalized[len("/workspace/"):])
    elif normalized == "/workspace":
        logical = PurePosixPath(".")
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


def _paths(kind: str, argv: Sequence[str]) -> tuple[list[str], list[str]]:
    values = [str(value) for value in argv]
    outputs: list[str] = []
    for index, value in enumerate(values[:-1]):
        if value in {"-o", "--output", "/Fo", "/Fe"}:
            outputs.append(values[index + 1])
        elif value.startswith(("/Fo", "/Fe")) and len(value) > 3:
            outputs.append(value[3:])
        elif value.startswith("-Wl,-Map,"):
            outputs.append(value[len("-Wl,-Map,"):])
    if kind == "archiver":
        outputs.extend(value for value in values[1:] if PurePosixPath(value).suffix.lower() in {".a", ".lib"})
        outputs = outputs[:1]
    if kind == "code-generator" and not outputs:
        for index, value in enumerate(values[:-1]):
            if value in {"--cpp_out", "--c_out", "-o"}:
                outputs.append(values[index + 1])
    inputs = [value for value in values[1:]
              if PurePosixPath(value).suffix.lower() in _INPUT_SUFFIXES and value not in outputs]
    if not outputs and kind in {"compiler", "assembler"}:
        source = next((value for value in inputs if PurePosixPath(value).suffix in _SOURCE_SUFFIXES), None)
        if source:
            outputs.append(str(PurePosixPath(source).with_suffix(".o")))
    return inputs, outputs


def _row(name: str, kind: str, argv: Sequence[str], workspace: Path, directory: str,
         origin: str) -> dict[str, Any]:
    values = [str(value) for value in argv]
    inputs, outputs = _paths(kind, values)
    return {"tool": name, "tool_kind": kind, "argv": values,
            "argv_sha256": hashlib.sha256(canonical_json(values)).hexdigest(),
            "inputs": [item for item in (_mapped(workspace, directory, value) for value in inputs) if item],
            "outputs": [item for item in (_mapped(workspace, directory, value) for value in outputs) if item],
            "origin": origin, "mapping_confidence": 1.0}


def _classify_tool(name: str, argv: Sequence[str]) -> ToolIdentity | None:
    normalized = PurePosixPath(name).name.lower()
    kind = tool_kind(normalized, argv)
    return ToolIdentity(normalized, kind) if kind is not None else None


CAPTURE_DESCRIPTOR = CapturedBuildDescriptor(
    family="native",
    capture_identity=CAPTURE_IDENTITY,
    provenance_schema="appsec-review/native-capture-provenance/1",
    catalog_label="native",
    classify_tool=_classify_tool,
    build_invocation=_row,
    link_kinds=frozenset({"linker-driver", "linker", "archiver"}),
    missing_tool_gap="native compiler execution was not observed in the standardized capture",
)
