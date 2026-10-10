from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.container_runtime import VerifiedCapture
from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/native-build-capture/2"
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
_INVOCATION_LIMIT = 16384
_EVENT_ORDINAL_LIMIT = 8
_REDACTED = "<redacted"


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


def _invocation_key(name: str, argv: Sequence[str]) -> str:
    return hashlib.sha256(canonical_json([name, *[str(value) for value in argv[1:]]])).hexdigest()


def capture_invocations(captures: Sequence[tuple[int, VerifiedCapture]], workspace: Path,
                        directory: str) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Publish native tool provenance only when a verified successful exec observed it."""
    rows: dict[str, dict[str, Any]] = {}
    facts = {"process_exec_events": 0, "failed_exec_events": 0, "redacted_exec_events": 0,
             "tool_call_records": 0, "redacted_tool_calls": 0, "unreconciled_tool_calls": 0,
             "connect_events": 0, "envp_events": 0, "envp_redacted_names": []}
    redacted_names: set[str] = set()
    truncated = False
    for ordinal, capture in captures:
        label = f"execution-capture:command-{ordinal:03d}"
        record_sha = str(capture.identity["sha256"])
        for event in capture.events():
            if event.get("kind") == "connect":
                facts["connect_events"] += 1
            if event.get("kind") != "process_exec":
                continue
            facts["process_exec_events"] += 1
            argv = [str(value) for value in event.get("argv", ())]
            executable = str(event.get("executable", ""))
            if executable.startswith(_REDACTED) or (argv and argv[0].startswith(_REDACTED)):
                facts["redacted_exec_events"] += 1
                continue
            if event.get("result", 0) != 0:
                facts["failed_exec_events"] += 1
                continue
            if event.get("envp_captured"):
                facts["envp_events"] += 1
                redacted_names.update(str(name) for name in event.get("envp_redacted_names", ()))
            name = PurePosixPath(executable or (argv[0] if argv else "")).name.lower()
            kind = tool_kind(name, argv)
            if kind is None:
                continue
            key = _invocation_key(name, argv)
            row = rows.get(key)
            if row is None:
                if len(rows) >= _INVOCATION_LIMIT:
                    truncated = True
                    continue
                row = rows[key] = _row(name, kind, argv, workspace, directory,
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
            name = PurePosixPath(str(document.get("tool", ""))).name.lower()
            if tool_kind(name, argv) is None:
                continue
            row = rows.get(_invocation_key(name, argv))
            if row is None:
                facts["unreconciled_tool_calls"] += 1
                continue
            if row["evidence"]["tool_call"] is None:
                row["evidence"]["tool_call"] = {
                    "uri": call["uri"], "sha256": call["sha256"],
                    "exit_code": document.get("exit_code"),
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
        gaps.append(f"{facts['redacted_tool_calls']} tool-call records were redacted by the secret scan")
    if facts["unreconciled_tool_calls"]:
        gaps.append(f"{facts['unreconciled_tool_calls']} tool-call records had no matching successful "
                    "process-exec event and are not claimed as tool execution")
    if truncated:
        gaps.append("native tool invocation catalog truncated at its row bound")
    return list(rows.values()), facts, gaps


def link_rows(rows: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return [row for row in rows if row.get("tool_kind") in {"linker-driver", "linker", "archiver"}]
