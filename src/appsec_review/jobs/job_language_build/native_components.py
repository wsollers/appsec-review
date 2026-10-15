"""Captured C/C++ compiles of a non-native unit's ``native_components``.

node-gyp, phpize/make, setuptools and clang --target=wasm32 compile C/C++ inside the unit's own
family build. The single execution capture of that build is the authority for those compiles:
each successful, image-owned compiler exec becomes one compile-database entry carrying its
kernel-observed argv and working directory, tagged with the unit's real family. The native
analysis jobs consume this database exactly like a CMake ``compile_commands.json``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path, PurePosixPath
import posixpath
from typing import Any

from appsec_review.container_runtime import VerifiedCapture
from appsec_review.container_runtime.capture_files import process_directories
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from . import native
from .capture import image_owned


SCHEMA = "appsec-review/native-component-compile-database/1"
_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++"})
_ENTRY_LIMIT = 4096


def _source_argument(argv: Sequence[str]) -> str | None:
    values = [str(value) for value in argv[1:]]
    skip = {"-o", "-MF", "-MT", "-MQ", "-include", "-imacros", "-x"}
    for index, value in enumerate(values):
        if index and values[index - 1] in skip:
            continue
        if not value.startswith("-") and PurePosixPath(value).suffix.lower() in _SOURCE_SUFFIXES:
            return value
    return None


def _output_argument(argv: Sequence[str]) -> str | None:
    values = [str(value) for value in argv]
    for index, value in enumerate(values[:-1]):
        if value == "-o":
            return values[index + 1]
    return None


def compile_entries(captures: Sequence[tuple[int, VerifiedCapture]], *,
                    initial_directory: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Return compile-database rows for every captured C/C++ translation unit."""
    entries: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: set[str] = set()
    for ordinal, capture in captures:
        events = list(capture.events())
        directories = process_directories(events, initial_directory)
        for event in events:
            if not isinstance(event, Mapping) or event.get("kind") != "process_exec":
                continue
            argv, executable = event.get("argv"), event.get("executable")
            if (not isinstance(argv, list) or not argv or not isinstance(executable, str) or
                    event.get("result") != 0 or not image_owned(executable)):
                continue
            argv = [str(value) for value in argv]
            if native.tool_kind(PurePosixPath(executable).name, argv) not in {"compiler", "linker-driver"}:
                continue
            if "-cc1" in argv or "-cc1as" in argv:
                continue  # clang's internal frontend re-exec, not a user-visible compile.
            if event.get("argv_truncated"):
                gaps.append(f"native component compile in command {ordinal} had truncated argv")
                continue
            source = _source_argument(argv)
            if source is None:
                continue  # A link-only driver invocation compiles no translation unit.
            directory = directories.get((int(event.get("pid", 0)), int(event.get("ordinal", 0))),
                                        initial_directory)
            file = posixpath.normpath(source if source.startswith("/") else posixpath.join(directory, source))
            entry = {"directory": directory, "arguments": argv, "file": file,
                     "output": _output_argument(argv), "capture_command": ordinal,
                     "capture_record_sha256": str(capture.identity.get("sha256", "")),
                     "executable": executable}
            key = hashlib.sha256(canonical_json([directory, argv])).hexdigest()
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)
            if len(entries) >= _ENTRY_LIMIT:
                gaps.append("native component compile database truncated at its entry bound")
                return entries, gaps
    return entries, gaps


def invocation_rows(captures: Sequence[tuple[int, VerifiedCapture]], *, family: str,
                    source_dir: str) -> list[dict[str, Any]]:
    """Protected tool-invocation rows for the captured native compiles of a family build."""
    entries, _gaps = compile_entries(
        captures, initial_directory=posixpath.normpath(f"/workspace/{source_dir}"))
    return [{"ordinal": index, "tool": PurePosixPath(str(entry["executable"])).name,
             "tool_kind": "compiler-driver", "directory": entry["directory"],
             "argv": list(entry["arguments"]), "inputs": [], "outputs": [],
             "native_component": True, "family": family,
             "mapping": "syscall-process-exec", "mapping_confidence": 1.0}
            for index, entry in enumerate(entries, 1)]


def publish(root: Path, run_root: Path, *, dispatch: Mapping[str, Any], workspace: Path,
            captures: Sequence[tuple[int, VerifiedCapture]]) -> tuple[dict[str, Any] | None, list[str]]:
    """Write the unit's run-owned native compile database and return its identity and gaps."""
    components = [dict(item) for item in dispatch.get("native_components", ())
                  if isinstance(item, Mapping)]
    if not components:
        return None, []
    source_dir = str(dispatch.get("recipe", {}).get("source_dir", dispatch.get("root", ".")))
    initial = posixpath.normpath(f"/workspace/{source_dir}")
    entries, gaps = compile_entries(captures, initial_directory=initial)
    workspace_root = workspace.resolve()
    compiled = set()
    for entry in entries:
        file = str(entry["file"])
        if file.startswith("/workspace/"):
            compiled.add(file[len("/workspace/"):])
    missing = sorted(str(item["path"]) for item in components
                     if PurePosixPath(str(item["path"])).suffix.lower() in _SOURCE_SUFFIXES and
                     str(item["path"]) not in compiled)
    if not captures:
        gaps.append("native component compiles were not captured; no execution capture exists")
    elif missing:
        gaps.append("native component sources were not observed in a captured compile: " +
                    ", ".join(missing[:20]))
    for entry in entries:
        relative = str(entry["file"])[len("/workspace/"):] if str(entry["file"]).startswith("/workspace/") else None
        path = workspace_root / relative if relative else None
        if path is not None and path.is_file() and not path.is_symlink():
            entry["source_sha256"] = file_sha256(path)
    path = root / "native-compile-commands.json"
    document = {"schema": SCHEMA, "build_unit_id": dispatch["build_unit_id"],
                "family": dispatch["family"], "root": dispatch["root"],
                "native_components": components, "entries": entries}
    atomic_json(path, document)
    return ({"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
             "entry_count": len(entries), "family": dispatch["family"],
             "native_components": components}, gaps)


def compile_commands(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Project a published database to the compile_commands.json rows native jobs read."""
    if document.get("schema") != SCHEMA or not isinstance(document.get("entries"), list):
        raise ValueError("native component compile database is invalid")
    return [{"directory": str(item["directory"]), "arguments": list(item["arguments"]),
             "file": str(item["file"]), **({"output": item["output"]} if item.get("output") else {})}
            for item in document["entries"]]
