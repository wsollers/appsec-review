"""Deterministic native dependency observations from accepted compiler/linker evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import PurePosixPath
import re
from typing import Any

from appsec_review.jobs.engineering_contracts import NATIVE_DEPENDENCY_CANDIDATE_SCHEMA
from appsec_review.storage import canonical_json


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,255}$")
_LIBRARY = re.compile(r"^(?:lib)?(?P<name>[A-Za-z0-9][A-Za-z0-9_.+\-]*?)\.so(?:\.\d+)*$", re.I)
_WINDOWS = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.+\-]*?)\.(?:lib|dll)$", re.I)
_DARWIN = re.compile(r"^(?:lib)?(?P<name>[A-Za-z0-9][A-Za-z0-9_.+\-]*?)\.dylib$", re.I)
_ARCHIVE = re.compile(r"^(?:lib)?(?P<name>[A-Za-z0-9][A-Za-z0-9_.+\-]*?)\.a$", re.I)
_METADATA_SUFFIXES = (".pc", "config.cmake", "-config.cmake")
_BUILD_CONTEXT_FIELDS = ("configuration", "dependency_scope", "environment", "profile", "target")


def _candidate_id(native_name: str) -> str:
    return "native-dependency-" + hashlib.sha256(native_name.casefold().encode()).hexdigest()[:24]


def _name_from_file(value: str) -> tuple[str, str] | None:
    basename = PurePosixPath(value.replace("\\", "/")).name
    for pattern, kind in ((_WINDOWS, "import_name"), (_DARWIN, "shared_library_path"),
                          (_ARCHIVE, "archive_path"), (_LIBRARY, "soname")):
        match = pattern.fullmatch(basename)
        if match:
            return match.group("name"), kind
    return None


def _add(found: dict[str, dict[str, Any]], name: str, *, kind: str, value: str,
         command_id: str | None, command_sha256: str | None, artifact_sha256: str | None = None,
         metadata: Mapping[str, Any] | None = None,
         context: Mapping[str, str] | None = None) -> None:
    if not _NAME.fullmatch(name):
        return
    key = name.casefold()
    item = found.setdefault(key, {
        "schema": NATIVE_DEPENDENCY_CANDIDATE_SCHEMA,
        "candidate_id": _candidate_id(key), "native_name": name,
        "observations": [], "metadata": {}, "repository": None,
    })
    observation = {"kind": kind, "value": value[:4096]}
    if command_id:
        observation["command_id"] = command_id
    if command_sha256:
        observation["command_sha256"] = command_sha256
    if artifact_sha256:
        observation["artifact_sha256"] = artifact_sha256
    if context:
        observation.update(context)
    if observation not in item["observations"]:
        item["observations"].append(observation)
    if metadata:
        item["metadata"].update({str(k): v for k, v in metadata.items() if v is not None})


def _build_context(row: Mapping[str, Any], argv: Sequence[str]) -> dict[str, str]:
    """Retain bounded structured build context and recognize explicit debug compiler flags."""
    context = {field: str(row[field])[:4096] for field in _BUILD_CONTEXT_FIELDS
               if isinstance(row.get(field), (str, int, float)) and not isinstance(row.get(field), bool)}
    lowered = [value.casefold() for value in argv]
    debug = any(value == "-g" or re.fullmatch(r"-g[0-3]", value) or value in {"/debug", "-ddebug"}
                or value.startswith("-ddebug=") for value in lowered)
    for index, value in enumerate(lowered[:-1]):
        if value in {"--configuration", "--config", "--profile"}:
            context.setdefault("configuration", argv[index + 1][:4096])
    for value in lowered:
        if "cmake_build_type=debug" in value:
            debug = True
    if debug:
        context.setdefault("configuration", "debug")
    return context


def parse_native_candidates(
    invocations: Sequence[Mapping[str, Any]], *,
    artifacts: Sequence[Mapping[str, Any]] = (),
    metadata_files: Sequence[Mapping[str, Any]] = (),
    max_candidates: int = 4096,
    max_tokens_per_command: int = 16384,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Return bounded, deduplicated dependency candidates and named coverage gaps.

    ``invocations`` must come from hash-verified protected compile/link receipts. Raw argv is
    interpreted as data. Every candidate retains the command or artifact identity that supports it.
    """
    found: dict[str, dict[str, Any]] = {}
    gaps: list[str] = []
    for ordinal, row in enumerate(invocations):
        if len(found) >= max_candidates:
            gaps.append(f"native dependency candidate bound exceeded ({max_candidates})")
            break
        argv = row.get("argv")
        if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)):
            gaps.append(f"native invocation {ordinal} has no argv")
            continue
        if len(argv) > max_tokens_per_command:
            gaps.append(f"native invocation {ordinal} exceeds command token bound ({max_tokens_per_command})")
            argv = argv[:max_tokens_per_command]
        command_id = str(row.get("command_id") or row.get("origin") or f"invocation:{ordinal}")
        command_sha = str(row.get("argv_sha256") or hashlib.sha256(canonical_json(list(argv))).hexdigest())
        values = [str(value) for value in argv]
        context = _build_context(row, values)
        skip_next = False
        for index, value in enumerate(values[1:], 1):
            if skip_next:
                skip_next = False
                continue
            if value in {"-L", "-o", "--output", "/Fo", "/Fe", "-I", "-isystem"}:
                skip_next = True
                continue
            if value == "-l" and index + 1 < len(values) and _NAME.fullmatch(values[index + 1]):
                _add(found, values[index + 1], kind="link_flag", value=values[index + 1],
                     command_id=command_id, command_sha256=command_sha, context=context)
                skip_next = True
                continue
            if value == "-framework" and index + 1 < len(values):
                framework = values[index + 1]
                _add(found, framework, kind="framework", value=framework,
                     command_id=command_id, command_sha256=command_sha, context=context)
                skip_next = True
                continue
            names: list[tuple[str, str, str]] = []
            if value.startswith("-l:"):
                parsed = _name_from_file(value[3:])
                if parsed:
                    names.append((parsed[0], "exact_library_name", value))
            elif value.startswith("-l") and _NAME.fullmatch(value[2:]):
                names.append((value[2:], "link_flag", value))
            elif value.startswith("-Wl,"):
                parts = value[4:].split(",")
                for part_index, part in enumerate(parts):
                    if part.startswith("-l") and _NAME.fullmatch(part[2:]):
                        names.append((part[2:], "linker_forwarded_flag", part))
                    elif part == "-l" and part_index + 1 < len(parts) and _NAME.fullmatch(parts[part_index + 1]):
                        names.append((parts[part_index + 1], "linker_forwarded_flag", parts[part_index + 1]))
            else:
                parsed = _name_from_file(value)
                if parsed:
                    names.append((parsed[0], parsed[1], value))
            for name, kind, evidence in names:
                _add(found, name, kind=kind, value=evidence,
                     command_id=command_id, command_sha256=command_sha, context=context)

    for artifact in artifacts:
        for raw in artifact.get("loader_dependencies", ()) or ():
            parsed = _name_from_file(str(raw))
            if parsed:
                _add(found, parsed[0], kind="loader_needed", value=str(raw), command_id=None,
                     command_sha256=None, artifact_sha256=str(artifact.get("sha256", "")))
        soname = artifact.get("loader_soname")
        parsed = _name_from_file(str(soname)) if soname else None
        if parsed:
            _add(found, parsed[0], kind="soname", value=str(soname), command_id=None,
                 command_sha256=None, artifact_sha256=str(artifact.get("sha256", "")))

    for record in metadata_files:
        path, fields = str(record.get("path", "")), record.get("fields")
        if not path.lower().endswith(_METADATA_SUFFIXES) or not isinstance(fields, Mapping):
            continue
        name = str(fields.get("Name") or fields.get("name") or PurePosixPath(path).stem)
        if name.lower().endswith("config"):
            name = name[:-6]
        repository = fields.get("URL") or fields.get("url") or fields.get("repository")
        _add(found, name, kind="package_metadata", value=path, command_id=None,
             command_sha256=None, artifact_sha256=str(record.get("sha256", "")),
             metadata={"repository_url": repository, "version": fields.get("Version") or fields.get("version"),
                       "metadata_path": path, "metadata_sha256": record.get("sha256")})

    candidates = []
    for item in found.values():
        item["observations"] = sorted(item["observations"], key=lambda value: canonical_json(value))
        candidates.append(item)
    return sorted(candidates, key=lambda item: (item["native_name"].casefold(), item["candidate_id"])), gaps


__all__ = ["parse_native_candidates"]
