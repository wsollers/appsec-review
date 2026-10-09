from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET
from typing import Any

from appsec_review.container_runtime import VerifiedCapture
from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/dotnet-build-capture/2"
_PROJECT_SUFFIXES = {".csproj", ".vbproj", ".fsproj"}
_ASSEMBLY_SUFFIXES = {".dll", ".exe", ".netmodule", ".winmd"}
_PACKAGE_SUFFIXES = {".nupkg", ".snupkg"}
_NATIVE_SUFFIXES = {".so", ".a", ".o", ".dylib"}
_SOURCE_SUFFIXES = {".cs", ".vb", ".fs", ".fsi", ".fsx"}
_TOOL_KINDS = {
    "csc": "compiler", "csc.dll": "compiler", "vbc": "compiler", "vbc.dll": "compiler",
    "fsc": "compiler", "fsc.dll": "compiler", "vbccompiler.dll": "compiler",
    "resgen": "resource-compiler", "resgen.dll": "resource-compiler",
    "al": "assembler", "ilasm": "assembler", "crossgen2": "aot-compiler",
    "crossgen2.dll": "aot-compiler", "ilc": "aot-compiler", "ilc.dll": "aot-compiler",
    "dotnet-illink": "linker-trimmer", "illink": "linker-trimmer", "illink.dll": "linker-trimmer",
    "link": "linker", "ld": "linker", "clang": "linker-driver", "clang++": "linker-driver",
    "ar": "archiver", "nuget": "package-builder", "msbuild": "build-driver",
    "msbuild.dll": "build-driver", "dotnet": "build-driver",
}
_INVOCATION_LIMIT = 16384
_EVENT_ORDINAL_LIMIT = 8
_REDACTED = "<redacted"


def validate_recipe(recipe: Mapping[str, Any], workspace: Path | None = None) -> tuple[str, ...]:
    """Validate the .NET-specific build-only contract."""
    errors: list[str] = []
    commands = [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]
    for argv in commands:
        if not isinstance(argv, list) or not argv:
            continue
        executable = PurePosixPath(str(argv[0])).name.lower()
        words = [str(value).lower() for value in argv[1:]]
        if executable == "dotnet":
            verb = next((value for value in words if not value.startswith("-")), "")
            if verb not in {"restore", "build", "publish", "pack", "msbuild"}:
                errors.append(f"dotnet subcommand is unsupported: {verb or '<missing>'}")
    return tuple(dict.fromkeys(errors))


def project_topology(workspace: Path) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    projects: list[dict[str, Any]] = []
    gaps: list[str] = []
    platform_gaps: list[str] = []
    for path in sorted(workspace.rglob("*")):
        if path.suffix.lower() not in _PROJECT_SUFFIXES or not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(workspace).as_posix()
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            gaps.append(f"{relative}: project XML could not be parsed")
            continue
        values: dict[str, list[str]] = {}
        for element in root.iter():
            name = element.tag.rsplit("}", 1)[-1]
            if element.text and element.text.strip():
                values.setdefault(name, []).append(element.text.strip())
        frameworks: list[str] = []
        for key in ("TargetFramework", "TargetFrameworks", "TargetFrameworkVersion"):
            for value in values.get(key, ()):
                frameworks.extend(part.strip() for part in value.split(";") if part.strip())
        sdk = str(root.attrib.get("Sdk", ""))
        runtime_identifiers = [item.strip() for key in ("RuntimeIdentifier", "RuntimeIdentifiers")
                               for value in values.get(key, ()) for item in value.split(";") if item.strip()]
        windows_only = (
            any(value.lower().startswith(("v4", "net4")) or "-windows" in value.lower()
                for value in frameworks)
            or any(value.lower().startswith("win-") for value in runtime_identifiers)
            or any(value.lower() == "windows" for value in values.get("TargetPlatformIdentifier", ()))
            or "windowsdesktop" in sdk.lower()
            or any(value.lower() == "true" for key in ("UseWPF", "UseWindowsForms")
                   for value in values.get(key, ()))
        )
        refs = sorted({str(element.attrib.get("Include")) for element in root.iter()
                       if element.tag.rsplit("}", 1)[-1] == "ProjectReference" and element.attrib.get("Include")})
        packages = sorted({(str(element.attrib.get("Include")), str(element.attrib.get("Version", "")))
                           for element in root.iter()
                           if element.tag.rsplit("}", 1)[-1] == "PackageReference" and element.attrib.get("Include")})
        projects.append({"path": relative, "sha256": file_sha256(path), "sdk": sdk,
                         "frameworks": sorted(set(frameworks)), "project_references": refs,
                         "runtime_identifiers": sorted(set(runtime_identifiers)),
                         "package_references": [{"name": name, "version": version} for name, version in packages],
                         "windows_only": windows_only})
        if windows_only:
            platform_gaps.append(
                f"{relative}: Windows-only or .NET Framework target is not executable in the Linux build boundary")
    return projects, gaps, platform_gaps


def artifact_kind(path: Path) -> str | None:
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in _ASSEMBLY_SUFFIXES:
        return "managed-assembly"
    if suffix == ".pdb":
        return "debug-information"
    if suffix in _PACKAGE_SUFFIXES:
        return "nuget-package"
    if suffix in _NATIVE_SUFFIXES:
        return "native-output"
    if not suffix and path.is_file():
        try:
            with path.open("rb") as stream:
                magic = stream.read(4)
            if magic == b"\x7fELF":
                return "native-output"
        except OSError:
            pass
    if suffix in _SOURCE_SUFFIXES and any(part in {"obj", "generated"} for part in path.parts):
        return "generated-source"
    if name.endswith(".deps.json"):
        return "dependency-manifest"
    if name.endswith(".runtimeconfig.json") or name.endswith(".runtimeconfig.dev.json"):
        return "runtime-configuration"
    if name == "project.assets.json":
        return "nuget-assets"
    if suffix in {".resources", ".resx"}:
        return "resource"
    if suffix in {".binlog", ".cache"}:
        return "build-intermediate"
    return None


def tool_identity(name: str, argv: Sequence[str]) -> tuple[str, str] | None:
    """Classify the executable a successful syscall event actually started.

    Roslyn and several SDK tools are managed DLLs hosted by ``dotnet``.  In that case the
    hosted DLL, rather than the generic host, is the meaningful build tool identity.
    """
    normalized = PurePosixPath(name).name.lower()
    if normalized == "dotnet":
        for value in argv[1:]:
            candidate = PurePosixPath(str(value).replace("\\", "/")).name.lower()
            if candidate in _TOOL_KINDS and candidate != "dotnet":
                return candidate, _TOOL_KINDS[candidate]
    kind = _TOOL_KINDS.get(normalized)
    return (normalized, kind) if kind is not None else None


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


def _argument_path(value: str) -> tuple[str, bool]:
    lowered = value.lower()
    for prefix in ("/out:", "-out:", "/doc:", "-doc:", "/pdb:", "-pdb:"):
        if lowered.startswith(prefix):
            return value[len(prefix):], True
    for prefix in ("/reference:", "-reference:", "/r:", "-r:", "/resource:", "-resource:"):
        if lowered.startswith(prefix):
            candidate = value[len(prefix):].split(",", 1)[0]
            if "=" in candidate:
                candidate = candidate.split("=", 1)[1]
            return candidate, False
    return value, False


def _row(tool: str, kind: str, argv: Sequence[str], workspace: Path, directory: str,
         origin: str) -> dict[str, Any]:
    values = [str(value) for value in argv]
    inputs: list[str] = []
    outputs: list[str] = []
    for value in values[1:]:
        candidate, output = _argument_path(value)
        suffix = PurePosixPath(candidate.replace("\\", "/")).suffix.lower()
        if output:
            outputs.append(candidate)
        elif suffix in _SOURCE_SUFFIXES | _ASSEMBLY_SUFFIXES | {".resources", ".resx", ".json"}:
            inputs.append(candidate)
    return {"tool": tool, "tool_kind": kind, "argv": values,
            "argv_sha256": hashlib.sha256(canonical_json(values)).hexdigest(),
            "inputs": [item for item in (_mapped(workspace, directory, value) for value in inputs) if item],
            "outputs": [item for item in (_mapped(workspace, directory, value) for value in outputs) if item],
            "origin": origin, "mapping_confidence": 1.0}


def _invocation_key(tool: str, argv: Sequence[str]) -> str:
    # A PATH wrapper and the resolved binary differ only in argv[0].
    return hashlib.sha256(canonical_json([tool, *[str(value) for value in argv[1:]]])).hexdigest()


def capture_invocations(captures: Sequence[tuple[int, VerifiedCapture]], workspace: Path,
                        directory: str) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Derive .NET tool provenance only from successful captured process-exec syscalls."""
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
            identity = tool_identity(PurePosixPath(executable or (argv[0] if argv else "")).name, argv)
            if identity is None:
                continue
            tool, kind = identity
            key = _invocation_key(tool, argv)
            row = rows.get(key)
            if row is None:
                if len(rows) >= _INVOCATION_LIMIT:
                    truncated = True
                    continue
                row = rows[key] = _row(tool, kind, argv, workspace, directory,
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
            identity = tool_identity(str(document.get("tool", "")), argv)
            if identity is None:
                continue
            tool, _kind = identity
            row = rows.get(_invocation_key(tool, argv))
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
    if facts["unreconciled_tool_calls"]:
        gaps.append(f"{facts['unreconciled_tool_calls']} tool-call records had no matching successful "
                    "process-exec event and are not claimed as tool execution")
    if truncated:
        gaps.append(".NET tool invocation catalog truncated at its row bound")
    return list(rows.values()), facts, gaps
