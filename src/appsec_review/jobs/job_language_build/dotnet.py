from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path, PurePosixPath
import re
import shlex
import xml.etree.ElementTree as ET
from typing import Any

from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/dotnet-build-capture/1"
_PROJECT_SUFFIXES = {".csproj", ".vbproj", ".fsproj"}
_ASSEMBLY_SUFFIXES = {".dll", ".exe", ".netmodule", ".winmd"}
_PACKAGE_SUFFIXES = {".nupkg", ".snupkg"}
_NATIVE_SUFFIXES = {".so", ".a", ".o", ".dylib"}
_SOURCE_SUFFIXES = {".cs", ".vb", ".fs", ".fsi", ".fsx"}
_TOOL_KINDS = {
    "csc": "compiler", "csc.dll": "compiler", "vbc": "compiler", "vbc.dll": "compiler",
    "fsc": "compiler", "fsc.dll": "compiler", "resgen": "resource-compiler",
    "al": "assembler", "ilasm": "assembler", "crossgen2": "aot-compiler",
    "ilc": "aot-compiler", "dotnet-illink": "linker-trimmer", "illink": "linker-trimmer",
    "link": "linker", "ld": "linker", "clang": "linker-driver", "clang++": "linker-driver",
    "ar": "archiver", "nuget": "package-builder", "msbuild": "build-driver",
    "dotnet": "build-driver",
}
_INVOCATION = re.compile(
    r"(?P<cmd>(?:\"[^\"]+\"|\S+)*(?:csc|vbc|fsc|resgen|ilasm|crossgen2|ilc|illink|dotnet-illink|"
    r"clang\+\+|clang|\bar\b|\bld\b|nuget)(?:\.dll|\.exe)?(?:\s+(?:\"[^\"]*\"|\S+))*)",
    re.IGNORECASE,
)


def validate_recipe(recipe: Mapping[str, Any], workspace: Path | None = None) -> tuple[str, ...]:
    """Validate the .NET-specific offline and no-execution contract."""
    errors: list[str] = []
    commands = [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]
    saw_restore = False
    for argv in commands:
        if not isinstance(argv, list) or not argv:
            continue
        executable = PurePosixPath(str(argv[0])).name.lower()
        words = [str(value).lower() for value in argv[1:]]
        if executable == "dotnet":
            verb = next((value for value in words if not value.startswith("-")), "")
            if verb not in {"restore", "build", "publish", "pack", "msbuild"}:
                errors.append(f"dotnet subcommand is unsupported: {verb or '<missing>'}")
            if verb == "restore":
                saw_restore = True
                if "--locked-mode" not in words and not any(
                        value.lower() == "/p:restorelockedmode=true" for value in words):
                    errors.append("dotnet restore must use a locked dependency graph")
            if verb in {"build", "publish", "pack"} and "--no-restore" not in words:
                errors.append(f"dotnet {verb} must not perform an implicit restore")
            if verb == "msbuild":
                restore_requested = any(value in {"/restore", "-restore", "/t:restore", "-t:restore",
                                                  "/target:restore", "-target:restore"}
                                        for value in words)
                if restore_requested:
                    saw_restore = True
                    if "/p:restorelockedmode=true" not in words:
                        errors.append("dotnet msbuild restore must use RestoreLockedMode=true")
                elif "/p:restoreduringbuild=false" not in words:
                    errors.append("dotnet msbuild must explicitly disable restore during build")
            if verb in {"build", "publish", "pack", "msbuild"} and not (
                    any(value in {"-v:diag", "--verbosity:diagnostic", "/v:diag"} for value in words)
                    or any(words[offset:offset + 2] == ["--verbosity", "diagnostic"]
                           for offset in range(max(0, len(words) - 1)))):
                errors.append(f"dotnet {verb} must enable diagnostic build provenance")
        elif executable == "msbuild":
            if any(value in {"/restore", "-restore", "/t:restore", "-t:restore",
                             "/target:restore", "-target:restore"} for value in words):
                saw_restore = True
                if not any(value == "/p:restorelockedmode=true" for value in words):
                    errors.append("MSBuild restore must use RestoreLockedMode=true")
            elif not any(value == "/p:restoreduringbuild=false" for value in words):
                errors.append("MSBuild must explicitly disable restore during build")
            if not any(value in {"-v:diag", "/v:diag"} for value in words):
                errors.append("MSBuild must enable diagnostic build provenance")
    dependencies = {PurePosixPath(str(value)).name.lower() for value in recipe.get("dependency_files", ())}
    if saw_restore and "packages.lock.json" not in dependencies:
        errors.append("locked restore requires packages.lock.json in accepted dependency inputs")
    if workspace is not None and saw_restore and not any(
            path.name.lower() == "packages.lock.json" for path in workspace.rglob("packages.lock.json")):
        errors.append("accepted packages.lock.json is absent from the build workspace")
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


def parse_tool_invocations(streams: Sequence[bytes], workspace: Path) -> list[dict[str, Any]]:
    """Extract sanitized tool provenance from MSBuild diagnostic output."""
    rows: list[dict[str, Any]] = []
    for stream_index, stream in enumerate(streams):
        for line_number, line in enumerate(stream.decode("utf-8", "replace").splitlines(), 1):
            match = _INVOCATION.search(line)
            if match is None:
                continue
            try:
                argv = shlex.split(match.group("cmd"), posix=True)
            except ValueError:
                continue
            if not argv:
                continue
            tool = Path(argv[0]).name.lower()
            if tool == "dotnet" and len(argv) > 1 and Path(argv[1]).name.lower() in _TOOL_KINDS:
                tool = Path(argv[1]).name.lower()
            tool_kind = _TOOL_KINDS.get(tool)
            if tool_kind is None:
                continue
            paths = []
            for value in argv[1:]:
                candidate = value.split(":", 1)[-1] if value.startswith(("/out:", "-out:")) else value
                logical = candidate.replace("\\", "/")
                if logical.startswith("/workspace/"):
                    logical = logical[len("/workspace/"):]
                path = (workspace / Path(*PurePosixPath(logical).parts)).resolve()
                if (workspace.resolve() == path or workspace.resolve() in path.parents) and path.is_file():
                    paths.append({"workspace_path": path.relative_to(workspace).as_posix(),
                                  "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
            rows.append({"ordinal": len(rows) + 1, "tool": tool, "tool_kind": tool_kind,
                         "argv": argv,
                         "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
                         "origin": {"stream": "stdout" if stream_index % 2 == 0 else "stderr",
                                    "line": line_number},
                         "input_output_identities": paths, "mapping": "msbuild-diagnostic-stream",
                         "mapping_confidence": 0.8})
    return rows[:4096]
