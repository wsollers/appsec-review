from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import tarfile
import tomllib
from typing import Any
import zipfile

from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/python-package-build-capture/1"
_PACKAGE_MODULES = {"build", "pip", "compileall"}
_NATIVE_TOOLS = {
    "cc": "compiler-driver", "c++": "compiler-driver", "gcc": "compiler-driver",
    "g++": "compiler-driver", "clang": "compiler-driver", "clang++": "compiler-driver",
    "as": "assembler", "ld": "linker", "ld.lld": "linker", "ar": "archiver",
    "llvm-ar": "archiver", "protoc": "code-generator", "cython": "transpiler",
}


def validate_dispatch(dispatch: Mapping[str, Any], workspace: Path | None = None) -> list[str]:
    """Enforce a package-only, offline Python build without importing target code."""
    recipe = dispatch.get("recipe")
    if not isinstance(recipe, Mapping) or dispatch.get("family") != "python":
        return ["Python execution requires an accepted Python recipe"]
    errors: list[str] = []
    dependencies = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
    if not dependencies & {"pyproject.toml", "setup.py", "setup.cfg"}:
        errors.append("Python package metadata is unavailable")
    locked = bool(dependencies & {"poetry.lock", "Pipfile.lock", "pylock.toml"})
    requirements = [value for value in recipe.get("dependency_files", ())
                    if PurePosixPath(str(value)).name.startswith("requirements")]
    if requirements and workspace is not None:
        for relative in requirements:
            path = workspace / Path(*PurePosixPath(str(relative)).parts)
            text = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
            locked = locked or "--hash=sha256:" in text
    if recipe.get("network_required") is True and not locked:
        errors.append("network dependency resolution requires a hash-locked Python dependency input")
    for argv in [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]:
        if not isinstance(argv, list) or not argv:
            continue
        executable = PurePosixPath(str(argv[0])).name
        words = [str(value) for value in argv[1:]]
        lower = [value.lower() for value in words]
        if executable in {"python", "python3"}:
            if len(words) >= 2 and words[0] == "-m":
                module = words[1]
                if module not in _PACKAGE_MODULES:
                    errors.append(f"Python module execution is outside the package-build allowlist: {module}")
                if module == "build" and "--no-isolation" not in lower:
                    errors.append("PEP 517 builds must use the dependency-bearing image with --no-isolation")
                if module == "pip" and "--no-index" not in lower:
                    errors.append("pip commands must explicitly disable indexes")
            elif words and PurePosixPath(words[0]).name == "setup.py":
                verbs = {value for value in lower[1:] if not value.startswith("-")}
                if not verbs or not verbs <= {"build", "build_py", "build_ext", "sdist", "bdist_wheel"}:
                    errors.append("setup.py may perform only bounded package-build commands")
            else:
                errors.append("Python may execute only approved package-builder modules or setup.py")
        elif executable in {"pip", "pip3"}:
            if "--no-index" not in lower:
                errors.append("pip commands must explicitly disable indexes")
            verb = next((value for value in lower if not value.startswith("-")), "")
            if verb not in {"wheel", "install"}:
                errors.append(f"pip subcommand is outside the package-build allowlist: {verb or '<missing>'}")
    return list(dict.fromkeys(errors))


def environment(recipe: Mapping[str, Any]) -> dict[str, str]:
    return {
        "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_FIND_LINKS": "/opt/project-deps", "PYTHONDONTWRITEBYTECODE": "0",
        "PYTHONHASHSEED": "0", "SOURCE_DATE_EPOCH": "0",
    }


def artifact_kind(path: Path, relative: str, before: Mapping[str, str]) -> str | None:
    lower, suffix = relative.lower(), path.suffix.lower()
    if suffix == ".whl":
        return "wheel"
    if lower.endswith((".tar.gz", ".tar.bz2", ".tar.xz", ".zip")) and "/dist/" in "/" + lower:
        return "source-distribution"
    if suffix in {".pyc", ".pyo"} or "__pycache__/" in lower:
        return "bytecode"
    if suffix in {".so", ".pyd", ".dylib"}:
        return "native-extension"
    if any(part.endswith((".dist-info", ".egg-info")) for part in PurePosixPath(relative).parts):
        return "package-metadata"
    if suffix in {".c", ".cc", ".cpp", ".h"} and before.get(relative) != file_sha256(path):
        return "generated-source"
    if suffix in {".o", ".obj", ".a"}:
        return "native-intermediate"
    return None


def project_metadata(workspace: Path, source_dir: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    root = workspace / Path(*PurePosixPath(source_dir).parts)
    projects: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    gaps: list[str] = []
    pyproject = root / "pyproject.toml"
    if pyproject.is_file() and not pyproject.is_symlink():
        try:
            value = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeError) as exc:
            return [], [], [f"pyproject.toml could not be parsed: {type(exc).__name__}"]
        project = value.get("project", {}) if isinstance(value, Mapping) else {}
        poetry = value.get("tool", {}).get("poetry", {}) if isinstance(value.get("tool"), Mapping) else {}
        build_system = value.get("build-system", {}) if isinstance(value.get("build-system"), Mapping) else {}
        name = str(project.get("name") or poetry.get("name") or root.name)
        dependencies = project.get("dependencies", [])
        if not isinstance(dependencies, list):
            dependencies = []
        projects.append({"name": name, "path": pyproject.relative_to(workspace).as_posix(),
                         "sha256": file_sha256(pyproject),
                         "build_backend": str(build_system.get("build-backend", "")),
                         "requires": [str(item)[:512] for item in dependencies[:1000]]})
        for dependency in dependencies[:1000]:
            relationships.append({"from": name, "to": re.split(r"[ <>=!~;\[]", str(dependency), maxsplit=1)[0],
                                  "kind": "requires", "declaration_sha256":
                                  hashlib.sha256(str(dependency).encode()).hexdigest()})
        workspace_table = value.get("tool", {}).get("uv", {}).get("workspace", {}) \
            if isinstance(value.get("tool"), Mapping) else {}
        members = workspace_table.get("members", []) if isinstance(workspace_table, Mapping) else []
        if isinstance(members, list):
            for member in members[:1000]:
                relationships.append({"from": name, "to": str(member), "kind": "workspace-member"})
    elif (root / "setup.py").is_file() or (root / "setup.cfg").is_file():
        marker = root / ("setup.py" if (root / "setup.py").is_file() else "setup.cfg")
        projects.append({"name": root.name, "path": marker.relative_to(workspace).as_posix(),
                         "sha256": file_sha256(marker), "build_backend": "setuptools-legacy",
                         "requires": []})
    return projects, relationships, gaps


def package_contents(path: Path, workspace: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    gaps: list[str] = []
    try:
        if path.suffix.lower() == ".whl" or path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                if len(names) > 100000:
                    return [], [f"{path.name}: package member bound exceeded"]
                rows = [{"package_path": path.relative_to(workspace).as_posix(), "member": name,
                         "size_bytes": archive.getinfo(name).file_size}
                        for name in names if not name.endswith("/")]
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                members = archive.getmembers()
                if len(members) > 100000:
                    return [], [f"{path.name}: package member bound exceeded"]
                rows = [{"package_path": path.relative_to(workspace).as_posix(), "member": item.name,
                         "size_bytes": item.size} for item in members if item.isfile()]
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        gaps.append(f"{path.name}: package archive could not be inspected")
    return rows, gaps


def tool_invocations(commands: Sequence[Mapping[str, Any]], streams: Sequence[bytes],
                     workspace: Path, projects: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    backend = next((str(item.get("build_backend")) for item in projects if item.get("build_backend")), "")
    for command in commands:
        tool = str(command.get("tool", ""))
        rows.append({"ordinal": len(rows) + 1, "tool": tool,
                     "tool_kind": "bytecode-compiler" if "compileall" in str(command.get("module", ""))
                                  else "package-builder",
                     "argv_sha256": command.get("argv_sha256"),
                     "directory": command.get("working_directory"), "inputs": [], "outputs": [],
                     "mapping": "accepted-command", "mapping_confidence": 1.0})
    if backend and any(row["tool_kind"] == "package-builder" for row in rows):
        rows.append({"ordinal": len(rows) + 1, "tool": backend, "tool_kind": "build-backend",
                     "argv_sha256": hashlib.sha256(canonical_json([backend])).hexdigest(),
                     "directory": projects[0].get("path", ""), "inputs": [], "outputs": [],
                     "mapping": "pyproject-build-backend", "mapping_confidence": 1.0})
    for stream_index, data in enumerate(streams):
        for line_number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            try:
                argv = shlex.split(line.strip())
            except ValueError:
                continue
            if not argv or Path(argv[0]).name not in _NATIVE_TOOLS:
                continue
            tool = Path(argv[0]).name
            rows.append({"ordinal": len(rows) + 1, "tool": tool, "tool_kind": _NATIVE_TOOLS[tool],
                         "argv_sha256": hashlib.sha256(canonical_json(argv)).hexdigest(),
                         "directory": "/workspace", "inputs": [], "outputs": [],
                         "origin": {"stream": "stdout" if stream_index % 2 == 0 else "stderr",
                                    "line": line_number},
                         "mapping": "package-build-diagnostic-stream", "mapping_confidence": 0.8})
    return rows[:4096]
