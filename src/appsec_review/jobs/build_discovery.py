from __future__ import annotations

from collections import defaultdict
import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping, Sequence


BUILD_DESCRIPTOR_SCHEMA = "appsec-review/build-descriptor-package/1"
BUILD_RECIPE_SCHEMA = "appsec-review/build-recipe/1"

_MARKERS: dict[str, tuple[str, str]] = {
    "CMakeLists.txt": ("native", "cmake"),
    "CMakePresets.json": ("native", "cmake"),
    "configure.ac": ("native", "autotools"),
    "configure.in": ("native", "autotools"),
    "Makefile.am": ("native", "autotools"),
    "Makefile": ("native", "make"),
    "meson.build": ("native", "meson"),
    "Cargo.toml": ("rust", "cargo"),
    "go.mod": ("go", "go"),
    "go.work": ("go", "go"),
    "pom.xml": ("java", "maven"),
    "build.gradle": ("java", "gradle"),
    "build.gradle.kts": ("java", "gradle"),
    "package.json": ("node", "node"),
    "pyproject.toml": ("python", "python"),
    "setup.py": ("python", "python"),
    "setup.cfg": ("python", "python"),
    "composer.json": ("php", "composer"),
}
_SUFFIX_MARKERS: dict[str, tuple[str, str]] = {
    ".csproj": ("dotnet", "dotnet"),
    ".vbproj": ("dotnet", "dotnet"),
    ".fsproj": ("dotnet", "dotnet"),
    ".sln": ("dotnet", "dotnet"),
    ".vcxproj": ("native", "msbuild"),
    ".wat": ("wasm", "wasm"),
    ".wasm": ("wasm", "wasm"),
}
_SOURCE_MARKERS: dict[str, tuple[str, str]] = {
    ".c": ("native", "direct-native"), ".cc": ("native", "direct-native"),
    ".cpp": ("native", "direct-native"), ".cxx": ("native", "direct-native"),
    ".java": ("java", "javac"), ".kt": ("java", "javac"), ".kts": ("java", "javac"),
    ".rs": ("rust", "rustc"),
    ".go": ("go", "go"), ".wat": ("wasm", "wasm"),
}
_CONTEXT_NAMES = {
    "README", "README.md", "README.rst", "Dockerfile", "build.sh", "build.ps1",
    "gradle.properties", "settings.gradle", "settings.gradle.kts", "gradle.lockfile",
    "maven-wrapper.properties", "gradle-wrapper.properties", "Cargo.lock",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock", "requirements.txt",
    "poetry.lock", "Pipfile.lock", "pylock.toml", "setup.cfg",
    "rust-toolchain", "rust-toolchain.toml", "Directory.Build.props", "global.json",
    "packages.lock.json", "Directory.Packages.props", "NuGet.Config",
}
_PROFILE_COMMANDS: dict[str, frozenset[str]] = {
    "native": frozenset({"cmake", "ninja", "make", "gmake", "clang", "clang++", "gcc", "g++",
                         "emcc", "em++", "emar", "wasm-ld", "llvm-ar", "wasm-opt", "wasm-tools",
                         "autoreconf", "autoconf",
                         "automake", "libtoolize", "meson", "bear", "pkg-config"}),
    "rust": frozenset({"cargo", "rustc", "wasm-pack", "wasm-bindgen", "wasm-opt", "wasm-tools"}),
    "go": frozenset({"go"}),
    "java": frozenset({"mvn", "mvnw", "gradle", "gradlew", "javac", "kotlinc", "kapt", "jar", "protoc"}),
    "node": frozenset({"npm", "npx", "pnpm", "yarn", "node", "tsc", "asc", "wasm-opt", "wasm-tools"}),
    "dotnet": frozenset({"dotnet", "msbuild"}),
    "python": frozenset({"python", "python3", "pip", "pip3"}),
    "php": frozenset({"php", "composer"}),
    "wasm": frozenset({"cargo", "rustc", "clang", "clang++", "cmake", "wasm-tools", "wasm-opt",
                        "wasm-ld", "emcc", "em++", "emar", "asc"}),
}
_SECRET_KEY = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
_ENV_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
_FORBIDDEN_SUBCOMMANDS = {
    "cargo": {"install", "run", "test"}, "go": {"get", "install", "run", "test"},
    "dotnet": {"run", "test", "tool"}, "npm": {"exec", "install", "test", "start", "publish"},
    "npx": {"--yes", "-y"}, "pnpm": {"add", "dlx", "exec", "install", "test", "start", "publish"},
    "yarn": {"add", "dlx", "exec", "install", "test", "start", "publish"}, "mvn": {"exec:java", "test"},
    "gradle": {"run", "test"}, "gradlew": {"run", "test"},
    "composer": {"exec", "run-script", "test"}, "php": {"-r", "--interactive"},
}


def _marker(path: PurePosixPath) -> tuple[str, str] | None:
    return _MARKERS.get(path.name) or _SUFFIX_MARKERS.get(path.suffix.lower())


def _id(root: str, family: str, system: str) -> str:
    value = hashlib.sha256(f"{root}\0{family}\0{system}".encode()).hexdigest()[:20]
    return f"build-unit-{value}"


def discover_build_units(files: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Group accepted build descriptors into stable, repository-independent build units."""
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for item in files:
        path = PurePosixPath(str(item["path"]))
        marker = _marker(path)
        if marker is None:
            continue
        family, system = marker
        root = path.parent.as_posix()
        groups[(root, family, system)].append(item)
    for root, family, _system in [
        key for key in tuple(groups) if key[2] in {"cmake", "autotools", "meson"}
    ]:
        groups.pop((root, family, "make"), None)
    descriptor_roots = [(PurePosixPath(root), family) for root, family, _system in groups]
    for item in files:
        path = PurePosixPath(str(item["path"]))
        fallback = _SOURCE_MARKERS.get(path.suffix.lower())
        if fallback is None:
            continue
        family, system = fallback
        if any(existing_family == family and
               (root.as_posix() == "." or path == root or root in path.parents)
               for root, existing_family in descriptor_roots):
            continue
        parts = path.parts
        conventional = next((index for index, part in enumerate(parts[:-1])
                             if part in {"src", "source"}), None)
        root = PurePosixPath(*parts[:conventional]).as_posix() if conventional else path.parent.as_posix()
        groups[(root or ".", family, system)].append(item)
    # A preset is context for the CMake project at the same root, never a second unit.
    values = []
    for (root, family, system), markers in sorted(groups.items()):
        ordered = sorted(markers, key=lambda item: str(item["path"]))
        values.append({
            "build_unit_id": _id(root, family, system),
            "root": root,
            "family": family,
            "build_system": system,
            "markers": [{"path": item["path"], "sha256": item["sha256"],
                         "size_bytes": item["size_bytes"]} for item in ordered],
            "provenance": "deterministic-marker",
        })
    return values


def descriptor_package(target_root: Path, unit: Mapping[str, Any], files: Sequence[Mapping[str, Any]],
                       *, max_files: int = 24, max_file_bytes: int = 64 * 1024,
                       max_total_bytes: int = 256 * 1024) -> dict[str, Any]:
    root = str(unit["root"])
    candidates: list[Mapping[str, Any]] = []
    marker_paths = {str(item["path"]) for item in unit["markers"]}
    for item in files:
        path = PurePosixPath(str(item["path"]))
        under = root == "." or path.as_posix() == root or path.as_posix().startswith(root + "/")
        if not under:
            continue
        if str(item["path"]) in marker_paths or path.name in _CONTEXT_NAMES or path.name.startswith("Dockerfile"):
            candidates.append(item)
    documents = []
    total = 0
    gaps = []
    for item in sorted(candidates, key=lambda value: str(value["path"])):
        if len(documents) >= max_files:
            gaps.append("descriptor file-count bound reached")
            break
        size = int(item["size_bytes"])
        if size > max_file_bytes or total + size > max_total_bytes:
            gaps.append(f"{item['path']}: descriptor content omitted by byte bound")
            continue
        path = (target_root / Path(*PurePosixPath(str(item["path"])).parts)).resolve()
        if target_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            raise ValueError("build descriptor escaped the accepted target")
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeError:
            gaps.append(f"{item['path']}: descriptor is not UTF-8 text")
            continue
        documents.append({"path": item["path"], "sha256": item["sha256"], "content": text})
        total += size
    return {"schema": BUILD_DESCRIPTOR_SCHEMA, "build_unit": dict(unit), "documents": documents,
            "bounds": {"max_files": max_files, "max_file_bytes": max_file_bytes,
                       "max_total_bytes": max_total_bytes, "actual_files": len(documents),
                       "actual_bytes": total}, "gaps": gaps}


def _relative(value: Any, *, allow_dot: bool = True) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return (allow_dot or value != ".") and not any(part in {"", ".."} for part in path.parts)


def _within(value: str, root: str) -> bool:
    path = PurePosixPath(value)
    boundary = PurePosixPath(root)
    return root == "." or path == boundary or boundary in path.parents


def validate_build_recipe(recipe: Mapping[str, Any], unit: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {"schema", "build_unit_id", "image_profile", "source_dir", "build_dir",
                "system_packages", "environment", "dependency_files", "configure_commands",
                "build_commands", "expected_outputs", "network_required", "reason"}
    if set(recipe) != required or recipe.get("schema") != BUILD_RECIPE_SCHEMA:
        return ["recipe fields or schema are unsupported"]
    if recipe.get("build_unit_id") != unit.get("build_unit_id"):
        errors.append("recipe build_unit_id does not match the accepted unit")
    profile = recipe.get("image_profile")
    if profile != unit.get("family") or profile not in _PROFILE_COMMANDS:
        errors.append("recipe image_profile does not match the accepted unit family")
    root = str(unit.get("root", ""))
    for field in ("source_dir", "build_dir"):
        if not _relative(recipe.get(field)):
            errors.append(f"{field} must be a normalized relative path")
        elif not _within(str(recipe[field]), root):
            errors.append(f"{field} must stay within the accepted build-unit root")
    if recipe.get("source_dir") != root:
        errors.append("source_dir must equal the accepted build-unit root")
    packages = recipe.get("system_packages")
    if (not isinstance(packages, list) or len(packages) > 64 or
            any(not isinstance(item, str) or not _PACKAGE.fullmatch(item) for item in packages) or
            len(packages) != len(set(packages))):
        errors.append("system_packages must be a bounded unique package-name list")
    environment = recipe.get("environment")
    if not isinstance(environment, Mapping) or len(environment) > 32:
        errors.append("environment must be a bounded object")
    else:
        for key, value in environment.items():
            if not isinstance(key, str) or not _ENV_KEY.fullmatch(key) or _SECRET_KEY.search(key):
                errors.append(f"environment key is unsafe: {key}")
            if not isinstance(value, str) or len(value.encode("utf-8")) > 1024 or "\0" in value:
                errors.append(f"environment value is invalid: {key}")
    dependencies = recipe.get("dependency_files")
    marker_paths = {str(item["path"]) for item in unit.get("markers", ())}
    accepted_paths = marker_paths | {
        str(item["path"]) for item in unit.get("descriptor_package", {}).get("documents", ())
    }
    if (not isinstance(dependencies, list) or len(dependencies) > 64 or
            any(not isinstance(item, str) or not _relative(item) for item in dependencies)):
        errors.append("dependency_files must be bounded normalized relative paths")
    elif not marker_paths <= set(dependencies):
        errors.append("dependency_files must include every accepted build marker")
    elif not set(dependencies) <= accepted_paths:
        errors.append("dependency_files contains a path outside the accepted descriptor package")
    if profile == "node" and isinstance(dependencies, list):
        names = {PurePosixPath(item).name for item in dependencies if isinstance(item, str)}
        locks = names & {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
        if "package.json" not in names or len(locks) > 1:
            errors.append("Node recipes require package.json and at most one supported lockfile")
    allowed = _PROFILE_COMMANDS.get(str(profile), frozenset())
    for field in ("configure_commands", "build_commands"):
        commands = recipe.get(field)
        if not isinstance(commands, list) or len(commands) > 16:
            errors.append(f"{field} must be a bounded command list")
            continue
        for index, argv in enumerate(commands):
            if (not isinstance(argv, list) or not argv or len(argv) > 128 or
                    any(not isinstance(arg, str) or "\0" in arg or len(arg) > 2048 for arg in argv)):
                errors.append(f"{field}[{index}] is not a bounded argv array")
                continue
            executable = PurePosixPath(argv[0]).name
            if executable not in allowed or argv[0] != executable:
                errors.append(f"{field}[{index}] executable is not allowlisted for {profile}")
                continue
            if any("\n" in arg or "\r" in arg or arg in {";", "&&", "||", "|"} for arg in argv):
                errors.append(f"{field}[{index}] contains shell syntax")
            words = {arg.lower() for arg in argv[1:] if not arg.startswith("-")}
            if words & _FORBIDDEN_SUBCOMMANDS.get(executable, set()):
                errors.append(f"{field}[{index}] requests execution, tests, or tool installation")
            lowered = [str(arg).lower() for arg in argv[1:]]
            if executable in {"mvn", "mvnw"}:
                goals = [value for value in lowered if not value.startswith("-")]
                allowed_goals = {"clean", "compile", "package", "process-resources", "generate-sources",
                                 "generate-resources", "jar:jar", "war:war"}
                if any(value not in allowed_goals for value in goals):
                    errors.append(f"{field}[{index}] Maven goal is not build-only")
                if not any(value == "-dskiptests" or value.startswith("-dmaven.test.skip=true")
                           for value in lowered):
                    errors.append(f"{field}[{index}] Maven build must explicitly disable tests")
            if executable in {"gradle", "gradlew"}:
                tasks = [value for value in lowered if not value.startswith("-")]
                allowed_tasks = {"assemble", "classes", "jar", "war", "clean", "build"}
                if any(value.rsplit(":", 1)[-1] not in allowed_tasks for value in tasks):
                    errors.append(f"{field}[{index}] Gradle task is not build-only")
                if any(value.rsplit(":", 1)[-1] == "build" for value in tasks) and not any(
                        lowered[offset:offset + 2] == ["-x", "test"]
                        for offset in range(max(0, len(lowered) - 1))):
                    errors.append(f"{field}[{index}] Gradle build must exclude tests")
            if profile == "node" and executable == "node" and "--check" not in argv[1:]:
                errors.append(f"{field}[{index}] may execute a target application")
    if isinstance(recipe.get("build_commands"), list) and not recipe["build_commands"]:
        errors.append("build_commands must contain at least one build command")
    outputs = recipe.get("expected_outputs")
    if (not isinstance(outputs, list) or len(outputs) > 64 or
            any(not isinstance(item, str) or not _relative(item) for item in outputs)):
        errors.append("expected_outputs must be bounded normalized relative paths")
    elif any(not _within(item, root) for item in outputs):
        errors.append("expected_outputs must stay within the accepted build-unit root")
    if type(recipe.get("network_required")) is not bool:
        errors.append("network_required must be boolean")
    reason = recipe.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 4096:
        errors.append("reason is missing or exceeds the bound")
    return errors
