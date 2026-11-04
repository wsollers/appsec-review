from __future__ import annotations

from collections import defaultdict
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable, Literal, Mapping, Sequence
import xml.etree.ElementTree as ET

from appsec_review.jobs.engine_contracts import UNITY_BUILD_SYSTEM, UNITY_LANGUAGE_FAMILY


BUILD_DESCRIPTOR_SCHEMA = "appsec-review/build-descriptor-package/1"
BUILD_RECIPE_SCHEMA = "appsec-review/build-recipe/1"

_MARKERS: dict[str, tuple[str, str]] = {
    "CMakeLists.txt": ("native", "cmake"),
    "CMakePresets.json": ("native", "cmake"),
    "configure.ac": ("native", "autotools"),
    "configure.in": ("native", "autotools"),
    "Makefile.am": ("native", "autotools"),
    "Makefile": ("native", "make"),
    "makefile": ("native", "make"),
    "GNUmakefile": ("native", "make"),
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
    # A phpize extension: config.m4 declares PHP_NEW_EXTENSION and phpize drives the C build.
    "config.m4": ("php", "phpize"),
}
_SUFFIX_MARKERS: dict[str, tuple[str, str]] = {
    ".csproj": ("dotnet", "dotnet"),
    ".vbproj": ("dotnet", "dotnet"),
    ".fsproj": ("dotnet", "dotnet"),
    ".sln": ("dotnet", "dotnet"),
    ".vcxproj": ("native", "msbuild"),
    ".vcproj": ("native", "vcbuild"),
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
# Every build system discovery can assign to a unit. Planning registers exactly these, so a unit
# discovery emits can never be rejected as unregistered by the plan validator.
WASM_C_BUILD_SYSTEM = "clang"
DISCOVERED_BUILD_SYSTEMS = frozenset(
    {system for _, system in (*_MARKERS.values(), *_SUFFIX_MARKERS.values(), *_SOURCE_MARKERS.values())}
    | {WASM_C_BUILD_SYSTEM, UNITY_BUILD_SYSTEM})
_CONTEXT_NAMES = {
    "README", "README.md", "README.rst", "Dockerfile", "build.sh", "build.ps1",
    "build.gradle", "build.gradle.kts", "gradle.properties", "settings.gradle", "settings.gradle.kts", "gradle.lockfile",
    "maven-wrapper.properties", "gradle-wrapper.properties", "Cargo.lock",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock", "requirements.txt",
    "poetry.lock", "Pipfile.lock", "pylock.toml", "setup.cfg",
    "rust-toolchain", "rust-toolchain.toml", "Directory.Build.props", "global.json",
    "packages.lock.json", "Directory.Packages.props", "NuGet.Config", "tsconfig.json",
    "binding.gyp", "config.m4", "go.sum", "go.work.sum",
    "Gruntfile.js", "gulpfile.js",
    "Gemfile", "Gemfile.lock", "ReadMe.txt", "fbuild.bff", "build_ms.bat",
}
# Families whose own packaging tool drives a C/C++ compile inside the same build (node-gyp,
# setuptools, phpize, clang --target=wasm32). C/C++ sources under such a root are the unit's
# typed ``native_components``, not a second direct-native unit that would need its own build.
NATIVE_COMPONENT_OWNER_FAMILIES = frozenset({"node", "python", "php", "wasm"})
_BUILD_SCRIPT_NAMES = frozenset({"build.sh"})
_WASM_SCRIPT = re.compile(r"--target[= ]wasm32|\bwasm32-|(?:^|\s)(?:emcc|em\+\+)(?:\s|$)", re.M)
_NODE_ANCESTOR_CONTEXT_NAMES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
}


def _is_context_name(name: str) -> bool:
    # requirements-build.txt, requirements-dev.txt, ... carry pinned build-backend inputs.
    return name in _CONTEXT_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def _is_node_ancestor_context(path: PurePosixPath) -> bool:
    return (path.name in _NODE_ANCESTOR_CONTEXT_NAMES or
            (path.name.startswith("tsconfig.") and path.name.endswith(".json")))


_PROFILE_COMMANDS: dict[str, frozenset[str]] = {
    "native": frozenset({"cmake", "ninja", "make", "gmake", "clang", "clang++", "gcc", "g++",
                         "emcc", "em++", "emar", "wasm-ld", "llvm-ar", "wasm-opt", "wasm-tools",
                         "autoreconf", "autoconf",
                         "automake", "libtoolize", "meson", "bear", "pkg-config"}),
    "rust": frozenset({"cargo", "rustc", "wasm-pack", "wasm-bindgen", "wasm-opt", "wasm-tools"}),
    "go": frozenset({"go"}),
    "java": frozenset({"mvn", "mvnw", "gradle", "gradlew", "javac", "kotlinc", "kapt", "jar", "protoc"}),
    "android": frozenset({"gradle", "gradlew"}),
    "node": frozenset({"npm", "npx", "pnpm", "yarn", "node", "tsc", "asc", "wasm-opt", "wasm-tools"}),
    "dotnet": frozenset({"dotnet", "msbuild"}),
    "python": frozenset({"python", "python3", "pip", "pip3"}),
    "php": frozenset({"php", "composer", "phpize", "make"}),
    "wasm": frozenset({"cargo", "rustc", "clang", "clang++", "cmake", "wasm-tools", "wasm-opt",
                        "wasm-ld", "emcc", "em++", "emar", "asc"}),
}
_SECRET_KEY = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
_ENV_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
_FORBIDDEN_SUBCOMMANDS = {
    "make": {"check", "test", "install", "uninstall"},
    "gmake": {"check", "test", "install", "uninstall"},
    "cargo": {"install", "run", "test"}, "go": {"get", "install", "run", "test"},
    "dotnet": {"run", "test", "tool"}, "npm": {"exec", "install", "test", "start", "publish"},
    "npx": {"--yes", "-y"}, "pnpm": {"add", "dlx", "exec", "install", "test", "start", "publish"},
    "yarn": {"add", "dlx", "exec", "install", "test", "start", "publish"}, "mvn": {"exec:java", "test"},
    "composer": {"exec", "run-script", "test"}, "php": {"-r", "--interactive"},
}
_NATIVE_BOOTSTRAP_COMMANDS = frozenset({"autoreconf", "autoconf", "automake", "libtoolize"})

_GRADLE_BUILD_TASKS = ("assemble", "classes", "jar", "war", "clean", "build")
_ANDROID_GRADLE_BUILD_TASKS = ("assemble", "assembleDebug")


def required_image_profile(unit: Mapping[str, Any]) -> str:
    """Return the execution image selected from accepted deterministic build facts."""
    if unit.get("build_system") == UNITY_BUILD_SYSTEM:
        return "unity"
    facts = unit.get("descriptor_facts", {})
    if (unit.get("family") == "java" and unit.get("build_system") == "gradle" and
            isinstance(facts, Mapping) and facts.get("kind") == "android-gradle-application"):
        return "android"
    return str(unit.get("family", ""))


def build_recipe_inference_policy(unit: Mapping[str, Any]) -> dict[str, Any]:
    """Expose the validator's bounded command contract to recipe inference."""
    profile = required_image_profile(unit)
    policy: dict[str, Any] = {"required_image_profile": profile,
                              "allowed_executables": sorted(_PROFILE_COMMANDS.get(profile, ()))}
    if profile == "php" and unit.get("build_system") == "phpize":
        policy["allowed_executables"].append("./configure")
    if profile == "node":
        authority = _node_build_authority(unit)
        if authority is not None:
            policy["descriptor_build_command"] = authority[0]
    components = [str(item.get("path")) for item in unit.get("native_components", ())
                  if isinstance(item, Mapping)]
    if components:
        policy["native_components"] = {
            "sources": components,
            "contract": ("these C/C++ sources are compiled by this unit's own build tool in the "
                         "same container; do not plan a separate native build for them"),
        }
    if profile == "android":
        policy["gradle"] = {
            "allowed_executables": ["gradle", "gradlew"],
            "allowed_task_suffixes": list(_ANDROID_GRADLE_BUILD_TASKS),
            "module_qualification": "an allowed task may be qualified by a module from settings.gradle",
            "forbidden_task_classes": ["test", "connected-test", "install", "run"],
        }
    return policy


def jvm_build_command_errors(profile: str, argv: Sequence[str]) -> tuple[str, ...]:
    """Validate Maven and Gradle build-only goals for planning and execution."""
    if not argv:
        return ("JVM command is empty",)
    executable = PurePosixPath(str(argv[0])).name
    lowered = [str(value).lower() for value in argv[1:]]
    errors: list[str] = []
    if executable in {"mvn", "mvnw"}:
        goals = [value for value in lowered if not value.startswith("-")]
        allowed_goals = {"clean", "compile", "package", "process-resources", "generate-sources",
                         "generate-resources", "jar:jar", "war:war"}
        if any(value not in allowed_goals for value in goals):
            errors.append("Maven goal is not build-only")
        if not any(value == "-dskiptests" or value.startswith("-dmaven.test.skip=true")
                   for value in lowered):
            errors.append("Maven build must explicitly disable tests")
    if executable in {"gradle", "gradlew"}:
        tasks: list[str] = []
        excluded: set[str] = set()
        index = 0
        while index < len(lowered):
            value = lowered[index]
            if value in {"-x", "--exclude-task"}:
                if index + 1 >= len(lowered):
                    errors.append("Gradle task exclusion is missing its task")
                    break
                excluded.add(lowered[index + 1].rsplit(":", 1)[-1])
                index += 2
                continue
            if value.startswith("--exclude-task="):
                excluded.add(value.split("=", 1)[1].rsplit(":", 1)[-1])
            elif not value.startswith("-"):
                tasks.append(value.rsplit(":", 1)[-1])
            index += 1
        configured_tasks = _ANDROID_GRADLE_BUILD_TASKS if profile == "android" else _GRADLE_BUILD_TASKS
        allowed_tasks = {value.lower() for value in configured_tasks}
        if any(value not in allowed_tasks for value in tasks):
            errors.append(
                f"Gradle task is not allowed for {profile} profile; allowed task suffixes: " +
                ", ".join(configured_tasks))
        if "build" in tasks and "test" not in excluded:
            errors.append("Gradle build must exclude the test task")
    return tuple(dict.fromkeys(errors))


def _marker(path: PurePosixPath) -> tuple[str, str] | None:
    return _MARKERS.get(path.name) or _SUFFIX_MARKERS.get(path.suffix.lower())


def is_build_descriptor(path: PurePosixPath) -> bool:
    """Select project markers and build context before ordinary content-inventory limits."""
    engine_descriptor = (
        path.parent.name == "ProjectSettings" and path.name in {
            "ProjectVersion.txt", "ProjectSettings.asset", "EditorBuildSettings.asset"}
        or path.parent.name == "Packages" and path.name in {"manifest.json", "packages-lock.json"}
        or path.suffix.lower() in {".asmdef", ".asmref", ".uproject", ".uplugin"}
        or path.suffix.lower() == ".meta" and PurePosixPath(path.stem).suffix.lower() in {
            ".dll", ".so", ".dylib", ".a", ".bundle"}
    )
    return engine_descriptor or (
        path.suffix.lower() != ".wasm" and (_marker(path) is not None or _is_context_name(path.name)))


def _id(root: str, family: str, system: str) -> str:
    value = hashlib.sha256(f"{root}\0{family}\0{system}".encode()).hexdigest()[:20]
    return f"build-unit-{value}"


def _wasm_build_script(path: PurePosixPath, read_text: Callable[[str], str | None] | None) -> bool:
    if read_text is None or path.name not in _BUILD_SCRIPT_NAMES:
        return False
    text = read_text(path.as_posix())
    return bool(text) and bool(_WASM_SCRIPT.search(text or ""))


def _component(item: Mapping[str, Any]) -> dict[str, Any]:
    return {"path": item["path"], "sha256": item["sha256"], "size_bytes": item["size_bytes"]}


def discover_build_units(files: Sequence[Mapping[str, Any]], *,
                         read_text: Callable[[str], str | None] | None = None,
                         engine_discovery: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Group accepted build descriptors into stable, repository-independent build units.

    ``read_text`` returns the bounded text of a cataloged file. It lets a build script that
    targets wasm32 route its C sources to the wasm family instead of a direct-native unit.
    """
    from appsec_review.jobs.engine_discovery import discover_unity

    engines = (engine_discovery if engine_discovery is not None else
               discover_unity(files, read_text=lambda descriptor, _limit:
                              read_text(str(descriptor["path"])) if read_text is not None else None))
    unity_roots = [PurePosixPath(project["root"]) for project in engines["projects"]]
    def unity_owner(path: PurePosixPath) -> PurePosixPath | None:
        return max((root for root in unity_roots if root.as_posix() == "." or root in path.parents),
                   key=lambda root: len(root.parts), default=None)

    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    components: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for item in files:
        path = PurePosixPath(str(item["path"]))
        marker = _marker(path)
        if marker is None:
            continue
        owner = unity_owner(path)
        if owner is not None and (
                path.suffix.lower() in {".csproj", ".vbproj", ".fsproj", ".sln", ".vcxproj", ".vcproj"}
                or path.name == "package.json" and "Packages" in path.relative_to(owner).parts[:-1]):
            continue
        family, system = marker
        root = path.parent.as_posix()
        groups[(root, family, system)].append(item)
    for item in files:
        path = PurePosixPath(str(item["path"]))
        root = path.parent.as_posix()
        if _wasm_build_script(path, read_text) and not any(key[0] == root for key in groups):
            groups[(root, "wasm", WASM_C_BUILD_SYSTEM)].append(item)
    for root, family, _system in [
        key for key in tuple(groups) if key[2] in {"cmake", "autotools", "meson"}
    ]:
        groups.pop((root, family, "make"), None)
    gradle_roots = [PurePosixPath(root) for root, family, system in groups
                    if family == "java" and system == "gradle" and any(
                        PurePosixPath(str(item["path"])).parent == PurePosixPath(root) and
                        PurePosixPath(str(item["path"])).name in {"settings.gradle", "settings.gradle.kts"}
                        for item in files)]
    for root, family, system in tuple(groups):
        path = PurePosixPath(root)
        if family == "java" and system == "gradle" and any(parent != path and parent in path.parents for parent in gradle_roots):
            groups.pop((root, family, system), None)
    descriptor_roots = [(PurePosixPath(root), family) for root, family, _system in groups]
    for item in files:
        path = PurePosixPath(str(item["path"]))
        fallback = _SOURCE_MARKERS.get(path.suffix.lower())
        if fallback is None:
            continue
        if ".teamcity" in path.parts:
            # TeamCity Kotlin DSL is CI configuration, not an independently compilable JVM
            # source tree. It is cataloged and analyzed by the CI lanes instead.
            continue
        family, system = fallback
        matching_roots = [root for root, existing_family in descriptor_roots
                          if existing_family == family and
                          (root.as_posix() == "." or path == root or root in path.parents)]
        owner = unity_owner(path)
        if (owner is not None and family == "native" and
                not any(len(root.parts) >= len(owner.parts) for root in matching_roots)):
            components[(owner.as_posix(), UNITY_LANGUAGE_FAMILY, UNITY_BUILD_SYSTEM)].append(item)
            continue
        if matching_roots:
            continue
        if family == "native":
            owners = [key for key in groups if key[1] in NATIVE_COMPONENT_OWNER_FAMILIES and
                      (key[0] == "." or PurePosixPath(key[0]) in path.parents)]
            if owners:
                # The nearest owning package root compiles this source in its own build.
                owner = max(owners, key=lambda key: (len(PurePosixPath(key[0]).parts), key))
                components[owner].append(item)
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
        native = components.get((root, family, system))
        if native:
            values[-1]["native_components"] = [
                _component(value) for value in sorted(native, key=lambda value: str(value["path"]))]
    for project in engines["projects"]:
        root = str(project["root"])
        values.append({
            "build_unit_id": _id(root, UNITY_LANGUAGE_FAMILY, UNITY_BUILD_SYSTEM),
            "root": root, "family": UNITY_LANGUAGE_FAMILY, "build_system": UNITY_BUILD_SYSTEM,
            "engine": dict(project["engine"]), "markers": list(project["markers"]),
            "descriptor_facts": dict(project["descriptor_facts"]),
            "engine_project": project,
            "native_components": sorted(
                components.get((root, UNITY_LANGUAGE_FAMILY, UNITY_BUILD_SYSTEM), ()),
                key=lambda value: str(value["path"])),
            "provenance": "deterministic-engine-descriptors",
        })
    values.sort(key=lambda value: (str(value["root"]), str(value["family"]), str(value["build_system"])))
    return values


_INTERPRETED_SUFFIXES = {".py": "python", ".php": "php"}
SOURCE_ONLY_SCOPE_SOURCE_LIMIT = 256


def source_only_scopes(files: Sequence[Mapping[str, Any]],
                       units: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Name interpreted source trees that no build unit owns.

    Such a scope has no material build: it is recorded as not applicable for build capture and
    compiler artifacts, so its absence from the build lanes is explicit rather than silent.
    A scope root is the shallowest directory that directly holds a source of its language.
    """
    unit_roots = [PurePosixPath(str(unit["root"])) for unit in units]
    owned = lambda path: any(root.as_posix() == "." or root in path.parents for root in unit_roots)
    candidates = [(PurePosixPath(str(item["path"])), _INTERPRETED_SUFFIXES[PurePosixPath(
        str(item["path"])).suffix.lower()], item) for item in files
        if PurePosixPath(str(item["path"])).suffix.lower() in _INTERPRETED_SUFFIXES]
    holders: dict[str, set[PurePosixPath]] = defaultdict(set)
    for path, language, _item in candidates:
        if not owned(path):
            holders[language].add(path.parent)
    scopes: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for path, language, item in candidates:
        if owned(path):
            continue
        root = min((parent for parent in (path.parent, *path.parent.parents)
                    if parent in holders[language]), key=lambda value: len(value.parts))
        scopes[(root.as_posix(), language)].append(item)
    values = []
    for (root, language), items in sorted(scopes.items()):
        ordered = sorted(items, key=lambda value: str(value["path"]))
        values.append({
            "scope_id": "source-scope-" + hashlib.sha256(
                f"{root}\0{language}".encode()).hexdigest()[:20],
            "root": root, "language": language, "family": language,
            "source_count": len(ordered),
            "sources": [{"path": value["path"], "sha256": value["sha256"]}
                        for value in ordered[:SOURCE_ONLY_SCOPE_SOURCE_LIMIT]],
            "sources_truncated": len(ordered) > SOURCE_ONLY_SCOPE_SOURCE_LIMIT,
        })
    return values


def unsupported_build_gaps(files: Sequence[Mapping[str, Any]],
                           units: Sequence[Mapping[str, Any]]) -> list[str]:
    """Name recognized project lifecycles that have no safe execution lane."""
    claimed = {str(marker.get("path")) for unit in units for marker in unit.get("markers", ())
               if isinstance(marker, Mapping)}
    return [
        f"{item['path']}: Bundler build unavailable: no pinned Ruby build profile or executor; "
        "gem installation, lifecycle hooks, packaging, and native extensions were not run"
        for item in files
        if PurePosixPath(str(item.get("path", ""))).name == "Gemfile" and str(item.get("path")) not in claimed
    ]


NODE_LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
# Dependency lockfiles are inventory, not prose a planner reads: their identity (path and catalog
# sha256) pins what the dependency restore installs. One larger than the descriptor content bound
# is carried by identity alone instead of becoming an inventory gap.
_LOCKFILE_NAMES = frozenset({
    *NODE_LOCKFILES, "Cargo.lock", "composer.lock", "poetry.lock", "Pipfile.lock", "pylock.toml",
    "gradle.lockfile", "packages.lock.json", "go.sum", "go.work.sum",
})
# Members a workspace inventory may name. A recipe carries every member manifest, and recipes
# accept at most 64 dependency files.
NODE_WORKSPACE_MEMBER_LIMIT = 48
_WORKSPACE_DECLARATION_BYTES = 64 * 1024
_WORKSPACE_LISTING_LIMIT = 512


def _workspace_pattern(pattern: str) -> re.Pattern[str] | None:
    """Compile one npm/Yarn/pnpm workspace glob over workspace-relative directory paths."""
    value = pattern.strip()
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    if not value or value.startswith("/") or "\\" in value:
        return None
    segments = value.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        return None
    parts = []
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            parts.append("[^/]+(?:/[^/]+)*" if last else "(?:[^/]+/)*")
            continue
        text = "".join("[^/]*" if char == "*" else "[^/]" if char == "?" else re.escape(char)
                       for char in segment)
        parts.append(text if last else text + "/")
    return re.compile("".join(parts))


def _pnpm_workspace_patterns(text: str) -> list[str] | None:
    """Read the ``packages`` list of a pnpm-workspace.yaml; ``None`` when it is not that shape."""
    patterns: list[str] | None = None
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():
            if patterns is not None:
                break
            key, _, rest = line.partition(":")
            if key.strip() == "packages":
                if rest.strip() not in {"", "[]"}:
                    flow = rest.strip()
                    if not (flow.startswith("[") and flow.endswith("]")):
                        return None
                    return [item.strip().strip("'\"") for item in flow[1:-1].split(",")
                            if item.strip()]
                patterns = []
            continue
        if patterns is None:
            continue
        item = line.strip()
        if not item.startswith("- "):
            return None
        patterns.append(item[2:].strip().strip("'\""))
    return patterns


def _read_bounded(target_root: Path, item: Mapping[str, Any]) -> str | None:
    if int(item["size_bytes"]) > _WORKSPACE_DECLARATION_BYTES:
        return None
    path = (target_root / Path(*PurePosixPath(str(item["path"])).parts)).resolve()
    if target_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("workspace declaration escaped the accepted target")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeError:
        return None


def _workspace_declaration(target_root: Path, directory: PurePosixPath,
                           by_path: Mapping[str, Mapping[str, Any]]
                           ) -> tuple[str, str, list[str] | None] | None:
    """Return (manager, declaration path, patterns) for a directory that declares a workspace."""
    pnpm = (directory / "pnpm-workspace.yaml").as_posix()
    if pnpm in by_path:
        text = _read_bounded(target_root, by_path[pnpm])
        return "pnpm", pnpm, (_pnpm_workspace_patterns(text) if text is not None else None)
    manifest = (directory / "package.json").as_posix()
    if manifest not in by_path:
        return None
    text = _read_bounded(target_root, by_path[manifest])
    if text is None:
        return None
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return None
    declared = document.get("workspaces") if isinstance(document, Mapping) else None
    if declared is None:
        return None
    if isinstance(declared, Mapping):
        declared = declared.get("packages")
    if not isinstance(declared, list) or any(not isinstance(item, str) for item in declared):
        return "npm", manifest, None
    return "npm", manifest, list(declared)


def node_workspace(target_root: Path, unit: Mapping[str, Any],
                   files: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any] | None, list[str]]:
    """Resolve the npm, Yarn, or pnpm workspace a Node build unit roots or belongs to.

    A workspace member's dependency inventory is the workspace root's lockfile, and a root's
    inventory includes every member manifest: package managers install a workspace as one tree
    and link members into it. Only accepted catalog files are consulted (the catalog excludes
    ``node_modules`` and symlinks); a declared member the catalog could not accept, a missing
    or ambiguous root lockfile, or an unreadable declaration is a named inventory gap.
    """
    if unit.get("family") != "node":
        return None, []
    by_path = {str(item["path"]): item for item in files}
    unit_root = PurePosixPath(str(unit["root"]))
    manifests = sorted(PurePosixPath(path).parent for path in by_path
                       if PurePosixPath(path).name == "package.json")
    for directory in (unit_root, *unit_root.parents):
        declaration = _workspace_declaration(target_root, directory, by_path)
        if declaration is None:
            continue
        manager, declared_by, patterns = declaration
        prefix = "" if directory.as_posix() == "." else directory.as_posix() + "/"
        label = directory.as_posix()
        if patterns is None:
            if directory != unit_root:
                continue
            return None, [f"{declared_by}: workspace declaration could not be read; "
                          "the workspace dependency inventory is unavailable"]
        includes = [(raw, _workspace_pattern(raw)) for raw in patterns if not raw.startswith("!")]
        excludes = [_workspace_pattern(raw[1:]) for raw in patterns if raw.startswith("!")]
        gaps = [f"{declared_by}: workspace pattern is unsupported: {raw[:256]}"
                for raw, compiled in includes if compiled is None]
        members = []
        for candidate in manifests:
            if candidate == directory or (directory.as_posix() != "." and directory not in candidate.parents):
                continue
            relative = candidate.as_posix()[len(prefix):]
            if "node_modules" in candidate.parts:
                continue
            if (any(compiled is not None and compiled.fullmatch(relative) for _raw, compiled in includes) and
                    not any(compiled is not None and compiled.fullmatch(relative) for compiled in excludes)):
                members.append(candidate.as_posix())
        role = ("root" if directory == unit_root else
                "member" if unit_root.as_posix() in members else None)
        if role is None:
            # A nested project the workspace does not claim installs on its own.
            return None, []
        base = target_root / Path(*directory.parts)
        for raw, compiled in includes:
            if compiled is None:
                continue
            literal = []
            for segment in raw.strip().removeprefix("./").rstrip("/").split("/"):
                if any(char in segment for char in "*?[{"):
                    break
                literal.append(segment)
            parent = base.joinpath(*literal) if literal else base
            if not any(char in raw for char in "*?[{"):
                if parent.is_symlink():
                    gaps.append(f"{prefix}{'/'.join(literal)}: workspace member is a symlink; "
                                "its manifest is outside the accepted inventory")
                elif (PurePosixPath(prefix + "/".join(literal)) / "package.json").as_posix() not in by_path:
                    gaps.append(f"{prefix}{'/'.join(literal)}: declared workspace member has no "
                                "accepted package.json")
                continue
            if parent.is_symlink() or not parent.is_dir():
                continue
            for index, entry in enumerate(sorted(parent.iterdir())):
                if index >= _WORKSPACE_LISTING_LIMIT:
                    gaps.append(f"{declared_by}: workspace member listing bound reached")
                    break
                relative = "/".join([*literal, entry.name])
                if entry.is_symlink() and compiled.fullmatch(relative) and not any(
                        value is not None and value.fullmatch(relative) for value in excludes):
                    gaps.append(f"{prefix}{relative}: workspace member is a symlink; "
                                "its manifest is outside the accepted inventory")
        if len(members) > NODE_WORKSPACE_MEMBER_LIMIT:
            gaps.append(f"{declared_by}: workspace declares more than {NODE_WORKSPACE_MEMBER_LIMIT} "
                        "members; the workspace dependency inventory is unbounded")
            members = members[:NODE_WORKSPACE_MEMBER_LIMIT]
        locks = [(directory / name).as_posix() for name in NODE_LOCKFILES
                 if (directory / name).as_posix() in by_path]
        if manager == "pnpm":
            locks = [path for path in locks if path.endswith("pnpm-lock.yaml")] or locks
        if not locks:
            gaps.append(f"{label}: workspace dependency inventory unavailable: no "
                        "package-lock.json, pnpm-lock.yaml, or yarn.lock at the workspace root")
        elif len(locks) > 1:
            gaps.append(f"{label}: workspace dependency inventory is ambiguous: "
                        + ", ".join(locks))
        lockfile = locks[0] if len(locks) == 1 else None
        if lockfile is not None and manager == "npm":
            manager = {"pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn"}.get(
                PurePosixPath(lockfile).name, "npm")
        inventory = sorted({declared_by, (directory / "package.json").as_posix(),
                            *([lockfile] if lockfile else []),
                            *((PurePosixPath(member) / "package.json").as_posix() for member in members)}
                           & set(by_path))
        return {"root": label, "role": role, "manager": manager, "declaration": declared_by,
                "lockfile": lockfile, "members": members, "inventory": inventory}, gaps
    return None, []


def _identity(item: Mapping[str, Any]) -> dict[str, Any]:
    return {"path": item["path"], "sha256": item["sha256"], "size_bytes": item["size_bytes"]}


def descriptor_package(target_root: Path, unit: Mapping[str, Any], files: Sequence[Mapping[str, Any]],
                       *, max_files: int = 24, max_file_bytes: int = 64 * 1024,
                       max_total_bytes: int = 256 * 1024) -> dict[str, Any]:
    root = str(unit["root"])
    candidates: list[Mapping[str, Any]] = []
    marker_paths = {str(item["path"]) for item in unit["markers"]}
    # Native component sources are what the family build compiles; the planner needs them to
    # write the compile command (for example a clang --target=wasm32 translation of build.sh).
    component_paths = {str(item["path"]) for item in unit.get("native_components", ())}
    workspace, gaps = node_workspace(target_root, unit, files)
    workspace_root = PurePosixPath(workspace["root"]) if workspace else None
    for item in files:
        path = PurePosixPath(str(item["path"]))
        under = root == "." or path.as_posix() == root or path.as_posix().startswith(root + "/")
        unit_root = PurePosixPath(root)
        ancestor_context = (
            unit.get("family") == "node" and _is_node_ancestor_context(path) and
            path.parent != unit_root and
            (path.parent == PurePosixPath(".") or path.parent in unit_root.parents)
        )
        if workspace_root is not None and ancestor_context and path.name in NODE_LOCKFILES:
            # A workspace member's lockfile is the workspace root's, never a further ancestor's.
            ancestor_context = path.parent == workspace_root
        if not under and not ancestor_context:
            continue
        if (str(item["path"]) in marker_paths or str(item["path"]) in component_paths or
                _is_context_name(path.name) or
                path.name.startswith("Dockerfile") or ancestor_context):
            candidates.append(item)
    documents = []
    total = 0
    by_path = {str(item["path"]): item for item in files}
    inventory = {path: _identity(by_path[path]) for path in (workspace or {}).get("inventory", ())}
    for item in sorted(candidates, key=lambda value: (
            0 if str(value["path"]) in marker_paths else
            1 if PurePosixPath(str(value["path"])).parent == PurePosixPath(root) else 2,
            str(value["path"]))):
        if len(documents) >= max_files:
            gaps.append("descriptor file-count bound reached")
            break
        size = int(item["size_bytes"])
        if size > max_file_bytes or total + size > max_total_bytes:
            if PurePosixPath(str(item["path"])).name in _LOCKFILE_NAMES:
                inventory[str(item["path"])] = _identity(item)
                continue
            gaps.append(f"{item['path']}: descriptor content omitted by byte bound")
            continue
        path = (target_root / Path(*PurePosixPath(str(item["path"])).parts)).resolve()
        if target_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            raise ValueError("build descriptor escaped the accepted target")
        try:
            with path.open("rb") as stream:
                content = stream.read(max_file_bytes + 1)
            if hashlib.sha256(content).hexdigest() != item["sha256"] or len(content) != size:
                raise ValueError(f"build descriptor identity changed: {item['path']}")
            text = content.decode("utf-8")
        except UnicodeError:
            gaps.append(f"{item['path']}: descriptor is not UTF-8 text")
            continue
        documents.append({"path": item["path"], "sha256": item["sha256"], "content": text})
        total += size
    for relative in inventory:
        path = (target_root / Path(*PurePosixPath(relative).parts)).resolve()
        if target_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            raise ValueError("dependency inventory escaped the accepted target")
    documents.sort(key=lambda document: str(document["path"]))
    package = {"schema": BUILD_DESCRIPTOR_SCHEMA, "build_unit": dict(unit), "documents": documents,
               "bounds": {"max_files": max_files, "max_file_bytes": max_file_bytes,
                          "max_total_bytes": max_total_bytes, "actual_files": len(documents),
                          "actual_bytes": total}, "gaps": gaps}
    if inventory:
        # Identity-only dependency inventory: the restore pins these exact bytes, but the
        # planner never needs their content.
        package["inventory"] = [inventory[path] for path in sorted(inventory)]
    if workspace is not None:
        package["workspace"] = {key: value for key, value in workspace.items() if key != "inventory"}
    return package


def copied_source_symlink(source: Path, ignored: frozenset[str] | set[str]) -> Path | None:
    """Return the first symlink a build-source copy would carry, or ``None``.

    Directories the copy ignores are never entered: an installed ``node_modules`` holds
    package-manager links (workspace members, ``.bin`` entries) that are not build source.
    """
    for directory, dirnames, filenames in os.walk(source, topdown=True, followlinks=False):
        base = Path(directory)
        kept = []
        for name in sorted(dirnames):
            if name in ignored:
                continue
            if (base / name).is_symlink():
                return base / name
            kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            if name not in ignored and (base / name).is_symlink():
                return base / name
    return None


def ensure_declared_build_dir(workspace: Path, recipe: Any) -> str | None:
    """Create an accepted recipe's absent ``build_dir`` inside a run-owned build workspace.

    Recipes cannot run ``mkdir``, so a compiler writing ``-o build/x`` needs the declared
    directory to exist. Returns the created relative path, or ``None`` when nothing was created.
    """
    build_dir = recipe.get("build_dir") if isinstance(recipe, Mapping) else None
    if not _relative(build_dir) or build_dir == ".":
        return None
    root = workspace.resolve(strict=True)
    current = root
    for part in PurePosixPath(build_dir).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("declared build_dir traverses a symlink in the build workspace")
        if current.exists() and not current.is_dir():
            return None
    if current.is_dir():
        return None
    current.mkdir(parents=True)
    if root not in current.resolve(strict=True).parents:
        raise ValueError("declared build_dir escaped the build workspace")
    return PurePosixPath(build_dir).as_posix()


def descriptor_inventory_paths(unit: Mapping[str, Any]) -> list[str]:
    """Every accepted descriptor path of a unit: its content documents and identity inventory."""
    package = unit.get("descriptor_package", {})
    if not isinstance(package, Mapping):
        return []
    return sorted({str(item["path"]) for key in ("documents", "inventory")
                   for item in package.get(key, ()) if isinstance(item, Mapping) and "path" in item})


def android_descriptor_facts(package: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return bounded Android Gradle facts from accepted descriptor bytes."""
    documents = package.get("documents", ())
    texts = [str(item.get("content", "")) for item in documents if isinstance(item, Mapping)]
    joined = "\n".join(texts)
    if not re.search(
            r"(?:id\s*\(\s*[\"']com\.android\.application[\"']\s*\)|id\s+[\"']com\.android\.application[\"'])",
            joined):
        return None

    def match(pattern: str) -> str | None:
        found = re.search(pattern, joined)
        return found.group(1) if found else None

    return {
        "kind": "android-gradle-application",
        "plugin_id": "com.android.application",
        "plugin_version": match(r"com\.android\.application[\"']\s*\)?\s*version\s*[\"']([^\"']+)") or "declared-in-parent",
        "compile_sdk": match(r"compileSdk\s*=\s*(\d+)"),
        "target_sdk": match(r"targetSdk\s*=\s*(\d+)"),
        "build_tools": match(r"buildToolsVersion\s*=\s*[\"']([^\"']+)"),
    }

def _relative(value: Any, *, allow_dot: bool = True) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return (allow_dot or value != ".") and not any(part in {"", ".."} for part in path.parts)


def _within(value: str, root: str) -> bool:
    path = PurePosixPath(value)
    boundary = PurePosixPath(root)
    return root == "." or path == boundary or boundary in path.parents


def _execution_cwd_errors(recipe: Mapping[str, Any], root: str) -> list[str]:
    if "execution_cwd" not in recipe:
        return []
    values = recipe["execution_cwd"]
    if (not isinstance(values, Mapping) or not values or
            set(values) - {"configure", "build"}):
        return ["execution_cwd must be a nonempty configure/build phase mapping"]
    errors = []
    for phase, value in values.items():
        if (not _relative(value) or len(value) > 512 or ":" in value or
                any(ord(character) < 32 or ord(character) == 127 for character in value) or
                PurePosixPath(value).as_posix() != value):
            errors.append(f"execution_cwd.{phase} must be a normalized target-relative path")
        elif not _within(value, root):
            errors.append(f"execution_cwd.{phase} must stay within the accepted build-unit root")
    return errors


def recipe_execution_cwd(recipe: Mapping[str, Any], phase: Literal["configure", "build"]) -> str:
    """Return a lexical target-relative cwd without creating or resolving directories.

    validate_build_recipe binds source_dir to its accepted unit; callers additionally verify
    directory evidence, existence and effective workspace custody before each command.
    """
    if phase not in ("configure", "build"):
        raise ValueError("recipe execution phase must be configure or build")
    source = recipe.get("source_dir")
    if (not _relative(source) or ":" in source or PurePosixPath(source).as_posix() != source or
            any(ord(character) < 32 or ord(character) == 127 for character in source)):
        raise ValueError("source_dir must be a normalized target-relative path")
    errors = _execution_cwd_errors(recipe, source)
    if errors:
        raise ValueError("; ".join(errors))
    return recipe.get("execution_cwd", {}).get(phase, source)


_NODE_DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")


def _node_manifest(unit: Mapping[str, Any]) -> Mapping[str, Any]:
    root = PurePosixPath(str(unit.get("root", ".")))
    manifest = (root / "package.json").as_posix()
    for item in unit.get("descriptor_package", {}).get("documents", ()):
        if not isinstance(item, Mapping) or str(item.get("path", "")) != manifest:
            continue
        try:
            document = json.loads(str(item.get("content", "")))
        except json.JSONDecodeError:
            return {}
        return document if isinstance(document, Mapping) else {}
    return {}


def node_manifest_declares_dependencies(unit: Mapping[str, Any]) -> bool:
    """Return whether the build unit's own accepted package.json declares packages."""
    document = _node_manifest(unit)
    return any(isinstance(document.get(field), Mapping) and bool(document[field])
               for field in _NODE_DEPENDENCY_FIELDS)


def _node_restore_only(argv: Any) -> bool:
    return isinstance(argv, list) and argv[:2] in (
        ["npm", "ci"], ["npm", "install"], ["pnpm", "install"], ["yarn", "install"],
    )


def _node_optional_command(argv: Any) -> bool:
    if not isinstance(argv, list) or not argv or argv[0] not in {"npm", "pnpm", "yarn"}:
        return False
    for argument in argv[1:]:
        if argument == "--":
            break
        if isinstance(argument, str) and argument.partition("=")[0] == "--if-present":
            return True
    return False


def _node_grunt_commands(unit: Mapping[str, Any]) -> list[tuple[list[str], str]]:
    path = (PurePosixPath(str(unit.get("root", "."))) / "Gruntfile.js").as_posix()
    build_tasks = {"clean", "copy", "concat", "ngAnnotate", "uglify", "rev", "useminPrepare", "usemin"}
    commands = []
    for document in unit.get("descriptor_package", {}).get("documents", ()):
        if document.get("path") != path or not isinstance(document.get("content"), str):
            continue
        text = document["content"]
        excluded = [match.span() for match in re.finditer(
            r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`|//[^\r\n]*|/\*[\s\S]*?\*/""", text)]
        registrations = [match.group(1) for match in re.finditer(
            r"grunt\.registerTask\s*\(\s*['\"]([^'\"]+)['\"]\s*,", text)
            if not any(start <= match.start() < end for start, end in excluded)]
        for match in re.finditer(
            r"grunt\.registerTask\s*\(\s*(['\"])(build[A-Za-z0-9_-]*)\1\s*,\s*(\[[^\]]*\])\s*\)", text,
        ):
            if any(start <= match.start() < end for start, end in excluded):
                continue
            _quote, name, literal = match.groups()
            if registrations.count(name) != 1:
                continue
            try:
                tasks = ast.literal_eval(literal)
            except (ValueError, SyntaxError):
                continue
            if (isinstance(tasks, list) and tasks and
                    all(isinstance(task, str) and re.fullmatch(r"[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)*", task)
                        and task.split(":", 1)[0] in build_tasks for task in tasks)):
                commands.append((["npx", "--no-install", "grunt", name], path))
    return sorted(commands, key=lambda value: (value[0][-1] != "build", value[0][-1]))


def _node_build_authority(unit: Mapping[str, Any]) -> tuple[list[str], str] | None:
    scripts = _node_manifest(unit).get("scripts", {})
    for name in ("build", "minify"):
        if isinstance(scripts, Mapping) and isinstance(scripts.get(name), str) and scripts[name].strip():
            path = (PurePosixPath(str(unit.get("root", "."))) / "package.json").as_posix()
            return ["npm", "run", name], path
    commands = _node_grunt_commands(unit)
    return commands[0] if commands else None


def _native_non_build_command(argv: Any) -> bool:
    if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
        return True
    executable = PurePosixPath(argv[0]).name
    if executable in _NATIVE_BOOTSTRAP_COMMANDS | {"pkg-config"}:
        return True
    if any(value in {"--version", "--help"} for value in argv[1:]):
        return True
    if executable == "cmake":
        return "--build" not in argv[1:]
    if executable == "meson":
        return argv[1:2] != ["compile"]
    if executable in {"make", "gmake", "ninja"}:
        for value in argv[1:]:
            if value == "--":
                break
            if value.partition("=")[0] in {
                    "--dry-run", "--just-print", "--recon", "--question", "--touch"}:
                return True
            if value.startswith("-") and not value.startswith("--"):
                for option in value[1:]:
                    if option in ("nqtvh" if executable != "ninja" else "nth"):
                        return True
                    if option in "CfIjloW":
                        break
    return False


def make_default_build_commands(unit: Mapping[str, Any]) -> tuple[Mapping[str, Any], str] | None:
    """Resolve the default goal's literal rule closure without executing Make or includes."""
    root = PurePosixPath(str(unit.get("root", ".")))
    markers = {str(marker["path"]): marker for marker in unit.get("markers", ())
               if PurePosixPath(str(marker["path"])).parent == root}
    documents = {str(document.get("path")): document
                 for document in unit.get("descriptor_package", {}).get("documents", ())}
    for name in ("GNUmakefile", "makefile", "Makefile"):
        path = (root / name).as_posix()
        if path not in markers or path not in documents:
            continue
        text = documents[path].get("content")
        if not isinstance(text, str):
            continue
        rules: dict[str, tuple[list[str], list[str]]] = {}
        current: list[str] = []
        default = None
        for line in text.replace("\\\n", " ").splitlines():
            if line.startswith("\t"):
                for target in current:
                    rules[target][1].append(line.strip())
                continue
            declared_default = re.fullmatch(r"\.DEFAULT_GOAL\s*:?=\s*([^\s$]+)\s*", line)
            if declared_default:
                default = declared_default.group(1)
            match = re.match(r"^([^#\s:=][^:=]*?)\s*:(?!=)([^;#]*)(?:;(.*))?$", line)
            current = []
            if not match:
                continue
            for target in match.group(1).split():
                if default is None and not target.startswith("."):
                    default = target
                prerequisites, commands = rules.setdefault(target, ([], []))
                prerequisites.extend(match.group(2).split())
                if match.group(3):
                    commands.append(match.group(3))
                current.append(target)
        pending = [default] if default is not None else []
        visited: set[str] = set()
        commands = []
        while pending:
            target = pending.pop()
            if target in visited:
                continue
            visited.add(target)
            prerequisites, target_commands = rules.get(target, ([], []))
            pending.extend(prerequisites)
            commands.extend(target_commands)
        return markers[path], "\n".join(commands)
    return None


def _make_default_capability_gap(unit: Mapping[str, Any]) -> str | None:
    resolved = make_default_build_commands(unit)
    if resolved is not None:
        marker, body = resolved
        authority = f"{marker['path']}@{marker['sha256']}"
        if (re.search(r"\bif\s+not\s+exist\b", body, re.I) and
                re.search(r"\b(?:powershell|msbuild)\b", body, re.I)):
            return (f"unavailable_native_windows_toolchain: {authority}: "
                    "default Make target requires Windows shell/MSBuild authority")
        if re.search(r"(?:^|[;&|])\s*[@+-]*docker\s+build\b", body, re.M):
            return (f"unsupported_native_orchestration: {authority}: "
                    "default Make target builds a Docker image, not a native compiler unit")
    return None


def native_build_capability_gap(unit: Mapping[str, Any]) -> str | None:
    """Separate Visual C++ authority from cross-platform .NET/MSBuild projects."""
    if unit.get("family") == "dotnet":
        markers = {str(item["path"]): item for item in unit.get("markers", ())
                   if PurePosixPath(str(item["path"])).suffix.lower() == ".sln" and
                   PurePosixPath(str(item["path"])).parent == PurePosixPath(str(unit.get("root", ".")))}
        for document in unit.get("descriptor_package", {}).get("documents", ()):
            path = str(document.get("path", ""))
            text = document.get("content")
            if path not in markers or not isinstance(text, str):
                continue
            if re.search(
                    r'^[ \t]*Project\("\{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942\}"\)'
                    r'[ \t]*=[ \t]*"[^"\r\n]*",[ \t]*"[^"\r\n]+\.vcx?proj"[ \t]*,', text, re.I | re.M):
                return (f"unavailable_native_project_toolchain: {path}@{markers[path]['sha256']}: "
                        "accepted solution declares Visual C++ members requiring native MSBuild/VCBuild "
                        "capability not supplied by the Linux .NET profile; Windows platform unproven")
        return None
    if unit.get("family") != "native":
        return None
    if unit.get("build_system") == "autotools" and not any(
            PurePosixPath(str(marker["path"])).name in {"configure.ac", "configure.in"} and
            PurePosixPath(str(marker["path"])).parent == PurePosixPath(str(unit.get("root", ".")))
            for marker in unit.get("markers", ())):
        return ("nonstandalone_autotools_fragment: Makefile.am does not establish an independent "
                "build without its owning configure.ac/configure.in project")
    if unit.get("build_system") == "make":
        return _make_default_capability_gap(unit)
    if unit.get("build_system") not in {"msbuild", "vcbuild"}:
        return None
    markers = {str(item["path"]): item for item in unit.get("markers", ())
               if PurePosixPath(str(item["path"])).suffix.lower() in {".vcxproj", ".vcproj"}}
    if not markers:
        return None
    for document in unit.get("descriptor_package", {}).get("documents", ()):
        path = str(document.get("path", ""))
        if path not in markers or not isinstance(document.get("content"), str):
            continue
        try:
            root = ET.fromstring(document["content"])
        except ET.ParseError as error:
            return f"unavailable_native_project_toolchain: {path}: descriptor XML cannot be resolved ({error})"
        evidence = []
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            value = (element.text or "").strip()
            if tag == "Platform" and (element.attrib.get("Name") or value).lower() == "win32":
                evidence.append("Win32 platform")
            elif tag == "PlatformToolset" and re.fullmatch(r"v[0-9]+(?:_xp)?", value):
                evidence.append(f"MSVC toolset {value}")
            elif tag == "Tool" and element.attrib.get("Name") in {"VCCLCompilerTool", "VCLinkerTool"}:
                evidence.append(element.attrib["Name"])
            elif tag == "WindowsTargetPlatformVersion" and value:
                evidence.append("Windows SDK")
        if evidence:
            return (f"unavailable_native_windows_toolchain: {path}@{markers[path].get('sha256')}: "
                    f"{', '.join(sorted(set(evidence)))} requires MSVC/Windows capability, "
                    "not a Linux native placeholder or toolchain probe")
    return ("unavailable_native_project_toolchain: accepted Visual C++ descriptor requires "
            "MSBuild/VCBuild capability not supplied by the Linux native profile; Windows platform unproven")


def normalize_build_recipe(recipe: Mapping[str, Any], unit: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Apply narrow descriptor-backed corrections before accepting inferred build argv."""
    value = dict(recipe)
    if (value.get("image_profile") == "native" and isinstance(unit, Mapping) and
            unit.get("build_system") == "autotools" and native_build_capability_gap(unit) is None):
        commands = value.get("build_commands")
        configure = value.get("configure_commands")
        if isinstance(commands, list) and isinstance(configure, list):
            bootstrap = []
            for command in commands:
                if not isinstance(command, list) or not command or command[0] not in _NATIVE_BOOTSTRAP_COMMANDS:
                    break
                bootstrap.append(command)
            if bootstrap and any(not _native_non_build_command(command) for command in commands[len(bootstrap):]):
                value["configure_commands"] = [*bootstrap, *configure]
                value["build_commands"] = commands[len(bootstrap):]
    if value.get("image_profile") == "node" and isinstance(unit, Mapping):
        dependencies = list(value.get("dependency_files", ()))
        root = PurePosixPath(str(unit.get("root", ".")))
        package = unit.get("descriptor_package", {})
        workspace = package.get("workspace") if isinstance(package, Mapping) else None
        if isinstance(workspace, Mapping):
            # A workspace installs as one tree at its root: the root manifest and lockfile and
            # every member manifest, whichever unit (root or member) the recipe builds.
            lockfile = workspace.get("lockfile")
            if lockfile:
                dependencies = [path for path in dependencies
                                if PurePosixPath(str(path)).name not in NODE_LOCKFILES or path == lockfile]
            for item in package.get("inventory", ()):
                path = str(item.get("path", "")) if isinstance(item, Mapping) else ""
                if path and path not in dependencies:
                    dependencies.append(path)
            if lockfile and value.get("network_required") is False:
                # Members' and root devDependencies (often the compiler itself) are hoisted
                # into the workspace tree only by the locked workspace restore.
                value["network_required"] = True
        has_lock = any(PurePosixPath(str(path)).name in {
            "package-lock.json", "pnpm-lock.yaml", "yarn.lock"} for path in dependencies)
        for item in (*package.get("documents", ()), *package.get("inventory", ())):
            path = PurePosixPath(str(item.get("path", "")))
            is_lock = path.name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
            if (path.parent != root and
                    (path.parent == PurePosixPath(".") or path.parent in root.parents) and
                    _is_node_ancestor_context(path) and not (is_lock and has_lock) and
                    path.as_posix() not in dependencies):
                dependencies.append(path.as_posix())
                has_lock = has_lock or is_lock
        value["dependency_files"] = dependencies
        if value.get("network_required") is False and node_manifest_declares_dependencies(unit):
            # Declared packages (including devDependencies such as typescript and @types/*) are
            # build inputs. Without a restore the build resolves whatever the image happens to
            # carry, so a lockless manifest still needs the networked, script-disabled restore.
            value["network_required"] = True
    if value.get("image_profile") == "java" and isinstance(value.get("environment"), Mapping):
        # The pinned build image owns the JDK location. Model-inferred JAVA_HOME values are
        # target-host assumptions and can name a JDK that is absent from the image.
        environment = dict(value["environment"])
        environment.pop("JAVA_HOME", None)
        value["environment"] = environment
    if value.get("image_profile") == "dotnet":
        for field in ("configure_commands", "build_commands"):
            commands = value.get(field)
            if isinstance(commands, list):
                # Restore-generated obj/project.assets.json lives beside the target source and is
                # intentionally not retained in the descriptor-only dependency image. Let the
                # workspace build regenerate it, reusing the image-owned NuGet package cache.
                value[field] = [
                    [argument for argument in command if argument != "--no-restore"]
                    if isinstance(command, list) else command
                    for command in commands
                ]
    dependencies = value.get("dependency_files")
    names = ({PurePosixPath(item).name for item in dependencies if isinstance(item, str)}
             if isinstance(dependencies, list) else set())
    if value.get("image_profile") == "node" and "package-lock.json" not in names:
        for field in ("configure_commands", "build_commands"):
            commands = value.get(field)
            if not isinstance(commands, list):
                continue
            normalized = []
            for raw in commands:
                argv = list(raw) if isinstance(raw, list) else raw
                if isinstance(argv, list) and argv[:2] == ["npm", "ci"]:
                    # The derived project image performs the lockless, script-disabled restore.
                    # Do not repeat an installer against the writable target workspace.
                    continue
                normalized.append(argv)
            value[field] = normalized
    if value.get("image_profile") == "node" and isinstance(unit, Mapping):
        commands = value.get("build_commands")
        if (isinstance(commands, list) and
                all(_node_restore_only(argv) or _node_optional_command(argv) for argv in commands)):
            authority = _node_build_authority(unit)
            if authority is not None:
                command, path = authority
                value["build_commands"] = [command]
                if path not in value["dependency_files"]:
                    value["dependency_files"].append(path)
                value["reason"] = f"Accepted {path} declares the mandatory build-only command; installation or optional scripts are not build authority"
    return value


GO_SUBCOMMANDS = frozenset({"build", "generate", "mod"})
GO_MOD_SUBCOMMANDS = frozenset({"download", "verify", "vendor"})
# These options replace the toolchain, the working directory, or the source tree the accepted
# recipe names, so observed tool identities would no longer describe the accepted build.
_GO_FORBIDDEN_OPTIONS = ("-toolexec", "-exec", "-overlay", "-C", "-modfile")


def _go_option_errors(values: Sequence[str]) -> list[str]:
    return [f"go option is forbidden: {option}" for option in _GO_FORBIDDEN_OPTIONS
            if any(value == option or value.startswith(option + "=") or
                   value == "-" + option or value.startswith("-" + option + "=") for value in values)]


def go_recipe_errors(recipe: Mapping[str, Any]) -> tuple[str, ...]:
    """The Go build-only command contract: bounded subcommands, no toolchain or tree substitution."""
    errors: list[str] = []
    builds = 0
    for argv in [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]:
        if not isinstance(argv, list) or len(argv) < 2 or argv[0] != "go":
            errors.append("Go recipes may execute go commands only")
            continue
        values = [str(value) for value in argv[1:]]
        subcommand = values[0]
        if subcommand not in GO_SUBCOMMANDS:
            errors.append(f"go subcommand is unsupported: {subcommand}")
            continue
        if subcommand == "mod" and (len(values) < 2 or values[1] not in GO_MOD_SUBCOMMANDS):
            errors.append("go mod subcommand is unsupported: " + (values[1] if len(values) > 1 else "<missing>"))
        builds += subcommand == "build"
        errors.extend(_go_option_errors(values[1:]))
        for index, value in enumerate(values):
            output = (values[index + 1] if value == "-o" and index + 1 < len(values) else
                      value[3:] if value.startswith("-o=") else None)
            if output is not None and (output.startswith("/") or ".." in PurePosixPath(output).parts):
                errors.append("go build output must stay inside the accepted build unit")
    if builds < 1:
        errors.append("Go recipe must contain a go build command")
    environment = recipe.get("environment")
    flags = str(environment.get("GOFLAGS", "")).split() if isinstance(environment, Mapping) else []
    errors.extend(_go_option_errors(flags))
    return tuple(dict.fromkeys(errors))


def validate_build_recipe(recipe: Mapping[str, Any], unit: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {"schema", "build_unit_id", "image_profile", "source_dir", "build_dir",
                "system_packages", "environment", "dependency_files", "configure_commands",
                "build_commands", "expected_outputs", "network_required", "reason"}
    # Optional execution paths never replace the immutable source origin.
    if (set(recipe) - {"image_repairs", "execution_cwd"} != required or
            recipe.get("schema") != BUILD_RECIPE_SCHEMA):
        return ["recipe fields or schema are unsupported"]
    if "image_repairs" in recipe:
        from appsec_review.jobs.job_project_build.repair import image_repair_errors

        errors.extend(image_repair_errors(recipe, str(unit.get("build_system", ""))))
    if recipe.get("build_unit_id") != unit.get("build_unit_id"):
        errors.append("recipe build_unit_id does not match the accepted unit")
    capability_gap = native_build_capability_gap(unit)
    if capability_gap is not None:
        errors.append(capability_gap)
    profile = recipe.get("image_profile")
    required_profile = required_image_profile(unit)
    if profile not in _PROFILE_COMMANDS or profile != required_profile:
        errors.append(f"recipe image_profile must equal required profile {required_profile}")
    root = str(unit.get("root", ""))
    for field in ("source_dir", "build_dir"):
        if not _relative(recipe.get(field)):
            errors.append(f"{field} must be a normalized relative path")
        elif not _within(str(recipe[field]), root):
            errors.append(f"{field} must stay within the accepted build-unit root")
    if recipe.get("source_dir") != root:
        errors.append("source_dir must equal the accepted build-unit root")
    errors.extend(_execution_cwd_errors(recipe, root))
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
    accepted_paths = marker_paths | set(descriptor_inventory_paths(unit))
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
        commands = [*recipe.get("configure_commands", ()), *recipe.get("build_commands", ())]
        if any(isinstance(argv, list) and len(argv) >= 2 and argv[:2] == ["npm", "ci"]
               for argv in commands) and "package-lock.json" not in locks:
            errors.append("Node recipes may use npm ci only when package-lock.json is accepted")
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
            if (profile == "php" and unit.get("build_system") == "phpize" and
                    argv[0] == "./configure"):
                # phpize generates this configure script from the accepted config.m4; it is the
                # extension's build driver, the same role CMake's generated files play.
                executable = "./configure"
            elif executable not in allowed or argv[0] != executable:
                errors.append(f"{field}[{index}] executable is not allowlisted for {profile}")
                continue
            if any("\n" in arg or "\r" in arg or arg in {";", "&&", "||", "|"} for arg in argv):
                errors.append(f"{field}[{index}] contains shell syntax")
            words = {arg.lower() for arg in argv[1:] if not arg.startswith("-")}
            if words & _FORBIDDEN_SUBCOMMANDS.get(executable, set()):
                errors.append(f"{field}[{index}] requests execution, tests, or tool installation")
            lowered = [str(arg).lower() for arg in argv[1:]]
            if executable in {"mvn", "mvnw", "gradle", "gradlew"}:
                errors.extend(f"{field}[{index}] {error}"
                              for error in jvm_build_command_errors(str(profile), argv))
            if profile == "node" and executable == "node" and "--check" not in argv[1:]:
                errors.append(f"{field}[{index}] may execute a target application")
            if profile == "node" and _node_optional_command(argv):
                errors.append(f"{field}[{index}] requests an optional script with --if-present, not a mandatory build")
            if profile == "node" and executable == "npx" and "grunt" in argv[1:]:
                if not any(argv == command for command, _path in _node_grunt_commands(unit)):
                    errors.append(f"{field}[{index}] requires an accepted literal build-only Grunt task with --no-install")
            if profile == "node" and executable == "npx" and "gulp" in argv[1:]:
                scripts = _node_manifest(unit).get("scripts", {})
                if (not isinstance(scripts, Mapping) or scripts.get("build") != "gulp build" or
                        argv != ["npx", "--no-install", "gulp", "build"]):
                    errors.append(f"{field}[{index}] requires the accepted build-only Gulp script with --no-install")
    if isinstance(recipe.get("build_commands"), list) and not recipe["build_commands"]:
        errors.append("build_commands must contain at least one build command")
    elif (profile == "node" and isinstance(recipe.get("build_commands"), list) and
          all(_node_restore_only(argv) for argv in recipe["build_commands"])):
        errors.append("Node build_commands contain dependency installation only, not a build")
    if (profile == "native" and isinstance(recipe.get("build_commands"), list) and
            recipe["build_commands"] and all(_native_non_build_command(argv) for argv in recipe["build_commands"])):
        errors.append("Native build_commands contain no compilation or build step; "
                      "version, dry-run, configuration, and bootstrap-only commands are not builds")
    outputs = recipe.get("expected_outputs")
    if (not isinstance(outputs, list) or len(outputs) > 64 or
            any(not isinstance(item, str) or not _relative(item) for item in outputs)):
        errors.append("expected_outputs must be bounded normalized relative paths")
    elif any(not _within(item, root) for item in outputs):
        errors.append("expected_outputs must stay within the accepted build-unit root")
    if type(recipe.get("network_required")) is not bool:
        errors.append("network_required must be boolean")
    if profile == "dotnet" and recipe.get("network_required") is False:
        documents = unit.get("descriptor_package", {}).get("documents", ())
        remote_references = any(
            isinstance(item, Mapping) and isinstance(item.get("content"), str) and
            ("<packagereference" in item["content"].lower() or
             "<packagedownload" in item["content"].lower())
            for item in documents
        )
        if remote_references:
            errors.append(".NET recipes with accepted package references require dependency egress")
    reason = recipe.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 4096:
        errors.append("reason is missing or exceeds the bound")
    if profile == "go":
        errors.extend(go_recipe_errors(recipe))
    return errors
