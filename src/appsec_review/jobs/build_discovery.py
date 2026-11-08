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
    # A Gradle build whose root holds only settings.gradle (modules carry the build files) is still
    # one Gradle build, driven from that root; its modules are never independent units.
    "settings.gradle": ("java", "gradle"),
    "settings.gradle.kts": ("java", "gradle"),
    # An Xcode project: the unit root is the directory holding the .xcodeproj bundle. Family
    # ``swift`` places it under the Swift policy (tools.enable_swift): cataloged, kept out of every
    # executable planning input while disabled, so no Linux image is ever asked to build it.
    "project.pbxproj": ("swift", "xcodebuild"),
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
    marker = _MARKERS.get(path.name) or _SUFFIX_MARKERS.get(path.suffix.lower())
    if marker is not None and path.name == "project.pbxproj" and path.parent.suffix.lower() != ".xcodeproj":
        return None
    return marker


_SLN_PROJECT_LINE = re.compile(r'^Project\("\{[0-9A-Fa-f-]+\}"\)\s*=\s*"[^"]+"\s*,\s*"([^"]+)"', re.M)
_NATIVE_PROJECT_SUFFIXES = frozenset({".vcxproj", ".vcproj"})
_MANAGED_PROJECT_SUFFIXES = frozenset({".csproj", ".vbproj", ".fsproj"})
_PROJECT_SUFFIXES = _NATIVE_PROJECT_SUFFIXES | _MANAGED_PROJECT_SUFFIXES


def solution_projects(sln_path: str, text: str, inventory: Sequence[str] | None = None) -> list[str]:
    """Target-relative paths of the projects a ``.sln`` lists (those in the inventory, when given)."""
    import posixpath
    base = posixpath.dirname(sln_path) or "."
    found = []
    for match in _SLN_PROJECT_LINE.finditer(text):
        relative = match.group(1).replace("\\", "/")
        joined = posixpath.normpath(posixpath.join(base, relative)) if base != "." else posixpath.normpath(relative)
        if joined.startswith("../") or joined == ".." or PurePosixPath(joined).suffix.lower() not in _PROJECT_SUFFIXES:
            continue
        if inventory is None or joined in inventory:
            found.append(joined)
    return found


def solution_marker(sln_path: str, text: str | None, inventory: Sequence[str]) -> tuple[str, str]:
    """The family and system of a solution, from the projects it lists (plan §2.1 decision 3).

    All native projects (``.vcxproj``/``.vcproj``) → ``(native, msbuild)``; all managed
    (``.csproj``/``.vbproj``/``.fsproj``) → ``(dotnet, dotnet)``; mixed → ``(native, msbuild)`` (the unit's
    ``languages`` fact names both). Unreadable or project-less solutions keep the ``.NET`` default.
    """
    if text is None:
        return _SUFFIX_MARKERS[".sln"]
    suffixes = {PurePosixPath(path).suffix.lower() for path in solution_projects(sln_path, text)}
    if suffixes and suffixes <= _MANAGED_PROJECT_SUFFIXES:
        return ("dotnet", "dotnet")
    if suffixes & _NATIVE_PROJECT_SUFFIXES:
        return ("native", "msbuild")
    return _SUFFIX_MARKERS[".sln"]


def _marker_root(path: PurePosixPath) -> str:
    """The build unit root a marker file belongs to (its directory, or the bundle's parent)."""
    if path.name == "project.pbxproj" and path.parent.suffix.lower() == ".xcodeproj":
        return path.parent.parent.as_posix()
    return path.parent.as_posix()


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


_ORPHAN_LANGUAGE = {".c": "c", ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".m": "objective-c", ".mm": "objective-c++",
                    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".rs": "rust", ".go": "go", ".wat": "wat",
                    ".cs": "c#", ".swift": "swift", ".cu": "cuda"}
# Compiled-language suffixes discovery decides orphan-hood for, with the build family that compiles them.
_ORPHAN_FAMILY = {**{suffix: family for suffix, (family, _system) in _SOURCE_MARKERS.items()},
                  ".m": "native", ".mm": "native", ".cu": "native", ".cs": "dotnet", ".swift": "swift"}


# Build systems whose descriptors are read for build points; a unit of these with no build point,
# nothing driven and nothing unresolved is not a unit (an include-only CMakeLists.txt, a Makefile of
# variables). Manifest-driven systems (cargo, npm, go, ...) are units by their manifest.
# Build systems whose descriptors are read for build points; a unit of these with no build point,
# nothing driven and nothing unresolved is not a unit (an include-only CMakeLists.txt, a Makefile of
# variables). Manifest-driven systems (cargo, npm, go, ...) are units by their manifest.
_DEMOTABLE_SYSTEMS = frozenset({"cmake", "make", "meson", "autotools"})


# Build outputs under a unit root: never sources, never roots (§2.1 item 4). Installed dependency
# trees (node_modules, vendor, Pods) are context or excluded by policy, not outputs, and are not here.
_GENERATED_DIRS = frozenset({"obj", "CMakeFiles", "DerivedData", ".gradle"})


def _under_generated_dir(path: str) -> bool:
    parts = PurePosixPath(path).parts[:-1]
    if any(part in _GENERATED_DIRS for part in parts):
        return True
    # MSBuild output layout bin/<Configuration>/...; a plain bin/ (src/bin/cli.rs) is source.
    return any(part == "bin" and index + 1 < len(parts) and parts[index + 1] in {"Debug", "Release", "x64", "Win32", "ARM64"}
               for index, part in enumerate(parts))


# Plan §2.1 decision 4: generated and installed trees are never units. ``node_modules/``, a Cargo/Go/
# Composer ``vendor/``, CocoaPods ``Pods/`` are installed dependencies (context of the unit that
# installs them); Gradle ``buildSrc/`` is build logic (context of the Gradle root); Go ``testdata/`` is
# fixture data (inert). Detection is literal: the tree's parent holds the manager's manifest, or the
# tree holds the manager's own signature file.
_INSTALLED_TREE_SIGNATURES = {
    "node_modules": ("node", ("package.json",), (".package-lock.json",)),
    "vendor": ("vendor", ("Cargo.toml", "go.mod", "go.work", "composer.json"), ("modules.txt", "autoload.php")),
    "Pods": ("cocoapods", ("Podfile",), ("Manifest.lock", "Pods.xcodeproj/project.pbxproj")),
}


def installed_trees(inventory_paths: Sequence[str]) -> list[dict[str, Any]]:
    """Installed, build-logic and fixture trees in an inventory: ``[{path, kind, manager}]``, sorted."""
    paths = set(inventory_paths)
    found: dict[str, dict[str, Any]] = {}

    def present(directory: str, name: str) -> bool:
        return ((directory + "/" + name) if directory != "." else name) in paths

    def any_beneath(directory: str, name: str) -> bool:
        prefix = "" if directory == "." else directory + "/"
        return any(path.startswith(prefix) and (path.endswith("/" + name) or path[len(prefix):] == name) for path in paths)

    def go_module_above(directory: str) -> bool:
        current = PurePosixPath(directory)
        for ancestor in (current, *current.parents):
            if present(ancestor.as_posix(), "go.mod") or present(ancestor.as_posix(), "go.work"):
                return True
        return False

    for path in inventory_paths:
        parts = PurePosixPath(path).parts[:-1]
        for index, part in enumerate(parts):
            tree = "/".join(parts[: index + 1])
            if tree in found:
                break
            parent = "/".join(parts[:index]) or "."
            if part in _INSTALLED_TREE_SIGNATURES:
                manager, manifests, signatures = _INSTALLED_TREE_SIGNATURES[part]
                if any(present(parent, m) for m in manifests) or any(any_beneath(tree, sig) or present(tree, sig) for sig in signatures) \
                        or (part == "vendor" and any_beneath(tree, ".cargo-checksum.json")):
                    if manager == "vendor":
                        manager = ("cargo" if present(parent, "Cargo.toml") or any_beneath(tree, ".cargo-checksum.json") else
                                   "go" if present(parent, "go.mod") or present(parent, "go.work") or present(tree, "modules.txt") else "composer")
                    found[tree] = {"path": tree, "kind": "installed", "manager": manager}
                    break
            if part == "buildSrc" and any(present(parent, m) for m in ("settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts")):
                found[tree] = {"path": tree, "kind": "build_logic", "manager": "gradle"}
                break
            if part == "testdata" and go_module_above(parent):
                found[tree] = {"path": tree, "kind": "fixture", "manager": "go"}
                break
    return [found[key] for key in sorted(found)]


def _under_installed_tree(path: str, trees: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    return next((tree for tree in trees if _is_under(path, str(tree["path"])) and path != tree["path"]), None)



def _under_build_tree(path: str, build_trees: Sequence[str]) -> bool:
    return any(_is_under(path, tree) and path != tree for tree in build_trees)


def _family_of_system(system: str) -> str:
    return next((family for family, candidate in (*_MARKERS.values(), *_SUFFIX_MARKERS.values()) if candidate == system), "native")


# Descriptor files read per unit beyond its markers and its folded members' descriptors; the markers
# of a solution's listed projects, a workspace's members and a CMake tree's subdirectories are read
# through the fold, bounded by _MEMBER_LIMIT.
_DESCRIPTOR_READ_LIMIT = 48
_MEMBER_LIMIT = 256
_DESCRIPTOR_SUFFIXES = frozenset({".cmake", ".mk", ".am", ".ac", ".sln", ".vcxproj", ".csproj", ".vbproj", ".fsproj"})


def unit_label(unit: Mapping[str, Any]) -> str:
    """``<root>|<build system>``: how facts, the assignment and the cases name a unit."""
    return f"{unit['root']}|{unit['build_system']}"


def _is_under(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(root + "/")


def _descriptor_candidates(unit: Mapping[str, Any], inventory_paths: Sequence[str], other_markers: set[str],
                           nested_roots: Sequence[str], build_trees: Sequence[str] = (),
                           trees: Sequence[Mapping[str, Any]] = ()) -> list[str]:
    """Paths under the unit's root (not under a nested unit, not another unit's marker, not generated
    output, not an installed tree) that describe its build."""
    root = str(unit["root"])
    candidates = []
    for path in inventory_paths:
        if (not _is_under(path, root) or path in other_markers or _under_build_tree(path, build_trees)
                or _under_generated_dir(path) or _under_installed_tree(path, trees) is not None):
            continue
        parent = PurePosixPath(path).parent.as_posix()
        if any(other != root and _is_under(parent, other) for other in nested_roots):
            continue  # a nested unit's descriptors belong to it
        posix = PurePosixPath(path)
        if (is_build_descriptor(posix) or _is_context_name(posix.name) or posix.suffix.lower() in _DESCRIPTOR_SUFFIXES
                or posix.name == "pnpm-workspace.yaml"
                or (unit["build_system"] == "go" and posix.suffix == ".go")):
            candidates.append(path)
    return candidates


def _attach_build_points(units: list[dict[str, Any]], inventory_paths: Sequence[str],
                         read_text: Callable[[str], str | None] | None,
                         build_trees: Sequence[str] = (), trees: Sequence[Mapping[str, Any]] = ()) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read each unit's descriptors for build points; fold driven members; return (demoted, folded).

    Plan §2.1 decision 1: a root that drives members is the unit and the members are its build points.
    A unit's ``drives`` whose ``via`` is a folding construct (``add_subdirectory``, ``$(MAKE) -C``,
    ``subdir``, ``SUBDIRS``, a solution's project, a Gradle ``include``, a workspace member, a Maven
    module) and whose path is the root of a unit the driver's build system reads folds that unit into
    the driver: its markers become the driver's ``descriptors``, its points the driver's points. The
    fold is literal (only a named directory folds) and transitive (a folded member's own drives are
    read). A drive to a unit of another build system (``invokes:cmake`` from a Makefile, Gradle's
    ``externalNativeBuild``) leaves that unit standing and is recorded on it as ``driven_by``.
    """
    from appsec_review.jobs.build_points import EXTRACTORS, FOLDABLE_SYSTEMS, FOLDING_VIAS, extract_build_points

    demoted: list[dict[str, Any]] = []
    folded: list[dict[str, Any]] = []
    folded_ids: set[str] = set()
    by_root: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in units:
        by_root[str(unit["root"])].append(unit)
    marker_paths = {str(m["path"]) for unit in units for m in unit.get("markers", ())}
    texts: dict[str, str | None] = {}

    def text_of(path: str) -> str | None:
        if path not in texts:
            texts[path] = read_text(path) if read_text is not None else None
        return texts[path]

    # Shallow roots first: a parent folds its members before a member would read its own descriptors.
    for unit in sorted(units, key=lambda u: (len(PurePosixPath(str(u["root"])).parts), str(u["root"]), str(u["build_system"]))):
        if unit["build_unit_id"] in folded_ids:
            continue
        if unit["build_system"] not in EXTRACTORS or read_text is None:
            unit["source_resolution"] = "containment"
            continue
        root = str(unit["root"])
        own_markers = [str(m["path"]) for m in unit.get("markers", ())]
        members: list[dict[str, Any]] = []  # units folded into this one, in fold order
        member_descriptors: list[str] = []
        while True:
            nested_roots = [str(other["root"]) for other in units
                            if other is not unit and other["build_unit_id"] not in folded_ids and other not in members]
            other_markers = marker_paths - set(own_markers) - set(member_descriptors)
            candidates = _descriptor_candidates(unit, inventory_paths, other_markers, nested_roots, build_trees, trees)
            if unit["build_system"] in {"msbuild", "dotnet", "vcbuild"}:
                # A solution's listed projects are its descriptors wherever they sit (a sibling directory,
                # two directories up); a project file nothing lists stays another unit's marker.
                for marker in own_markers:
                    if marker.lower().endswith(".sln"):
                        candidates.extend(solution_projects(marker, text_of(marker) or "", inventory_paths))
                candidates = [c for c in candidates if not (c.lower().endswith(tuple(_PROJECT_SUFFIXES)) and c in other_markers)]
            extras = sorted(set(candidates) - set(own_markers) - set(member_descriptors))[:_DESCRIPTOR_READ_LIMIT]
            descriptors: dict[str, str] = {}
            for path in [*own_markers, *member_descriptors, *extras]:
                text = text_of(path)
                if text is not None:
                    descriptors[path] = text
            extracted = extract_build_points(unit, descriptors, inventory_paths)
            new_member = None
            for drive in extracted["drives"]:
                if drive.get("via") not in FOLDING_VIAS or drive.get("unresolved"):
                    continue
                for candidate in by_root.get(str(drive["path"]), ()):
                    if candidate is unit or candidate in members or candidate["build_unit_id"] in folded_ids:
                        continue
                    if candidate["build_system"] not in FOLDABLE_SYSTEMS.get(str(unit["build_system"]), frozenset()):
                        continue
                    if drive.get("project") and drive["project"] not in {str(m["path"]) for m in candidate.get("markers", ())}:
                        continue  # a solution folds the project it lists, not another project in that directory
                    if len(members) >= _MEMBER_LIMIT:
                        extracted["unresolved"].append({"evidence": drive["evidence"], "reason": "member bound reached"})
                        continue
                    new_member = (candidate, drive)
                    break
                if new_member is not None:
                    break
            if new_member is None:
                break
            candidate, drive = new_member
            members.append(candidate)
            folded_ids.add(candidate["build_unit_id"])
            member_descriptors.extend(str(m["path"]) for m in candidate.get("markers", ()))
            folded.append({"build_unit_id": candidate["build_unit_id"], "root": str(candidate["root"]),
                           "build_system": candidate["build_system"],
                           "markers": [str(m["path"]) for m in candidate.get("markers", ())],
                           "folded_into": unit_label(unit), "via": drive["via"], "evidence": drive["evidence"]})
        unit["build_points"] = extracted["build_points"]
        if unit["build_system"] in {"msbuild", "dotnet", "vcbuild"}:
            languages = {str(p["name"]): [p["language"]] for p in extracted["build_points"] if p.get("language")}
            if languages:
                unit["languages"] = languages  # a mixed solution names every project's language (§2.1 decision 3)
        if member_descriptors:
            unit["descriptors"] = sorted(dict.fromkeys(member_descriptors))
        if extracted["drives"]:
            unit["drives"] = extracted["drives"]
        if extracted["includes"]:
            unit["includes"] = extracted["includes"]
        if extracted["unresolved"]:
            unit["unresolved"] = extracted["unresolved"]
        # Complete: every construct of a descriptor-driven native system was read, so the sources its
        # build points name are all it compiles (a delegating-only descriptor names none, completely).
        # A project a solution lists but the target lacks compiles nothing here: it is recorded, but
        # it does not make the solution's resolution containment (§2.1 decision 3).
        dynamic = [u for u in extracted["unresolved"] if u.get("kind") != "missing_project"]
        unit["source_resolution"] = ("complete" if not dynamic
                                     and unit["build_system"] in {"cmake", "make", "meson", "autotools", "msbuild", "dotnet", "vcbuild"}
                                     else "containment")
        if (unit["build_system"] in _DEMOTABLE_SYSTEMS and not extracted["build_points"] and not extracted["drives"]
                and not extracted["unresolved"]):
            demoted.append({"build_unit_id": unit["build_unit_id"], "root": root, "build_system": unit["build_system"],
                            "markers": own_markers,
                            "reason": "no build point, nothing driven: the descriptor declares no build"})
    folded_set = {item["build_unit_id"] for item in folded}
    # A drive to a standing unit of another build system: recorded on the driven unit.
    standing = [unit for unit in units if unit["build_unit_id"] not in folded_set]
    for unit in standing:
        for drive in unit.get("drives", ()):
            if drive.get("unresolved"):
                continue
            for driven in by_root.get(str(drive["path"]), ()):
                if driven is unit or driven["build_unit_id"] in folded_set or "driven_by" in driven:
                    continue
                driven["driven_by"] = {"unit": unit_label(unit), "via": drive["via"], "evidence": drive["evidence"]}
    return demoted, folded


# Plan §2.1 decision 2: when several native build systems share one root, the unit whose build the
# native lane runs for a compilation database is the capture authority, in this order.
CAPTURE_AUTHORITY_ORDER = ("cmake", "meson", "autotools", "make", "msbuild", "dotnet", "vcbuild")
_PARALLEL_SYSTEMS = frozenset(CAPTURE_AUTHORITY_ORDER)
_GENERATED_MAKEFILE = re.compile(r"CMAKE generated file|Generated by \"[^\"]*Makefiles\" Generator|generated by automake|"
                                 r"Makefile\.in generated by automake|generated by configure", re.I)
_WRAPPER_TOOLS = {"cmake": re.compile(r"(?<![\w-])cmake(?![\w-])"), "meson": re.compile(r"(?<![\w-])(?:meson|ninja)(?![\w-])"),
                  "autotools": re.compile(r"(?<![\w-])(?:\./configure|autoreconf|automake)(?![\w-])"),
                  "msbuild": re.compile(r"(?<![\w-])(?:msbuild|dotnet\s+build)(?![\w-])"),
                  "dotnet": re.compile(r"(?<![\w-])(?:msbuild|dotnet\s+build)(?![\w-])"),
                  "vcbuild": re.compile(r"(?<![\w-])(?:vcbuild|msbuild)(?![\w-])")}


def _resolve_parallel_systems(units: list[dict[str, Any]], folded: Sequence[Mapping[str, Any]],
                              read_text: Callable[[str], str | None] | None) -> list[dict[str, Any]]:
    """Decide the Makefiles beside another native system and record ``parallel_with``/``capture_authority``.

    Returns the units demoted here (generated Makefiles → inert; wrapper Makefiles → context of the
    authority), each with ``role`` so the assignment can name it. A root whose CMake descriptor was
    folded into a parent still has that parent as its authority.
    """
    demoted: list[dict[str, Any]] = []
    # The standing unit that owns a root's descriptor of each system: the unit at that root, or the
    # unit a folded root's markers were folded into.
    owner_by_root_system: dict[tuple[str, str], dict[str, Any]] = {}
    by_label = {unit_label(unit): unit for unit in units}
    for unit in units:
        owner_by_root_system[(str(unit["root"]), str(unit["build_system"]))] = unit
    for item in folded:
        owner = by_label.get(str(item["folded_into"]))
        if owner is not None and (str(item["root"]), str(item["build_system"])) not in owner_by_root_system:
            owner_by_root_system[(str(item["root"]), str(item["build_system"]))] = owner
    roots: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for unit in units:
        if unit["build_system"] in _PARALLEL_SYSTEMS:
            roots[str(unit["root"])].append(unit)
    for root in sorted(roots):
        others_here = [(system, owner) for (r, system), owner in owner_by_root_system.items()
                       if r == root and system in _PARALLEL_SYSTEMS and system != "make"]
        for unit in [u for u in roots[root] if u["build_system"] == "make"]:
            if not others_here:
                continue
            texts = [read_text(str(m["path"])) or "" for m in unit.get("markers", ())] if read_text is not None else []
            authority_system = min((system for system, _owner in others_here), key=CAPTURE_AUTHORITY_ORDER.index)
            authority = next(owner for system, owner in others_here if system == authority_system)
            if any(_GENERATED_MAKEFILE.search(text[:2048]) for text in texts):
                demoted.append({"build_unit_id": unit["build_unit_id"], "root": root, "build_system": "make",
                                "markers": [str(m["path"]) for m in unit.get("markers", ())], "role": "inert",
                                "reason": f"generator output of the {authority_system} build at this root"})
                roots[root].remove(unit)
                continue
            compiles = any(point.get("sources") for point in unit.get("build_points", ()))
            invokes = any(_WRAPPER_TOOLS.get(authority_system, _WRAPPER_TOOLS["cmake"]).search(text) for text in texts)
            if not compiles and invokes:
                demoted.append({"build_unit_id": unit["build_unit_id"], "root": root, "build_system": "make",
                                "markers": [str(m["path"]) for m in unit.get("markers", ())],
                                "role": "context", "unit": unit_label(authority),
                                "reason": f"a wrapper whose rules only invoke the {authority_system} build at this root"})
                roots[root].remove(unit)
    demoted_ids = {item["build_unit_id"] for item in demoted}
    # A checked-in solution CMake generated (ALL_BUILD/ZERO_CHECK projects, a CustomBuild step on
    # CMakeLists.txt) is a parallel unit that states its generator; CMake stays the authority.
    for unit in units:
        if unit["build_system"] not in {"msbuild", "dotnet", "vcbuild"} or read_text is None:
            continue
        paths = [str(m["path"]) for m in unit.get("markers", ())] + [
            str(p["descriptor"]) for p in unit.get("build_points", ()) if p.get("descriptor")]
        texts = [read_text(path) or "" for path in paths]
        if any(re.search(r'"(?:ALL_BUILD|ZERO_CHECK)"|<CustomBuild Include="CMakeLists\.txt"', text) for text in texts):
            unit["generated_by"] = "cmake"
    for root, here in roots.items():
        systems = {str(u["build_system"]): u for u in here}
        for (r, system), owner in owner_by_root_system.items():
            if (r == root and system in _PARALLEL_SYSTEMS and system not in systems and owner not in here
                    and owner["build_unit_id"] not in demoted_ids):
                systems[system] = owner  # a folded descriptor at this root: its owner is the parallel
        if len(systems) < 2:
            continue
        authority_system = min(systems, key=CAPTURE_AUTHORITY_ORDER.index)
        for system, unit in systems.items():
            if unit not in here:
                continue  # the folding owner stands elsewhere; its own root decides its facts
            unit["parallel_with"] = sorted(unit_label(other) for s, other in systems.items() if other is not unit)
            unit["capture_authority"] = "primary" if system == authority_system else "secondary"
    return demoted



def discover_build_units(files: Sequence[Mapping[str, Any]], *,
                         read_text: Callable[[str], str | None] | None = None,
                         engine_discovery: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """The build units of an inventory; :func:`discover_build_inventory` also returns the orphans."""
    return discover_build_inventory(files, read_text=read_text, engine_discovery=engine_discovery)["units"]


def discover_build_inventory(files: Sequence[Mapping[str, Any]], *,
                             read_text: Callable[[str], str | None] | None = None,
                             engine_discovery: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Group accepted build descriptors into stable, repository-independent build units, fold the
    members a unit drives into it, and name the compiled-language sources no build point claims.

    Returns ``{"units", "orphaned_sources", "demoted_markers", "folded_roots"}``. ``read_text`` returns
    the bounded text of a cataloged file; without it no descriptor is read, so every unit is a marker
    root with containment resolution and nothing folds.
    """
    from appsec_review.jobs.engine_discovery import discover_unity

    engines = (engine_discovery if engine_discovery is not None else
               discover_unity(files, read_text=lambda descriptor, _limit:
                              read_text(str(descriptor["path"])) if read_text is not None else None))
    unity_roots = [PurePosixPath(project["root"]) for project in engines["projects"]]
    def unity_owner(path: PurePosixPath) -> PurePosixPath | None:
        return max((root for root in unity_roots if root.as_posix() == "." or root in path.parents),
                   key=lambda root: len(root.parts), default=None)

    inventory_paths = [str(item["path"]) for item in files]
    # A CMake build tree (CMakeCache.txt) is generated output: nothing under it is a marker (§2.1
    # decisions 3 and 4); the generated solution and projects there are inert.
    build_trees = sorted(PurePosixPath(path).parent.as_posix() for path in inventory_paths
                         if PurePosixPath(path).name == "CMakeCache.txt"
                         and (PurePosixPath(path).parent / "CMakeLists.txt").as_posix() not in inventory_paths)  # in-source builds keep their sources
    # A project a solution lists is the solution's build point, never a marker of its own (decision 1
    # and 3); the solution itself is typed by the projects it lists.
    listed_projects: set[str] = set()
    solution_types: dict[str, tuple[str, str]] = {}
    for path in inventory_paths:
        if PurePosixPath(path).suffix.lower() == ".sln" and not _under_build_tree(path, build_trees) \
                and _under_installed_tree(path, installed_trees(inventory_paths)) is None:
            text = read_text(path) if read_text is not None else None
            if text is not None:
                listed_projects.update(solution_projects(path, text, inventory_paths))
            solution_types[path] = solution_marker(path, text, inventory_paths)
    trees = installed_trees(inventory_paths)
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for item in files:
        path = PurePosixPath(str(item["path"]))
        marker = _marker(path)
        if (marker is None or str(path) in listed_projects or _under_build_tree(str(path), build_trees)
                or _under_installed_tree(str(path), trees) is not None):
            continue
        owner = unity_owner(path)
        if owner is not None and (
                path.suffix.lower() in {".csproj", ".vbproj", ".fsproj", ".sln", ".vcxproj", ".vcproj"}
                or path.name == "package.json" and "Packages" in path.relative_to(owner).parts[:-1]):
            continue
        family, system = solution_types.get(str(path), marker)
        root = _marker_root(path)
        groups[(root, family, system)].append(item)
    for item in files:
        path = PurePosixPath(str(item["path"]))
        root = path.parent.as_posix()
        if _wasm_build_script(path, read_text) and not any(key[0] == root for key in groups):
            groups[(root, "wasm", WASM_C_BUILD_SYSTEM)].append(item)
    # A Makefile beside a CMake, meson or autotools descriptor is read, not dropped (plan §2.1
    # decision 2): generated output is inert, a wrapper that only invokes the other system is that
    # unit's context, and a Makefile with compile rules of its own is a parallel unit.
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
        if system == "xcodebuild":
            values[-1]["language"] = "swift"
            values[-1]["descriptor_facts"] = {"kind": "xcode-project", "platform": "apple",
                                              "bundles": sorted({PurePosixPath(str(item["path"])).parent.name
                                                                 for item in ordered})}
    for project in engines["projects"]:
        root = str(project["root"])
        values.append({
            "build_unit_id": _id(root, UNITY_LANGUAGE_FAMILY, UNITY_BUILD_SYSTEM),
            "root": root, "family": UNITY_LANGUAGE_FAMILY, "build_system": UNITY_BUILD_SYSTEM,
            "engine": dict(project["engine"]), "markers": list(project["markers"]),
            "descriptor_facts": dict(project["descriptor_facts"]),
            "engine_project": project,
            "provenance": "deterministic-engine-descriptors",
        })
    values.sort(key=lambda value: (str(value["root"]), str(value["family"]), str(value["build_system"])))
    by_path = {str(item["path"]): item for item in files}
    demoted, folded = _attach_build_points(values, inventory_paths, read_text, build_trees, trees)
    removed = {d["build_unit_id"] for d in demoted} | {f["build_unit_id"] for f in folded}
    values = [unit for unit in values if unit["build_unit_id"] not in removed]
    demoted.extend(_resolve_parallel_systems(values, folded, read_text))
    values = [unit for unit in values if unit["build_unit_id"] not in {d["build_unit_id"] for d in demoted}]
    # Orphan decision: a compiled-language source is claimed when a build point names it (source or
    # header through an include directory, or containment in a member directory), or when it sits
    # under a unit of its family whose build points could not be read completely (unresolved
    # constructs, no extractor). Otherwise it is orphaned: a finding (dead code, build drift, an
    # abandoned port, or a build we did not understand), reported with the nearest unit considered and
    # why it did not claim it; never built, never attached to a neighbour (decision 2026-11-08, T-056.3).
    claimed: set[str] = set()
    containment_units: list[dict[str, Any]] = []
    for unit in values:
        for point in unit.get("build_points", ()):
            claimed.update(point.get("sources", ()))
            claimed.update(point.get("headers", ()))
        if unit.get("source_resolution") != "complete":
            containment_units.append(unit)
    candidates: list[tuple[Mapping[str, Any], str, str]] = []
    for path in inventory_paths:
        posix = PurePosixPath(path)
        orphan_family = _ORPHAN_FAMILY.get(posix.suffix.lower())
        if (orphan_family is None or _under_generated_dir(path) or path in claimed or _under_build_tree(path, build_trees)
                or _under_installed_tree(path, trees) is not None):
            continue
        if ".teamcity" in posix.parts:
            # TeamCity Kotlin DSL is CI configuration, not an independently compilable JVM
            # source tree. It is cataloged and analyzed by the CI lanes instead.
            continue
        nearest = max((unit for unit in values if _is_under(path, str(unit["root"]))),
                      key=lambda unit: (len(PurePosixPath(str(unit["root"])).parts), str(unit["root"])), default=None)
        if nearest is None:
            candidates.append((by_path[path], orphan_family, "no_build_point"))
            continue
        same_family = [unit for unit in values if _is_under(path, str(unit["root"])) and unit["family"] == orphan_family]
        if not same_family:
            # Under a unit of another family (a .c under a node package, a .cs under a Gradle root):
            # nothing of its family claims it.
            candidates.append((by_path[path], orphan_family, "no_build_point"))
            continue
        innermost = max(same_family, key=lambda unit: (len(PurePosixPath(str(unit["root"])).parts), str(unit["root"])))
        if innermost in containment_units or innermost["build_system"] == UNITY_BUILD_SYSTEM:
            continue  # containment claims it: the unit's descriptors could not be read completely
        candidates.append((by_path[path], orphan_family, "no_build_point"))
    orphans: list[dict[str, Any]] = []
    for item, family, reason in candidates:
        path = PurePosixPath(str(item["path"]))
        nearest = max((unit for unit in values if _is_under(str(path), str(unit["root"]))),
                      key=lambda unit: (len(PurePosixPath(str(unit["root"])).parts), str(unit["root"])), default=None)
        orphans.append({
            "path": str(path), "sha256": item["sha256"], "size_bytes": item["size_bytes"],
            "family": family, "language": _ORPHAN_LANGUAGE.get(path.suffix.lower(), family), "reason": reason,
            "nearest_unit": None if nearest is None else {
                "root": str(nearest["root"]), "family": nearest["family"], "build_system": nearest["build_system"],
                "why_not": ("different family" if nearest["family"] != family else
                            "no build point of that unit names this source")},
        })
    orphans.sort(key=lambda value: value["path"])
    for tree in trees:
        # Installed dependencies and build logic are context of the nearest standing unit above them
        # (the one that installs or reads them); fixture data is inert.
        parent = PurePosixPath(str(tree["path"])).parent.as_posix()
        nearest = max((unit for unit in values if _is_under(parent, str(unit["root"]))),
                      key=lambda unit: (len(PurePosixPath(str(unit["root"])).parts), str(unit["root"])), default=None)
        if tree["kind"] == "fixture" or nearest is None:
            tree["role"] = "inert"
        else:
            tree["role"], tree["unit"] = "context", unit_label(nearest)
    return {"units": values, "orphaned_sources": orphans, "demoted_markers": demoted, "folded_roots": folded,
            "generated_trees": [{"path": tree, "kind": "cmake_build_tree", "evidence": f"{tree}/CMakeCache.txt" if tree != "." else "CMakeCache.txt"}
                                for tree in build_trees],
            "installed_trees": trees}


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
    # The descriptors of folded members (a solution's projects, a workspace's member manifests, a
    # CMake tree's subdirectory lists) define the unit's build points: the planner reads them too.
    marker_paths |= {str(path) for path in unit.get("descriptors", ())}
    marker_paths |= {str(point["descriptor"]) for point in unit.get("build_points", ())
                     if isinstance(point, Mapping) and point.get("descriptor")}
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
        container_context = (path.name.startswith("Dockerfile")
                             and (path.parent == unit_root or path.parent in unit_root.parents
                                  or path.parent == PurePosixPath(".")))
        if workspace_root is not None and ancestor_context and path.name in NODE_LOCKFILES:
            # A workspace member's lockfile is the workspace root's, never a further ancestor's.
            ancestor_context = path.parent == workspace_root
        if not under and not ancestor_context and not container_context and str(item["path"]) not in marker_paths:
            continue  # a member descriptor outside the root (a solution's sibling project) still belongs
        if (str(item["path"]) in marker_paths or
                _is_context_name(path.name) or
                container_context or ancestor_context or
                (unit.get("build_system") == "unity" and (
                    path.suffix in {".meta", ".asset"} or path.name == "ProjectVersion.txt"))):
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
        if PurePosixPath(str(item["path"])).name.startswith("Dockerfile"):
            from appsec_review.jobs.job_build_environment_analysis.job import redact
            if redact(text) != text:
                gaps.append(f"{item['path']}: sensitive container declarations withheld")
                inventory[str(item["path"])] = _identity(item)
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
    """Keep Android facts in their physical declaring Gradle document, not pooled text."""
    declarations = []
    for document in package.get("documents", ()):
        if PurePosixPath(document["path"]).name not in {"build.gradle", "build.gradle.kts"}:
            continue
        text = document.get("content", "")
        plugin = re.search(
            r"""(?:id\s*\(\s*["']com\.android\.(application|library)["']\s*\)|id\s+["']com\.android\.(application|library)["'])([^\n}]*)""",
            text)
        if not plugin or re.search(r"\bapply\s+false\b", plugin[3]):
            continue
        def observed(pattern):
            match = re.search(pattern, text)
            return match[1] if match else None
        declarations.append({
            "path": document["path"], "sha256": document["sha256"],
            "plugin_id": "com.android." + (plugin[1] or plugin[2]),
            "plugin_version": observed(r"""com\.android\.(?:application|library)["']\s*\)?\s*version\s*["']([^"']+)"""),
            "compile_sdk": observed(r"\bcompileSdk(?:Version)?\s*(?:=\s*)?(\d+)\b"),
            "target_sdk": observed(r"\btargetSdk(?:Version)?\s*(?:=\s*)?(\d+)\b"),
            "build_tools": observed(r"""buildToolsVersion\s*(?:=\s*)?["']([^"']+)"""),
        })
    applications = [item for item in declarations if item["plugin_id"] == "com.android.application"]
    if not applications:
        return None
    fields = {}
    for name in ("plugin_version", "compile_sdk", "target_sdk", "build_tools"):
        values = {item[name] for item in applications}
        fields[name] = next(iter(values)) if len(values) == 1 else None
    return {
        "kind": "android-gradle-application",
        "plugin_id": "com.android.application",
        **fields, "declarations": declarations,
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
    # The unit's Visual C++ descriptors: a standalone project's marker, or the projects a solution
    # lists (its build points' descriptors, plan §2.1 decisions 1 and 3).
    markers = {str(item["path"]): item for item in unit.get("markers", ())
               if PurePosixPath(str(item["path"])).suffix.lower() in {".vcxproj", ".vcproj"}}
    solutions = {str(item["path"]): item for item in unit.get("markers", ())
                 if PurePosixPath(str(item["path"])).suffix.lower() == ".sln"}
    for point in unit.get("build_points", ()):
        descriptor = str(point.get("descriptor") or "")
        if PurePosixPath(descriptor).suffix.lower() in {".vcxproj", ".vcproj"}:
            markers.setdefault(descriptor, {"path": descriptor, "sha256": None})
    if not markers and not solutions:
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
            return (f"unavailable_native_windows_toolchain: {path}@{markers[path].get('sha256') or document.get('sha256')}: "
                    f"{', '.join(sorted(set(evidence)))} requires MSVC/Windows capability, "
                    "not a Linux native placeholder or toolchain probe")
    if solutions and not markers:
        [(path, marker)] = list(solutions.items())[:1]
        return (f"unavailable_native_project_toolchain: {path}@{marker['sha256']}: "
                "accepted solution declares Visual C++ members requiring native MSBuild/VCBuild "
                "capability not supplied by the Linux native profile; Windows platform unproven")
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
