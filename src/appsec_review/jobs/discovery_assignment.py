"""The total assignment of a target's paths to discovery roles.

``docs/plans/build-discovery-test-program-2026-11-08.md`` §2: discovery is correct for a folder when
every path has exactly one role —

- ``evidence_of:<unit>[#<build point>]`` a marker, a descriptor, or a source a build point names;
- ``context:<unit>`` lockfiles, props, settings, presets a unit reads but does not build;
- ``source_only:<language>`` interpreted code with no build step;
- ``orphaned:<reason>`` a compiled-language source no build script, descriptor or compiler line
  names (a finding, never built);
- ``inert`` not code and not build input;
- ``excluded:<policy>`` a configured exclusion;
- ``unclaimed`` a discovery defect.

:func:`assign_paths` derives the assignment from an inventory and a discovery result
(:func:`appsec_review.jobs.build_discovery.discover_build_inventory` plus the catalog's
``source_only_scopes``). A source a build point names is ``evidence_of:<unit>#<point>``; a source
under a unit's root that the unit's family compiles but no point names is ``evidence_of:<unit>`` only
while the unit's resolution is containment (its descriptors could not be read completely).
"""
from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping

ROLES = ("evidence_of", "context", "source_only", "orphaned", "inert", "excluded", "unclaimed")

# Sources each build family compiles when they sit under one of its unit roots.
FAMILY_SOURCE_SUFFIXES: dict[str, frozenset[str]] = {
    "native": frozenset({".c", ".cc", ".cpp", ".cxx", ".cu", ".cuh", ".h", ".hh", ".hpp", ".hxx", ".inl", ".m", ".mm", ".s", ".asm"}),
    "rust": frozenset({".rs"}),
    "go": frozenset({".go"}),
    "java": frozenset({".java", ".kt", ".kts", ".scala", ".groovy"}),
    "node": frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".css", ".scss", ".html", ".vue", ".svelte"}),
    "dotnet": frozenset({".cs", ".vb", ".fs", ".resx", ".xaml"}),
    "python": frozenset({".py", ".pyi", ".pyx"}),
    "php": frozenset({".php"}),
    "wasm": frozenset({".wat", ".wasm", ".c", ".cc", ".cpp"}),
    "swift": frozenset({".swift", ".m", ".mm", ".h", ".storyboard", ".xib", ".plist", ".xcassets", ".entitlements"}),
    "unity": frozenset({".cs", ".asmdef", ".asset", ".prefab", ".unity", ".meta", ".shader", ".cginc", ".hlsl", ".compute"}),
}

# Compiled-language suffixes: a file with one of these and no claiming unit is orphaned.
COMPILED_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".cu", ".java", ".kt", ".kts", ".rs", ".go", ".wat", ".cs", ".swift", ".m", ".mm"})

SOURCE_ONLY_LANGUAGE_SUFFIXES = {
    ".php": "php", ".py": "python", ".rb": "ruby", ".pl": "perl", ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript", ".lua": "lua", ".sql": "sql",
}


def _under(path: PurePosixPath, root: str) -> bool:
    return root == "." or PurePosixPath(root) == path or PurePosixPath(root) in path.parents


def _nearest(path: PurePosixPath, roots: Iterable[str]) -> str | None:
    candidates = [root for root in roots if _under(path, root)]
    return max(candidates, key=lambda root: (len(PurePosixPath(root).parts), root), default=None)


def assign_paths(files: Iterable[Mapping[str, Any]], discovery: Mapping[str, Any], *,
                 source_only_scopes: Iterable[Mapping[str, Any]] = (),
                 excluded: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return ``{path: role}`` for every inventoried path (plus every explicitly excluded one)."""
    from appsec_review.jobs.build_discovery import _under_generated_dir, is_build_descriptor

    units = list(discovery.get("units") or discovery.get("build_units") or [])
    orphans = {str(item["path"]): item for item in discovery.get("orphaned_sources") or []}
    by_root: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        by_root.setdefault(str(unit["root"]), []).append(unit)
    marker_owner: dict[str, str] = {}
    claims: dict[str, list[tuple[int, int, int, str]]] = {}
    included: dict[str, str] = {}
    for unit_index, unit in enumerate(units):
        label = _unit_label(unit)
        root = str(unit["root"])
        for marker in unit.get("markers", ()):
            marker_owner.setdefault(str(marker["path"]), label)
        for point_index, point in enumerate(unit.get("build_points", ())):
            if point.get("descriptor"):
                # A member's own build file (a listed project, an included Gradle project, a workspace
                # member's manifest, a module POM) is evidence of that member point (§2.1 decision 1).
                marker_owner.setdefault(str(point["descriptor"]), f"{label}#{point['name']}")
            for path in (*point.get("sources", ()), *point.get("headers", ())):
                # A path two units' points both name belongs to the unit whose root contains it (the
                # innermost), then to the first point in descriptor order (§2.1 item 7): a header a
                # consumer reaches through -I stays with the library that builds it.
                depth = len(PurePosixPath(root).parts) if _under(PurePosixPath(str(path)), root) else -1
                # Among parallel units at one root the capture authority's point wins (§2.1 decision 2).
                secondary = 1 if unit.get("capture_authority") == "secondary" else 0
                claims.setdefault(str(path), []).append((-depth, secondary, unit_index, point_index, f"{label}#{point['name']}"))
        for path in unit.get("descriptors", ()):
            # A folded member's descriptor that defines no member point of its own (a CMake
            # subdirectory's CMakeLists.txt, a sub-make's Makefile) is evidence of the unit.
            marker_owner.setdefault(str(path), label)
        for path in unit.get("includes", ()):
            included.setdefault(str(path), label)
    component_owner = {path: min(options)[-1] for path, options in claims.items()}
    # A demoted marker is inert (a descriptor that declares no build, generator output) unless the
    # demotion names the unit it is context of (a wrapper Makefile beside the build it invokes).
    demoted: dict[str, str] = {}
    for item in discovery.get("demoted_markers") or []:
        role = f"context:{item['unit']}" if item.get("role") == "context" and item.get("unit") else "inert"
        for path in item.get("markers", ()):
            demoted.setdefault(str(path), role)
    scopes = [(str(scope["root"]), str(scope.get("language") or "source")) for scope in source_only_scopes]
    generated_trees = [str(item["path"]) for item in discovery.get("generated_trees") or []]
    installed = [(str(item["path"]), f"context:{item['unit']}" if item.get("role") == "context" else "inert")
                 for item in discovery.get("installed_trees") or []]
    assignment: dict[str, str] = {}
    for path, policy in sorted((excluded or {}).items()):
        assignment[path] = f"excluded:{policy}"
    for item in files:
        path = str(item["path"])
        if path in assignment:
            continue
        posix = PurePosixPath(path)
        suffix = posix.suffix.lower()
        tree_role = next((role for tree, role in installed if _under(posix, tree) and path != tree), None)
        if tree_role is not None:
            assignment[path] = tree_role  # an installed, build-logic or fixture tree (§2.1 decision 4)
            continue
        if path in demoted:
            assignment[path] = demoted[path]
            continue
        if _under_generated_dir(path) or any(_under(posix, tree) and path != tree for tree in generated_trees):
            assignment[path] = "inert"  # build output (§2.1 decisions 3 and 4)
            continue
        if path in marker_owner:
            assignment[path] = f"evidence_of:{marker_owner[path]}"
            continue
        if path in component_owner:
            assignment[path] = f"evidence_of:{component_owner[path]}"
            continue
        if path in included:
            assignment[path] = f"context:{included[path]}"
            continue
        if path in orphans:
            assignment[path] = f"orphaned:{orphans[path].get('reason', 'no_build_point')}"
            continue
        root = _nearest(posix, by_root)
        if posix.name.lower().startswith("readme") or posix.name.lower() in {"license", "license.md", "license.txt", "changelog.md", "notice"}:
            assignment[path] = "inert"
            continue
        if root is not None:
            owners = by_root[root]
            if posix.name.lower() in _CONTEXT_FILE_NAMES:
                # Lockfiles, wrapper properties, presets: context the unit reads, never a source.
                assignment[path] = f"context:{_unit_label(owners[0])}"
                continue
            compiled_by = [unit for unit in owners if suffix in FAMILY_SOURCE_SUFFIXES.get(str(unit["family"]), frozenset())]
            if compiled_by:
                assignment[path] = f"evidence_of:{_unit_label(compiled_by[0])}"
                continue
            if suffix in _INCLUDED_ONLY_SUFFIXES:
                # A module nothing includes is inert, not context of whatever unit happens to be above it.
                assignment[path] = "inert"
                continue
            if is_build_descriptor(posix) or posix.name.lower() in _CONTEXT_FILE_NAMES or suffix in _CONTEXT_SUFFIXES:
                assignment[path] = f"context:{_unit_label(owners[0])}"
                continue
        scope = _nearest(posix, [root for root, _language in scopes])
        if scope is not None and suffix in SOURCE_ONLY_LANGUAGE_SUFFIXES:
            language = next(language for root, language in scopes if root == scope)
            assignment[path] = f"source_only:{language}"
            continue
        if suffix in COMPILED_SUFFIXES:
            # Discovery should have reported this one; the assignment names the defect.
            assignment[path] = "unclaimed"
            continue
        if suffix in SOURCE_ONLY_LANGUAGE_SUFFIXES:
            assignment[path] = f"source_only:{SOURCE_ONLY_LANGUAGE_SUFFIXES[suffix]}"
            continue
        assignment[path] = "inert"
    return assignment


def _unit_label(unit: Mapping[str, Any]) -> str:
    return f"{unit['root']}|{unit['build_system']}"


_CONTEXT_FILE_NAMES = frozenset({
    "cargo.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "go.sum", "composer.lock", "poetry.lock",
    "gradle.properties", "gradle-wrapper.properties", "gradlew", "gradlew.bat", "global.json", "nuget.config",
    "directory.build.props", "directory.build.targets", "cmakepresets.json", "cmakeuserpresets.json",
    ".npmrc", ".yarnrc", ".yarnrc.yml", "tsconfig.json", "babel.config.js", ".babelrc", "rust-toolchain.toml",
    "rust-toolchain", "requirements.txt", "setup.cfg", "tox.ini", "manifest.json", "packages-lock.json",
})
# Modules that are context only when a descriptor includes them (CMake modules, Make fragments).
_INCLUDED_ONLY_SUFFIXES = frozenset({".cmake", ".mk"})
_CONTEXT_SUFFIXES = frozenset({".props", ".targets", ".filters", ".user", ".in", ".am", ".ac", ".m4",
                               ".lock", ".sln.docstates", ".xcscheme", ".xcworkspacedata", ".pbxproj", ".plist",
                               ".gradle", ".kts", ".toml", ".yaml", ".yml", ".json", ".ninja"})


def summarize(assignment: Mapping[str, str]) -> dict[str, Any]:
    """Role counts and the lists a reviewer acts on (orphaned, unclaimed)."""
    roles = Counter(value.split(":", 1)[0] for value in assignment.values())
    return {
        "roles": dict(sorted(roles.items())),
        "orphaned": sorted(path for path, role in assignment.items() if role.startswith("orphaned:")),
        "unclaimed": sorted(path for path, role in assignment.items() if role == "unclaimed"),
    }
