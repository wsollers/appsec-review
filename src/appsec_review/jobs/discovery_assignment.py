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
``source_only_scopes``). Until build points land (T-056.2) a source under a unit's root that the
unit's family compiles is ``evidence_of:<unit>`` without a ``#<build point>`` suffix.
"""
from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping

ROLES = ("evidence_of", "context", "source_only", "orphaned", "inert", "excluded", "unclaimed")

# Sources each build family compiles when they sit under one of its unit roots.
FAMILY_SOURCE_SUFFIXES: dict[str, frozenset[str]] = {
    "native": frozenset({".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl", ".m", ".mm", ".s", ".asm"}),
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
COMPILED_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".java", ".kt", ".kts", ".rs", ".go", ".wat", ".cs", ".swift", ".m", ".mm"})

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
    from appsec_review.jobs.build_discovery import is_build_descriptor

    units = list(discovery.get("units") or discovery.get("build_units") or [])
    orphans = {str(item["path"]): item for item in discovery.get("orphaned_sources") or []}
    by_root: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        by_root.setdefault(str(unit["root"]), []).append(unit)
    marker_owner: dict[str, str] = {}
    component_owner: dict[str, str] = {}
    for unit in units:
        label = _unit_label(unit)
        for marker in unit.get("markers", ()):
            marker_owner.setdefault(str(marker["path"]), label)
        for component in unit.get("native_components", ()):
            component_owner.setdefault(str(component["path"]), label)
    scopes = [(str(scope["root"]), str(scope.get("language") or "source")) for scope in source_only_scopes]
    assignment: dict[str, str] = {}
    for path, policy in sorted((excluded or {}).items()):
        assignment[path] = f"excluded:{policy}"
    for item in files:
        path = str(item["path"])
        if path in assignment:
            continue
        posix = PurePosixPath(path)
        suffix = posix.suffix.lower()
        if path in marker_owner:
            assignment[path] = f"evidence_of:{marker_owner[path]}"
            continue
        if path in component_owner:
            assignment[path] = f"evidence_of:{component_owner[path]}"
            continue
        if path in orphans:
            assignment[path] = f"orphaned:{orphans[path].get('reason', 'no_build_point')}"
            continue
        root = _nearest(posix, by_root)
        if root is not None:
            owners = by_root[root]
            compiled_by = [unit for unit in owners if suffix in FAMILY_SOURCE_SUFFIXES.get(str(unit["family"]), frozenset())]
            if compiled_by:
                assignment[path] = f"evidence_of:{_unit_label(compiled_by[0])}"
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
_CONTEXT_SUFFIXES = frozenset({".props", ".targets", ".filters", ".user", ".cmake", ".mk", ".in", ".am", ".ac", ".m4",
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
