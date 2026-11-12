from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Iterator, Mapping

from appsec_review.config.exclusions import PathExclusions
from appsec_review.jobs.build_discovery import is_build_descriptor


LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".java": "Java", ".kt": "Kotlin", ".go": "Go", ".rs": "Rust", ".c": "C",
    ".h": "C/C++", ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hh": "C++", ".hpp": "C++", ".hxx": "C++",
    ".cs": "C#", ".rb": "Ruby",
    ".php": "PHP", ".swift": "Swift", ".sh": "Shell", ".ps1": "PowerShell",
}
SOURCE_METRICS_SEMANTICS = "appsec-review/source-counting/1"
FILE_DISCOVERY_SEMANTICS = "appsec-review/file-discovery/1"
PROJECT_FILES = {"pyproject.toml", "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
                 "go.mod", "Cargo.toml", "Gemfile", "composer.json"}
BUILD_FILES = {"Makefile", "makefile", "GNUmakefile", "CMakeLists.txt", "meson.build",
               "BUILD", "WORKSPACE", "Dockerfile"}

# Ecosystem tables used to decide which of several components sharing one root owns a file.
# Every project manifest the catalog recognizes (PROJECT_FILES by name, MANIFEST_SUFFIX_ECOSYSTEMS by
# suffix) names exactly one ecosystem. A Visual Studio solution aggregates projects of any language,
# so it is its own ecosystem that no source file belongs to.
MANIFEST_ECOSYSTEMS: dict[str, str] = {
    "pyproject.toml": "python", "package.json": "node", "pom.xml": "jvm", "build.gradle": "jvm",
    "build.gradle.kts": "jvm", "go.mod": "go", "Cargo.toml": "rust", "Gemfile": "ruby",
    "composer.json": "php",
}
MANIFEST_SUFFIX_ECOSYSTEMS: dict[str, str] = {
    ".csproj": "dotnet", ".vbproj": "dotnet", ".fsproj": "dotnet",
    ".vcxproj": "native", ".vcproj": "native", ".sln": "msbuild-solution",
}
# Source suffixes (the keys of LANGUAGES that belong to a manifest ecosystem) mapped to that ecosystem.
SOURCE_ECOSYSTEMS: dict[str, str] = {
    ".py": "python", ".js": "node", ".ts": "node", ".tsx": "node", ".java": "jvm", ".kt": "jvm",
    ".go": "go", ".rs": "rust", ".c": "native", ".h": "native", ".cc": "native", ".cpp": "native",
    ".cxx": "native", ".hh": "native", ".hpp": "native", ".hxx": "native",
    ".cs": "dotnet", ".rb": "ruby", ".php": "php",
}
PROJECT_FILE_SUFFIXES = frozenset(MANIFEST_SUFFIX_ECOSYSTEMS)


def manifest_ecosystem(manifest: str | None) -> str | None:
    """Return the ecosystem a cataloged project manifest declares, or ``None`` when unrecognized."""
    if not manifest:
        return None
    path = Path(manifest)
    if path.name == "ProjectVersion.txt" and path.parent.name == "ProjectSettings":
        return "dotnet"
    return MANIFEST_ECOSYSTEMS.get(path.name) or MANIFEST_SUFFIX_ECOSYSTEMS.get(path.suffix.lower())


def source_ecosystem(path: str | None) -> str | None:
    """Return the manifest ecosystem a source path belongs to by suffix, or ``None`` when it has none."""
    if not path:
        return None
    return SOURCE_ECOSYSTEMS.get(Path(path).suffix.lower())


@dataclass(frozen=True, slots=True)
class Bounds:
    max_files: int = 10_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_path_length: int = 512


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _walk_files(root: Path, skip_directory: Callable[[Path], bool] | None = None) -> Iterator[Path]:
    """Yield deterministic target paths without retaining a whole-tree filename list."""
    def fail(error: OSError) -> None:
        raise error

    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=fail):
        base = Path(directory)
        kept = []
        for name in sorted(dirnames):
            candidate = base / name
            if skip_directory is not None and skip_directory(candidate):
                continue
            if candidate.is_symlink():
                yield candidate
            elif name not in {".git", ".hg", ".svn"}:
                kept.append(name)
        dirnames[:] = kept
        for name in sorted(filenames):
            yield base / name


def inventory(root: Path, bounds: Bounds = Bounds(), exclusions: PathExclusions | None = None) -> dict[str, Any]:
    """Catalog the target's files. ``exclusions`` (config/exclusions.py) leaves configured paths out;
    each is listed once under ``configured_exclusions`` with its pattern and scope, not as a gap.
    Files excluded as a configured asset class are also totalled by class under ``excluded_assets``."""
    root = root.resolve(strict=True)
    exclusions = exclusions or PathExclusions()
    configured: list[dict[str, str]] = []
    asset_totals: dict[str, dict[str, int]] = {}
    files: list[dict[str, Any]] = []
    artifact_candidates: list[dict[str, Any]] = []
    gaps: list[dict[str, str]] = []
    excluded: set[str] = set()
    content_files = content_bytes = 0
    discovery = {"file_paths_examined": 0,
                 "descriptors_matched": 0, "descriptors_retained": 0,
                 "descriptors_unavailable": 0, "content_files_retained": 0,
                 "content_bytes_retained": 0, "content_files_omitted": 0}
    source_metrics: list[dict[str, Any]] = []
    source_metric_gaps: list[dict[str, str]] = []
    source_metric_bytes = 0
    def skip_directory(path: Path) -> bool:
        relative = path.relative_to(root).as_posix()
        rule = exclusions.match_directory(relative)
        if rule is not None:
            configured.append({"path": relative + "/", **rule.as_dict()})
            return True
        if not path.is_symlink() and path.name in {".git", ".hg", ".svn"}:
            gaps.append({"path": relative, "reason": "excluded_directory"})
            excluded.add(relative)
            return True
        return False

    for path in _walk_files(root, skip_directory):
        relative = path.relative_to(root).as_posix()
        parts = path.relative_to(root).parts
        discovery["file_paths_examined"] += 1
        rule = exclusions.match(relative)
        if rule is not None:
            configured.append({"path": relative, **rule.as_dict()})
            if rule.asset_class is not None:
                total = asset_totals.setdefault(rule.asset_class, {"files": 0, "bytes": 0})
                total["files"] += 1
                total["bytes"] += path.lstat().st_size if not path.is_symlink() and path.is_file() else 0
            continue
        descriptor = is_build_descriptor(PurePosixPath(relative))
        discovery["descriptors_matched"] += int(descriptor)
        language = LANGUAGES.get(path.suffix.lower())
        if language is not None and path.is_file() and not path.is_symlink():
            try:
                size = path.stat().st_size
                if size > bounds.max_file_bytes:
                    source_metric_gaps.append({"path": relative, "reason": "source_file_too_large"})
                elif len(source_metrics) >= bounds.max_files:
                    source_metric_gaps.append({"path": relative, "reason": "source_file_count_bound_reached"})
                elif source_metric_bytes + size > bounds.max_total_bytes:
                    source_metric_gaps.append({"path": relative, "reason": "source_total_bytes_bound_reached"})
                else:
                    text = path.read_text(encoding="utf-8")
                    lowered = {part.lower() for part in parts}
                    source_metrics.append({
                        "path": relative, "sha256": sha256_file(path), "size_bytes": size,
                        "language": language,
                        "sloc": sum(bool(line.strip()) for line in text.splitlines()),
                        "generated": bool(lowered & {"generated", "gen"}),
                        "vendored": bool(lowered & {"vendor", "vendors", "third_party"}),
                        "test": bool(lowered & {"test", "tests", "spec", "specs"}) or
                                path.name.lower().startswith(("test_", "spec_")),
                    })
                    source_metric_bytes += size
            except (OSError, UnicodeError):
                source_metric_gaps.append({"path": relative, "reason": "source_decode_failed"})
        excluded_part = next((part for part in parts if part in {".git", ".hg", ".svn"}), None)
        if excluded_part:
            prefix = Path(*parts[:parts.index(excluded_part) + 1]).as_posix()
            if prefix not in excluded:
                gaps.append({"path": prefix, "reason": "excluded_directory"})
                excluded.add(prefix)
            continue
        if path.is_symlink():
            gaps.append({"path": relative, "reason": "symlink_excluded"})
            discovery["descriptors_unavailable"] += int(descriptor)
            continue
        if not path.is_file():
            if descriptor:
                gaps.append({"path": relative, "reason": "non_regular_descriptor"})
                discovery["descriptors_unavailable"] += 1
            continue
        if len(relative) > bounds.max_path_length:
            gaps.append({"path": relative[:bounds.max_path_length], "reason": "path_too_long"})
            discovery["descriptors_unavailable"] += int(descriptor)
            continue
        size = path.stat().st_size
        if size > bounds.max_file_bytes:
            gaps.append({"path": relative, "reason": "file_too_large"})
            discovery["descriptors_unavailable"] += int(descriptor)
            continue
        if not descriptor and (content_files >= bounds.max_files or content_bytes + size > bounds.max_total_bytes):
            gaps.append({"path": relative, "reason": "inventory_bound_reached"})
            discovery["content_files_omitted"] += 1
            continue
        if not descriptor:
            content_files += 1
            content_bytes += size
            with path.open("rb") as stream:
                sample = stream.read(8192)
        if not descriptor and b"\0" in sample:
            artifact_candidates.append({"path": relative, "size_bytes": size,
                                        "sha256": sha256_file(path)})
            continue
        digest = sha256_file(path)
        from appsec_review.runtime.scope import target_role
        from appsec_review.config.assurance import SCOPE_VERSION
        files.append({"path": relative, "size_bytes": size, "sha256": digest,
                      "language": language,
                      "generated": any(part in {"generated", "gen"} for part in parts),
                      "scope_role": target_role(relative).value, "scope_version": SCOPE_VERSION,
                      "delivery_status": "unknown"})
        discovery["descriptors_retained"] += int(descriptor)
    snapshot = raw_snapshot(root)
    discovery["content_files_retained"] = content_files
    discovery["content_bytes_retained"] = content_bytes
    file_discovery = {"semantics": FILE_DISCOVERY_SEMANTICS, **discovery,
                      "descriptor_coverage": "partial" if discovery["descriptors_unavailable"] else "complete"}
    return {"files": files, "gaps": gaps, "file_count": len(files),
            "total_bytes": sum(item["size_bytes"] for item in files),
            "artifact_candidates": artifact_candidates,
            "artifact_candidate_count": len(artifact_candidates),
            "artifact_candidate_bytes": sum(item["size_bytes"] for item in artifact_candidates),
            "source_metrics_semantics": SOURCE_METRICS_SEMANTICS,
            "source_metrics": source_metrics, "source_metric_gaps": source_metric_gaps,
            "file_discovery": file_discovery,
            "configured_exclusions": sorted(configured, key=lambda item: item["path"]),
            "excluded_assets": {
                "policy": "configured asset classes are excluded by file-name suffix; not a coverage gap",
                "classes": {name: asset_totals[name] for name in sorted(asset_totals)},
                "files": sum(item["files"] for item in asset_totals.values()),
                "bytes": sum(item["bytes"] for item in asset_totals.values())},
            "snapshot": snapshot}


def raw_snapshot(root: Path) -> dict[str, Any]:
    """Identify all target-owned regular bytes, including excluded/generated content."""
    root = root.resolve(strict=True)
    digest = hashlib.sha256()
    count = total = 0
    for path in _walk_files(root):
        relative_path = path.relative_to(root)
        if any(part in {".git", ".hg", ".svn"} for part in relative_path.parts):
            continue
        relative = relative_path.as_posix()
        if path.is_symlink():
            digest.update(f"SYMLINK\0{relative}\0{path.readlink()}\n".encode())
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        file_digest = sha256_file(path)
        digest.update(f"FILE\0{relative}\0{size}\0{file_digest}\n".encode())
        count += 1
        total += size
    return {"schema": "appsec-review/raw-target-snapshot/1", "sha256": digest.hexdigest(),
            "file_count": count, "total_bytes": total,
            "coverage": "all regular target bytes including catalog-excluded directories and files"}


def source_fingerprint(root: Path, bounds: Bounds = Bounds()) -> str:
    del bounds
    return str(raw_snapshot(root)["sha256"])


def write_json(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    from appsec_review.storage import atomic_json, file_sha256
    atomic_json(path, value)
    return {"path": path.as_posix(), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
