from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import tarfile
from typing import Any

from appsec_review.config.assurance import ScopeRole
from appsec_review.jobs.delivery_scope import apply_scope
from appsec_review.jobs.job_language_build import node_installed, node_scripts
from appsec_review.jobs.job_project_build.job import node_installer_command
from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/node-build-capture/3"
LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn",
}
TOOL_KINDS = {
    "tsc": "typescript-compiler", "babel": "transpiler", "babeljs": "transpiler",
    "swc": "transpiler", "esbuild": "bundler", "webpack": "bundler",
    "rollup": "bundler", "vite": "bundler", "parcel": "bundler",
    "node-gyp": "native-addon-builder", "prebuild": "package-builder",
    "prebuildify": "package-builder", "npm": "package-manager",
    "pnpm": "package-manager", "yarn": "package-manager", "node": "runtime-driver",
    "protoc": "code-generator", "graphql-codegen": "code-generator",
    "openapi-generator": "code-generator", "prisma": "code-generator",
    "cc": "compiler-driver", "gcc": "compiler-driver", "clang": "compiler-driver",
    "c++": "compiler-driver", "g++": "compiler-driver", "clang++": "compiler-driver",
    "as": "assembler", "ld": "linker", "ld.lld": "linker", "ar": "archiver",
    "llvm-ar": "archiver", "ranlib": "post-link", "strip": "post-link",
    "objcopy": "post-link",
}

_COVERAGE_EXCHANGE_FILE = re.compile(
    r"(^|/)(lcov(?:\.info)?|coverage\.lcov|cobertura(?:-coverage)?\.xml|coverage\.xml|"
    r"jacoco(?:test)?report\.xml|jacoco\.xml|coverage(?:-final)?\.json|.*\.coverage\.json)$",
    re.I,
)
_PROFILE_EXCHANGE_FILE = re.compile(
    r"(^|/)(gmon\.out|callgrind(?:\.out(?:\.\d+)?)?|.*\.(?:callgrind|folded|stacks|"
    r"perf-script|perf\.txt|llvm-sample|sample\.prof|prof|profraw|profdata|pprof)|"
    r"(?:profile|pprof)\.pb(?:\.gz)?)$",
    re.I,
)


def is_coverage_exchange_path(path: str | Path) -> bool:
    """Return whether a path has a bounded, well-known coverage exchange filename."""
    return bool(_COVERAGE_EXCHANGE_FILE.search(str(path).replace("\\", "/")))


def is_profile_exchange_path(path: str | Path) -> bool:
    """Return whether a path has a bounded, well-known execution-profile filename."""
    return bool(_PROFILE_EXCHANGE_FILE.search(str(path).replace("\\", "/")))


_SOURCE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_GENERATED_SUFFIXES = _SOURCE_SUFFIXES | {".d.ts", ".d.mts", ".d.cts"}
_PACKAGE_METADATA = {"package.json"}
_RESOLVED_DEPENDENCY_METADATA = {*LOCKFILES, ".pnp.cjs", ".pnp.loader.mjs", node_installed.RECORD_NAME}
# Install-time native code and archives stay visible to supply-chain scanners.
_RETAINED_DEPENDENCY_KINDS = {"native-addon", "shared-library", "native-symbols", "package"}
_MAX_UNVERIFIED_GAPS = 50
_MAX_PACK_FACTS = 256
_MAX_PACK_MEMBERS = 4096
_NATIVE_SYMBOL_SUFFIXES = {".pdb", ".debug", ".dwo", ".dwp", ".sym"}
_PACKAGE_SUFFIXES = {".tgz", ".zip"}
_INTEGRITY_SUFFIXES = (".integrity", ".sha1", ".sha256", ".sha512", ".shasum")
_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
_MAX_METADATA_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_MAP_BYTES = 16 * 1024 * 1024
_CONFIG_NAMES = {
    "package.json", "tsconfig.json", "babel.config.js", "babel.config.cjs", "babel.config.mjs",
    ".babelrc", ".swcrc", "webpack.config.js", "webpack.config.cjs", "webpack.config.mjs",
    "rollup.config.js", "rollup.config.mjs", "vite.config.js", "vite.config.ts",
}
_CONTROL = {"&&", "||", ";", "|", "&"}
_SECRET = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)


def dependency_identity(dispatch: Mapping[str, Any]) -> tuple[str | None, dict[str, Any], list[str]]:
    hashes = dispatch.get("image", {}).get("dependency_hashes", {})
    if not isinstance(hashes, Mapping):
        raise ValueError("accepted Node dependency identities are unavailable")
    by_name = {PurePosixPath(str(path)).name: (str(path), str(digest))
               for path, digest in hashes.items()}
    locks = [(name, *by_name[name]) for name in sorted(LOCKFILES) if name in by_name]
    package = by_name.get("package.json")
    if package is None:
        return None, {}, ["Node build package.json identity is unavailable"]
    lock_managers = {LOCKFILES[name] for name, *_ in locks}
    if len(lock_managers) > 1:
        return None, {}, ["Node build declares multiple package-manager lockfiles"]
    commands = [*dispatch.get("recipe", {}).get("configure_commands", ()),
                *dispatch.get("recipe", {}).get("build_commands", ())]
    invoked = {Path(str(argv[0])).name for argv in commands if isinstance(argv, list) and argv}
    managers = invoked & set(LOCKFILES.values())
    if len(managers) > 1:
        return None, {}, ["accepted Node commands use multiple package managers"]
    preferred = next((row for row in locks if row[0] == "npm-shrinkwrap.json"), None)
    lock_name, lock_path, lock_sha = preferred or (locks[0] if locks else (None, None, None))
    manager = LOCKFILES[str(lock_name)] if lock_name else next(iter(managers), "npm")
    identity = {
        "manager": manager,
        "package_manifest": {"path": package[0], "sha256": package[1]},
        "lockfile": ({"path": lock_path, "sha256": lock_sha} if lock_name else None),
        "sha256": hashlib.sha256(canonical_json({
            "manager": manager, "package": package,
            "lock": ((lock_path, lock_sha) if lock_name else None),
        })).hexdigest(),
    }
    if managers and managers != {manager}:
        return None, identity, [f"accepted Node commands use {', '.join(sorted(managers))}, "
                                f"but the dependency inputs bind the build to {manager}"]
    return manager, identity, []


def environment_facts(environment: Mapping[str, str]) -> dict[str, str]:
    return {key: "set" for key in sorted(environment) if not _SECRET.search(key)}


def artifact_kind(path: Path) -> str | None:
    name, suffix = path.name.lower(), path.suffix.lower()
    if is_coverage_exchange_path(path):
        return "test-coverage"
    if is_profile_exchange_path(path):
        return "execution-profile"
    if name.endswith((".d.ts", ".d.mts", ".d.cts")):
        return "generated-declaration"
    if name.endswith(".node.map") or suffix in _NATIVE_SYMBOL_SUFFIXES:
        return "native-symbols"
    if suffix == ".map":
        return "source-map"
    if suffix == ".node":
        return "native-addon"
    if suffix in {".dll", ".so", ".dylib"} or ".so." in name:
        return "shared-library"
    if suffix in _PACKAGE_SUFFIXES:
        return "package"
    if name.endswith(_INTEGRITY_SUFFIXES):
        return "package-integrity"
    if name in _PACKAGE_METADATA:
        return "package-metadata"
    if name in _RESOLVED_DEPENDENCY_METADATA:
        return "resolved-dependency-metadata"
    if suffix in _GENERATED_SUFFIXES:
        return "generated-code"
    if suffix in {".wasm", ".css", ".html"}:
        return "bundle-asset"
    return None


def _catalog_files(workspace: Path, limit: int) -> tuple[list[Path], list[str]]:
    """Bound discovery, not delivery, by entry count; never infer scope from a directory."""
    files: list[Path] = []
    gaps: list[str] = []
    entries = 0
    for raw_root, directories, names in os.walk(workspace, followlinks=False):
        root = Path(raw_root)
        entries += len(directories) + len(names)
        if entries > limit:
            gaps.append("Node workspace discovery bound reached; delivery coverage incomplete")
            break
        for name in sorted([*directories, *names]):
            if (root / name).is_symlink():
                gaps.append(f"{(root / name).relative_to(workspace).as_posix()}: symlink delivery unresolved")
        directories[:] = sorted(name for name in directories
                                if not (root / name).is_symlink())
        files.extend(root / name for name in names)
    return sorted(files, key=lambda path: path.relative_to(workspace).as_posix()), gaps


def _package_delivery(artifacts: list[dict[str, Any]], run_root: Path,
                      package_facts: Sequence[Mapping[str, Any]]) -> list[str]:
    """Bind npm package members to retained workspace bytes without extracting them.

    Facts come only from a successful direct npm pack invocation, bound to its
    output digest. Diagnostic command traces and package.json declarations do not
    establish delivery.
    """
    by_path = {row["workspace_path"]: row for row in artifacts}
    gaps: list[str] = []
    if len(package_facts) > 256:
        gaps.append("npm package delivery fact count bound reached")
    for fact in package_facts[:256]:
        package = by_path.get(str(fact.get("workspace_path", "")))
        if package is None or package["sha256"] != fact.get("sha256") or package["kind"] != "package":
            gaps.append("npm package delivery fact has no retained matching archive")
            continue
        source_dir = PurePosixPath(str(fact.get("source_dir", ".")))
        if source_dir.is_absolute() or ".." in source_dir.parts:
            raise ValueError("npm package delivery fact has an invalid source directory")
        evidence = {"kind": "accepted-npm-pack", "workspace_path": package["workspace_path"],
                    "sha256": package["sha256"]}
        package.update(scope_role=ScopeRole.DELIVERABLE.value, delivery_evidence=evidence)
        package_path = run_root / package["path"]
        if package_path.is_symlink() or file_sha256(package_path) != package["sha256"]:
            raise ValueError("npm package changed during delivery reconciliation")
        try:
            total = 0
            with tarfile.open(package_path, "r|gz") as archive:
                for ordinal, member in enumerate(archive, 1):
                    total += member.size
                    if ordinal > 4096 or total > _MAX_ARTIFACT_BYTES:
                        gaps.append(f"{package['workspace_path']}: package delivery member bound reached")
                        break
                    logical = PurePosixPath(member.name)
                    if (logical.is_absolute() or ".." in logical.parts or
                            not logical.parts or logical.parts[0] != "package"):
                        gaps.append(f"{package['workspace_path']}: package member path is unresolved")
                        continue
                    if member.isdir():
                        continue
                    if not member.isfile() or member.size > _MAX_METADATA_BYTES:
                        gaps.append(f"{package['workspace_path']}: package member type or byte bound unsupported")
                        continue
                    relative = (source_dir / PurePosixPath(*logical.parts[1:])).as_posix()
                    row = by_path.get(relative)
                    if row is None:
                        # Archive scanners still cover the member; source indexing cannot.
                        gaps.append(f"{relative}: delivered package member lacks retained workspace mapping")
                        continue
                    stream = archive.extractfile(member)
                    if stream is None:
                        continue
                    with stream:
                        digest = hashlib.sha256(stream.read(member.size + 1)).hexdigest()
                    if digest != row["sha256"] or member.size != row["size_bytes"]:
                        gaps.append(f"{relative}: package member differs from retained workspace bytes")
                        continue
                    row.update(
                        scope_role=(ScopeRole.SHIPPED_DEPENDENCY.value if "node_modules" in logical.parts
                                    else ScopeRole.DELIVERABLE.value),
                        delivery_evidence={**evidence, "kind": "accepted-package-member", "member": member.name})
        except (OSError, tarfile.TarError, EOFError):
            gaps.append(f"{package['workspace_path']}: package delivery members could not be inspected")
        if file_sha256(package_path) != package["sha256"]:
            raise ValueError("npm package changed during delivery reconciliation")
    return gaps


def _size_limit(kind: str) -> int:
    if kind == "source-map":
        return _MAX_SOURCE_MAP_BYTES
    if kind in {"package-metadata", "resolved-dependency-metadata", "package-integrity"}:
        return _MAX_METADATA_BYTES
    return _MAX_ARTIFACT_BYTES


def _integrity_archive(relative: str, archives: Mapping[str, str]) -> tuple[str, str] | None:
    lowered = relative.lower()
    for suffix in _INTEGRITY_SUFFIXES:
        if lowered.endswith(suffix):
            archive = relative[:-len(suffix)]
            digest = archives.get(archive)
            return (archive, digest) if digest is not None else None
    return None


def _symbol_addon(relative: str, addons: Mapping[str, str]) -> tuple[str, str] | None:
    lowered = relative.lower()
    candidates = []
    if lowered.endswith(".node.map"):
        candidates.append(relative[:-4])
    if lowered.endswith(".node.debug"):
        candidates.append(relative[:-6])
    suffix = PurePosixPath(relative).suffix
    if suffix.lower() in _NATIVE_SYMBOL_SUFFIXES:
        candidates.append(relative[:-len(suffix)] + ".node")
    for candidate in candidates:
        digest = addons.get(candidate)
        if digest is not None:
            return candidate, digest
    return None


class _InstalledCoverage:
    """Installer-record coverage of a workspace; the deepest recorded install path decides."""

    def __init__(self, workspace: Path) -> None:
        prefixes, discovery_gaps = node_installed.discover_prefixes(workspace)
        self.records = [node_installed.parse_installed_record(workspace, prefix) for prefix in prefixes]
        self.roots: dict[str, tuple[node_installed.InstalledRecord, node_installed.InstalledPackage | None]] = {}
        self.domains: dict[str, node_installed.InstalledRecord] = {}
        self.unverified_reasons: dict[str, str] = {}
        self.record_paths = {record.record.workspace_path for record in self.records
                             if record.available and record.record is not None}
        for record in (item for item in self.records if item.available):
            self.domains.setdefault(_modules_root(node_installed.record_path(record.prefix)), record)
            for package in record.packages:
                self.domains.setdefault(_modules_root(package.install_path), record)
                self.roots.setdefault(package.install_path, (record, package))
            for unverified in record.unverified:
                self.domains.setdefault(_modules_root(unverified.install_path), record)
                self.roots.setdefault(unverified.install_path, (record, None))
                self.unverified_reasons.setdefault(unverified.install_path, unverified.reason)
        self.gaps = list(discovery_gaps)
        for record in self.records:
            modules = PurePosixPath(record.prefix, "node_modules").as_posix()
            # A nested prefix without its own record is described by its parent's record.
            if record.available or (record.reason == "missing" and modules in self.domains):
                continue
            self.gaps.append(f"{modules}: npm installer record unavailable ({record.reason}); "
                             "dependency files cataloged per-file in the target lane")
        unverified_items = [item for record in self.records for item in record.unverified]
        self.gaps.extend(f"{item.install_path}: installed package does not match npm installer record "
                         f"({item.reason}); cataloged per-file"
                         for item in unverified_items[:_MAX_UNVERIFIED_GAPS])
        if len(unverified_items) > _MAX_UNVERIFIED_GAPS:
            self.gaps.append(f"{len(unverified_items) - _MAX_UNVERIFIED_GAPS} further unverified npm "
                             "packages cataloged per-file")

    def owner(self, relative: str) -> tuple[node_installed.InstalledRecord,
                                             node_installed.InstalledPackage | None] | None:
        for parent in PurePosixPath(relative).parents:
            found = self.roots.get(parent.as_posix())
            if found is not None:
                return found
        return None

    def domain(self, relative: str) -> node_installed.InstalledRecord | None:
        root = _modules_root(relative)
        return self.domains.get(root) if root is not None else None


def _modules_root(relative: str) -> str | None:
    parts = PurePosixPath(relative).parts
    if "node_modules" not in parts:
        return None
    return PurePosixPath(*parts[:parts.index("node_modules") + 1]).as_posix()


def _installed_evidence(record: node_installed.InstalledRecord,
                        package: node_installed.InstalledPackage) -> dict[str, str]:
    assert record.record is not None
    return {"kind": "npm-installed-record", "workspace_path": record.record.workspace_path,
            "sha256": record.record.sha256, "entry": package.entry}


def _installed_role(package: node_installed.InstalledPackage) -> str:
    return (ScopeRole.BUILD_DEPENDENCY if package.build_only else ScopeRole.RUNTIME_DEPENDENCY).value


def _pack_members(workspace: Path, package_facts: Sequence[Mapping[str, Any]]) -> set[str]:
    """Workspace paths named by accepted npm pack archives; never summarized.

    Uses the bounds of ``_package_delivery``, which still decides each member's role.
    """
    members: set[str] = set()
    for fact in package_facts[:_MAX_PACK_FACTS]:
        logical = PurePosixPath(str(fact.get("workspace_path", "")))
        source_dir = PurePosixPath(str(fact.get("source_dir", ".")))
        if (not logical.parts or logical.is_absolute() or ".." in logical.parts or
                source_dir.is_absolute() or ".." in source_dir.parts):
            continue
        archive_path = workspace / Path(*logical.parts)
        try:
            if (archive_path.is_symlink() or not archive_path.is_file() or
                    artifact_kind(archive_path) != "package" or
                    file_sha256(archive_path) != fact.get("sha256")):
                continue
            total = 0
            with tarfile.open(archive_path, "r|gz") as archive:
                for ordinal, member in enumerate(archive, 1):
                    total += member.size
                    if ordinal > _MAX_PACK_MEMBERS or total > _MAX_ARTIFACT_BYTES:
                        break
                    name = PurePosixPath(member.name)
                    if (member.isfile() and not name.is_absolute() and ".." not in name.parts and
                            len(name.parts) > 1 and name.parts[0] == "package"):
                        members.add((source_dir / PurePosixPath(*name.parts[1:])).as_posix())
        except (OSError, tarfile.TarError, EOFError):
            continue
    return members


def _summary_gap(record: node_installed.InstalledRecord, packages: int, files: int, size: int,
                 uncovered: int) -> str:
    assert record.record is not None
    gap = (f"dependency-content-summarized: {packages} packages ({files} files, {size} bytes) "
           f"recorded by {record.record.workspace_path} routed to supply_chain review; "
           "per-file target review not performed")
    if uncovered:
        gap += f"; {uncovered} files under node_modules not covered by the installer record remain per-file"
    return gap


def catalog(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int,
            build_unit_id: str, *,
            package_facts: Sequence[Mapping[str, Any]] = (),
            dispositions: Any = None) -> tuple[list[dict[str, Any]], list[str]]:
    """Catalog Node build rows; installer-verified dependency trees become package rows.

    ``dispositions`` is the shared build-output recorder; when supplied, each covered
    install path is recorded there so summarized files stay accounted for.
    """
    artifacts: list[dict[str, Any]] = []
    candidates, gaps = _catalog_files(workspace, max(1, limit) * 10)
    coverage = _InstalledCoverage(workspace)
    gaps.extend(coverage.gaps)
    kept = _pack_members(workspace, package_facts)
    # install path -> [files, bytes, retained files, retained bytes]
    totals: dict[str, list[int]] = {}
    retained_paths: dict[str, list[str]] = {}
    package_rows: dict[str, dict[str, Any]] = {}
    uncovered: dict[str, int] = {}
    archives: dict[str, str] = {}
    addons: dict[str, str] = {}
    for candidate in candidates:
        try:
            relative = candidate.relative_to(workspace).as_posix()
            if (not candidate.is_file() or candidate.is_symlink()
                    or candidate.stat().st_size > _MAX_ARTIFACT_BYTES):
                continue
            if candidate.suffix.lower() in _PACKAGE_SUFFIXES:
                digest = file_sha256(candidate)
                if before.get(relative) != digest:
                    archives[relative] = digest
            elif candidate.suffix.lower() == ".node":
                digest = file_sha256(candidate)
                if before.get(relative) != digest:
                    addons[relative] = digest
        except OSError:
            continue
    for path in candidates:
        try:
            if path.is_symlink() or not path.is_file():
                continue
        except OSError:
            continue
        relative = path.relative_to(workspace).as_posix()
        owner = coverage.owner(relative)
        package = owner[1] if owner is not None else None
        anchor = False
        if package is not None:
            try:
                file_size = path.stat().st_size
            except OSError:
                continue
            total = totals.setdefault(package.install_path, [0, 0, 0, 0])
            total[0] += 1
            total[1] += file_size
            anchor = relative == package.manifest.workspace_path
            if not (anchor or relative in kept or artifact_kind(path) in _RETAINED_DEPENDENCY_KINDS):
                continue  # Summarized: the package row stands for these bytes.
        elif relative not in coverage.record_paths and (domain := coverage.domain(relative)) is not None:
            uncovered[domain.prefix] = uncovered.get(domain.prefix, 0) + 1
        kind = artifact_kind(path)
        if kind is None:
            continue
        integrity_archive = _integrity_archive(relative, archives) if kind == "package-integrity" else None
        if kind == "package-integrity" and integrity_archive is None:
            continue
        symbol_addon = _symbol_addon(relative, addons) if kind == "native-symbols" else None
        if kind == "native-symbols" and symbol_addon is None:
            continue
        size = path.stat().st_size
        size_limit = _size_limit(kind)
        if size > size_limit:
            gaps.append(f"{relative}: {kind} exceeds {size_limit} byte retention bound")
            continue
        digest = file_sha256(path)
        unchanged = before.get(relative) == digest
        if unchanged and kind not in {
            "test-coverage", "execution-profile", "package-metadata",
            "resolved-dependency-metadata", "native-addon", "shared-library",
        } and "node_modules" not in PurePosixPath(relative).parts:
            continue
        value: dict[str, Any] = {
            "path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
            "sha256": digest, "size_bytes": size, "kind": kind,
            "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
            "mapping_confidence": 1.0,
            "artifact_origin": "accepted-input" if unchanged else "build-output",
        }
        if kind == "package-metadata":
            value["package_metadata"] = {"format": "package.json", "role": "package-manifest"}
        elif kind == "resolved-dependency-metadata":
            if path.name == node_installed.RECORD_NAME:
                value["dependency_metadata"] = {"format": path.name, "manager": "npm",
                                                  "role": "installed-dependency-record"}
            else:
                manager = LOCKFILES.get(path.name.lower(),
                                        "yarn" if path.name.lower().startswith(".pnp") else None)
                value["dependency_metadata"] = {"format": path.name, "manager": manager,
                                                  "role": "resolved-dependency-graph"}
        elif integrity_archive is not None:
            value["package_archive"] = {"workspace_path": integrity_archive[0],
                                        "sha256": integrity_archive[1]}
        elif symbol_addon is not None:
            value["native_addon"] = {"workspace_path": symbol_addon[0],
                                     "sha256": symbol_addon[1]}
        if kind == "source-map":
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
                sources = document.get("sources", ()) if isinstance(document, Mapping) else ()
                if not isinstance(sources, list) or len(sources) > 4096:
                    raise ValueError("source list is invalid or exceeds its row bound")
                source_root = str(document.get("sourceRoot", ""))
                source_identities = []
                for item in sources:
                    if not isinstance(item, str):
                        continue
                    logical = PurePosixPath(source_root) / PurePosixPath(item)
                    candidate = (path.parent / Path(*logical.parts)).resolve()
                    row: dict[str, Any] = {"declared_path": item}
                    if (workspace.resolve() in candidate.parents and
                            candidate.is_file() and not candidate.is_symlink()):
                        row.update(workspace_path=candidate.relative_to(workspace).as_posix(),
                                   sha256=file_sha256(candidate), size_bytes=candidate.stat().st_size,
                                   mapping="source-map", mapping_confidence=1.0)
                    else:
                        row.update(mapping="declared-path-unresolved", mapping_confidence=0.5)
                    source_identities.append(row)
                value["source_map"] = {
                    "sources": [str(item) for item in sources if isinstance(item, str)],
                    "source_identities": source_identities,
                    "source_root": source_root,
                    "file": str(document.get("file", "")),
                }
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                gaps.append(f"{relative}: source-map provenance unavailable: {type(exc).__name__}")
        if package is not None and owner is not None:
            record = owner[0]
            if anchor:
                if digest != package.manifest.sha256:
                    raise ValueError("installed npm package manifest changed during cataloging")
                value.update(
                    scope_role=_installed_role(package),
                    delivery_evidence=_installed_evidence(record, package),
                    package_metadata={
                        "format": "package.json", "role": "installed-dependency-package",
                        "ecosystem": "npm", "manager": "npm",
                        "name": package.name, "version": package.version,
                        "resolved": package.resolved, "integrity": package.integrity,
                        "dev": package.dev, "optional": package.optional,
                        "dev_optional": package.dev_optional,
                        "install_path": package.install_path,
                        "files": 0, "bytes": 0, "retained_files": 0,
                    })
                package_rows[package.install_path] = value
            else:
                if relative not in kept:
                    value.update(scope_role=_installed_role(package),
                                 delivery_evidence=_installed_evidence(record, package))
                total = totals[package.install_path]
                total[2] += 1
                total[3] += size
                retained_paths.setdefault(package.install_path, []).append(relative)
        artifacts.append(value)
        if len(artifacts) >= limit:
            gaps.append("Node artifact catalog truncated at configured count bound")
            break
    gaps.extend(_installed_summary(coverage, totals, package_rows, uncovered))
    if dispositions is not None:
        _record_dispositions(dispositions, coverage, retained_paths)
    gaps.extend(_package_delivery(artifacts, run_root, package_facts))
    gaps.extend(apply_scope(artifacts))
    return artifacts, gaps


def _installed_summary(coverage: _InstalledCoverage, totals: Mapping[str, list[int]],
                       package_rows: Mapping[str, dict[str, Any]],
                       uncovered: Mapping[str, int]) -> list[str]:
    """One D6(a) gap per available record; files and bytes exclude retained rows."""
    gaps = []
    for record in coverage.records:
        owned = [package for package in record.packages
                 if coverage.roots.get(package.install_path, (None, None))[1] is package]
        if not record.available or not owned:
            continue
        files = size = 0
        for package in owned:
            seen, seen_bytes, retained, retained_bytes = totals.get(package.install_path, (0, 0, 0, 0))
            files += seen - retained
            size += seen_bytes - retained_bytes
            if (row := package_rows.get(package.install_path)) is not None:
                row["package_metadata"].update(files=seen, bytes=seen_bytes, retained_files=retained)
        gaps.append(_summary_gap(record, len(owned), files, size, uncovered.get(record.prefix, 0)))
    return gaps


def _record_dispositions(dispositions: Any, coverage: _InstalledCoverage,
                         retained_paths: Mapping[str, Sequence[str]]) -> None:
    for install_path, (record, package) in sorted(coverage.roots.items()):
        if package is not None:
            dispositions.classify_tree(
                install_path, disposition="supply_chain", basis="installer-record",
                name="npm-installed-package", reason="verified against installed manifest",
                evidence_ref=f"{record.record.workspace_path}#{package.entry}", confidence="fact",
                scope_role=_installed_role(package),
                keep=(package.manifest.workspace_path, *retained_paths.get(install_path, ())))
            continue
        parent = coverage.owner(install_path)
        if parent is not None and parent[1] is not None:
            dispositions.classify_tree(
                install_path, disposition="per_file", basis="installer-record",
                name="npm-unverified-package", reason=coverage.unverified_reasons[install_path],
                confidence="fact")


def _package_document(workspace: Path, source_dir: str) -> tuple[Path, Mapping[str, Any]] | None:
    path = workspace / Path(*PurePosixPath(source_dir).parts) / "package.json"
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    return (path, value) if isinstance(value, Mapping) else None


def _script_name(argv: Sequence[str], manager: str) -> str | None:
    values = list(argv[1:])
    if manager == "npm":
        marker = "run" if "run" in values else "run-script" if "run-script" in values else None
        if marker is None:
            return None
        index = values.index(marker) + 1
        return values[index] if index < len(values) and not values[index].startswith("-") else None
    if "run" in values:
        index = values.index("run") + 1
        return values[index] if index < len(values) and not values[index].startswith("-") else None
    skip = False
    for index, value in enumerate(values):
        if skip:
            skip = False
            continue
        if value in {"--cwd", "--dir", "--prefix"}:
            skip = True
            continue
        if not value.startswith("-"):
            return value
    return None


def validate_lifecycle_scripts(workspace: Path, source_dir: str,
                               commands: Sequence[Sequence[str]]) -> list[str]:
    """Classify every package script the recipe's commands reach, at every depth.

    Gaps name the full chain from the recipe-requested script to the offending command.
    """
    package = _package_document(workspace, source_dir)
    if package is None:
        return ["package.json is unavailable for lifecycle-script validation"]
    if not isinstance(package[1].get("scripts", {}), Mapping):
        return ["package.json scripts must be an object"]
    return node_scripts.classify(workspace, source_dir, commands)


def _npm_pack_integrity(source_dir: str, argv: Sequence[str], after: Mapping[str, str],
                        stdout: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    if (Path(str(argv[0])).name != "npm" or tuple(argv[1:2]) != ("pack",)
            or "--json" not in argv):
        return [], []
    try:
        document = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return [], ["npm pack --json integrity metadata was unavailable or not parseable"]
    rows = document if isinstance(document, list) else [document]
    if len(rows) > 256:
        return [], ["npm pack --json integrity metadata exceeds 256 row bound"]
    values: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        filename = row.get("filename")
        integrity, shasum = row.get("integrity"), row.get("shasum")
        if (not isinstance(filename, str) or not filename or
                (not isinstance(integrity, str) and not isinstance(shasum, str))):
            continue
        logical = PurePosixPath(filename.replace("\\", "/"))
        if logical.is_absolute() or any(part in {"", ".", ".."} for part in logical.parts):
            continue
        workspace_path = (PurePosixPath(source_dir) / logical).as_posix()
        digest = after.get(workspace_path)
        if digest is None:
            continue
        value: dict[str, Any] = {"workspace_path": workspace_path, "sha256": digest,
                                 "source_dir": source_dir}
        if isinstance(integrity, str) and len(integrity) <= 1024:
            value["integrity"] = integrity
        if isinstance(shasum, str) and re.fullmatch(r"[0-9a-fA-F]{40}", shasum):
            value["shasum"] = shasum.lower()
        for key in ("size", "unpackedSize", "totalFiles"):
            if type(row.get(key)) is int and 0 <= row[key] <= 2**63 - 1:
                value[key] = row[key]
        if "integrity" in value or "shasum" in value:
            values.append(value)
    return values, ([] if values else ["npm pack --json exposed no bound integrity metadata"])


def invocation_rows(workspace: Path, source_dir: str, argv: Sequence[str], *, success: bool,
                    before: Mapping[str, str], after: Mapping[str, str],
                    diagnostic_streams: Sequence[bytes] = ()) -> tuple[list[dict[str, Any]], list[str]]:
    tool = Path(str(argv[0])).name
    rows: list[dict[str, Any]] = [{
        "tool": tool, "tool_kind": TOOL_KINDS.get(tool, "build-driver"), "argv": list(argv),
        "directory": source_dir, "inputs": [], "outputs": [], "origin": "accepted-recipe",
        "mapping": "direct-invocation", "mapping_confidence": 1.0,
    }]
    gaps: list[str] = []
    changed = sorted(path for path, digest in after.items() if before.get(path) != digest)
    rows[0]["outputs"] = [{"workspace_path": path, "sha256": after[path],
                           "mapping": "command-delta", "mapping_confidence": 0.75}
                          for path in changed[:4096]]
    root = workspace / Path(*PurePosixPath(source_dir).parts)
    rows[0]["inputs"] = [{"workspace_path": path.relative_to(workspace).as_posix(),
                           "sha256": file_sha256(path), "size_bytes": path.stat().st_size,
                           "mapping": "configuration-input", "mapping_confidence": 0.75}
                          for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink()
                          and (path.name in _CONFIG_NAMES or path.suffix.lower() in _SOURCE_SUFFIXES)][:4096]
    if success and diagnostic_streams:
        integrity, integrity_gaps = _npm_pack_integrity(source_dir, argv, after, diagnostic_streams[0])
        if integrity:
            rows[0]["package_integrity"] = integrity
        gaps.extend(integrity_gaps)
    for stream in diagnostic_streams:
        for line in stream.decode("utf-8", "replace").splitlines()[:20000]:
            try:
                trace = shlex.split(line.strip())
            except ValueError:
                continue
            if not trace:
                continue
            trace_tool = Path(trace[0]).name
            if trace_tool not in TOOL_KINDS or trace_tool in {"npm", "pnpm", "yarn", "node"}:
                continue
            outputs = [trace[index + 1] for index, value in enumerate(trace[:-1]) if value == "-o"]
            inputs = [value for value in trace[1:] if value not in outputs and
                      Path(value).suffix.lower() in (_SOURCE_SUFFIXES | {".o", ".obj", ".a", ".lib"})]
            rows.append({"tool": trace_tool, "tool_kind": TOOL_KINDS[trace_tool], "argv": trace,
                         "directory": source_dir,
                         "inputs": [{"workspace_path": value, "mapping": "diagnostic-path",
                                     "mapping_confidence": 0.75} for value in inputs],
                         "outputs": [{"workspace_path": value, "mapping": "diagnostic-path",
                                      "mapping_confidence": 0.75} for value in outputs],
                         "origin": "retained-build-diagnostics", "mapping": "diagnostic-trace",
                         "mapping_confidence": 0.9})
    if not success or tool not in {"npm", "pnpm", "yarn"}:
        return rows, gaps
    if tool == "npm" and "pack" in argv:
        return rows, gaps
    if node_installer_command(argv):
        # A dependency restore runs no named package script; its own row is the provenance.
        return rows, gaps
    package = _package_document(workspace, source_dir)
    script_name = _script_name(argv, tool)
    scripts = package[1].get("scripts", {}) if package else {}
    script = scripts.get(script_name) if isinstance(scripts, Mapping) and script_name else None
    if not isinstance(script, str):
        gaps.append("successful package-manager command did not resolve to a bounded package script")
        return rows, gaps
    try:
        tokens = shlex.split(script)
    except ValueError:
        gaps.append(f"package script {script_name} could not be parsed for nested tool provenance")
        return rows, gaps
    if not tokens or any(value in _CONTROL for value in tokens):
        gaps.append(f"package script {script_name} uses shell composition; nested invocation provenance is ambiguous")
        return rows, gaps
    nested_tool = Path(tokens[0]).name
    rows.append({
        "tool": nested_tool, "tool_kind": TOOL_KINDS.get(nested_tool, "package-script-tool"),
        "argv": tokens, "directory": source_dir, "inputs": rows[0]["inputs"],
        "outputs": rows[0]["outputs"], "origin": f"package.json#scripts.{script_name}",
        "mapping": "successful-package-script", "mapping_confidence": 0.9,
    })
    return rows, gaps
