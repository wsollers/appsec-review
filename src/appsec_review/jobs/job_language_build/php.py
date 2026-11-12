from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.config.assurance import ScopeRole
from appsec_review.jobs.artifact_kinds import binary_role
from appsec_review.jobs.build_output_scope import (
    LINKED_KINDS, BuildOutputDispositions, Decision, summarized_content_gap,
)
from appsec_review.jobs.delivery_scope import apply_scope, scope_fields
from appsec_review.storage import canonical_json, file_sha256

from . import php_installed


CAPTURE_IDENTITY = "appsec-review/php-composer-build-capture/3"
_MAX_UNVERIFIED_GAPS = 50
_ARCHIVE_SUFFIXES = (".phar", ".zip", ".tar", ".tar.gz", ".tgz")
_LINKED_SUFFIXES = {".a": "static-library", ".lib": "static-library", ".exe": "executable"}


def validate_php_dispatch(dispatch: Mapping[str, Any]) -> list[str]:
    """Validate the language-family constraints that are stricter than a generic recipe."""
    recipe = dispatch.get("recipe")
    if not isinstance(recipe, Mapping) or dispatch.get("build_system") not in {"composer", "phpize"}:
        return ["PHP execution requires an accepted Composer or phpize recipe"]
    dependencies = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
    gaps: list[str] = []
    if dispatch.get("build_system") == "phpize":
        return [] if "config.m4" in dependencies else ["phpize extension metadata is unavailable"]
    if "composer.json" not in dependencies:
        gaps.append("Composer project metadata is unavailable")
    return gaps


def composer_policy(settings: Mapping[str, Any]) -> dict[str, Any]:
    value = settings.get("php")
    if not isinstance(value, Mapping):
        raise ValueError("language-build PHP settings are required")
    plugins, scripts = value.get("composer_plugins"), value.get("composer_scripts")
    if plugins not in {"disabled", "sandboxed"} or scripts not in {"disabled", "sandboxed"}:
        raise ValueError("Composer plugin/script policy is invalid")
    return {
        "composer_plugins": plugins,
        "composer_scripts": scripts,
        "require_lockfile": value.get("require_lockfile") is True,
        "dependency_mode": "declared-dependencies-online",
        "network": "allowed",
        "application_execution": "forbidden",
        "test_execution": "forbidden",
    }


def policy_argv(argv: Sequence[str], policy: Mapping[str, Any]) -> tuple[str, ...]:
    result = [str(value) for value in argv]
    if result and PurePosixPath(result[0]).name == "composer":
        if policy["composer_plugins"] == "disabled" and "--no-plugins" not in result:
            result.append("--no-plugins")
        if policy["composer_scripts"] == "disabled" and "--no-scripts" not in result:
            result.append("--no-scripts")
        if "--no-interaction" not in result:
            result.append("--no-interaction")
    return tuple(result)


def _load_json(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> Any:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > max_bytes:
        raise ValueError(f"Composer metadata is unavailable or exceeds its bound: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def composer_metadata(workspace: Path, source_dir: str) -> tuple[dict[str, Any], list[str]]:
    root = workspace / Path(*PurePosixPath(source_dir).parts)
    manifest_path, lock_path = root / "composer.json", root / "composer.lock"
    gaps: list[str] = []
    manifest = _load_json(manifest_path)
    if lock_path.is_file() and not lock_path.is_symlink():
        lock = _load_json(lock_path)
    else:
        # An unlocked project resolves its declared constraints at build time.
        lock = {}
        gaps.append("composer.lock is absent; dependency versions were resolved at build time")
    if not isinstance(manifest, Mapping) or not isinstance(lock, Mapping):
        raise ValueError("Composer metadata roots must be objects")
    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    for scope in ("packages", "packages-dev"):
        values = lock.get(scope, [])
        if not isinstance(values, list) or len(values) > 10000:
            raise ValueError("Composer lock package list is invalid or exceeds its bound")
        for raw in values:
            if not isinstance(raw, Mapping) or not isinstance(raw.get("name"), str):
                raise ValueError("Composer lock package entry is invalid")
            package = {"name": raw["name"], "version": str(raw.get("version", "")),
                       "scope": "development" if scope == "packages-dev" else "runtime",
                       "dist_sha256": str(raw.get("dist", {}).get("shasum", ""))
                           if isinstance(raw.get("dist"), Mapping) else ""}
            # The lock's own sections decide the role: `packages` is the production closure,
            # reviewed as supply chain; nothing here establishes that a package ships.
            package.update(scope_fields({
                "scope_role": (ScopeRole.BUILD_DEPENDENCY if scope == "packages-dev"
                               else ScopeRole.RUNTIME_DEPENDENCY).value,
                "artifact_origin": "accepted-input",
            }))
            packages.append(package)
            requires = raw.get("require", {})
            if isinstance(requires, Mapping):
                for dependency in sorted(requires):
                    if "/" in str(dependency):
                        relationships.append({"from": raw["name"], "to": str(dependency),
                                              "constraint": str(requires[dependency]), "kind": "requires"})
    root_name = str(manifest.get("name", "root-project"))
    requires = manifest.get("require", {})
    if isinstance(requires, Mapping):
        for dependency in sorted(requires):
            if "/" in str(dependency):
                relationships.append({"from": root_name, "to": str(dependency),
                                      "constraint": str(requires[dependency]), "kind": "requires"})
    scripts = manifest.get("scripts", {})
    script_records = []
    if isinstance(scripts, Mapping):
        for name, commands in sorted(scripts.items()):
            values = commands if isinstance(commands, list) else [commands]
            encoded = canonical_json(values)
            script_records.append({"event": str(name), "command_count": len(values),
                                   "commands_sha256": hashlib.sha256(encoded).hexdigest()})
    return ({"schema": "appsec-review/php-composer-metadata/1", "root_package": root_name,
             "composer_json": {"sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size},
             "composer_lock": ({"sha256": file_sha256(lock_path), "size_bytes": lock_path.stat().st_size,
                                "content_hash": lock.get("content-hash")} if lock else None),
             "packages": packages, "relationships": relationships, "scripts": script_records,
             "plugins": [item for item in packages if item["name"].startswith("composer/")]}, gaps)


def artifact_kind(path: Path, relative: str, before: Mapping[str, str]) -> str | None:
    name, suffix = path.name.lower(), path.suffix.lower()
    normalized = relative.replace("\\", "/")
    if name in {"composer.json", "composer.lock", "installed.json", "installed.php"}:
        return "package-metadata"
    if "/vendor/composer/autoload_" in "/" + normalized or name == "autoload.php" and "/vendor/" in "/" + normalized:
        return "generated-autoload"
    if suffix == ".php" and before.get(relative) != file_sha256(path):
        return "generated-source"
    if suffix in {".so", ".dll", ".dylib"} or ".so." in name:
        return "native-extension"
    if any(normalized.lower().endswith(value) for value in _ARCHIVE_SUFFIXES):
        return "distributable-archive"
    return None


def catalog(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int,
            build_unit_id: str, build_system: str = "composer", *,
            dispositions: Any = None) -> tuple[list[dict[str, Any]], list[str]]:
    """Catalog PHP build outputs from the disposition walk.

    A recipe-run ``composer install`` leaves an installer record; its verified packages are
    registered before the walk and become one supply-chain row each instead of per-file rows.
    Configured ``[build_outputs]`` exclusions are counted in ``dispositions``, not listed.
    """
    if dispositions is None:
        dispositions = BuildOutputDispositions(family="php")
    installed = InstalledCatalog(workspace, before, dispositions)
    artifacts: list[dict[str, Any]] = []
    gaps: list[str] = list(installed.gaps)
    for relative, decision in dispositions.walk(workspace):
        path = workspace / relative
        recorded = installed.visit(relative, decision)
        kind = recorded or artifact_kind(path, relative, before)
        if kind is None and decision.kept:
            kind = _linked_kind(path)
        if kind is None:
            continue
        digest = file_sha256(path)
        if (recorded is None and not decision.kept and before.get(relative) == digest and
                kind not in {"package-metadata", "native-extension", "distributable-archive"}):
            continue
        artifact = {"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
                    "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind,
                    "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
                    "mapping_confidence": 1.0,
                    "artifact_origin": "accepted-input" if before.get(relative) == digest else "build-output"}
        if decision.scope_role is not None:
            artifact.update(scope_role=decision.scope_role, build_output_root=decision.root)
        installed.describe(artifact, decision)
        artifacts.append(artifact)
        if len(artifacts) >= limit:
            gaps.append("PHP artifact catalog truncated at configured count bound")
            break
    if build_system == "composer" and not any(item["kind"] == "generated-autoload" for item in artifacts):
        gaps.append("Composer autoload generation produced no retained autoload artifact")
    if build_system == "phpize" and not any(item["kind"] == "native-extension" for item in artifacts):
        gaps.append("phpize build produced no retained native extension module")
    gaps.extend(installed.summary(dispositions))
    gaps.extend(dispositions.named_gaps())
    gaps.extend(apply_scope(artifacts))
    return artifacts, gaps


def _linked_kind(path: Path) -> str | None:
    """The kind of a linked binary the walk kept under a verified package."""
    role, _container = binary_role(path)
    return role if role in LINKED_KINDS else _LINKED_SUFFIXES.get(path.suffix.lower())


def _new_file_below(workspace: Path, root: str, before: Mapping[str, str]) -> bool:
    for raw_root, directories, names in os.walk(workspace / Path(*PurePosixPath(root).parts), followlinks=False):
        directories.sort()
        directory = Path(raw_root)
        relative = directory.relative_to(workspace).as_posix()
        if any(f"{relative}/{name}" not in before and not (directory / name).is_symlink() for name in names):
            return True
    return False


def _record_written(workspace: Path, before: Mapping[str, str], record: php_installed.InstalledRecord) -> bool:
    """Whether the build wrote this vendor tree's record (or, without one, any file in the tree)."""
    path = php_installed.record_path(record.prefix)
    if record.record is not None:
        return before.get(path) != record.record.sha256
    if record.reason == "missing":
        return _new_file_below(workspace, php_installed.vendor_root(record.prefix), before)
    try:
        return before.get(path) != file_sha256(workspace / Path(*PurePosixPath(path).parts))
    except OSError:
        return True


def _installed_role(package: php_installed.InstalledPackage) -> str:
    return (ScopeRole.BUILD_DEPENDENCY if package.dev else ScopeRole.RUNTIME_DEPENDENCY).value


class InstalledCatalog:
    """Installer-record coverage of the Composer vendor trees a build wrote, for the catalog walk.

    A ``vendor/composer/installed.json`` equal to the pre-build snapshot is committed target
    content, not a recipe-run ``composer install``: its tree is not classified and gets no record
    row and no gap, so its files keep the per-file behaviour. For a written record, each verified
    package is registered with the shared build-output recorder before the walk, which prunes
    the package's tree to its ``composer.json`` anchor and linked binaries. Composer 2's
    ``dev-package-names`` makes a package a ``build_dependency``; every other verified package,
    and every Composer 1 package (that layout records no dev marking), is a
    ``runtime_dependency``.
    """

    def __init__(self, workspace: Path, before: Mapping[str, str], dispositions: BuildOutputDispositions) -> None:
        prefixes, discovery_gaps = php_installed.discover_prefixes(workspace)
        self.records = [record for record in (php_installed.parse_installed_record(workspace, prefix)
                                              for prefix in prefixes)
                        if _record_written(workspace, before, record)]
        self.gaps = list(discovery_gaps)
        self.record_paths = {record.record.workspace_path for record in self.records if record.record is not None}
        self.packages: dict[str, tuple[php_installed.InstalledRecord, php_installed.InstalledPackage]] = {}
        self.domains: dict[str, str] = {}
        self.registered: set[str] = set()
        self.uncovered: dict[str, int] = {}
        # install path -> [retained rows, retained bytes]
        self.retained: dict[str, list[int]] = {}
        self.rows: dict[str, dict[str, Any]] = {}
        unverified: list[php_installed.UnverifiedPackage] = []
        for record in self.records:
            root = php_installed.vendor_root(record.prefix)
            if not record.available:
                self.gaps.append(f"{root}: Composer installer record unavailable ({record.reason}); "
                                 "dependency files cataloged per-file in the target lane")
                continue
            self.domains[root] = record.prefix
            unverified.extend(record.unverified)
            for package in record.packages:
                self.packages[package.install_path] = (record, package)
        self.gaps.extend(f"{item.install_path}: installed package is not verified against the Composer "
                         f"installer record ({item.reason}); cataloged per-file"
                         for item in unverified[:_MAX_UNVERIFIED_GAPS])
        if len(unverified) > _MAX_UNVERIFIED_GAPS:
            self.gaps.append(f"{len(unverified) - _MAX_UNVERIFIED_GAPS} further unverified Composer packages "
                             "cataloged per-file")
        for install_path, (record, package) in sorted(self.packages.items()):
            assert record.record is not None
            if dispositions.classify_tree(
                    install_path, disposition="supply_chain", basis="installer-record",
                    name="composer-installed-package", reason="verified against installed manifest",
                    evidence_ref=f"{record.record.workspace_path}#{package.entry}", confidence="fact",
                    scope_role=_installed_role(package), keep=(package.manifest.workspace_path,),
                    keep_linked=True, bound_group=php_installed.vendor_root(record.prefix)):
                self.registered.add(install_path)
        for item in unverified:
            # Deepest registered root wins: an unverified package nested in a verified one stays per-file.
            if any(parent.as_posix() in self.packages for parent in PurePosixPath(item.install_path).parents):
                dispositions.classify_tree(
                    item.install_path, disposition="per_file", basis="installer-record",
                    name="composer-unverified-package", reason=item.reason, confidence="fact")

    def _owner(self, decision: Decision) -> tuple[php_installed.InstalledRecord,
                                                  php_installed.InstalledPackage] | None:
        return self.packages.get(decision.root) if decision.kept and decision.root is not None else None

    def visit(self, relative: str, decision: Decision) -> str | None:
        """Count a walked file no record covers; return the kind of a record or anchor row."""
        if relative in self.record_paths:
            return "resolved-dependency-metadata"
        owner = self._owner(decision)
        if owner is not None:
            return "package-metadata" if relative == owner[1].manifest.workspace_path else None
        for root, prefix in self.domains.items():
            if relative.startswith(root + "/"):
                # Composer's own loader and bookkeeping are not dependency content.
                if not php_installed.installer_owned(prefix, relative):
                    self.uncovered[prefix] = self.uncovered.get(prefix, 0) + 1
                break
        return None

    def describe(self, artifact: dict[str, Any], decision: Decision) -> None:
        """Add the installer-record facts of a record, anchor or retained row."""
        relative = str(artifact["workspace_path"])
        if relative in self.record_paths:
            artifact["dependency_metadata"] = {"format": php_installed.RECORD_NAME, "manager": "composer",
                                               "role": "installed-dependency-record"}
            return
        owner = self._owner(decision)
        if owner is None:
            return
        record, package = owner
        assert record.record is not None
        artifact["delivery_evidence"] = {
            "kind": "composer-installed-record", "workspace_path": record.record.workspace_path,
            "sha256": record.record.sha256, "entry": package.entry}
        if relative != package.manifest.workspace_path:
            total = self.retained.setdefault(package.install_path, [0, 0])
            total[0] += 1
            total[1] += int(artifact["size_bytes"])
            return
        if artifact["sha256"] != package.manifest.sha256:
            raise ValueError("installed Composer package manifest changed during cataloging")
        artifact["package_metadata"] = {
            "format": php_installed.MANIFEST_NAME, "role": "installed-dependency-package",
            "ecosystem": "composer", "manager": "composer", "name": package.name,
            "version": package.version, "version_normalized": package.version_normalized,
            "package_type": package.package_type, "dev": package.dev,
            "dist": dict(package.dist) if package.dist is not None else None,
            "source": dict(package.source) if package.source is not None else None,
            "install_path": package.install_path, "files": 0, "bytes": 0, "retained_files": 0}
        self.rows[package.install_path] = artifact

    def summary(self, dispositions: BuildOutputDispositions) -> list[str]:
        """One summary gap per written record from the walk's root counts; retained rows excluded."""
        counted = {str(root["root"]): root for root in dispositions.roots()}
        gaps = []
        for record in self.records:
            if not record.available or record.record is None:
                continue
            owned = [package for package in record.packages if package.install_path in self.registered]
            uncovered = self.uncovered.get(record.prefix, 0)
            if not owned:
                if uncovered:
                    gaps.append(f"{php_installed.vendor_root(record.prefix)}: Composer installer record covers "
                                f"no installed package; {uncovered} files under vendor remain per-file")
                continue
            files = size = 0
            for package in owned:
                root = counted[package.install_path]
                retained, retained_bytes = self.retained.get(package.install_path, (0, 0))
                files += int(root["files"]) - retained
                size += int(root["bytes"]) - retained_bytes
                if (row := self.rows.get(package.install_path)) is not None:
                    row["package_metadata"].update(files=int(root["files"]), bytes=int(root["bytes"]),
                                                   retained_files=retained)
            gap = summarized_content_gap(len(owned), "packages", files, size, record.record.workspace_path,
                                         "supply_chain")
            if uncovered:
                gap += f"; {uncovered} files under vendor not covered by the installer record remain per-file"
            gaps.append(gap)
        return gaps


def invocation_kind(tool: str, argv: Sequence[str]) -> str:
    name = PurePosixPath(tool).name
    if name == "composer":
        subcommand = next((value for value in argv[1:] if not str(value).startswith("-")), "")
        return {"dump-autoload": "autoload-generator", "dumpautoload": "autoload-generator",
                "archive": "package-builder", "install": "dependency-installer",
                "update": "dependency-installer"}.get(str(subcommand), "composer-build-driver")
    if name in {"phpize", "php-config", "configure"}:
        return "native-extension-configurer"
    if name in {"make", "gmake"}:
        return "build-driver"
    if name in {"cc", "gcc", "clang", "c++", "g++", "clang++"}:
        return "compiler-driver"
    if name in {"ld", "ld.lld"}:
        return "linker"
    if name in {"ar", "llvm-ar"}:
        return "archiver"
    return "php-build-driver"


def generates_autoloader(argv: Sequence[str]) -> bool:
    """Whether a Composer invocation writes the autoloader as part of its documented behavior.

    `install` and `update` dump the autoloader unless `--no-autoloader` is given;
    `dump-autoload` does nothing else.
    """
    if not argv or PurePosixPath(str(argv[0])).name != "composer":
        return False
    subcommand = next((str(value) for value in argv[1:] if not str(value).startswith("-")), "")
    if subcommand in {"dump-autoload", "dumpautoload"}:
        return True
    return subcommand in {"install", "update"} and "--no-autoloader" not in {str(value) for value in argv}
