from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.storage import canonical_json, file_sha256


CAPTURE_IDENTITY = "appsec-review/php-composer-build-capture/1"
_ARCHIVE_SUFFIXES = (".phar", ".zip", ".tar", ".tar.gz", ".tgz")


def validate_php_dispatch(dispatch: Mapping[str, Any]) -> list[str]:
    """Validate the language-family constraints that are stricter than a generic recipe."""
    recipe = dispatch.get("recipe")
    if not isinstance(recipe, Mapping) or dispatch.get("build_system") != "composer":
        return ["PHP execution requires an accepted Composer recipe"]
    dependencies = {PurePosixPath(str(value)).name for value in recipe.get("dependency_files", ())}
    gaps: list[str] = []
    if "composer.json" not in dependencies:
        gaps.append("Composer project metadata is unavailable")
    if "composer.lock" not in dependencies:
        gaps.append("Composer lockfile is required for a lockfile-bound build")
    if recipe.get("network_required") is not True:
        gaps.append("Composer dependencies were not resolved into the pinned project image")
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
        "dependency_mode": "derived-image-offline",
        "network": "disabled",
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
    manifest, lock = _load_json(manifest_path), _load_json(lock_path)
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
             "composer_lock": {"sha256": file_sha256(lock_path), "size_bytes": lock_path.stat().st_size,
                               "content_hash": lock.get("content-hash")},
             "packages": packages, "relationships": relationships, "scripts": script_records,
             "plugins": [item for item in packages if item["name"].startswith("composer/")]}, [])


def artifact_kind(path: Path, relative: str, before: Mapping[str, str]) -> str | None:
    name, suffix = path.name.lower(), path.suffix.lower()
    normalized = relative.replace("\\", "/")
    if name in {"composer.json", "composer.lock", "installed.json", "installed.php"}:
        return "package-metadata"
    if "/vendor/composer/autoload_" in "/" + normalized or name == "autoload.php" and "/vendor/" in "/" + normalized:
        return "generated-autoload"
    if suffix == ".php" and before.get(relative) != file_sha256(path):
        return "generated-source"
    if suffix == ".so":
        return "native-extension"
    if any(normalized.lower().endswith(value) for value in _ARCHIVE_SUFFIXES):
        return "distributable-archive"
    return None


def catalog(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int,
            build_unit_id: str) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    gaps: list[str] = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(workspace).as_posix()
        kind = artifact_kind(path, relative, before)
        if kind is None:
            continue
        digest = file_sha256(path)
        if kind != "package-metadata" and before.get(relative) == digest:
            continue
        artifacts.append({"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
                          "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind,
                          "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
                          "mapping_confidence": 1.0})
        if len(artifacts) >= limit:
            gaps.append("PHP artifact catalog truncated at configured count bound")
            break
    if not any(item["kind"] == "generated-autoload" for item in artifacts):
        gaps.append("Composer autoload generation produced no retained autoload artifact")
    return artifacts, gaps


def invocation_kind(tool: str, argv: Sequence[str]) -> str:
    name = PurePosixPath(tool).name
    if name == "composer":
        subcommand = next((value for value in argv[1:] if not str(value).startswith("-")), "")
        return {"dump-autoload": "autoload-generator", "archive": "package-builder",
                "install": "dependency-installer"}.get(str(subcommand), "composer-build-driver")
    if name in {"phpize", "php-config"}:
        return "native-extension-configurer"
    if name in {"cc", "gcc", "clang", "c++", "g++", "clang++"}:
        return "compiler-driver"
    if name in {"ld", "ld.lld"}:
        return "linker"
    if name in {"ar", "llvm-ar"}:
        return "archiver"
    return "php-build-driver"
