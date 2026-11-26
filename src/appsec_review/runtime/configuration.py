"""Immutable configuration revisions with explicit operational compatibility."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, TYPE_CHECKING

from appsec_review.config.operational import configuration_compatible, operational_changes
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import immutable_bytes, reference, safe_path
from appsec_review.storage.validation import current_validation

if TYPE_CHECKING:
    from appsec_review.config import AppConfig


CONFIGURATION_SCHEMA = "appsec-review/run-configuration/2"
REVISION_SCHEMA = "appsec-review/operational-configuration/1"
_HASH = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class ConfigurationSnapshot:
    directory: Path
    manifest: Mapping[str, Any]
    document: Mapping[str, Any]

    @property
    def sha256(self) -> str:
        return str(self.manifest["resolved_sha256"])

    def artifacts(self, run_root: Path) -> list[dict[str, Any]]:
        names = ["manifest.json", "resolved.json", "appsec-review.toml"]
        if (self.directory / "host-pins.toml").is_file():
            names.append("host-pins.toml")
        result = [reference(run_root, self.directory / name) for name in names]
        for layer in self.manifest.get("source_layers", ()):
            result.append(reference(run_root, safe_path(run_root,
                (self.directory / layer["file"]).relative_to(run_root).as_posix())))
        if self.manifest.get("schema") == REVISION_SCHEMA:
            result.extend(configuration_snapshot(run_root).artifacts(run_root))
        return result


def _regular_file(path: Path) -> Path:
    if not path.is_file():
        raise ValueError("configuration control anchor is not a regular file")
    return path


def _document(path: Path) -> dict[str, Any]:
    value = json.loads(_regular_file(path).read_bytes())
    if not isinstance(value, dict):
        raise ValueError("configuration document must be an object")
    return value


def base_configuration_sha256(run_root: Path) -> str:
    manifest = _document(safe_path(run_root, "data/configuration/manifest.json"))
    value = manifest.get("resolved_sha256")
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError("invalid frozen configuration identity")
    return value


def configuration_directory(run_root: Path, expected_sha256: str | None = None) -> Path:
    base_sha = base_configuration_sha256(run_root)
    expected = expected_sha256 or base_sha
    if not isinstance(expected, str) or not _HASH.fullmatch(expected):
        raise ValueError("invalid requested configuration identity")
    relative = ("data/configuration" if expected == base_sha
                else f"data/configuration/revisions/{expected}")
    if expected != base_sha and not safe_path(run_root, relative + "/manifest.json").is_file():
        raise ValueError("requested configuration revision is unavailable")
    return safe_path(run_root, relative)


def admitted_configuration_sha256(run_root: Path, binding: Mapping[str, Any] | None) -> str:
    if binding is not None and binding.get("repair") is not None:
        from appsec_review.storage.shared import verify_reference
        admission = _document(verify_reference(run_root, binding["repair"]))
        value = admission.get("resolved_config_sha256")
        if not isinstance(value, str) or not _HASH.fullmatch(value):
            raise ValueError("repair admission lacks its configuration identity")
        return value
    return base_configuration_sha256(run_root)


def configuration_snapshot(run_root: Path, expected_sha256: str | None = None) -> ConfigurationSnapshot:
    """Resolve a specific immutable version; never select a mutable latest pointer."""
    base_sha = base_configuration_sha256(run_root)
    expected = expected_sha256 or base_sha
    if not isinstance(expected, str) or not _HASH.fullmatch(expected):
        raise ValueError("invalid requested configuration identity")
    relative = ("data/configuration" if expected == base_sha
                else f"data/configuration/revisions/{expected}")
    directory = configuration_directory(run_root, expected)
    manifest_path = safe_path(run_root, relative + "/manifest.json")
    resolved_path = safe_path(run_root, relative + "/resolved.json")
    source_path = safe_path(run_root, relative + "/appsec-review.toml")
    manifest = _document(manifest_path)
    required_schema = CONFIGURATION_SCHEMA if expected == base_sha else REVISION_SCHEMA
    if manifest.get("schema") != required_schema:
        raise ValueError("unsupported configuration snapshot")
    if (manifest.get("resolved_sha256") != expected
            or file_sha256(_regular_file(resolved_path)) != expected
            or file_sha256(_regular_file(source_path)) != manifest.get("source_sha256")):
        raise ValueError("configuration snapshot hash mismatch")
    document = _document(resolved_path)
    for layer in manifest.get("source_layers", ()):
        filename = layer.get("file")
        if filename not in ("profile.toml", "overlay.toml"):
            raise ValueError("unsupported immutable configuration source layer")
        if file_sha256(_regular_file(safe_path(run_root, relative + "/" + filename))) != layer.get("sha256"):
            raise ValueError("configuration source-layer hash mismatch")
        import tomllib
        key = "configuration_" + filename.removesuffix(".toml")
        source_document = tomllib.loads(safe_path(run_root, relative + "/" + filename).read_text(encoding="utf-8"))
        if source_document != document.get(key, {}).get("document"):
            raise ValueError("source layer differs from its recorded resolved provenance")
    host_pins = document.get("configuration_host_pins")
    if host_pins is not None and file_sha256(
            _regular_file(safe_path(run_root, relative + "/host-pins.toml"))) != host_pins["sha256"]:
        raise ValueError("configuration host-pins hash mismatch")
    snapshot = ConfigurationSnapshot(directory, manifest, document)
    if expected != base_sha:
        if (manifest.get("schema") != REVISION_SCHEMA
                or manifest.get("base_resolved_sha256") != base_sha):
            raise ValueError("configuration revision is not bound to the original run")
        base = configuration_snapshot(run_root, base_sha)
        changes = operational_changes(base.document, document)
        if changes != manifest.get("operational_changes"):
            raise ValueError("configuration revision deltas differ from its recorded admission")
    return snapshot


def configuration_document(run_root: Path, expected_sha256: str | None = None) -> Mapping[str, Any]:
    return configuration_snapshot(run_root, expected_sha256).document


def context_configuration(context: Any) -> Mapping[str, Any]:
    return configuration_document(context.run_root, getattr(context, "resolved_config_sha256", None))


def candidate_configuration_changes(config: AppConfig, run_root: Path) -> list[dict[str, Any]]:
    base = configuration_snapshot(run_root)
    if config.resolved_sha256 == base.sha256:
        return []
    if hashlib.sha256(config.resolved_json).hexdigest() != config.resolved_sha256:
        raise ValueError("candidate configuration bytes do not match their identity")
    return operational_changes(base.document, json.loads(config.resolved_json))


def configuration_matches(config: AppConfig, run_root: Path, prior_sha256: str) -> bool:
    """Compare an existing producer's configuration with a validated live candidate."""
    if prior_sha256 == config.resolved_sha256:
        return True
    previous = configuration_snapshot(run_root, prior_sha256)
    if hashlib.sha256(config.resolved_json).hexdigest() != config.resolved_sha256:
        raise ValueError("candidate configuration bytes do not match their identity")
    return configuration_compatible(previous.document, json.loads(config.resolved_json))


def configurations_compatible(run_root: Path, first_sha256: str, second_sha256: str) -> bool:
    if first_sha256 == second_sha256:
        return True
    validation = current_validation(run_root)
    cache_key = ("operational-configuration-compatibility", first_sha256, second_sha256)
    if validation is not None:
        with validation.lock:
            cached = validation.records.get(cache_key)
        if cached is not None:
            return bool(cached)
    first = configuration_snapshot(run_root, first_sha256)
    second = configuration_snapshot(run_root, second_sha256)
    result = configuration_compatible(first.document, second.document)
    if validation is not None:
        with validation.lock:
            validation.records[cache_key] = result
    return result


def persist_configuration_revision(config: AppConfig, run_root: Path) -> ConfigurationSnapshot:
    """Write a new version before the repair binding commits its admission."""
    changes = candidate_configuration_changes(config, run_root)
    base_sha = base_configuration_sha256(run_root)
    if config.resolved_sha256 == base_sha:
        return configuration_snapshot(run_root, base_sha)
    relative = f"data/configuration/revisions/{config.resolved_sha256}"
    if safe_path(run_root, relative + "/manifest.json").is_file():
        return configuration_snapshot(run_root, config.resolved_sha256)
    source = config.source_path.read_bytes()
    if hashlib.sha256(source).hexdigest() != config.source_sha256:
        raise ValueError("configuration source changed before operational admission")
    immutable_bytes(run_root, relative + "/appsec-review.toml", source)
    immutable_bytes(run_root, relative + "/resolved.json", config.resolved_json)
    if config.host_pins is not None:
        immutable_bytes(run_root, relative + "/host-pins.toml", config.host_pins.content)
    source_layers = []
    for name, path, expected in (("profile", config.profile_path, config.profile_sha256),
                                 ("overlay", config.overlay_path, config.overlay_sha256)):
        if path is None:
            continue
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("configuration source layer changed before admission")
        filename = name + ".toml"
        immutable_bytes(run_root, relative + "/" + filename, content)
        source_layers.append({"file": filename, "sha256": expected})
    manifest = {
        "source_layers": source_layers,
        "schema": REVISION_SCHEMA, "base_resolved_sha256": base_sha,
        "source_sha256": config.source_sha256, "resolved_sha256": config.resolved_sha256,
        "resolved": {"path": "resolved.json", "sha256": config.resolved_sha256},
        "sources": [dict(layer) for layer in config.layers],
        "selection": {"profile": config.profile,
                      "overlay": str(config.overlay_path) if config.overlay_path else None,
                      "compiler_target": config.compiler_target.value,
                      "source": config.selection_source},
        "operational_changes": changes,
    }
    immutable_bytes(run_root, relative + "/manifest.json", canonical_json(manifest))
    return configuration_snapshot(run_root, config.resolved_sha256)
