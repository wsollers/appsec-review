"""Bounded Unity metadata discovery over accepted catalog descriptors, never a tree walk."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
import hashlib
import json
import math
from pathlib import PurePosixPath
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import yaml

from appsec_review.jobs.engine_contracts import (
    UNITY_FINGERPRINT_SCHEMA, UnityProject,
)
from appsec_review.storage import canonical_json


MAX_FILES = 16384
MAX_ROOTS = 256
MAX_DESCRIPTOR_BYTES = 262144
MAX_TOTAL_BYTES = 4194304
MAX_ITEMS = 4096
MAX_DEPTH = 24
MAX_FIELD_BYTES = 2048
_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[abfp]\d+(?:c\d+)?)?\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_NATIVE = (".dll", ".so", ".dylib", ".a", ".bundle")
_SETTINGS = frozenset({
    "scriptingBackend", "scriptingDefineSymbols", "additionalCompilerArguments",
    "apiCompatibilityLevel", "apiCompatibilityLevelPerPlatform", "scriptingRuntimeVersion",
    "selectedStandaloneTarget", "activeInputHandler", "managedStrippingLevel",
    "stripEngineCode", "allowUnsafeCode", "AndroidTargetArchitectures",
    "AndroidMinSdkVersion", "AndroidTargetSdkVersion", "iOSSDKVersion",
    "platformArchitecture", "iPhoneSdkVersion",
    "iOSTargetOSVersionString", "tvOSSDKVersion", "tvOSTargetOSVersionString",
    "scriptingEnabled", "scriptingStackTraceInformation", "il2cppCompilerConfiguration",
})
_SECRET = re.compile(r"password|passwd|secret|credential|token|license|api[_-]?key|authorization", re.I)
_UNORDERED = frozenset({
    "declarations", "resolutions", "embedded_packages", "plugins", "engine_context", "assemblies",
    "references", "includePlatforms", "excludePlatforms", "defineConstraints", "versionDefines",
    "precompiledReferences", "modules", "defines", "platformData",
})


def _ordered(value: Any, field: str = "") -> Any:
    def defines(item: str) -> list[str]:
        return sorted({part.strip() for part in item.split(";") if part.strip()})
    if isinstance(value, Mapping):
        if field == "scriptingDefineSymbols":
            return {key: defines(item) if isinstance(item, str) else _ordered(item, key)
                    for key, item in sorted(value.items())}
        return {key: _ordered(item, key) for key, item in sorted(value.items())}
    if isinstance(value, list):
        ordered = [_ordered(item) for item in value]
        if field in _UNORDERED:
            unique = {canonical_json(item): item for item in ordered}
            return [unique[key] for key in sorted(unique)]
        return ordered
    if field == "scriptingDefineSymbols" and isinstance(value, str):
        return defines(value)
    return value


def _public_string(value: str) -> str:
    """Keep package selectors useful without publishing URL credentials or query values."""
    if "://" in value:
        try:
            parts = urlsplit(value)
            host = parts.netloc.rsplit("@", 1)[-1]
            fragment = "" if _SECRET.search(parts.fragment) and "=" in parts.fragment else parts.fragment
            return urlunsplit((parts.scheme, host, parts.path, "", fragment))
        except ValueError:
            return "[redacted invalid URL]"
    if re.search(r"(?:password|secret|token|credential|license|api[_-]?key)\s*[=:]", value, re.I):
        return "[redacted credential-bearing value]"
    return value


def _public(value: Any, depth: int = 0, field: str = "") -> Any:
    if depth > MAX_DEPTH:
        raise ValueError("metadata nesting exceeds bound")
    if isinstance(value, Mapping):
        return {str(key): _public(item, depth + 1, key) for key, item in value.items()
                if isinstance(key, str) and (field == "dependencies" or not _SECRET.search(key))}
    if isinstance(value, list):
        result, redact_next = [], False
        for item in value:
            secret_argument = isinstance(item, str) and item.startswith("-") and _SECRET.search(item)
            result.append("[redacted credential argument]" if redact_next or secret_argument
                          else _public(item, depth + 1))
            redact_next = bool(secret_argument and "=" not in item)
        return result
    if isinstance(value, str):
        return _public_string(value)
    if value is None or type(value) in (bool, int, float):
        return value
    raise ValueError("metadata contains unsupported values")


def _bounded(value: Any) -> None:
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_ITEMS or depth > MAX_DEPTH:
            raise ValueError("metadata item/nesting bound exceeded")
        if isinstance(item, str) and len(item.encode("utf-8")) > MAX_FIELD_BYTES:
            raise ValueError("metadata field byte bound exceeded")
        if type(item) is float and not math.isfinite(item):
            raise ValueError("nonfinite metadata value")
        if isinstance(item, Mapping):
            if any(not isinstance(key, str) for key in item):
                raise ValueError("metadata keys must be strings")
            pending.extend((key, depth + 1) for key in item)
            pending.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)


def _json(text: str) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("nonfinite JSON value")

    value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
    _bounded(value)
    if not isinstance(value, dict):
        raise ValueError("descriptor must contain an object")
    return value


def _yaml(text: str, expected: str) -> dict[str, Any]:
    text = re.sub(r"^%.*\n", "", text, flags=re.M)
    text = re.sub(r"^--- !u!\d+.*$", "---", text, flags=re.M)
    for count, token in enumerate(yaml.scan(text)):
        if count > MAX_ITEMS * 4 or isinstance(token, (yaml.AliasToken, yaml.AnchorToken)):
            raise ValueError("YAML token/alias bound exceeded")
    value = yaml.safe_load(text)
    _bounded(value)
    if not isinstance(value, dict) or not isinstance(value.get(expected), dict):
        raise ValueError(f"descriptor lacks {expected}")
    return value[expected]


def _path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 1024:
        return None
    path = PurePosixPath(value)
    if (path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/"))
            or "\\" in value or ":" in value or any(ord(char) < 32 for char in value)):
        return None
    return path.as_posix()


def _root(path: str) -> str | None:
    for suffix in (
        "ProjectSettings/ProjectVersion.txt", "ProjectSettings/ProjectSettings.asset",
        "ProjectSettings/EditorBuildSettings.asset", "Packages/manifest.json",
        "Packages/packages-lock.json",
    ):
        if path == suffix or path.endswith("/" + suffix):
            return path[:-len(suffix)].rstrip("/") or "."
    return None


def _under(path: str, root: str) -> str | None:
    if root == ".":
        return path
    return path[len(root) + 1:] if path.startswith(root + "/") else None


def _descriptor(path: str) -> bool:
    return (_root(path) is not None or path.endswith((".asmdef", ".asmref", ".uproject", ".uplugin"))
            or path.endswith("package.json")
            or path.endswith(".meta") and path[:-5].lower().endswith(_NATIVE))


def discover_unity(
    files: Iterable[Mapping[str, Any]], *,
    read_text: Callable[[Mapping[str, Any], int], str | bytes],
) -> dict[str, Any]:
    """Read only accepted ``path/sha256/size_bytes`` descriptors via a bounded callback.

    The callback owns custody/path/symlink checks and receives ``(descriptor, max_bytes)``.
    Returned bytes are checked against the accepted identity before parsing. Text callbacks
    must preserve exact UTF-8 bytes (including newlines and a possible BOM).
    """
    gaps: list[str] = []
    catalog: dict[str, dict[str, Any]] = {}
    rejected: set[str] = set()
    counts = dict(catalog_files=0, eligible_descriptors=0, read_descriptors=0,
                  bytes_read=0, uninspected_descriptors=0, projects=0)
    for ordinal, item in enumerate(files):
        if ordinal >= MAX_FILES:
            gaps.append("catalog_file_limit: remaining accepted paths uninspected")
            break
        counts["catalog_files"] += 1
        if not isinstance(item, Mapping):
            gaps.append("invalid_catalog_descriptor")
            continue
        path, digest, size = _path(item.get("path")), item.get("sha256"), item.get("size_bytes")
        if (path is None or not isinstance(digest, str) or not _HASH.fullmatch(digest)
                or type(size) is not int or size < 0):
            gaps.append("invalid_catalog_descriptor: path/hash/size")
            continue
        record = {"path": path, "sha256": digest, "size_bytes": size}
        if path in rejected:
            continue
        if path in catalog and catalog[path] != record:
            gaps.append(f"conflicting_catalog_descriptor: {path}")
            rejected.add(path)
            del catalog[path]
        else:
            catalog[path] = record
    all_roots = sorted({root for path in catalog if (root := _root(path)) is not None})
    roots, omitted_roots = all_roots[:MAX_ROOTS], all_roots[MAX_ROOTS:]
    counts.update(roots_observed=len(all_roots), roots_inspected=len(roots),
                  uninspected_roots=len(omitted_roots))
    if omitted_roots:
        gaps.append(f"unity_root_limit: {len(omitted_roots)} candidate roots uninspected")
    parsed: dict[str, Any] = {}
    failures: dict[str, str] = {}
    for path, record in sorted(catalog.items()):
        if not _descriptor(path):
            continue
        if (descriptor_root := _root(path)) is not None and descriptor_root not in roots:
            continue
        # A package.json is relevant only within an independently identified candidate root.
        if path.endswith("package.json") and not any(
                (relative := _under(path, root)) is not None
                and relative.startswith(("Packages/", "Assets/")) for root in roots):
            continue
        counts["eligible_descriptors"] += 1
        failure_kind = "descriptor_uninspected_byte_bound"
        try:
            size = record["size_bytes"]
            if size > MAX_DESCRIPTOR_BYTES or counts["bytes_read"] + size > MAX_TOTAL_BYTES:
                counts["uninspected_descriptors"] += 1
                raise ValueError("descriptor byte bound exceeded; content uninspected")
            failure_kind = "descriptor_read_unavailable"
            payload = read_text(dict(record), min(MAX_DESCRIPTOR_BYTES, MAX_TOTAL_BYTES - counts["bytes_read"]))
            failure_kind = "descriptor_identity_changed"
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            if not isinstance(payload, bytes):
                raise ValueError("descriptor reader did not return UTF-8 bytes/text")
            counts["bytes_read"] += len(payload)
            counts["read_descriptors"] += 1
            if len(payload) != size or hashlib.sha256(payload).hexdigest() != record["sha256"]:
                raise ValueError("accepted descriptor hash/size changed")
            failure_kind = "descriptor_invalid_content"
            text = payload.decode("utf-8-sig", errors="strict")
            if path.endswith("ProjectVersion.txt"):
                fields = {}
                for line in text.splitlines():
                    if not line.strip():
                        continue
                    key, separator, value = line.partition(":")
                    if not separator or key in fields:
                        raise ValueError("invalid or duplicate editor version field")
                    fields[key] = value.strip()
                _bounded(fields)
                version = fields.get("m_EditorVersion", "")
                if not _VERSION.fullmatch(version):
                    raise ValueError("invalid Unity editor version")
                revision = None
                if "m_EditorVersionWithRevision" in fields:
                    match = re.fullmatch(re.escape(version) + r" \(([a-fA-F0-9]{6,64})\)",
                                         fields["m_EditorVersionWithRevision"])
                    if not match:
                        raise ValueError("editor version/revision disagree")
                    revision = match[1]
                parsed[path] = {"declared_version": version, "declared_revision": revision}
            elif path.endswith("ProjectSettings.asset"):
                parsed[path] = _yaml(text, "PlayerSettings")
            elif path.endswith("EditorBuildSettings.asset"):
                parsed[path] = _yaml(text, "EditorBuildSettings")
            elif path.endswith(".meta"):
                parsed[path] = _yaml(text, "PluginImporter")
            else:
                parsed[path] = _json(text)
        except (ValueError, OSError, RuntimeError, yaml.YAMLError, RecursionError) as exc:
            reason = (f"descriptor_unavailable_invalid_or_uninspected: {path}: "
                      f"{failure_kind} ({type(exc).__name__})")
            failures[path] = reason
            gaps.append(reason)
    observations: list[dict[str, Any]] = [
        {"kind": "unity", "root": root, "root_state": "uninspected", "engine_conflict": False,
         "gaps": ["unity_root_limit: content not inspected"]}
        for root in omitted_roots
    ]
    projects: list[UnityProject] = []
    for root in roots:
        prefix = "" if root == "." else root + "/"
        local_gaps = [reason for path, reason in failures.items() if _under(path, root) is not None]
        version_path = prefix + "ProjectSettings/ProjectVersion.txt"
        settings_path = prefix + "ProjectSettings/ProjectSettings.asset"
        manifest_path = prefix + "Packages/manifest.json"
        lock_path = prefix + "Packages/packages-lock.json"
        version, settings, manifest, lock = (
            parsed.get(path) for path in (version_path, settings_path, manifest_path, lock_path)
        )
        manifest_ok = isinstance(manifest, dict) and isinstance(manifest.get("dependencies"), dict)
        if manifest_ok:
            manifest_ok = all(_NAME.fullmatch(name) and isinstance(request, str) and request
                              for name, request in manifest["dependencies"].items())
        if manifest is not None and not manifest_ok:
            local_gaps.append(f"invalid_manifest_dependencies: {manifest_path}")
        conflicts = [catalog[path] for path in sorted(catalog)
                     if path.endswith((".uproject", ".uplugin"))
                     and str(PurePosixPath(path).parent) == root]
        valid = version is not None and (settings is not None or manifest_ok)
        state = "ambiguous" if valid and conflicts else "validated" if valid else "incomplete"
        if not valid:
            local_gaps.append(f"incomplete_unity_root: {root}: valid editor version and settings/manifest required")
        if conflicts:
            local_gaps.append(f"competing_engine_descriptors: {root}: Unity and Unreal; execution ambiguous")
        # The package lock is read (``lock_inspected``) but is context the editor regenerates, never a
        # marker of the project (plan §2.1 item 5).
        markers = [catalog[path] for path in sorted(catalog)
                   if _root(path) == root and not path.endswith("Packages/packages-lock.json")]
        observation = {"root": root, "kind": "unity", "root_state": state,
                       "engine_conflict": bool(conflicts), "markers": markers,
                       "competing_markers": conflicts, "gaps": sorted(set(local_gaps))}
        observations.append(observation)
        if not valid:
            gaps.extend(local_gaps)
            continue
        inventory: dict[str, Any] = {
            "declarations": [], "resolutions": [], "embedded_packages": [],
            "plugins": [], "engine_context": [], "assemblies": [],
        }
        if manifest_ok:
            for name, requested in sorted(manifest["dependencies"].items()):
                declaration = {"name": name, "requested": _public_string(requested),
                               "evidence": catalog[manifest_path]}
                if name.startswith("com.unity.modules."):
                    inventory["engine_context"].append({**declaration, "kind": "builtin"})
                else:
                    inventory["declarations"].append(declaration)
        else:
            local_gaps.append(f"dependency_declarations_unavailable: {root}")
        lock_ok = isinstance(lock, dict) and isinstance(lock.get("dependencies"), dict)
        if lock_ok:
            for name, entry in sorted(lock["dependencies"].items()):
                if (not _NAME.fullmatch(name) or not isinstance(entry, dict)
                        or not isinstance(entry.get("version"), str) or not entry["version"]
                        or not isinstance(entry.get("source", "unknown"), str)
                        or not isinstance(entry.get("dependencies", {}), dict)
                        or any(not _NAME.fullmatch(child) or not isinstance(request, str)
                               for child, request in entry.get("dependencies", {}).items())):
                    local_gaps.append(f"invalid_lock_entry: {lock_path}: {name}")
                    continue
                resolution = {
                    "name": name, "version": _public_string(entry["version"]),
                    "source": _public_string(str(entry.get("source", "unknown"))),
                    "depth": entry.get("depth") if type(entry.get("depth")) is int else None,
                    "dependencies": {child: _public_string(request)
                                     for child, request in entry.get("dependencies", {}).items()},
                    "revision": (entry["hash"] if isinstance(entry.get("hash"), str)
                                 and re.fullmatch(r"[a-fA-F0-9]{40,64}", entry["hash"]) else None),
                    "evidence": catalog[lock_path],
                }
                if name.startswith("com.unity.modules.") or entry.get("source") == "builtin":
                    inventory["engine_context"].append({**resolution, "kind": "builtin"})
                else:
                    inventory["resolutions"].append(resolution)
        else:
            local_gaps.append(f"dependency_resolution_unavailable: {lock_path}")
        builtin_names = {item["name"] for item in inventory["engine_context"]}
        for item in list(inventory["declarations"]):
            if item["name"] in builtin_names:
                inventory["declarations"].remove(item)
                inventory["engine_context"].append({**item, "kind": "builtin"})
        raw_settings = _public({key: value for key, value in (settings or {}).items() if key in _SETTINGS})
        scenes = []
        build_settings_path = prefix + "ProjectSettings/EditorBuildSettings.asset"
        build_settings = parsed.get(build_settings_path)
        if build_settings is not None:
            scenes = _public(build_settings.get("m_Scenes", []))
        for path, value in sorted(parsed.items()):
            relative = _under(path, root)
            if relative is None or not relative.startswith(("Assets/", "Packages/")):
                continue
            # Nested independently identified projects retain their own inventories.
            if any(other != root and _under(path, other) is not None
                   and _under(other, root) is not None for other in all_roots):
                continue
            if path.endswith((".asmdef", ".asmref")):
                for field in ("includePlatforms", "excludePlatforms"):
                    if field in value and (
                            not isinstance(value[field], list) or
                            any(not isinstance(item, str) for item in value[field])):
                        local_gaps.append(f"invalid_assembly_platform_filter: {path}: {field}")
                inventory["assemblies"].append({
                    "path": path, "evidence": catalog[path],
                    "facts": _public({key: value[key] for key in (
                        "name", "reference", "references", "includePlatforms", "excludePlatforms",
                        "defineConstraints", "versionDefines", "autoReferenced", "overrideReferences",
                        "precompiledReferences", "allowUnsafeCode",
                    ) if key in value}),
                })
            elif path.endswith(".meta"):
                companion = path[:-5]
                if companion not in catalog:
                    local_gaps.append(f"plugin_binary_not_cataloged: {companion}")
                    continue
                inventory["plugins"].append({
                    "path": companion, "name": PurePosixPath(companion).name,
                    "evidence": catalog[path],
                    "importer": _public({key: value[key] for key in (
                        "platformData", "isPreloaded", "isOverridable", "isExplicitlyReferenced",
                        "validateReferences",
                    ) if key in value}),
                })
            elif path.endswith("/package.json"):
                parts = PurePosixPath(relative).parts
                embedded = len(parts) == 3 and parts[0] == "Packages"
                content_identified = isinstance(value.get("unity"), str) or value.get("type") == "asset"
                name, release = value.get("name"), value.get("version")
                if (not (embedded or content_identified) or not isinstance(name, str)
                        or not _NAME.fullmatch(name) or "." not in name
                        or not isinstance(release, str) or not release):
                    local_gaps.append(f"unidentified_package_metadata: {path}")
                    continue
                dependencies = value.get("dependencies", {})
                if not isinstance(dependencies, dict) or any(
                        not _NAME.fullmatch(child) or not isinstance(request, str)
                        for child, request in dependencies.items()):
                    local_gaps.append(f"invalid_embedded_dependencies: {path}")
                    dependencies = {}
                inventory["embedded_packages"].append({
                    "name": name, "version": _public_string(release), "path": path,
                    "kind": "embedded" if embedded else "content-only",
                    "dependencies": {child: _public_string(request)
                                     for child, request in dependencies.items()},
                    "evidence": catalog[path],
                })
        embedded_names = Counter(item["name"] for item in inventory["embedded_packages"])
        for name, count in sorted(embedded_names.items()):
            if count > 1:
                local_gaps.append(f"competing_embedded_package_metadata: {root}: {name}")
        locked_versions = {item["name"]: item["version"] for item in inventory["resolutions"]}
        for item in inventory["embedded_packages"]:
            if item["name"] in locked_versions and item["version"] != locked_versions[item["name"]]:
                local_gaps.append(f"dependency_version_conflict: {root}: {item['name']}")
        project: UnityProject = {
            "root": root, "engine": {"kind": "unity", **version}, "markers": markers,
            "descriptor_facts": {
                "root_state": state, "engine_conflict": bool(conflicts),
                "competing_markers": conflicts, "raw_settings": raw_settings, "scenes": scenes,
                "manifest_inspected": bool(manifest_ok), "lock_inspected": bool(lock_ok),
            },
            "inventory": inventory, "gaps": sorted(set(local_gaps)),
        }
        projects.append(project)
        observation["gaps"] = project["gaps"]
        gaps.extend(local_gaps)
    for path in sorted(catalog):
        if path.endswith((".uproject", ".uplugin")):
            observations.append({"kind": "unreal", "root": str(PurePosixPath(path).parent),
                                 "marker": catalog[path], "root_state": "observed_not_supported"})
    counts["projects"] = len(projects)
    return {"projects": projects, "observations": observations,
            "gaps": sorted(set(gaps)), "counts": counts}


def unity_configuration_fingerprint(
    project: UnityProject, source_fingerprint: str, build_inputs: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Fingerprint configuration claims, not descriptor bytes or a claim of executed builds."""
    _bounded(build_inputs or {})
    supplied = _public(dict(build_inputs or {}))
    _bounded(supplied)
    inventory = project["inventory"]
    declarations = inventory.get("declarations", [])
    resolved = {item["name"] for item in (
        *inventory.get("resolutions", []), *inventory.get("embedded_packages", []))}
    def known(value):
        if value is None:
            return False
        if isinstance(value, str):
            return value.strip().casefold() not in {"", "unknown", "noassertion", "unspecified"}
        return bool(value) if isinstance(value, (Mapping, list)) else True
    unknown = [key for key in ("recipe", "toolchain", "target_platform", "architecture", "scripting_backend", "sdk")
               if not known(supplied.get(key))]
    if not isinstance(source_fingerprint, str) or not _HASH.fullmatch(source_fingerprint):
        unknown.append("source_snapshot")
    if not project["engine"].get("declared_version"):
        unknown.append("editor_version")
    if not project["engine"].get("declared_revision"):
        unknown.append("editor_revision")
    if not project["descriptor_facts"].get("raw_settings"):
        unknown.append("project_settings")
    if not project["descriptor_facts"].get("manifest_inspected"):
        unknown.append("dependency_declarations")
    if any(item["name"] not in resolved for item in declarations):
        unknown.append("dependency_resolution")
    for item in inventory.get("resolutions", []):
        if item.get("source") == "git" and not item.get("revision"):
            unknown.append("dependency_revision:" + item["name"])
        if item.get("source") in {None, "", "unknown"}:
            unknown.append("dependency_source:" + item["name"])
    for item in inventory.get("plugins", []):
        if not known(item.get("version")):
            unknown.append("plugin_version:" + item["path"])
        if not known(item.get("provenance")):
            unknown.append("plugin_provenance:" + item["path"])
    if project["descriptor_facts"].get("engine_conflict"):
        unknown.append("engine_identity")
    if project["gaps"]:
        unknown.append("metadata_coverage")
    # Descriptor hashes locate evidence; they do not stand in for package or build identity.
    def without_evidence(value):
        if isinstance(value, Mapping):
            return {key: without_evidence(item) for key, item in value.items()
                    if key not in {"evidence", "markers", "competing_markers"}}
        if isinstance(value, list):
            return [without_evidence(item) for item in value]
        return value
    inputs = _ordered(_public({
        "root": project["root"], "engine": project["engine"],
        "source_snapshot": source_fingerprint if isinstance(source_fingerprint, str)
        and _HASH.fullmatch(source_fingerprint) else None,
        "settings": project["descriptor_facts"].get("raw_settings", {}),
        "scenes": project["descriptor_facts"].get("scenes", []),
        "inventory": without_evidence(inventory), "build_inputs": supplied,
    }))
    unknown = sorted(set(unknown))
    return {"schema": UNITY_FINGERPRINT_SCHEMA,
            "sha256": hashlib.sha256(canonical_json({"schema": UNITY_FINGERPRINT_SCHEMA,
                                                    "inputs": inputs,
                                                    "unknown_inputs": unknown})).hexdigest(),
            "status": "partial" if unknown else "complete", "unknown_inputs": unknown, "inputs": inputs}
