"""Configured Unity BuildPlayer execution in the shared immutable container boundary."""
from __future__ import annotations

from collections.abc import Mapping
from concurrent.futures import CancelledError
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import time
from typing import Any

from appsec_review.config.unity import UnityBuildSettings, VERSION
from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.artifact_kinds import binary_role
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.review.secret_redaction import redact_source_line
from appsec_review.runtime import UnitContext
from appsec_review.runtime import execution_safety as safety
from appsec_review.signing.core import SignatureVerificationError
from appsec_review.storage import atomic_json, canonical_json, file_sha256


RECEIPT_SCHEMA = "appsec-review/language-build-receipt/1"
EXECUTOR_IDENTITY = "appsec-review/unity-build-executor/1"
_CLI_TARGET = {
    "StandaloneLinux64": "Linux64", "StandaloneWindows64": "Win64",
    "Android": "Android", "WebGL": "WebGL",
}
_PLATFORMS = {
    "StandaloneLinux64": {"x86_64": {"Mono", "IL2CPP"}},
    "StandaloneWindows64": {"x86_64": {"Mono"}},
    "Android": {"arm64": {"IL2CPP"}, "armv7": {"Mono", "IL2CPP"}},
    "WebGL": {"wasm32": {"IL2CPP"}},
}
_SECRET_LINE = re.compile(
    r"(?i)(license|licensing|serial|password|passwd|secret|token|credential|authorization|cookie"
    r"|https?://[^/\s]+@|[A-Z0-9]{4}(?:-[A-Z0-9]{4}){3,}"
    r"|gh[opusr]_[A-Za-z0-9]{10,}|github_pat_|eyJ[A-Za-z0-9_-]+\.)"
)


class _UnityError(ValueError):
    """A fixed, credential-free executor diagnostic."""


# The bridge is injected only into the run-owned copy. It does not change player
# settings: mismatched backend/architecture are a blocked preflight, not a repair.
_BRIDGE = r"""using System;
using System.Linq;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;

public static class APPSEC_CLASS
{
    [Serializable] private class Facts {
        public string token, editor_version, editor_full_version, target, architecture, scripting_backend;
        public bool license_ready, module_ready;
    }
    private static string Env(string name) { return Environment.GetEnvironmentVariable(name); }
    private static Facts ReadFacts() {
        var target = (BuildTarget)Enum.Parse(typeof(BuildTarget), Env("APPSEC_UNITY_TARGET"));
        var group = BuildPipeline.GetBuildTargetGroup(target);
#if UNITY_2021_2_OR_NEWER
        var backend = PlayerSettings.GetScriptingBackend(NamedBuildTarget.FromBuildTargetGroup(group));
#else
        var backend = PlayerSettings.GetScriptingBackend(group);
#endif
        string architecture = target == BuildTarget.WebGL ? "wasm32" : "x86_64";
        if (target == BuildTarget.Android) {
            var android = PlayerSettings.Android.targetArchitectures;
            architecture = android == AndroidArchitecture.ARM64 ? "arm64" :
                android == AndroidArchitecture.ARMv7 ? "armv7" : "unsupported-or-multiple";
        }
        return new Facts {
            token = Env("APPSEC_UNITY_TOKEN"), editor_version = Application.unityVersion,
            editor_full_version = UnityEditorInternal.InternalEditorUtility.GetFullUnityVersion(),
            target = EditorUserBuildSettings.activeBuildTarget.ToString(), architecture = architecture,
            scripting_backend = backend == ScriptingImplementation.Mono2x ? "Mono" :
                backend == ScriptingImplementation.IL2CPP ? "IL2CPP" : "unsupported",
            // Reaching an executeMethod in a normal batch editor startup requires
            // successful editor licensing; no activation/serial flags are supplied.
            license_ready = true, module_ready = BuildPipeline.IsBuildTargetSupported(group, target)
        };
    }
    public static void Preflight() {
        try {
            Console.WriteLine("APPSEC_UNITY_PREFLIGHT " + JsonUtility.ToJson(ReadFacts()));
            EditorApplication.Exit(0);
        } catch (Exception) { EditorApplication.Exit(21); }
    }
    public static void Build() {
        try {
            var facts = ReadFacts();
            if (!facts.module_ready || !facts.license_ready ||
                facts.target != Env("APPSEC_UNITY_TARGET") ||
                facts.architecture != Env("APPSEC_UNITY_ARCHITECTURE") ||
                facts.scripting_backend != Env("APPSEC_UNITY_BACKEND") ||
                facts.editor_version != Env("APPSEC_UNITY_VERSION")) {
                EditorApplication.Exit(22); return;
            }
            var scenes = EditorBuildSettings.scenes.Where(scene => scene.enabled)
                .Select(scene => scene.path).ToArray();
            if (scenes.Length == 0) { EditorApplication.Exit(23); return; }
            var report = BuildPipeline.BuildPlayer(new BuildPlayerOptions {
                scenes = scenes, locationPathName = Env("APPSEC_UNITY_OUTPUT"),
                target = (BuildTarget)Enum.Parse(typeof(BuildTarget), Env("APPSEC_UNITY_TARGET")),
                options = BuildOptions.None
            });
            EditorApplication.Exit(report.summary.result == BuildResult.Succeeded ? 0 : 24);
        } catch (Exception) { EditorApplication.Exit(25); }
    }
}
"""


def _engine(action: Mapping[str, Any]) -> dict[str, Any]:
    project = action.get("engine_project", {})
    value = action.get("engine", project.get("engine", {}) if isinstance(project, Mapping) else {})
    if not isinstance(value, Mapping):
        return {"kind": "unity"}
    return {key: value[key] for key in ("kind", "declared_version", "declared_revision")
            if isinstance(value.get(key), str) and re.fullmatch(r"[A-Za-z0-9._-]{1,80}", value[key])}


def _facts(action: Mapping[str, Any]) -> dict[str, Any]:
    project = action.get("engine_project", {})
    inherited = project.get("descriptor_facts", {}) if isinstance(project, Mapping) else {}
    direct = action.get("descriptor_facts", {})
    facts = {**(dict(inherited) if isinstance(inherited, Mapping) else {}),
             **(dict(direct) if isinstance(direct, Mapping) else {})}
    if isinstance(inherited, Mapping) and inherited.get("engine_conflict"):
        facts["engine_conflict"] = True
    if isinstance(inherited, Mapping) and inherited.get("root_state") == "ambiguous":
        facts["root_state"] = "ambiguous"
    return facts


def _gates(action: Mapping[str, Any], settings: UnityBuildSettings) -> list[str]:
    missing = [name for name in ("tag", "image_id", "user", "editor_version", "editor_executable",
                                "target", "architecture", "scripting_backend", "output_path")
               if not getattr(settings, name)]
    gaps = [f"Unity configured capability is missing: {name}" for name in missing]
    if not settings.license_ready:
        gaps.append("Unity license readiness was not declared; no license acquisition is attempted")
    if settings.target not in settings.modules:
        gaps.append("Unity target module readiness was not declared")
    if settings.target in {"iOS", "tvOS", "StandaloneOSX"}:
        gaps.append(f"Unity {settings.target} build is unavailable in the Linux container; source inventory remains available")
    elif settings.target and settings.architecture and settings.scripting_backend and (
            settings.scripting_backend not in _PLATFORMS.get(settings.target, {}).get(settings.architecture, set())):
        gaps.append("Unity configured target/architecture/backend combination is unsupported on Linux")
    if settings.editor_version and int(settings.editor_version.split(".", 1)[0]) < 2021:
        gaps.append("Unity bridge requires editor 2021.3 or newer")
    if settings.editor_version.startswith("2021.") and not settings.editor_version.startswith("2021.3."):
        gaps.append("Unity bridge requires editor 2021.3 or newer")
    engine = _engine(action)
    if engine.get("kind") != "unity":
        gaps.append("Unity engine authority is missing or conflicting")
    declared = engine.get("declared_version")
    if not declared:
        gaps.append("Unity declared project editor version is unavailable")
    elif declared != settings.editor_version:
        gaps.append("Unity declared project editor version does not match configured editor version")
    revision = engine.get("declared_revision")
    if revision and revision != settings.editor_revision:
        gaps.append("Unity declared project editor revision does not match configured editor revision")
    project = action.get("engine_project", {})
    project_engine = project.get("engine", {}) if isinstance(project, Mapping) else {}
    if isinstance(project_engine, Mapping) and any(
            project_engine.get(key) is not None and engine.get(key) != project_engine[key]
            for key in ("kind", "declared_version", "declared_revision")):
        gaps.append("Unity action and project engine authority conflict")
    facts = _facts(action)
    if isinstance(facts, Mapping):
        if facts.get("engine_conflict") or facts.get("root_state") == "ambiguous":
            gaps.append("Unity project engine authority is conflicting or ambiguous")
        for name, configured in (("target", settings.target), ("architecture", settings.architecture),
                                 ("scripting_backend", settings.scripting_backend)):
            if facts.get(name) and facts[name] != configured:
                gaps.append(f"Unity project {name} conflicts with configured capability")
    return gaps


def _identity(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _stream(run_root: Path, path: Path, result: Any, name: str, limit: int) -> dict[str, Any]:
    raw = bytes(getattr(result, name, b""))
    # Do not publish Unity licensing/client diagnostics, even if the image prints
    # credentials without the orchestrator supplying any.
    text = raw[:limit].decode("utf-8", "replace")
    clean = "\n".join(redact_source_line(line, whole_line=bool(_SECRET_LINE.search(line)))
                      for line in text.splitlines()).encode()[:limit]
    path.write_bytes(clean)
    path.chmod(0o600)
    original_count = getattr(result, f"{name}_bytes", None)
    count = len(raw) if original_count is None else int(original_count)
    return {**_identity(run_root, path), "byte_count": count, "retained_byte_count": len(clean),
            "capture_limit": limit, "captured_bytes": len(clean), "total_bytes": count,
            "capture_limit_bytes": limit, "truncated": bool(getattr(result, f"{name}_truncated", False))
            or count > limit, "redacted": clean != raw[:limit]}


def _manifest(workspace: Path, limit: int, *, gaps: list[str] | None = None) -> dict[str, str]:
    files = {}
    def unreadable(error: OSError) -> None:
        raise error

    for directory, directories, names in os.walk(workspace, followlinks=False, onerror=unreadable):
        for name in sorted([*directories, *names]):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                if gaps is None:
                    raise _UnityError("Unity workspace contains a symlink or nonregular output")
                if "Unity workspace excludes symlink or nonregular output" not in gaps:
                    gaps.append("Unity workspace excludes symlink or nonregular output")
                continue
            if stat.S_ISREG(mode):
                if len(files) >= limit:
                    if gaps is None:
                        raise _UnityError("Unity workspace file-count bound exceeded")
                    gaps.append("Unity workspace manifest file-count bound exceeded")
                    return files
                files[path.relative_to(workspace).as_posix()] = file_sha256(path)
    return files


def _managed_dll(path: Path) -> bool:
    """Check bounded PE/CLR headers, not a filename or an embedded BSJB string."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            return False
        pe_offset = struct.unpack_from("<I", dos, 60)[0]
        if not 64 <= pe_offset <= size - 24:
            return False
        stream.seek(pe_offset)
        pe = stream.read(24)
        sections = struct.unpack_from("<H", pe, 6)[0]
        optional_size, characteristics = struct.unpack_from("<HH", pe, 20)
        if (pe[:4] != b"PE\0\0" or not 1 <= sections <= 96
                or not characteristics & 0x2000 or not 2 <= optional_size <= 4096):
            return False
        optional = stream.read(optional_size)
        if len(optional) != optional_size:
            return False
        magic = struct.unpack_from("<H", optional)[0]
        directory = {0x10b: 96, 0x20b: 112}.get(magic)
        if (directory is None or len(optional) < directory + 15 * 8
                or struct.unpack_from("<I", optional, directory - 4)[0] < 15):
            return False
        cli_rva, cli_size = struct.unpack_from("<II", optional, directory + 14 * 8)
        table = stream.read(sections * 40)
        if len(table) != sections * 40 or cli_size < 72:
            return False

        def file_offset(rva: int, length: int) -> int | None:
            if not rva or length <= 0:
                return None
            for index in range(sections):
                address, raw_size, raw_offset = struct.unpack_from("<III", table, index * 40 + 12)
                delta = rva - address
                if 0 <= delta and delta + length <= raw_size and raw_offset + delta + length <= size:
                    return raw_offset + delta
            return None

        cli_offset = file_offset(cli_rva, 72)
        if cli_offset is None:
            return False
        stream.seek(cli_offset)
        cli = stream.read(72)
        if len(cli) != 72 or not 72 <= struct.unpack_from("<I", cli)[0] <= cli_size:
            return False
        metadata_rva, metadata_size = struct.unpack_from("<II", cli, 8)
        metadata_offset = file_offset(metadata_rva, metadata_size)
        if metadata_offset is None or metadata_size < 20:
            return False
        stream.seek(metadata_offset)
        header = stream.read(16)
        if len(header) != 16 or header[:4] != b"BSJB":
            return False
        version_size = struct.unpack_from("<I", header, 12)[0]
        return 0 < version_size <= min(1024, metadata_size - 20)


def _outputs(run_root: Path, workspace: Path, output: Path, limit: int, *,
             target: str, scripting_backend: str) -> list[dict[str, Any]]:
    if not output.exists() or output.is_symlink() or not output.resolve().is_relative_to(workspace.resolve()):
        raise _UnityError("Unity configured build output is missing or escaped the workspace")
    if output.is_file() and output.stat().st_size == 0:
        raise _UnityError("Unity configured player output is empty")
    # A standalone executable has adjacent player data and native libraries. Hash
    # the explicit output directory, not just its launcher's filename.
    output_root = output if output.is_dir() else output.parent
    artifacts = []
    pending = [output_root]
    examined = 0
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                examined += 1
                if examined > limit * 10:
                    raise _UnityError("Unity output directory-entry bound exceeded")
                path = Path(entry.path)
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISLNK(mode) or not path.resolve().is_relative_to(workspace.resolve()):
                    raise _UnityError("Unity build output contains a symlink or path escape")
                if stat.S_ISDIR(mode):
                    pending.append(path)
                    continue
                if not stat.S_ISREG(mode):
                    raise _UnityError("Unity build output is not a regular file")
                if len(artifacts) >= limit:
                    raise _UnityError("Unity output artifact-count bound exceeded")
                kind, container = binary_role(path)
                if path.suffix.lower() == ".dll" and _managed_dll(path):
                    kind, container = "managed-assembly", "pe"
                if path.suffix.lower() == ".apk":
                    kind, container = "android-apk", "zip"
                artifacts.append({**_identity(run_root, path), "kind": kind or "resource",
                                  "format": container, "workspace_path": path.relative_to(workspace).as_posix(),
                                  "mapping": "exact-workspace-path", "mapping_confidence": 1.0})
    if not artifacts or not any(item["size_bytes"] for item in artifacts):
        raise _UnityError("Unity configured build output contains no nonempty artifacts")
    if target.startswith("Standalone") and scripting_backend == "Mono":
        managed = output.parent / (output.stem + "_Data") / "Managed"
        if not output.is_file() or not any(
                item["kind"] == "managed-assembly" and item["size_bytes"] > 0
                and (workspace / item["workspace_path"]).is_relative_to(managed)
                for item in artifacts):
            raise _UnityError("Unity standalone Mono player is incomplete: adjacent player _Data/Managed DLL is missing")
    artifacts.sort(key=lambda item: item["workspace_path"])
    return artifacts


def execute_unity_build(unit: UnitContext, action: Mapping[str, Any], settings: UnityBuildSettings,
                        *, executor_factory=None) -> dict[str, Any]:
    """Execute a configured editor, not a capability probe promoted to build success."""
    identifier = action.get("build_unit_id")
    relative = action.get("root")
    if not isinstance(identifier, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier):
        raise ValueError("invalid Unity build_unit_id")
    if not isinstance(relative, str) or (relative != "." and (
            not relative or not re.fullmatch(r"[A-Za-z0-9_./-]+", relative)
            or PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts
            or PurePosixPath(relative).as_posix() != relative)):
        raise ValueError("invalid Unity build-unit root")
    if action.get("family") != "dotnet" or action.get("build_system") != "unity":
        raise ValueError("Unity execution requires an accepted dotnet/unity action")
    engine = _engine(action)
    fingerprint = hashlib.sha256(canonical_json({
        "schema": "appsec-review/unity-build-fingerprint/1",
        "source_fingerprint": unit.job.source_fingerprint, "root": relative,
        "build_unit_id": identifier, "engine": engine, "settings": settings.view(),
        "configuration_fingerprint": settings.identity,
    })).hexdigest()
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA, "executor_identity": EXECUTOR_IDENTITY,
        "source_fingerprint": unit.job.source_fingerprint, "build_unit_id": identifier,
        "family": "dotnet", "build_system": "unity", "root": relative, "engine": engine,
        "fingerprint": fingerprint, "settings_fingerprint": settings.identity,
        "probe_disposition": "COMPUTED", "terminal_status": "NOT_REQUESTED",
        "workspace": None, "image_id": settings.image_id or None,
        "commands": [], "artifacts": [], "gaps": [], "checkpoint_reused": False,
        "capture_provenance": {"complete": False, "compiler_execution_observed": False},
    }
    facts = _facts(action)
    configuration = action.get("configuration_fingerprint")
    if configuration is None and isinstance(facts, Mapping):
        configuration = facts.get("configuration_fingerprint")
    if configuration is not None:
        if (not isinstance(configuration, Mapping)
                or configuration.get("schema") != "appsec-review/unity-configuration-fingerprint/1"
                or not isinstance(configuration.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", configuration["sha256"])):
            raise ValueError("invalid Unity configuration fingerprint")
        # Inventory owns the document's schema and secret sanitization. Never
        # echo arbitrary caller-supplied inputs from an unverified document.
        receipt["configuration_fingerprint"] = {
            "schema": configuration["schema"], "sha256": configuration["sha256"],
            "status": "partial", "unknown_inputs": ["configured_inputs_not_recomputed"],
        }
    project_identity = action.get("engine_project")
    if isinstance(project_identity, Mapping):
        from appsec_review.jobs.engine_discovery import unity_configuration_fingerprint
        receipt["configuration_fingerprint"] = unity_configuration_fingerprint(
            project_identity, unit.job.source_fingerprint, {
                "toolchain": {"image_id": settings.image_id, "editor_version": settings.editor_version,
                              "editor_revision": settings.editor_revision, "modules": list(settings.modules)},
                "recipe": {"execute_method": settings.execute_method or "reviewed-run-owned-bridge",
                           "output_path": settings.output_path, "settings_sha256": settings.identity},
                "target_platform": settings.target or None,
                "scripting_backend": settings.scripting_backend or None,
            })
    if not settings.enabled:
        receipt["gaps"] = ["Unity build was not requested: configured execution is disabled"]
        return receipt
    receipt["gaps"] = _gates(action, settings)
    if receipt["gaps"]:
        receipt["terminal_status"] = "BLOCKED"
        return receipt
    root = unit.job.run_root / "data" / "build" / "probes" / identifier / "attempts" / unit.job.attempt_id / "unity"
    workspace = root / "workspace"
    commands = receipt["commands"]
    started_execution = False
    created_root = False
    stage = "workspace"
    try:
        safety.check_running()
        target = unit.job.target_root
        if target is None or target.is_symlink():
            raise _UnityError("Unity target root is unavailable or a symlink")
        if source_fingerprint(target) != unit.job.source_fingerprint:
            raise _UnityError("Unity target changed after the accepted source snapshot")
        source_root = target
        for part in PurePosixPath(relative).parts:
            source_root /= part
            if source_root.is_symlink():
                raise _UnityError("Unity source build-unit root contains a symlink")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", unit.job.attempt_id):
            raise _UnityError("Unity attempt identity is invalid")
        run_root = unit.job.run_root.resolve(strict=True)
        if target.resolve().is_relative_to(run_root) or run_root.is_relative_to(target.resolve()):
            raise _UnityError("Unity target and run roots must be disjoint")
        current = run_root
        for part in root.relative_to(unit.job.run_root).parts:
            current = current / part
            if current.is_symlink():
                raise _UnityError("Unity run-owned output path contains a symlink")
        root.mkdir(parents=True, exist_ok=False)
        created_root = True
        # Reuse the established source-root, symlink and bounded workspace guards.
        from appsec_review.jobs.job_project_build.job import _copy_source
        try:
            _copy_source(unit, action, workspace)
        except ValueError as error:
            if "symlink" in str(error):
                raise _UnityError("Unity source copy rejected an unsupported symlink") from error
            raise _UnityError("Unity source copy rejected an unsafe root or dependency") from error
        receipt["workspace"] = workspace.relative_to(unit.job.run_root).as_posix()
        project = workspace if relative == "." else workspace / relative
        output = project / settings.output_path
        if output.exists() or output.is_symlink():
            raise _UnityError("Unity configured build output already exists in copied source")
        if output.parent.exists() and any(output.parent.iterdir()):
            raise _UnityError("Unity configured output directory contains preexisting copied files")
        version_file = project / "ProjectSettings" / "ProjectVersion.txt"
        if not version_file.is_file() or version_file.stat().st_size > 65536:
            raise _UnityError("Unity project editor-version authority is unavailable")
        version_text = version_file.read_text(encoding="utf-8")
        source_version = re.findall(r"^m_EditorVersion:\s*(\S+)\s*$", version_text, re.MULTILINE)
        if source_version != [settings.editor_version]:
            raise _UnityError("Unity source editor-version authority does not match configured version")
        source_revisions = re.findall(r"^m_EditorVersionWithRevision:\s*(\S+)\s+\(([0-9a-f]+)\)\s*$",
                                      version_text, re.MULTILINE)
        if ("m_EditorVersionWithRevision:" in version_text and
                source_revisions != [(settings.editor_version, settings.editor_revision)]):
            raise _UnityError("Unity source editor-revision authority does not match configured revision")
        bridge_root = project / "Assets" / "Editor" / "AppSecReviewRunOwnedBridge"
        if bridge_root.exists() or bridge_root.is_symlink():
            raise _UnityError("Unity run-owned bridge would overwrite project source")
        bridge_root.mkdir(parents=True)
        bridge = bridge_root / "AppSecReviewRunOwnedBridge.cs"
        bridge_class = "AppSecReviewRunOwned_" + fingerprint[:16]
        bridge.write_text(_BRIDGE.replace("APPSEC_CLASS", bridge_class), encoding="utf-8")
        assembly = bridge_root / "AppSecReviewRunOwnedBridge.asmdef"
        atomic_json(assembly, {"name": bridge_class, "includePlatforms": ["Editor"],
                               "autoReferenced": True})
        receipt["prepared_inputs"] = [
            {**_identity(unit.job.run_root, path), "purpose": "reviewed-run-owned-unity-build-bridge"}
            for path in (bridge, assembly)]
        _manifest(workspace, settings.artifact_count_limit * 10)
        profile = BuildProfile("unity", settings.tag, settings.image_id, settings.user)
        stage = "image"
        executor = executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
            profile, timeout_seconds=settings.timeout_seconds, output_bytes=settings.output_bytes)
        try:
            executor.resolve()
        except SignatureVerificationError as error:
            raise _UnityError("Unity configured image signature verification failed") from error
        except (OSError, ValueError, RuntimeError) as error:
            raise _UnityError("Unity configured immutable image is unavailable or identity verification failed") from error
        environment = {
            "APPSEC_UNITY_TARGET": settings.target, "APPSEC_UNITY_ARCHITECTURE": settings.architecture,
            "APPSEC_UNITY_BACKEND": settings.scripting_backend,
            "APPSEC_UNITY_VERSION": settings.editor_version,
            "APPSEC_UNITY_OUTPUT": "/workspace/" + ("" if relative == "." else relative + "/") + settings.output_path,
            "APPSEC_UNITY_TOKEN": fingerprint,
        }
        logs = root / "logs"
        logs.mkdir()

        def invoke(name: str, argv: tuple[str, ...]) -> Any:
            nonlocal started_execution, stage
            stage = name
            safety.check_running()
            started = time.monotonic()
            command = {
                "ordinal": len(commands) + 1, "stage": name,
                "command_id": hashlib.sha256(canonical_json({
                    "attempt": unit.job.attempt_id, "unit": identifier, "stage": name,
                    "argv": list(argv),
                })).hexdigest(),
                "tool": PurePosixPath(settings.editor_executable).name,
                "tool_kind": "build-driver" if name == "build" else "toolchain-preflight",
                "build_unit_id": identifier, "attempt_identity": unit.job.attempt_id,
                "argv_sha256": hashlib.sha256(canonical_json(list(argv))).hexdigest(),
                "working_directory": relative, "image_id": settings.image_id,
                "environment_facts": {key: "set" for key in sorted(environment)},
                "exit_code": None, "timed_out": False, "cancelled": False,
            }
            commands.append(command)
            for stream in ("stdout", "stderr"):
                command[stream] = _stream(unit.job.run_root, logs / f"{name}.{stream}",
                                          None, stream, settings.output_bytes)
            try:
                started_execution = True
                result = executor.execute(argv, workspace=workspace, working_directory=relative,
                                          environment=environment)
            except (safety.ReviewStopped, CancelledError):
                command["cancelled"] = True
                raise
            finally:
                command["duration_ms"] = max(0, int((time.monotonic() - started) * 1000))
            command.update(exit_code=result.exit_code, timed_out=result.timed_out,
                           cancelled=bool(getattr(result, "cancelled", False)))
            for stream in ("stdout", "stderr"):
                command[stream] = _stream(unit.job.run_root, logs / f"{name}.{stream}",
                                          result, stream, settings.output_bytes)
            if command["cancelled"] or result.exit_code in {-2, -15, 130, 143}:
                command["cancelled"] = True
                raise CancelledError()
            if result.timed_out or result.exit_code != 0:
                raise _UnityError(f"Unity {name} {'timed out' if result.timed_out else 'exited unsuccessfully'}")
            return result

        version = invoke("editor-version", (settings.editor_executable, "-version", "-batchmode", "-nographics"))
        versions = set(VERSION.findall(version.stdout.decode("utf-8", "replace")))
        if versions != {settings.editor_version}:
            raise _UnityError("Unity actual editor version does not match configured version")
        common = (settings.editor_executable, "-batchmode", "-nographics", "-quit", "-projectPath",
                  "/workspace/" + ("" if relative == "." else relative),
                  "-buildTarget", _CLI_TARGET[settings.target], "-logFile", "-")
        preflight = invoke("preflight", (*common, "-executeMethod", bridge_class + ".Preflight"))
        records = [line.removeprefix("APPSEC_UNITY_PREFLIGHT ") for line in
                   preflight.stdout.decode("utf-8", "replace").splitlines()
                   if line.startswith("APPSEC_UNITY_PREFLIGHT ")]
        if len(records) != 1:
            raise _UnityError("Unity actual license/module/backend preflight evidence is unavailable")
        observed = json.loads(records[0])
        if not isinstance(observed, dict) or observed.get("token") != fingerprint:
            raise _UnityError("Unity preflight evidence identity does not match this build")
        for key, expected in (("editor_version", settings.editor_version), ("target", settings.target),
                              ("architecture", settings.architecture),
                              ("scripting_backend", settings.scripting_backend),
                              ("license_ready", True), ("module_ready", True)):
            if observed.get(key) != expected or type(observed.get(key)) is not type(expected):
                raise _UnityError(f"Unity actual {key} preflight does not match configured readiness")
        revision = settings.editor_revision
        if revision and not re.search(r"\(" + re.escape(revision) + r"\)",
                                      str(observed.get("editor_full_version", ""))):
            raise _UnityError("Unity actual editor revision does not match configured revision")
        receipt["preflight"] = {key: observed[key] for key in (
            "editor_version", "target", "architecture", "scripting_backend", "license_ready", "module_ready")}
        if revision:
            receipt["preflight"]["editor_revision"] = revision
        if output.exists() or output.is_symlink():
            raise _UnityError("Unity preflight unexpectedly created the configured build output")
        if output.parent.exists() and any(output.parent.iterdir()):
            raise _UnityError("Unity preflight unexpectedly populated the configured output directory")
        stage = "build"
        invoke("build", (*common, "-executeMethod", settings.execute_method or bridge_class + ".Build"))
        stage = "outputs"
        receipt["artifacts"] = _outputs(
            unit.job.run_root, workspace, output, settings.artifact_count_limit,
            target=settings.target, scripting_backend=settings.scripting_backend)
        for artifact in receipt["artifacts"]:
            artifact["build_unit_id"] = identifier
        if source_fingerprint(target) != unit.job.source_fingerprint:
            raise _UnityError("Unity original target changed during isolated execution")
        receipt["terminal_status"] = "SUCCEEDED"
    except safety.ReviewStopped:
        receipt["terminal_status"] = "CANCELLED"
        receipt["gaps"].append("Unity execution was stopped by the shared execution boundary")
        if safety.active():
            raise
    except CancelledError:
        receipt["terminal_status"] = "CANCELLED"
        receipt["gaps"].append("Unity execution was cancelled by the shared execution boundary")
    except (OSError, ValueError, RuntimeError, SignatureVerificationError) as error:
        receipt["terminal_status"] = "FAILED" if (
            stage in {"build", "outputs"} or any(command.get("timed_out") for command in commands)) else "BLOCKED"
        # Exception messages from a runner can contain credentials. Retain only
        # our local diagnostics; external failures are represented by their type.
        message = str(error) if isinstance(error, _UnityError) else f"Unity {stage} failed ({type(error).__name__})"
        receipt["gaps"].append(message)
        receipt["artifacts"] = []
    finally:
        if started_execution and workspace.is_dir() and not workspace.is_symlink():
            try:
                manifest = root / "workspace-manifest.json"
                manifest_gaps: list[str] = []
                files = _manifest(workspace, settings.artifact_count_limit * 10, gaps=manifest_gaps)
                atomic_json(manifest, {"schema": "appsec-review/build-workspace-manifest/1",
                                      "build_unit_id": identifier, "files": files,
                                      "complete": not manifest_gaps, "gaps": manifest_gaps})
                receipt["workspace_manifest"] = {
                    "schema": "appsec-review/build-workspace-manifest/1",
                    **_identity(unit.job.run_root, manifest),
                }
                if manifest_gaps:
                    receipt["gaps"].extend(manifest_gaps)
                    receipt["artifacts"] = []
                    if receipt["terminal_status"] == "SUCCEEDED":
                        receipt["terminal_status"] = "FAILED"
            except (OSError, ValueError):
                gap = "Unity workspace inventory is unavailable: unreadable or changing output"
                atomic_json(root / "workspace-manifest.json", {
                    "schema": "appsec-review/build-workspace-manifest/1",
                    "build_unit_id": identifier, "files": {}, "complete": False, "gaps": [gap],
                })
                receipt["workspace_manifest"] = {
                    "schema": "appsec-review/build-workspace-manifest/1",
                    **_identity(unit.job.run_root, root / "workspace-manifest.json"),
                }
                receipt["gaps"].append(gap)
                receipt["artifacts"] = []
                if receipt["terminal_status"] == "SUCCEEDED":
                    receipt["terminal_status"] = "FAILED"
        if started_execution:
            receipt["gaps"].append("Unity compiler/linker execution capture is not supported; command and output evidence only")
        if created_root:
            atomic_json(root / "receipt.json", receipt)
    return receipt
