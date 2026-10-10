from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import time
from typing import Any

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity,
    RelationKind, RelationRecord, index_fingerprint,
)
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256, protected_json


JVM_EXECUTOR_IDENTITY = "appsec-review/jvm-language-build-executor/1"
JVM_CAPTURE_IDENTITY = "appsec-review/jvm-build-capture/1"
JVM_RECEIPT_SCHEMA = "appsec-review/language-build-receipt/1"
_SECRET = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
_TOOLS = {
    "javac": "compiler", "kotlinc": "compiler", "kapt": "annotation-processor",
    "ksp": "code-generator", "java": "jvm-launcher", "jar": "archiver",
    "javadoc": "documentation-generator", "protoc": "code-generator",
}
_KIND_BY_SUFFIX = {
    ".class": "jvm-class", ".jar": "jar", ".war": "war", ".ear": "ear",
    ".java": "generated-java-source", ".kt": "generated-kotlin-source",
    ".kts": "generated-kotlin-source", ".kotlin_module": "kotlin-module-metadata",
    ".smap": "source-debug-map", ".map": "source-map", ".properties": "metadata",
    ".xml": "metadata", ".json": "metadata", ".proto": "generated-source",
}
_RESOURCE_NAMES = {"MANIFEST.MF", "pom.properties", "pom.xml", "module-info.class"}


class JvmIntegrityError(ValueError):
    """A changed accepted input or retained identity must stop publication."""


def validate_jvm_settings(settings: Mapping[str, Any]) -> None:
    jvm = settings.get("jvm")
    if not isinstance(jvm, Mapping):
        raise ValueError("language-build JVM settings are required")
    required = {"trace_bytes", "provenance_count_limit", "diagnostic_tail_bytes",
                "system_path", "tool_paths"}
    if set(jvm) != required:
        raise ValueError("language-build JVM settings fields are invalid")
    for key in ("trace_bytes", "provenance_count_limit", "diagnostic_tail_bytes"):
        if type(jvm.get(key)) is not int or int(jvm[key]) < 1:
            raise ValueError(f"language-build JVM bound is invalid: {key}")
    if not isinstance(jvm.get("system_path"), str) or not str(jvm["system_path"]).startswith("/"):
        raise ValueError("language-build JVM system_path is invalid")
    tools = jvm.get("tool_paths")
    if (not isinstance(tools, Mapping) or set(tools) != set(_TOOLS) or
            any(not isinstance(value, str) or not value.startswith("/") or "\0" in value
                for value in tools.values())):
        raise ValueError("language-build JVM tool paths are invalid")


def _jvm_argv(recipe: Mapping[str, Any], raw: list[str]) -> tuple[tuple[str, ...], str | None]:
    from .job import _normalized_argv

    requested = Path(str(raw[0])).name
    wrapper = requested if requested in {"mvnw", "gradlew"} else None
    argv = list(_normalized_argv(recipe, raw))
    if requested == "mvnw":
        argv[0], wrapper = "mvn", "mvnw"
    elif requested == "gradlew":
        argv[0], wrapper = "gradle", "gradlew"
    tool = Path(argv[0]).name
    lowered = [value.lower() for value in argv[1:]]
    if tool == "mvn":
        goals = [value for value in lowered if not value.startswith("-")]
        allowed_goals = {"clean", "compile", "package", "process-resources", "generate-sources",
                         "generate-resources", "jar:jar", "war:war"}
        if any(value not in allowed_goals for value in goals):
            raise JvmIntegrityError("accepted Maven command could execute tests or an application")
        if not any(value == "-dskiptests" or value.startswith("-dmaven.test.skip=true")
                   for value in lowered):
            raise JvmIntegrityError("accepted Maven build must explicitly disable tests")
    if tool == "gradle":
        tasks = [value for value in lowered if not value.startswith("-")]
        allowed_tasks = {"assemble", "classes", "jar", "war", "clean"}
        if any(value.rsplit(":", 1)[-1] not in allowed_tasks | {"build"} for value in tasks):
            raise JvmIntegrityError("accepted Gradle command could execute tests or an application")
        if "build" in tasks and not any(lowered[index:index + 2] == ["-x", "test"]
                                        for index in range(max(0, len(lowered) - 1))):
            raise JvmIntegrityError("accepted Gradle build must exclude the test task")
    return tuple(argv), wrapper


def _instrumentation(workspace: Path, source_dir: str, settings: Mapping[str, Any]) -> tuple[Path, str]:
    root = workspace / Path(*PurePosixPath(source_dir).parts) / ".appsec-review-jvm"
    binary, trace = root / "bin", root / "invocations.bin"
    binary.mkdir(parents=True, exist_ok=True)
    for tool, real in sorted(settings["tool_paths"].items()):
        script = binary / tool
        script.write_text(
            "#!/bin/sh\n"
            "trace=${APPSEC_JVM_TRACE:?}\n"
            f"printf '%s\\0%s\\0%s\\0' '{tool}' \"${{APPSEC_JVM_PARENT_COMMAND:-unknown}}\" \"$#\" >> \"$trace\"\n"
            "for arg in \"$@\"; do printf '%s\\0' \"$arg\" >> \"$trace\"; done\n"
            f"exec {shlex.quote(str(real))} \"$@\"\n", encoding="utf-8", newline="\n")
        script.chmod(0o700)
    logical = f"/workspace/{source_dir}/.appsec-review-jvm"
    return trace, logical


def _environment(recipe: Mapping[str, Any], workspace: Path, settings: Mapping[str, Any]) -> tuple[dict[str, str], Path]:
    from .job import _probe_environment

    environment = _probe_environment({**recipe, "build_system": recipe.get("build_system")})
    trace, logical = _instrumentation(workspace, str(recipe["source_dir"]), settings)
    environment["APPSEC_JVM_TRACE"] = logical + "/invocations.bin"
    environment["PATH"] = logical + "/bin:" + str(settings["system_path"])
    environment.setdefault("MAVEN_OPTS", "-Dmaven.repo.local=/opt/project-deps/maven")
    environment.setdefault("GRADLE_USER_HOME", "/opt/project-deps/gradle")
    return environment, trace


def _stream(run_root: Path, path: Path, result: Any, name: str, limit: int,
            tail_limit: int) -> dict[str, Any]:
    data = bytes(getattr(result, name))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    total_value = getattr(result, f"{name}_bytes", None)
    total = len(data) if total_value is None else int(total_value)
    truncated = bool(getattr(result, f"{name}_truncated", total > len(data)))
    value: dict[str, Any] = {"path": path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(path), "byte_count": total, "retained_byte_count": len(data),
        "capture_limit": limit, "truncated": truncated}
    tail = bytes(getattr(result, f"{name}_tail", b""))[-tail_limit:]
    if truncated and tail:
        tail_path = path.with_name(path.name + ".tail")
        tail_path.write_bytes(tail)
        try:
            tail_path.chmod(0o600)
        except OSError:
            pass
        value["diagnostic_tail"] = {"path": tail_path.relative_to(run_root).as_posix(),
            "sha256": file_sha256(tail_path), "byte_count": len(tail)}
    return value


def _trace_rows(trace: Path, workspace: Path, limit: int, byte_limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    if not trace.is_file():
        return [], ["nested JVM tool provenance was not emitted by the build"]
    data = trace.read_bytes()
    gaps: list[str] = []
    if len(data) > byte_limit:
        data = data[:byte_limit]
        gaps.append("JVM invocation trace exceeded its configured byte bound")
    fields = data.split(b"\0")
    rows, offset = [], 0
    while offset + 3 <= len(fields) and len(rows) < limit:
        try:
            tool = fields[offset].decode("utf-8", "replace")
            parent = fields[offset + 1].decode("ascii", "replace")
            count = int(fields[offset + 2].decode("ascii"))
        except (ValueError, UnicodeError):
            gaps.append("JVM invocation trace ended with an invalid record")
            break
        offset += 3
        if count < 0 or count > 4096 or offset + count > len(fields):
            gaps.append("JVM invocation trace ended with an incomplete record")
            break
        argv = [tool, *(value.decode("utf-8", "replace") for value in fields[offset:offset + count])]
        offset += count
        inputs, outputs = _paths(argv[1:])
        rows.append({"ordinal": len(rows) + 1, "tool": tool,
            "tool_kind": _TOOLS.get(tool, "jvm-tool"), "argv": argv,
            "parent_command_id": parent,
            "working_directory": ".", "inputs": _mapped(workspace, inputs),
            "outputs": _mapped(workspace, outputs), "mapping": "instrumented-tool-wrapper",
            "mapping_confidence": 1.0})
    if len(rows) >= limit and offset + 3 <= len(fields):
        gaps.append("JVM invocation trace exceeded its configured record bound")
    return rows, gaps


def _paths(args: list[str]) -> tuple[list[str], list[str]]:
    inputs, outputs = [], []
    for index, value in enumerate(args):
        suffix = Path(value).suffix.lower()
        if value in {"-d", "-s", "-h"} and index + 1 < len(args):
            outputs.append(args[index + 1])
        elif suffix in {".java", ".kt", ".kts", ".class", ".jar", ".proto"}:
            inputs.append(value)
        elif suffix in {".war", ".ear"}:
            outputs.append(value)
    return inputs, outputs


def _mapped(workspace: Path, values: list[str]) -> list[dict[str, Any]]:
    from .job import _mapped_files
    return _mapped_files(workspace, "/workspace", values)


def _artifact_kind(path: Path) -> str | None:
    if path.name in _RESOURCE_NAMES:
        return "dependency-metadata" if path.name.startswith("pom") else "jvm-resource"
    suffix = path.suffix.lower()
    kind = _KIND_BY_SUFFIX.get(suffix)
    if kind == "metadata" and not any(part in {"META-INF", "build", "target", "generated"}
                                       for part in path.parts):
        return None
    return kind


def _catalog(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int,
             build_unit_id: str) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts, gaps = [], []
    for path in sorted(workspace.rglob("*")):
        try:
            if path.is_symlink() or not path.is_file() or ".appsec-review-jvm" in path.parts:
                continue
        except OSError:
            continue
        relative, digest = path.relative_to(workspace).as_posix(), file_sha256(path)
        kind = _artifact_kind(path)
        if kind is None or before.get(relative) == digest:
            continue
        artifacts.append({"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
            "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind,
            "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
            "mapping_confidence": 1.0})
        if len(artifacts) >= limit:
            gaps.append("JVM artifact catalog truncated at configured count bound")
            break
    return artifacts, gaps


def _manifest(workspace: Path, limit: int) -> dict[str, str]:
    from .job import _snapshot
    return _snapshot(workspace, limit)


def _fingerprint(dispatch: Mapping[str, Any], accepted: Mapping[str, Any], settings: Mapping[str, Any]) -> str:
    image = dispatch["image"]
    return hashlib.sha256(canonical_json({"schema": JVM_RECEIPT_SCHEMA,
        "target": dispatch["source_fingerprint"], "recipe": dispatch["recipe_identity"],
        "dependencies": image["dependency_hashes"], "build_dependencies": dispatch.get("build_dependencies", ()),
        "image": image["image_id"], "executor": JVM_EXECUTOR_IDENTITY, "capture": JVM_CAPTURE_IDENTITY,
        "toolchain": {"family": "java", "image_id": image["image_id"], "settings": settings},
        "probe": dispatch["probe_identity"], "upstream_handoff": accepted["project_build_handoff_sha256"]
    })).hexdigest()


def _index(unit: Any, receipt: Mapping[str, Any]) -> dict[str, Any]:
    producer = [{"sha256": item["sha256"]} for item in receipt["artifacts"]]
    fingerprint = index_fingerprint(name="build", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=producer, tool_identity={"executor": JVM_EXECUTOR_IDENTITY,
        "image": receipt["image"]["image_id"]}, parser_identity="jvm-provenance/1",
        normalizer_identity="jvm-build-normalizer/1", mapping_identity="jvm-workspace-path/1")
    shard = "jvm-" + str(receipt["build_unit_id"])
    path = unit.job.run_root / "data" / "indices" / "build" / f"{fingerprint}-{shard}.sqlite"
    reused = path.is_file()
    if not reused:
        builder = IndexBuilder(path, name="build", fingerprint=fingerprint,
            target_snapshot=unit.job.source_fingerprint, shard_id=shard)
        action_ids = []
        action_by_command: dict[str, str] = {}
        for command in receipt["commands"]:
            identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                {"unit": receipt["build_unit_id"], "command": command["command_id"]})
            action_ids.append(identity.value)
            action_by_command[str(command["command_id"])] = identity.value
            payload = {key: command.get(key) for key in ("command_id", "ordinal", "tool", "tool_kind",
                "argv_sha256", "working_directory", "environment_facts", "exit_code", "timed_out",
                "duration_ms", "image_id", "attempt_identity", "wrapper_resolution")}
            builder.add_entity(EntityRecord(identity, command["command_id"], command["tool"],
                f"{command['tool_kind']} {receipt['build_system']} build action", payload))
        for invocation in receipt["tool_invocations"]:
            identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                {"unit": receipt["build_unit_id"], "parent": invocation["parent_command_id"],
                 "ordinal": invocation["ordinal"], "tool": invocation["tool"],
                 "argv_sha256": invocation["argv_sha256"]})
            payload = {key: invocation.get(key) for key in ("ordinal", "tool", "tool_kind",
                "argv_sha256", "parent_command_id", "working_directory", "inputs", "outputs",
                "mapping", "mapping_confidence")}
            builder.add_entity(EntityRecord(identity, invocation["argv_sha256"], invocation["tool"],
                f"observed {invocation['tool_kind']} invocation", payload))
            parent = action_by_command.get(str(invocation["parent_command_id"]))
            if parent:
                builder.add_relation(RelationRecord(RelationKind.DEPENDS_ON, identity.value,
                                                     parent, True, 1.0))
        for artifact in receipt["artifacts"]:
            kind = EntityKind.LIBRARY if artifact["kind"] in {"jar", "war", "ear"} else EntityKind.EVIDENCE_ARTIFACT
            identity = LogicalIdentity.derive(kind, unit.job.source_fingerprint,
                {"unit": receipt["build_unit_id"], "path": artifact["workspace_path"],
                 "sha256": artifact["sha256"]})
            builder.add_entity(EntityRecord(identity, artifact["sha256"],
                PurePosixPath(artifact["workspace_path"]).name,
                f"{artifact['kind']} {artifact['workspace_path']}",
                {key: artifact[key] for key in ("workspace_path", "sha256", "size_bytes", "kind",
                                                 "build_unit_id", "mapping", "mapping_confidence")}))
            for action_id in action_ids:
                builder.add_relation(RelationRecord(RelationKind.GENERATED_FROM, identity.value,
                                                     action_id, True, 1.0))
        builder.add_coverage("jvm-build", "complete" if receipt["terminal_status"] == "SUCCEEDED" else "partial",
                             None if receipt["terminal_status"] == "SUCCEEDED" else "; ".join(receipt["gaps"][:10]))
        sha = builder.build()
    else:
        sha = file_sha256(path)
    identity = IndexIdentity("build", "appsec-review/retrieval-index/2", sha, fingerprint,
        path.relative_to(unit.job.run_root).as_posix(),
        {"job": "job_language_build", "unit": unit.unit_id, "family": "java"},
        tuple(receipt["gaps"]), shard)
    return {"identity": asdict(identity), "reused": reused}


def execute_jvm_one(unit: Any, dispatch: Mapping[str, Any], accepted: Mapping[str, Any],
                    executor_factory: Any = None) -> dict[str, Any]:
    from .job import _copy_source

    build_unit_id, recipe, image = str(dispatch["build_unit_id"]), dispatch["recipe"], dispatch["image"]
    settings = unit.job.config.settings["jvm"]
    artifact_overrides = unit.job.config.settings.get("compiler_artifact_collection_overrides", {})
    capture = unit.job.config.settings.get("build_capture", {})
    fingerprint = _fingerprint(dispatch, accepted, {
        **settings,
        "processing_modes": {
            "build_execution_capture": capture.get("mode", "required"),
            "compiler_artifact_collection": artifact_overrides.get(
                "java", unit.job.config.settings.get(
                    "compiler_artifact_collection_mode", "required")),
        },
    })
    root = unit.job.run_root / "data" / "build" / "jvm" / "units" / build_unit_id
    workspace = root / "workspace"
    cache = unit.job.metadata_root / "language-builds" / "jvm" / fingerprint / "accepted.json"
    with FileLock(cache.parent / "build.lock"):
        if cache.is_file():
            prior = json.loads(cache.read_text(encoding="utf-8"))
            if prior.get("fingerprint") != fingerprint or prior.get("terminal_status") != "SUCCEEDED":
                raise JvmIntegrityError("JVM checkpoint identity is invalid")
            prior_workspace = Path(str(prior.get("workspace", "")))
            if not prior_workspace.is_dir() or prior_workspace.is_symlink():
                raise JvmIntegrityError("JVM checkpoint workspace is unavailable")
            if prior_workspace.resolve() != workspace.resolve():
                if root.exists():
                    shutil.rmtree(root)
                shutil.copytree(prior_workspace.parent, root)
            expected = prior.get("workspace_files")
            if not isinstance(expected, Mapping) or _manifest(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10) != expected:
                raise JvmIntegrityError("JVM checkpoint workspace identity changed")
            receipt = {**prior["receipt"], "workspace": workspace.relative_to(unit.job.run_root).as_posix(),
                       "checkpoint_reused": True, "completed_at": datetime.now(timezone.utc).isoformat()}
            return receipt
    _copy_source(unit, dispatch, workspace)
    before = _manifest(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    environment, trace = _environment({**recipe, "build_system": dispatch.get("build_system")}, workspace, settings)
    profile = BuildProfile("java", str(image["image_tag"]), str(image["image_id"]), str(image["user"]))
    executor = executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
        profile, timeout_seconds=int(unit.job.config.settings["command_timeout_seconds"]),
        output_bytes=int(unit.job.config.settings["output_bytes"]))
    started_at, started = datetime.now(timezone.utc).isoformat(), time.monotonic()
    commands, gaps = [], []
    try:
        executor.resolve()
    except (RuntimeError, OSError) as exc:
        return {"schema": JVM_RECEIPT_SCHEMA, "fingerprint": fingerprint,
            "build_unit_id": build_unit_id, "family": "java", "root": dispatch["root"],
            "build_system": dispatch.get("build_system"), "artifacts": [], "commands": [],
            "tool_invocations": [], "terminal_status": "FAILED",
            "gaps": [f"JVM build image unavailable: {type(exc).__name__}: {exc}"],
            "checkpoint_reused": False}
    protected = root / "protected-commands"
    protected.mkdir(parents=True, exist_ok=True)
    for ordinal, raw in enumerate([*recipe["configure_commands"], *recipe["build_commands"]], 1):
        argv, wrapper = _jvm_argv(recipe, raw)
        attempt_identity = hashlib.sha256(canonical_json({"run": unit.job.run_id,
            "attempt": unit.job.attempt_id, "unit": build_unit_id, "ordinal": ordinal})).hexdigest()
        command_id = hashlib.sha256(canonical_json({"attempt": attempt_identity, "argv": list(argv)})).hexdigest()
        command_environment = {**environment, "APPSEC_JVM_PARENT_COMMAND": command_id}
        exact = protected / f"{command_id}.json"
        protected_json(exact, {"schema": "appsec-review/protected-build-command/2", "argv": list(argv),
            "working_directory": str(recipe["source_dir"]), "environment": command_environment,
            "access": "run-owned-protected"})
        try:
            exact.chmod(0o600)
        except OSError:
            pass
        command_started = time.monotonic()
        try:
            result = executor.execute(argv, workspace=workspace,
                working_directory=str(recipe["source_dir"]), environment=command_environment)
        except (RuntimeError, OSError) as exc:
            gaps.append(f"JVM build command {ordinal} failed to start ({type(exc).__name__}: {exc})")
            break
        stdout = _stream(unit.job.run_root, root / "logs" / f"{ordinal:03d}.stdout", result,
                         "stdout", int(unit.job.config.settings["output_bytes"]), int(settings["diagnostic_tail_bytes"]))
        stderr = _stream(unit.job.run_root, root / "logs" / f"{ordinal:03d}.stderr", result,
                         "stderr", int(unit.job.config.settings["output_bytes"]), int(settings["diagnostic_tail_bytes"]))
        failed = result.timed_out or result.exit_code != 0
        commands.append({"command_id": command_id, "attempt_identity": attempt_identity,
            "ordinal": ordinal, "tool": Path(argv[0]).name, "tool_kind": "build-driver",
            "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
            "working_directory": str(recipe["source_dir"]),
            "environment_facts": {key: "set" for key in sorted(command_environment) if not _SECRET.search(key)},
            "wrapper_resolution": ({"requested": wrapper, "executed": argv[0],
                "policy": "pinned-system-tool"} if wrapper else None),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": int((time.monotonic() - command_started) * 1000),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "stdout": stdout, "stderr": stderr,
            "protected_argv": {"path": exact.relative_to(unit.job.run_root).as_posix(),
                               "sha256": file_sha256(exact), "byte_count": exact.stat().st_size},
            "image_id": image["image_id"], "build_unit_id": build_unit_id})
        if failed:
            gaps.append(f"JVM build command {ordinal} {'timed out' if result.timed_out else f'exited {result.exit_code}'}")
            break
    from appsec_review.jobs.cataloging import source_fingerprint
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise JvmIntegrityError("target changed during JVM language-build execution")
    artifacts, artifact_gaps = _catalog(unit.job.run_root, workspace, before,
        int(unit.job.config.settings["artifact_count_limit"]), build_unit_id)
    gaps.extend(artifact_gaps)
    rows, trace_gaps = _trace_rows(trace, workspace, int(settings["provenance_count_limit"]),
                                   int(settings["trace_bytes"]))
    if trace.is_file():
        try:
            trace.chmod(0o600)
        except OSError:
            pass
    gaps.extend(trace_gaps)
    command_streams = {item["command_id"]: {"stdout": item["stdout"], "stderr": item["stderr"]}
                       for item in commands}
    for row in rows:
        row["parent_streams"] = command_streams.get(row["parent_command_id"], {})
    trace_protected = protected / f"jvm-invocations-{unit.job.attempt_id}.json"
    protected_json(trace_protected, {"schema": "appsec-review/protected-jvm-invocations/1", "rows": rows})
    try:
        trace_protected.chmod(0o600)
    except OSError:
        pass
    sanitized = [{key: value for key, value in row.items() if key != "argv"} |
                 {"argv_sha256": hashlib.sha256(canonical_json(row["argv"])).hexdigest()}
                 for row in rows]
    workspace_files = _manifest(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    workspace_manifest = root / "workspace-manifest.json"
    atomic_json(workspace_manifest, {"schema": "appsec-review/build-workspace-manifest/1",
        "build_unit_id": build_unit_id, "files": workspace_files})
    status = "FAILED" if any(gap.startswith("JVM build command") for gap in gaps) else "SUCCEEDED"
    receipt: dict[str, Any] = {"schema": JVM_RECEIPT_SCHEMA, "fingerprint": fingerprint,
        "source_fingerprint": unit.job.source_fingerprint,
        "upstream_handoff_sha256": accepted["project_build_handoff_sha256"],
        "build_unit_id": build_unit_id, "family": "java", "root": dispatch["root"],
        "build_system": dispatch.get("build_system"), "recipe": recipe,
        "recipe_identity": dispatch["recipe_identity"], "probe_identity": dispatch["probe_identity"],
        "image": image, "workspace": workspace.relative_to(unit.job.run_root).as_posix(),
        "commands": commands, "tool_invocations": sanitized,
        "protected_tool_invocations": {"path": trace_protected.relative_to(unit.job.run_root).as_posix(),
            "sha256": file_sha256(trace_protected), "byte_count": trace_protected.stat().st_size},
        "workspace_manifest": {"path": workspace_manifest.relative_to(unit.job.run_root).as_posix(),
            "sha256": file_sha256(workspace_manifest)}, "artifacts": artifacts,
        "gaps": list(dict.fromkeys(gaps)), "terminal_status": status, "checkpoint_reused": False,
        "started_at": started_at, "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "executor_identity": JVM_EXECUTOR_IDENTITY, "capture_identity": JVM_CAPTURE_IDENTITY}
    if status == "SUCCEEDED":
        receipt["retrieval_index"] = _index(unit, receipt)
        cache.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(cache.parent / "build.lock"):
            atomic_json(cache, {"schema": "appsec-review/language-build-checkpoint/1",
                "fingerprint": fingerprint, "terminal_status": status, "workspace": str(workspace),
                "workspace_files": workspace_files, "receipt": receipt})
    return receipt
