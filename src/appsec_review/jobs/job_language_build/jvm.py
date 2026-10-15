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
from appsec_review.jobs.build_discovery import jvm_build_command_errors
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity,
    RelationKind, RelationRecord, index_fingerprint,
)
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256, protected_json

from . import gradle_provenance


JVM_EXECUTOR_IDENTITY = "appsec-review/jvm-language-build-executor/3"
JVM_CAPTURE_IDENTITY = "appsec-review/jvm-build-capture/3"
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
    ".dex": "dex", ".apk": "android-apk", ".aab": "android-app-bundle",
}
_RESOURCE_NAMES = {"MANIFEST.MF", "pom.properties", "pom.xml", "module-info.class"}


class JvmIntegrityError(ValueError):
    """A changed accepted input or retained identity must stop publication."""


def validate_jvm_settings(settings: Mapping[str, Any]) -> None:
    jvm = settings.get("jvm")
    if not isinstance(jvm, Mapping):
        raise ValueError("language-build JVM settings are required")
    required = {"trace_bytes", "provenance_count_limit", "diagnostic_tail_bytes",
                "system_paths", "tool_paths"}
    if set(jvm) != required:
        raise ValueError("language-build JVM settings fields are invalid")
    for key in ("trace_bytes", "provenance_count_limit", "diagnostic_tail_bytes"):
        if type(jvm.get(key)) is not int or int(jvm[key]) < 1:
            raise ValueError(f"language-build JVM bound is invalid: {key}")
    paths = jvm.get("system_paths")
    if (not isinstance(paths, Mapping) or set(paths) != {"java", "android"} or
            any(not isinstance(value, str) or not value or
                any(not part.startswith("/") for part in value.split(":"))
                for value in paths.values())):
        raise ValueError("language-build JVM system_paths are invalid")
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
    if tool in {"mvn", "gradle"}:
        errors = jvm_build_command_errors(str(recipe.get("image_profile", "")), argv)
        if errors:
            raise JvmIntegrityError("accepted JVM build command is invalid: " + "; ".join(errors))
    return tuple(argv), wrapper


def _wrapper_script(tool: str, real: str) -> str:
    """Return a wrapper that records argv, and the content of every readable `@argfile`, then
    execs `real` (already shell-quoted). Build tools delete their argument files after the
    compiler exits, so the content is retained at exec time. Each invocation writes its own
    record file, so concurrent compilations (Gradle --parallel, Maven -T) never interleave."""
    return (
        "#!/bin/sh\n"
        "trace_dir=${APPSEC_JVM_TRACE_DIR:?}\n"
        "parent=${APPSEC_JVM_PARENT_COMMAND:-unknown}\n"
        "record=\"$trace_dir/$(date +%s%N)-$$\"\n"
        f"printf '%s\\0%s\\0%s\\0' '{tool}' \"$parent\" \"$#\" >> \"$record\"\n"
        "for arg in \"$@\"; do printf '%s\\0' \"$arg\" >> \"$record\"; done\n"
        "for arg in \"$@\"; do\n"
        "  case $arg in\n"
        "    @*) file=${arg#@}\n"
        "        if [ -f \"$file\" ] && [ -r \"$file\" ]; then\n"
        "          printf '%s\\0%s\\0%s\\0%s\\0' '@argfile' \"$parent\" 2 \"$file\" >> \"$record\"\n"
        "          tr -d '\\000' < \"$file\" >> \"$record\"\n"
        "          printf '\\0' >> \"$record\"\n"
        "        fi ;;\n"
        "  esac\n"
        "done\n"
        f"exec {real} \"$@\"\n")


def _logical_root(source_dir: str) -> str:
    return f"/workspace/{source_dir}/.appsec-review-jvm"


def _instrumentation(workspace: Path, source_dir: str, settings: Mapping[str, Any]) -> tuple[Path, str]:
    root = workspace / Path(*PurePosixPath(source_dir).parts) / ".appsec-review-jvm"
    binary, trace = root / "bin", root / "invocations.bin"
    binary.mkdir(parents=True, exist_ok=True)
    for tool, real in sorted(settings["tool_paths"].items()):
        script = binary / tool
        script.write_text(_wrapper_script(tool, shlex.quote(str(real))), encoding="utf-8", newline="\n")
        # The build container may run as a different numeric identity than the orchestrator
        # that wrote this run-owned wrapper (the configured profile user when the orchestrator
        # is root). The wrapper holds no secrets, so it must be executable by that identity.
        script.chmod(0o755)
    # Per-invocation records (and the Gradle task records) are written by that same identity;
    # the executor makes the run-owned workspace writable for it.
    trace.with_name("invocations.d").mkdir(exist_ok=True)
    gradle_provenance.write_init_script(root, {
        tool: _wrapper_script(tool, gradle_provenance.TEMPLATE_PLACEHOLDER)
        for tool in gradle_provenance.MIRRORED_TOOLS})
    return trace, _logical_root(source_dir)


def _environment(recipe: Mapping[str, Any], workspace: Path, settings: Mapping[str, Any]) -> tuple[dict[str, str], Path]:
    from .job import _probe_environment

    environment = _probe_environment({**recipe, "build_system": recipe.get("build_system")})
    trace, logical = _instrumentation(workspace, str(recipe["source_dir"]), settings)
    profile = str(recipe.get("image_profile", ""))
    system_paths = settings["system_paths"]
    if profile not in system_paths:
        raise JvmIntegrityError(f"JVM image profile has no configured system path: {profile}")
    environment["APPSEC_JVM_TRACE"] = logical + "/invocations.bin"
    environment["APPSEC_JVM_TRACE_DIR"] = logical + "/invocations.d"
    environment["APPSEC_JVM_INSTRUMENTATION"] = logical
    environment["PATH"] = logical + "/bin:" + str(system_paths[profile])
    environment.setdefault("MAVEN_OPTS", "-Dmaven.repo.local=/opt/project-deps/maven")
    if str(recipe.get("build_system", "")) == "maven":
        # maven-compiler-plugin compiles in-process through javax.tools by default, so no javac
        # process ever reaches the instrumented wrapper and nested provenance is lost. Forking
        # through the wrapper keeps the accepted goals while making each compilation observable.
        environment["MAVEN_OPTS"] = (environment["MAVEN_OPTS"] +
                                     " -Dmaven.compiler.fork=true"
                                     f" -Dmaven.compiler.executable={logical}/bin/javac")
    if profile == "android":
        # The derived image is read-only at execution time. Gradle extracts native runtime files
        # beneath its user home, so the Android execution profile must use its executable tmpfs.
        environment["GRADLE_USER_HOME"] = "/tmp/gradle"
    else:
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


def _trace_chunks(trace: Path) -> list[bytes]:
    """Read the legacy serial trace and the per-invocation record files in exec order."""
    chunks = [trace.read_bytes()] if trace.is_file() and not trace.is_symlink() else []
    directory = trace.with_name("invocations.d")
    if directory.is_dir() and not directory.is_symlink():
        chunks.extend(path.read_bytes() for path in sorted(directory.iterdir())
                      if path.is_file() and not path.is_symlink())
    return chunks


def _trace_rows(trace: Path, workspace: Path, limit: int, byte_limit: int) -> tuple[list[dict[str, Any]], list[str]]:
    chunks = _trace_chunks(trace)
    if not chunks:
        return [], ["nested JVM tool provenance was not emitted by the build"]
    gaps: list[str] = []
    rows: list[dict[str, Any]] = []
    remaining = byte_limit
    for chunk in chunks:
        if remaining <= 0 or len(rows) >= limit:
            gaps.append("JVM invocation trace exceeded its configured " +
                        ("byte" if remaining <= 0 else "record") + " bound")
            break
        if len(chunk) > remaining:
            chunk = chunk[:remaining]
            gaps.append("JVM invocation trace exceeded its configured byte bound")
        remaining -= len(chunk)
        gaps.extend(_trace_chunk_rows(chunk, rows, limit))
    for row in rows:
        _finish_row(row, workspace)
    return rows, list(dict.fromkeys(gaps))


def _trace_chunk_rows(data: bytes, rows: list[dict[str, Any]], limit: int) -> list[str]:
    fields = data.split(b"\0")
    gaps: list[str] = []
    offset, owner = 0, None
    while offset + 3 <= len(fields):
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
        values = [value.decode("utf-8", "replace") for value in fields[offset:offset + count]]
        offset += count
        if tool == "@argfile":
            # The wrapper retains each @argfile right after the exec record that named it.
            if owner is not None and count == 2 and "@" + values[0] in owner["argv"][1:]:
                owner["argfiles"][values[0]] = values[1]
            else:
                gaps.append("JVM invocation trace has an argument file without its invocation")
            continue
        if len(rows) >= limit:
            gaps.append("JVM invocation trace exceeded its configured record bound")
            break
        owner = {"ordinal": len(rows) + 1, "tool": tool, "argv": [tool, *values],
                 "parent_command_id": parent, "argfiles": {}}
        rows.append(owner)
    return gaps


def _finish_row(row: dict[str, Any], workspace: Path) -> None:
    argfiles = row.pop("argfiles")
    expanded = gradle_provenance.expanded_argv(row["argv"], argfiles)
    tool, arguments = row["tool"], expanded[1:]
    launcher = None
    if tool == "java" and gradle_provenance.KOTLIN_COMPILER_MAIN in arguments:
        # Out-of-process Kotlin compilation execs the JDK launcher with the compiler main class.
        launcher, tool = "java", "kotlinc"
        arguments = arguments[arguments.index(gradle_provenance.KOTLIN_COMPILER_MAIN) + 1:]
    inputs, outputs = _paths(arguments)
    row.update({"tool": tool, "tool_kind": _TOOLS.get(tool, "jvm-tool"),
        "launcher": launcher, "expanded_argv": [tool, *arguments],
        "argfiles": [{"path": path, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                      "byte_count": len(text.encode("utf-8"))} for path, text in sorted(argfiles.items())],
        "working_directory": ".", "inputs": _mapped(workspace, inputs),
        "outputs": _mapped(workspace, outputs), "evidence_kind": "observed-exec",
        "mapping": "instrumented-tool-wrapper", "mapping_confidence": 1.0})


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


def _remove_jdk_mirrors(root: Path, gaps: list[str]) -> None:
    """Remove the run-owned JDK mirrors; their links name container paths and are not evidence."""
    mirrors = root / "jdk"
    if not mirrors.exists() or mirrors.is_symlink():
        return
    try:
        shutil.rmtree(mirrors)  # Never follows the mirror's links into the real JDK.
    except OSError as exc:
        gaps.append(f"run-owned Gradle JDK mirror could not be removed ({type(exc).__name__})")


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
        "gradle_init_script": gradle_provenance.INIT_SCRIPT_SHA256,
        "probe": dispatch["probe_identity"], "upstream_handoff": accepted["project_build_handoff_sha256"]
    })).hexdigest()


def _index(unit: Any, receipt: Mapping[str, Any]) -> dict[str, Any]:
    producer = [{"sha256": item["sha256"]} for item in receipt["artifacts"]]
    fingerprint = index_fingerprint(name="build", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=producer, tool_identity={"executor": JVM_EXECUTOR_IDENTITY,
        "image": receipt["image"]["image_id"]}, parser_identity="jvm-provenance/2",
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
                "argv_sha256", "expanded_argv_sha256", "launcher", "evidence_kind",
                "parent_command_id", "working_directory", "inputs", "outputs",
                "mapping", "mapping_confidence")}
            builder.add_entity(EntityRecord(identity, invocation["argv_sha256"], invocation["tool"],
                f"observed {invocation['tool_kind']} invocation", payload))
            parent = action_by_command.get(str(invocation["parent_command_id"]))
            if parent:
                builder.add_relation(RelationRecord(RelationKind.DEPENDS_ON, identity.value,
                                                     parent, True, 1.0))
        for declared in receipt.get("declared_compilations", ()):
            identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                {"unit": receipt["build_unit_id"], "parent": declared["parent_command_id"],
                 "declared_task": declared["task_path"], "tool": declared["tool"]})
            payload = {key: declared.get(key) for key in ("ordinal", "tool", "tool_kind",
                "evidence_kind", "task_path", "task_type", "parent_command_id", "did_work",
                "declared_arguments_sha256", "declared_settings", "inputs", "outputs",
                "observed_invocation_ordinals", "mapping", "mapping_confidence")}
            builder.add_entity(EntityRecord(identity, declared["task_path"], declared["tool"],
                f"build-tool-declared {declared['tool_kind']} task (not an observed exec)", payload))
            parent = action_by_command.get(str(declared["parent_command_id"]))
            if parent:
                builder.add_relation(RelationRecord(RelationKind.DEPENDS_ON, identity.value, parent,
                                                     True, gradle_provenance.DECLARED_CONFIDENCE))
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
    image_profile = str(recipe.get("image_profile", ""))
    if image_profile not in {"java", "android"} or str(image.get("family", "")) != image_profile:
        raise JvmIntegrityError("JVM recipe and accepted image profiles do not match")
    environment, trace = _environment({**recipe, "build_system": dispatch.get("build_system")}, workspace, settings)
    profile = BuildProfile(image_profile, str(image["image_tag"]), str(image["image_id"]), str(image["user"]))
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
        instrumentation = None
        if Path(argv[0]).name == "gradle":
            argv, instrumentation = gradle_provenance.instrument_argv(
                argv, _logical_root(str(recipe["source_dir"])))
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
            "instrumentation": instrumentation,
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
    _remove_jdk_mirrors(trace.parent, gaps)
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
    instrumentation_root = trace.parent
    records, record_gaps = gradle_provenance.read_task_records(
        instrumentation_root / "gradle-tasks.jsonl", int(settings["trace_bytes"]),
        int(settings["provenance_count_limit"]))
    gaps.extend(record_gaps)
    declared, declared_gaps = gradle_provenance.declared_compilations(
        records, rows, lambda values: _mapped(workspace, values))
    gaps.extend(declared_gaps)
    if (any(item.get("instrumentation") for item in commands) and
            not any(item.get("record_kind") == "session" for item in records)):
        gaps.append("Gradle provenance init script did not report; Gradle compiler provenance is unavailable")
    for path in [trace.with_name("invocations.d"), *trace.with_name("invocations.d").glob("*"),
                 instrumentation_root / "gradle-tasks.jsonl"]:
        try:
            if path.exists() and not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        except OSError:
            pass
    command_streams = {item["command_id"]: {"stdout": item["stdout"], "stderr": item["stderr"]}
                       for item in commands}
    for row in rows:
        row["parent_streams"] = command_streams.get(row["parent_command_id"], {})
    trace_protected = protected / f"jvm-invocations-{unit.job.attempt_id}.json"
    protected_json(trace_protected, {"schema": "appsec-review/protected-jvm-invocations/2", "rows": rows,
                                     "declared_compilations": declared})
    try:
        trace_protected.chmod(0o600)
    except OSError:
        pass
    sanitized = [{key: value for key, value in row.items() if key not in {"argv", "expanded_argv"}} |
                 {"argv_sha256": hashlib.sha256(canonical_json(row["argv"])).hexdigest(),
                  "expanded_argv_sha256": hashlib.sha256(canonical_json(row["expanded_argv"])).hexdigest()}
                 for row in rows]
    sanitized_declared = [{key: value for key, value in row.items() if key != "declared_arguments"} |
                          {"declared_arguments_sha256": hashlib.sha256(
                              canonical_json(row["declared_arguments"])).hexdigest()}
                          for row in declared]
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
        "declared_compilations": sanitized_declared,
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
