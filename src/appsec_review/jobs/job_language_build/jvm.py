from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
import time
from typing import Any

from appsec_review.config.assurance import ComponentReleases
from appsec_review.jobs.artifact_kinds import require_artifact_kind
from appsec_review.jobs.delivery_scope import POLICY_IDENTITY, apply_scope, scope_fields
from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.jobs.build_discovery import jvm_build_command_errors
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity,
    RelationKind, RelationRecord, index_fingerprint,
)
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import immutable_bytes

from . import gradle_provenance


JVM_EXECUTOR_IDENTITY = "appsec-review/jvm-language-build-executor/3"
JVM_CAPTURE_IDENTITY = "appsec-review/jvm-build-capture/3"
JVM_RECEIPT_SCHEMA = "appsec-review/language-build-receipt/1"
_RELEASE_COMPONENTS = ("platform", "validation", "build_toolchain", "jvm_instrumentation")
_INSTRUMENTATION_MOUNT = "/appsec-jvm"
_EVIDENCE_MOUNT = "/appsec-jvm-evidence"
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
    ".dex": "dex", ".apk": "android-apk",
}
_RESOURCE_NAMES = {"MANIFEST.MF", "pom.properties", "pom.xml", "module-info.class"}
# The wrapper's pseudo-tool record that carries an @argfile's bounded contents.
_ARGFILE_RECORD = "@argfile"
_ARGFILE_BYTES = 1024 * 1024
_SOURCE_READ_BYTES = 64 * 1024
_JAVAC_SOURCE_LIMIT = 20000
# javac options whose next argument is a value, never a source file.
_JAVAC_VALUE_OPTIONS = frozenset({
    "-d", "-s", "-h", "-cp", "-classpath", "--class-path", "-sourcepath", "--source-path",
    "-processorpath", "--processor-path", "--processor-module-path", "-processor",
    "--module-path", "-p", "--module-source-path", "--upgrade-module-path", "--system",
    "--release", "-source", "--source", "-target", "--target", "-encoding", "-bootclasspath",
    "--boot-class-path", "-extdirs", "-endorseddirs", "--add-modules", "--limit-modules",
    "--add-exports", "--add-reads", "--patch-module", "--module", "-m", "--module-version",
    "-Xmaxerrs", "-Xmaxwarns", "-Xstdout", "--default-module-for-created-files",
})
_JAVA_COMMENT_OR_LITERAL = re.compile(
    r'//[^\n]*|/\*.*?\*/|"""(?:\\.|[^\\])*?"""|"(?:\\.|[^"\\\n])*"|' + r"'(?:\\.|[^'\\\n])*'", re.S)
_JAVA_PACKAGE = re.compile(
    r"\s*(?:@[\w.]+(?:\([^)]*\))?\s*)*package\s+([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*;")
_JAVA_TOKEN = re.compile(r"[{}]|\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)")


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
    """Return a wrapper that records argv and, for every readable `@argfile`, its path, the
    directory the tool ran in, and its bounded NUL-stripped contents, then execs `real` (already
    shell-quoted). Build tools delete their argument files after the compiler exits, so the
    content is retained at exec time. Each invocation writes its own
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
        "        if [ -f \"$file\" ] && [ -r \"$file\" ] && [ ! -L \"$file\" ]; then\n"
        f"          printf '%s\\0%s\\0%s\\0%s\\0%s\\0' '{_ARGFILE_RECORD}' \"$parent\" 3 \"$file\" \"$PWD\" >> \"$record\"\n"
        f"          head -c {_ARGFILE_BYTES} \"$file\" | tr -d '\\000' >> \"$record\"\n"
        "          printf '\\0' >> \"$record\"\n"
        "        fi ;;\n"
        "  esac\n"
        "done\n"
        f"exec {real} \"$@\"\n")


def _resolved_tool(tool: str, configured: str) -> str:
    """Shell expression for the real tool: the configured path when it exists in the image, else
    the image's own JDK (``$JAVA_HOME/bin``). Build images differ: the Java image installs the JDK
    under /usr/bin, while the Android image ships it only under JAVA_HOME."""
    configured = shlex.quote(configured)
    fallback = shlex.quote(tool)
    return (f'"$(if [ -x {configured} ]; then printf %s {configured}; '
            f'elif [ -n "${{JAVA_HOME:-}}" ] && [ -x "$JAVA_HOME/bin/"{fallback} ]; '
            f'then printf %s "$JAVA_HOME/bin/"{fallback}; else printf %s {configured}; fi)"')


def _instrumentation(root: Path, evidence_root: Path, settings: Mapping[str, Any]) -> tuple[Path, str]:
    binary, trace = root / "bin", evidence_root / "invocations.bin"
    binary.mkdir(parents=True, exist_ok=True)
    for tool, real in sorted(settings["tool_paths"].items()):
        script = binary / tool
        script.write_text(_wrapper_script(tool, _resolved_tool(tool, str(real))), encoding="utf-8",
                          newline="\n")
        # The build container may run as a different numeric identity than the orchestrator
        # that wrote this run-owned wrapper (the configured profile user when the orchestrator
        # is root). The wrapper holds no secrets, so it must be executable by that identity.
        script.chmod(0o755)
    # Per-invocation records (and the Gradle task records) are written by that same identity;
    # the executor makes the run-owned workspace writable for it.
    trace.with_name("invocations.d").mkdir(parents=True, exist_ok=True)
    gradle_provenance.write_init_script(root, {
        tool: _wrapper_script(tool, gradle_provenance.TEMPLATE_PLACEHOLDER)
        for tool in gradle_provenance.MIRRORED_TOOLS})
    return trace, _INSTRUMENTATION_MOUNT


def _environment(recipe: Mapping[str, Any], workspace: Path, settings: Mapping[str, Any], *,
                 instrumentation_root: Path, evidence_root: Path) -> tuple[dict[str, str], Path]:
    from .job import _probe_environment

    environment = _probe_environment({**recipe, "build_system": recipe.get("build_system")})
    roots = [path.resolve() for path in (workspace, instrumentation_root, evidence_root)]
    if any(left.is_relative_to(right) or right.is_relative_to(left)
           for index, left in enumerate(roots) for right in roots[index + 1:]):
        raise JvmIntegrityError("JVM instrumentation and evidence must be outside the target workspace")
    trace, logical = _instrumentation(instrumentation_root, evidence_root, settings)
    profile = str(recipe.get("image_profile", ""))
    system_paths = settings["system_paths"]
    if profile not in system_paths:
        raise JvmIntegrityError(f"JVM image profile has no configured system path: {profile}")
    environment["APPSEC_JVM_TRACE"] = _EVIDENCE_MOUNT + "/invocations.bin"
    environment["APPSEC_JVM_TRACE_DIR"] = _EVIDENCE_MOUNT + "/invocations.d"
    environment["APPSEC_JVM_INSTRUMENTATION"] = logical
    environment["APPSEC_JVM_EVIDENCE"] = _EVIDENCE_MOUNT
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


def _argfile_arguments(text: str) -> list[str]:
    """Split an @argfile the way javac does: whitespace separates, quotes group, # comments."""
    arguments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    started = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                quote = None
            elif char == "\\" and index + 1 < len(text):
                index += 1
                current.append({"n": "\n", "t": "\t", "r": "\r", "f": "\f"}.get(text[index], text[index]))
            else:
                current.append(char)
        elif char in "\"'":
            quote, started = char, True
        elif char == "#" and not started:
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        elif char.isspace():
            if started:
                arguments.append("".join(current))
                current, started = [], False
        else:
            current.append(char)
            started = True
        index += 1
    if started:
        arguments.append("".join(current))
    return arguments


def _bounded_text(path: Path, limit: int) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as stream:
            return stream.read(limit).decode("utf-8", "replace")
    except OSError:
        return None


def _blank(match: re.Match[str]) -> str:
    # Comments become spaces and literals become empty strings, so neither can hide or fake
    # a brace, a package declaration, or a type declaration.
    text = match.group(0)
    return '""' if text.startswith(('"', "'")) else re.sub(r"[^\n]", " ", text)


def java_declarations(text: str) -> tuple[str, list[str]]:
    """The package and top-level type names a Java source declares, from bounded text."""
    stripped = _JAVA_COMMENT_OR_LITERAL.sub(_blank, text)
    package_match = _JAVA_PACKAGE.match(stripped)
    package = re.sub(r"\s+", "", package_match.group(1)) if package_match else ""
    names: list[str] = []
    depth = 0
    for match in _JAVA_TOKEN.finditer(stripped):
        token = match.group(0)
        if token == "{":
            depth += 1
        elif token == "}":
            depth = max(0, depth - 1)
        elif depth == 0 and match.group(1) and match.group(1) not in names:
            names.append(match.group(1))
    return package, names


def _logical(directory: str, value: str) -> str | None:
    """A path as the build container saw it, made workspace-relative; None outside it."""
    normalized = value.replace("\\", "/")
    if not normalized.startswith("/"):
        base = directory if directory.startswith("/") else posixpath.join("/workspace", directory)
        normalized = posixpath.join(base, normalized)
    normalized = posixpath.normpath(normalized)
    if normalized == "/workspace":
        return "."
    if not normalized.startswith("/workspace/"):
        return None
    return normalized[len("/workspace/"):]


def javac_outputs(workspace: Path, directory: str, arguments: list[str]) -> tuple[list[str], list[str]]:
    """Class files a javac invocation wrote, from ``-d`` and each source's package and types.

    ``arguments`` are javac's arguments with @argfiles already expanded. javac writes
    ``<d>/<package path>/<Type>.class`` for every top-level type a source declares, and
    ``<Type>$<n>.class`` or ``<Type>$<Inner>.class`` for its nested, local, and anonymous
    classes. Only class files that exist are named. A source that cannot be read is returned
    as a gap, never guessed, and its classes stay unattributed.
    """
    destination: str | None = None
    sources: list[str] = []
    gaps: list[str] = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if value in _JAVAC_VALUE_OPTIONS:
            if value == "-d" and index + 1 < len(arguments):
                destination = arguments[index + 1]
            index += 2
            continue
        if not value.startswith("-") and value.lower().endswith(".java"):
            sources.append(value)
        index += 1
    if len(sources) > _JAVAC_SOURCE_LIMIT:
        return [], [f"javac source list exceeded {_JAVAC_SOURCE_LIMIT}; class outputs were not mapped"]
    root = workspace.resolve()
    base = _logical(directory, destination) if destination is not None else None
    if destination is not None and base is None:
        return [], gaps  # Classes written outside the workspace are not catalogued artifacts.
    listings: dict[str, list[str]] = {}
    outputs: list[str] = []
    for source in sources:
        logical = _logical(directory, source)
        if logical is None:
            continue
        text = _bounded_text(root / Path(*PurePosixPath(logical).parts), _SOURCE_READ_BYTES)
        if text is None:
            gaps.append(f"javac source was unreadable; its class outputs were not mapped: {logical}")
            continue
        package, types = java_declarations(text)
        stem = PurePosixPath(logical).stem
        if base is None:
            output_directory = PurePosixPath(logical).parent.as_posix()
        else:
            output_directory = posixpath.normpath(posixpath.join(base, *package.split("."))) if package else base
        if stem in {"package-info", "module-info"}:
            types = [stem]
        elif stem not in types:
            types.insert(0, stem)
        if output_directory not in listings:
            folder = root / Path(*PurePosixPath(output_directory).parts)
            try:
                listings[output_directory] = sorted(
                    item.name for item in folder.iterdir() if item.name.endswith(".class")
                ) if folder.is_dir() and not folder.is_symlink() else []
            except OSError:
                listings[output_directory] = []
        for type_name in types:
            for name in listings[output_directory]:
                if name == f"{type_name}.class" or name.startswith(f"{type_name}$"):
                    outputs.append(posixpath.join(output_directory, name))
    return list(dict.fromkeys(outputs)), gaps


def _trace_rows(trace: Path, workspace: Path, limit: int, byte_limit: int,
                source_dir: str = ".") -> tuple[list[dict[str, Any]], list[str]]:
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
        gaps.extend(_finish_row(row, workspace, source_dir))
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
        if tool == _ARGFILE_RECORD:
            # The wrapper retains each @argfile (path, the PWD javac ran in, bounded contents)
            # right after the exec record that named it, in the same per-exec record file.
            if owner is None or owner["parent_command_id"] != parent or count != 3 or \
                    f"@{values[0]}" not in owner["argv"][1:]:
                gaps.append("JVM argfile record did not follow the invocation that named it")
                continue
            owner.setdefault("argfiles", []).append({
                "reference": values[0], "working_directory": values[1],
                "sha256": hashlib.sha256(values[2].encode("utf-8")).hexdigest(),
                "arguments": _argfile_arguments(values[2])})
            continue
        if len(rows) >= limit:
            gaps.append("JVM invocation trace exceeded its configured record bound")
            break
        owner = {"ordinal": len(rows) + 1, "tool": tool, "argv": [tool, *values],
                 "parent_command_id": parent}
        rows.append(owner)
    return gaps


def _finish_row(row: dict[str, Any], workspace: Path, source_dir: str) -> list[str]:
    """Expand argfiles, classify the exec, and resolve its inputs and outputs."""
    gaps: list[str] = []
    argfiles = {f"@{item['reference']}": item for item in row.get("argfiles", ())}
    arguments: list[str] = []
    for value in row["argv"][1:]:
        if value in argfiles:
            arguments.extend(argfiles[value]["arguments"])
            continue
        if value.startswith("@") and row["tool"] in {"javac", "java"}:
            gaps.append(f"{row['tool']} argfile contents were not recorded: {value[1:]}")
        arguments.append(value)
    tool, launcher = row["tool"], None
    if tool == "java" and gradle_provenance.KOTLIN_COMPILER_MAIN in arguments:
        # Out-of-process Kotlin compilation execs the JDK launcher with the compiler main class.
        launcher, tool = "java", "kotlinc"
        arguments = arguments[arguments.index(gradle_provenance.KOTLIN_COMPILER_MAIN) + 1:]
    # Build tools name argfiles with absolute paths; the wrapper records the directory the tool
    # ran in, so relative arguments inside it resolve exactly. Otherwise the recipe source_dir.
    directory = next((str(item["working_directory"]) for item in row.get("argfiles", ())
                      if str(item["working_directory"]).startswith("/workspace")), source_dir)
    inputs, outputs = _paths(arguments)
    if tool == "javac":
        classes, class_gaps = javac_outputs(workspace, directory, arguments)
        if class_gaps:
            # The classes stay unattributed, and artifact indexing names each one as a gap.
            row["class_mapping_gaps"] = class_gaps[:16]
        mapped_classes = [{**item, "mapping": "javac-derived-class"}
                          for item in _mapped(workspace, ".", classes) if item.get("sha256")]
        mapped_outputs = [*_mapped(workspace, directory, outputs), *mapped_classes]
    else:
        mapped_outputs = _mapped(workspace, directory, outputs)
    row.update({"tool": tool, "tool_kind": _TOOLS.get(tool, "jvm-tool"), "launcher": launcher,
        "expanded_argv": [tool, *arguments], "working_directory": directory,
        "inputs": _mapped(workspace, directory, inputs), "outputs": mapped_outputs,
        "evidence_kind": "observed-exec", "mapping": "instrumented-tool-wrapper",
        "mapping_confidence": 1.0})
    return gaps


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


def _mapped(workspace: Path, directory: str, values: list[str]) -> list[dict[str, Any]]:
    from .job import _mapped_files
    base = directory if directory.startswith("/") else posixpath.join("/workspace", directory)
    return _mapped_files(workspace, posixpath.normpath(base), values)


def _remove_jdk_mirrors(root: Path, gaps: list[str]) -> None:
    """Remove the run-owned JDK mirrors; their links name container paths and are not evidence."""
    mirrors = root / "jdk"
    if mirrors.is_symlink():
        raise JvmIntegrityError("JVM mirror directory is a symlink")
    if not mirrors.exists():
        return
    try:
        shutil.rmtree(mirrors)  # Never follows the mirror's links into the real JDK.
    except OSError as exc:
        raise JvmIntegrityError("supplied Gradle JDK mirrors could not be removed before publication") from exc


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
            if path.is_symlink() or not path.is_file():
                continue
        except OSError:
            continue
        relative, digest = path.relative_to(workspace).as_posix(), file_sha256(path)
        kind = _artifact_kind(path)
        if kind is None or before.get(relative) == digest:
            continue
        artifacts.append({"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
            "sha256": digest, "size_bytes": path.stat().st_size, "kind": require_artifact_kind(kind),
            "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
            "mapping_confidence": 1.0, "artifact_origin": "build-output"})
        if len(artifacts) >= limit:
            gaps.append("JVM artifact catalog truncated at configured count bound")
            break
    return artifacts, gaps


def _manifest(workspace: Path, limit: int) -> dict[str, str]:
    from .job import _snapshot
    return _snapshot(workspace, limit)


def _fingerprint(dispatch: Mapping[str, Any], accepted: Mapping[str, Any], settings: Mapping[str, Any], *,
                 releases: ComponentReleases | None = None, policy: Mapping[str, Any] | None = None) -> str:
    image = dispatch["image"]
    return hashlib.sha256(canonical_json({"schema": JVM_RECEIPT_SCHEMA,
        "target": dispatch["source_fingerprint"], "recipe": dispatch["recipe_identity"],
        "dependencies": image["dependency_hashes"], "build_dependencies": dispatch.get("build_dependencies", ()),
        "image": image["image_id"], "executor": JVM_EXECUTOR_IDENTITY, "capture": JVM_CAPTURE_IDENTITY,
        "toolchain": {"family": "java", "image_id": image["image_id"], "settings": settings},
        "component_releases": {key: (releases.values.get(key) if releases else None)
                               for key in _RELEASE_COMPONENTS},
        "review_policy": {key: value for key, value in (policy or {}).items() if key != "releases"},
        "workspace_layout": "jvm-detached-instrumentation/1",
        "delivery_policy": POLICY_IDENTITY,
        "probe": dispatch["probe_identity"], "upstream_handoff": accepted["project_build_handoff_sha256"]
    })).hexdigest()


def _index(unit: Any, receipt: Mapping[str, Any]) -> dict[str, Any]:
    producer = [{"sha256": item["sha256"]} for item in receipt["artifacts"]]
    fingerprint = index_fingerprint(name="build", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=producer, tool_identity={"executor": JVM_EXECUTOR_IDENTITY,
        "image": receipt["image"]["image_id"], "delivery_policy": POLICY_IDENTITY},
        parser_identity="jvm-provenance/2",
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
                {**{key: artifact[key] for key in ("workspace_path", "sha256", "size_bytes", "kind",
                                                  "build_unit_id", "mapping", "mapping_confidence")},
                 **scope_fields(artifact)}))
            for action_id in action_ids:
                builder.add_relation(RelationRecord(RelationKind.GENERATED_FROM, identity.value,
                                                     action_id, True, 1.0))
        complete = receipt["terminal_status"] == "SUCCEEDED" and not receipt["gaps"]
        builder.add_coverage("jvm-build", "complete" if complete else "partial",
                             None if complete else "; ".join(receipt["gaps"][:10]))
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
    releases = unit.job.review_policy.releases
    reusable, reuse_reason = releases.require(*_RELEASE_COMPONENTS)
    fingerprint = _fingerprint(dispatch, accepted, {
        **settings,
        "processing_modes": {
            "build_execution_capture": capture.get("mode", "required"),
            "compiler_artifact_collection": artifact_overrides.get(
                "java", unit.job.config.settings.get(
                    "compiler_artifact_collection_mode", "required")),
        },
    }, releases=releases, policy=unit.job.review_policy.view())
    root = (unit.job.run_root / "data" / "build" / "jvm" / "units" / build_unit_id /
            "attempts" / unit.job.attempt_id)
    workspace = root / "workspace"
    namespace = hashlib.sha256(str(unit.job.run_root.resolve()).encode()).hexdigest()
    cache = unit.job.metadata_root / "language-builds" / namespace / "jvm" / fingerprint / "accepted.json"
    if not reusable:
        unit.job.events.write("CHECKPOINT_MISSED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
                              action="jvm_build", reason=reuse_reason)
    with FileLock(cache.parent / "build.lock"):
        if reusable and cache.is_file():
            prior = json.loads(cache.read_text(encoding="utf-8"))
            if prior.get("fingerprint") != fingerprint or prior.get("terminal_status") != "SUCCEEDED":
                raise JvmIntegrityError("JVM checkpoint identity is invalid")
            prior_workspace = Path(str(prior.get("workspace", "")))
            if not prior_workspace.is_dir() or prior_workspace.is_symlink():
                raise JvmIntegrityError("JVM checkpoint workspace is unavailable")
            if (unit.job.run_root.resolve() not in prior_workspace.resolve().parents
                    or prior_workspace.resolve() != (unit.job.run_root / prior["receipt"]["workspace"]).resolve()):
                raise JvmIntegrityError("JVM checkpoint workspace identity differs")
            workspace, root = prior_workspace, prior_workspace.parent
            expected = prior.get("workspace_files")
            if not isinstance(expected, Mapping) or _manifest(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10) != expected:
                raise JvmIntegrityError("JVM checkpoint workspace identity changed")
            evidence = prior.get("instrumentation_evidence_files")
            evidence_root = root / "instrumentation-evidence"
            if (not isinstance(evidence, Mapping) or not evidence_root.is_dir()
                    or (evidence_root / "jdk").exists() or (evidence_root / "jdk").is_symlink()
                    or _manifest(evidence_root, int(unit.job.config.settings["artifact_count_limit"]) * 10)
                    != evidence):
                raise JvmIntegrityError("JVM checkpoint instrumentation evidence changed")
            evidence_manifest = prior["receipt"].get("instrumentation_evidence_manifest", {})
            if (evidence_manifest.get("path") != (root / "instrumentation-evidence-manifest.json").relative_to(
                    unit.job.run_root).as_posix()
                    or file_sha256(root / "instrumentation-evidence-manifest.json") != evidence_manifest.get("sha256")):
                raise JvmIntegrityError("JVM checkpoint instrumentation evidence manifest changed")
            receipt = {**prior["receipt"], "workspace": workspace.relative_to(unit.job.run_root).as_posix(),
                       "checkpoint_reused": True, "completed_at": datetime.now(timezone.utc).isoformat()}
            return receipt
    _copy_source(unit, dispatch, workspace)
    before = _manifest(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    image_profile = str(recipe.get("image_profile", ""))
    if image_profile not in {"java", "android"} or str(image.get("family", "")) != image_profile:
        raise JvmIntegrityError("JVM recipe and accepted image profiles do not match")
    instrumentation_root, evidence_root = root / "instrumentation", root / "instrumentation-evidence"
    for directory in (instrumentation_root, evidence_root):
        if directory.is_symlink():
            raise JvmIntegrityError("JVM instrumentation directory is a symlink")
        if directory.exists():
            shutil.rmtree(directory)
    environment, trace = _environment(
        {**recipe, "build_system": dispatch.get("build_system")}, workspace, settings,
        instrumentation_root=instrumentation_root, evidence_root=evidence_root)
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
                argv, _INSTRUMENTATION_MOUNT, release_id=releases.values.get("jvm_instrumentation"))
        attempt_identity = hashlib.sha256(canonical_json({"run": unit.job.run_id,
            "attempt": unit.job.attempt_id, "unit": build_unit_id, "ordinal": ordinal})).hexdigest()
        command_id = hashlib.sha256(canonical_json({"attempt": attempt_identity, "argv": list(argv)})).hexdigest()
        command_environment = {**environment, "APPSEC_JVM_PARENT_COMMAND": command_id}
        exact = protected / f"{command_id}.json"
        immutable_bytes(unit.job.run_root, exact.relative_to(unit.job.run_root).as_posix(),
            canonical_json({"schema": "appsec-review/protected-build-command/2", "argv": list(argv),
            "working_directory": str(recipe["source_dir"]), "environment": command_environment,
            "access": "run-owned-protected"}))
        try:
            exact.chmod(0o600)
        except OSError:
            pass
        command_started = time.monotonic()
        try:
            result = executor.execute(argv, workspace=workspace,
                working_directory=str(recipe["source_dir"]), environment=command_environment,
                instrumentation_root=instrumentation_root, instrumentation_evidence_root=evidence_root)
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
    gaps.extend(apply_scope(artifacts))
    rows, trace_gaps = _trace_rows(trace, workspace, int(settings["provenance_count_limit"]),
                                   int(settings["trace_bytes"]), str(recipe["source_dir"]))
    if trace.is_file():
        try:
            trace.chmod(0o600)
        except OSError:
            pass
    gaps.extend(trace_gaps)
    records, record_gaps = gradle_provenance.read_task_records(
        evidence_root / "gradle-tasks.jsonl", int(settings["trace_bytes"]),
        int(settings["provenance_count_limit"]))
    gaps.extend(record_gaps)
    declared, declared_gaps = gradle_provenance.declared_compilations(
        records, rows, lambda values: _mapped(workspace, str(recipe["source_dir"]), values))
    gaps.extend(declared_gaps)
    if (any(item.get("instrumentation") for item in commands) and
            not any(item.get("record_kind") == "session" for item in records)):
        gaps.append("Gradle provenance init script did not report; Gradle compiler provenance is unavailable")
    for path in [trace.with_name("invocations.d"), *trace.with_name("invocations.d").glob("*"),
                 evidence_root / "gradle-tasks.jsonl"]:
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
    immutable_bytes(unit.job.run_root, trace_protected.relative_to(unit.job.run_root).as_posix(),
        canonical_json({"schema": "appsec-review/protected-jvm-invocations/2", "rows": rows,
                        "declared_compilations": declared}))
    try:
        trace_protected.chmod(0o600)
    except OSError:
        pass
    # Argfile contents are arguments too; only their digests leave the protected record.
    sanitized = [{key: value for key, value in row.items() if key not in {"argv", "expanded_argv", "argfiles"}} |
                 {"argv_sha256": hashlib.sha256(canonical_json(row["argv"])).hexdigest(),
                  "expanded_argv_sha256": hashlib.sha256(canonical_json(row["expanded_argv"])).hexdigest()} |
                 ({"argfile_sha256": [item["sha256"] for item in row["argfiles"]]} if row.get("argfiles") else {})
                 for row in rows]
    sanitized_declared = [{key: value for key, value in row.items() if key != "declared_arguments"} |
                          {"declared_arguments_sha256": hashlib.sha256(
                              canonical_json(row["declared_arguments"])).hexdigest()}
                          for row in declared]
    workspace_files = _manifest(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    instrumentation_evidence_files = _manifest(
        evidence_root, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    evidence_manifest = root / "instrumentation-evidence-manifest.json"
    atomic_json(evidence_manifest, {"schema": "appsec-review/jvm-instrumentation-evidence/1",
        "build_unit_id": build_unit_id,
        "files": [{"path": (evidence_root / relative).relative_to(unit.job.run_root).as_posix(),
                   "sha256": digest} for relative, digest in sorted(instrumentation_evidence_files.items())]})
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
        "instrumentation_evidence_manifest": {
            "path": evidence_manifest.relative_to(unit.job.run_root).as_posix(),
            "sha256": file_sha256(evidence_manifest)},
        "component_releases": {key: releases.values.get(key) for key in _RELEASE_COMPONENTS},
        "checkpoint_reuse_reason": reuse_reason,
        "gaps": list(dict.fromkeys(gaps)), "terminal_status": status, "checkpoint_reused": False,
        "started_at": started_at, "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "executor_identity": JVM_EXECUTOR_IDENTITY, "capture_identity": JVM_CAPTURE_IDENTITY}
    if status == "SUCCEEDED":
        receipt["retrieval_index"] = _index(unit, receipt)
    if status == "SUCCEEDED" and reusable:
        cache.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(cache.parent / "build.lock"):
            atomic_json(cache, {"schema": "appsec-review/language-build-checkpoint/1",
                "fingerprint": fingerprint, "terminal_status": status, "workspace": str(workspace),
                "workspace_files": workspace_files, "instrumentation_evidence_files": instrumentation_evidence_files,
                "receipt": receipt})
    return receipt
