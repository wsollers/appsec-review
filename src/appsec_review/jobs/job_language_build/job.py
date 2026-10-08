from __future__ import annotations

from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import time
from typing import Any

from appsec_review.config import LanguageBuildSettings
from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.container_runtime.project_images import project_recipe_identity
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.cataloging import source_fingerprint, write_json
from appsec_review.jobs.job_project_build import load_accepted_builds
from appsec_review.jobs.job_project_build.job import _normalized_argv, _probe_environment, _safe_root
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256, protected_json

from . import dotnet, jvm, node, php, python, rust


SCHEMA = "appsec-review/language-build-handoff/1"
RECEIPT_SCHEMA = "appsec-review/language-build-receipt/1"
EXECUTOR_IDENTITY = "appsec-review/generic-language-build-executor/1"
CAPTURE_IDENTITIES = {"native": "appsec-review/native-build-capture/1",
                      "go": "appsec-review/go-build-capture/1",
                      "dotnet": dotnet.CAPTURE_IDENTITY,
                      "java": jvm.JVM_CAPTURE_IDENTITY,
                      "node": node.CAPTURE_IDENTITY,
                      "php": php.CAPTURE_IDENTITY,
                      "python": python.CAPTURE_IDENTITY,
                      "rust": rust.CAPTURE_IDENTITY,
                      "wasm": "appsec-review/protected-build-capture/2"}
_SECRET_KEY = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".h", ".hh", ".hpp", ".hxx", ".go", ".s"}
_OBJECT_SUFFIXES = {".o", ".obj"}
_STATIC_SUFFIXES = {".a", ".lib"}
_SHARED_SUFFIXES = {".so", ".dll", ".dylib"}
_DEBUG_SUFFIXES = {".pdb", ".dwarf", ".dwo", ".debug"}
_MAP_SUFFIXES = {".map"}
_BITCODE_SUFFIXES = {".bc", ".ll"}
_TOOL_KINDS = {
    "cc": "compiler-driver", "c++": "compiler-driver", "gcc": "compiler-driver",
    "g++": "compiler-driver", "clang": "compiler-driver", "clang++": "compiler-driver",
    "as": "assembler", "ar": "archiver", "llvm-ar": "archiver", "ld": "linker",
    "ld.lld": "linker", "lld": "linker", "ranlib": "post-link", "strip": "post-link",
    "objcopy": "post-link", "protoc": "code-generator", "bison": "code-generator",
    "flex": "code-generator",
    "compile": "compiler", "asm": "assembler", "link": "linker", "cgo": "cgo",
    "pack": "package-builder", "go": "build-driver", "gcc": "compiler",
}
_GO_TRACE_TOOLS = {"compile", "asm", "link", "cgo", "pack", "gcc", "clang", "as", "ld", "ar"}


class FrameworkIntegrityError(ValueError):
    """A changed accepted identity or run-owned artifact; publication must stop."""


def _artifact(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "language-build" / name
    identity = write_json(path, value)
    identity["path"] = path.relative_to(unit.job.run_root).as_posix()
    return identity


def _safe_artifact(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("accepted language-build artifact path is invalid")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted language-build artifact identity changed")
    return json.loads(path.read_text(encoding="utf-8"))


def load_accepted_language_build(run_root: Path) -> Mapping[str, Any]:
    pointer_path = run_root / "data" / "jobs" / "job_language_build" / "latest.json"
    if not pointer_path.is_file():
        raise ValueError("accepted job_language_build handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _safe_artifact(run_root, {"path": pointer.get("handoff_path"),
                                      "sha256": pointer.get("handoff_sha256")})
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED" or
            handoff.get("job_id") != "job_language_build"):
        raise ValueError("language-build handoff is not accepted")
    published = handoff.get("outputs", {}).get("acceptance.publish_handoff", {})
    identity = published.get("artifact") if isinstance(published, Mapping) else None
    if not isinstance(identity, Mapping):
        raise ValueError("language-build handoff does not publish its receipt set")
    document = _safe_artifact(run_root, identity)
    if document.get("schema") != SCHEMA:
        raise ValueError("language-build handoff schema is unsupported")
    return {**document, "language_build_handoff_sha256": pointer["handoff_sha256"]}


def _dispatches(unit: UnitContext) -> tuple[list[dict[str, Any]], Mapping[str, Any]]:
    accepted = load_accepted_builds(unit.job.run_root)
    if accepted.get("source_fingerprint") != unit.job.source_fingerprint:
        raise ValueError("target snapshot differs from accepted project-build dispatch")
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed after the accepted review snapshot")
    probes = {str(item.get("build_unit_id")): item for item in accepted.get("probe_receipts", ())}
    if len(probes) != len(accepted.get("probe_receipts", ())):
        raise ValueError("project-build handoff contains duplicate build units")
    values: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in accepted.get("build_dispatches", ()):
        if not isinstance(raw, Mapping) or raw.get("workflow") != "lang_jobflow_build":
            raise ValueError("project-build handoff contains an unknown build workflow")
        build_unit_id = str(raw.get("build_unit_id", ""))
        if not re.fullmatch(r"build-unit-[0-9a-f]{20}", build_unit_id) or build_unit_id in seen:
            raise ValueError("project-build handoff contains an unknown or duplicate build unit")
        seen.add(build_unit_id)
        probe = probes.get(build_unit_id)
        image, recipe = raw.get("image"), raw.get("recipe")
        if not isinstance(probe, Mapping) or probe.get("terminal_status") != "SUCCEEDED":
            raise ValueError("accepted build dispatch is not backed by a successful probe")
        if hashlib.sha256(canonical_json(probe)).hexdigest() != raw.get("probe_identity"):
            raise ValueError("accepted build dispatch probe identity mismatch")
        if not isinstance(image, Mapping) or not isinstance(recipe, Mapping):
            raise ValueError("accepted build dispatch recipe or image is unavailable")
        if (raw.get("source_fingerprint") != unit.job.source_fingerprint or raw.get("family") != probe.get("family") or
                raw.get("root") != probe.get("root") or raw.get("recipe_identity") != probe.get("recipe_identity") or
                image.get("image_id") != probe.get("image_id")):
            raise ValueError("accepted build dispatch recipe, image, or probe identity mismatch")
        dependencies = image.get("dependency_hashes")
        if not isinstance(dependencies, Mapping):
            raise ValueError("accepted build dispatch dependency identities are unavailable")
        profile = BuildProfile(str(raw["family"]), str(image.get("image_tag", "")),
                               str(image.get("base_image_id", "")), str(image.get("user", "")))
        expected_recipe = project_recipe_identity({**recipe, "build_system": raw.get("build_system")}, profile,
                                                   {str(k): str(v) for k, v in dependencies.items()})
        if expected_recipe != raw.get("recipe_identity"):
            raise ValueError("accepted build dispatch operational recipe identity mismatch")
        pseudo_unit = {"build_unit_id": build_unit_id, "family": raw["family"], "root": raw["root"],
                       "markers": [{"path": path} for path in dependencies],
                       "descriptor_package": {"documents": [{"path": path} for path in dependencies]}}
        errors = validate_build_recipe(recipe, pseudo_unit)
        if errors:
            raise ValueError("accepted build dispatch recipe is invalid: " + "; ".join(errors))
        build_dependencies = raw.get("build_dependencies")
        if (not isinstance(build_dependencies, list) or len(build_dependencies) != len(set(build_dependencies)) or
                any(not isinstance(value, str) or value == build_unit_id for value in build_dependencies)):
            raise ValueError("accepted build dispatch dependencies are invalid")
        _safe_root(unit.job.target_root or Path(), str(raw["root"]))
        values.append(dict(raw))
    return values, accepted


def _copy_source(unit: UnitContext, dispatch: Mapping[str, Any], workspace: Path) -> None:
    target = (unit.job.target_root or Path()).resolve(strict=True)
    source = _safe_root(target, str(dispatch["root"]))
    if workspace.exists():
        shutil.rmtree(workspace)
    destination = workspace if dispatch["root"] == "." else workspace / Path(*PurePosixPath(str(dispatch["root"])).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError("build source contains an unsupported symlink")
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(
        ".git", ".hg", ".svn", "build", "target", "node_modules"))
    try:
        workspace.chmod(0o777)
        for path in workspace.rglob("*"):
            path.chmod(0o777 if path.is_dir() else 0o666)
    except OSError:
        pass


def _snapshot(root: Path, limit: int) -> dict[str, str]:
    values: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            values[path.relative_to(root).as_posix()] = file_sha256(path)
            if len(values) > limit:
                raise ValueError("language-build workspace file-count bound exceeded")
    return values


def _kind(path: Path, family: str = "native", *, relative: str = "",
          before: Mapping[str, str] | None = None) -> str | None:
    if family == "dotnet":
        return dotnet.artifact_kind(path)
    if family == "rust":
        return rust.artifact_kind(path, relative, before or {})
    if family == "node":
        return node.artifact_kind(path)
    if family == "python":
        return python.artifact_kind(path, relative, before or {})
    suffix = path.suffix.lower()
    if path.name == "compile_commands.json": return "compile-database"
    if suffix in _SOURCE_SUFFIXES: return "generated-source"
    if suffix in _OBJECT_SUFFIXES: return "object"
    if suffix in _STATIC_SUFFIXES: return "static-library"
    if suffix in _SHARED_SUFFIXES: return "shared-library"
    if suffix in _BITCODE_SUFFIXES: return "llvm-bitcode"
    if suffix in _DEBUG_SUFFIXES: return "debug-information"
    if suffix in _MAP_SUFFIXES: return "link-map"
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return None
    return "executable" if magic == b"\x7fELF" else None


def _catalog(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int,
             build_unit_id: str, family: str = "native") -> tuple[list[dict[str, Any]], list[str]]:
    if family == "node":
        return node.catalog(run_root, workspace, before, limit, build_unit_id)
    artifacts, gaps = [], []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative, digest = path.relative_to(workspace).as_posix(), file_sha256(path)
        kind = _kind(path, family, relative=relative, before=before)
        if kind is None or before.get(relative) == digest:
            continue
        artifact = {"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
                          "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind,
                          "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
                          "mapping_confidence": 1.0}
        if kind in {"executable", "shared-library", "native-output"}:
            artifact.update(loader_dependencies=[], loader_dependency_status="unobserved")
            gaps.append(f"{relative}: static loader dependencies were not observable without a pinned parser")
        artifacts.append(artifact)
        if len(artifacts) >= limit:
            gaps.append("artifact catalog truncated at configured count bound")
            break
    return artifacts, gaps


def _compile_rows(workspace: Path, source_dir: str, build_dir: str) -> tuple[list[dict[str, Any]], list[str]]:
    paths = [workspace / Path(*PurePosixPath(build_dir).parts) / "compile_commands.json",
             workspace / Path(*PurePosixPath(source_dir).parts) / "compile_commands.json"]
    path = next((item for item in paths if item.is_file() and not item.is_symlink()), None)
    if path is None:
        return [], ["compile database was not emitted; compiler-to-artifact mappings are unavailable"]
    if path.stat().st_size > 16 * 1024 * 1024:
        return [], ["compile database exceeded the 16 MiB provenance bound"]
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or len(raw) > 4096:
        raise ValueError("emitted compile database is invalid or exceeds its row bound")
    rows = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise ValueError("emitted compile database row is invalid")
        argv = item.get("arguments")
        if argv is None and isinstance(item.get("command"), str):
            argv = shlex.split(item["command"])
        if not isinstance(argv, list) or not argv or any(not isinstance(v, str) or "\0" in v for v in argv):
            raise ValueError("emitted compile database argv is invalid")
        directory = str(item.get("directory", ""))
        declared_output = item.get("output")
        if not declared_output and "-o" in argv and argv.index("-o") + 1 < len(argv):
            declared_output = argv[argv.index("-o") + 1]
        inputs = _mapped_files(workspace, directory, [item.get("file")])
        outputs = _mapped_files(workspace, directory, [declared_output])
        rows.append({"ordinal": index + 1, "tool_kind": _TOOL_KINDS.get(Path(argv[0]).name, "compiler-driver"),
                     "tool": Path(argv[0]).name, "argv": argv, "directory": str(item.get("directory", "")),
                     "input": item.get("file"), "output": declared_output,
                     "inputs": inputs, "outputs": outputs,
                     "mapping": "compile-database", "mapping_confidence": 1.0})
    return rows, []


def _workspace_path(workspace: Path, directory: str, value: Any) -> Path | None:
    if not isinstance(value, str) or not value or "\0" in value:
        return None
    normalized = value.replace("\\", "/")
    base = directory.replace("\\", "/")
    host_candidate = Path(value).resolve()
    workspace_text = workspace.resolve().as_posix()
    if re.match(r"^[A-Za-z]:/", normalized) or normalized == workspace_text or normalized.startswith(workspace_text + "/"):
        if workspace.resolve() == host_candidate or workspace.resolve() in host_candidate.parents:
            return host_candidate
        return None
    if normalized == "/workspace":
        logical = PurePosixPath(".")
    elif normalized.startswith("/workspace/"):
        logical = PurePosixPath(normalized[len("/workspace/"):])
    elif normalized.startswith("/"):
        return None
    else:
        if base == "/workspace":
            base = ""
        elif base.startswith("/workspace/"):
            base = base[len("/workspace/"):]
        elif base.startswith("/"):
            return None
        logical = PurePosixPath(base) / PurePosixPath(normalized)
    if any(part == ".." for part in logical.parts):
        return None
    candidate = (workspace / Path(*logical.parts)).resolve()
    if workspace.resolve() != candidate and workspace.resolve() not in candidate.parents:
        return None
    return candidate


def _mapped_files(workspace: Path, directory: str, values: list[Any]) -> list[dict[str, Any]]:
    mapped = []
    for value in values:
        path = _workspace_path(workspace, directory, value)
        if path is None:
            continue
        row: dict[str, Any] = {"workspace_path": path.relative_to(workspace).as_posix()}
        if path.is_file() and not path.is_symlink():
            row.update(sha256=file_sha256(path), size_bytes=path.stat().st_size,
                       mapping="exact-workspace-path", mapping_confidence=1.0)
        else:
            row.update(mapping="declared-path-unresolved", mapping_confidence=0.5)
        mapped.append(row)
    return mapped


def _link_rows(workspace: Path, build_dir: str) -> tuple[list[dict[str, Any]], list[str]]:
    root = workspace / Path(*PurePosixPath(build_dir).parts)
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("link.txt"))[:4096] if root.is_dir() else ():
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:100]:
            if not line.strip():
                continue
            argv = shlex.split(line)
            if not argv:
                continue
            tool = Path(argv[0]).name
            kind = _TOOL_KINDS.get(tool, "compiler-driver-link")
            output_values: list[str] = []
            for index, value in enumerate(argv[:-1]):
                if value == "-o":
                    output_values.append(argv[index + 1])
            if kind == "archiver":
                candidates = [value for value in argv[1:] if value.endswith(tuple(_STATIC_SUFFIXES))]
                output_values.extend(candidates[:1])
            input_values = [value for value in argv[1:] if value.endswith(
                tuple(_OBJECT_SUFFIXES | _STATIC_SUFFIXES | _SHARED_SUFFIXES | _BITCODE_SUFFIXES)) and
                value not in output_values]
            directory = path.parent.relative_to(workspace).as_posix()
            rows.append({"tool_kind": "compiler-driver-link" if kind == "compiler-driver" else kind, "tool": tool,
                         "argv": argv, "directory": directory,
                         "origin": path.relative_to(workspace).as_posix(),
                         "inputs": _mapped_files(workspace, directory, input_values),
                         "outputs": _mapped_files(workspace, directory, output_values),
                         "mapping": "build-system-link-receipt", "mapping_confidence": 1.0})
    return rows, ([] if rows else
                  ["exact linker/archiver provenance was not emitted; link relationships remain ambiguous"])


def _normalized_links(rows: list[Mapping[str, Any]], build_dir: str) -> list[dict[str, Any]]:
    build_prefix = PurePosixPath(build_dir).as_posix().strip("./")

    def copied_path(value: Mapping[str, Any]) -> str | None:
        workspace_path = PurePosixPath(str(value.get("workspace_path", ""))).as_posix()
        if workspace_path == build_prefix:
            return "build"
        if build_prefix and workspace_path.startswith(build_prefix + "/"):
            return "build/" + workspace_path[len(build_prefix) + 1:]
        return None

    result = []
    for row in rows:
        outputs = [value for value in (copied_path(item) for item in row.get("outputs", ())) if value]
        inputs = [value for value in (copied_path(item) for item in row.get("inputs", ())) if value]
        if len(outputs) != 1 or not inputs:
            continue
        result.append({"output_path": outputs[0], "input_paths": sorted(set(inputs)),
                       "receipt": str(row.get("origin", "")),
                       "command_sha256": hashlib.sha256(canonical_json(row["argv"])).hexdigest()})
    return result


def _stream_artifact(run_root: Path, path: Path, *, result, stream: str, limit: int) -> dict[str, Any]:
    data = getattr(result, stream)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    raw_count = getattr(result, f"{stream}_bytes", None)
    count = len(data) if raw_count is None else int(raw_count)
    truncated = bool(getattr(result, f"{stream}_truncated", count > len(data)))
    value = {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
             "byte_count": count, "retained_byte_count": len(data), "capture_limit": limit,
             "truncated": truncated}
    tail = bytes(getattr(result, f"{stream}_tail", b""))
    if truncated and tail:
        tail_path = path.with_name(path.name + ".tail")
        tail_path.write_bytes(tail)
        value["diagnostic_tail"] = {"path": tail_path.relative_to(run_root).as_posix(),
                                    "sha256": file_sha256(tail_path), "byte_count": len(tail)}
    return value


def _go_argv(argv: tuple[str, ...]) -> tuple[str, ...]:
    if len(argv) > 1 and argv[0] == "go" and argv[1] in {"build", "generate"} and "-x" not in argv[2:]:
        return (argv[0], argv[1], "-x", *argv[2:])
    return argv


def _go_environment(recipe: Mapping[str, Any], workspace: Path) -> dict[str, str]:
    environment = _probe_environment(recipe)
    environment["GOPROXY"] = "off"
    environment["GOSUMDB"] = "off"
    environment.setdefault("GOCACHE", "/tmp/appsec-go-cache")
    source = workspace / Path(*PurePosixPath(str(recipe["source_dir"])).parts)
    if (source / "vendor").is_dir():
        flags = environment.get("GOFLAGS", "").split()
        if not any(value.startswith("-mod=") for value in flags):
            environment["GOFLAGS"] = " ".join([*flags, "-mod=vendor"]).strip()
    return environment


def _go_trace_rows(workspace: Path, data: bytes) -> list[dict[str, Any]]:
    rows, directory = [], "/workspace"
    for line in data.decode("utf-8", "replace").splitlines():
        text = line.strip()
        if text.startswith("cd "):
            directory = text[3:].strip()
            continue
        if not text or text.startswith(("WORK=", "mkdir ", "cat ", "cp ")):
            continue
        try:
            argv = shlex.split(text)
        except ValueError:
            continue
        while argv and "=" in argv[0] and not argv[0].startswith(("/", ".")):
            argv.pop(0)
        if not argv:
            continue
        tool = Path(argv[0]).name
        if tool not in _GO_TRACE_TOOLS:
            continue
        outputs: list[str] = []
        for index, value in enumerate(argv[:-1]):
            if value == "-o":
                outputs.append(argv[index + 1])
        inputs = [value for value in argv[1:] if value not in outputs and
                  Path(value).suffix.lower() in (_SOURCE_SUFFIXES | _OBJECT_SUFFIXES | _STATIC_SUFFIXES)]
        rows.append({"ordinal": len(rows) + 1, "tool_kind": _TOOL_KINDS.get(tool, "compiler"),
                     "tool": tool, "argv": argv, "directory": directory,
                     "inputs": _mapped_files(workspace, directory, inputs),
                     "outputs": _mapped_files(workspace, directory, outputs),
                     "mapping": "go-x-trace", "mapping_confidence": 1.0})
    return rows


def _go_module_metadata(workspace: Path, source_dir: str) -> list[dict[str, Any]]:
    root = workspace / Path(*PurePosixPath(source_dir).parts)
    names = {"go.mod", "go.sum", "go.work", "go.work.sum", "modules.txt"}
    values = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and (path.name in names or
                path.as_posix().endswith("/vendor/modules.txt")):
            values.append({"workspace_path": path.relative_to(workspace).as_posix(),
                           "sha256": file_sha256(path), "size_bytes": path.stat().st_size,
                           "kind": "go-module-metadata"})
    return values


def _go_package_rows(data: bytes) -> list[dict[str, Any]]:
    text = data.decode("utf-8", "replace")
    decoder, offset, rows = json.JSONDecoder(), 0, []
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError:
            break
        if not isinstance(value, Mapping) or not isinstance(value.get("ImportPath"), str):
            continue
        rows.append({"import_path": value["ImportPath"], "module_path":
                     value.get("Module", {}).get("Path") if isinstance(value.get("Module"), Mapping) else None,
                     "dependencies": sorted(str(item) for item in value.get("Imports", ()) if isinstance(item, str)),
                     "standard": bool(value.get("Standard", False)), "cgo_files": sorted(value.get("CgoFiles", ())),
                     "go_files": sorted(value.get("GoFiles", ())), "compiled_go_files": sorted(value.get("CompiledGoFiles", ()))})
    return rows


def _go_list_argv(commands: list[list[str]]) -> tuple[str, ...]:
    packages: list[str] = []
    forwarded: list[str] = []
    takes_value = {"-tags", "-mod", "-modfile", "-overlay"}
    for raw in commands:
        if len(raw) < 2 or raw[0] != "go" or raw[1] != "build":
            continue
        index = 2
        while index < len(raw):
            value = str(raw[index])
            if value in takes_value and index + 1 < len(raw):
                forwarded.extend((value, str(raw[index + 1])))
                index += 2
                continue
            if any(value.startswith(prefix + "=") for prefix in takes_value):
                forwarded.append(value)
            elif not value.startswith("-"):
                packages.append(value)
            index += 1
        break
    return ("go", "list", "-deps", "-json", *forwarded, *(packages or ["./..."]))


def _fingerprint(dispatch: Mapping[str, Any], accepted: Mapping[str, Any], settings: Mapping[str, Any] | None = None) -> str:
    image = dispatch["image"]
    return hashlib.sha256(canonical_json({"schema": RECEIPT_SCHEMA, "target": dispatch["source_fingerprint"],
        "recipe": dispatch["recipe_identity"], "dependencies": image["dependency_hashes"],
        "image": image["image_id"], "executor": EXECUTOR_IDENTITY,
        "capture": CAPTURE_IDENTITIES[str(dispatch["family"])],
        "toolchain": {"family": dispatch["family"], "image_id": image["image_id"]},
        "probe": dispatch["probe_identity"], "upstream_handoff": accepted["project_build_handoff_sha256"],
        "limits": ({key: settings[key] for key in
                    ("command_timeout_seconds", "output_bytes", "artifact_count_limit")}
                   if settings is not None else {}),
        "family_options": (settings.get(str(dispatch["family"]), {}) if settings is not None else {})})).hexdigest()


def _stream_identity(run_root: Path, path: Path, result: Any, name: str, limit: int) -> dict[str, Any]:
    data = bytes(getattr(result, name))
    total = getattr(result, f"{name}_bytes", None)
    total = len(data) if total is None else int(total)
    truncated = bool(getattr(result, f"{name}_truncated", False) or total > len(data))
    tail = bytes(getattr(result, f"{name}_tail", b""))
    tail_path = path.with_name(path.name + ".tail")
    try: path.chmod(0o600)
    except OSError: pass
    identity = {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
                "captured_bytes": len(data), "total_bytes": total,
                "capture_limit_bytes": limit, "truncated": truncated}
    try: path.chmod(0o600)
    except OSError: pass
    if truncated and tail:
        tail_path.write_bytes(tail)
        try: tail_path.chmod(0o600)
        except OSError: pass
        try: tail_path.chmod(0o600)
        except OSError: pass
        identity["diagnostic_tail"] = {"path": tail_path.relative_to(run_root).as_posix(),
                                       "sha256": file_sha256(tail_path),
                                       "size_bytes": len(tail)}
    return identity


def _platform_receipt(unit: UnitContext, dispatch: Mapping[str, Any], accepted: Mapping[str, Any],
                      gaps: list[str], projects: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema": RECEIPT_SCHEMA, "fingerprint": _fingerprint(dispatch, accepted, unit.job.config.settings),
            "source_fingerprint": unit.job.source_fingerprint,
            "upstream_handoff_sha256": accepted["project_build_handoff_sha256"],
            "build_unit_id": dispatch["build_unit_id"], "family": "dotnet", "root": dispatch["root"],
            "build_system": dispatch.get("build_system"), "recipe": dispatch["recipe"],
            "recipe_identity": dispatch["recipe_identity"], "probe_identity": dispatch["probe_identity"],
            "image": dispatch["image"], "workspace": None, "commands": [], "tool_invocations": [],
            "project_topology": projects, "artifacts": [], "gaps": gaps,
            "terminal_status": "NOT_APPLICABLE", "checkpoint_reused": False,
            "executor_identity": EXECUTOR_IDENTITY, "capture_identity": dotnet.CAPTURE_IDENTITY}


def _unavailable_dotnet_receipt(unit: UnitContext, probe: Mapping[str, Any],
                                accepted: Mapping[str, Any]) -> dict[str, Any]:
    root = str(probe.get("root", "."))
    projects, topology_gaps, platform_gaps = dotnet.project_topology(
        _safe_root(unit.job.target_root or Path(), root))
    gaps = list(dict.fromkeys([*topology_gaps, *platform_gaps, *probe.get("gaps", ())]))
    status = "NOT_APPLICABLE" if platform_gaps else "BLOCKED"
    fingerprint = hashlib.sha256(canonical_json({
        "schema": RECEIPT_SCHEMA, "target": unit.job.source_fingerprint,
        "family": "dotnet", "build_unit_id": probe.get("build_unit_id"),
        "probe": hashlib.sha256(canonical_json(probe)).hexdigest(),
        "upstream_handoff": accepted["project_build_handoff_sha256"],
        "executor": EXECUTOR_IDENTITY, "capture": dotnet.CAPTURE_IDENTITY,
    })).hexdigest()
    return {"schema": RECEIPT_SCHEMA, "fingerprint": fingerprint,
            "source_fingerprint": unit.job.source_fingerprint,
            "upstream_handoff_sha256": accepted["project_build_handoff_sha256"],
            "build_unit_id": probe.get("build_unit_id"), "family": "dotnet", "root": root,
            "build_system": probe.get("build_system"), "probe_identity": hashlib.sha256(
                canonical_json(probe)).hexdigest(), "commands": [], "tool_invocations": [],
            "project_topology": projects, "artifacts": [], "gaps": gaps,
            "terminal_status": status, "checkpoint_reused": False,
            "executor_identity": EXECUTOR_IDENTITY, "capture_identity": dotnet.CAPTURE_IDENTITY}


def _node_gap_receipt(unit: UnitContext, dispatch: Mapping[str, Any], accepted: Mapping[str, Any],
                      dependency: Mapping[str, Any], gaps: list[str]) -> dict[str, Any]:
    return {"schema": RECEIPT_SCHEMA,
            "fingerprint": _fingerprint(dispatch, accepted, unit.job.config.settings),
            "source_fingerprint": unit.job.source_fingerprint,
            "upstream_handoff_sha256": accepted["project_build_handoff_sha256"],
            "build_unit_id": dispatch["build_unit_id"], "family": "node", "root": dispatch["root"],
            "build_system": dispatch.get("build_system"), "recipe": dispatch["recipe"],
            "recipe_identity": dispatch["recipe_identity"], "probe_identity": dispatch["probe_identity"],
            "image": dispatch["image"], "workspace": None, "commands": [], "tool_invocations": [],
            "dependency_identity": dict(dependency), "artifacts": [], "gaps": gaps,
            "terminal_status": "BLOCKED", "checkpoint_reused": False,
            "executor_identity": EXECUTOR_IDENTITY, "capture_identity": node.CAPTURE_IDENTITY}


def _validate_checkpoint_artifacts(run_root: Path, receipt: Mapping[str, Any]) -> None:
    identities: list[Mapping[str, Any]] = []
    identities.extend(item for item in receipt.get("artifacts", ()) if isinstance(item, Mapping))
    for key in ("workspace_manifest", "protected_compile_commands", "link_database"):
        value = receipt.get(key)
        if isinstance(value, Mapping): identities.append(value)
    for command in receipt.get("commands", ()):
        if not isinstance(command, Mapping): continue
        for key in ("stdout", "stderr", "protected_argv"):
            value = command.get(key)
            if isinstance(value, Mapping):
                identities.append(value)
                tail = value.get("diagnostic_tail")
                if isinstance(tail, Mapping): identities.append(tail)
    for identity in identities:
        path = (run_root / str(identity.get("path", ""))).resolve()
        if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            raise FrameworkIntegrityError("language-build checkpoint artifact path is invalid")
        if file_sha256(path) != identity.get("sha256"):
            raise FrameworkIntegrityError("language-build checkpoint artifact identity changed")
    manifest_identity = receipt.get("workspace_manifest")
    workspace_relative = receipt.get("workspace")
    if isinstance(manifest_identity, Mapping) and isinstance(workspace_relative, str):
        manifest_path = run_root / str(manifest_identity["path"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        files = manifest.get("files") if isinstance(manifest, Mapping) else None
        workspace = (run_root / workspace_relative).resolve()
        if (manifest.get("schema") != "appsec-review/build-workspace-manifest/1" or
                not isinstance(files, Mapping) or run_root.resolve() not in workspace.parents):
            raise FrameworkIntegrityError("language-build checkpoint workspace manifest is invalid")
        for relative, digest in files.items():
            logical = PurePosixPath(str(relative))
            path = (workspace / Path(*logical.parts)).resolve()
            if (".." in logical.parts or workspace != path and workspace not in path.parents or
                    not path.is_file() or path.is_symlink() or file_sha256(path) != digest):
                raise FrameworkIntegrityError("language-build checkpoint workspace identity changed")


def _execute_one(unit: UnitContext, dispatch: Mapping[str, Any], accepted: Mapping[str, Any], executor_factory=None) -> dict[str, Any]:
    build_unit_id, recipe, image = str(dispatch["build_unit_id"]), dispatch["recipe"], dispatch["image"]
    family = str(dispatch["family"])
    fingerprint = _fingerprint(dispatch, accepted, unit.job.config.settings)
    root = unit.job.run_root / "data" / "build" / family / "units" / build_unit_id
    workspace = root / "workspace"
    cache = unit.job.metadata_root / "language-builds" / fingerprint / "accepted.json"
    with FileLock(cache.parent / "build.lock"):
        if cache.is_file():
            prior = json.loads(cache.read_text(encoding="utf-8"))
            prior_workspace = Path(str(prior.get("workspace", "")))
            if (prior.get("fingerprint") == fingerprint and prior.get("terminal_status") == "SUCCEEDED" and
                    prior_workspace.is_dir() and not prior_workspace.is_symlink()):
                if prior_workspace.resolve() != workspace.resolve():
                    if root.exists(): shutil.rmtree(root)
                    shutil.copytree(prior_workspace.parent, root)
                _validate_checkpoint_artifacts(unit.job.run_root, prior["receipt"])
                artifacts = [dict(identity) for identity in prior["receipt"].get("artifacts", ())]
                gaps: list[str] = []
                receipt = {**prior["receipt"], "workspace": workspace.relative_to(unit.job.run_root).as_posix(),
                           "artifacts": artifacts, "gaps": gaps, "checkpoint_reused": True,
                           "completed_at": datetime.now(timezone.utc).isoformat()}
                unit.job.events.write("LANGUAGE_BUILD_REUSED", unit_id=unit.unit_id,
                                      build_unit_id=build_unit_id, fingerprint=fingerprint,
                                      result_count=len(artifacts), gap_count=len(gaps), duration_ms=0)
                return receipt
    _copy_source(unit, dispatch, workspace)
    projects: list[dict[str, Any]] = []
    rust_settings = None
    if family == "rust":
        typed = unit.job.config.typed_settings
        if not isinstance(typed, LanguageBuildSettings):
            raise ValueError("typed language-build settings are unavailable")
        rust_settings = typed.rust
        rust_errors = rust.validate_dispatch(dispatch, rust_settings)
        if rust_errors:
            raise ValueError("accepted Rust dispatch is invalid: " + "; ".join(rust_errors))
    node_dependency: dict[str, Any] = {}
    node_manager: str | None = None
    if family == "node":
        node_manager, node_dependency, node_gaps = node.dependency_identity(dispatch)
        node_gaps.extend(node.validate_lifecycle_scripts(
            workspace, str(recipe["source_dir"]),
            [*recipe["configure_commands"], *recipe["build_commands"]]))
        if node_gaps:
            return _node_gap_receipt(unit, dispatch, accepted, node_dependency, node_gaps)
    php_policy: dict[str, Any] = {}
    php_metadata: dict[str, Any] | None = None
    if family == "php":
        php_errors = php.validate_php_dispatch(dispatch)
        php_policy = php.composer_policy(unit.job.config.settings)
        if php_policy["require_lockfile"] and php_errors:
            raise ValueError("accepted PHP dispatch is invalid: " + "; ".join(php_errors))
        php_metadata, _ = php.composer_metadata(workspace, str(recipe["source_dir"]))
    if family == "dotnet":
        projects, topology_gaps, platform_gaps = dotnet.project_topology(workspace)
        recipe_gaps = list(dotnet.validate_recipe(recipe, workspace))
        if platform_gaps:
            return _platform_receipt(unit, dispatch, accepted,
                                     [*topology_gaps, *platform_gaps], projects)
        if recipe_gaps:
            return {**_platform_receipt(unit, dispatch, accepted,
                                        [*topology_gaps, *recipe_gaps], projects),
                    "terminal_status": "BLOCKED"}
    python_relationships: list[dict[str, Any]] = []
    python_metadata_gaps: list[str] = []
    if family == "python":
        projects, python_relationships, python_metadata_gaps = python.project_metadata(
            workspace, str(recipe["source_dir"]))
        recipe_gaps = python.validate_dispatch(dispatch, workspace)
        if recipe_gaps:
            return {"schema": RECEIPT_SCHEMA,
                    "fingerprint": _fingerprint(dispatch, accepted, unit.job.config.settings),
                    "source_fingerprint": unit.job.source_fingerprint,
                    "upstream_handoff_sha256": accepted["project_build_handoff_sha256"],
                    "build_unit_id": build_unit_id, "family": family, "root": dispatch["root"],
                    "build_system": dispatch.get("build_system"), "recipe_identity": dispatch["recipe_identity"],
                    "probe_identity": dispatch["probe_identity"], "image": image, "workspace": None,
                    "commands": [], "tool_invocations": [], "project_topology": projects,
                    "package_relationships": python_relationships, "artifacts": [],
                    "gaps": [*python_metadata_gaps, *recipe_gaps], "terminal_status": "BLOCKED",
                    "checkpoint_reused": False, "executor_identity": EXECUTOR_IDENTITY,
                    "capture_identity": python.CAPTURE_IDENTITY}
    before = _snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    rust_environment: dict[str, str] = {}
    rust_invocations: Path | None = None
    if family == "rust" and rust_settings is not None:
        rust_environment, rust_invocations = rust.install_capture_wrappers(workspace, rust_settings)
    profile = BuildProfile(family, str(image["image_tag"]), str(image["image_id"]), str(image["user"]))
    executor = executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
        profile, timeout_seconds=int(unit.job.config.settings["command_timeout_seconds"]),
        output_bytes=int(unit.job.config.settings["output_bytes"]))
    executor.resolve()
    protected = root / "protected-commands"
    protected.mkdir(parents=True, exist_ok=True)
    commands, gaps, go_trace_rows, node_rows = [], [], [], []
    cargo_metadata: dict[str, Any] | None = None
    rust_stderr = bytearray()
    operational_recipe = {**recipe, "build_system": dispatch.get("build_system")}
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    command_plan: list[tuple[str, Sequence[str]]] = []
    if family == "rust" and rust_settings is not None:
        command_plan.append(("metadata", rust.metadata_argv(recipe, rust_settings)))
    command_plan.extend(("configure", raw) for raw in recipe["configure_commands"])
    command_plan.extend(("build", raw) for raw in recipe["build_commands"])
    unit.job.events.write("LANGUAGE_BUILD_STARTED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
                          family=family, recipe_identity=dispatch["recipe_identity"],
                          image_id=image["image_id"], command_count=len(command_plan))
    for ordinal, (role, raw) in enumerate(command_plan, 1):
        argv = tuple(raw) if role == "metadata" else _normalized_argv(recipe, list(raw))
        if family == "go":
            argv = _go_argv(argv)
        elif family == "rust" and rust_settings is not None:
            argv = rust.build_argv(argv, rust_settings)
        elif family == "php":
            argv = php.policy_argv(argv, php_policy)
        environment = (_go_environment(operational_recipe, workspace) if family == "go"
                       else _probe_environment(operational_recipe))
        if family == "node":
            environment.update({"NPM_CONFIG_OFFLINE": "true", "NPM_CONFIG_AUDIT": "false",
                                "NPM_CONFIG_FUND": "false", "YARN_ENABLE_NETWORK": "0",
                                "YARN_ENABLE_IMMUTABLE_INSTALLS": "true",
                                "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0", "V": "1",
                                "MAKEFLAGS": "V=1", "npm_config_loglevel": "verbose"})
        elif family == "rust":
            prior_flags = environment.get("RUSTFLAGS", "").strip()
            wrapper_flags = rust_environment.get("RUSTFLAGS", "").strip()
            environment.update(rust_environment)
            if prior_flags and wrapper_flags:
                environment["RUSTFLAGS"] = prior_flags + " " + wrapper_flags
        elif family == "python":
            environment.update(python.environment(operational_recipe))
        elif family == "php":
            environment.update({"COMPOSER_NO_INTERACTION": "1", "COMPOSER_DISABLE_NETWORK": "1",
                                "COMPOSER_PROCESS_TIMEOUT": str(unit.job.config.settings["command_timeout_seconds"])})
        command_before = (_snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
                          if family == "node" else {})
        command_started = time.monotonic()
        result = executor.execute(argv, workspace=workspace, working_directory=str(recipe["source_dir"]),
                                  environment=environment)
        command_id = hashlib.sha256(canonical_json({"attempt": unit.job.attempt_id,
                                                    "unit": build_unit_id, "ordinal": ordinal,
                                                    "argv": list(argv)})).hexdigest()
        stdout, stderr = root / "logs" / f"{ordinal:03d}.stdout", root / "logs" / f"{ordinal:03d}.stderr"
        stdout.parent.mkdir(parents=True, exist_ok=True)
        stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
        exact = protected / f"{command_id[:24]}.json"
        protected_json(exact, {"schema": "appsec-review/protected-build-command/2", "argv": list(result.argv),
            "working_directory": str(recipe["source_dir"]), "environment": dict(environment),
            "access": "run-owned-protected"})
        try: exact.chmod(0o600)
        except OSError: pass
        failed = result.timed_out or result.exit_code != 0
        limit = int(unit.job.config.settings["output_bytes"])
        stdout_identity = _stream_identity(unit.job.run_root, stdout, result, "stdout", limit)
        stderr_identity = _stream_identity(unit.job.run_root, stderr, result, "stderr", limit)
        commands.append({"command_id": command_id, "attempt_identity": unit.job.attempt_id,
            "ordinal": ordinal, "tool": Path(argv[0]).name,
            "tool_kind": (php.invocation_kind(Path(argv[0]).name, argv) if family == "php" else
                          _TOOL_KINDS.get(Path(argv[0]).name, "build-driver")),
            "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
            "working_directory": str(recipe["source_dir"]),
            "environment_facts": {key: "set" for key in sorted(environment)
                                  if not _SECRET_KEY.search(key)},
            "started_at": datetime.now(timezone.utc).isoformat(), "duration_ms": int((time.monotonic()-command_started)*1000),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "stdout": stdout_identity, "stderr": stderr_identity,
            "protected_argv": {"path": exact.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(exact)},
            "image_id": image["image_id"], "build_unit_id": build_unit_id,
            "role": role,
            "module": (argv[2] if len(argv) > 2 and argv[1] == "-m" else None)})
        if family == "go":
            go_trace_rows.extend(_go_trace_rows(workspace, result.stderr))
        elif family == "node":
            command_after = _snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
            observed, observed_gaps = node.invocation_rows(
                workspace, str(recipe["source_dir"]), result.argv, success=not failed,
                before=command_before, after=command_after,
                diagnostic_streams=(result.stdout, result.stderr))
            node_rows.extend(observed)
            gaps.extend(observed_gaps)
        elif family == "rust":
            rust_stderr.extend(result.stderr)
            if result.stderr_truncated and result.stderr_tail:
                rust_stderr.extend(b"\n")
                rust_stderr.extend(result.stderr_tail)
            if role == "metadata" and not failed:
                cargo_metadata = rust.parse_metadata(result.stdout)
        unit.job.events.write("BUILD_COMMAND_COMPLETED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
            command_id=command_id, tool=Path(argv[0]).name, disposition="FAILED" if failed else "SUCCEEDED",
            result_count=0, gap_count=1 if failed else 0,
            truncated=stdout_identity["truncated"] or stderr_identity["truncated"],
            duration_ms=commands[-1]["duration_ms"])
        if failed:
            gaps.append(f"build command {ordinal} {'timed out' if result.timed_out else f'exited {result.exit_code}'}")
            break
    package_relationships: list[dict[str, Any]] = []
    if family == "go" and not any(command["timed_out"] or command["exit_code"] != 0 for command in commands):
        ordinal = len(commands) + 1
        argv = _normalized_argv(recipe, list(_go_list_argv(list(recipe["build_commands"]))))
        environment = _go_environment(operational_recipe, workspace)
        command_started = time.monotonic()
        result = executor.execute(argv, workspace=workspace, working_directory=str(recipe["source_dir"]),
                                  environment=environment)
        command_id = hashlib.sha256(canonical_json({"attempt": unit.job.attempt_id,
                                                    "unit": build_unit_id, "ordinal": ordinal,
                                                    "argv": list(argv)})).hexdigest()
        stdout, stderr = root / "logs" / f"{ordinal:03d}.stdout", root / "logs" / f"{ordinal:03d}.stderr"
        stdout.parent.mkdir(parents=True, exist_ok=True)
        stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
        exact = protected / f"{command_id}.json"
        protected_json(exact, {"schema": "appsec-review/protected-build-command/2", "argv": list(result.argv),
            "working_directory": str(recipe["source_dir"]), "environment": dict(environment),
            "access": "run-owned-protected"})
        try: exact.chmod(0o600)
        except OSError: pass
        limit = int(unit.job.config.settings["output_bytes"])
        stdout_identity = _stream_identity(unit.job.run_root, stdout, result, "stdout", limit)
        stderr_identity = _stream_identity(unit.job.run_root, stderr, result, "stderr", limit)
        commands.append({"command_id": command_id, "attempt_identity": unit.job.attempt_id,
            "ordinal": ordinal, "tool": "go", "tool_kind": "package-catalog", "role": "catalog",
            "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
            "working_directory": str(recipe["source_dir"]),
            "environment_facts": {key: "set" for key in sorted(environment) if not _SECRET_KEY.search(key)},
            "started_at": datetime.now(timezone.utc).isoformat(),
            "duration_ms": int((time.monotonic() - command_started) * 1000),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "stdout": stdout_identity, "stderr": stderr_identity,
            "protected_argv": {"path": exact.relative_to(unit.job.run_root).as_posix(),
                               "sha256": file_sha256(exact)},
            "image_id": image["image_id"], "build_unit_id": build_unit_id})
        package_relationships = _go_package_rows(result.stdout) if result.exit_code == 0 and not result.timed_out else []
        if not package_relationships:
            gaps.append("go package relationship catalog was unavailable")
        unit.job.events.write("BUILD_COMMAND_COMPLETED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
            command_id=command_id, tool="go", disposition=("SUCCEEDED" if package_relationships else "FAILED"),
            result_count=len(package_relationships), gap_count=0 if package_relationships else 1,
            truncated=stdout_identity["truncated"] or stderr_identity["truncated"],
            duration_ms=commands[-1]["duration_ms"])
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise FrameworkIntegrityError("target changed during generic language-build execution")
    if family == "php":
        artifacts, catalog_gaps = php.catalog(unit.job.run_root, workspace, before,
            int(unit.job.config.settings["artifact_count_limit"]), build_unit_id)
    else:
        artifacts, catalog_gaps = _catalog(unit.job.run_root, workspace, before,
                                           int(unit.job.config.settings["artifact_count_limit"]), build_unit_id, family)
    gaps.extend([*python_metadata_gaps, *catalog_gaps])
    build_metadata: list[dict[str, Any]] = []
    if family == "go":
        source_prefix = PurePosixPath(str(recipe["source_dir"]))
        for artifact in [value for value in artifacts if value.get("kind") == "executable"]:
            workspace_path = PurePosixPath(str(artifact["workspace_path"]))
            try:
                inspected_path = workspace_path.relative_to(source_prefix).as_posix()
            except ValueError:
                inspected_path = workspace_path.as_posix()
            ordinal = len(commands) + 1
            argv = ("go", "tool", "buildid", inspected_path)
            environment = _go_environment(operational_recipe, workspace)
            command_started = time.monotonic()
            result = executor.execute(argv, workspace=workspace, working_directory=str(recipe["source_dir"]),
                                      environment=environment)
            command_id = hashlib.sha256(canonical_json({"attempt": unit.job.attempt_id,
                                                        "unit": build_unit_id, "ordinal": ordinal,
                                                        "argv": list(argv)})).hexdigest()
            stdout, stderr = root / "logs" / f"{ordinal:03d}.stdout", root / "logs" / f"{ordinal:03d}.stderr"
            stdout.parent.mkdir(parents=True, exist_ok=True)
            stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
            exact = protected / f"{command_id}.json"
            protected_json(exact, {"schema": "appsec-review/protected-build-command/2", "argv": list(result.argv),
                "working_directory": str(recipe["source_dir"]), "environment": dict(environment),
                "access": "run-owned-protected"})
            limit = int(unit.job.config.settings["output_bytes"])
            stdout_identity = _stream_identity(unit.job.run_root, stdout, result, "stdout", limit)
            stderr_identity = _stream_identity(unit.job.run_root, stderr, result, "stderr", limit)
            commands.append({"command_id": command_id, "attempt_identity": unit.job.attempt_id,
                "ordinal": ordinal, "tool": "go", "tool_kind": "post-link", "role": "inspect",
                "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
                "working_directory": str(recipe["source_dir"]),
                "environment_facts": {key: "set" for key in sorted(environment) if not _SECRET_KEY.search(key)},
                "started_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": int((time.monotonic() - command_started) * 1000),
                "exit_code": result.exit_code, "timed_out": result.timed_out,
                "stdout": stdout_identity, "stderr": stderr_identity,
                "protected_argv": {"path": exact.relative_to(unit.job.run_root).as_posix(),
                                   "sha256": file_sha256(exact)},
                "image_id": image["image_id"], "build_unit_id": build_unit_id})
            build_id = result.stdout.decode("utf-8", "replace").strip() if result.exit_code == 0 else ""
            if build_id:
                artifact["build_id_sha256"] = hashlib.sha256(build_id.encode()).hexdigest()
                build_metadata.append({"workspace_path": artifact["workspace_path"],
                                       "build_id_sha256": artifact["build_id_sha256"],
                                       "debug_data": "embedded-go-debug-data-unparsed"})
            else:
                gaps.append(f"{artifact['workspace_path']}: Go build ID was unavailable")
    package_members: list[dict[str, Any]] = []
    if family == "python":
        for artifact in artifacts:
            if artifact["kind"] not in {"wheel", "source-distribution"}:
                continue
            rows, archive_gaps = python.package_contents(unit.job.run_root / artifact["path"], workspace)
            package_members.extend(rows)
            gaps.extend(archive_gaps)
    if family == "native":
        compile_rows, compile_gaps = _compile_rows(workspace, str(recipe["source_dir"]), str(recipe["build_dir"]))
        gaps.extend(compile_gaps)
        link_rows, link_gaps = _link_rows(workspace, str(recipe["build_dir"]))
        gaps.extend(link_gaps)
        normalized_links = _normalized_links(link_rows, str(recipe["build_dir"]))
    elif family == "go":
        compile_rows, link_rows, normalized_links = go_trace_rows, [], []
        if not compile_rows:
            gaps.append("go -x did not expose compiler, assembler, linker, cgo, or package-builder invocations")
    elif family == "node":
        compile_rows, link_rows, normalized_links = node_rows, [], []
        if not compile_rows:
            gaps.append("Node build did not expose compiler, transpiler, generator, bundler, or package invocations")
    elif family == "rust":
        compile_rows = rust.parse_invocations(bytes(rust_stderr), workspace,
                                              rust_invocations or workspace / ".missing")
        link_rows = []
        normalized_links = _normalized_links(
            [row for row in compile_rows if row.get("tool_kind") in {"linker-driver", "archiver"}],
            str(recipe["build_dir"]),
        )
        kinds = {str(row.get("tool_kind")) for row in compile_rows}
        for expected in ("compiler", "linker-driver", "archiver"):
            if expected not in kinds:
                gaps.append(f"Rust {expected} invocation was not observable in the bounded capture")
        if cargo_metadata is None:
            gaps.append("Cargo metadata was unavailable")
    elif family == "python":
        streams = [stream for command in commands for stream in (
            (unit.job.run_root / command["stdout"]["path"]).read_bytes(),
            (unit.job.run_root / command["stderr"]["path"]).read_bytes())]
        compile_rows = python.tool_invocations(commands, streams, workspace, projects)
        link_rows, normalized_links = [], []
        if not compile_rows:
            gaps.append("Python package build did not expose a package-builder or compiler invocation")
    elif family == "php":
        compile_rows = [{"ordinal": command["ordinal"], "tool": command["tool"],
                         "tool_kind": command["tool_kind"], "directory": command["working_directory"],
                         "argv_sha256": command["argv_sha256"], "inputs": [], "outputs": [],
                         "mapping": "top-level-protected-command", "mapping_confidence": 1.0}
                        for command in commands]
        link_rows, normalized_links = [], []
        if not any(row["tool_kind"] in {"autoload-generator", "package-builder", "code-generator",
                                        "compiler-driver", "linker", "archiver"} for row in compile_rows):
            gaps.append("PHP build exposed no autoload, package, code-generation, or native-tool invocation")
    else:
        compile_rows = dotnet.parse_tool_invocations(
            [stream for command in commands for stream in (
                (unit.job.run_root / command["stdout"]["path"]).read_bytes(),
                (unit.job.run_root / command["stderr"]["path"]).read_bytes())], workspace)
        link_rows, normalized_links = [], []
        if not compile_rows:
            gaps.append("MSBuild diagnostic streams did not expose compiler or post-compile invocations")
    link_database = workspace / Path(*PurePosixPath(str(recipe["build_dir"])).parts) / ".appsec-review-link-commands.json"
    atomic_json(link_database, normalized_links)
    compile_protected = root / "protected-commands" / f"compile-database-{unit.job.attempt_id}.json"
    protected_json(compile_protected, {"schema": "appsec-review/protected-compile-commands/1",
                                   "rows": [*compile_rows, *link_rows]})
    try: compile_protected.chmod(0o600)
    except OSError: pass
    sanitized_compile = [{key: value for key, value in row.items() if key != "argv"} |
                         {"argv_sha256": (hashlib.sha256(canonical_json(row["argv"])).hexdigest()
                                          if "argv" in row else row["argv_sha256"])}
                         for row in [*compile_rows, *link_rows]]
    workspace_manifest_path = root / "workspace-manifest.json"
    workspace_files = _snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    atomic_json(workspace_manifest_path, {"schema": "appsec-review/build-workspace-manifest/1",
                "build_unit_id": build_unit_id, "files": workspace_files})
    status = "FAILED" if any("build command" in gap for gap in gaps) else "SUCCEEDED"
    receipt = {"schema": RECEIPT_SCHEMA, "fingerprint": fingerprint, "source_fingerprint": unit.job.source_fingerprint,
        "upstream_handoff_sha256": accepted["project_build_handoff_sha256"], "build_unit_id": build_unit_id,
        "family": family, "root": dispatch["root"], "build_system": dispatch.get("recipe", {}).get("build_system", dispatch.get("build_system")),
        "recipe": recipe, "recipe_identity": dispatch["recipe_identity"], "probe_identity": dispatch["probe_identity"],
        "image": image, "workspace": workspace.relative_to(unit.job.run_root).as_posix(),
        "commands": commands, "tool_invocations": sanitized_compile,
        "project_topology": projects,
        "dependency_identity": node_dependency if family == "node" else None,
        "protected_compile_commands": {"path": compile_protected.relative_to(unit.job.run_root).as_posix(),
                                       "sha256": file_sha256(compile_protected)},
        "link_database": {"path": link_database.relative_to(unit.job.run_root).as_posix(),
                          "sha256": file_sha256(link_database), "relationship_count": len(normalized_links)},
        "workspace_manifest": {"path": workspace_manifest_path.relative_to(unit.job.run_root).as_posix(),
                               "sha256": file_sha256(workspace_manifest_path)},
        "artifacts": artifacts, "gaps": list(dict.fromkeys(gaps)), "terminal_status": status,
        "checkpoint_reused": False, "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(), "duration_ms": int((time.monotonic()-started)*1000),
        "executor_identity": EXECUTOR_IDENTITY, "capture_identity": CAPTURE_IDENTITIES[family]}
    if family == "go":
        receipt["module_metadata"] = _go_module_metadata(workspace, str(recipe["source_dir"]))
        receipt["package_relationships"] = package_relationships
        receipt["build_metadata"] = build_metadata
    if family == "rust":
        receipt["cargo_metadata"] = cargo_metadata or {
            "schema": "appsec-review/rust-cargo-metadata/1", "packages": [], "relationships": []}
        receipt["package_relationships"] = list(receipt["cargo_metadata"].get("relationships", ()))
    if family == "python":
        receipt["package_relationships"] = python_relationships
        receipt["package_members"] = package_members
    if family == "php":
        receipt["composer"] = php_metadata
        receipt["composer_policy"] = php_policy
        receipt["package_relationships"] = list((php_metadata or {}).get("relationships", ()))
    if status == "SUCCEEDED":
        cache.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(cache.parent / "build.lock"):
            atomic_json(cache, {"schema": "appsec-review/language-build-checkpoint/1", "fingerprint": fingerprint,
                                "terminal_status": status, "workspace": str(workspace), "receipt": receipt})
    unit.job.events.write("LANGUAGE_BUILD_COMPLETED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
                          disposition=status, result_count=len(artifacts), gap_count=len(receipt["gaps"]),
                          command_count=len(commands), link_relationship_count=len(normalized_links),
                          checkpoint_reused=False, duration_ms=receipt["duration_ms"])
    return receipt


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != ("load", "execute", "acceptance"):
        raise ValueError("language-build topology does not match central configuration")
    expected = {"load": ("native", "go", "dotnet", "node", "python", "rust", "php", "java", "wasm"),
                "execute": ("native", "go", "dotnet", "node", "python", "rust", "php", "java", "wasm"),
                "acceptance": ("publish_handoff",)}
    for step, tasks in expected.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"language-build task order mismatch: {step}")
    for key in ("command_timeout_seconds", "output_bytes", "artifact_count_limit"):
        if type(context.config.settings.get(key)) is not int or context.config.settings[key] < 1:
            raise ValueError(f"language-build bound is invalid: {key}")
    dotnet_settings = context.config.settings.get("dotnet")
    expected_dotnet = {"require_locked_restore", "capture_msbuild_diagnostics", "generated_sources",
                       "allow_publish", "allow_pack", "allow_aot"}
    if (not isinstance(dotnet_settings, Mapping) or set(dotnet_settings) != expected_dotnet or
            any(type(dotnet_settings[key]) is not bool for key in expected_dotnet)):
        raise ValueError("language-build dotnet settings are invalid")
    go_settings = context.config.settings.get("go")
    if (not isinstance(go_settings, Mapping) or set(go_settings) != {
            "offline", "capture_trace", "package_catalog", "diagnostic_tail_bytes"} or
            any(type(go_settings.get(key)) is not bool for key in
                ("offline", "capture_trace", "package_catalog")) or
            any(go_settings.get(key) is not True for key in
                ("offline", "capture_trace", "package_catalog")) or
            type(go_settings.get("diagnostic_tail_bytes")) is not int or
            not 1 <= go_settings["diagnostic_tail_bytes"] <= 1024 * 1024):
        raise ValueError("language-build Go settings are invalid")
    typed = context.config.typed_settings
    rust_value = context.config.settings.get("rust")
    if (not isinstance(typed, LanguageBuildSettings) or not isinstance(rust_value, Mapping) or
            set(rust_value) - {"toolchain", "target", "profile", "features", "locked", "offline",
                               "capture_linker", "diagnostic_tail_bytes"} or
            any(type(rust_value.get(key)) is not bool for key in ("locked", "offline", "capture_linker"))):
        raise ValueError("language-build Rust settings are invalid")
    node_settings = context.config.settings.get("node")
    if (not isinstance(typed, LanguageBuildSettings) or not isinstance(node_settings, Mapping) or set(node_settings) != {
            "package_managers", "require_lockfile", "network", "lifecycle_scripts",
            "capture_source_maps", "diagnostic_tail_bytes"} or
            node_settings.get("package_managers") != ["npm", "pnpm", "yarn"] or
            node_settings.get("require_lockfile") is not True or
            node_settings.get("network") != "denied" or
            node_settings.get("lifecycle_scripts") != "sandboxed" or
            node_settings.get("capture_source_maps") is not True or
            type(node_settings.get("diagnostic_tail_bytes")) is not int or
            node_settings["diagnostic_tail_bytes"] < 1):
        raise ValueError("language-build Node settings are invalid")
    python_settings = context.config.settings.get("python")
    if (not isinstance(python_settings, Mapping) or set(python_settings) != {
            "frontend", "require_locked_dependencies", "offline", "capture_native_tools",
            "diagnostic_tail_bytes"} or python_settings.get("frontend") not in {"build", "pip", "setuptools"} or
            python_settings.get("require_locked_dependencies") is not True or
            python_settings.get("offline") is not True or python_settings.get("capture_native_tools") is not True or
            type(python_settings.get("diagnostic_tail_bytes")) is not int or
            python_settings["diagnostic_tail_bytes"] < 1):
        raise ValueError("language-build Python settings are invalid")
    jvm.validate_jvm_settings(context.config.settings)
    from . import wasm
    wasm_settings = context.config.settings.get("wasm")
    if not isinstance(wasm_settings, Mapping) or set(wasm_settings) != {"workspace_file_limit", "producers"}:
        raise ValueError("language-build WASM settings are invalid")
    if type(wasm_settings["workspace_file_limit"]) is not int or wasm_settings["workspace_file_limit"] < 1:
        raise ValueError("language-build WASM workspace bound is invalid")
    wasm._producer_rules(wasm_settings)


def _publish_build_index(unit: UnitContext, receipts: list[Mapping[str, Any]]) -> dict[str, Any]:
    prior_path, prior_sha = resolve_accepted_manifest(unit.job.run_root)
    prior, _ = load_verified_manifest(unit.job.run_root, prior_path, prior_sha)
    producer = [{"build_unit_id": receipt.get("build_unit_id"), "fingerprint": receipt.get("fingerprint"),
                 "status": receipt.get("terminal_status")} for receipt in receipts]
    fingerprint = index_fingerprint(name="build", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=producer, tool_identity={"executor": EXECUTOR_IDENTITY},
        parser_identity="language-build-command-artifact/1", normalizer_identity="sanitized-build-evidence/1",
        mapping_identity="workspace-artifact/1", upstream_manifests=(prior_sha,))
    path = unit.job.run_root / "data" / "indices" / "build" / f"language-build-{unit.job.attempt_id}-{fingerprint}.sqlite"
    builder = IndexBuilder(path, name="build", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id="language-build")
    for receipt in receipts:
        build_unit_id = str(receipt.get("build_unit_id"))
        package_ids: dict[str, str] = {}
        metadata = receipt.get("cargo_metadata")
        if isinstance(metadata, Mapping):
            for package in metadata.get("packages", ()):
                if not isinstance(package, Mapping) or not isinstance(package.get("id"), str):
                    continue
                package_identity = LogicalIdentity.derive(EntityKind.PROJECT, unit.job.source_fingerprint,
                    {"build_unit_id": build_unit_id, "cargo_package_id": package["id"]})
                package_ids[package["id"]] = package_identity.value
                builder.add_entity(EntityRecord(package_identity, package["id"], str(package.get("name", "")),
                    f"Cargo package {package.get('name', '')} {package.get('version', '')}",
                    {key: package.get(key) for key in ("name", "version", "features", "targets")}))
            for relation in metadata.get("relationships", ()):
                if not isinstance(relation, Mapping):
                    continue
                source_id, target_id = package_ids.get(str(relation.get("from"))), package_ids.get(str(relation.get("to")))
                if source_id and target_id:
                    builder.add_relation(RelationRecord(RelationKind.DEPENDS_ON, source_id, target_id,
                                                        True, 1.0, payload={"source": "cargo-resolve"}))
        for command in receipt.get("commands", ()):
            identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                {"build_unit_id": build_unit_id, "command_id": command.get("command_id")})
            streams = {name: {key: stream.get(key) for key in
                       ("sha256", "captured_bytes", "total_bytes", "capture_limit_bytes", "truncated")}
                       for name in ("stdout", "stderr") if isinstance((stream := command.get(name)), Mapping)}
            payload = {key: command.get(key) for key in
                       ("command_id", "ordinal", "tool", "tool_kind", "argv_sha256", "working_directory",
                        "environment_facts", "exit_code", "timed_out", "duration_ms", "image_id")}
            payload["streams"] = streams
            builder.add_entity(EntityRecord(identity, str(command.get("command_id")),
                f"{command.get('tool', 'build')} command", f"{command.get('tool_kind', 'build-driver')} "
                f"{command.get('exit_code')} {command.get('argv_sha256')}", payload))
        for artifact in receipt.get("artifacts", ()):
            kind = EntityKind.LIBRARY if "library" in str(artifact.get("kind")) else (
                EntityKind.EXECUTABLE if artifact.get("kind") in {"executable", "managed-assembly", "native-output"}
                else EntityKind.EVIDENCE_ARTIFACT)
            identity = LogicalIdentity.derive(kind, unit.job.source_fingerprint,
                {"build_unit_id": build_unit_id, "path": artifact.get("workspace_path"),
                 "sha256": artifact.get("sha256")})
            builder.add_entity(EntityRecord(identity, str(artifact.get("workspace_path")),
                str(artifact.get("workspace_path")), f"{artifact.get('kind')} {artifact.get('workspace_path')}",
                {key: artifact.get(key) for key in ("workspace_path", "sha256", "size_bytes", "kind",
                                                     "mapping", "mapping_confidence", "build_unit_id")}))
    gaps = [gap for receipt in receipts for gap in receipt.get("gaps", ())]
    builder.add_coverage("language-build", "partial" if gaps else "complete", gaps[0] if gaps else None)
    sha = builder.build()
    identity = IndexIdentity("build", "appsec-review/retrieval-index/2", sha, fingerprint,
                             path.relative_to(unit.job.run_root).as_posix(),
                             {"job": "job_language_build", "unit": unit.unit_id}, tuple(gaps), "language-build")
    indexes = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}) for raw in prior["indexes"]]
    indexes = [value for value in indexes if not (value.name == "build" and value.shard_id == "language-build")]
    indexes.append(identity)
    manifest = unit.job.run_root / "data" / "indices" / "manifests" / f"language-build-{unit.job.attempt_id}.json"
    write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=unit.job.target_root or Path(), indexes=indexes,
                   upstream_manifests=({"path": prior_path.relative_to(unit.job.run_root).as_posix(),
                                        "sha256": prior_sha},))
    return {"path": manifest.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(manifest)}


def build_job(*, executor_factory=None) -> Job:
    from . import wasm

    def load_family(family: str):
      def load(unit: UnitContext) -> Mapping[str, Any]:
        dispatches, accepted = _dispatches(unit)
        wasm_rules = wasm._producer_rules(unit.job.config.settings["wasm"])
        wasm_selected = [(item, wasm._select_producer(item, wasm_rules)) for item in dispatches]
        if family == "wasm":
            selected = [{**item, "wasm_producer": producer} for item, producer in wasm_selected if producer]
        else:
            selected = [item for item, producer in wasm_selected
                        if item["family"] == family and producer is None]
        selected_ids = {str(item["build_unit_id"]) for item in selected}
        unavailable = ([item for item in accepted.get("probe_receipts", ())
                        if item.get("family") == "dotnet"
                        and str(item.get("build_unit_id")) not in selected_ids]
                       if family == "dotnet" else [])
        if family == "rust":
            typed = unit.job.config.typed_settings
            if not isinstance(typed, LanguageBuildSettings):
                raise ValueError("typed language-build settings are unavailable")
            for dispatch in selected:
                errors = rust.validate_dispatch(dispatch, typed.rust)
                if errors:
                    raise ValueError("accepted Rust dispatch is invalid: " + "; ".join(errors))
        gaps = [f"{item.get('build_unit_id')}: " + "; ".join(item.get("gaps", ()))
                for item in unavailable]
        if family == "wasm":
            gaps.extend(f"{item['build_unit_id']}: no configured WebAssembly producer matched accepted recipe"
                        for item, producer in wasm_selected if producer is None and
                        (item["family"] == "wasm" or any(str(value).lower().endswith(".wasm")
                         for value in item["recipe"].get("expected_outputs", ()))))
        return {"dispatches": selected, "unavailable": unavailable, "accepted": accepted,
                "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else
                                   "SUCCEEDED" if selected else "NOT_APPLICABLE"}
      return load

    def execute_family(family: str):
      def execute(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output(f"load.{family}")
        dispatches = {str(item["build_unit_id"]): item for item in loaded["dispatches"]}
        known_units = {str(item.get("build_unit_id")) for item in loaded["accepted"].get("probe_receipts", ())}
        if any(dependency not in known_units for item in dispatches.values()
               for dependency in item.get("build_dependencies", ())):
            raise ValueError("accepted build dispatch references an unknown dependency")
        pending = set(dispatches)
        completed = {str(item.get("build_unit_id")): _unavailable_dotnet_receipt(
                         unit, item, loaded["accepted"])
                     for item in loaded.get("unavailable", ())}

        def run(dispatch, upstream):
            try:
                if family == "java":
                    return jvm.execute_jvm_one(unit, dispatch, loaded["accepted"], executor_factory)
                if family == "wasm":
                    return wasm._execute_one(unit, dispatch, loaded["accepted"],
                                             dispatch["wasm_producer"], upstream, executor_factory)
                return _execute_one(unit, dispatch, loaded["accepted"], executor_factory)
            except jvm.JvmIntegrityError:
                raise
            except wasm.WasmIntegrityError:
                raise
            except FrameworkIntegrityError:
                raise
            except wasm.ProducerUnavailable as exc:
                return {"schema": RECEIPT_SCHEMA, "build_unit_id": dispatch["build_unit_id"],
                    "family": family, "source_family": dispatch["family"],
                    "producer": dispatch["wasm_producer"], "root": dispatch["root"],
                    "artifacts": [], "commands": [], "relationships": [],
                    "terminal_status": "FAILED",
                    "gaps": [f"bounded WebAssembly producer failed: {exc}"]}
            except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
                return {"schema": RECEIPT_SCHEMA, "build_unit_id": dispatch["build_unit_id"],
                    "family": family, "root": dispatch["root"], "artifacts": [], "commands": [],
                    "terminal_status": "FAILED",
                    "gaps": [f"bounded {family} build failed: {type(exc).__name__}: {exc}"]}

        while pending:
            ready = sorted(key for key in pending if not (set(dispatches[key].get("build_dependencies", ())) & pending))
            if not ready:
                raise ValueError("accepted build dispatch dependencies contain a cycle")
            runnable = []
            for key in ready:
                failed = [dependency for dependency in dispatches[key].get("build_dependencies", ())
                          if dependency in dispatches and (dependency not in completed or
                          completed[dependency].get("terminal_status") != "SUCCEEDED")]
                if failed:
                    completed[key] = {"schema": RECEIPT_SCHEMA, "build_unit_id": key, "family": family,
                        "root": dispatches[key]["root"], "artifacts": [], "commands": [],
                        "terminal_status": "BLOCKED", "gaps": ["dependency build unavailable: " + ", ".join(failed)]}
                else:
                    relevant = [dependency for dependency in dispatches[key].get("build_dependencies", ())
                                if dependency in dispatches]
                    runnable.append((key, {dependency: str(completed[dependency].get("fingerprint", ""))
                                           for dependency in relevant}))
            with ThreadPoolExecutor(max_workers=min(len(runnable) or 1,
                    int(unit.job.config.step("execute").workers))) as pool:
                futures = {key: pool.submit(run, dispatches[key], upstream) for key, upstream in runnable}
                for key, _upstream in runnable:
                    completed[key] = futures[key].result()
            pending.difference_update(ready)
        receipts = [completed[key] for key in sorted(completed)]
        gaps = [f"{value['build_unit_id']}: {gap}" for value in receipts for gap in value.get("gaps", ())]
        return {"receipts": receipts, "receipt_count": len(receipts), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED" if receipts else "NOT_APPLICABLE"}
      return execute

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.native")
        executions = [unit.output("execute.native"), unit.output("execute.go"), unit.output("execute.dotnet"),
                      unit.output("execute.node"), unit.output("execute.python"),
                      unit.output("execute.rust"), unit.output("execute.php"), unit.output("execute.java"),
                      unit.output("execute.wasm")]
        unsupported = [item for item in _dispatches(unit)[0]
                       if item["family"] not in {"native", "go", "dotnet", "node", "python", "rust", "php", "java", "wasm"}]
        unsupported_gaps = [f"{item['build_unit_id']}: accepted {item['family']} execution is not implemented"
                            for item in unsupported]
        document = {"schema": SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
                    "upstream_project_build_handoff_sha256": loaded["accepted"]["project_build_handoff_sha256"],
                    "receipts": [receipt for result in executions for receipt in result["receipts"]],
                    "gaps": list(dict.fromkeys([*unsupported_gaps,
                        *(gap for result in executions for gap in result["gaps"])]))}
        artifact = _artifact(unit, "accepted-language-builds.json", document)
        index_manifest = _publish_build_index(unit, document["receipts"])
        return {"artifact": artifact, "build_count": len(document["receipts"]), "gaps": document["gaps"],
                "index_manifest": index_manifest,
                "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}

    units = (Unit("load.native", load_family("native")), Unit("load.go", load_family("go")),
             Unit("load.dotnet", load_family("dotnet")),
             Unit("load.node", load_family("node")),
             Unit("load.python", load_family("python")),
             Unit("load.rust", load_family("rust")),
             Unit("load.php", load_family("php")),
             Unit("load.java", load_family("java")),
             Unit("load.wasm", load_family("wasm")),
             Unit("execute.native", execute_family("native"), ("load.native",)),
             Unit("execute.go", execute_family("go"), ("load.go",)),
             Unit("execute.dotnet", execute_family("dotnet"), ("load.dotnet",)),
             Unit("execute.node", execute_family("node"), ("load.node",)),
             Unit("execute.python", execute_family("python"), ("load.python",)),
             Unit("execute.rust", execute_family("rust"), ("load.rust",)),
             Unit("execute.php", execute_family("php"), ("load.php",)),
             Unit("execute.java", execute_family("java"), ("load.java",)),
             Unit("execute.wasm", execute_family("wasm"), ("load.wasm",)),
             Unit("acceptance.publish_handoff", publish,
                  ("execute.native", "execute.go", "execute.dotnet", "execute.node", "execute.python",
                   "execute.rust", "execute.php", "execute.java", "execute.wasm")))
    implementation = hashlib.sha256(Path(__file__).read_bytes() + Path(jvm.__file__).read_bytes() +
        Path(python.__file__).read_bytes() +
        Path(wasm.__file__).read_bytes() +
        (b"injected" if executor_factory else b"container")).hexdigest()
    return Job("job_language_build", "language_build", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=implementation, units=units)
