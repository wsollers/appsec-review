from __future__ import annotations

from collections.abc import Mapping
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

from appsec_review.container_runtime import BuildContainerExecutor, BuildProfile
from appsec_review.container_runtime.project_images import project_recipe_identity
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.cataloging import source_fingerprint, write_json
from appsec_review.jobs.job_project_build import load_accepted_builds
from appsec_review.jobs.job_project_build.job import _normalized_argv, _probe_environment, _safe_root
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256


SCHEMA = "appsec-review/language-build-handoff/1"
RECEIPT_SCHEMA = "appsec-review/language-build-receipt/1"
EXECUTOR_IDENTITY = "appsec-review/generic-language-build-executor/1"
CAPTURE_IDENTITY = "appsec-review/native-build-capture/1"
_SECRET_KEY = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm", ".h", ".hh", ".hpp", ".hxx"}
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
}


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
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git", ".hg", ".svn", "build", "target"))
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


def _kind(path: Path) -> str | None:
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
             build_unit_id: str) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts, gaps = [], []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative, digest = path.relative_to(workspace).as_posix(), file_sha256(path)
        kind = _kind(path)
        if kind is None or before.get(relative) == digest:
            continue
        artifact = {"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
                          "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind,
                          "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
                          "mapping_confidence": 1.0}
        if kind in {"executable", "shared-library"}:
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


def _fingerprint(dispatch: Mapping[str, Any], accepted: Mapping[str, Any]) -> str:
    image = dispatch["image"]
    return hashlib.sha256(canonical_json({"schema": RECEIPT_SCHEMA, "target": dispatch["source_fingerprint"],
        "recipe": dispatch["recipe_identity"], "dependencies": image["dependency_hashes"],
        "image": image["image_id"], "executor": EXECUTOR_IDENTITY, "capture": CAPTURE_IDENTITY,
        "toolchain": {"family": dispatch["family"], "image_id": image["image_id"]},
        "probe": dispatch["probe_identity"], "upstream_handoff": accepted["project_build_handoff_sha256"]})).hexdigest()


def _execute_one(unit: UnitContext, dispatch: Mapping[str, Any], accepted: Mapping[str, Any], executor_factory=None) -> dict[str, Any]:
    build_unit_id, recipe, image = str(dispatch["build_unit_id"]), dispatch["recipe"], dispatch["image"]
    fingerprint = _fingerprint(dispatch, accepted)
    root = unit.job.run_root / "data" / "build" / "native" / "units" / build_unit_id
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
                artifacts, gaps = [], []
                for identity in prior["receipt"].get("artifacts", ()):
                    path = unit.job.run_root / str(identity["path"])
                    if not path.is_file() or path.is_symlink() or file_sha256(path) != identity["sha256"]:
                        gaps.append("checkpoint artifact identity changed")
                        break
                    artifacts.append(dict(identity))
                if gaps:
                    raise ValueError("language-build checkpoint artifact identity changed")
                receipt = {**prior["receipt"], "workspace": workspace.relative_to(unit.job.run_root).as_posix(),
                           "artifacts": artifacts, "gaps": gaps, "checkpoint_reused": True,
                           "completed_at": datetime.now(timezone.utc).isoformat()}
                unit.job.events.write("LANGUAGE_BUILD_REUSED", unit_id=unit.unit_id,
                                      build_unit_id=build_unit_id, fingerprint=fingerprint,
                                      result_count=len(artifacts), gap_count=len(gaps), duration_ms=0)
                return receipt
    _copy_source(unit, dispatch, workspace)
    before = _snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    profile = BuildProfile("native", str(image["image_tag"]), str(image["image_id"]), str(image["user"]))
    executor = executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
        profile, timeout_seconds=int(unit.job.config.settings["command_timeout_seconds"]),
        output_bytes=int(unit.job.config.settings["output_bytes"]))
    executor.resolve()
    protected = root / "protected-commands"
    protected.mkdir(parents=True, exist_ok=True)
    commands, gaps = [], []
    operational_recipe = {**recipe, "build_system": dispatch.get("build_system")}
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    unit.job.events.write("LANGUAGE_BUILD_STARTED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
                          family="native", recipe_identity=dispatch["recipe_identity"],
                          image_id=image["image_id"], command_count=(len(recipe["configure_commands"]) +
                                                                    len(recipe["build_commands"])))
    for ordinal, raw in enumerate([*recipe["configure_commands"], *recipe["build_commands"]], 1):
        argv = _normalized_argv(recipe, raw)
        command_started = time.monotonic()
        result = executor.execute(argv, workspace=workspace, working_directory=str(recipe["source_dir"]),
                                  environment=_probe_environment(operational_recipe))
        command_id = hashlib.sha256(canonical_json({"unit": build_unit_id, "ordinal": ordinal,
                                                    "argv": list(argv)})).hexdigest()
        stdout, stderr = root / "logs" / f"{ordinal:03d}.stdout", root / "logs" / f"{ordinal:03d}.stderr"
        stdout.parent.mkdir(parents=True, exist_ok=True)
        stdout.write_bytes(result.stdout); stderr.write_bytes(result.stderr)
        exact = protected / f"{command_id}.json"
        atomic_json(exact, {"schema": "appsec-review/protected-build-command/2", "argv": list(result.argv),
            "working_directory": str(recipe["source_dir"]), "environment": dict(_probe_environment(operational_recipe)),
            "access": "run-owned-protected"})
        try: exact.chmod(0o600)
        except OSError: pass
        failed = result.timed_out or result.exit_code != 0
        commands.append({"command_id": command_id, "ordinal": ordinal, "tool": Path(argv[0]).name,
            "tool_kind": _TOOL_KINDS.get(Path(argv[0]).name, "build-driver"),
            "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
            "working_directory": str(recipe["source_dir"]),
            "environment_facts": {key: "set" for key in sorted(_probe_environment(operational_recipe))
                                  if not _SECRET_KEY.search(key)},
            "started_at": datetime.now(timezone.utc).isoformat(), "duration_ms": int((time.monotonic()-command_started)*1000),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "stdout": stdout.relative_to(unit.job.run_root).as_posix(),
            "stderr": stderr.relative_to(unit.job.run_root).as_posix(),
            "protected_argv": {"path": exact.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(exact)},
            "image_id": image["image_id"], "build_unit_id": build_unit_id})
        unit.job.events.write("BUILD_COMMAND_COMPLETED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
            command_id=command_id, tool=Path(argv[0]).name, disposition="FAILED" if failed else "SUCCEEDED",
            result_count=0, gap_count=1 if failed else 0, truncated=False,
            duration_ms=commands[-1]["duration_ms"])
        if failed:
            gaps.append(f"build command {ordinal} {'timed out' if result.timed_out else f'exited {result.exit_code}'}")
            break
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed during generic language-build execution")
    artifacts, catalog_gaps = _catalog(unit.job.run_root, workspace, before,
                                       int(unit.job.config.settings["artifact_count_limit"]), build_unit_id)
    gaps.extend(catalog_gaps)
    compile_rows, compile_gaps = _compile_rows(workspace, str(recipe["source_dir"]), str(recipe["build_dir"]))
    gaps.extend(compile_gaps)
    link_rows, link_gaps = _link_rows(workspace, str(recipe["build_dir"]))
    gaps.extend(link_gaps)
    normalized_links = _normalized_links(link_rows, str(recipe["build_dir"]))
    link_database = workspace / Path(*PurePosixPath(str(recipe["build_dir"])).parts) / ".appsec-review-link-commands.json"
    atomic_json(link_database, normalized_links)
    compile_protected = root / "protected-commands" / "compile-database.json"
    atomic_json(compile_protected, {"schema": "appsec-review/protected-compile-commands/1",
                                   "rows": [*compile_rows, *link_rows]})
    try: compile_protected.chmod(0o600)
    except OSError: pass
    sanitized_compile = [{key: value for key, value in row.items() if key != "argv"} |
                         {"argv_sha256": hashlib.sha256(canonical_json(row["argv"])).hexdigest()}
                         for row in [*compile_rows, *link_rows]]
    workspace_manifest_path = root / "workspace-manifest.json"
    workspace_files = _snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    atomic_json(workspace_manifest_path, {"schema": "appsec-review/build-workspace-manifest/1",
                "build_unit_id": build_unit_id, "files": workspace_files})
    status = "FAILED" if any("build command" in gap for gap in gaps) else "SUCCEEDED"
    receipt = {"schema": RECEIPT_SCHEMA, "fingerprint": fingerprint, "source_fingerprint": unit.job.source_fingerprint,
        "upstream_handoff_sha256": accepted["project_build_handoff_sha256"], "build_unit_id": build_unit_id,
        "family": "native", "root": dispatch["root"], "build_system": dispatch.get("recipe", {}).get("build_system", dispatch.get("build_system")),
        "recipe": recipe, "recipe_identity": dispatch["recipe_identity"], "probe_identity": dispatch["probe_identity"],
        "image": image, "workspace": workspace.relative_to(unit.job.run_root).as_posix(),
        "commands": commands, "tool_invocations": sanitized_compile,
        "protected_compile_commands": {"path": compile_protected.relative_to(unit.job.run_root).as_posix(),
                                       "sha256": file_sha256(compile_protected)},
        "link_database": {"path": link_database.relative_to(unit.job.run_root).as_posix(),
                          "sha256": file_sha256(link_database), "relationship_count": len(normalized_links)},
        "workspace_manifest": {"path": workspace_manifest_path.relative_to(unit.job.run_root).as_posix(),
                               "sha256": file_sha256(workspace_manifest_path)},
        "artifacts": artifacts, "gaps": list(dict.fromkeys(gaps)), "terminal_status": status,
        "checkpoint_reused": False, "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(), "duration_ms": int((time.monotonic()-started)*1000),
        "executor_identity": EXECUTOR_IDENTITY, "capture_identity": CAPTURE_IDENTITY}
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
    expected = {"load": ("accepted_dispatch",), "execute": ("native",), "acceptance": ("publish_handoff",)}
    for step, tasks in expected.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"language-build task order mismatch: {step}")
    for key in ("command_timeout_seconds", "output_bytes", "artifact_count_limit"):
        if type(context.config.settings.get(key)) is not int or context.config.settings[key] < 1:
            raise ValueError(f"language-build bound is invalid: {key}")


def build_job(*, executor_factory=None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        dispatches, accepted = _dispatches(unit)
        native = [item for item in dispatches if item["family"] == "native"]
        unsupported = [item for item in dispatches if item["family"] != "native"]
        gaps = [f"{item['build_unit_id']}: accepted {item['family']} execution is not implemented" for item in unsupported]
        return {"dispatches": native, "accepted": accepted, "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED" if native else "NOT_APPLICABLE"}

    def execute(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_dispatch")
        dispatches = {str(item["build_unit_id"]): item for item in loaded["dispatches"]}
        known_units = {str(item.get("build_unit_id")) for item in loaded["accepted"].get("probe_receipts", ())}
        if any(dependency not in known_units for item in dispatches.values()
               for dependency in item.get("build_dependencies", ())):
            raise ValueError("accepted build dispatch references an unknown dependency")
        pending, completed = set(dispatches), {}

        def run(dispatch):
            try:
                return _execute_one(unit, dispatch, loaded["accepted"], executor_factory)
            except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
                return {"schema": RECEIPT_SCHEMA, "build_unit_id": dispatch["build_unit_id"],
                    "family": "native", "root": dispatch["root"], "artifacts": [], "commands": [],
                    "terminal_status": "FAILED", "gaps": [f"bounded native build failed: {type(exc).__name__}: {exc}"]}

        while pending:
            ready = sorted(key for key in pending if not (set(dispatches[key].get("build_dependencies", ())) & pending))
            if not ready:
                raise ValueError("accepted build dispatch dependencies contain a cycle")
            runnable = []
            for key in ready:
                failed = [dependency for dependency in dispatches[key].get("build_dependencies", ())
                          if dependency not in completed or completed[dependency].get("terminal_status") != "SUCCEEDED"]
                if failed:
                    completed[key] = {"schema": RECEIPT_SCHEMA, "build_unit_id": key, "family": "native",
                        "root": dispatches[key]["root"], "artifacts": [], "commands": [],
                        "terminal_status": "BLOCKED", "gaps": ["dependency build unavailable: " + ", ".join(failed)]}
                else:
                    runnable.append(key)
            with ThreadPoolExecutor(max_workers=min(len(runnable) or 1,
                    int(unit.job.config.step("execute").workers))) as pool:
                futures = {key: pool.submit(run, dispatches[key]) for key in runnable}
                for key in runnable:
                    completed[key] = futures[key].result()
            pending.difference_update(ready)
        receipts = [completed[key] for key in sorted(completed)]
        gaps = [f"{value['build_unit_id']}: {gap}" for value in receipts for gap in value.get("gaps", ())]
        return {"receipts": receipts, "receipt_count": len(receipts), "gaps": gaps,
                "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED" if receipts else "NOT_APPLICABLE"}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        loaded, executed = unit.output("load.accepted_dispatch"), unit.output("execute.native")
        document = {"schema": SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
                    "upstream_project_build_handoff_sha256": loaded["accepted"]["project_build_handoff_sha256"],
                    "receipts": executed["receipts"], "gaps": list(dict.fromkeys([*loaded["gaps"], *executed["gaps"]]))}
        artifact = _artifact(unit, "accepted-language-builds.json", document)
        return {"artifact": artifact, "build_count": len(document["receipts"]), "gaps": document["gaps"],
                "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}

    units = (Unit("load.accepted_dispatch", load),
             Unit("execute.native", execute, ("load.accepted_dispatch",)),
             Unit("acceptance.publish_handoff", publish, ("execute.native",)))
    implementation = hashlib.sha256(Path(__file__).read_bytes() +
        (b"injected" if executor_factory else b"container")).hexdigest()
    return Job("job_language_build", "language_build", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=implementation, units=units)
