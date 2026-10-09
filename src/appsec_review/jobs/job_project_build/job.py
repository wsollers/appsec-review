from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import time
from typing import Any

from appsec_review.container_runtime import (
    BuildContainerExecutor,
    CaptureScope,
    BuildProfile,
    ProjectImageBuildError,
    ProjectImageResolver,
    project_dependency_environment,
    profiles_from_settings,
)
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.cataloging import source_fingerprint, write_json
from appsec_review.jobs.job_target_analysis_plan import ModelClient, ModelRequest, load_accepted_plan
from appsec_review.observability import PipelineLog, emit_model_event
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import FileLock, atomic_bytes, atomic_json, canonical_json, file_sha256, protected_json

from .repair import REPAIR_SCHEMA, apply_repair, validate_repair_proposal


SCHEMA = "appsec-review/project-build-dispatch/2"
EXECUTOR_IDENTITY = "appsec-review/build-container-executor/2"
REPAIR_CACHE_SCHEMA = "appsec-review/build-image-repair-cache/1"
BUILD_FAMILIES = ("native", "rust", "go", "java", "node", "dotnet", "python", "php", "wasm")
STATIC_LANES = ("global", *BUILD_FAMILIES)
_IGNORED = {".git", ".hg", ".svn", "build", "target", "node_modules", "bin", "obj", ".gradle"}
_ARTIFACT_SUFFIXES = {".o", ".obj", ".a", ".lib", ".so", ".dll", ".dylib", ".exe", ".wasm",
                      ".class", ".jar", ".war", ".ear", ".rlib", ".rmeta", ".pdb"}
_SECRET_KEY = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
_BUILD_CAPABILITIES = {
    "native": ("build", "ast", "ir", "infer", "codeql", "joern", "binary"),
    "rust": ("build", "ast", "ir", "codeql", "binary"), "go": ("build", "codeql", "binary"),
    "java": ("build", "bytecode", "codeql", "binary"), "node": ("build", "codeql"),
    "dotnet": ("build", "bytecode", "codeql", "binary"), "python": ("package", "codeql"),
    "php": ("package",), "wasm": ("build", "ir", "binary"),
}


def _artifact(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "project-build" / name
    identity = write_json(path, value)
    identity["path"] = path.relative_to(unit.job.run_root).as_posix()
    return identity


def _safe_root(target: Path, relative: str) -> Path:
    logical = PurePosixPath(relative)
    if relative != "." and (not logical.parts or logical.is_absolute() or ".." in logical.parts):
        raise ValueError("accepted build-unit root is invalid")
    path = target.resolve(strict=True) if relative == "." else (target / Path(*logical.parts)).resolve(strict=True)
    if path != target.resolve() and target.resolve() not in path.parents:
        raise ValueError("accepted build-unit root escapes the target")
    if not path.is_dir() or path.is_symlink():
        raise ValueError("accepted build-unit root is not a regular directory")
    return path


def _copy_source(unit: UnitContext, action: Mapping[str, Any], workspace: Path) -> None:
    target = (unit.job.target_root or Path()).resolve(strict=True)
    source = _safe_root(target, str(action["root"]))
    destination = workspace if str(action["root"]) == "." else workspace / Path(*PurePosixPath(str(action["root"])).parts)
    if workspace.exists():
        resolved = workspace.resolve()
        build_root = (unit.job.run_root / "data" / "build" / "probes").resolve()
        if resolved != build_root and build_root not in resolved.parents:
            raise ValueError("probe workspace deletion escaped the run-owned build root")
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"build source contains an unsupported symlink: {path.relative_to(target)}")
    shutil.copytree(source, destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns(*sorted(_IGNORED)))
    try:
        workspace.chmod(0o777)
        for directory in (path for path in workspace.rglob("*") if path.is_dir()):
            directory.chmod(0o777)
    except OSError:
        pass


def _snapshot(root: Path, limit: int) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        try:
            if path.is_symlink() or not path.is_file():
                continue
        except OSError:
            continue
        result[path.relative_to(root).as_posix()] = file_sha256(path)
        if len(result) > limit:
            raise ValueError("probe workspace file-count bound exceeded")
    return result


def _kind(path: Path) -> str | None:
    if path.suffix.lower() in _ARTIFACT_SUFFIXES:
        return path.suffix.lower().removeprefix(".") or "binary"
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return None
    return "elf" if magic == b"\x7fELF" else "pe" if magic[:2] == b"MZ" else "wasm" if magic == b"\x00asm" else None


def _outputs(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int) -> list[dict[str, Any]]:
    values = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative, digest = path.relative_to(workspace).as_posix(), file_sha256(path)
        kind = _kind(path)
        if kind is None or before.get(relative) == digest:
            continue
        values.append({"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
                       "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind})
        if len(values) >= limit:
            break
    return values


def _normalized_argv(recipe: Mapping[str, Any], argv: list[str]) -> tuple[str, ...]:
    source_dir = str(recipe["source_dir"])
    executable = {"mvnw": "mvn", "gradlew": "gradle"}.get(str(argv[0]), str(argv[0]))
    result = [executable]
    for argument in argv[1:]:
        value = str(argument)
        if value == source_dir:
            value = "."
        elif source_dir != "." and value.startswith(source_dir + "/"):
            value = value[len(source_dir) + 1:]
        result.append(value)
    return tuple(result)


def _probe_environment(recipe: Mapping[str, Any]) -> dict[str, str]:
    environment = {str(key): str(value) for key, value in recipe["environment"].items()}
    if str(recipe.get("build_system", "")) == "maven":
        # The derived image cache is immutable at probe time. Maven's go-offline goal is not
        # complete for every historical plugin (notably resources-plugin 2.6), so keep the
        # actual build repository writable and let the networked build container fill any gaps.
        options = environment.get("MAVEN_OPTS", "").strip()
        environment["MAVEN_OPTS"] = "-Dmaven.repo.local=/tmp/appsec-review-maven" + (
            f" {options}" if options else "")
    for key, protected in project_dependency_environment(recipe).items():
        if key == "MAVEN_OPTS":
            continue
        if key not in environment:
            continue  # The derived image already carries the protected value.
        if key == "PATH":
            environment[key] = protected.replace("$PATH", environment[key])
        else:
            environment[key] = protected
    return environment


def _probe_stream(run_root: Path, path: Path, result: Any, name: str, limit: int) -> dict[str, Any]:
    data = bytes(getattr(result, name))
    path.write_bytes(data)
    try: path.chmod(0o600)
    except OSError: pass
    try: path.chmod(0o600)
    except OSError: pass
    raw_count = getattr(result, f"{name}_bytes", None)
    count = len(data) if raw_count is None else int(raw_count)
    truncated = bool(getattr(result, f"{name}_truncated", count > len(data)))
    identity: dict[str, Any] = {
        "path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
        "byte_count": count, "retained_byte_count": len(data), "capture_limit": limit,
        "truncated": truncated,
    }
    tail = bytes(getattr(result, f"{name}_tail", b""))
    if truncated and tail:
        tail_path = path.with_name(path.name + ".tail")
        tail_path.write_bytes(tail)
        try: tail_path.chmod(0o600)
        except OSError: pass
        try: tail_path.chmod(0o600)
        except OSError: pass
        identity["diagnostic_tail"] = {
            "path": tail_path.relative_to(run_root).as_posix(), "sha256": file_sha256(tail_path),
            "byte_count": len(tail),
        }
    return identity


def _retained_stream(run_root: Path, path: Path, data: bytes, limit: int) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try: path.chmod(0o600)
    except OSError: pass
    truncated = len(data) >= limit
    value: dict[str, Any] = {"path": path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(path), "byte_count": len(data), "retained_byte_count": len(data),
        "capture_limit": limit, "truncated": truncated}
    if truncated and data:
        tail = path.with_name(path.name + ".tail")
        tail.write_bytes(data[-min(32768, len(data)):])
        try: tail.chmod(0o600)
        except OSError: pass
        value["diagnostic_tail"] = {"path": tail.relative_to(run_root).as_posix(),
            "sha256": file_sha256(tail), "byte_count": tail.stat().st_size}
    return value


def _capture_member(root: Path, value: object) -> Path:
    if not isinstance(value, Mapping):
        raise ValueError("build execution capture member is invalid")
    uri = value.get("uri")
    if not isinstance(uri, str):
        raise ValueError("build execution capture member URI is invalid")
    logical = PurePosixPath(uri)
    if not logical.parts or logical.is_absolute() or ".." in logical.parts:
        raise ValueError("build execution capture member URI is not normalized")
    path = (root / Path(*logical.parts)).resolve(strict=True)
    resolved_root = root.resolve(strict=True)
    if resolved_root not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("build execution capture member escaped its root")
    if file_sha256(path) != value.get("sha256"):
        raise ValueError("build execution capture member identity changed")
    return path


def _capture_identity(unit: UnitContext, result: Any, *, build_unit_id: str,
                      family: str) -> tuple[dict[str, Any], list[str]]:
    value = getattr(result, "capture_record", None)
    if not isinstance(value, Path):
        raise RuntimeError("build execution capture record is required")
    path = value.resolve(strict=True)
    run_root = unit.job.run_root.resolve(strict=True)
    if run_root not in path.parents or path.is_symlink():
        raise ValueError("build execution capture record escaped the run")
    document = json.loads(path.read_text(encoding="utf-8"))
    scope = document.get("scope")
    if (document.get("schema") != "appsec-review/build-execution-record/1" or
            not isinstance(scope, Mapping) or scope.get("run_id") != unit.job.run_id or
            scope.get("job_id") != "job_project_build" or
            scope.get("attempt_id") != unit.job.attempt_id or
            scope.get("build_unit_id") != build_unit_id or scope.get("family") != family):
        raise ValueError("build execution capture record identity is invalid")
    coverage = document.get("coverage")
    if not isinstance(coverage, Mapping) or not isinstance(coverage.get("gaps"), list):
        raise ValueError("build execution capture coverage is invalid")
    complete = coverage.get("complete")
    if not isinstance(complete, bool) or complete == bool(coverage["gaps"]):
        raise ValueError("build execution capture coverage disposition is inconsistent")
    capture_root = path.parent
    _capture_member(capture_root, document.get("events"))
    streams = document.get("streams")
    if not isinstance(streams, Mapping) or set(streams) != {"stdout", "stderr"}:
        raise ValueError("build execution capture streams are invalid")
    for stream in streams.values():
        _capture_member(capture_root, stream)
    tool_calls = document.get("tool_calls")
    if not isinstance(tool_calls, Mapping) or not isinstance(tool_calls.get("records"), list):
        raise ValueError("build execution tool calls are invalid")
    for member in tool_calls["records"]:
        tool_path = _capture_member(capture_root, member)
        tool = json.loads(tool_path.read_text(encoding="utf-8"))
        if tool.get("schema") != "appsec-review/build-tool-call/1":
            raise ValueError("build execution tool-call schema is invalid")
        for name in ("stdout", "stderr"):
            _capture_member(tool_path.parent, tool.get(name))
    identity = {"schema": document["schema"],
                "path": path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(path), "size_bytes": path.stat().st_size,
                "complete": complete}
    return identity, [str(gap) for gap in coverage["gaps"]]


def _probe_cache(unit: UnitContext, recipe_identity: str) -> Path:
    return unit.job.metadata_root / "project-probes" / recipe_identity / "accepted.json"


def _probe_one(unit: UnitContext, entry: Mapping[str, Any], executor_factory=None,
               *, attempt_number: int = 1) -> dict[str, Any]:
    action, image = entry["action"], entry.get("image")
    recipe, build_unit_id = action.get("recipe"), str(action["build_unit_id"])
    base = {"build_unit_id": build_unit_id, "family": action.get("family"), "root": action.get("root"),
            "build_system": action.get("build_system"), "artifacts": []}
    if not isinstance(recipe, Mapping):
        return {**base, "terminal_status": "BLOCKED", "probe_disposition": "BLOCKED",
                "gaps": ["validated inference build recipe is unavailable"]}
    if not isinstance(image, Mapping) or image.get("terminal_status") != "SUCCEEDED":
        return {**base, "terminal_status": "BLOCKED", "probe_disposition": "BLOCKED",
                "gaps": list(entry.get("gaps", ())) or ["project build image is unavailable"]}
    recipe_identity, cache = str(image["recipe_identity"]), _probe_cache(unit, str(image["recipe_identity"]))
    with FileLock(cache.parent / "probe.lock"):
        if cache.is_file() and not bool(unit.job.config.settings["force_buildability_probe"]):
            prior = json.loads(cache.read_text(encoding="utf-8"))
            if (prior.get("recipe_identity") == recipe_identity and prior.get("image_id") == image["image_id"] and
                    prior.get("terminal_status") == "SUCCEEDED"):
                unit.job.events.write("BUILD_PROBE_REUSED", unit_id=unit.unit_id, build_unit_id=build_unit_id,
                    recipe_identity=recipe_identity, image_id=image["image_id"], disposition="REUSED", duration_ms=0)
                return {**base, "schema": SCHEMA, "executor_identity": EXECUTOR_IDENTITY,
                        "recipe_identity": recipe_identity, "image_id": image["image_id"],
                        "terminal_status": "SUCCEEDED", "probe_disposition": "REUSED",
                        "checkpoint_reused": True, "commands": [], "gaps": [],
                        "attempt_number": 0}
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed after the accepted review snapshot")
    root = (unit.job.run_root / "data" / "build" / "probes" / build_unit_id /
            f"attempt-{attempt_number:03d}")
    workspace = root / "workspace"
    _copy_source(unit, action, workspace)
    before = _snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    profile = BuildProfile(str(action["family"]), str(image["image_tag"]), str(image["image_id"]), str(image["user"]))
    executor = executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
        profile, timeout_seconds=int(unit.job.config.settings["command_timeout_seconds"]),
        output_bytes=int(unit.job.config.settings["output_bytes"]))
    executor.resolve()
    if action["family"] == "node" and recipe.get("network_required"):
        prepare = getattr(executor, "prepare_node_dependencies", None)
        if not callable(prepare):
            raise RuntimeError("Node dependency-bearing builds require a dependency-view executor")
        prepare(workspace=workspace, source_dir=str(recipe["source_dir"]))
    command_receipts, gaps = [], []
    for ordinal, argv in enumerate([*recipe["configure_commands"], *recipe["build_commands"]], 1):
        command = _normalized_argv(recipe, argv)
        invocation = hashlib.sha256(
            f"{unit.job.run_id}:{unit.job.attempt_id}:{build_unit_id}:{attempt_number}:{ordinal}".encode()).hexdigest()
        started = time.monotonic()
        unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id, tool_invocation_id=invocation,
            tool_id="build-probe", retry_count=attempt_number - 1,
            tool_identity={"family": action["family"], "image_id": image["image_id"]},
            input_identities={"recipe_identity": recipe_identity,
                              "argv_sha256": hashlib.sha256(canonical_json(list(command))).hexdigest()})
        captured = getattr(executor, "execute_captured", None)
        if not callable(captured) or unit.job.config.build_capture is None:
            raise RuntimeError("project builds require execution capture")
        result = captured(
            command, workspace=workspace, working_directory=str(recipe["source_dir"]),
            environment=_probe_environment({**recipe, "build_system": action["build_system"]}),
            capture_directory=root / "execution-capture" / f"command-{ordinal:03d}",
            capture_config=unit.job.config.build_capture,
            scope=CaptureScope(unit.job.run_id, "job_project_build", unit.job.attempt_id,
                               build_unit_id, str(action["family"])))
        capture_identity, capture_gaps = _capture_identity(
            unit, result, build_unit_id=build_unit_id, family=str(action["family"]))
        gaps.extend(f"build command {ordinal} capture: {gap}" for gap in capture_gaps)
        logs = root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        stdout, stderr = logs / f"command-{ordinal:03d}.stdout", logs / f"command-{ordinal:03d}.stderr"
        limit = int(unit.job.config.settings["output_bytes"])
        stdout_identity = _probe_stream(unit.job.run_root, stdout, result, "stdout", limit)
        stderr_identity = _probe_stream(unit.job.run_root, stderr, result, "stderr", limit)
        protected = root / "protected-commands" / f"{invocation[:24]}.json"
        protected.parent.mkdir(parents=True, exist_ok=True)
        protected_json(protected, {"schema": "appsec-review/protected-build-command/2",
            "argv": list(result.argv), "working_directory": str(recipe["source_dir"]),
            "environment": _probe_environment({**recipe, "build_system": action["build_system"]}),
            "access": "run-owned-protected"})
        try: protected.chmod(0o600)
        except OSError: pass
        command_receipts.append({"ordinal": ordinal,
            "attempt_identity": f"{unit.job.attempt_id}:{build_unit_id}:{attempt_number}",
            "command_identity": invocation,
            "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "image_id": image["image_id"], "capture_limit": limit,
            "working_directory": str(recipe["source_dir"]),
            "environment_facts": {key: "set" for key in sorted(recipe.get("environment", {}))
                                  if not _SECRET_KEY.search(str(key))},
            "stdout": stdout_identity, "stderr": stderr_identity,
            "protected_argv": {"path": protected.relative_to(unit.job.run_root).as_posix(),
                               "sha256": file_sha256(protected), "size_bytes": protected.stat().st_size},
            "execution_capture": capture_identity})
        failed = result.timed_out or result.exit_code != 0 or bool(capture_gaps)
        unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id, tool_invocation_id=invocation,
            tool_id="build-probe", retry_count=attempt_number - 1,
            tool_identity={"family": action["family"], "image_id": image["image_id"]},
            disposition="FAILED" if failed else "SUCCEEDED", result_count=0, gap_count=1 if failed else 0,
            truncated=stdout_identity["truncated"] or stderr_identity["truncated"],
            duration_ms=int((time.monotonic() - started) * 1000))
        if failed:
            if result.timed_out or result.exit_code != 0:
                gaps.append(
                    f"build command {ordinal} {'timed out' if result.timed_out else f'exited {result.exit_code}'}")
            break
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed during isolated probe execution")
    artifacts = _outputs(unit.job.run_root, workspace, before, int(unit.job.config.settings["artifact_count_limit"]))
    status = "FAILED" if gaps else "SUCCEEDED"
    receipt = {**base, "schema": SCHEMA, "executor_identity": EXECUTOR_IDENTITY,
               "recipe_identity": recipe_identity, "image_id": image["image_id"], "commands": command_receipts,
               "artifacts": artifacts, "terminal_status": status,
               "probe_disposition": "FAILED" if gaps else "PROBED", "gaps": gaps,
               "checkpoint_reused": False, "attempt_number": attempt_number}
    if status == "SUCCEEDED":
        cache.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(cache.parent / "probe.lock"):
            atomic_json(cache, {"schema": "appsec-review/build-probe-cache/1", "recipe_identity": recipe_identity,
                                "image_id": image["image_id"], "terminal_status": "SUCCEEDED"})
    return receipt


def _repair_cache(unit: UnitContext, base_recipe_identity: str) -> Path:
    return unit.job.metadata_root / "project-build-repairs" / base_recipe_identity / "accepted.json"


def _repair_validation_unit(action: Mapping[str, Any], recipe: Mapping[str, Any]) -> dict[str, Any]:
    documents = [{"path": str(path)} for path in recipe.get("dependency_files", ())]
    return {"build_unit_id": action["build_unit_id"], "family": action["family"],
            "root": action["root"], "build_system": action["build_system"],
            "markers": documents, "descriptor_package": {"documents": documents}}


def _probe_diagnostics(unit: UnitContext, receipt: Mapping[str, Any]) -> dict[str, Any]:
    command = receipt.get("commands", ())[-1] if receipt.get("commands") else {}
    result: dict[str, Any] = {
        "terminal_status": receipt.get("terminal_status"),
        "gaps": list(receipt.get("gaps", ()))[:20],
        "command": {key: command.get(key) for key in ("ordinal", "argv_sha256", "exit_code", "timed_out")},
    }
    for key in ("stdout", "stderr"):
        stream = command.get(key)
        relative = stream.get("path") if isinstance(stream, Mapping) else stream
        if not isinstance(relative, str):
            result[f"{key}_tail"] = ""
            continue
        path = (unit.job.run_root / relative).resolve()
        if unit.job.run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            raise ValueError("probe diagnostic path is invalid")
        result[f"{key}_tail"] = path.read_bytes()[-32768:].decode("utf-8", "replace")
    return result


def _repair_guidance(unit: UnitContext, family: str, model: Mapping[str, Any]) -> tuple[str, str, str, str]:
    repository = unit.job.repository_root
    guidance_path = repository / "skills" / "build-image-repair" / "SKILL.md"
    if not guidance_path.is_file():
        guidance_path = Path(__file__).parents[4] / "skills" / "build-image-repair" / "SKILL.md"
    prompt_root = repository / "pipeline" / "prompt-fragments"
    if not prompt_root.is_dir():
        prompt_root = Path(__file__).parents[4] / "pipeline" / "prompt-fragments"
    persona = (prompt_root / "personas" / "devops-engineer.md").read_text(encoding="utf-8")
    role = (prompt_root / "roles" / f"build-engineer-{family}.md").read_text(encoding="utf-8")
    guidance = guidance_path.read_text(encoding="utf-8")
    identity = hashlib.sha256(persona.encode() + b"\0" + role.encode() + b"\0" + guidance.encode()).hexdigest()
    bundle = unit.job.run_root / "data" / "guidance" / identity
    atomic_bytes(bundle / "persona.md", persona.encode("utf-8"))
    atomic_bytes(bundle / "role.md", role.encode("utf-8"))
    atomic_bytes(bundle / "task.md", guidance.encode("utf-8"))
    atomic_json(bundle / "model-identity.json", {
        "provider": str(model["provider"]), "model": str(model["model"]),
        "reasoning": str(model["reasoning"]), "guidance_sha256": identity,
        "persona": "devops_engineer", "role": f"build_engineer_{family}",
        "task": "build_image_repair",
    })
    return persona, role, guidance, identity


def _infer_repair(unit: UnitContext, *, action: Mapping[str, Any], recipe: Mapping[str, Any],
                  dockerfile: bytes, diagnostics: Mapping[str, Any], attempts: list[Mapping[str, Any]],
                  repair_number: int, model_client: ModelClient) -> Mapping[str, Any]:
    model = unit.job.config.settings["model"]
    persona, role, guidance, guidance_sha = _repair_guidance(unit, str(action["family"]), model)
    summary = {
        "schema": "appsec-review/build-image-repair-request/1",
        "build_unit": {key: action.get(key) for key in
                       ("build_unit_id", "family", "root", "build_system")},
        "planning_package_hints": list(action.get("package_hints", ())),
        "accepted_recipe": {key: recipe.get(key) for key in
                            ("source_dir", "build_dir", "dependency_files", "configure_commands",
                             "build_commands", "expected_outputs", "network_required", "system_packages")},
        "dockerfile": dockerfile.decode("utf-8", "replace"),
        "failure": diagnostics,
        "prior_attempts": attempts[-10:],
    }
    request = ModelRequest(
        schema=REPAIR_SCHEMA, persona=persona, role=role, guidance=guidance, summary=summary,
        allowed_scanners=(), allowed_build_systems=(str(action["build_system"]),),
        allowed_components=(), allowed_paths=tuple(str(value) for value in recipe.get("dependency_files", ())),
        allowed_build_units=(str(action["build_unit_id"]),), provider=str(model["provider"]),
        model=str(model["model"]), reasoning=str(model["reasoning"]),
        max_input_tokens=int(model["max_input_tokens"]), max_output_tokens=int(model["max_output_tokens"]),
    )
    request_payload = {"schema": request.schema, "summary": summary, "provider": request.provider,
                       "model": request.model, "reasoning": request.reasoning,
                       "guidance_sha256": guidance_sha}
    encoded = canonical_json(request_payload)
    if len(encoded) + len(persona.encode()) + len(role.encode()) + len(guidance.encode()) > request.max_input_tokens * 4:
        raise ValueError("build image repair request exceeded its configured input budget")
    request_sha = hashlib.sha256(encoded).hexdigest()
    invocation = hashlib.sha256(
        f"{unit.job.run_id}:{unit.job.attempt_id}:{action['build_unit_id']}:{repair_number}:{request_sha}".encode()
    ).hexdigest()
    log = PipelineLog(unit.job.run_root)
    emit_model_event(log, event_type="MODEL_CALL_STARTED", run_id=unit.job.run_id,
        invocation_id=invocation, provider=request.provider, model=request.model,
        reasoning_level=request.reasoning, guidance_bundle_sha256=guidance_sha,
        request_sha256=request_sha, retry_count=repair_number - 1, job_id="job_project_build",
        attempt_id=unit.job.attempt_id, build_unit_id=str(action["build_unit_id"]),
        inference_task="build_image_repair")
    started = time.monotonic()
    try:
        result = model_client.complete(request, timeout_seconds=int(model["timeout_seconds"]))
        if result.raw_response is not None:
            atomic_bytes(unit.unit_root / str(action["build_unit_id"]) /
                         f"repair-{repair_number:03d}" / "model-response.txt",
                         result.raw_response.encode("utf-8")[:2 * 1024 * 1024])
        errors = validate_repair_proposal(result.proposal)
        if errors:
            raise ValueError("; ".join(errors))
        emit_model_event(log, event_type="MODEL_CALL_COMPLETED", run_id=unit.job.run_id,
            invocation_id=invocation, provider=request.provider, model=request.model,
            reasoning_level=request.reasoning, guidance_bundle_sha256=guidance_sha,
            request_sha256=request_sha, terminal_status="ACCEPTED",
            duration_ms=int((time.monotonic() - started) * 1000), retry_count=repair_number - 1,
            input_tokens=result.input_tokens, output_tokens=result.output_tokens,
            cache_tokens=result.cache_tokens, job_id="job_project_build", attempt_id=unit.job.attempt_id,
            build_unit_id=str(action["build_unit_id"]), inference_task="build_image_repair")
        return result.proposal
    except Exception as exc:
        emit_model_event(log, event_type="MODEL_CALL_COMPLETED", run_id=unit.job.run_id,
            invocation_id=invocation, provider=request.provider, model=request.model,
            reasoning_level=request.reasoning, guidance_bundle_sha256=guidance_sha,
            request_sha256=request_sha, terminal_status="FAILED",
            duration_ms=int((time.monotonic() - started) * 1000), retry_count=repair_number - 1,
            error_class=type(exc).__name__, job_id="job_project_build", attempt_id=unit.job.attempt_id,
            build_unit_id=str(action["build_unit_id"]), inference_task="build_image_repair")
        raise


def _probe_with_repairs(unit: UnitContext, entry: Mapping[str, Any], *, profile: BuildProfile,
                        resolver: Any, model_client: ModelClient | None, executor_factory=None) -> dict[str, Any]:
    action, image = dict(entry["action"]), entry.get("image")
    first = _probe_one(unit, entry, executor_factory, attempt_number=1)
    accepted_recipe = action.get("recipe")
    attempts: list[dict[str, Any]] = [{
        "attempt_number": 1,
        "kind": ("reused-repair" if action.get("recipe_provenance") == "reused-image-repair"
                 else "default"),
        "recipe_identity": first.get("recipe_identity"),
        "image_id": first.get("image_id"), "terminal_status": first["terminal_status"],
        "gaps": list(first.get("gaps", ())),
    }]
    if first["terminal_status"] == "SUCCEEDED":
        return {**first, "accepted_recipe": accepted_recipe, "accepted_image": image,
                "recipe_provenance": action.get("recipe_provenance", "accepted-inference"),
                "base_recipe_identity": entry.get("base_recipe_identity", first.get("recipe_identity")),
                "attempts": attempts, "repair_attempt_count": 0}
    model = unit.job.config.settings["model"]
    repair_limit = int(unit.job.config.settings["repair_attempts"])
    if not bool(model["enabled"]) or model_client is None:
        gap = ("build image repair model is disabled" if not bool(model["enabled"])
               else "build image repair model is unavailable")
        return {**first, "gaps": [*first["gaps"], gap], "attempts": attempts,
                "repair_attempt_count": 0, "accepted_recipe": accepted_recipe,
                "accepted_image": image, "recipe_provenance": action.get("recipe_provenance", "accepted-inference")}
    current_recipe = dict(accepted_recipe)
    diagnostics = _probe_diagnostics(unit, first)
    last_probe = first
    for repair_number in range(1, repair_limit + 1):
        repair_root = unit.unit_root / str(action["build_unit_id"]) / f"repair-{repair_number:03d}"
        attempt_started = time.monotonic()
        try:
            _identity, dockerfile = resolver.definition(
                {**current_recipe, "build_system": action["build_system"]}, profile)
            atomic_bytes(repair_root / "Dockerfile", dockerfile)
            proposal = _infer_repair(unit, action=action, recipe=current_recipe, dockerfile=dockerfile,
                                     diagnostics=diagnostics, attempts=attempts,
                                     repair_number=repair_number, model_client=model_client)
            candidate = apply_repair(current_recipe, proposal)
            errors = validate_build_recipe(candidate, _repair_validation_unit(action, candidate))
            if errors:
                raise ValueError("repaired build recipe is invalid: " + "; ".join(errors))
            current_recipe = candidate
            image_started = time.monotonic()
            repaired_image, stdout, stderr = resolver.resolve(
                {**candidate, "build_system": action["build_system"]}, profile)
            stream_limit = int(unit.job.config.settings["output_bytes"])
            image_streams = {
                "stdout": _retained_stream(unit.job.run_root, repair_root / "image-build.stdout", stdout, stream_limit),
                "stderr": _retained_stream(unit.job.run_root, repair_root / "image-build.stderr", stderr, stream_limit),
            }
            image_value = _image_dict(repaired_image, profile.user)
            candidate_action = {**action, "recipe": candidate,
                                "recipe_provenance": "inference-image-repair"}
            candidate_entry = {"action": candidate_action, "image": image_value,
                               "terminal_status": "SUCCEEDED", "gaps": []}
            last_probe = _probe_one(unit, candidate_entry, executor_factory,
                                    attempt_number=repair_number + 1)
            attempts.append({"attempt_number": repair_number + 1, "kind": "inference-repair",
                             "repair_number": repair_number,
                             "recipe_identity": repaired_image.recipe_identity,
                             "image_id": repaired_image.image_id,
                             "dockerfile_sha256": repaired_image.dockerfile_sha256,
                             "dockerfile_path": repaired_image.dockerfile_path,
                             "system_packages": list(candidate["system_packages"]),
                             "attempt_identity": f"{unit.job.attempt_id}:{action['build_unit_id']}:repair:{repair_number}",
                             "command_identity": hashlib.sha256(canonical_json({"kind": "project-image-build",
                                 "recipe_identity": repaired_image.recipe_identity})).hexdigest(),
                             "duration_ms": int((time.monotonic() - image_started) * 1000),
                             "streams": image_streams,
                             "terminal_status": last_probe["terminal_status"],
                             "gaps": list(last_probe.get("gaps", ()))})
            if last_probe["terminal_status"] == "SUCCEEDED":
                base_identity = str(entry.get("base_recipe_identity") or first["recipe_identity"])
                cache = _repair_cache(unit, base_identity)
                cache.parent.mkdir(parents=True, exist_ok=True)
                with FileLock(cache.parent / "repair.lock"):
                    atomic_json(cache, {"schema": REPAIR_CACHE_SCHEMA,
                        "base_recipe_identity": base_identity, "recipe": candidate,
                        "recipe_identity": repaired_image.recipe_identity,
                        "image_id": repaired_image.image_id,
                        "dockerfile_sha256": repaired_image.dockerfile_sha256,
                        "dockerfile_path": repaired_image.dockerfile_path})
                unit.job.events.write("PROJECT_IMAGE_REPAIR_ACCEPTED", unit_id=unit.unit_id,
                    build_unit_id=action["build_unit_id"], family=action["family"],
                    repair_attempt=repair_number, recipe_identity=repaired_image.recipe_identity,
                    image_id=repaired_image.image_id)
                return {**last_probe, "accepted_recipe": candidate, "accepted_image": image_value,
                        "recipe_provenance": "inference-image-repair",
                        "base_recipe_identity": base_identity, "attempts": attempts,
                        "repair_attempt_count": repair_number}
            diagnostics = _probe_diagnostics(unit, last_probe)
        except Exception as exc:
            stdout = exc.stdout if isinstance(exc, ProjectImageBuildError) else b""
            stderr = exc.stderr if isinstance(exc, ProjectImageBuildError) else str(exc).encode("utf-8")
            stream_limit = int(unit.job.config.settings["output_bytes"])
            image_streams = {
                "stdout": _retained_stream(unit.job.run_root, repair_root / "image-build.stdout", stdout, stream_limit),
                "stderr": _retained_stream(unit.job.run_root, repair_root / "image-build.stderr", stderr, stream_limit),
            }
            diagnostics = {"terminal_status": "FAILED", "error_class": type(exc).__name__,
                           "stdout_tail": stdout[-32768:].decode("utf-8", "replace"),
                           "stderr_tail": stderr[-32768:].decode("utf-8", "replace")}
            attempts.append({"attempt_number": repair_number + 1, "kind": "inference-repair",
                             "repair_number": repair_number, "terminal_status": "FAILED",
                             "error_class": type(exc).__name__, "gaps": [str(exc)[:4096]],
                             "attempt_identity": f"{unit.job.attempt_id}:{action['build_unit_id']}:repair:{repair_number}",
                             "command_identity": hashlib.sha256(canonical_json({"kind": "project-image-build",
                                 "repair_number": repair_number, "family": action["family"]})).hexdigest(),
                             "duration_ms": int((time.monotonic() - attempt_started) * 1000),
                             "streams": image_streams,
                             "system_packages": list(current_recipe.get("system_packages", ()))})
            unit.job.events.write("PROJECT_IMAGE_REPAIR_FAILED", unit_id=unit.unit_id,
                build_unit_id=action["build_unit_id"], family=action["family"],
                repair_attempt=repair_number, error_class=type(exc).__name__)
    return {**last_probe, "terminal_status": "FAILED", "probe_disposition": "FAILED",
            "gaps": [*last_probe.get("gaps", ()),
                     f"build remained unavailable after {repair_limit} image repair attempts"],
            "accepted_recipe": current_recipe, "accepted_image": image,
            "recipe_provenance": action.get("recipe_provenance", "accepted-inference"),
            "attempts": attempts, "repair_attempt_count": repair_limit}


def load_accepted_builds(run_root: Path) -> Mapping[str, Any]:
    pointer = run_root / "data" / "jobs" / "job_project_build" / "latest.json"
    if not pointer.is_file():
        raise ValueError("accepted job_project_build handoff is required")
    value = json.loads(pointer.read_text(encoding="utf-8"))
    handoff_path = (run_root / str(value.get("handoff_path", ""))).resolve()
    if run_root.resolve() not in handoff_path.parents or not handoff_path.is_file() or handoff_path.is_symlink():
        raise ValueError("project-build handoff path is invalid")
    if file_sha256(handoff_path) != value["handoff_sha256"]:
        raise ValueError("project-build handoff identity changed")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED" or
            handoff.get("job_id") != "job_project_build"):
        raise ValueError("project-build handoff is not accepted")
    artifact = handoff["outputs"]["acceptance.publish_handoff"]["artifact"]
    path = (run_root / str(artifact.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("project-build artifact path is invalid")
    if file_sha256(path) != artifact["sha256"]:
        raise ValueError("project-build artifact identity changed")
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != SCHEMA:
        raise ValueError("project-build dispatch schema is unsupported")
    return {**document, "project_build_handoff_sha256": value["handoff_sha256"],
            "project_build_artifact_sha256": artifact["sha256"]}


def _validate_config(context, _result) -> None:
    expected = ("plan", "image", "static_dispatch", "probe", "build_dispatch", "acceptance")
    if tuple(context.config.steps) != expected:
        raise ValueError("project-build topology does not match central configuration")
    task_sets = {"plan": ("load_recipes",), "image": BUILD_FAMILIES, "static_dispatch": STATIC_LANES,
                 "probe": BUILD_FAMILIES, "build_dispatch": BUILD_FAMILIES, "acceptance": ("publish_handoff",)}
    for step, tasks in task_sets.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"project-build task order mismatch: {step}")
    if set(profiles_from_settings(context.config.settings.get("profiles"))) != set(BUILD_FAMILIES):
        raise ValueError("project-build profiles must cover every build family")
    if type(context.config.settings.get("force_buildability_probe")) is not bool:
        raise ValueError("force_buildability_probe must be boolean")
    repair_attempts = context.config.settings.get("repair_attempts")
    if type(repair_attempts) is not int or not 3 <= repair_attempts <= 10:
        raise ValueError("repair_attempts must be an integer between 3 and 10")
    model = context.config.settings.get("model")
    required_model = {"enabled", "provider", "model", "reasoning", "max_input_tokens",
                      "max_output_tokens", "timeout_seconds"}
    if not isinstance(model, Mapping) or set(model) != required_model:
        raise ValueError("project-build repair model settings are invalid")
    if type(model["enabled"]) is not bool:
        raise ValueError("project-build repair model enabled must be boolean")
    if any(type(model[key]) is not int or model[key] <= 0 for key in
           ("max_input_tokens", "max_output_tokens", "timeout_seconds")):
        raise ValueError("project-build repair model limits must be positive integers")


def _image_dict(image: Any, user: str) -> dict[str, Any]:
    return {key: getattr(image, key) for key in image.__slots__} | {"user": user,
            "terminal_status": "SUCCEEDED", "gaps": []}


def _reuse_accepted_repair(unit: UnitContext, action: Mapping[str, Any], base_identity: str,
                           resolver: Any, profile: BuildProfile) -> tuple[dict[str, Any], dict[str, Any]] | None:
    cache = _repair_cache(unit, base_identity)
    if not cache.is_file():
        return None
    with FileLock(cache.parent / "repair.lock"):
        value = json.loads(cache.read_text(encoding="utf-8"))
    recipe = value.get("recipe")
    if (value.get("schema") != REPAIR_CACHE_SCHEMA or value.get("base_recipe_identity") != base_identity or
            not isinstance(recipe, Mapping)):
        raise ValueError("accepted build image repair cache is invalid")
    errors = validate_build_recipe(recipe, _repair_validation_unit(action, recipe))
    if errors:
        raise ValueError("accepted build image repair recipe is invalid: " + "; ".join(errors))
    image, _stdout, _stderr = resolver.resolve({**recipe, "build_system": action["build_system"]}, profile)
    if (image.recipe_identity != value.get("recipe_identity") or
            image.dockerfile_sha256 != value.get("dockerfile_sha256") or
            image.dockerfile_path != value.get("dockerfile_path")):
        raise ValueError("accepted build image repair identity changed")
    if image.image_id != value.get("image_id"):
        return None  # A rebuilt image must pass the default/repair probe sequence before acceptance.
    return ({**dict(action), "recipe": dict(recipe), "recipe_provenance": "reused-image-repair"},
            _image_dict(image, profile.user))


def _deterministic_native_recipe(unit: UnitContext, action: Mapping[str, Any]) -> Mapping[str, Any] | None:
    if action.get("family") != "native" or action.get("build_system") != "cmake":
        return None
    root = str(action["root"])
    source = _safe_root(unit.job.target_root or Path(), root)
    marker = source / "CMakeLists.txt"
    if not marker.is_file() or marker.is_symlink():
        return None
    build_dir = "build" if root == "." else f"{root}/build"
    marker_path = "CMakeLists.txt" if root == "." else f"{root}/CMakeLists.txt"
    recipe = {"schema": "appsec-review/build-recipe/1", "build_unit_id": action["build_unit_id"],
              "image_profile": "native", "source_dir": root, "build_dir": build_dir,
              "system_packages": [], "environment": {}, "dependency_files": [marker_path],
              "configure_commands": [["cmake", "-S", root, "-B", build_dir,
                                        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                                        "-DCMAKE_BUILD_TYPE=RelWithDebInfo"]],
              "build_commands": [["cmake", "--build", build_dir, "--parallel", "2"]],
              "expected_outputs": [build_dir], "network_required": False,
              "reason": "Deterministic offline CMake recipe derived from the accepted CMake build marker."}
    pseudo_unit = {"build_unit_id": action["build_unit_id"], "family": "native", "root": root,
                   "build_system": "cmake", "markers": [{"path": marker_path}],
                   "descriptor_package": {"documents": [{"path": marker_path}]}}
    errors = validate_build_recipe(recipe, pseudo_unit)
    if errors:
        raise ValueError("deterministic native recipe is invalid: " + "; ".join(errors))
    return recipe


def _deterministic_jvm_recipe(unit: UnitContext, action: Mapping[str, Any]) -> Mapping[str, Any] | None:
    if action.get("family") != "java" or action.get("build_system") != "javac":
        return None
    root = str(action["root"])
    source = _safe_root(unit.job.target_root or Path(), root)
    target = (unit.job.target_root or Path()).resolve(strict=True)
    sources = sorted(path for path in source.rglob("*")
                     if path.is_file() and not path.is_symlink() and path.suffix.lower() in {".java", ".kt"})
    if not sources or len(sources) > 60:
        return None

    target_paths = [path.relative_to(target).as_posix() for path in sources]
    local_paths = [path.relative_to(source).as_posix() for path in sources]
    java_sources = [path for path in local_paths if path.endswith(".java")]
    kotlin_sources = [path for path in local_paths if path.endswith(".kt")]
    build_dir = "build" if root == "." else f"{root}/build"
    classes_dir = "build/classes" if root == "." else f"{root}/build/classes"
    jar_path = "build/appsec-review.jar" if root == "." else f"{root}/build/appsec-review.jar"

    commands: list[list[str]] = []
    if kotlin_sources:
        commands.append(["kotlinc", *kotlin_sources, *java_sources, "-d", "build/classes"])
    if java_sources:
        javac = ["javac"]
        if kotlin_sources:
            javac.extend(["-classpath", "build/classes"])
        commands.append([*javac, "-d", "build/classes", *java_sources])
    commands.append(["jar", "--create", "--file", "build/appsec-review.jar", "-C", "build/classes", "."])
    recipe = {
        "schema": "appsec-review/build-recipe/1", "build_unit_id": action["build_unit_id"],
        "image_profile": "java", "source_dir": root, "build_dir": build_dir,
        "system_packages": [], "environment": {}, "dependency_files": target_paths,
        "configure_commands": [], "build_commands": commands,
        "expected_outputs": [classes_dir, jar_path], "network_required": False,
        "reason": "Deterministic offline JVM compilation derived from bounded Java/Kotlin source markers.",
    }
    pseudo_unit = {
        "build_unit_id": action["build_unit_id"], "family": "java", "root": root,
        "build_system": "javac", "markers": [{"path": path} for path in target_paths],
        "descriptor_package": {"documents": [{"path": path} for path in target_paths]},
    }
    errors = validate_build_recipe(recipe, pseudo_unit)
    if errors:
        raise ValueError("deterministic JVM recipe is invalid: " + "; ".join(errors))
    return recipe


def build_job(*, executor_factory=None, image_resolver_factory=None,
              model_client: ModelClient | None = None) -> Job:
    def plan(unit: UnitContext) -> Mapping[str, Any]:
        accepted = load_accepted_plan(unit.job.run_root)
        actions = list(accepted["build_topology"]["build_actions"])
        components = {str(item["component_id"]): str(item["root"])
                      for item in accepted.get("components", ())}
        action_by_component: dict[str, str] = {}
        for component_id, component_root in components.items():
            candidates = [item for item in actions if component_root == "." or item["root"] == component_root or
                          str(item["root"]).startswith(component_root.rstrip("/") + "/")]
            if candidates:
                action_by_component[component_id] = str(min(candidates, key=lambda item: len(str(item["root"])))
                                                        ["build_unit_id"])
        dependencies: dict[str, set[str]] = {str(item["build_unit_id"]): set() for item in actions}
        for relation in accepted.get("build_topology", {}).get("relationships", ()):
            if relation.get("kind") != "depends_on":
                continue
            owner = action_by_component.get(str(relation.get("component_id")))
            dependency = action_by_component.get(str(relation.get("dependency_component_id")))
            if owner and dependency and owner != dependency:
                dependencies[owner].add(dependency)
        resolved_actions = []
        for item in actions:
            deterministic = _deterministic_native_recipe(unit, item) or _deterministic_jvm_recipe(unit, item)
            selected = deterministic if deterministic is not None else item.get("recipe")
            recipe_fields: dict[str, Any] = {}
            if isinstance(selected, Mapping):
                recipe_fields = {
                    "recipe": {**dict(selected), "system_packages": []},
                    "package_hints": list(selected.get("system_packages", ())),
                    "requires_inference": False,
                    "recipe_provenance": (
                        "deterministic-cmake-marker" if deterministic is not None and item.get("family") == "native"
                        else "deterministic-jvm-source-set" if deterministic is not None
                        else "accepted-inference-default-image"),
                }
            resolved_actions.append({**dict(item), **recipe_fields,
                "build_dependencies": sorted(dependencies[str(item["build_unit_id"])])})
        actions = resolved_actions
        return {"actions": actions, "scanner_selections": accepted["scanner_selections"], "action_count": len(actions),
                "terminal_status": "SUCCEEDED" if actions else "NOT_APPLICABLE", "gaps": []}

    def image_handler(family: str):
        def execute(unit: UnitContext) -> Mapping[str, Any]:
            actions = [value for value in unit.output("plan.load_recipes")["actions"] if value.get("family") == family]
            profiles = profiles_from_settings(unit.job.config.settings["profiles"])
            resolver = image_resolver_factory(unit) if image_resolver_factory else ProjectImageResolver(
                metadata_root=unit.job.metadata_root, target_root=unit.job.target_root or Path(),
                timeout_seconds=int(unit.job.config.settings["image_build_timeout_seconds"]),
                output_bytes=int(unit.job.config.settings["output_bytes"]))
            entries, gaps = [], []
            for action in actions:
                recipe = action.get("recipe")
                if not isinstance(recipe, Mapping):
                    gap = f"{action['build_unit_id']}: validated inference build recipe is unavailable"
                    entries.append({"action": action, "image": None, "terminal_status": "BLOCKED", "gaps": [gap]})
                    gaps.append(gap)
                    continue
                try:
                    image_started = time.monotonic()
                    unit.job.events.write("PROJECT_IMAGE_BUILD_STARTED", unit_id=unit.unit_id,
                                          build_unit_id=action["build_unit_id"], family=family)
                    image, stdout, stderr = resolver.resolve({**recipe, "build_system": action["build_system"]}, profiles[family])
                    base_recipe_identity = image.recipe_identity
                    cached = _reuse_accepted_repair(unit, action, base_recipe_identity,
                                                    resolver, profiles[family])
                    if cached is not None:
                        action, value = cached
                        image = None
                        unit.job.events.write("PROJECT_IMAGE_REPAIR_REUSED", unit_id=unit.unit_id,
                            build_unit_id=action["build_unit_id"], family=family,
                            recipe_identity=value["recipe_identity"], image_id=value["image_id"])
                    else:
                        value = _image_dict(image, profiles[family].user)
                    logs = unit.unit_root / str(action["build_unit_id"])
                    logs.mkdir(parents=True, exist_ok=True)
                    stream_limit = int(unit.job.config.settings["output_bytes"])
                    streams = {
                        "stdout": _retained_stream(unit.job.run_root, logs / "image-build.stdout", stdout, stream_limit),
                        "stderr": _retained_stream(unit.job.run_root, logs / "image-build.stderr", stderr, stream_limit),
                    }
                    if image is not None:
                        unit.job.events.write("PROJECT_IMAGE_REUSED" if image.reused else "PROJECT_IMAGE_BUILT",
                            unit_id=unit.unit_id, build_unit_id=action["build_unit_id"], family=family,
                            recipe_identity=image.recipe_identity, image_id=image.image_id,
                            disposition="REUSED" if image.reused else "BUILT",
                            reuse_disposition=image.cache_disposition,
                            reuse_rejection_reason=image.cache_rejection_reason,
                            saved_count=image.saved_build_count)
                    entries.append({"action": action, "image": value,
                                    "base_recipe_identity": base_recipe_identity,
                                    "attempt_identity": f"{unit.job.attempt_id}:{action['build_unit_id']}:image",
                                    "command_identity": hashlib.sha256(canonical_json({"kind": "project-image-build",
                                        "recipe_identity": base_recipe_identity})).hexdigest(),
                                    "duration_ms": int((time.monotonic() - image_started) * 1000),
                                    "streams": streams,
                                    "terminal_status": "SUCCEEDED", "gaps": []})
                except (RuntimeError, ValueError, OSError) as exc:
                    logs = unit.unit_root / str(action["build_unit_id"])
                    logs.mkdir(parents=True, exist_ok=True)
                    stdout = exc.stdout if isinstance(exc, ProjectImageBuildError) else b""
                    stderr = exc.stderr if isinstance(exc, ProjectImageBuildError) else str(exc).encode("utf-8")
                    stream_limit = int(unit.job.config.settings["output_bytes"])
                    streams = {
                        "stdout": _retained_stream(unit.job.run_root, logs / "image-build.stdout", stdout, stream_limit),
                        "stderr": _retained_stream(unit.job.run_root, logs / "image-build.stderr", stderr, stream_limit),
                    }
                    gap = f"{action['build_unit_id']}: project image resolution failed ({type(exc).__name__}: {exc})"
                    unit.job.events.write("PROJECT_IMAGE_BUILD_FAILED", unit_id=unit.unit_id,
                        build_unit_id=action["build_unit_id"], family=family, error_class=type(exc).__name__)
                    entries.append({"action": action, "image": None,
                        "attempt_identity": f"{unit.job.attempt_id}:{action['build_unit_id']}:image",
                        "command_identity": hashlib.sha256(canonical_json({"kind": "project-image-build",
                            "family": family, "build_unit_id": action["build_unit_id"]})).hexdigest(),
                        "duration_ms": int((time.monotonic() - image_started) * 1000), "streams": streams,
                        "terminal_status": "FAILED", "gaps": [gap]})
                    gaps.append(gap)
            return {"family": family, "entries": entries, "image_count": sum(value["image"] is not None for value in entries),
                    "terminal_status": "NOT_APPLICABLE" if not entries else "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED",
                    "gaps": gaps}
        return execute

    def static_handler(lane: str):
        def execute(unit: UnitContext) -> Mapping[str, Any]:
            planned = unit.output("plan.load_recipes")
            actions, selections = list(planned["actions"]), list(planned["scanner_selections"])
            roots, dispatches = [str(value["root"]) for value in actions], []
            if lane == "global":
                for selection in selections:
                    scope = [item for item in selection["scope"] if not any(
                        root == "." or str(item["path"]) == root or str(item["path"]).startswith(root + "/") for root in roots)]
                    if scope:
                        dispatches.append({"workflow": "global_jobflow_static", "tool_id": selection["scanner_id"],
                                           "scope": scope, "reason": selection["reason"]})
            else:
                for action in (value for value in actions if value.get("family") == lane):
                    root, tools = str(action["root"]), []
                    for selection in selections:
                        scope = [item for item in selection["scope"] if root == "." or str(item["path"]) == root or
                                 str(item["path"]).startswith(root + "/")]
                        if scope:
                            tools.append({"tool_id": selection["scanner_id"], "scope": scope, "reason": selection["reason"]})
                    dispatches.append({"workflow": "lang_jobflow_static", "family": lane,
                                       "build_unit_id": action["build_unit_id"], "root": root, "tools": tools})
            for value in dispatches:
                unit.job.events.write("LANGUAGE_STATIC_WORKFLOW_DISPATCHED", unit_id=unit.unit_id,
                    family=lane, workflow=value["workflow"], build_unit_id=value.get("build_unit_id"),
                    tool_count=len(value.get("tools", ())) or int("tool_id" in value))
            return {"lane": lane, "dispatches": dispatches, "dispatch_count": len(dispatches),
                    "terminal_status": "SUCCEEDED" if dispatches else "NOT_APPLICABLE", "gaps": []}
        return execute

    def probe_handler(family: str):
        def execute(unit: UnitContext) -> Mapping[str, Any]:
            profiles = profiles_from_settings(unit.job.config.settings["profiles"])
            resolver = image_resolver_factory(unit) if image_resolver_factory else ProjectImageResolver(
                metadata_root=unit.job.metadata_root, target_root=unit.job.target_root or Path(),
                timeout_seconds=int(unit.job.config.settings["image_build_timeout_seconds"]),
                output_bytes=int(unit.job.config.settings["output_bytes"]))
            receipts = []
            for entry in unit.output(f"image.{family}")["entries"]:
                if (not isinstance(entry.get("image"), Mapping) or
                        not isinstance(entry.get("action", {}).get("recipe"), Mapping)):
                    receipts.append(_probe_one(unit, entry, executor_factory))
                else:
                    receipts.append(_probe_with_repairs(unit, entry, profile=profiles[family],
                                                        resolver=resolver, model_client=model_client,
                                                        executor_factory=executor_factory))
            gaps = [f"{value['build_unit_id']}: {gap}" for value in receipts for gap in value["gaps"]]
            return {"family": family, "receipts": receipts, "probe_count": len(receipts),
                    "reused_count": sum(value.get("probe_disposition") == "REUSED" for value in receipts),
                    "terminal_status": "NOT_APPLICABLE" if not receipts else "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED",
                    "gaps": gaps}
        return execute

    def build_dispatch_handler(family: str):
        def execute(unit: UnitContext) -> Mapping[str, Any]:
            receipts = unit.output(f"probe.{family}")["receipts"]
            images = {value["action"]["build_unit_id"]: value for value in unit.output(f"image.{family}")["entries"]}
            dispatches, gaps = [], []
            for receipt in receipts:
                if receipt["terminal_status"] != "SUCCEEDED":
                    gaps.extend(receipt["gaps"])
                    continue
                entry = images[receipt["build_unit_id"]]
                accepted_recipe = receipt.get("accepted_recipe", entry["action"]["recipe"])
                accepted_image = receipt.get("accepted_image", entry["image"])
                value = {"workflow": "lang_jobflow_build", "family": family, "build_unit_id": receipt["build_unit_id"],
                         "root": receipt["root"], "build_system": receipt["build_system"],
                         "recipe": accepted_recipe,
                         "recipe_provenance": receipt.get(
                             "recipe_provenance", entry["action"].get("recipe_provenance", "accepted-inference")),
                         "recipe_identity": receipt["recipe_identity"], "image": accepted_image,
                         "source_fingerprint": unit.job.source_fingerprint,
                         "probe_identity": hashlib.sha256(canonical_json(receipt)).hexdigest(),
                         "build_dependencies": list(entry["action"].get("build_dependencies", ())),
                         "probe_disposition": receipt["probe_disposition"],
                         "capabilities": list(_BUILD_CAPABILITIES[family])}
                dispatches.append(value)
                unit.job.events.write("LANGUAGE_BUILD_WORKFLOW_DISPATCHED", unit_id=unit.unit_id, family=family,
                    workflow="lang_jobflow_build", build_unit_id=receipt["build_unit_id"],
                    recipe_identity=receipt["recipe_identity"], image_id=receipt["image_id"],
                    probe_disposition=receipt["probe_disposition"])
            return {"family": family, "dispatches": dispatches, "dispatch_count": len(dispatches),
                    "terminal_status": "NOT_APPLICABLE" if not receipts else "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED",
                    "gaps": gaps}
        return execute

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        images = {family: unit.output(f"image.{family}") for family in BUILD_FAMILIES}
        probes = {family: unit.output(f"probe.{family}") for family in BUILD_FAMILIES}
        static = {lane: unit.output(f"static_dispatch.{lane}") for lane in STATIC_LANES}
        builds = {family: unit.output(f"build_dispatch.{family}") for family in BUILD_FAMILIES}
        receipts = [value for family in BUILD_FAMILIES for value in probes[family]["receipts"]]
        gaps = [gap for collection in (images, probes, builds) for value in collection.values() for gap in value["gaps"]]
        document = {"schema": SCHEMA, "source_fingerprint": unit.job.source_fingerprint, "images": images,
                    "probes": probes, "probe_receipts": receipts,
                    "static_dispatches": [item for value in static.values() for item in value["dispatches"]],
                    "build_dispatches": [item for value in builds.values() for item in value["dispatches"]],
                    "probe_artifact_count": sum(len(item["artifacts"]) for item in receipts),
                    "gaps": list(dict.fromkeys(gaps))}
        artifact = _artifact(unit, "accepted-project-build-dispatch.json", document)
        return {"artifact": artifact, "probe_count": len(receipts),
                "probe_reused_count": sum(item.get("probe_disposition") == "REUSED" for item in receipts),
                "static_dispatch_count": len(document["static_dispatches"]),
                "build_dispatch_count": len(document["build_dispatches"]), "gaps": document["gaps"],
                "terminal_status": "COMPLETED_WITH_GAPS" if document["gaps"] else "SUCCEEDED"}

    units: list[Unit] = [Unit("plan.load_recipes", plan)]
    units.extend(Unit(f"image.{family}", image_handler(family), ("plan.load_recipes",)) for family in BUILD_FAMILIES)
    units.extend(Unit(f"static_dispatch.{lane}", static_handler(lane), ("plan.load_recipes",)) for lane in STATIC_LANES)
    units.extend(Unit(f"probe.{family}", probe_handler(family), (f"image.{family}",)) for family in BUILD_FAMILIES)
    units.extend(Unit(f"build_dispatch.{family}", build_dispatch_handler(family),
                      (f"image.{family}", f"probe.{family}")) for family in BUILD_FAMILIES)
    terminal = tuple([*(f"static_dispatch.{lane}" for lane in STATIC_LANES),
                      *(f"build_dispatch.{family}" for family in BUILD_FAMILIES)])
    units.append(Unit("acceptance.publish_handoff", publish, terminal))
    source_files = (Path(__file__), Path(__file__).with_name("repair.py"),
                    Path(__file__).parents[2] / "container_runtime" / "build_executor.py",
                    Path(__file__).parents[2] / "container_runtime" / "project_images.py")
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in source_files) +
                                    (b"injected" if executor_factory or image_resolver_factory or model_client
                                     else b"docker")).hexdigest()
    return Job("job_project_build", "project_build", UnitExecutor(tuple(units)).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA, implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(), units=tuple(units))
