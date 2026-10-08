from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import time
from typing import Any

from appsec_review.container_runtime import (
    BuildContainerExecutor,
    BuildProfile,
    ProjectImageBuildError,
    ProjectImageResolver,
    project_dependency_environment,
    profiles_from_settings,
)
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.cataloging import source_fingerprint, write_json
from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256


SCHEMA = "appsec-review/project-build-dispatch/2"
EXECUTOR_IDENTITY = "appsec-review/build-container-executor/2"
BUILD_FAMILIES = ("native", "rust", "go", "java", "node", "dotnet", "python", "php", "wasm")
STATIC_LANES = ("global", *BUILD_FAMILIES)
_IGNORED = {".git", ".hg", ".svn", "build", "target", "node_modules", "bin", "obj", ".gradle"}
_ARTIFACT_SUFFIXES = {".o", ".obj", ".a", ".lib", ".so", ".dll", ".dylib", ".exe", ".wasm",
                      ".class", ".jar", ".war", ".ear", ".rlib", ".rmeta", ".pdb"}
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
        if path.is_file() and not path.is_symlink():
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
    source_dir, result = str(recipe["source_dir"]), [str(argv[0])]
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
    for key, protected in project_dependency_environment(recipe).items():
        if key not in environment:
            continue  # The derived image already carries the protected value.
        if key == "MAVEN_OPTS":
            environment[key] = protected + " " + environment[key]
        elif key == "PATH":
            environment[key] = protected.replace("$PATH", environment[key])
        else:
            environment[key] = protected
    return environment


def _probe_cache(unit: UnitContext, recipe_identity: str) -> Path:
    return unit.job.metadata_root / "project-probes" / recipe_identity / "accepted.json"


def _probe_one(unit: UnitContext, entry: Mapping[str, Any], executor_factory=None) -> dict[str, Any]:
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
                        "checkpoint_reused": True, "commands": [], "gaps": []}
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed after the accepted review snapshot")
    root, workspace = (unit.job.run_root / "data" / "build" / "probes" / build_unit_id,
                       unit.job.run_root / "data" / "build" / "probes" / build_unit_id / "workspace")
    _copy_source(unit, action, workspace)
    before = _snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    profile = BuildProfile(str(action["family"]), str(image["image_tag"]), str(image["image_id"]), str(image["user"]))
    executor = executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
        profile, timeout_seconds=int(unit.job.config.settings["command_timeout_seconds"]),
        output_bytes=int(unit.job.config.settings["output_bytes"]))
    executor.resolve()
    command_receipts, gaps = [], []
    for ordinal, argv in enumerate([*recipe["configure_commands"], *recipe["build_commands"]], 1):
        command = _normalized_argv(recipe, argv)
        invocation = hashlib.sha256(f"{unit.job.run_id}:{unit.job.attempt_id}:{build_unit_id}:{ordinal}".encode()).hexdigest()
        started = time.monotonic()
        unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id, tool_invocation_id=invocation,
            tool_id="build-probe", retry_count=0, tool_identity={"family": action["family"], "image_id": image["image_id"]},
            input_identities={"recipe_identity": recipe_identity,
                              "argv_sha256": hashlib.sha256(canonical_json(list(command))).hexdigest()})
        result = executor.execute(command, workspace=workspace, working_directory=str(recipe["source_dir"]),
                                  environment=_probe_environment({**recipe, "build_system": action["build_system"]}))
        logs = root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        stdout, stderr = logs / f"command-{ordinal:03d}.stdout", logs / f"command-{ordinal:03d}.stderr"
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        command_receipts.append({"ordinal": ordinal,
            "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "stdout": stdout.relative_to(unit.job.run_root).as_posix(), "stderr": stderr.relative_to(unit.job.run_root).as_posix()})
        failed = result.timed_out or result.exit_code != 0
        unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id, tool_invocation_id=invocation,
            tool_id="build-probe", retry_count=0, tool_identity={"family": action["family"], "image_id": image["image_id"]},
            disposition="FAILED" if failed else "SUCCEEDED", result_count=0, gap_count=1 if failed else 0,
            truncated=False, duration_ms=int((time.monotonic() - started) * 1000))
        if failed:
            gaps.append(f"build command {ordinal} {'timed out' if result.timed_out else f'exited {result.exit_code}'}")
            break
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed during isolated probe execution")
    artifacts = _outputs(unit.job.run_root, workspace, before, int(unit.job.config.settings["artifact_count_limit"]))
    status = "FAILED" if gaps else "SUCCEEDED"
    receipt = {**base, "schema": SCHEMA, "executor_identity": EXECUTOR_IDENTITY,
               "recipe_identity": recipe_identity, "image_id": image["image_id"], "commands": command_receipts,
               "artifacts": artifacts, "terminal_status": status,
               "probe_disposition": "FAILED" if gaps else "PROBED", "gaps": gaps, "checkpoint_reused": False}
    if status == "SUCCEEDED":
        cache.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(cache.parent / "probe.lock"):
            atomic_json(cache, {"schema": "appsec-review/build-probe-cache/1", "recipe_identity": recipe_identity,
                                "image_id": image["image_id"], "terminal_status": "SUCCEEDED"})
    return receipt


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


def _image_dict(image: Any, user: str) -> dict[str, Any]:
    return {key: getattr(image, key) for key in image.__slots__} | {"user": user,
            "terminal_status": "SUCCEEDED", "gaps": []}


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


def build_job(*, executor_factory=None, image_resolver_factory=None) -> Job:
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
            recipe = _deterministic_native_recipe(unit, item)
            resolved_actions.append({**dict(item),
                **({"recipe": recipe, "requires_inference": False,
                    "recipe_provenance": "deterministic-cmake-marker"} if recipe is not None else {}),
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
                    unit.job.events.write("PROJECT_IMAGE_BUILD_STARTED", unit_id=unit.unit_id,
                                          build_unit_id=action["build_unit_id"], family=family)
                    image, stdout, stderr = resolver.resolve({**recipe, "build_system": action["build_system"]}, profiles[family])
                    logs = unit.unit_root / str(action["build_unit_id"])
                    logs.mkdir(parents=True, exist_ok=True)
                    (logs / "image-build.stdout").write_bytes(stdout)
                    (logs / "image-build.stderr").write_bytes(stderr)
                    value = _image_dict(image, profiles[family].user)
                    unit.job.events.write("PROJECT_IMAGE_REUSED" if image.reused else "PROJECT_IMAGE_BUILT",
                        unit_id=unit.unit_id, build_unit_id=action["build_unit_id"], family=family,
                        recipe_identity=image.recipe_identity, image_id=image.image_id,
                        disposition="REUSED" if image.reused else "BUILT")
                    entries.append({"action": action, "image": value, "terminal_status": "SUCCEEDED", "gaps": []})
                except (RuntimeError, ValueError, OSError) as exc:
                    logs = unit.unit_root / str(action["build_unit_id"])
                    logs.mkdir(parents=True, exist_ok=True)
                    if isinstance(exc, ProjectImageBuildError):
                        (logs / "image-build.stdout").write_bytes(exc.stdout)
                        (logs / "image-build.stderr").write_bytes(exc.stderr)
                    gap = f"{action['build_unit_id']}: project image resolution failed ({type(exc).__name__}: {exc})"
                    unit.job.events.write("PROJECT_IMAGE_BUILD_FAILED", unit_id=unit.unit_id,
                        build_unit_id=action["build_unit_id"], family=family, error_class=type(exc).__name__)
                    entries.append({"action": action, "image": None, "terminal_status": "FAILED", "gaps": [gap]})
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
            receipts = [_probe_one(unit, entry, executor_factory) for entry in unit.output(f"image.{family}")["entries"]]
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
                value = {"workflow": "lang_jobflow_build", "family": family, "build_unit_id": receipt["build_unit_id"],
                         "root": receipt["root"], "build_system": receipt["build_system"],
                         "recipe": entry["action"]["recipe"],
                         "recipe_provenance": entry["action"].get("recipe_provenance", "accepted-inference"),
                         "recipe_identity": receipt["recipe_identity"], "image": entry["image"],
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
    source_files = (Path(__file__), Path(__file__).parents[2] / "container_runtime" / "build_executor.py",
                    Path(__file__).parents[2] / "container_runtime" / "project_images.py")
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in source_files) +
                                    (b"injected" if executor_factory or image_resolver_factory else b"docker")).hexdigest()
    return Job("job_project_build", "project_build", UnitExecutor(tuple(units)).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA, implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(), units=tuple(units))
