from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
from typing import Any

from appsec_review.container_runtime import BuildContainerExecutor, profiles_from_settings
from appsec_review.jobs.cataloging import source_fingerprint, write_json
from appsec_review.jobs.job_target_analysis_plan import load_accepted_plan
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256


SCHEMA = "appsec-review/project-build/1"
EXECUTOR_IDENTITY = "appsec-review/build-container-executor/2"
BUILD_FAMILIES = ("native", "rust", "go", "java", "node", "dotnet", "python", "php", "wasm")
_IGNORED = {".git", ".hg", ".svn", "build", "target", "node_modules", "bin", "obj", ".gradle"}
_ARTIFACT_SUFFIXES = {
    ".o", ".obj", ".a", ".lib", ".so", ".dll", ".dylib", ".exe", ".wasm",
    ".class", ".jar", ".war", ".ear", ".rlib", ".rmeta", ".pdb",
}


def _artifact(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "project-build" / name
    identity = write_json(path, value)
    identity["path"] = path.relative_to(unit.job.run_root).as_posix()
    return identity


def _safe_root(target: Path, relative: str) -> Path:
    logical = PurePosixPath(relative)
    if relative != "." and (not logical.parts or ".." in logical.parts):
        raise ValueError("accepted build-unit root is invalid")
    path = (target / Path(*logical.parts)).resolve(strict=True) if relative != "." else target.resolve(strict=True)
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
        build_root = (unit.job.run_root / "data" / "build" / "units").resolve()
        if resolved != build_root and build_root not in resolved.parents:
            raise ValueError("build workspace deletion escaped the run-owned build root")
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"build source contains an unsupported symlink: {path.relative_to(target)}")
    shutil.copytree(source, destination, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(*sorted(_IGNORED)))
    try:
        workspace.chmod(0o777)
        for directory in [path for path in workspace.rglob("*") if path.is_dir()]:
            directory.chmod(0o777)
    except OSError:
        pass


def _snapshot(root: Path, limit: int) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(root).as_posix()] = file_sha256(path)
            if len(result) > limit:
                raise ValueError("build workspace file-count bound exceeded")
    return result


def _kind(path: Path) -> str | None:
    suffix = path.suffix.lower()
    if suffix in _ARTIFACT_SUFFIXES:
        return suffix.removeprefix(".") or "binary"
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return None
    if magic == b"\x7fELF":
        return "elf"
    if magic[:2] == b"MZ":
        return "pe"
    if magic == b"\x00asm":
        return "wasm"
    return None


def _outputs(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int) -> list[dict[str, Any]]:
    values = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(workspace).as_posix()
        digest = file_sha256(path)
        kind = _kind(path)
        if kind is None or before.get(relative) == digest:
            continue
        values.append({"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
                       "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind})
        if len(values) >= limit:
            break
    return values


def _checkpoint_path(unit: UnitContext, build_unit_id: str) -> Path:
    return unit.job.run_root / "data" / "build" / "units" / build_unit_id / "checkpoint.json"


def _load_checkpoint(unit: UnitContext, build_unit_id: str, identity: str) -> Mapping[str, Any] | None:
    path = _checkpoint_path(unit, build_unit_id)
    if not path.is_file() or path.is_symlink():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("identity") != identity or value.get("terminal_status") != "SUCCEEDED":
        return None
    for artifact in value.get("artifacts", ()):
        candidate = (unit.job.run_root / str(artifact["path"])).resolve()
        if unit.job.run_root.resolve() not in candidate.parents or not candidate.is_file():
            return None
        if file_sha256(candidate) != artifact["sha256"]:
            return None
    return {**value, "checkpoint_reused": True}


def _build_one(unit: UnitContext, action: Mapping[str, Any], executor_factory=None) -> dict[str, Any]:
    recipe = action.get("recipe")
    build_unit_id = str(action["build_unit_id"])
    if not isinstance(recipe, Mapping):
        return {"build_unit_id": build_unit_id, "family": action.get("family"),
                "root": action.get("root"), "build_system": action.get("build_system"),
                "terminal_status": "BLOCKED", "artifacts": [],
                "gaps": ["validated inference build recipe is unavailable"]}
    if recipe.get("network_required") is True:
        return {"build_unit_id": build_unit_id, "family": action.get("family"),
                "root": action.get("root"), "build_system": action.get("build_system"),
                "terminal_status": "BLOCKED", "artifacts": [],
                "gaps": ["build recipe requires network; build execution policy is network-disabled"]}
    profiles = profiles_from_settings(unit.job.config.settings["profiles"])
    profile = profiles[str(recipe["image_profile"])]
    identity = hashlib.sha256(canonical_json({"schema": SCHEMA,
        "executor_identity": EXECUTOR_IDENTITY, "recipe": recipe,
        "source_fingerprint": unit.job.source_fingerprint, "image_id": profile.image_id})).hexdigest()
    checkpoint = _load_checkpoint(unit, build_unit_id, identity)
    if checkpoint is not None:
        return dict(checkpoint)
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed after the accepted review snapshot")
    root = unit.job.run_root / "data" / "build" / "units" / build_unit_id
    workspace = root / "workspace"
    _copy_source(unit, action, workspace)
    before = _snapshot(workspace, int(unit.job.config.settings["artifact_count_limit"]) * 10)
    executor = (executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
        profile, timeout_seconds=int(unit.job.config.settings["command_timeout_seconds"]),
        output_bytes=int(unit.job.config.settings["output_bytes"])))
    executor.resolve()
    command_receipts = []
    gaps = []
    for index, argv in enumerate([*recipe["configure_commands"], *recipe["build_commands"]], 1):
        source_dir = str(recipe["source_dir"])
        normalized_argv = [str(argv[0])]
        for argument in argv[1:]:
            value = str(argument)
            if value == source_dir:
                value = "."
            elif source_dir != "." and value.startswith(source_dir + "/"):
                value = value[len(source_dir) + 1:]
            normalized_argv.append(value)
        result = executor.execute(tuple(normalized_argv), workspace=workspace,
                                  working_directory=source_dir,
                                  environment=recipe["environment"])
        logs = root / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        stdout = logs / f"command-{index:03d}.stdout"
        stderr = logs / f"command-{index:03d}.stderr"
        stdout.write_bytes(result.stdout)
        stderr.write_bytes(result.stderr)
        command_receipts.append({"ordinal": index,
            "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "stdout": stdout.relative_to(unit.job.run_root).as_posix(),
            "stderr": stderr.relative_to(unit.job.run_root).as_posix()})
        if result.timed_out or result.exit_code != 0:
            gaps.append(f"build command {index} {'timed out' if result.timed_out else f'exited {result.exit_code}'}")
            break
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed during isolated build execution")
    artifacts = _outputs(unit.job.run_root, workspace, before,
                         int(unit.job.config.settings["artifact_count_limit"]))
    status = "SUCCEEDED" if not gaps else "FAILED"
    if not artifacts and not gaps:
        gaps.append("build completed but no compiled artifacts were identified")
        status = "PARTIAL"
    receipt = {"schema": SCHEMA, "executor_identity": EXECUTOR_IDENTITY,
               "identity": identity, "build_unit_id": build_unit_id,
               "family": recipe["image_profile"], "root": action["root"],
               "build_system": action["build_system"], "image_id": profile.image_id,
               "commands": command_receipts, "artifacts": artifacts,
               "terminal_status": status, "gaps": gaps, "checkpoint_reused": False}
    atomic_json(_checkpoint_path(unit, build_unit_id), receipt)
    return receipt


def load_accepted_builds(run_root: Path) -> Mapping[str, Any]:
    pointer = run_root / "data" / "jobs" / "job_project_build" / "latest.json"
    if not pointer.is_file():
        raise ValueError("accepted job_project_build handoff is required")
    value = json.loads(pointer.read_text(encoding="utf-8"))
    handoff_path = run_root / value["handoff_path"]
    if file_sha256(handoff_path) != value["handoff_sha256"]:
        raise ValueError("project-build handoff identity changed")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    artifact = handoff["outputs"]["acceptance.publish_handoff"]["artifact"]
    path = run_root / artifact["path"]
    if file_sha256(path) != artifact["sha256"]:
        raise ValueError("project-build artifact identity changed")
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_config(context, _result) -> None:
    if tuple(context.config.steps) != ("plan", "build", "acceptance"):
        raise ValueError("project-build topology does not match central configuration")
    if tuple(context.config.step("plan").tasks) != ("load_recipes",):
        raise ValueError("project-build planning configuration is invalid")
    if tuple(context.config.step("build").tasks) != BUILD_FAMILIES:
        raise ValueError("project-build family configuration is invalid")
    if tuple(context.config.step("acceptance").tasks) != ("publish_handoff",):
        raise ValueError("project-build acceptance configuration is invalid")
    profiles = profiles_from_settings(context.config.settings.get("profiles"))
    if set(profiles) != set(BUILD_FAMILIES):
        raise ValueError("project-build profiles must cover every build family")


def build_job(*, executor_factory=None) -> Job:
    def plan(unit: UnitContext) -> Mapping[str, Any]:
        accepted = load_accepted_plan(unit.job.run_root)
        actions = list(accepted["build_topology"]["build_actions"])
        return {"actions": actions, "action_count": len(actions),
                "terminal_status": "SUCCEEDED" if actions else "NOT_APPLICABLE", "gaps": []}

    def family_handler(family: str):
        def execute(unit: UnitContext) -> Mapping[str, Any]:
            actions = [item for item in unit.output("plan.load_recipes")["actions"]
                       if item.get("family") == family]
            receipts = [_build_one(unit, action, executor_factory) for action in actions]
            gaps = [f"{item['build_unit_id']}: {gap}" for item in receipts for gap in item["gaps"]]
            status = ("NOT_APPLICABLE" if not receipts else
                      "SUCCEEDED" if all(item["terminal_status"] == "SUCCEEDED" for item in receipts)
                      else "COMPLETED_WITH_GAPS")
            return {"family": family, "receipts": receipts, "unit_count": len(receipts),
                    "artifact_count": sum(len(item["artifacts"]) for item in receipts),
                    "terminal_status": status, "gaps": gaps}
        return execute

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        families = {family: unit.output(f"build.{family}") for family in BUILD_FAMILIES}
        receipts = [item for value in families.values() for item in value["receipts"]]
        document = {"schema": SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
                    "families": families, "builds": receipts,
                    "artifact_count": sum(len(item["artifacts"]) for item in receipts),
                    "gaps": [gap for value in families.values() for gap in value["gaps"]]}
        artifact = _artifact(unit, "accepted-project-builds.json", document)
        status = "SUCCEEDED" if not document["gaps"] else "COMPLETED_WITH_GAPS"
        return {"artifact": artifact, "build_count": len(receipts),
                "artifact_count": document["artifact_count"], "gaps": document["gaps"],
                "terminal_status": status}

    units = (Unit("plan.load_recipes", plan), *(
        Unit(f"build.{family}", family_handler(family), ("plan.load_recipes",))
        for family in BUILD_FAMILIES),
        Unit("acceptance.publish_handoff", publish,
             tuple(f"build.{family}" for family in BUILD_FAMILIES)))
    implementation = hashlib.sha256(Path(__file__).read_bytes() +
        Path(__file__).parents[2].joinpath("container_runtime", "build_executor.py").read_bytes() +
        (b"injected" if executor_factory else b"docker")).hexdigest()
    return Job("job_project_build", "project_build", UnitExecutor(tuple(units)).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(),
               units=tuple(units))
