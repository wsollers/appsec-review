from __future__ import annotations

from collections.abc import Mapping
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
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build.job import (
    _dispatches, _mapped_files, _probe_environment, _snapshot,
)
from appsec_review.jobs.job_project_build.job import _normalized_argv
from appsec_review.runtime import UnitContext
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256, protected_json


RECEIPT_SCHEMA = "appsec-review/wasm-build-receipt/1"
EXECUTOR_IDENTITY = "appsec-review/wasm-output-family-executor/1"
CAPTURE_IDENTITY = "appsec-review/protected-build-capture/2"
_SECRET_KEY = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL)", re.I)
_WASM_MAGIC = b"\x00asm"
_TOOL_KINDS = {
    "cargo": "package-builder", "rustc": "compiler", "wasm-pack": "package-builder",
    "wasm-bindgen": "binding-generator", "emcc": "compiler-driver", "em++": "compiler-driver",
    "clang": "compiler-driver", "clang++": "compiler-driver", "asc": "transpiler",
    "wasm-ld": "linker", "ld.lld": "linker", "llvm-ar": "archiver", "emar": "archiver",
    "wasm-opt": "post-link", "wasm-tools": "post-link", "npm": "package-builder",
    "pnpm": "package-builder", "yarn": "package-builder", "npx": "package-builder",
    "cmake": "build-driver", "make": "build-driver", "ninja": "build-driver",
}
_OBSERVED_TOOLS = frozenset(_TOOL_KINDS) | {"cc", "c++", "ar", "ld", "rust-lld", "lld"}


class ProducerUnavailable(RuntimeError):
    """A bounded producer/tool failure, not a framework-integrity failure."""


class WasmIntegrityError(ValueError):
    """A changed accepted identity or protected artifact; publication must stop."""


def _runtime_settings(unit: UnitContext) -> dict[str, Any]:
    """Project the shared language-build limits into the WASM adapter contract."""
    wasm = unit.job.config.settings.get("wasm")
    if not isinstance(wasm, Mapping):
        raise WasmIntegrityError("language-build WASM settings are unavailable")
    return {
        "command_timeout_seconds": unit.job.config.settings["command_timeout_seconds"],
        "stream_limit_bytes": unit.job.config.settings["output_bytes"],
        "artifact_count_limit": unit.job.config.settings["artifact_count_limit"],
        "workspace_file_limit": wasm["workspace_file_limit"],
        "producers": wasm["producers"],
    }


def _producer_rules(settings: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw = settings.get("producers")
    if not isinstance(raw, Mapping) or not raw:
        raise ValueError("wasm-build producers configuration is required")
    result: dict[str, dict[str, Any]] = {}
    for name, value in raw.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) or
                not isinstance(value, Mapping) or set(value) != {"families", "tools", "indicators"}):
            raise ValueError(f"wasm-build producer configuration is invalid: {name}")
        families, tools, indicators = value["families"], value["tools"], value["indicators"]
        if (not isinstance(families, list) or not families or
                any(item not in {"native", "rust", "node", "wasm"} for item in families) or
                not isinstance(tools, list) or not tools or
                any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.+\-]+", item) for item in tools) or
                not isinstance(indicators, list) or
                any(not isinstance(item, str) or not item or len(item) > 256 for item in indicators)):
            raise ValueError(f"wasm-build producer configuration is invalid: {name}")
        result[name] = {"families": tuple(families), "tools": tuple(tools),
                        "indicators": tuple(indicators)}
    return result


def _select_producer(dispatch: Mapping[str, Any], rules: Mapping[str, Mapping[str, Any]]) -> str | None:
    recipe = dispatch["recipe"]
    commands = [*recipe["configure_commands"], *recipe["build_commands"]]
    tools = {PurePosixPath(str(argv[0])).name for argv in commands if argv}
    searchable = "\n".join(str(value).lower() for argv in commands for value in argv)
    searchable += "\n" + "\n".join(str(value).lower() for value in recipe.get("expected_outputs", ()))
    wasm_intent = (".wasm" in searchable or "wasm32" in searchable or
                   any(tool in {"emcc", "em++", "asc", "wasm-ld", "wasm-pack", "wasm-bindgen"}
                       for tool in tools))
    if not wasm_intent:
        return None
    for name, rule in rules.items():
        if dispatch["family"] not in rule["families"] or not (tools & set(rule["tools"])):
            continue
        if rule["indicators"] and not any(value.lower() in searchable for value in rule["indicators"]):
            continue
        return name
    return None


def _copy_source(unit: UnitContext, dispatch: Mapping[str, Any], workspace: Path) -> None:
    target = (unit.job.target_root or Path()).resolve(strict=True)
    source = (target / Path(*PurePosixPath(str(dispatch["root"])).parts)).resolve(strict=True)
    if target != source and target not in source.parents:
        raise ValueError("wasm build source escaped the accepted target")
    if workspace.exists():
        shutil.rmtree(workspace)
    destination = workspace if dispatch["root"] == "." else workspace / Path(*PurePosixPath(str(dispatch["root"])).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if any(path.is_symlink() for path in source.rglob("*")):
        raise ValueError("wasm build source contains an unsupported symlink")
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns(".git", ".hg", ".svn", "build", "target"))
    try:
        workspace.chmod(0o777)
        for path in workspace.rglob("*"):
            path.chmod(0o777 if path.is_dir() else 0o666)
    except OSError:
        pass


def _kind(path: Path) -> str | None:
    suffix, name = path.suffix.lower(), path.name.lower()
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return None
    if magic == _WASM_MAGIC:
        return "wasm-component" if ".component." in name or name.endswith(".component.wasm") else "wasm-module"
    if suffix == ".wat": return "wasm-text"
    if suffix in {".wit", ".wai"} or name in {"wit-bindgen.json", "component-type.json"}: return "interface-metadata"
    if suffix in {".map", ".dwarf", ".debug", ".dwo", ".pdb"}: return "debug-metadata"
    if suffix in {".js", ".mjs", ".cjs", ".ts"} or name.endswith(".d.ts"): return "binding"
    if suffix in {".a", ".lib"}: return "static-library"
    if suffix in {".so", ".dll", ".dylib"}: return "native-side-module"
    if suffix in {".o", ".obj", ".bc", ".ll"}: return "intermediate"
    if suffix in {".tgz", ".whl", ".crate", ".zip"}: return "package"
    if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs"}: return "generated-source"
    return None


def _catalog(run_root: Path, workspace: Path, before: Mapping[str, str], limit: int,
             build_unit_id: str) -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    gaps: list[str] = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative, digest = path.relative_to(workspace).as_posix(), file_sha256(path)
        kind = _kind(path)
        if kind is None or before.get(relative) == digest:
            continue
        artifacts.append({"path": path.relative_to(run_root).as_posix(), "workspace_path": relative,
                          "sha256": digest, "size_bytes": path.stat().st_size, "kind": kind,
                          "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
                          "mapping_confidence": 1.0})
        if len(artifacts) >= limit:
            gaps.append("artifact catalog truncated at configured count bound")
            break
    return artifacts, gaps


def _stream_identity(path: Path, result: Any, name: str, limit: int, run_root: Path) -> dict[str, Any]:
    data = getattr(result, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    truncated = bool(getattr(result, f"{name}_truncated", False))
    total = getattr(result, f"{name}_bytes", None)
    total = len(data) if total is None else int(total)
    value = {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
             "retained_bytes": path.stat().st_size, "observed_bytes": total,
             "capture_limit_bytes": limit, "truncated": truncated}
    tail = getattr(result, f"{name}_tail", b"")
    if truncated and tail:
        tail_path = path.with_name(path.name + ".tail")
        tail_path.write_bytes(tail)
        value["diagnostic_tail"] = {"path": tail_path.relative_to(run_root).as_posix(),
                                    "sha256": file_sha256(tail_path), "bytes": len(tail)}
    return value


def _capture_argv(recipe: Mapping[str, Any], raw: list[str]) -> tuple[str, ...]:
    argv = list(_normalized_argv(recipe, raw))
    tool = Path(argv[0]).name
    if tool == "cargo" and "build" in argv and not any(value in {"-v", "-vv", "--verbose"} for value in argv):
        argv.append("-vv")
    elif tool == "cmake" and "--build" in argv and "--verbose" not in argv:
        argv.append("--verbose")
    elif tool in {"make", "gmake"} and not any(value.startswith("V=") for value in argv):
        argv.append("V=1")
    elif tool == "ninja" and "-v" not in argv:
        argv.append("-v")
    return tuple(argv)


def _observed_invocations(workspace: Path, working_directory: str, result: Any,
                          command_id: str, limit: int = 20000) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    data = result.stdout + b"\n" + result.stderr
    for line in data.decode("utf-8", "replace").splitlines():
        value = line.strip()
        if value.startswith("Running `") and value.endswith("`"):
            value = value[len("Running `"):-1]
        try:
            tokens = shlex.split(value)
        except ValueError:
            continue
        start = next((index for index, token in enumerate(tokens)
                      if Path(token).name in _OBSERVED_TOOLS), None)
        if start is None:
            continue
        argv = tokens[start:]
        tool = Path(argv[0]).name
        inputs = [item for item in argv[1:] if item.endswith(
            (".c", ".cc", ".cpp", ".cxx", ".rs", ".o", ".obj", ".a", ".lib", ".bc", ".wasm"))]
        outputs = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item in {"-o", "--output"}]
        rows.append({"ordinal": len(rows) + 1, "parent_command_id": command_id,
            "tool": tool, "tool_kind": _TOOL_KINDS.get(tool, "build-tool"), "argv": argv,
            "working_directory": working_directory,
            "inputs": _mapped_files(workspace, working_directory, inputs),
            "outputs": _mapped_files(workspace, working_directory, outputs),
            "mapping": "verbose-build-stream", "mapping_confidence": 1.0})
        if len(rows) >= limit:
            break
    return rows


def _fingerprint(dispatch: Mapping[str, Any], accepted: Mapping[str, Any], producer: str,
                 upstream: Mapping[str, str], settings: Mapping[str, Any]) -> str:
    image = dispatch["image"]
    return hashlib.sha256(canonical_json({
        "schema": RECEIPT_SCHEMA, "target": dispatch["source_fingerprint"],
        "recipe": dispatch["recipe_identity"], "dependencies": image["dependency_hashes"],
        "build_dependencies": dict(sorted(upstream.items())), "image": image["image_id"],
        "toolchain": {"source_family": dispatch["family"], "producer": producer,
                      "image_id": image["image_id"]},
        "executor": EXECUTOR_IDENTITY, "capture": CAPTURE_IDENTITY,
        "capture_limit": settings["stream_limit_bytes"], "artifact_limit": settings["artifact_count_limit"],
        "probe": dispatch["probe_identity"], "upstream_handoff": accepted["project_build_handoff_sha256"],
    })).hexdigest()


def _execute_one(unit: UnitContext, dispatch: Mapping[str, Any], accepted: Mapping[str, Any], producer: str,
                 upstream: Mapping[str, str], executor_factory=None) -> dict[str, Any]:
    build_unit_id, recipe, image = str(dispatch["build_unit_id"]), dispatch["recipe"], dispatch["image"]
    settings = _runtime_settings(unit)
    fingerprint = _fingerprint(dispatch, accepted, producer, upstream, settings)
    root = unit.job.run_root / "data" / "build" / "wasm" / "units" / build_unit_id
    workspace = root / "workspace"
    cache = unit.job.metadata_root / "wasm-builds" / fingerprint / "accepted.json"
    with FileLock(cache.parent / "build.lock"):
        if cache.is_file():
            prior = json.loads(cache.read_text(encoding="utf-8"))
            if prior.get("fingerprint") != fingerprint or prior.get("terminal_status") != "SUCCEEDED":
                raise WasmIntegrityError("wasm-build checkpoint identity is invalid")
            prior_workspace = Path(str(prior.get("workspace", "")))
            if not prior_workspace.is_dir() or prior_workspace.is_symlink():
                raise WasmIntegrityError("wasm-build checkpoint workspace is unavailable")
            if prior_workspace.resolve() != workspace.resolve():
                if root.exists(): shutil.rmtree(root)
                shutil.copytree(prior_workspace.parent, root)
            receipt = dict(prior["receipt"])
            identities = [*receipt.get("artifacts", ()), receipt.get("workspace_manifest", {}),
                          receipt.get("protected_tool_invocations", {})]
            for command in receipt.get("commands", ()):
                identities.extend([command.get("stdout", {}), command.get("stderr", {}),
                                   command.get("protected_argv", {})])
                for stream in (command.get("stdout", {}), command.get("stderr", {})):
                    if isinstance(stream, Mapping) and isinstance(stream.get("diagnostic_tail"), Mapping):
                        identities.append(stream["diagnostic_tail"])
            for identity in identities:
                path = unit.job.run_root / str(identity.get("path", ""))
                if not path.is_file() or path.is_symlink() or file_sha256(path) != identity.get("sha256"):
                    raise WasmIntegrityError("wasm-build checkpoint artifact identity changed")
            return {**receipt, "workspace": workspace.relative_to(unit.job.run_root).as_posix(),
                    "checkpoint_reused": True, "completed_at": datetime.now(timezone.utc).isoformat()}

    _copy_source(unit, dispatch, workspace)
    before = _snapshot(workspace, int(settings["workspace_file_limit"]))
    profile = BuildProfile(str(dispatch["family"]), str(image["image_tag"]),
                           str(image["image_id"]), str(image["user"]))
    executor = executor_factory(unit, profile) if executor_factory else BuildContainerExecutor(
        profile, timeout_seconds=int(settings["command_timeout_seconds"]),
        output_bytes=int(settings["stream_limit_bytes"]))
    try:
        executor.resolve()
    except RuntimeError as exc:
        raise ProducerUnavailable(str(exc)) from exc
    protected = root / "protected-commands"
    protected.mkdir(parents=True, exist_ok=True)
    commands: list[dict[str, Any]] = []
    gaps: list[str] = []
    started_at, started = datetime.now(timezone.utc).isoformat(), time.monotonic()
    operational_recipe = {**recipe, "build_system": dispatch.get("build_system")}
    environment = _probe_environment(operational_recipe)
    raw_commands = [*recipe["configure_commands"], *recipe["build_commands"]]
    for ordinal, raw in enumerate(raw_commands, 1):
        argv = _capture_argv(recipe, raw)
        command_id = hashlib.sha256(canonical_json({"attempt": unit.job.attempt_id,
            "unit": build_unit_id, "ordinal": ordinal, "argv": list(argv)})).hexdigest()
        command_started_at, command_started = datetime.now(timezone.utc).isoformat(), time.monotonic()
        try:
            result = executor.execute(argv, workspace=workspace, working_directory=str(recipe["source_dir"]),
                                      environment=environment)
        except (RuntimeError, OSError) as exc:
            raise ProducerUnavailable(str(exc)) from exc
        exact = protected / f"{command_id}.json"
        protected_command = {"schema": "appsec-review/protected-build-command/2",
            "argv": list(result.argv), "working_directory": str(recipe["source_dir"]),
            "environment": dict(environment), "access": "run-owned-protected"}
        protected_json(exact, protected_command)
        try: exact.chmod(0o600)
        except OSError: pass
        logs = root / "logs"
        limit = int(settings["stream_limit_bytes"])
        stdout = _stream_identity(logs / f"{ordinal:03d}.stdout", result, "stdout", limit, unit.job.run_root)
        stderr = _stream_identity(logs / f"{ordinal:03d}.stderr", result, "stderr", limit, unit.job.run_root)
        failed = result.timed_out or result.exit_code != 0
        commands.append({"command_id": command_id, "attempt_id": unit.job.attempt_id,
            "build_attempt_id": f"{build_unit_id}:{unit.job.attempt_id}", "ordinal": ordinal,
            "tool": Path(argv[0]).name, "tool_kind": _TOOL_KINDS.get(Path(argv[0]).name, "build-driver"),
            "argv_sha256": hashlib.sha256(canonical_json(list(result.argv))).hexdigest(),
            "working_directory": str(recipe["source_dir"]),
            "environment_facts": {key: "set" for key in sorted(environment) if not _SECRET_KEY.search(key)},
            "started_at": command_started_at, "duration_ms": int((time.monotonic()-command_started)*1000),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "stdout": stdout, "stderr": stderr,
            "protected_argv": {"path": exact.relative_to(unit.job.run_root).as_posix(),
                               "sha256": file_sha256(exact), "size_bytes": exact.stat().st_size},
            "image_id": image["image_id"], "build_unit_id": build_unit_id})
        unit.job.events.write("WASM_BUILD_COMMAND_COMPLETED", unit_id=unit.unit_id,
            build_unit_id=build_unit_id, command_id=command_id, tool=Path(argv[0]).name,
            disposition="FAILED" if failed else "SUCCEEDED", result_count=0,
            gap_count=1 if failed else 0, truncated=stdout["truncated"] or stderr["truncated"],
            duration_ms=commands[-1]["duration_ms"])
        if failed:
            gaps.append(f"build command {ordinal} {'timed out' if result.timed_out else f'exited {result.exit_code}'}")
            break
    if source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint:
        raise ValueError("target changed during wasm output-family execution")
    artifacts, catalog_gaps = _catalog(unit.job.run_root, workspace, before,
        int(settings["artifact_count_limit"]), build_unit_id)
    gaps.extend(catalog_gaps)
    if not any(item["kind"] in {"wasm-module", "wasm-component"} for item in artifacts) and not gaps:
        gaps.append("accepted WebAssembly recipe produced no retained wasm module or component")
    observed = [row for command in commands for row in _observed_invocations(
        workspace, str(recipe["source_dir"]), type("Streams", (), {
            "stdout": (unit.job.run_root / command["stdout"]["path"]).read_bytes(),
            "stderr": (unit.job.run_root / command["stderr"]["path"]).read_bytes(),
        })(), command["command_id"])]
    observed_path = protected / f"observed-tool-invocations-{unit.job.attempt_id}.json"
    protected_json(observed_path,
        {"schema": "appsec-review/protected-tool-invocations/1", "rows": observed})
    try: observed_path.chmod(0o600)
    except OSError: pass
    sanitized_observed = [{key: value for key, value in row.items() if key != "argv"} |
                          {"argv_sha256": hashlib.sha256(canonical_json(row["argv"])).hexdigest()}
                          for row in observed]
    if artifacts and not any(row["tool_kind"] in {"compiler", "compiler-driver", "transpiler", "linker",
                                                   "archiver", "post-link", "binding-generator"}
                             for row in [*commands, *sanitized_observed]):
        gaps.append("nested compiler/linker provenance was not emitted by the accepted producer")
    manifest_path = root / "workspace-manifest.json"
    manifest = {"schema": "appsec-review/build-workspace-manifest/1", "build_unit_id": build_unit_id,
                "files": _snapshot(workspace, int(settings["workspace_file_limit"]))}
    atomic_json(manifest_path, manifest)
    status = "FAILED" if any(gap.startswith("build command") for gap in gaps) else "SUCCEEDED"
    relationships = []
    for command in commands:
        output_candidates = [item for item in artifacts if item["kind"] in {"wasm-module", "wasm-component"}]
        relationships.extend({"kind": "PRODUCED_BY", "artifact_sha256": item["sha256"],
                              "command_id": command["command_id"], "confidence": 0.5,
                              "mapping": "bounded-build-attribution"} for item in output_candidates)
    receipt = {"schema": RECEIPT_SCHEMA, "fingerprint": fingerprint,
        "source_fingerprint": unit.job.source_fingerprint,
        "upstream_handoff_sha256": accepted["project_build_handoff_sha256"],
        "upstream_build_fingerprints": dict(sorted(upstream.items())), "build_unit_id": build_unit_id,
        "source_family": dispatch["family"], "producer": producer, "root": dispatch["root"],
        "build_system": dispatch.get("build_system"), "recipe_identity": dispatch["recipe_identity"],
        "probe_identity": dispatch["probe_identity"], "image": image,
        "workspace": workspace.relative_to(unit.job.run_root).as_posix(), "commands": commands,
        "tool_invocations": [{key: value for key, value in command.items()
                              if key not in {"stdout", "stderr", "protected_argv"}}
                             for command in commands] + sanitized_observed,
        "protected_tool_invocations": {"path": observed_path.relative_to(unit.job.run_root).as_posix(),
                                       "sha256": file_sha256(observed_path),
                                       "size_bytes": observed_path.stat().st_size},
        "artifacts": artifacts, "relationships": relationships,
        "workspace_manifest": {"path": manifest_path.relative_to(unit.job.run_root).as_posix(),
                               "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size},
        "gaps": list(dict.fromkeys(gaps)), "terminal_status": status, "checkpoint_reused": False,
        "started_at": started_at, "completed_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": int((time.monotonic()-started)*1000),
        "executor_identity": EXECUTOR_IDENTITY, "capture_identity": CAPTURE_IDENTITY}
    if status == "SUCCEEDED":
        cache.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(cache.parent / "build.lock"):
            atomic_json(cache, {"schema": "appsec-review/wasm-build-checkpoint/1",
                "fingerprint": fingerprint, "terminal_status": status,
                "workspace": str(workspace), "receipt": receipt})
    return receipt
