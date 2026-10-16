from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import threading
from typing import Any

import appsec_review.applicability as applicability_contract
from appsec_review.applicability import (
    ApplicabilityAction, ProcessingDisposition, decision_from_mapping, finalize_processing,
    resolved_configuration_identity,
)
from appsec_review.codeql import CodeQLExecutor, CodeQLImageResolver, load_sarif, tree_manifest
from appsec_review.codeql.runtime import (
    EXPORT_MANIFEST_NAME, EXPORT_MANIFEST_SCHEMA, GraphExportIntegrityError, compile_cache_volume,
    graph_compile_arguments, graph_export_arguments, load_asset_lock,
    load_graph_exports,
)
from appsec_review.config import CodeQLAnalysisSettings, CodeQLExportSettings
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_evidence_collection.job import load_target_catalog
from appsec_review.jobs.job_language_build import load_accepted_language_build
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.retrieval.core import resolve_context_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, canonical_json, file_sha256

from .planning import (
    CodeQLPlan, CodeQLScope, build_codeql_plan, export_lock_mismatches, plan_graph_exports,
    replay_commands,
)
from appsec_review import seeding
from .sarif import NORMALIZER_IDENTITY, normalize_sarif
from appsec_review.jobs.job_codeql_analysis.datasets import CONSUMES, DATASETS


SCHEMA = "appsec-review/codeql-analysis-handoff/1"
DATABASE_CHECKPOINT_SCHEMA = "appsec-review/codeql-database-checkpoint/3"
QUERY_CHECKPOINT_SCHEMA = "appsec-review/codeql-query-checkpoint/2"
EXPORT_CHECKPOINT_SCHEMA = "appsec-review/codeql-export-checkpoint/1"
GRAPH_EXPORTS_SCHEMA = "appsec-review/codeql-graph-exports/1"
_RUNNER = ("containers", "tools", "codeql", "codeql_runner.py")
_ASSET_LOCK = ("containers", "tools", "codeql", "assets.lock.json")
SCOPE_FILE, SEEDS_FILE = "scope.csv", "seeds.csv"


class FrameworkIntegrityError(ValueError):
    """A changed accepted identity or run-owned CodeQL artifact; publication must stop."""


def _settings(unit: UnitContext) -> CodeQLAnalysisSettings:
    value = unit.job.config.typed_settings
    if not isinstance(value, CodeQLAnalysisSettings):
        raise ValueError("typed CodeQL analysis settings are required")
    return value


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if run_root.resolve() not in resolved.parents or resolved.is_symlink():
        raise FrameworkIntegrityError("CodeQL artifact escaped the run")
    return {"path": resolved.relative_to(run_root.resolve()).as_posix(),
            "sha256": file_sha256(resolved), "size_bytes": resolved.stat().st_size}


def _json_artifact(run_root: Path, path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    atomic_json(path, dict(value))
    return _artifact(run_root, path)


def _safe_json(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise FrameworkIntegrityError("CodeQL input artifact is unavailable or escaped the run")
    if file_sha256(path) != identity.get("sha256"):
        raise FrameworkIntegrityError("CodeQL input artifact identity changed")
    return json.loads(path.read_text(encoding="utf-8"))


def _accepted_handoff_identity(run_root: Path, job_id: str) -> Mapping[str, str]:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        raise FrameworkIntegrityError(f"accepted {job_id} handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    identity = {"path": str(pointer.get("handoff_path", "")),
                "sha256": str(pointer.get("handoff_sha256", ""))}
    handoff = _safe_json(run_root, identity)
    if (handoff.get("schema") != "appsec-review/job-handoff/1" or
            handoff.get("status") != "ACCEPTED" or handoff.get("job_id") != job_id):
        raise FrameworkIntegrityError(f"{job_id} handoff is not accepted")
    return identity


def _optional_accepted_handoff_identity(run_root: Path, job_id: str) -> Mapping[str, str] | None:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.exists():
        return None
    return _accepted_handoff_identity(run_root, job_id)


def _accepted_index_manifests(run_root: Path, identity: Mapping[str, str]) -> tuple[Mapping[str, str], ...]:
    handoff = _safe_json(run_root, identity)
    values: list[Mapping[str, str]] = []
    for output in handoff.get("outputs", {}).values():
        manifest = output.get("index_manifest") if isinstance(output, Mapping) else None
        if not isinstance(manifest, Mapping):
            continue
        normalized = {"path": str(manifest.get("path", "")),
                      "sha256": str(manifest.get("sha256", ""))}
        path = (run_root / normalized["path"]).resolve()
        if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
            raise FrameworkIntegrityError("accepted upstream index manifest escaped the run")
        load_verified_manifest(run_root, path, normalized["sha256"])
        values.append(normalized)
    return tuple(values)


def _scope_from(value: Mapping[str, Any]) -> CodeQLScope:
    return CodeQLScope(**{**value, "source_languages": tuple(value["source_languages"]),
                          "files": tuple(value["files"])})


def _plan_from(unit: UnitContext) -> CodeQLPlan:
    value = _safe_json(unit.job.run_root, unit.output("plan.inventory")["plan"])
    return CodeQLPlan(value["schema"], value["source_fingerprint"],
                      tuple(value["extractor_inventory"]),
                      tuple(_scope_from(item) for item in value["scopes"]),
                      tuple(value.get("gaps", ())), tuple(value.get("non_applicable", ())),
                      tuple(value.get("decisions", ())))


def _receipt_map(unit: UnitContext) -> Mapping[str, Mapping[str, Any]]:
    accepted = load_accepted_language_build(unit.job.run_root)
    if accepted.get("source_fingerprint") != unit.job.source_fingerprint:
        raise FrameworkIntegrityError("CodeQL language-build snapshot identity changed")
    values = {str(item.get("build_unit_id")): item for item in accepted.get("receipts", ())}
    if len(values) != len(accepted.get("receipts", ())):
        raise FrameworkIntegrityError("CodeQL language-build handoff contains duplicate units")
    return values


def _accepted_replay(unit: UnitContext, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    recipe, image = receipt.get("recipe"), receipt.get("image")
    if not isinstance(recipe, Mapping) or not isinstance(image, Mapping):
        raise FrameworkIntegrityError("accepted CodeQL build recipe or image is unavailable")
    accepted = replay_commands(receipt)
    if accepted is None:
        raise FrameworkIntegrityError("accepted CodeQL build command set is incomplete")
    commands, protected = [], []
    for ordinal, (command, role) in enumerate(accepted, 1):
        identity = command.get("protected_argv")
        if not isinstance(identity, Mapping):
            raise FrameworkIntegrityError("accepted CodeQL build command lacks protected argv")
        document = _safe_json(unit.job.run_root, identity)
        argv, environment = document.get("argv"), document.get("environment")
        if (document.get("schema") != "appsec-review/protected-build-command/2" or
                not isinstance(argv, list) or not argv or not isinstance(environment, Mapping)):
            raise FrameworkIntegrityError("accepted CodeQL protected build command is invalid")
        argv_sha = hashlib.sha256(canonical_json(argv)).hexdigest()
        if (argv_sha != command.get("argv_sha256") or
                document.get("working_directory") != command.get("working_directory") or
                command.get("image_id") != image.get("image_id")):
            raise FrameworkIntegrityError("accepted CodeQL build command identity mismatch")
        commands.append({"ordinal": ordinal, "argv": argv, "argv_sha256": argv_sha,
                         "working_directory": document["working_directory"],
                         "environment": dict(environment), "role": role})
        protected.append({"path": identity["path"], "sha256": identity["sha256"],
                          "argv_sha256": argv_sha})
    return {"schema": "appsec-review/codeql-build-replay/1", "commands": commands,
            "recipe_identity": receipt["recipe_identity"], "build_image_id": image["image_id"],
            "dependency_hashes": dict(image.get("dependency_hashes", {})),
            "protected_commands": protected}


def _verify_scope_sources(unit: UnitContext, scope: CodeQLScope) -> None:
    target = (unit.job.target_root or Path()).resolve(strict=True)
    for record in scope.files:
        logical = PurePosixPath(str(record["path"]))
        if logical.is_absolute() or ".." in logical.parts:
            raise FrameworkIntegrityError("CodeQL source mapping is invalid")
        source = (target / Path(*logical.parts)).resolve(strict=True)
        if target not in source.parents or not source.is_file() or source.is_symlink():
            raise FrameworkIntegrityError("CodeQL accepted source escaped the target")
        if file_sha256(source) != record["sha256"]:
            raise FrameworkIntegrityError("CodeQL accepted source identity changed")


def _copy_clean_target(unit: UnitContext, workspace: Path) -> None:
    target = (unit.job.target_root or Path()).resolve(strict=True)
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    for path in sorted(target.rglob("*")):
        relative = path.relative_to(target)
        if any(part in {".git", ".hg", ".svn", "build", "dist", "target", "bin", "obj",
                        "__pycache__", ".pytest_cache"} for part in relative.parts):
            continue
        if path.is_symlink():
            raise FrameworkIntegrityError("CodeQL target contains an unsupported symlink")
        if path.is_file():
            destination = workspace / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)


def _make_workspace_accessible(workspace: Path, *, writable_files: bool = False) -> None:
    # Dagster and the analysis container deliberately use different users. Source inputs stay
    # immutable; directories must allow the isolated user to create traced build outputs.
    for path in sorted(workspace.rglob("*")):
        if path.is_dir():
            path.chmod(0o777)
        elif path.is_file():
            if writable_files:
                path.chmod(0o666)
            else:
                executable = bool(path.stat().st_mode & 0o111)
                path.chmod(0o555 if executable else 0o444)
    workspace.chmod(0o777)


def _verify_workspace_scope(workspace: Path, scope: CodeQLScope) -> None:
    for record in scope.files:
        candidate = (workspace / Path(*PurePosixPath(str(record["path"])).parts)).resolve()
        if workspace.resolve() not in candidate.parents or not candidate.is_file() or candidate.is_symlink():
            raise FrameworkIntegrityError("CodeQL materialized scope is missing accepted source")
        if file_sha256(candidate) != record["sha256"]:
            raise FrameworkIntegrityError("CodeQL materialized scope source identity changed")


def _workspace_manifest_files(workspace: Path, manifest: Mapping[str, Any], *, file_limit: int,
                              allow_manifest_backed_symlinks: bool = False) -> dict[str, str]:
    expected = manifest.get("files")
    if (manifest.get("schema") != "appsec-review/build-workspace-manifest/1" or
            not isinstance(expected, Mapping) or len(expected) > file_limit):
        raise FrameworkIntegrityError("CodeQL materialized environment manifest is invalid")
    expected_files = {str(path): str(digest) for path, digest in expected.items()}
    workspace_root = workspace.resolve(strict=True)
    actual: dict[str, str] = {}
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            if not allow_manifest_backed_symlinks:
                raise FrameworkIntegrityError("CodeQL materialized environment contains a symlink")
            try:
                link_target = path.readlink()
            except (OSError, RuntimeError) as exc:
                raise FrameworkIntegrityError(
                    "CodeQL materialized environment contains an invalid symlink") from exc
            relative = path.relative_to(workspace).as_posix()
            container_dependency = (
                path.name == "node_modules" and
                relative not in expected_files and
                PurePosixPath(link_target.as_posix()) == PurePosixPath("/opt/project") / relative
            )
            if container_dependency:
                continue
            if link_target.is_absolute():
                raise FrameworkIntegrityError(
                    "CodeQL materialized environment contains an unsafe symlink")
            try:
                resolved = path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise FrameworkIntegrityError(
                    "CodeQL materialized environment contains an invalid symlink") from exc
            if (workspace_root not in resolved.parents or
                    not resolved.is_file() or resolved.is_symlink()):
                raise FrameworkIntegrityError(
                    "CodeQL materialized environment contains an unsafe symlink")
            resolved_relative = resolved.relative_to(workspace_root).as_posix()
            if expected_files.get(resolved_relative) != file_sha256(resolved):
                raise FrameworkIntegrityError(
                    "CodeQL materialized environment contains an unpinned symlink")
            continue
        if not path.is_file():
            continue
        if len(actual) >= file_limit:
            raise FrameworkIntegrityError("CodeQL materialized environment exceeds its file bound")
        actual[path.relative_to(workspace).as_posix()] = file_sha256(path)
    if actual != expected_files:
        raise FrameworkIntegrityError("CodeQL materialized environment identity changed")
    return expected_files


def _verify_workspace_manifest(workspace: Path, manifest: Mapping[str, Any], *, file_limit: int) -> None:
    _workspace_manifest_files(workspace, manifest, file_limit=file_limit)


def _stage_manifest_workspace(source: Path, workspace: Path, manifest: Mapping[str, Any],
                              *, file_limit: int) -> None:
    expected = _workspace_manifest_files(
        source, manifest, file_limit=file_limit, allow_manifest_backed_symlinks=True)
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    source_root = source.resolve(strict=True)
    for relative, digest in sorted(expected.items()):
        logical = PurePosixPath(relative)
        if (logical.is_absolute() or logical.as_posix() != relative or ".." in logical.parts or
                any("\\" in part for part in logical.parts)):
            raise FrameworkIntegrityError("CodeQL materialized environment manifest is invalid")
        source_path = source / Path(*logical.parts)
        current = source
        for part in logical.parts:
            current /= part
            if current.is_symlink():
                raise FrameworkIntegrityError(
                    "CodeQL materialized environment manifest traverses a symlink")
        resolved = source_path.resolve(strict=True)
        if (source_root not in resolved.parents or not source_path.is_file() or
                file_sha256(source_path) != digest):
            raise FrameworkIntegrityError("CodeQL materialized environment identity changed")
        destination = workspace / Path(*logical.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)
    _verify_workspace_manifest(workspace, manifest, file_limit=file_limit)


def _stage_workspace(unit: UnitContext, scope: CodeQLScope,
                     receipt: Mapping[str, Any] | None, workspace: Path) -> None:
    _verify_scope_sources(unit, scope)
    if scope.language == "actions" or scope.mode == "manual" or receipt is None:
        _copy_clean_target(unit, workspace)
    else:
        if receipt is None:
            raise FrameworkIntegrityError("CodeQL source scope lacks an accepted environment")
        identity = receipt.get("workspace_manifest")
        workspace_value = receipt.get("workspace")
        if not isinstance(identity, Mapping) or not isinstance(workspace_value, str):
            raise FrameworkIntegrityError("CodeQL materialized environment identity is unavailable")
        manifest = _safe_json(unit.job.run_root, identity)
        source = (unit.job.run_root / workspace_value).resolve(strict=True)
        if unit.job.run_root.resolve() not in source.parents or not source.is_dir() or source.is_symlink():
            raise FrameworkIntegrityError("CodeQL materialized environment escaped the run")
        _stage_manifest_workspace(
            source, workspace, manifest, file_limit=_settings(unit).database_file_limit)
    _verify_workspace_scope(workspace, scope)
    _make_workspace_accessible(workspace)


def _checkpoint(path: Path, identity: str, schema: str) -> Mapping[str, Any] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != schema or value.get("identity") != identity:
        return None
    if value.get("terminal_status") != "SUCCEEDED":
        return None
    return value


def _database_identity(unit: UnitContext, scope: CodeQLScope, *, image_identity: str,
                       replay: Mapping[str, Any] | None, settings: CodeQLAnalysisSettings,
                       asset_lock: Mapping[str, Any]) -> str:
    language = settings.languages[scope.language]
    return hashlib.sha256(canonical_json({
        "schema": DATABASE_CHECKPOINT_SCHEMA,
        "scope": asdict(scope), "mode": scope.mode,
        "configured_execution_mode": language.mode.value,
        "environment_identity": scope.environment_identity,
        "replay": replay, "codeql_image_identity": image_identity, "version": settings.version,
        "cli_sha256": settings.cli_sha256, "extractor_tree_sha256": language.extractor_tree_sha256,
        "runner_schema": "codeql-runner/2", "database_producer": "codeql-database/3",
        "limits": {"file_limit": settings.database_file_limit,
                   "bytes_limit": settings.database_bytes_limit,
                   "threads": settings.threads, "ram_mb": settings.ram_mb},
    })).hexdigest()


def _query_profiles(language: Any) -> tuple[Mapping[str, Any], ...]:
    default = {
        "query_id": "default", "kind": "default", "root": None,
        "query_pack": language.query_pack, "query_pack_version": language.query_pack_version,
        "query_suite": language.query_suite, "query_suite_sha256": language.query_suite_sha256,
        "query_pack_sha256": language.query_pack_sha256,
        "query_lock_sha256": language.query_lock_sha256,
        "tree_sha256": None, "file_count": None,
    }
    additional = tuple({**default, **asdict(value), "kind": "pack"}
                       for value in language.additional_queries)
    custom = tuple({**asdict(value), "kind": "custom"} for value in language.custom_queries)
    return (default, *additional, *custom)


def _query_identity(database: Mapping[str, Any], query_profile: Mapping[str, Any],
                    settings: CodeQLAnalysisSettings) -> str:
    return hashlib.sha256(canonical_json({
        "schema": QUERY_CHECKPOINT_SCHEMA,
        "database_identity": database["database_identity"],
        "database_tree_sha256": database["database_tree_sha256"],
        "query_profile": dict(query_profile),
        "normalizer": NORMALIZER_IDENTITY,
        "limits": {"result_limit": settings.result_limit,
                   "sarif_bytes_limit": settings.sarif_bytes_limit,
                   "max_paths": settings.max_paths, "threads": settings.threads,
                   "ram_mb": settings.ram_mb},
    })).hexdigest()


def _execution_artifact(unit: UnitContext, root: Path, action: str) -> Mapping[str, Any]:
    return _artifact(unit.job.run_root, root / "executions" / action / "receipt.json")


def _metrics_scope(scope: CodeQLScope) -> dict[str, Any]:
    return {"scope_id": scope.scope_id, "project_root": scope.root,
            "language": scope.language, "build_unit_id": scope.build_unit_id}


def _database_one(unit: UnitContext, scope: CodeQLScope,
                  receipts: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
    settings = _settings(unit)
    language = settings.languages[scope.language]
    receipt = receipts.get(scope.build_unit_id or "")
    if scope.build_unit_id and receipt is None:
        raise FrameworkIntegrityError("CodeQL planned build unit disappeared")
    image_value = (receipt.get("image") if receipt is not None else {
        "image_tag": settings.source_image_tag, "image_id": settings.source_image_id,
        "user": settings.runtime_user,
    })
    if not isinstance(image_value, Mapping):
        raise FrameworkIntegrityError("CodeQL environment image identity is unavailable")
    resolver = CodeQLImageResolver(repository_root=unit.job.repository_root,
        metadata_root=unit.job.metadata_root, settings=settings,
        timeout_seconds=settings.database_timeout_seconds, output_bytes=settings.output_bytes)
    image, _stdout, _stderr = resolver.resolve(
        build_image_tag=str(image_value["image_tag"]), build_image_id=str(image_value["image_id"]),
        runtime_user=str(image_value.get("user") or settings.runtime_user))
    root = unit.job.run_root / "data" / "codeql" / "scopes" / scope.scope_id
    root.mkdir(parents=True, exist_ok=True)
    image_artifact = _json_artifact(unit.job.run_root, root / "image.json", asdict(image))
    asset_lock = load_asset_lock(unit.job.repository_root)
    replay = _accepted_replay(unit, receipt) if scope.mode == "manual" and receipt is not None else None
    identity = _database_identity(unit, scope, image_identity=image.identity, replay=replay,
                                  settings=settings, asset_lock=asset_lock)
    checkpoint_path, database_path = root / "database-checkpoint.json", root / "database"
    manifest_path = root / "database-manifest.json"
    existing = _checkpoint(checkpoint_path, identity, DATABASE_CHECKPOINT_SCHEMA)
    if existing is not None:
        unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id, tool_id="codeql",
                              **_metrics_scope(scope),
                              database_identity=identity, image_id=image.image_id,
                              checkpoint_reused=True)
        if not database_path.is_dir() or not manifest_path.is_file():
            raise FrameworkIntegrityError("accepted CodeQL database checkpoint lost its artifacts")
        retained = json.loads(manifest_path.read_text(encoding="utf-8"))
        actual = tree_manifest(database_path, file_limit=settings.database_file_limit,
                               bytes_limit=settings.database_bytes_limit)
        if retained != actual or file_sha256(manifest_path) != existing.get("manifest_sha256"):
            raise FrameworkIntegrityError("accepted CodeQL database or manifest changed")
        unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id, tool_id="codeql",
                              **_metrics_scope(scope),
                              database_identity=identity, image_id=image.image_id,
                              disposition="SUCCEEDED", duration_ms=0, result_count=0, gap_count=0,
                              checkpoint_reused=True, truncated=False,
                              metrics_receipt=_artifact(unit.job.run_root, checkpoint_path))
        return {"scope": asdict(scope), "terminal_status": "SUCCEEDED", "database_identity": identity,
                "database_tree_sha256": actual["tree_sha256"], "database_reused": True,
                "database_manifest": _artifact(unit.job.run_root, manifest_path), "image": image_artifact,
                "gaps": []}
    for path in (database_path, root / "workspace", root / "executions" / "database"):
        if path.is_dir():
            shutil.rmtree(path)
    _stage_workspace(unit, scope, receipt, root / "workspace")
    argv = ["--mode", scope.mode, "--language", scope.language, "--workspace", "workspace",
            "--source-subroot", scope.root,
            "--database", "database", "--threads", str(settings.threads), "--ram", str(settings.ram_mb)]
    if replay is not None:
        atomic_json(root / "protected-replay.json", replay)
        # The runner intentionally uses a distinct non-root uid. The replay contains only the
        # already-accepted command/environment contract, so make that immutable input readable
        # across the hardened host/container ownership boundary.
        (root / "protected-replay.json").chmod(0o444)
        argv[4:4] = ["--replay", "protected-replay.json"]
    executor = CodeQLExecutor(image=image, run_root=unit.job.run_root, settings=settings)
    unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id, tool_id="codeql",
                          **_metrics_scope(scope),
                          database_identity=identity, image_id=image.image_id)
    result = executor.execute("database", tuple(argv), scratch_root=root)
    status = "FAILED" if result.timed_out or result.exit_code != 0 else "SUCCEEDED"
    gaps = (["CodeQL database creation timed out"] if result.timed_out else
            [f"CodeQL database creation exited {result.exit_code}"] if result.exit_code != 0 else [])
    execution = _execution_artifact(unit, root, "database")
    unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id, tool_id="codeql",
                          **_metrics_scope(scope),
                          database_identity=identity, image_id=image.image_id, disposition=status,
                          duration_ms=result.duration_ms, result_count=0, gap_count=len(gaps), gaps=gaps,
                          checkpoint_reused=False, truncated=result.stdout_truncated or result.stderr_truncated,
                          metrics_receipt=execution)
    if status != "SUCCEEDED":
        return {"scope": asdict(scope), "terminal_status": status, "database_identity": identity,
                "database_reused": False, "database_execution": execution,
                "image": image_artifact, "gaps": gaps}
    manifest = tree_manifest(database_path, file_limit=settings.database_file_limit,
                             bytes_limit=settings.database_bytes_limit)
    atomic_json(manifest_path, manifest)
    atomic_json(checkpoint_path, {"schema": DATABASE_CHECKPOINT_SCHEMA, "identity": identity,
                "terminal_status": "SUCCEEDED", "manifest_sha256": file_sha256(manifest_path)})
    return {"scope": asdict(scope), "terminal_status": "SUCCEEDED", "database_identity": identity,
            "database_tree_sha256": manifest["tree_sha256"], "database_reused": False,
            "database_manifest": _artifact(unit.job.run_root, manifest_path),
            "database_execution": execution, "image": image_artifact, "gaps": []}


def _database_isolated(unit: UnitContext, scope: CodeQLScope,
                       receipts: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
    try:
        return _database_one(unit, scope, receipts)
    except (RuntimeError, TimeoutError) as exc:
        gap = f"CodeQL {scope.language} database producer failed ({type(exc).__name__})"
        return {"scope": asdict(scope), "terminal_status": "FAILED", "database_reused": False,
                "database_identity": None, "gaps": [gap]}


def _query_one(unit: UnitContext, database: Mapping[str, Any],
               query_profile: Mapping[str, Any]) -> Mapping[str, Any]:
    if database.get("terminal_status") != "SUCCEEDED":
        return {**database, "query_profile": dict(query_profile),
                "query_reused": False, "query_identity": None,
                "gaps": list(database.get("gaps", ())) + ["CodeQL query skipped because database creation failed"]}
    settings = _settings(unit)
    scope = _scope_from(database["scope"])
    identity = _query_identity(database, query_profile, settings)
    scope_root = unit.job.run_root / "data" / "codeql" / "scopes" / scope.scope_id
    root = scope_root / "queries" / str(query_profile["query_id"])
    root.mkdir(parents=True, exist_ok=True)
    checkpoint_path, sarif_path = root / "query-checkpoint.json", root / "sarif" / "results.sarif"
    existing = _checkpoint(checkpoint_path, identity, QUERY_CHECKPOINT_SCHEMA)
    if existing is not None:
        unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id, tool_id="codeql",
                              **_metrics_scope(scope),
                              database_identity=database["database_identity"], query_identity=identity,
                              query_profile=query_profile["query_id"], query_suite=query_profile["query_suite"],
                              query_pack=query_profile["query_pack"],
                              query_pack_version=query_profile["query_pack_version"],
                              checkpoint_reused=True)
        if not sarif_path.is_file() or sarif_path.is_symlink() or file_sha256(sarif_path) != existing.get("sarif_sha256"):
            raise FrameworkIntegrityError("accepted CodeQL query checkpoint or SARIF changed")
        sarif = load_sarif(sarif_path, bytes_limit=settings.sarif_bytes_limit,
                           result_limit=settings.result_limit)
        result_count = sum(len(run.get("results", ())) for run in sarif["runs"])
        unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id, tool_id="codeql",
                              **_metrics_scope(scope),
                              database_identity=database["database_identity"], query_identity=identity,
                              query_profile=query_profile["query_id"], query_suite=query_profile["query_suite"],
                              query_pack=query_profile["query_pack"],
                              query_pack_version=query_profile["query_pack_version"],
                              disposition="SUCCEEDED", duration_ms=0, result_count=result_count,
                              gap_count=0, checkpoint_reused=True, truncated=False,
                              metrics_receipt=_artifact(unit.job.run_root, checkpoint_path))
        return {**database, "query_profile": dict(query_profile),
                "query_identity": identity, "query_reused": True,
                "sarif": _artifact(unit.job.run_root, sarif_path),
                "sarif_result_count": result_count, "gaps": []}
    query_database = root / "query-database"
    if query_database.exists():
        shutil.rmtree(query_database)
    shutil.copytree(scope_root / "database", query_database)
    _make_workspace_accessible(query_database, writable_files=True)
    if sarif_path.parent.exists():
        shutil.rmtree(sarif_path.parent)
    image_value = _safe_json(unit.job.run_root, database["image"])
    from appsec_review.codeql import CodeQLImage
    image = CodeQLImage(**image_value)
    executor = CodeQLExecutor(image=image, run_root=unit.job.run_root, settings=settings)
    unit.job.events.write("TOOL_INVOCATION_STARTED", unit_id=unit.unit_id, tool_id="codeql",
                          **_metrics_scope(scope),
                          database_identity=database["database_identity"], query_identity=identity,
                          image_id=image.image_id, query_profile=query_profile["query_id"],
                          query_suite=query_profile["query_suite"],
                          query_pack=query_profile["query_pack"],
                          query_pack_version=query_profile["query_pack_version"])
    selection = (["--pack", str(query_profile["query_pack"]),
                  "--pack-version", str(query_profile["query_pack_version"]),
                  "--suite", str(query_profile["query_suite"])]
                 if query_profile["kind"] in {"default", "pack"} else
                 ["--suite-path", f"{str(query_profile['root']).rstrip('/')}/{query_profile['query_suite']}"])
    result = executor.execute("query", (
        "--database", "query-database", "--output", "sarif/results.sarif",
        *selection, "--threads", str(settings.threads), "--ram", str(settings.ram_mb),
        "--max-paths", str(settings.max_paths),
    ), scratch_root=root)
    shutil.rmtree(query_database)
    status = "FAILED" if result.timed_out or result.exit_code != 0 else "SUCCEEDED"
    gaps = (["CodeQL query execution timed out"] if result.timed_out else
            [f"CodeQL query execution exited {result.exit_code}"] if result.exit_code != 0 else [])
    result_count = 0
    if status == "SUCCEEDED":
        try:
            sarif = load_sarif(sarif_path, bytes_limit=settings.sarif_bytes_limit,
                               result_limit=settings.result_limit)
            result_count = sum(len(run.get("results", ())) for run in sarif["runs"])
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            status, gaps = "FAILED", [f"CodeQL query produced invalid bounded SARIF ({type(exc).__name__})"]
    execution = _execution_artifact(unit, root, "query")
    unit.job.events.write("TOOL_INVOCATION_COMPLETED", unit_id=unit.unit_id, tool_id="codeql",
                          **_metrics_scope(scope),
                          database_identity=database["database_identity"], query_identity=identity,
                          image_id=image.image_id, query_profile=query_profile["query_id"],
                          query_suite=query_profile["query_suite"],
                          query_pack=query_profile["query_pack"],
                          query_pack_version=query_profile["query_pack_version"], disposition=status,
                          duration_ms=result.duration_ms, result_count=result_count,
                          gap_count=len(gaps), gaps=gaps,
                          checkpoint_reused=False, truncated=result.stdout_truncated or result.stderr_truncated,
                          metrics_receipt=execution)
    value = {**database, "terminal_status": status, "query_profile": dict(query_profile),
             "query_identity": identity,
             "query_reused": False, "query_execution": execution,
             "sarif_result_count": result_count, "gaps": gaps}
    if status == "SUCCEEDED":
        atomic_json(checkpoint_path, {"schema": QUERY_CHECKPOINT_SCHEMA, "identity": identity,
                    "terminal_status": "SUCCEEDED", "sarif_sha256": file_sha256(sarif_path)})
        value["sarif"] = _artifact(unit.job.run_root, sarif_path)
    return value


def _export_profile(settings: CodeQLAnalysisSettings, language: str) -> Mapping[str, Any] | None:
    """The configured, lock-equal graph export pack of one language, or ``None``."""
    configured = settings.languages.get(language)
    if not settings.export_queries.enabled or configured is None or not configured.export_queries:
        return None
    return asdict(configured.export_queries[0])


def _pack_tree(root: Path) -> tuple[str, int]:
    """Location-independent pack identity; the same algorithm the runner checks in scratch."""
    rows = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise FrameworkIntegrityError("CodeQL graph export pack contains a symlink")
        if path.is_file():
            rows.append(f"{file_sha256(path)}  {path.relative_to(root).as_posix()}\n".encode())
    return hashlib.sha256(b"".join(rows)).hexdigest(), len(rows)


def _verify_export_sources(repository_root: Path, profile: Mapping[str, Any],
                           settings: CodeQLAnalysisSettings) -> None:
    """The repository pack, contracts and lock must still equal the configured lock entry."""
    lock = repository_root.joinpath(*_ASSET_LOCK)
    if not lock.is_file() or lock.is_symlink() or file_sha256(lock) != settings.asset_lock_sha256:
        raise FrameworkIntegrityError("CodeQL asset lock differs from central configuration")
    pack = repository_root / str(profile["source_path"])
    if (not pack.is_dir() or pack.is_symlink() or
            _pack_tree(pack) != (profile["tree_sha256"], profile["file_count"])):
        raise FrameworkIntegrityError("CodeQL graph export pack differs from its locked tree")
    for path, digest in ((pack / "qlpack.yml", profile["query_pack_sha256"]),
                         (pack / str(profile["query_suite"]), profile["query_suite_sha256"]),
                         (repository_root / str(profile["columns_path"]), profile["columns_sha256"]),
                         (repository_root / str(profile["catalog_path"]), profile["catalog_sha256"])):
        if not path.is_file() or path.is_symlink() or file_sha256(path) != digest:
            raise FrameworkIntegrityError(f"CodeQL graph export input {path.name} differs from the lock")


def _export_identity(database: Mapping[str, Any], profile: Mapping[str, Any],
                     settings: CodeQLAnalysisSettings, *, runner_sha256: str,
                     seeds: Iterable[tuple[str, int, int]] | None = None) -> str:
    """Export checkpoint identity (plan section 7.2).

    It binds the database identity and tree, the export pack (not the catalog, which only the
    downstream normalizer reads), the export bounds and the runner. Query suites, SARIF limits and
    normalizers are deliberately absent, so a SARIF change never invalidates an export. The export
    scope (mode, and in seeded mode the depth, seed limit and sorted seed set) is bound too, so any
    change of what seeds the neighborhood re-runs the export.
    """
    export = settings.export_queries
    return hashlib.sha256(canonical_json({
        "schema": EXPORT_CHECKPOINT_SCHEMA,
        "database_identity": database["database_identity"],
        "database_tree_sha256": database["database_tree_sha256"],
        "export_pack": {key: value for key, value in profile.items()
                        if key not in {"catalog_path", "catalog_sha256"}},
        "export_manifest_schema": EXPORT_MANIFEST_SCHEMA,
        "bounds": {"row_limit": settings.export_queries.row_limit,
                   "max_bytes": settings.export_queries.max_bytes,
                   "timeout_seconds": settings.export_queries.timeout_seconds},
        "export_scope": seeding.identity_fragment(export.mode, export.seed_depth, export.seed_limit, seeds),
        "runner_sha256": runner_sha256,
    })).hexdigest()


def _default_export_executor(image: Any, run_root: Path, settings: CodeQLAnalysisSettings) -> Any:
    return CodeQLExecutor(image=image, run_root=run_root, settings=settings)


def _stage_export(unit: UnitContext, scope_root: Path, staging: Path, profile: Mapping[str, Any],
                  *, mode: str = "whole_program", depth: int = 0,
                  seed_rows: Iterable[tuple[str, int, int]] = ()) -> None:
    """Disposable database copy plus the repository-owned pack, columns, lock and export scope in scratch.

    ``scope.csv`` and ``seeds.csv`` are the header-less external predicate inputs of the QL pack
    (seeded-codeql-neighborhoods.md section 5); ``seeds.csv`` is empty in whole-program mode.
    """
    repository = unit.job.repository_root
    staging.mkdir(parents=True)
    shutil.copytree(scope_root / "database", staging / "database")
    _make_workspace_accessible(staging / "database", writable_files=True)
    shutil.copytree(repository / str(profile["source_path"]), staging / "pack")
    _make_workspace_accessible(staging / "pack")
    shutil.copyfile(repository / str(profile["columns_path"]), staging / "columns.json")
    shutil.copyfile(repository.joinpath(*_ASSET_LOCK), staging / "assets.lock.json")
    (staging / SCOPE_FILE).write_text(seeding.scope_csv(mode, depth), encoding="utf-8")
    (staging / SEEDS_FILE).write_text(
        seeding.seeds_csv(seed_rows if mode == "seeded" else ()), encoding="utf-8")
    for path in (staging / "columns.json", staging / "assets.lock.json", staging / SCOPE_FILE,
                 staging / SEEDS_FILE):
        path.chmod(0o444)
    staging.chmod(0o777)


def _verify_export_manifest(root: Path, scope: CodeQLScope, profile: Mapping[str, Any],
                            settings: CodeQLAnalysisSettings, *, seed_count: int = 0) -> Mapping[str, Any]:
    manifest = json.loads((root / EXPORT_MANIFEST_NAME).read_text(encoding="utf-8"))
    pack = manifest.get("pack")
    if (manifest.get("language") != scope.language or not isinstance(pack, Mapping) or
            pack.get("tree_sha256") != profile["tree_sha256"] or
            pack.get("query_pack") != profile["query_pack"] or
            pack.get("query_pack_version") != profile["query_pack_version"] or
            pack.get("columns_sha256") != profile["columns_sha256"] or
            manifest.get("row_limit") != settings.export_queries.row_limit or
            manifest.get("max_bytes") != settings.export_queries.max_bytes):
        raise GraphExportIntegrityError("graph export manifest differs from the configured pack or bounds")
    recorded = manifest.get("scope")
    if recorded is not None:
        export = settings.export_queries
        seeded = export.mode == "seeded"
        if (not isinstance(recorded, Mapping) or recorded.get("mode") != export.mode or
                (seeded and recorded.get("depth") != export.seed_depth) or
                recorded.get("seed_count") != (seed_count if seeded else 0)):
            raise GraphExportIntegrityError("graph export manifest scope differs from the configured export scope")
    return manifest


def _export_base(scope: CodeQLScope, database: Mapping[str, Any]) -> dict[str, Any]:
    return {"scope_id": scope.scope_id, "language": scope.language, "root": scope.root,
            "build_unit_id": scope.build_unit_id, "database_identity": database.get("database_identity"),
            "export_identity": None, "export_reused": False}


def _require_seed_reports(documents: Mapping[str, Mapping[str, Any]], settings: CodeQLAnalysisSettings) -> None:
    """A seeded export must carry both report queries; their absence is an invalid export."""
    if settings.export_queries.mode == "seeded" and not {"seed_functions", "neighborhood"} <= set(documents):
        raise GraphExportIntegrityError("seeded graph export lacks its seed_functions or neighborhood report")


def _seeded_record(settings: CodeQLAnalysisSettings, scope_seeds: seeding.ScopeSeeds,
                   plan: seeding.SeedPlan | None, documents: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Spec section 6 ``seeded`` object of one exported scope."""
    export = settings.export_queries
    if export.mode != "seeded":
        return seeding.whole_program_section()
    return seeding.seeded_section(
        depth=export.seed_depth, seed_limit=export.seed_limit, scope_seeds=scope_seeds,
        plan=plan or seeding.SeedPlan(), seed_functions=documents.get("seed_functions"),
        neighborhood=documents.get("neighborhood"))


def _export_success(unit: UnitContext, base: Mapping[str, Any], identity: str, root: Path,
                    manifest: Mapping[str, Any], documents: Mapping[str, Mapping[str, Any]],
                    *, reused: bool, execution: Mapping[str, Any] | None,
                    seeded: Mapping[str, Any] | None = None) -> dict[str, Any]:
    truncated = sorted(query_id for query_id, document in documents.items() if document["truncated"])
    gaps = [f"CodeQL graph export {query_id} truncated at {manifest['row_limit']} rows"
            for query_id in truncated]
    seeded = seeding.whole_program_section() if seeded is None else seeded
    gaps.extend(gap for gap in seeded["gaps"] if gap not in gaps)
    value = {**base, "export_status": "SUCCEEDED", "export_identity": identity, "export_reused": reused,
             "export_pack": dict(manifest["pack"]),
             "export_manifest": _artifact(unit.job.run_root, root / EXPORT_MANIFEST_NAME),
             "export_files": [{"query_id": item["query_id"],
                               **_artifact(unit.job.run_root, root / str(item["path"]))}
                              for item in manifest["exports"]],
             "export_count": len(documents),
             "row_count": sum(int(document["row_count"]) for document in documents.values()),
             "exported_rows": sum(len(document["rows"]) for document in documents.values()),
             "truncated_queries": truncated, "seeded": dict(seeded), "gaps": gaps}
    if execution is not None:
        value["export_execution"] = execution
    return value


def _seed_plan(unit: UnitContext, scopes: Sequence[CodeQLScope]) -> seeding.SeedPlan:
    """Seeds of every scope from the accepted upstream observation shards (seeded mode only)."""
    manifests = unit.output("plan.inventory").get("upstream_manifests", ())
    try:
        return seeding.extract_seeds(unit.job.run_root, manifests, scopes,
                                     seed_limit=_settings(unit).export_queries.seed_limit)
    except seeding.SeedIntegrityError as exc:
        raise FrameworkIntegrityError(str(exc)) from exc


def _export_one(unit: UnitContext, database: Mapping[str, Any], *,
                executor_factory: Any = None, seed_plan: seeding.SeedPlan | None = None) -> Mapping[str, Any]:
    """Run (or verify and reuse) the hash-pinned graph export of one scope's database.

    In seeded mode the export runs only when the scope has seeds; a scope without any is SKIPPED
    with a named gap and a ``seeded`` ledger, never reported as a clean export.
    """
    settings = _settings(unit)
    scope = _scope_from(database["scope"])
    base = _export_base(scope, database)
    profile = _export_profile(settings, scope.language)
    if profile is None:
        reason = ("graph export is disabled in central configuration" if not settings.export_queries.enabled
                  else f"no hash-pinned CodeQL graph export pack for {scope.language}")
        return {**base, "export_status": "NOT_APPLICABLE", "reason": reason, "gaps": []}
    if database.get("terminal_status") != "SUCCEEDED":
        return {**base, "export_status": "SKIPPED",
                "gaps": ["CodeQL graph export skipped because database creation failed"]}
    run_root = unit.job.run_root
    export = settings.export_queries
    seeded_mode = export.mode == "seeded"
    plan = seed_plan if seed_plan is not None or not seeded_mode else _seed_plan(unit, [scope])
    scope_seeds = plan.for_scope(scope.scope_id) if plan is not None else seeding.ScopeSeeds(scope.scope_id)
    if seeded_mode and not scope_seeds.seeds:
        section = seeding.skipped_section(depth=export.seed_depth, seed_limit=export.seed_limit,
                                          scope_seeds=scope_seeds, plan=plan or seeding.SeedPlan())
        return {**base, "export_status": "SKIPPED", "reason": seeding.NO_SEEDS_GAP,
                "seeded": section, "gaps": list(section["gaps"])}
    seed_rows = scope_seeds.rows if seeded_mode else ()
    runner_sha256 = file_sha256(unit.job.repository_root.joinpath(*_RUNNER))
    identity = _export_identity(database, profile, settings, runner_sha256=runner_sha256, seeds=seed_rows)
    scope_root = run_root / "data" / "codeql" / "scopes" / scope.scope_id
    exports_root, staging = scope_root / "exports", scope_root / "export"
    checkpoint_path = scope_root / "export-checkpoint.json"
    event = {"unit_id": unit.unit_id, "tool_id": "codeql-graph-export", **_metrics_scope(scope),
             "database_identity": database["database_identity"], "export_identity": identity,
             "export_pack": profile["query_pack"], "export_pack_version": profile["query_pack_version"]}
    existing = _checkpoint(checkpoint_path, identity, EXPORT_CHECKPOINT_SCHEMA)
    if existing is not None:
        unit.job.events.write("TOOL_INVOCATION_STARTED", **event, checkpoint_reused=True)
        try:
            documents = load_graph_exports(exports_root, bytes_limit=settings.export_queries.max_bytes)
            manifest = _verify_export_manifest(exports_root, scope, profile, settings,
                                               seed_count=len(seed_rows))
            _require_seed_reports(documents, settings)
        except (OSError, ValueError) as exc:
            raise FrameworkIntegrityError("accepted CodeQL graph export changed after its checkpoint") from exc
        if file_sha256(exports_root / EXPORT_MANIFEST_NAME) != existing.get("manifest_sha256"):
            raise FrameworkIntegrityError("accepted CodeQL graph export manifest changed after its checkpoint")
        value = _export_success(unit, base, identity, exports_root, manifest, documents,
                                reused=True, execution=None,
                                seeded=_seeded_record(settings, scope_seeds, plan, documents))
        unit.job.events.write("TOOL_INVOCATION_COMPLETED", **event, disposition="SUCCEEDED",
                              duration_ms=0, result_count=value["exported_rows"],
                              gap_count=len(value["gaps"]), checkpoint_reused=True,
                              truncated=bool(value["truncated_queries"]),
                              metrics_receipt=_artifact(run_root, checkpoint_path))
        return value
    checkpoint_path.unlink(missing_ok=True)
    for path in (exports_root, staging, scope_root / "executions" / "export",
                 scope_root / "executions" / "compile"):
        if path.is_dir():
            shutil.rmtree(path)
    _stage_export(unit, scope_root, staging, profile, mode=export.mode,
                  depth=export.seed_depth if seeded_mode else 0, seed_rows=seed_rows)
    from appsec_review.codeql import CodeQLImage
    image = CodeQLImage(**_safe_json(run_root, database["image"]))
    executor = (executor_factory or _default_export_executor)(image, run_root, settings)
    compiled = _precompile_export_pack(unit, image, executor, scope_root, profile, settings,
                                       language=scope.language, event=event)
    if compiled is not None:
        shutil.rmtree(staging)
        return {**base, "export_status": "FAILED", "export_identity": identity,
                "export_execution": compiled["execution"], "gaps": compiled["gaps"]}
    argv = graph_export_arguments(
        database="export/database", pack="export/pack", columns="export/columns.json",
        asset_lock="export/assets.lock.json", language=scope.language, output_dir="exports",
        row_limit=settings.export_queries.row_limit, max_bytes=settings.export_queries.max_bytes,
        threads=settings.threads, ram_mb=settings.ram_mb, scope_file=f"export/{SCOPE_FILE}",
        seeds_file=f"export/{SEEDS_FILE}")
    unit.job.events.write("TOOL_INVOCATION_STARTED", **event, image_id=image.image_id)
    result = executor.execute("export", argv, scratch_root=scope_root)
    shutil.rmtree(staging)
    status = "FAILED" if result.timed_out or result.exit_code != 0 else "SUCCEEDED"
    gaps = (["CodeQL graph export timed out"] if result.timed_out else
            [f"CodeQL graph export exited {result.exit_code}"] if result.exit_code != 0 else [])
    documents: Mapping[str, Mapping[str, Any]] = {}
    manifest: Mapping[str, Any] = {}
    if status == "SUCCEEDED":
        try:
            documents = load_graph_exports(exports_root, bytes_limit=settings.export_queries.max_bytes)
            manifest = _verify_export_manifest(exports_root, scope, profile, settings,
                                               seed_count=len(seed_rows))
            _require_seed_reports(documents, settings)
        except (OSError, ValueError) as exc:
            status, gaps = "FAILED", [f"CodeQL graph export produced an invalid bounded export ({type(exc).__name__})"]
    execution = _execution_artifact(unit, scope_root, "export")
    unit.job.events.write("TOOL_INVOCATION_COMPLETED", **event, image_id=image.image_id,
                          disposition=status, duration_ms=result.duration_ms,
                          result_count=sum(len(item["rows"]) for item in documents.values()),
                          gap_count=len(gaps), gaps=gaps, checkpoint_reused=False,
                          truncated=result.stdout_truncated or result.stderr_truncated,
                          metrics_receipt=execution)
    if status != "SUCCEEDED":
        return {**base, "export_status": "FAILED", "export_identity": identity,
                "export_execution": execution, "gaps": gaps}
    atomic_json(checkpoint_path, {"schema": EXPORT_CHECKPOINT_SCHEMA, "identity": identity,
                "terminal_status": "SUCCEEDED",
                "manifest_sha256": file_sha256(exports_root / EXPORT_MANIFEST_NAME)})
    return _export_success(unit, base, identity, exports_root, manifest, documents,
                           reused=False, execution=execution,
                           seeded=_seeded_record(settings, scope_seeds, plan, documents))


_PRECOMPILE_LOCKS: dict[str, threading.Lock] = {}
_PRECOMPILED: set[str] = set()
_PRECOMPILE_GUARD = threading.Lock()


def _precompile_export_pack(unit: UnitContext, image: Any, executor: Any, scope_root: Path,
                            profile: Mapping[str, Any], settings: CodeQLAnalysisSettings, *,
                            language: str, event: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Fill the persistent compile cache before evaluation, under its own timeout and resources.

    A cold compile of the export pack costs minutes of CPU and would otherwise be charged to the
    evaluation timeout. Scopes that share the cache wait for the first compile and then hit it.
    Returns ``None`` when the cache is warm and a failure record (a named gap, never a clean
    result) when the compile fails or times out.
    """
    key = f"{compile_cache_volume(image)}:{profile['tree_sha256']}"
    with _PRECOMPILE_GUARD:
        lock = _PRECOMPILE_LOCKS.setdefault(key, threading.Lock())
    with lock:
        if key in _PRECOMPILED:
            return None
        argv = graph_compile_arguments(
            pack="export/pack", columns="export/columns.json", asset_lock="export/assets.lock.json",
            language=language, threads=settings.compile_threads, ram_mb=settings.compile_ram_mb)
        compile_event = {**event, "tool_id": "codeql-graph-export-compile"}
        unit.job.events.write("TOOL_INVOCATION_STARTED", **compile_event, image_id=image.image_id)
        result = executor.execute("compile", argv, scratch_root=scope_root)
        failed = result.timed_out or result.exit_code != 0
        gaps = (["CodeQL graph export query compile timed out"] if result.timed_out else
                [f"CodeQL graph export query compile exited {result.exit_code}"] if failed else [])
        execution = _execution_artifact(unit, scope_root, "compile")
        unit.job.events.write("TOOL_INVOCATION_COMPLETED", **compile_event, image_id=image.image_id,
                              disposition="FAILED" if failed else "SUCCEEDED",
                              duration_ms=result.duration_ms, result_count=0, gap_count=len(gaps),
                              gaps=gaps, checkpoint_reused=False,
                              truncated=result.stdout_truncated or result.stderr_truncated,
                              metrics_receipt=execution)
        if failed:
            return {"execution": execution, "gaps": gaps}
        _PRECOMPILED.add(key)
        return None


def _export_isolated(unit: UnitContext, database: Mapping[str, Any], *,
                     executor_factory: Any = None,
                     seed_plan: seeding.SeedPlan | None = None) -> Mapping[str, Any]:
    try:
        return _export_one(unit, database, executor_factory=executor_factory, seed_plan=seed_plan)
    except (RuntimeError, TimeoutError) as exc:
        scope = _scope_from(database["scope"])
        return {**_export_base(scope, database), "export_status": "FAILED",
                "gaps": [f"CodeQL {scope.language} graph export producer failed ({type(exc).__name__})"]}


def _export_scopes(unit: UnitContext, *, executor_factory: Any = None) -> Mapping[str, Any]:
    """The ``export.scopes`` unit: one bounded graph export per successful exportable database."""
    settings = _settings(unit)
    values = unit.output("database.scopes")["databases"]
    verified: set[str] = set()
    for value in values:
        language = str(value["scope"]["language"])
        profile = _export_profile(settings, language)
        if (profile is not None and language not in verified and
                value.get("terminal_status") == "SUCCEEDED"):
            _verify_export_sources(unit.job.repository_root, profile, settings)
            verified.add(language)
    plan = None
    if settings.export_queries.mode == "seeded" and verified:
        # One pass over the accepted observation shards seeds every scope.
        plan = _seed_plan(unit, [_scope_from(value["scope"]) for value in values])
    with ThreadPoolExecutor(max_workers=settings.concurrency) as pool:
        results = list(pool.map(lambda value: _export_isolated(
            unit, value, executor_factory=executor_factory, seed_plan=plan), values))
    gaps = [gap for item in results for gap in item.get("gaps", ())]
    document = {"schema": GRAPH_EXPORTS_SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
                "settings": asdict(settings.export_queries), "exports": results}
    artifact = _json_artifact(unit.job.run_root,
                              unit.job.attempt_root / "artifacts" / "codeql" / "graph-exports.json", document)
    return {"schema": GRAPH_EXPORTS_SCHEMA, "artifact": artifact, "exports": results,
            "export_count": sum(item["export_status"] == "SUCCEEDED" for item in results),
            "export_reused": sum(bool(item.get("export_reused")) for item in results),
            "gaps": gaps,
            "dispositions": [{"scope_id": item["scope_id"], "language": item["language"],
                              "action": "export", "terminal_status": item["export_status"]}
                             for item in results],
            "terminal_status": "COMPLETED_WITH_GAPS" if gaps else "SUCCEEDED"}


def _location(unit: UnitContext, value: Mapping[str, Any]) -> SourceLocation | None:
    path = value.get("path")
    digest = value.get("file_sha256")
    if not isinstance(path, str) or not isinstance(digest, str):
        return None
    source = (unit.job.target_root or Path()) / Path(*PurePosixPath(path).parts)
    if not source.is_file() or source.is_symlink() or file_sha256(source) != digest:
        raise FrameworkIntegrityError("CodeQL normalized source identity changed")
    return SourceLocation(unit.job.source_fingerprint, path, digest, 0, source.stat().st_size,
        int(value["start_line"]), int(value["end_line"]), int(value["start_column"]),
        int(value["end_column"]), value.get("producer_location", {}),
        "codeql-sarif-exact-path" if float(value.get("confidence", 0)) == 1.0 else "codeql-sarif-suffix",
        float(value.get("confidence", 0)), bool(value.get("ambiguous", False)))


def _normalize_one(unit: UnitContext, query: Mapping[str, Any]) -> Mapping[str, Any]:
    scope = _scope_from(query["scope"])
    profile = query.get("query_profile") if isinstance(query.get("query_profile"), Mapping) else {
        "query_id": "default", "kind": "default"}
    query_id = str(profile["query_id"])
    gaps = list(query.get("gaps", ()))
    artifacts = [query[key] for key in ("database_manifest", "database_execution", "query_execution", "sarif", "image")
                 if isinstance(query.get(key), Mapping)]
    fingerprint = index_fingerprint(name="observations", target_snapshot=unit.job.source_fingerprint,
        producer_artifacts=artifacts,
        tool_identity={"tool": "codeql", "language": scope.language,
                       "query_profile": query_id,
                       "database_identity": query.get("database_identity"),
                       "query_identity": query.get("query_identity")},
        parser_identity=NORMALIZER_IDENTITY, normalizer_identity=NORMALIZER_IDENTITY,
        mapping_identity="accepted-codeql-source-map/1")
    shard = f"codeql-{scope.language}-{scope.scope_id}-{query_id}"
    physical = hashlib.sha256(shard.encode()).hexdigest()[:16]
    path = unit.job.run_root / "data" / "indices" / "observations" / f"{fingerprint}-{physical}.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint=fingerprint,
                           target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    evidence = LogicalIdentity.derive(EntityKind.EVIDENCE_ARTIFACT, unit.job.source_fingerprint,
        {"producer": "codeql", "scope": scope.scope_id, "query_profile": query_id,
         "database": query.get("database_identity"),
         "query": query.get("query_identity")})
    builder.add_entity(EntityRecord(evidence, f"codeql:{scope.scope_id}:{query_id}",
        f"CodeQL {query_id} execution",
        "; ".join(gaps), {"producer": "codeql", "language": scope.language,
                          "query_profile": query_id, "query_kind": profile.get("kind"),
                          "source_languages": list(scope.source_languages),
                          "status": query.get("terminal_status"), "scope_id": scope.scope_id}))
    observation_count = support_count = 0
    if query.get("terminal_status") == "SUCCEEDED":
        sarif = load_sarif(unit.job.run_root / query["sarif"]["path"],
                           bytes_limit=_settings(unit).sarif_bytes_limit,
                           result_limit=_settings(unit).result_limit)
        records, normalization_gaps = normalize_sarif(sarif, files=scope.files, root=scope.root,
            query_identity=str(query["query_identity"]), result_limit=_settings(unit).result_limit)
        gaps.extend(normalization_gaps)
        source_entities: dict[str, str] = {}
        for record in records:
            location_value = record.get("location")
            location = _location(unit, location_value) if isinstance(location_value, Mapping) else None
            native = {"producer": "codeql", "scope": scope.scope_id,
                      "query_profile": query_id,
                      "query_identity": query["query_identity"], "rule_id": record["rule_id"],
                      "native_id": record["native_id"], "location": location_value,
                      "partial_fingerprints": record["payload"].get("partial_fingerprints", {})}
            observation = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION,
                                                  unit.job.source_fingerprint, native)
            observation_payload = {**record["payload"], "language": scope.language,
                "query_profile": query_id, "query_kind": profile.get("kind"),
                "source_languages": list(scope.source_languages), "scope_id": scope.scope_id,
                "root": scope.root, "build_unit_id": scope.build_unit_id,
                "database_identity": query.get("database_identity"),
                "query_identity": query.get("query_identity")}
            builder.add_entity(EntityRecord(observation, record["native_id"], record["rule_id"],
                                             record["message"], observation_payload, location))
            builder.add_relation(RelationRecord(RelationKind.DERIVED_FROM, observation.value,
                                                evidence.value, True, 1.0))
            if location is not None:
                if location.path not in source_entities:
                    source = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                        {"path": location.path, "sha256": location.file_sha256})
                    source_entities[location.path] = source.value
                    builder.add_entity(EntityRecord(source, location.path, PurePosixPath(location.path).name,
                        location.path, {"sha256": location.file_sha256, "scope_id": scope.scope_id}, location))
                builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, observation.value,
                                                    source_entities[location.path], True, 1.0))
            for flow in record.get("flows", ()):
                flow_location_value = flow.get("location")
                flow_location = (_location(unit, flow_location_value)
                                 if isinstance(flow_location_value, Mapping) else None)
                if flow_location is None:
                    continue
                if flow_location.path not in source_entities:
                    source = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                        {"path": flow_location.path, "sha256": flow_location.file_sha256})
                    source_entities[flow_location.path] = source.value
                    builder.add_entity(EntityRecord(source, flow_location.path,
                        PurePosixPath(flow_location.path).name, flow_location.path,
                        {"sha256": flow_location.file_sha256, "scope_id": scope.scope_id}, flow_location))
                span = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, unit.job.source_fingerprint,
                    {"producer": "codeql", "observation": observation.value,
                     "ordinal": flow["ordinal"], "path": flow_location.path,
                     "line": flow_location.start_line, "column": flow_location.start_column})
                builder.add_entity(EntityRecord(span, str(flow["ordinal"]),
                    f"CodeQL flow step {flow['ordinal']}", str(flow.get("message", "flow step")),
                    {"producer": "codeql", "scope_id": scope.scope_id, "code_flow": flow.get("code_flow"),
                     "thread_flow": flow.get("thread_flow")}, flow_location))
                builder.add_relation(RelationRecord(RelationKind.SUPPORTS, span.value,
                                                    observation.value, True, 1.0))
                builder.add_relation(RelationRecord(RelationKind.OBSERVED_AT, span.value,
                                                    source_entities[flow_location.path], True, 1.0))
                support_count += 1
            observation_count += 1
        if observation_count == 0:
            gaps.append(f"CodeQL {query_id} query suite completed with zero observations; "
                        "this is not a clean classification")
    else:
        builder.add_coverage(f"codeql-{scope.language}", "unavailable", "; ".join(gaps[:10]))
    if query.get("terminal_status") == "SUCCEEDED":
        builder.add_coverage(f"codeql-{scope.language}", "partial" if gaps else "complete",
                             "; ".join(gaps[:10]) or None)
    sha = builder.build()
    identity = IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, fingerprint,
        path.relative_to(unit.job.run_root).as_posix(),
        {"job": "job_codeql_analysis", "unit": unit.unit_id, "language": scope.language,
         "query_profile": query_id},
        tuple(dict.fromkeys(gaps)), shard)
    return {**query, "index_identity": asdict(identity), "index": _artifact(unit.job.run_root, path),
            "observation_count": observation_count, "support_count": support_count,
            "gaps": list(dict.fromkeys(gaps))}


def _validate_config(context, _result) -> None:
    expected = {"plan": ("inventory",), "database": ("scopes",), "query": ("scopes",),
                "export": ("scopes",), "normalize": ("scopes",), "acceptance": ("publish_handoff",)}
    if tuple(context.config.steps) != tuple(expected):
        raise ValueError("CodeQL analysis topology does not match central configuration")
    for step, tasks in expected.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"CodeQL analysis task configuration mismatch: {step}")
    settings = getattr(context.config, "typed_settings", None)
    if isinstance(settings, CodeQLAnalysisSettings):
        # Re-run the typed validation: mode, 0 <= seed_depth <= max_seed_depth <= ceiling, seed_limit >= 1.
        CodeQLExportSettings(**{name: getattr(settings.export_queries, name)
                                for name in CodeQLExportSettings.__dataclass_fields__})


def _validate_scope_assets(scope: CodeQLScope, settings: CodeQLAnalysisSettings,
                           lock: Mapping[str, Any]) -> None:
    configured = settings.languages.get(scope.language)
    if (configured is None or
            configured.runtime_mode is not None and configured.runtime_mode != scope.mode):
        raise FrameworkIntegrityError(f"CodeQL {scope.language} mode differs from central configuration")
    locked = lock["query_packs"].get(scope.language)
    if not isinstance(locked, Mapping) or any((
        configured.query_pack != locked["name"],
        configured.query_pack_version != locked["version"],
        configured.query_suite != locked["suite"],
        configured.query_suite_sha256 != locked["suite_sha256"],
        configured.query_pack_sha256 != locked["qlpack_sha256"],
        configured.query_lock_sha256 != locked["lock_sha256"],
    )):
        raise FrameworkIntegrityError(f"CodeQL {scope.language} query assets differ from the lock")
    locked_custom = lock.get("custom_query_packs", {}).get(scope.language, [])
    locked_additional = locked.get("additional_suites", [])
    configured_additional = [asdict(item) for item in configured.additional_queries]
    if configured_additional != locked_additional:
        raise FrameworkIntegrityError(
            f"CodeQL {scope.language} additional query assets differ from the lock")
    configured_custom = [asdict(item) for item in configured.custom_queries]
    if configured_custom != locked_custom:
        raise FrameworkIntegrityError(
            f"CodeQL {scope.language} custom query assets differ from the lock")


def publication_status(processing_decisions: Sequence[Mapping[str, Any]],
                       scopes: Sequence[Mapping[str, Any]]) -> str:
    """CodeQL's terminal status: missing planned coverage is COMPLETED_WITH_GAPS, never SUCCEEDED.

    A planned language or project whose processing decision is a GAP (for example no extractor in
    the pinned runtime) or a scope that did not succeed leaves source unanalyzed, so an empty result
    must not read as a clean analysis.
    """
    uncovered = (any(item.get("disposition") == ProcessingDisposition.GAP.value for item in processing_decisions)
                 or any(item.get("terminal_status") != "SUCCEEDED" for item in scopes))
    return "COMPLETED_WITH_GAPS" if uncovered else "SUCCEEDED"


def build_job() -> Job:
    def plan(unit: UnitContext) -> Mapping[str, Any]:
        settings = _settings(unit)
        catalog, accepted = load_target_catalog(unit.job.run_root), load_accepted_language_build(unit.job.run_root)
        if (catalog.source_fingerprint != unit.job.source_fingerprint or
                accepted.get("source_fingerprint") != unit.job.source_fingerprint or
                source_fingerprint(unit.job.target_root or Path()) != unit.job.source_fingerprint):
            raise FrameworkIntegrityError("CodeQL accepted target snapshot changed")
        lock = load_asset_lock(unit.job.repository_root)
        configured_lock = settings.asset_lock_sha256
        if lock["sha256"] != configured_lock:
            raise FrameworkIntegrityError("CodeQL asset lock differs from central configuration")
        root = unit.unit_root / "inventory"
        root.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(unit.job.repository_root / "containers" / "tools" / "codeql" / "assets.lock.json",
                        root / "assets.lock.json")
        inventory_path = root / "extractor-inventory.json"
        runtime_gaps: list[str] = []
        try:
            resolver = CodeQLImageResolver(repository_root=unit.job.repository_root,
                metadata_root=unit.job.metadata_root, settings=settings,
                timeout_seconds=settings.database_timeout_seconds, output_bytes=settings.output_bytes)
            image, _stdout, _stderr = resolver.resolve(build_image_tag=settings.source_image_tag,
                build_image_id=settings.source_image_id, runtime_user=settings.runtime_user)
            executor = CodeQLExecutor(image=image, run_root=unit.job.run_root, settings=settings)
            result = executor.execute("inventory", ("--asset-lock", "assets.lock.json",
                                      "--output", "extractor-inventory.json"), scratch_root=root)
            if result.timed_out or result.exit_code != 0:
                raise FrameworkIntegrityError("pinned CodeQL capability validation failed")
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            if inventory.get("schema") != "appsec-review/codeql-extractor-inventory/1":
                raise FrameworkIntegrityError("pinned CodeQL extractor inventory is invalid")
        except RuntimeError as exc:
            runtime_gaps.append(f"CodeQL runtime dependency is unavailable ({type(exc).__name__})")
            inventory = {"schema": "appsec-review/codeql-extractor-inventory/1", "languages": [],
                         "roots": {}, "extractors": {}, "query_packs": {}, "prerequisites": {},
                         "gap": runtime_gaps[0]}
            atomic_json(inventory_path, inventory)
        planned = build_codeql_plan(source_fingerprint=unit.job.source_fingerprint,
            files=catalog.files, receipts=accepted.get("receipts", ()),
            supported_extractors=inventory["languages"], source_image_id=settings.source_image_id,
            projects=catalog.projects,
            language_modes={language: value.mode.value for language, value in settings.languages.items()},
            configuration_sha256=resolved_configuration_identity(unit.job.run_root),
            enable_swift=unit.job.tools.enable_swift)
        if runtime_gaps:
            planned = CodeQLPlan(planned.schema, planned.source_fingerprint,
                planned.extractor_inventory, planned.scopes,
                tuple(dict.fromkeys([*runtime_gaps, *planned.gaps])), planned.non_applicable,
                planned.decisions)
        for scope in planned.scopes:
            _validate_scope_assets(scope, settings, lock)
        export_mismatches = export_lock_mismatches(
            {language: [asdict(item) for item in value.export_queries]
             for language, value in settings.languages.items()}, lock)
        if export_mismatches:
            raise FrameworkIntegrityError("CodeQL graph export query assets differ from the lock: " +
                                          ", ".join(export_mismatches))
        export_plan = plan_graph_exports(
            planned.scopes, enabled=settings.export_queries.enabled,
            export_languages=(language for language, value in settings.languages.items()
                              if value.export_queries))
        plan_path = unit.job.attempt_root / "artifacts" / "codeql" / "plan.json"
        upstream_handoffs, upstream_manifests = {}, []
        for job_id in ("job_target_catalog", "job_language_build", "job_artifact_indexing",
                       "job_cpp_compiled_analysis"):
            identity = _accepted_handoff_identity(unit.job.run_root, job_id)
            upstream_handoffs[job_id] = identity
            upstream_manifests.extend(_accepted_index_manifests(unit.job.run_root, identity))
        # Direct application runs may not schedule these sibling producers, while Wave 1 does.
        # Compose every accepted sibling that exists so a final CodeQL publication cannot replace
        # unrelated static, post-build, AST, or artifact-security evidence.
        for job_id in ("job_artifact_security_analysis", "job_post_build_security_assessment",
                       "job_evidence_collection", "job_tree_sitter_ast", "job_cpp_symbol_index",
                       "job_cpg_analysis", "job_change_context_analysis"):
            identity = _optional_accepted_handoff_identity(unit.job.run_root, job_id)
            if identity is None:
                continue
            upstream_handoffs[job_id] = identity
            upstream_manifests.extend(_accepted_index_manifests(unit.job.run_root, identity))
        return {"plan": _json_artifact(unit.job.run_root, plan_path, planned.as_dict()),
                "inventory": _artifact(unit.job.run_root, inventory_path),
                "asset_lock": {"path": Path(lock["path"]).relative_to(unit.job.repository_root).as_posix(),
                               "sha256": lock["sha256"]},
                "scope_count": len(planned.scopes), "gaps": list(planned.gaps),
                "non_applicable": list(planned.non_applicable),
                "processing_decisions": list(planned.decisions),
                "export_plan": [dict(item) for item in export_plan],
                "upstream_handoffs": upstream_handoffs,
                "upstream_manifests": list({(item["path"], item["sha256"]): item
                                             for item in upstream_manifests}.values())}

    def databases(unit: UnitContext) -> Mapping[str, Any]:
        plan_value, receipts = _plan_from(unit), _receipt_map(unit)
        with ThreadPoolExecutor(max_workers=_settings(unit).concurrency) as pool:
            values = list(pool.map(lambda scope: _database_isolated(unit, scope, receipts), plan_value.scopes))
        return {"databases": values, "database_count": sum(
            item.get("terminal_status") == "SUCCEEDED" for item in values),
            "database_reused": sum(bool(item.get("database_reused")) for item in values),
            "gaps": [gap for item in values for gap in item.get("gaps", ())]}

    def queries(unit: UnitContext) -> Mapping[str, Any]:
        values = unit.output("database.scopes")["databases"]
        scheduled = [(value, profile)
                     for value in values
                     for profile in _query_profiles(
                         _settings(unit).languages[_scope_from(value["scope"]).language])]
        with ThreadPoolExecutor(max_workers=_settings(unit).concurrency) as pool:
            queried = list(pool.map(lambda item: _query_one(unit, item[0], item[1]), scheduled))
        return {"queries": queried, "query_count": sum(
            item.get("terminal_status") == "SUCCEEDED" for item in queried),
            "query_reused": sum(bool(item.get("query_reused")) for item in queried),
            "gaps": [gap for item in queried for gap in item.get("gaps", ())]}

    def normalize(unit: UnitContext) -> Mapping[str, Any]:
        values = unit.output("query.scopes")["queries"]
        with ThreadPoolExecutor(max_workers=_settings(unit).concurrency) as pool:
            normalized = list(pool.map(lambda value: _normalize_one(unit, value), values))
        return {"scopes": normalized,
                "observation_count": sum(int(item.get("observation_count", 0)) for item in normalized),
                "gaps": [gap for item in normalized for gap in item.get("gaps", ())]}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        plan_value, normalized = _plan_from(unit), unit.output("normalize.scopes")
        indexes = [IndexIdentity(**{**item["index_identity"],
                                    "gaps": tuple(item["index_identity"].get("gaps", ()))})
                   for item in normalized["scopes"]]
        upstream_path, upstream_sha = resolve_context_manifest(unit.job)
        load_verified_manifest(unit.job.run_root, upstream_path, upstream_sha)
        destination = unit.job.run_root / "data" / "indices" / "manifests" / f"codeql-{unit.job.attempt_id}.json"
        current = {"path": upstream_path.relative_to(unit.job.run_root).as_posix(),
                   "sha256": upstream_sha}
        upstream_manifests = [current, *unit.output("plan.inventory")["upstream_manifests"]]
        upstream_manifests = list({(item["path"], item["sha256"]): item
                                   for item in upstream_manifests}.values())
        write_manifest(destination, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
            target_root=unit.job.target_root or Path(), indexes=indexes,
            upstream_manifests=tuple(upstream_manifests))
        scopes = []
        for item in normalized["scopes"]:
            scope = item["scope"]
            profile = item.get("query_profile", {"query_id": "default", "kind": "default"})
            scopes.append({"scope_id": scope["scope_id"], "language": scope["language"],
                "source_languages": scope["source_languages"], "root": scope["root"],
                "build_unit_id": scope["build_unit_id"], "mode": scope["mode"],
                "query_profile": profile["query_id"], "query_kind": profile["kind"],
                "terminal_status": item["terminal_status"],
                "database_identity": item.get("database_identity"),
                "database_reused": bool(item.get("database_reused")),
                "query_identity": item.get("query_identity"), "query_reused": bool(item.get("query_reused")),
                "query_suite": profile["query_suite"],
                "sarif_results": item.get("sarif_result_count", 0),
                "normalized_observations": item.get("observation_count", 0),
                "gaps": item.get("gaps", [])})
        gaps = list(dict.fromkeys([*plan_value.gaps, *normalized["gaps"],
                                   *unit.output("export.scopes")["gaps"]]))
        processing_decisions = []
        for raw in plan_value.decisions:
            decision = decision_from_mapping(raw)
            if decision.action is ApplicabilityAction.RUN:
                matching = [item for item in scopes if item["language"] == decision.language and
                            ((decision.project_id.startswith("source:") and item["build_unit_id"] is None) or
                             item["build_unit_id"] == decision.project_id)]
                decision = finalize_processing(
                    decision, succeeded=bool(matching) and all(
                        item["terminal_status"] == "SUCCEEDED" for item in matching),
                    evidence_complete=bool(matching) and not any(
                        item.get("gaps") for item in matching),
                    toolchain_available=bool(plan_value.extractor_inventory),
                )
            processing_decisions.append(decision.as_dict())
        gaps.extend(f"{item['project_id']}: {item['reason_code']}"
                    for item in processing_decisions if item.get("disposition") == "GAP")
        gaps = list(dict.fromkeys(gaps))
        graph_exports = [dict(item) for item in unit.output("export.scopes")["exports"]]
        summary = {"schema": SCHEMA, "source_fingerprint": unit.job.source_fingerprint,
                   "scopes": scopes, "graph_exports": graph_exports,
                   "extractor_inventory": list(plan_value.extractor_inventory),
                   "non_applicable": list(plan_value.non_applicable), "gaps": gaps,
                   "processing_decisions": processing_decisions,
                   "observation_count": normalized["observation_count"], "security_findings": []}
        summary_path = unit.job.attempt_root / "artifacts" / "codeql" / "summary.json"
        artifact = _json_artifact(unit.job.run_root, summary_path, summary)
        unit.job.events.write("CODEQL_SCOPES_RECORDED", unit_id=unit.unit_id,
            receipt=artifact, scope_count=len(scopes), gap_count=len(gaps),
            metrics_semantics="appsec-review/review-metrics-semantics/1")
        return {"schema": SCHEMA, "artifact": artifact,
                "terminal_status": publication_status(processing_decisions, scopes),
                "index_manifest": _artifact(unit.job.run_root, destination),
                "item_count": normalized["observation_count"], "scope_count": len(scopes),
                "gaps": gaps, "non_applicable": list(plan_value.non_applicable),
                "processing_decisions": processing_decisions,
                "dispositions": processing_decisions,
                "scope_dispositions": {f"{item['scope_id']}:{item['query_profile']}": item["terminal_status"]
                                       for item in scopes}}

    units = (
        Unit("plan.inventory", plan),
        Unit("database.scopes", databases, ("plan.inventory",)),
        Unit("query.scopes", queries, ("database.scopes",)),
        Unit("export.scopes", _export_scopes, ("database.scopes", "plan.inventory")),
        Unit("normalize.scopes", normalize, ("query.scopes",)),
        Unit("acceptance.publish_handoff", publish, ("normalize.scopes", "export.scopes")),
    )
    implementation = hashlib.sha256(
        Path(__file__).read_bytes() + Path(applicability_contract.__file__).read_bytes() +
        Path(__file__).with_name("planning.py").read_bytes() +
        Path(__file__).with_name("sarif.py").read_bytes() +
        Path(seeding.__file__).with_name("ledger.py").read_bytes() +
        Path(__file__).parents[2].joinpath("codeql", "runtime.py").read_bytes()).hexdigest()
    validation = hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest()
    return Job("job_codeql_analysis", "codeql_analysis", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity=SCHEMA,
               implementation_identity=implementation, validation_identity=validation, units=units,
               datasets=DATASETS, consumes=CONSUMES)
