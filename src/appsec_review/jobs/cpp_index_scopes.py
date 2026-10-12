"""Generic C/C++ index scopes derived from the accepted compiled-analysis handoff.

An index scope is a set of accepted source files plus the exact compile commands that build them,
materialized under the C++ job's run-owned case root. Indexing jobs (clangd symbol index, Joern
CPG) mount that case root read-only at ``/target`` and read a container compile database; they
never see the original target tree, and every source file is hash-verified against the accepted
mapping before a tool runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.storage import (
    ArtifactIntegrityError, canonical_json, file_sha256, run_artifact, verify_run_artifact,
)


SCOPE_SCHEMA = "appsec-review/cpp-index-scope/1"
CHECKPOINT_SCHEMA = "appsec-review/cpp-index-scope-checkpoint/2"
SOURCE_MOUNT = "/target/source"
_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".c++", ".mm"})


def _read_json_artifact(run_root: Path, identity: Mapping[str, Any]) -> Any:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file() or path.is_symlink():
        raise ValueError("accepted upstream artifact is unavailable or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted upstream artifact identity changed")
    return json.loads(path.read_text(encoding="utf-8"))


def load_accepted_cpp(run_root: Path) -> Mapping[str, Any]:
    """Load and verify the accepted ``job_cpp_compiled_analysis`` handoff, result, and manifest."""
    pointer_path = run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "latest.json"
    if not pointer_path.is_file():
        raise ValueError("accepted job_cpp_compiled_analysis handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read_json_artifact(run_root, {"path": pointer.get("handoff_path"),
                                            "sha256": pointer.get("handoff_sha256")})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError("C++ compiled-analysis handoff is not accepted")
    if handoff.get("job_id") != "job_cpp_compiled_analysis":
        raise ValueError("accepted C++ handoff producer is invalid")
    result_path = str(handoff.get("resolving_paths", {}).get("result", ""))
    result_identity = next((item for item in handoff.get("artifacts", ())
                            if item.get("path") == result_path), None)
    if not isinstance(result_identity, Mapping):
        raise ValueError("accepted C++ handoff does not bind its result")
    result = _read_json_artifact(run_root, result_identity)
    if result.get("schema") not in {"appsec-review/unit-execution/1", "appsec-review/unit-execution/2"}:
        raise ValueError("accepted C++ result schema is unsupported")
    published = handoff.get("outputs", {}).get("acceptance.publish_handoff", {})
    manifest_identity = published.get("index_manifest") if isinstance(published, Mapping) else None
    if not isinstance(manifest_identity, Mapping):
        raise ValueError("accepted C++ handoff does not publish an index manifest")
    manifest_path = (run_root / str(manifest_identity.get("path", ""))).resolve()
    manifest_sha = str(manifest_identity.get("sha256", ""))
    if run_root.resolve() not in manifest_path.parents or not any(
        item.get("path") == manifest_identity.get("path") and item.get("sha256") == manifest_sha
        for item in handoff.get("artifacts", ())
    ):
        raise ValueError("accepted C++ index manifest is not bound to its handoff")
    load_verified_manifest(run_root, manifest_path, manifest_sha)
    return {"handoff": handoff, "handoff_sha256": pointer["handoff_sha256"], "result": result,
            "manifest": {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": manifest_sha}}


def container_compile_database(root: str, compile_commands: Any,
                               source_mount: str = SOURCE_MOUNT) -> list[dict[str, Any]]:
    """Rewrite accepted compile commands to read-only container paths under ``source_mount``.

    The driver is normalized to ``clang``/``clang++`` by source suffix; every other argument is
    preserved, with build-time ``/scratch`` paths rebased onto the mounted case root.
    """
    prefix = str(root).rstrip("/") + "/"
    mount_root = source_mount.rsplit("/", 1)[0]
    rows = []
    for command in compile_commands:
        target_path = str(command["target_path"])
        if not target_path.startswith(prefix):
            raise ValueError("compile unit is outside the accepted project root")
        relative = target_path[len(prefix):]
        arguments = []
        for index, value in enumerate(command["arguments"]):
            rewritten = str(value).replace("/scratch/source", source_mount).replace(
                "/scratch/build", f"{mount_root}/build")
            if index == 0:
                rewritten = "clang++" if PurePosixPath(relative).suffix.lower() in _CXX_SUFFIXES else "clang"
            arguments.append(rewritten)
        rows.append({"directory": source_mount, "file": f"{source_mount}/{relative}",
                     "arguments": arguments})
    return rows


@dataclass(frozen=True, slots=True)
class IndexScope:
    """One accepted C/C++ project: its verified files and the commands that compile them."""

    scope_id: str
    case_id: str
    project_id: str
    root: str
    case_snapshot: str
    case_root: Path
    files: tuple[Mapping[str, Any], ...]
    compile_commands: tuple[Mapping[str, Any], ...]
    compile_database: Mapping[str, Any]
    _by_relative: Mapping[str, Mapping[str, Any]] = field(default_factory=dict, repr=False, compare=False)

    def container_compile_database(self) -> list[dict[str, Any]]:
        return container_compile_database(self.root, self.compile_commands)

    def accepted_file(self, container_path: str) -> Mapping[str, Any] | None:
        """Map ``/target/source/<relative>`` back to the accepted mapping entry, if any."""
        prefix = SOURCE_MOUNT + "/"
        if not container_path.startswith(prefix):
            return None
        return self._by_relative.get(container_path[len(prefix):])

    def as_dict(self) -> dict[str, Any]:
        return {"schema": SCOPE_SCHEMA, "scope_id": self.scope_id, "case_id": self.case_id,
                "project_id": self.project_id, "root": self.root, "case_snapshot": self.case_snapshot,
                "file_count": len(self.files), "compile_unit_count": len(self.compile_commands),
                "compile_database": dict(self.compile_database)}


def _scope(run_root: Path, case_id: str, catalog: Mapping[str, Any]) -> IndexScope:
    mapping = catalog["mapping"]
    case_root = (run_root / "data" / "cpp" / "projects" / case_id).resolve()
    if run_root.resolve() not in case_root.parents:
        raise ValueError("C++ case root escapes the run")
    compile_database = catalog["compile_database"]
    path = (run_root / str(compile_database["path"])).resolve()
    if run_root.resolve() not in path.parents or file_sha256(path) != compile_database["sha256"]:
        raise ValueError(f"accepted compile database changed: {case_id}")
    by_relative = {}
    for item in mapping["files"]:
        scratch = PurePosixPath(str(item["scratch_path"]))
        if scratch.is_absolute() or ".." in scratch.parts or scratch.parts[:1] != ("source",):
            raise ValueError(f"accepted source mapping is not normalized: {case_id}")
        source = case_root / Path(*scratch.parts)
        if not source.is_file() or source.is_symlink() or file_sha256(source) != item["sha256"]:
            raise ValueError(f"materialized source changed after acceptance: {item['target_path']}")
        by_relative[PurePosixPath(*scratch.parts[1:]).as_posix()] = item
    scope_id = "cpp-scope-" + hashlib.sha256(canonical_json({
        "schema": SCOPE_SCHEMA, "case_id": case_id, "case_snapshot": mapping["case_snapshot"],
        "compile_database": compile_database["sha256"]})).hexdigest()[:24]
    return IndexScope(scope_id, case_id, str(mapping["project_id"]), str(mapping["root"]),
                      str(mapping["case_snapshot"]), case_root, tuple(mapping["files"]),
                      tuple(catalog["compile_commands"]), dict(compile_database), by_relative)


def accepted_cpp_scopes(run_root: Path) -> tuple[Mapping[str, Any], list[IndexScope], dict[str, str]]:
    """Return the accepted C++ handoff identity, its index scopes, and unavailable cases with reasons."""
    accepted = load_accepted_cpp(run_root)
    catalogs = accepted["result"].get("outputs", {}).get("catalog.projects", {}).get("projects", {})
    scopes: list[IndexScope] = []
    unavailable: dict[str, str] = {}
    for case_id, catalog in sorted(catalogs.items()):
        if catalog.get("terminal_status") != "SUCCEEDED":
            gaps = list(catalog.get("gaps", ()))
            unavailable[case_id] = str(gaps[0]) if gaps else "accepted C++ build catalog is unavailable"
            continue
        if not catalog.get("compile_commands"):
            unavailable[case_id] = "accepted C++ project has no compile commands"
            continue
        scopes.append(_scope(run_root, case_id, catalog))
    return accepted, scopes, unavailable


# Shared per-scope execution, checkpoint, and shard helpers for independent indexing jobs.

def tool_identity(repository_root: Path, tool_id: str) -> dict[str, Any]:
    """Catalog identity of a pinned tool image, or an explicit injected-executor marker."""
    from appsec_review.container_runtime import load_catalog

    if not (repository_root / "containers" / "catalog.toml").is_file():
        return {"tool_id": tool_id, "injected_executor": True}
    tool = load_catalog(repository_root).tool(tool_id)
    return {"tool_id": tool_id, "tag": tool.tag, "version": tool.version,
            "expected_image_id": tool.expected_image_id,
            "manifest_sha256": file_sha256(tool.manifest_path)}


def execute_scope_tool(unit: Any, scope: IndexScope, tool_id: str, argv: tuple[str, ...],
                       scratch: Path, executor_factory: Any = None, *,
                       file_size_limit_bytes: int | None = None) -> dict[str, Any]:
    """Run one catalog tool against a scope: case root read-only at /target, scratch read-write.

    The container compile database is written to ``/scratch/compile_commands.json`` first. A
    ``file_size_limit_bytes`` is enforced by the kernel (RLIMIT_FSIZE) on every file the tool
    writes, so a bounded output can never outgrow its limit on the run volume.
    """
    from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, load_catalog
    from appsec_review.storage import tool_input_json

    if scratch.exists():
        import shutil
        shutil.rmtree(scratch)
    scratch.mkdir(parents=True)
    compile_database = scratch / "compile_commands.json"
    tool_input_json(compile_database, scope.container_compile_database())
    executor = (executor_factory(unit) if executor_factory is not None else
                ContainerExecutor(load_catalog(unit.job.repository_root), unit.job.run_root))
    result = executor.execute(ExecutionRequest(tool_id=tool_id, argv=argv,
                                               target_root=scope.case_root, scratch_root=scratch,
                                               file_size_limit_bytes=file_size_limit_bytes))
    run_root = unit.job.run_root
    return {"tool_id": tool_id, "exit_code": result.exit_code, "timed_out": result.timed_out,
            "file_size_limit_bytes": file_size_limit_bytes,
            "file_size_limit_reached": bool(result.file_size_limit_reached),
            "oom_killed": result.oom_killed, "image_id": result.image_id,
            "image_digest": result.image_digest, "argv_identity": result.argv_identity,
            "stdout_truncated": result.stdout_truncated, "stderr_truncated": result.stderr_truncated,
            "stdout_path": result.stdout_path, "stderr_path": result.stderr_path,
            "receipt": artifact(run_root, run_root / result.receipt_path),
            "compile_database": artifact(run_root, compile_database)}


def artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return run_artifact(run_root, path)


class CheckpointIntegrityError(ArtifactIntegrityError):
    """A matching scope checkpoint references accepted evidence that is missing or changed.

    This is a framework-integrity failure: the checkpoint may not be reused, and the loss is not a
    producer gap, so the stale identities it names must never be republished.
    """


def _artifact_identities(value: Any) -> list[Mapping[str, Any]]:
    found: list[Mapping[str, Any]] = []
    if isinstance(value, Mapping):
        if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            found.append(value)
        for child in value.values():
            found.extend(_artifact_identities(child))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(_artifact_identities(child))
    return found


def _dotted(value: Mapping[str, Any], key: str) -> Any:
    for part in key.split("."):
        value = value.get(part) if isinstance(value, Mapping) else None
    return value


def scope_checkpoint(path: Path, identity: str, run_root: Path, scope: IndexScope, *,
                     required: tuple[str, ...] = ()) -> Mapping[str, Any] | None:
    """Return a prior scope result only after re-verifying every run-owned artifact it references.

    ``None`` means no checkpoint applies (absent, older schema, or a different identity) and the
    scope runs. A checkpoint whose identity matches but whose shard, receipt, compile database,
    output, manifest, or any other referenced artifact is missing or altered raises
    :class:`CheckpointIntegrityError`.
    """
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise CheckpointIntegrityError(f"scope checkpoint is not a regular run-owned file: {scope.scope_id}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CheckpointIntegrityError(f"scope checkpoint is unreadable: {scope.scope_id}") from exc
    if not isinstance(document, Mapping) or document.get("schema") != CHECKPOINT_SCHEMA \
            or document.get("identity") != identity:
        return None
    result = document.get("result")
    if not isinstance(result, Mapping) or result.get("scope_id") != scope.scope_id:
        raise CheckpointIntegrityError(f"scope checkpoint names a different scope: {scope.scope_id}")
    if result.get("accepted_compile_database") != dict(scope.compile_database):
        raise CheckpointIntegrityError(f"scope checkpoint compile database is not the accepted one: {scope.scope_id}")
    for key in required:
        value = _dotted(result, key)
        if not isinstance(value, Mapping) or not isinstance(value.get("path"), str):
            raise CheckpointIntegrityError(f"scope checkpoint lacks required artifact {key}: {scope.scope_id}")
    shard = result.get("index_identity")
    if not isinstance(shard, Mapping):
        raise CheckpointIntegrityError(f"scope checkpoint lacks its index identity: {scope.scope_id}")
    try:
        verify_run_artifact(run_root, shard, path_key="relative_path")
        for item in _artifact_identities(result):
            verify_run_artifact(run_root, item)
    except ArtifactIntegrityError as exc:
        raise CheckpointIntegrityError(f"{scope.scope_id}: {exc}") from exc
    return {**result, "checkpoint_reused": True}


def save_scope_checkpoint(path: Path, identity: str, result: Mapping[str, Any]) -> None:
    from appsec_review.storage import atomic_json

    atomic_json(path, {"schema": CHECKPOINT_SCHEMA, "identity": identity, "result": dict(result)})


def checkpoint_identity(values: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(values)).hexdigest()


def publish_scope_indexes(unit: Any, *, job_id: str, index_name: str, prefix: str,
                          results: list[Mapping[str, Any]], unavailable: Mapping[str, str],
                          gaps: list[str]) -> dict[str, Any]:
    """Compose this job's scope shards and a coverage shard onto the accepted manifest.

    Earlier shards from the same job are replaced; every other producer's shards are kept, so
    independent jobs that run in parallel never drop each other's evidence.
    """
    from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
    from appsec_review.retrieval.core import resolve_accepted_manifest

    run_root = unit.job.run_root
    indexes = [IndexIdentity(**{**item["index_identity"], "gaps": tuple(item["index_identity"]["gaps"])})
               for item in results]
    shard = f"{prefix}-coverage-{unit.job.attempt_id}"
    coverage_path = run_root / "data" / "indices" / index_name / f"{shard}.sqlite"
    fingerprint = checkpoint_identity({"schema": "appsec-review/cpp-index-coverage/1", "shard": shard,
                                       "scopes": sorted(item["scope_id"] for item in results),
                                       "unavailable": dict(sorted(unavailable.items()))})
    coverage = IndexBuilder(coverage_path, name=index_name, fingerprint=fingerprint,
                            target_snapshot=unit.job.source_fingerprint, shard_id=shard)
    for case_id, reason in sorted(unavailable.items()):
        coverage.add_coverage(f"{prefix}:{case_id}", "unavailable", reason)
    if not unavailable and not results:
        coverage.add_coverage(prefix, "unavailable", "no accepted C/C++ project scopes")
    coverage_sha = coverage.build()
    indexes.append(IndexIdentity(index_name, "appsec-review/retrieval-index/2", coverage_sha, fingerprint,
                                 coverage_path.relative_to(run_root).as_posix(),
                                 {"job": job_id, "unit": unit.unit_id}, tuple(gaps), shard))
    upstream_path, upstream_sha = resolve_accepted_manifest(run_root)
    upstream, _ = load_verified_manifest(run_root, upstream_path, upstream_sha)
    base = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))}) for item in upstream["indexes"]
            if item.get("producer", {}).get("job") != job_id]
    manifest_path = run_root / "data" / "indices" / "manifests" / f"{prefix}-{unit.job.attempt_id}.json"
    write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=unit.job.target_root or Path(), indexes=[*base, *indexes],
                   upstream_manifests=({"path": upstream_path.relative_to(run_root).as_posix(),
                                        "sha256": upstream_sha},))
    load_verified_manifest(run_root, manifest_path, file_sha256(manifest_path))
    return artifact(run_root, manifest_path)
