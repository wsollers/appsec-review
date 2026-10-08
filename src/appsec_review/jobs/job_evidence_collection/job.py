from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, ExecutionRequest, Mount, load_catalog
from appsec_review.jobs.job_evidence_collection.adapters import (
    Applicability,
    ScanCatalog,
    ToolAdapter,
    adapter_registry,
)
from appsec_review.jobs.job_evidence_collection.evidence import build_envelope
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256
from appsec_review.jobs.job_third_party_data_sync.publication import verify_current


CAPABILITIES: Mapping[str, tuple[str, ...]] = {
    "secrets": ("tool-gitleaks",),
    "source_sast": ("tool-semgrep", "tool-gosec", "tool-mobsfscan", "tool-shellcheck",
                    "tool-phpcs", "tool-phpstan", "tool-psalm", "tool-spotbugs"),
    "software_inventory": ("tool-syft",),
    "vulnerability_matching": ("tool-osv-scanner", "tool-grype"),
    "configuration": ("tool-hadolint", "tool-checkov", "tool-trivy", "tool-zizmor"),
    "binary_hardening": ("tool-blint",),
}
TOPOLOGY: Mapping[str, tuple[str, ...]] = {
    capability: tuple(tool.removeprefix("tool-").replace("-", "_") for tool in tools)
    for capability, tools in CAPABILITIES.items()
}
TOPOLOGY = {**TOPOLOGY, "evidence_publication": ("build_indexes", "publish_handoff")}


ExecutorFactory = Callable[[UnitContext], ContainerExecutor]


def _rel(run_root: Path, path: Path) -> str:
    return path.resolve().relative_to(run_root.resolve()).as_posix()


def _artifact(run_root: Path, path: Path) -> dict[str, Any]:
    return {"path": _rel(run_root, path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


def _read_artifact(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity["path"])).resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError("upstream artifact is missing or outside the run")
    if file_sha256(path) != identity["sha256"]:
        raise ValueError("upstream artifact hash changed")
    return json.loads(path.read_text(encoding="utf-8"))


def load_target_catalog(run_root: Path) -> ScanCatalog:
    latest_path = run_root / "data" / "jobs" / "job_target_catalog" / "latest.json"
    if not latest_path.is_file():
        raise ValueError("accepted job_target_catalog handoff is required")
    latest = json.loads(latest_path.read_text(encoding="utf-8"))
    handoff_path = (run_root / latest["handoff_path"]).resolve()
    if run_root.resolve() not in handoff_path.parents or file_sha256(handoff_path) != latest["handoff_sha256"]:
        raise ValueError("target catalog handoff identity mismatch")
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    if handoff.get("status") != "ACCEPTED" or handoff.get("schema") != "appsec-review/job-handoff/1":
        raise ValueError("target catalog handoff is not accepted")
    published = handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {})
    catalog_doc = _read_artifact(run_root, published["artifact"])
    if catalog_doc.get("schema") != "appsec-review/target-catalog/1":
        raise ValueError("target catalog schema mismatch")
    partition = _read_artifact(run_root, catalog_doc["artifacts"]["repository_discovery.partition_repository"])
    projects = _read_artifact(run_root, catalog_doc["artifacts"]["repository_discovery.discover_projects"])
    builds = _read_artifact(run_root, catalog_doc["artifacts"]["build_discovery.catalog_build_targets"])
    artifacts = tuple(item for item in builds.get("targets", []) if item.get("artifact_kind") == "built")
    return ScanCatalog(
        source_fingerprint=str(catalog_doc["source_fingerprint"]),
        handoff_sha256=str(latest["handoff_sha256"]), files=tuple(partition.get("files", [])),
        projects=tuple(projects.get("projects", [])), artifacts=artifacts,
    )


def plan_applicability(run_root: Path) -> list[dict[str, Any]]:
    catalog = load_target_catalog(run_root)
    return [{"tool_id": tool_id, "capability": adapter.capability,
             **adapter.applicability(catalog).as_dict()}
            for tool_id, adapter in adapter_registry().items()]


def _prerequisites(unit: UnitContext, adapter: ToolAdapter, selection: Applicability) -> tuple[Applicability, tuple[Mount, ...], dict[str, str], str | None]:
    if not selection.applicable:
        return selection, (), {}, None
    mounts: list[Mount] = []
    environment: dict[str, str] = {}
    repository = unit.job.repository_root
    if adapter.tool_id == "tool-semgrep":
        rules = repository / "rules" / "semgrep"
        try:
            lock = json.loads((rules / "rules.lock.json").read_text(encoding="utf-8"))
            expected = lock["files"]["security.yml"]["sha256"]
            verified = lock.get("schema") == "appsec-review/rule-bundle-lock/1" and file_sha256(
                rules / "security.yml") == expected
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            verified = False
        if not verified:
            return selection, (), {}, "hash-pinned Semgrep rule bundle is unavailable"
        mounts.append(Mount(rules, "/rules", True))
    if adapter.tool_id == "tool-osv-scanner":
        try:
            identity = verify_current(unit.job.repository_root / "data" / "feeds" / "osv", "osv")
            source = Path(identity["directory"]) / "sources" / "PyPI.zip"
            database = unit.unit_root / "inputs" / "osv-db" / "osv-scanner" / "PyPI"
            database.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, database / "all.zip")
            mounts.append(Mount(unit.unit_root / "inputs" / "osv-db", "/database", True))
            environment["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = "/database"
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return selection, (), {}, f"verified immutable OSV database snapshot is unavailable ({type(exc).__name__})"
    if adapter.tool_id == "tool-grype":
        try:
            identity = verify_current(unit.job.repository_root / "data" / "feeds" / "grype", "grype")
            mounts.append(Mount(Path(identity["directory"]), "/database", True))
            environment["GRYPE_DB_CACHE_DIR"] = "/database"
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            return selection, (), {}, f"verified immutable Grype database snapshot is unavailable ({type(exc).__name__})"
        syft = unit.output("software_inventory.syft")
        if syft.get("terminal_status") not in {"SUCCEEDED", "PARTIAL"} or not syft.get("scanner_output"):
            return selection, (), {}, "a successful Syft SBOM is required"
        mounts.append(Mount(unit.job.run_root / syft["scanner_output"], "/inputs/syft.json", True))
    return selection, tuple(mounts), environment, None


def _scope_identity(catalog: ScanCatalog, selection: Applicability) -> str:
    hashes = {str(item["path"]): item.get("sha256") for item in catalog.files}
    value = [{"path": path, "sha256": hashes.get(path)} for path in selection.files]
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _extra_identity(mounts: tuple[Mount, ...]) -> dict[str, str]:
    identity: dict[str, str] = {}
    for mount in mounts:
        source = mount.source.resolve()
        if source.is_file():
            identity[mount.target] = file_sha256(source)
        elif source.is_dir():
            digest = hashlib.sha256()
            for path in sorted((item for item in source.rglob("*") if item.is_file()),
                               key=lambda item: item.relative_to(source).as_posix()):
                digest.update(path.relative_to(source).as_posix().encode())
                digest.update(file_sha256(path).encode())
            identity[mount.target] = digest.hexdigest()
    return identity


def _checkpoint_identity(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                         selection: Applicability, image_id: str, mounts: tuple[Mount, ...]) -> str:
    value = {
        "tool_id": adapter.tool_id, "target_fingerprint": catalog.source_fingerprint,
        "catalog_handoff": catalog.handoff_sha256, "scope": _scope_identity(catalog, selection),
        "image_id": image_id, "adapter": adapter.adapter_identity, "parser": adapter.parser_identity,
        "validator": "static-tool-evidence/1", "inputs": _extra_identity(mounts),
        "job_settings": dict(unit.job.config.settings),
        "task_settings": dict(unit.job.config.step(unit.step_id).task(unit.task_id).settings),
    }
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _valid_checkpoint(run_root: Path, path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        for item in value.get("artifacts", []):
            artifact = (run_root / item["path"]).resolve()
            if run_root.resolve() not in artifact.parents or file_sha256(artifact) != item["sha256"]:
                return None
        return value
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        return None


def _write_evidence(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                    selection: Applicability, *, tool_identity: Mapping[str, Any],
                    raw_artifacts: tuple[Path, ...], observations: list[dict[str, Any]],
                    terminal_status: str, gaps: tuple[str, ...]) -> tuple[dict[str, Any], Path]:
    destination = unit.unit_root / "evidence.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    envelope = build_envelope(
        tool=tool_identity, target_fingerprint=catalog.source_fingerprint,
        applicability=selection.as_dict(), coverage_scope={
            "kind": selection.coverage_kind, "paths": list(selection.files),
            "path_count": len(selection.files),
        }, gaps=(*selection.gaps, *adapter.limitations, *gaps), raw_artifacts=raw_artifacts,
        parser_identity=adapter.parser_identity, observations=observations,
        cataloged_paths=catalog.paths, terminal_status=terminal_status, run_root=unit.job.run_root,
    )
    atomic_json(destination, envelope)
    return envelope, destination


def _execute_tool(unit: UnitContext, adapter: ToolAdapter, catalog: ScanCatalog,
                  executor_factory: ExecutorFactory, fail_tool: str | None) -> Mapping[str, Any]:
    selection, mounts, environment, blocked = _prerequisites(unit, adapter, adapter.applicability(catalog))
    if not selection.applicable:
        envelope, path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "disposition": "not_executed"},
            raw_artifacts=(), observations=[], terminal_status="NOT_APPLICABLE", gaps=(selection.reason,),
        )
        return {"tool_id": adapter.tool_id, "capability": adapter.capability,
                "terminal_status": "NOT_APPLICABLE", "checkpoint_reused": False,
                "artifact": _artifact(unit.job.run_root, path), "record_count": 0,
                "gaps": envelope["exclusions_and_gaps"]}
    if blocked is not None:
        envelope, path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "disposition": "blocked"},
            raw_artifacts=(), observations=[], terminal_status="BLOCKED", gaps=(blocked,),
        )
        return {"tool_id": adapter.tool_id, "capability": adapter.capability,
                "terminal_status": "BLOCKED", "checkpoint_reused": False,
                "artifact": _artifact(unit.job.run_root, path), "record_count": 0,
                "gaps": envelope["exclusions_and_gaps"]}

    executor = executor_factory(unit)
    tool = executor.catalog.tool(adapter.tool_id)
    image_id = executor.resolve_image(tool)
    identity = _checkpoint_identity(unit, adapter, catalog, selection, image_id, mounts)
    checkpoint_root = unit.job.run_root / "data" / "task-checkpoints" / "job_evidence_collection" / adapter.tool_id / identity[:24]
    checkpoint_path = checkpoint_root / "checkpoint.json"
    retry_marker = checkpoint_root.parent / "retry-required.json"
    with FileLock(checkpoint_root.parent / (identity[:24] + ".lock")):
        if fail_tool == adapter.tool_id:
            atomic_json(retry_marker, {"schema": "appsec-review/injected-tool-failure/1",
                                      "tool_id": adapter.tool_id, "checkpoint_identity": identity,
                                      "retry_required": True, "failed_attempt": unit.job.attempt_id})
            raise RuntimeError(f"injected bounded failure: {adapter.tool_id}")
        retry_required = False
        if retry_marker.is_file():
            marker = json.loads(retry_marker.read_text(encoding="utf-8"))
            retry_required = bool(marker.get("retry_required")) and marker.get("checkpoint_identity") == identity
        checkpoint = None if retry_required else _valid_checkpoint(unit.job.run_root, checkpoint_path)
        if checkpoint is not None:
            return {**checkpoint["output"], "checkpoint_reused": True,
                    "checkpoint": _artifact(unit.job.run_root, checkpoint_path)}
        scratch = unit.unit_root / "scratch"
        if adapter.tool_id == "tool-trivy":
            staged = scratch / "inputs"
            for relative in selection.files:
                source = (unit.job.target_root or Path()) / relative
                destination = staged / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        result = executor.execute(ExecutionRequest(
            tool_id=adapter.tool_id, argv=adapter.argv(tool.executable, selection),
            target_root=unit.job.target_root or Path(), scratch_root=scratch,
            extra_mounts=mounts, environment=environment,
        ))
        raw_paths = (unit.job.run_root / result.stdout_path, unit.job.run_root / result.stderr_path,
                     unit.job.run_root / result.receipt_path)
        gaps: list[str] = []
        if result.stdout_truncated:
            gaps.append("stdout was truncated at the configured byte bound")
        if result.stderr_truncated:
            gaps.append("stderr was truncated at the configured byte bound")
        if result.timed_out:
            raise RuntimeError(f"{adapter.tool_id} timed out")
        if result.oom_killed:
            raise RuntimeError(f"{adapter.tool_id} was OOM-killed")
        if result.exit_code not in adapter.accepted_exit_codes:
            raise RuntimeError(f"{adapter.tool_id} exited with {result.exit_code}")
        output = scratch / adapter.output_file.removeprefix("/scratch/") if adapter.output_file else raw_paths[0]
        if not output.is_file():
            raise ValueError(f"{adapter.tool_id} did not produce its expected output")
        if output.stat().st_size > tool.output_bytes:
            raise ValueError(f"{adapter.tool_id} output artifact exceeded its byte bound")
        if output not in raw_paths:
            raw_paths = (*raw_paths, output)
        observations = adapter.parse(output.read_bytes())
        terminal = "PARTIAL" if gaps else "SUCCEEDED"
        envelope, evidence_path = _write_evidence(
            unit, adapter, catalog, selection,
            tool_identity={"id": adapter.tool_id, "name": tool.name, "version": tool.version,
                           "image_tag": tool.tag, "image_id": image_id},
            raw_artifacts=raw_paths, observations=observations, terminal_status=terminal, gaps=tuple(gaps),
        )
        output_value = {
            "tool_id": adapter.tool_id, "capability": adapter.capability,
            "terminal_status": terminal, "checkpoint_reused": False,
            "artifact": _artifact(unit.job.run_root, evidence_path),
            "scanner_output": _rel(unit.job.run_root, output),
            "execution": _artifact(unit.job.run_root, unit.job.run_root / result.receipt_path),
            "record_count": envelope["record_count"], "gaps": envelope["exclusions_and_gaps"],
            "checkpoint_identity": identity,
        }
        checkpoint_root.mkdir(parents=True, exist_ok=True)
        atomic_json(checkpoint_path, {
            "schema": "appsec-review/tool-task-checkpoint/1", "identity": identity,
            "output": output_value,
            "artifacts": [output_value["artifact"], output_value["execution"],
                          _artifact(unit.job.run_root, output)],
        })
        if retry_required:
            atomic_json(retry_marker, {"schema": "appsec-review/injected-tool-failure/1",
                                      "tool_id": adapter.tool_id, "checkpoint_identity": identity,
                                      "retry_required": False, "failed_attempt": marker.get("failed_attempt"),
                                      "resolved_attempt": unit.job.attempt_id})
        return {**output_value, "checkpoint": _artifact(unit.job.run_root, checkpoint_path)}


def _build_indexes(unit: UnitContext, tool_units: tuple[str, ...]) -> Mapping[str, Any]:
    indexes: dict[str, dict[str, list[str]]] = {
        key: defaultdict(list) for key in ("path", "rule", "component", "package", "advisory", "language", "evidence_id")
    }
    gaps: list[str] = []
    dispositions: list[dict[str, Any]] = []
    for unit_id in tool_units:
        output = unit.output(unit_id)
        dispositions.append({"tool_id": output["tool_id"], "terminal_status": output["terminal_status"],
                             "checkpoint_reused": output["checkpoint_reused"], "record_count": output["record_count"],
                             "gaps": output.get("gaps", [])})
        evidence = _read_artifact(unit.job.run_root, output["artifact"])
        gaps.extend(str(item) for item in evidence.get("exclusions_and_gaps", []))
        for record in evidence.get("records", []):
            pairs = {
                "path": (record.get("location") or {}).get("path"), "rule": record.get("native_rule_id"),
                "component": record.get("component"), "package": record.get("package"),
                "advisory": record.get("advisory"), "language": record.get("language"),
                "evidence_id": record.get("evidence_id"),
            }
            for kind, value in pairs.items():
                if value is not None and len(indexes[kind][str(value)]) < 500:
                    indexes[kind][str(value)].append(record["evidence_id"])
    document = {
        "schema": "appsec-review/static-evidence-index/1",
        "indexes": {kind: dict(sorted(values.items())) for kind, values in indexes.items()},
        "dispositions": dispositions, "gaps": list(dict.fromkeys(gaps)),
    }
    path = unit.unit_root / "index.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(path, document)
    return {"artifact": _artifact(unit.job.run_root, path), "item_count": sum(
        len(values) for values in document["indexes"].values()), "dispositions": dispositions,
        "gaps": document["gaps"]}


def build_job(*, executor_factory: ExecutorFactory | None = None, fail_tool: str | None = None) -> Job:
    adapters = adapter_registry()
    if set(adapters) != {tool for tools in CAPABILITIES.values() for tool in tools}:
        raise ValueError("enabled static tool disposition is incomplete")

    def validate(context, result) -> None:
        if context.target_root is None:
            raise ValueError("evidence collection requires the graph-provided target root")
        if tuple(context.config.steps) != tuple(TOPOLOGY):
            raise ValueError("evidence collection topology does not match configuration")
        for step, tasks in TOPOLOGY.items():
            if tuple(context.config.step(step).tasks) != tasks:
                raise ValueError(f"evidence collection task order mismatch: {step}")
        catalog = load_catalog(context.repository_root)
        if set(catalog.tools) != set(adapters):
            missing = sorted(set(catalog.tools) - set(adapters))
            extra = sorted(set(adapters) - set(catalog.tools))
            raise ValueError(f"enabled tool/adapter mismatch: missing={missing}, extra={extra}")
        target_catalog = load_target_catalog(context.run_root)
        if context.source_fingerprint != target_catalog.source_fingerprint:
            raise ValueError("graph target fingerprint does not match the accepted target catalog")

    def factory(unit: UnitContext) -> ContainerExecutor:
        if executor_factory is not None:
            return executor_factory(unit)
        return ContainerExecutor(load_catalog(unit.job.repository_root), unit.job.run_root)

    units: list[Unit] = []
    tool_units: list[str] = []
    for capability, tool_ids in CAPABILITIES.items():
        for tool_id in tool_ids:
            adapter = adapters[tool_id]
            unit_id = f"{capability}.{tool_id.removeprefix('tool-').replace('-', '_')}"
            dependencies = ("software_inventory.syft",) if tool_id == "tool-grype" else ()
            def handler(unit: UnitContext, selected: ToolAdapter = adapter) -> Mapping[str, Any]:
                return _execute_tool(unit, selected, load_target_catalog(unit.job.run_root), factory, fail_tool)
            units.append(Unit(unit_id, handler, dependencies))
            tool_units.append(unit_id)

    tool_dependencies = tuple(tool_units)
    units.append(Unit("evidence_publication.build_indexes",
                      lambda unit: _build_indexes(unit, tool_dependencies), tool_dependencies))

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        index = unit.output("evidence_publication.build_indexes")
        document = {
            "schema": "appsec-review/evidence-collection-handoff/1",
            "target_fingerprint": unit.job.source_fingerprint,
            "index": index["artifact"], "dispositions": index["dispositions"],
            "gaps": index["gaps"], "security_findings": [],
        }
        path = unit.unit_root / "handoff.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json(path, document)
        return {"schema": document["schema"], "artifact": _artifact(unit.job.run_root, path),
                "item_count": index["item_count"], "gaps": document["gaps"],
                "dispositions": document["dispositions"]}

    units.append(Unit("evidence_publication.publish_handoff", publish,
                      ("evidence_publication.build_indexes",)))
    source_files = (Path(__file__), Path(__file__).with_name("adapters.py"), Path(__file__).with_name("evidence.py"))
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in source_files) + str(fail_tool).encode()).hexdigest()

    def runtime_identity() -> str:
        root = Path(os.environ.get("APPSEC_REVIEW_CONFIG", "appsec-review.toml")).resolve().parent
        catalog = load_catalog(root)
        paths = [root / "containers" / "catalog.toml", root / "containers" / "runtime-policy.toml",
                 root / "rules" / "semgrep" / "security.yml", root / "rules" / "semgrep" / "rules.lock.json",
                 root / "data" / "feeds" / "osv" / "current.json",
                 root / "data" / "feeds" / "grype" / "current.json",
                 *(tool.manifest_path for tool in catalog.tools.values())]
        digest = hashlib.sha256()
        for path in paths:
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes() if path.is_file() else b"MISSING")
        if executor_factory is None:
            for tool_id in sorted(catalog.tools):
                tool = catalog.tool(tool_id)
                inspected = subprocess.run(
                    ["docker", "image", "inspect", tool.tag, "--format", "{{.Id}}"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
                )
                if inspected.returncode != 0:
                    raise RuntimeError(f"cannot resolve runtime identity for {tool_id}")
                digest.update(tool_id.encode())
                digest.update(inspected.stdout.strip().encode())
        else:
            digest.update(b"injected-executor")
        return digest.hexdigest()

    return Job("job_evidence_collection", "evidence_collection", UnitExecutor(tuple(units)).execute,
               input_validators=(validate,), schema_identity="appsec-review/evidence-collection-job/1",
               implementation_identity=implementation,
               validation_identity=hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest(),
               runtime_identity=runtime_identity)
