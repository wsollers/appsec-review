from __future__ import annotations

from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time
from typing import Any

from appsec_review.container_runtime import ContainerExecutor, load_catalog
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import atomic_json, file_sha256

from .model import GrammarLock, partition_scopes, plan_scopes
from .normalize import NORMALIZER_SCHEMA
from .scope_execution import parse_scope


TOPOLOGY = {
    "load": ("accepted_inputs",),
    "plan": ("route_scopes",),
    "parse": ("dynamic_scopes",),
    "acceptance": ("publish_handoff",),
}
SCHEMA = "appsec-review/tree-sitter-ast/1"
ExecutorFactory = Callable[[UnitContext], ContainerExecutor]


def _read_verified(run_root: Path, identity: Mapping[str, Any]) -> Mapping[str, Any]:
    path = (run_root / str(identity.get("path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError("accepted upstream artifact is unavailable or outside the run")
    if file_sha256(path) != identity.get("sha256"):
        raise ValueError("accepted upstream artifact hash changed")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("accepted upstream artifact must be an object")
    return value


def _accepted_handoff(run_root: Path, job_id: str) -> tuple[Mapping[str, Any], str]:
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file():
        raise ValueError(f"accepted {job_id} handoff is required")
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff = _read_verified(run_root, {"path": pointer["handoff_path"], "sha256": pointer["handoff_sha256"]})
    if handoff.get("schema") != "appsec-review/job-handoff/1" or handoff.get("status") != "ACCEPTED":
        raise ValueError(f"{job_id} handoff is not accepted")
    return handoff, str(pointer["handoff_sha256"])


def _load_inputs(run_root: Path) -> Mapping[str, Any]:
    intake_handoff, intake_sha = _accepted_handoff(run_root, "job_review_intake")
    catalog_handoff, catalog_sha = _accepted_handoff(run_root, "job_target_catalog")
    intake_identity = intake_handoff.get("outputs", {}).get("publish_intake.publish_handoff", {}).get("artifact", {})
    catalog_identity = catalog_handoff.get("outputs", {}).get("publish_catalog.publish_handoff", {}).get("artifact", {})
    intake = _read_verified(run_root, intake_identity)
    catalog_root = _read_verified(run_root, catalog_identity)
    if intake.get("schema") != "appsec-review/review-intake/1" or catalog_root.get("schema") != "appsec-review/target-catalog/1":
        raise ValueError("accepted Tree-sitter inputs use unsupported schemas")
    artifacts = catalog_root.get("artifacts", {})
    partition = _read_verified(run_root, artifacts["repository_discovery.partition_repository"])
    components = _read_verified(run_root, artifacts["component_discovery.catalog_components"])
    builds = _read_verified(run_root, artifacts["build_discovery.catalog_build_targets"])
    if catalog_root.get("source_fingerprint") != intake.get("fingerprint", {}).get("sha256"):
        raise ValueError("target snapshot and catalog identities disagree")
    return {"source_fingerprint": catalog_root["source_fingerprint"], "files": partition.get("files", ()),
            "gaps": partition.get("gaps", ()), "components": components.get("components", ()),
            "build_units": builds.get("targets", ()), "intake_handoff_sha256": intake_sha,
            "catalog_handoff_sha256": catalog_sha}


def _grammar_locks(repository_root: Path) -> tuple[Mapping[str, GrammarLock], Mapping[str, Any]]:
    path = repository_root / "containers" / "tools" / "tree-sitter" / "assets.lock.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != "appsec-review/assets-lock/1" or document.get("image_id") != "tool-tree-sitter":
        raise ValueError("Tree-sitter asset lock identity is invalid")
    values = {item["language"]: GrammarLock(**{key: item[key] for key in GrammarLock.__slots__})
              for item in document.get("grammars", ())}
    values["C/C++"] = values["C++"]
    return values, document


def _validate(context, _result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("Tree-sitter AST topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"Tree-sitter AST task order mismatch: {step}")
    settings = context.config.settings
    for key in ("workers", "max_file_bytes", "max_nodes_per_file", "max_nodes_per_scope",
                "max_files_per_scope", "max_source_bytes_per_scope"):
        if type(settings.get(key)) is not int or int(settings[key]) < 1:
            raise ValueError(f"Tree-sitter setting is invalid: {key}")
    if (settings["workers"] > 32 or settings["max_file_bytes"] > 16 * 1024 * 1024 or
        settings["max_files_per_scope"] > 1024 or
        settings["max_source_bytes_per_scope"] > 128 * 1024 * 1024 or
        settings["max_nodes_per_file"] > 500_000 or settings["max_nodes_per_scope"] > 500_000):
        raise ValueError("Tree-sitter bounds exceed the production ceiling")


def build_job(*, executor_factory: ExecutorFactory | None = None) -> Job:
    def load(unit: UnitContext) -> Mapping[str, Any]:
        accepted = _load_inputs(unit.job.run_root)
        if accepted["source_fingerprint"] != unit.job.source_fingerprint:
            raise ValueError("graph target fingerprint does not match accepted inputs")
        locks, asset_lock = _grammar_locks(unit.job.repository_root)
        catalog = load_catalog(unit.job.repository_root)
        executor = executor_factory(unit) if executor_factory else ContainerExecutor(catalog, unit.job.run_root)
        image_id = executor.resolve_image(catalog.tool("tool-tree-sitter"))
        unit.job.events.write("TREE_SITTER_AST_STARTED", image_id=image_id,
                              catalog_handoff_sha256=accepted["catalog_handoff_sha256"])
        return {"accepted": accepted, "grammar_locks": {key: asdict(value) for key, value in locks.items()},
                "asset_lock": asset_lock, "image_id": image_id}

    def route(unit: UnitContext) -> Mapping[str, Any]:
        loaded = unit.output("load.accepted_inputs")
        settings = unit.job.config.settings
        scopes = plan_scopes(loaded["accepted"], max_files_per_scope=int(settings["max_files_per_scope"]),
                             max_source_bytes_per_scope=int(settings["max_source_bytes_per_scope"]))
        locks = loaded["grammar_locks"]
        runnable, gaps = partition_scopes(scopes, {key: GrammarLock(**value) for key, value in locks.items()})
        retained = {str(item.get("path")) for scope in scopes for item in scope.exclusions}
        orphaned = [item for item in loaded["accepted"]["gaps"]
                    if item.get("reason") in {"excluded_directory", "generated_file_excluded", "file_too_large"}
                    and str(item.get("path")) not in retained]
        if orphaned:
            gaps = (*gaps, {"scope_id": "catalog-exclusions", "language": "n/a",
                            "terminal_status": "UNAVAILABLE",
                            "reason": "accepted exclusions outside source scopes",
                            "gaps": [f"{item.get('path')}: {item.get('reason')}" for item in orphaned]})
        values = [asdict(scope) for scope in runnable]
        return {"scopes": values, "gaps": gaps, "scope_count": len(scopes),
                "runnable_scope_count": len(values),
                "terminal_status": "PARTIAL" if gaps else "SUCCEEDED"}

    def parse_scopes(unit: UnitContext) -> Mapping[str, Any]:
        planned = unit.output("plan.route_scopes")
        results: list[Mapping[str, Any]] = []
        dynamic_root = unit.unit_root / "dynamic"
        dynamic = [dynamic_root / f"{scope['scope_id']}.json" for scope in planned["scopes"]]
        if dynamic and all(path.is_file() for path in dynamic):
            results = [json.loads(path.read_text(encoding="utf-8")) for path in dynamic]
        else:
            workers = min(int(unit.job.config.settings["workers"]), max(1, len(planned["scopes"])))
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tree-sitter-scope") as pool:
                starts = {}
                futures = []
                for scope in planned["scopes"]:
                    future = pool.submit(parse_scope, unit, scope, executor_factory)
                    starts[future] = time.monotonic_ns()
                    futures.append(future)
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
                    counts = result.get("counts", {})
                    unit.job.events.write("TREE_SITTER_SCOPE_COMPLETED", scope_id=result["scope_id"],
                        language=result["language"], disposition=result["terminal_status"],
                        duration_ms=(time.monotonic_ns() - starts[future]) // 1_000_000,
                        files_parsed=counts.get("files_parsed", 0),
                        bytes_parsed=counts.get("bytes_parsed", 0), nodes_parsed=counts.get("nodes_parsed", 0),
                        errors=counts.get("diagnostic_count", 0), gaps=len(result.get("gaps", ())),
                        reused=bool(result.get("index_reused")))
        results.sort(key=lambda value: str(value["scope_id"]))
        dispositions = [*planned["gaps"], *results]
        gaps = [gap for value in dispositions for gap in value.get("gaps", ())]
        gaps.extend(value["reason"] for value in planned["gaps"])
        gaps = sorted(set(gaps))
        terminal = "PARTIAL" if any(value.get("terminal_status") != "SUCCEEDED" for value in dispositions) else "SUCCEEDED"
        return {"dispositions": dispositions, "gaps": gaps, "terminal_status": terminal,
                "scope_count": planned["scope_count"], "successful_scope_count": sum(
                    value.get("terminal_status") in {"SUCCEEDED", "PARTIAL"} and "index_identity" in value for value in results)}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        parsed = unit.output("parse.dynamic_scopes")
        successful = [value for value in parsed["dispositions"] if "index_identity" in value]
        indexes = [IndexIdentity(**{**value["index_identity"],
                                    "gaps": tuple(value["index_identity"].get("gaps", ()))}) for value in successful]
        coverage_fingerprint = hashlib.sha256(json.dumps({
            "schema": SCHEMA, "attempt_id": unit.job.attempt_id,
            "target_snapshot": unit.job.source_fingerprint, "dispositions": parsed["dispositions"],
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        coverage_path = (unit.job.run_root / "data" / "indices" / "analysis" /
                         f"tree-sitter-coverage-{unit.job.attempt_id}.sqlite")
        coverage = IndexBuilder(coverage_path, name="analysis", fingerprint=coverage_fingerprint,
                                target_snapshot=unit.job.source_fingerprint,
                                shard_id=f"tree-sitter-coverage-{unit.job.attempt_id}")
        for value in parsed["dispositions"]:
            status = ("complete" if value.get("terminal_status") == "SUCCEEDED" else
                      "partial" if "index_identity" in value else "unavailable")
            detail = "; ".join(value.get("gaps", ())) or value.get("reason")
            coverage.add_coverage(str(value["scope_id"]), status, detail)
        coverage_sha = coverage.build()
        indexes.append(IndexIdentity("analysis", "appsec-review/retrieval-index/2", coverage_sha,
            coverage_fingerprint, coverage_path.relative_to(unit.job.run_root).as_posix(),
            {"job": "job_tree_sitter_ast", "unit": unit.unit_id}, tuple(parsed["gaps"]),
            f"tree-sitter-coverage-{unit.job.attempt_id}"))
        upstream_path, upstream_sha = resolve_accepted_manifest(unit.job.run_root)
        upstream, _ = load_verified_manifest(unit.job.run_root, upstream_path, upstream_sha)
        base = [IndexIdentity(**{**item, "gaps": tuple(item.get("gaps", ()))})
                for item in upstream["indexes"]
                if item.get("producer", {}).get("job") != "job_tree_sitter_ast"]
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / f"tree-sitter-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
            target_root=unit.job.target_root or Path(), indexes=[*base, *indexes],
            upstream_manifests=({"path": upstream_path.relative_to(unit.job.run_root).as_posix(),
                                 "sha256": upstream_sha},))
        load_verified_manifest(unit.job.run_root, manifest_path, file_sha256(manifest_path))
        manifest = {"path": manifest_path.relative_to(unit.job.run_root).as_posix(),
                    "sha256": file_sha256(manifest_path), "size_bytes": manifest_path.stat().st_size}
        counts = {key: sum(int(value.get("counts", {}).get(key, 0)) for value in successful)
                  for key in ("files_parsed", "bytes_parsed", "nodes_parsed", "diagnostic_count")}
        document = {"schema": SCHEMA, "target_snapshot": unit.job.source_fingerprint,
                    "image_id": unit.output("load.accepted_inputs")["image_id"],
                    "asset_lock": unit.output("load.accepted_inputs")["asset_lock"],
                    "normalizer_schema": NORMALIZER_SCHEMA, "dispositions": parsed["dispositions"],
                    "counts": counts, "gaps": parsed["gaps"], "index_manifest": manifest,
                    "terminal_status": parsed["terminal_status"]}
        artifact_path = unit.unit_root / "accepted-tree-sitter-ast.json"
        atomic_json(artifact_path, document)
        artifact = {"path": artifact_path.relative_to(unit.job.run_root).as_posix(),
                    "sha256": file_sha256(artifact_path), "size_bytes": artifact_path.stat().st_size}
        unit.job.events.write("TREE_SITTER_AST_COMPLETED", **counts, gap_count=len(parsed["gaps"]),
                              successful_scope_count=parsed["successful_scope_count"],
                              scope_count=parsed["scope_count"])
        return {"schema": SCHEMA, "artifact": artifact, "index_manifest": manifest,
                "item_count": counts["nodes_parsed"], "gaps": parsed["gaps"],
                "dispositions": parsed["dispositions"], "terminal_status": parsed["terminal_status"]}

    units = (
        Unit("load.accepted_inputs", load),
        Unit("plan.route_scopes", route, ("load.accepted_inputs",)),
        Unit("parse.dynamic_scopes", parse_scopes, ("load.accepted_inputs", "plan.route_scopes")),
        Unit("acceptance.publish_handoff", publish, ("load.accepted_inputs", "parse.dynamic_scopes")),
    )
    implementation = hashlib.sha256(b"".join(path.read_bytes() for path in sorted(Path(__file__).parent.glob("*.py"))) +
                                    (b"custom-executor" if executor_factory else b"container-only")).hexdigest()
    return Job("job_tree_sitter_ast", "tree_sitter_ast", UnitExecutor(units).execute,
               input_validators=(_validate,), schema_identity=SCHEMA,
               implementation_identity=implementation, units=units)
