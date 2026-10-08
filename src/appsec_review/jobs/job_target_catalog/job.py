from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.jobs.cataloging import BUILD_FILES, PROJECT_FILES, inventory, write_json
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.storage import file_sha256


TOPOLOGY = {
    "repository_discovery": ("partition_repository", "census_languages", "discover_projects"),
    "build_discovery": ("discover_build_systems", "discover_compile_commands", "catalog_build_targets"),
    "component_discovery": ("catalog_components", "catalog_dependencies"),
    "retrieval_indexes": ("build_path_index", "build_symbol_index", "build_component_index"),
    "publish_catalog": ("validate_catalog", "publish_handoff"),
}


def _target(unit: UnitContext) -> Path:
    if unit.job.target_root is None:
        raise ValueError("review target is required")
    return unit.job.target_root


def _artifact(unit: UnitContext, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    path = unit.job.attempt_root / "artifacts" / "catalog" / name
    identity = write_json(path, value)
    identity["path"] = path.relative_to(unit.job.run_root).as_posix()
    return identity


def _run_artifact(unit: UnitContext, path: Path) -> dict[str, Any]:
    return {"path": path.relative_to(unit.job.run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _fingerprint(unit: UnitContext, name: str, artifacts: list[Mapping[str, Any]]) -> str:
    return index_fingerprint(
        name=name, target_snapshot=unit.job.source_fingerprint, producer_artifacts=artifacts,
        tool_identity={"producer": "job_target_catalog"}, parser_identity="catalog-parser/1",
        normalizer_identity="retrieval-normalizer/1", mapping_identity="source-map/1",
    )


def _gap_text(value: Any) -> str:
    """Render producer-owned gap data for retrieval metadata deterministically."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        path = value.get("path")
        reason = value.get("reason")
        if path is not None and reason is not None:
            return f"{path}: {reason}"
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _validate_config(context, result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise ValueError("target catalog topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise ValueError(f"target catalog task order mismatch: {step}")


def build_job(*, fail_task: str | None = None) -> Job:
    def maybe_fail(unit: UnitContext) -> None:
        if unit.unit_id == fail_task:
            raise RuntimeError(f"injected bounded failure: {fail_task}")

    def partition(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        snapshot = inventory(_target(unit))
        groups = Counter(item["path"].split("/", 1)[0] for item in snapshot["files"])
        doc = {"schema": "appsec-review/repository-partition/1", "source_fingerprint": unit.job.source_fingerprint,
               "partitions": [{"path": key, "file_count": groups[key]} for key in sorted(groups)],
               **snapshot}
        return {"artifact": _artifact(unit, "repository-partition.json", doc),
                "files": snapshot["files"], "gaps": snapshot["gaps"]}

    def census(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        counts = Counter(item["language"] or "Other" for item in unit.output("repository_discovery.partition_repository")["files"])
        doc = {"schema": "appsec-review/language-census/1",
               "languages": [{"language": key, "file_count": counts[key]} for key in sorted(counts)]}
        return {"artifact": _artifact(unit, "language-census.json", doc), **doc}

    def projects(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        found = []
        for item in unit.output("repository_discovery.partition_repository")["files"]:
            path = Path(item["path"])
            if path.name in PROJECT_FILES or path.suffix in {".csproj", ".sln"}:
                found.append({"manifest": item["path"], "root": path.parent.as_posix(), "sha256": item["sha256"]})
        doc = {"schema": "appsec-review/project-catalog/1", "projects": found,
               "gaps": [] if found else ["no recognized project manifests"]}
        return {"artifact": _artifact(unit, "projects.json", doc), **doc}

    def build_systems(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        systems = []
        for item in unit.output("repository_discovery.partition_repository")["files"]:
            name = Path(item["path"]).name
            if name in BUILD_FILES or name in PROJECT_FILES or Path(item["path"]).suffix in {".csproj", ".sln"}:
                systems.append({"path": item["path"], "kind": name, "sha256": item["sha256"]})
        doc = {"schema": "appsec-review/build-systems/1", "systems": systems,
               "gaps": [] if systems else ["no recognized build system"]}
        return {"artifact": _artifact(unit, "build-systems.json", doc), **doc}

    def compile_commands(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        commands = [item for item in unit.output("repository_discovery.partition_repository")["files"]
                    if Path(item["path"]).name == "compile_commands.json"]
        doc = {"schema": "appsec-review/compile-commands/1", "files": commands,
               "gaps": [] if commands else ["compile_commands.json not present"]}
        return {"artifact": _artifact(unit, "compile-commands.json", doc), **doc}

    def build_targets(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        targets = [{"id": f"build:{index:04d}", **item} for index, item in enumerate(
            unit.output("build_discovery.discover_build_systems")["systems"], 1)]
        doc = {"schema": "appsec-review/build-targets/1", "targets": targets,
               "gaps": unit.output("build_discovery.discover_build_systems")["gaps"]}
        return {"artifact": _artifact(unit, "build-targets.json", doc), **doc}

    def components(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        projects_value = unit.output("repository_discovery.discover_projects")["projects"]
        components_value = [{"component_id": f"component:{index:04d}", "root": project["root"],
                             "manifest": project["manifest"], "manifest_sha256": project["sha256"]}
                            for index, project in enumerate(projects_value, 1)]
        if not components_value:
            components_value = [{"component_id": "component:0001", "root": ".", "manifest": None,
                                 "manifest_sha256": None}]
        doc = {"schema": "appsec-review/component-catalog/1", "components": components_value, "gaps": []}
        return {"artifact": _artifact(unit, "components.json", doc), **doc}

    def dependencies(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        records = []
        gaps = []
        for component in unit.output("component_discovery.catalog_components")["components"]:
            manifest = component["manifest"]
            if not manifest:
                gaps.append(f"{component['component_id']}: no manifest for dependency extraction")
                continue
            path = _target(unit) / manifest
            try:
                if path.name == "package.json":
                    value = json.loads(path.read_text(encoding="utf-8"))
                    for section in ("dependencies", "devDependencies"):
                        for name, version in sorted(value.get(section, {}).items()):
                            records.append({"component_id": component["component_id"], "name": name,
                                            "constraint": str(version), "source": manifest, "location": section})
                else:
                    gaps.append(f"{manifest}: dependency parser deferred for this manifest type")
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                gaps.append(f"{manifest}: parse failed ({type(exc).__name__})")
        doc = {"schema": "appsec-review/dependency-catalog/1", "dependencies": records, "gaps": gaps}
        return {"artifact": _artifact(unit, "dependencies.json", doc), **doc}

    def path_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        partition = unit.output("repository_discovery.partition_repository")
        fingerprint = _fingerprint(unit, "source", [partition["artifact"]])
        path = unit.job.run_root / "data" / "indices" / "source" / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="source", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint)
        gaps = [_gap_text(gap) for gap in partition["gaps"]]
        for item in partition["files"]:
            identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                              {"path": item["path"], "sha256": item["sha256"]})
            source = _target(unit) / item["path"]
            text = ""
            line_count = 1
            if item["language"] is not None and item["size_bytes"] <= 16 * 1024 * 1024:
                try:
                    text = source.read_text(encoding="utf-8")
                    line_count = max(1, len(text.splitlines()))
                except (OSError, UnicodeError):
                    gaps.append(f"{item['path']}: text decode failed")
            location = SourceLocation(
                target_snapshot=unit.job.source_fingerprint, path=item["path"], file_sha256=item["sha256"],
                start_byte=0, end_byte=item["size_bytes"], start_line=1, end_line=line_count,
                start_column=1, end_column=1, producer_location={"inventory_path": item["path"]},
                mapping_method="inventory-exact", confidence=1.0,
            )
            builder.add_entity(EntityRecord(identity, item["path"], item["path"], text,
                                             {"language": item["language"], "size_bytes": item["size_bytes"]}, location))
        builder.add_coverage("target-files", "complete" if not gaps else "partial",
                             None if not gaps else "; ".join(gaps[:10]))
        sha256 = builder.build()
        index = IndexIdentity("source", "appsec-review/retrieval-index/1", sha256, fingerprint,
                              path.relative_to(unit.job.run_root).as_posix(),
                              {"job": "job_target_catalog", "unit": unit.unit_id}, tuple(gaps))
        return {"artifact": _run_artifact(unit, path), "index_identity": asdict(index),
                "item_count": len(partition["files"]), "gaps": gaps}

    def symbol_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        symbols = []
        gaps = []
        partition = unit.output("repository_discovery.partition_repository")
        fingerprint = _fingerprint(unit, "analysis", [partition["artifact"]])
        path = unit.job.run_root / "data" / "indices" / "analysis" / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint)
        pattern = re.compile(r"^\s*(?:def|class|function|func|interface|struct|enum)\s+([A-Za-z_$][\w$]*)")
        for item in partition["files"]:
            if item["generated"] or item["language"] is None:
                continue
            path = _target(unit) / item["path"]
            try:
                offset = 0
                for number, line in enumerate(path.read_text(encoding="utf-8", errors="strict").splitlines(keepends=True), 1):
                    match = pattern.match(line)
                    if match:
                        symbol_id = LogicalIdentity.derive(EntityKind.SYMBOL, unit.job.source_fingerprint,
                                                           {"path": item["path"], "line": number, "name": match.group(1)})
                        file_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                                         {"path": item["path"], "sha256": item["sha256"]})
                        location = SourceLocation(
                            target_snapshot=unit.job.source_fingerprint, path=item["path"], file_sha256=item["sha256"],
                            start_byte=offset, end_byte=offset + len(line.encode()), start_line=number, end_line=number,
                            start_column=match.start(1) + 1, end_column=match.end(1) + 1,
                            producer_location={"parser": "bounded-declaration-pattern", "line": number},
                            mapping_method="source-line-exact", confidence=1.0,
                        )
                        builder.add_entity(EntityRecord(symbol_id, match.group(1), match.group(1), line.rstrip(),
                                                        {"language": item["language"]}, location))
                        builder.add_relation(RelationRecord(RelationKind.DEFINES, file_id.value,
                                                            symbol_id.value, True, 1.0))
                        symbols.append(symbol_id.value)
                    if len(symbols) >= 50_000:
                        gaps.append("symbol index bound reached")
                        break
                    offset += len(line.encode())
            except (OSError, UnicodeError):
                gaps.append(f"{item['path']}: text decode failed")
            if len(symbols) >= 50_000:
                break
        builder.add_coverage("declarations", "complete" if not gaps else "partial",
                             None if not gaps else "; ".join(gaps[:10]))
        index_path = builder.path
        sha256 = builder.build()
        index = {"name": "analysis", "schema": "appsec-review/retrieval-index/1", "sha256": sha256,
                 "fingerprint": fingerprint, "relative_path": index_path.relative_to(unit.job.run_root).as_posix(),
                 "producer": {"job": "job_target_catalog", "unit": unit.unit_id}, "gaps": gaps}
        return {"artifact": _run_artifact(unit, index_path), "index_identity": index,
                "item_count": len(symbols), "gaps": gaps}

    def component_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        items = unit.output("component_discovery.catalog_components")["components"]
        artifact = unit.output("component_discovery.catalog_components")["artifact"]
        fingerprint = _fingerprint(unit, "components", [artifact])
        path = unit.job.run_root / "data" / "indices" / "components" / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="components", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint)
        for item in items:
            identity = LogicalIdentity.derive(EntityKind.COMPONENT, unit.job.source_fingerprint,
                                              {"component_id": item["component_id"], "manifest": item["manifest"]})
            builder.add_entity(EntityRecord(identity, item["component_id"], item["component_id"],
                                             " ".join(str(value) for value in item.values() if value), item))
        builder.add_coverage("components", "complete")
        sha256 = builder.build()
        index = {"name": "components", "schema": "appsec-review/retrieval-index/1", "sha256": sha256,
                 "fingerprint": fingerprint, "relative_path": path.relative_to(unit.job.run_root).as_posix(),
                 "producer": {"job": "job_target_catalog", "unit": unit.unit_id}, "gaps": []}
        return {"artifact": _run_artifact(unit, path), "index_identity": index,
                "item_count": len(items), "gaps": []}

    def validate_catalog(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        required = ("retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index",
                    "retrieval_indexes.build_component_index")
        for dependency in required:
            artifact = unit.output(dependency)["artifact"]
            path = unit.job.run_root / artifact["path"]
            from appsec_review.storage import file_sha256
            if not path.is_file() or file_sha256(path) != artifact["sha256"]:
                raise ValueError(f"catalog artifact failed validation: {dependency}")
        return {"status": "VALID", "validated": list(required),
                "gaps": sum((list(unit.output(item)["gaps"]) for item in required), [])}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        outputs = {key: unit.output(key)["artifact"] for key in (
            "repository_discovery.partition_repository", "repository_discovery.census_languages",
            "repository_discovery.discover_projects", "build_discovery.discover_build_systems",
            "build_discovery.discover_compile_commands", "build_discovery.catalog_build_targets",
            "component_discovery.catalog_components", "component_discovery.catalog_dependencies",
            "retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index",
            "retrieval_indexes.build_component_index")}
        build_inputs = [unit.output("build_discovery.discover_build_systems")["artifact"],
                        unit.output("build_discovery.discover_compile_commands")["artifact"],
                        unit.output("build_discovery.catalog_build_targets")["artifact"]]
        build_fingerprint = _fingerprint(unit, "build", build_inputs)
        build_path = unit.job.run_root / "data" / "indices" / "build" / f"{build_fingerprint}.sqlite"
        build_index = IndexBuilder(build_path, name="build", fingerprint=build_fingerprint,
                                   target_snapshot=unit.job.source_fingerprint)
        targets = unit.output("build_discovery.catalog_build_targets")["targets"]
        for target in targets:
            identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                                              {"id": target["id"], "path": target.get("path")})
            build_index.add_entity(EntityRecord(identity, target["id"], target.get("kind", target["id"]),
                                                " ".join(str(value) for value in target.values()), target))
        build_gaps = list(unit.output("build_discovery.catalog_build_targets")["gaps"])
        compile_files = unit.output("build_discovery.discover_compile_commands")["files"]
        for item in compile_files:
            identity = LogicalIdentity.derive(EntityKind.COMPILE_UNIT, unit.job.source_fingerprint,
                                              {"path": item["path"], "sha256": item["sha256"]})
            build_index.add_entity(EntityRecord(identity, item["path"], item["path"], item["path"],
                                                {"compile_database_sha256": item["sha256"]}))
        build_index.add_coverage("build-actions", "complete" if targets else "partial",
                                 None if targets else "no build targets discovered")
        build_index.add_coverage("compile-units", "complete" if compile_files else "unavailable",
                                 None if compile_files else "compile_commands.json not present")
        build_sha = build_index.build()
        build_identity = {"name": "build", "schema": "appsec-review/retrieval-index/1", "sha256": build_sha,
                          "fingerprint": build_fingerprint,
                          "relative_path": build_path.relative_to(unit.job.run_root).as_posix(),
                          "producer": {"job": "job_target_catalog", "unit": unit.unit_id},
                          "gaps": build_gaps}
        indexes = [IndexIdentity(**{**unit.output(name)["index_identity"],
                                   "gaps": tuple(unit.output(name)["index_identity"].get("gaps", ()))})
                   for name in ("retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index",
                                "retrieval_indexes.build_component_index")]
        indexes.append(IndexIdentity(**{**build_identity, "gaps": tuple(build_gaps)}))
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / f"catalog-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=_target(unit), indexes=indexes)
        doc = {"schema": "appsec-review/target-catalog/1", "source_fingerprint": unit.job.source_fingerprint,
               "artifacts": outputs, "validation": unit.output("publish_catalog.validate_catalog"),
               "security_findings": []}
        return {"schema": doc["schema"], "artifact": _artifact(unit, "target-catalog.json", doc),
                "index_manifest": _run_artifact(unit, manifest_path),
                "gaps": doc["validation"]["gaps"] + build_gaps}

    u = Unit
    units = (
        u("repository_discovery.partition_repository", partition),
        u("repository_discovery.census_languages", census, ("repository_discovery.partition_repository",)),
        u("repository_discovery.discover_projects", projects, ("repository_discovery.partition_repository",)),
        u("build_discovery.discover_build_systems", build_systems, ("repository_discovery.partition_repository",)),
        u("build_discovery.discover_compile_commands", compile_commands, ("repository_discovery.partition_repository",)),
        u("build_discovery.catalog_build_targets", build_targets, ("build_discovery.discover_build_systems", "build_discovery.discover_compile_commands")),
        u("component_discovery.catalog_components", components, ("repository_discovery.discover_projects",)),
        u("component_discovery.catalog_dependencies", dependencies, ("component_discovery.catalog_components",)),
        u("retrieval_indexes.build_path_index", path_index, ("repository_discovery.partition_repository",)),
        u("retrieval_indexes.build_symbol_index", symbol_index, ("repository_discovery.partition_repository",)),
        u("retrieval_indexes.build_component_index", component_index, ("component_discovery.catalog_components",)),
        u("publish_catalog.validate_catalog", validate_catalog, ("retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index", "retrieval_indexes.build_component_index")),
        u("publish_catalog.publish_handoff", publish, ("publish_catalog.validate_catalog", "build_discovery.catalog_build_targets", "component_discovery.catalog_dependencies")),
    )
    implementation = hashlib.sha256(Path(__file__).read_bytes() +
        Path(__file__).parents[1].joinpath("cataloging.py").read_bytes() + str(fail_task).encode()).hexdigest()
    validation = hashlib.sha256(Path(__file__).read_bytes() + b"validation").hexdigest()
    return Job("job_target_catalog", "target_catalog", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity="appsec-review/target-catalog-job/1",
               implementation_identity=implementation, validation_identity=validation)
