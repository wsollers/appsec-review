from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.jobs.cataloging import BUILD_FILES, PROJECT_FILES, inventory, write_json
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor


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
        items = [{"source_id": item["sha256"], "path": item["path"], "start_line": 1, "end_line": 1,
                  "language": item["language"], "size_bytes": item["size_bytes"]}
                 for item in unit.output("repository_discovery.partition_repository")["files"]]
        doc = {"schema": "appsec-review/path-index/1", "items": items,
               "gaps": unit.output("repository_discovery.partition_repository")["gaps"]}
        return {"artifact": _artifact(unit, "path-index.json", doc), "item_count": len(items), "gaps": doc["gaps"]}

    def symbol_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        symbols = []
        gaps = []
        pattern = re.compile(r"^\s*(?:def|class|function|func|interface|struct|enum)\s+([A-Za-z_$][\w$]*)")
        for item in unit.output("repository_discovery.partition_repository")["files"]:
            if item["generated"] or item["language"] is None:
                continue
            path = _target(unit) / item["path"]
            try:
                for number, line in enumerate(path.read_text(encoding="utf-8", errors="strict").splitlines(), 1):
                    match = pattern.match(line)
                    if match:
                        symbols.append({"symbol": match.group(1), "source_id": item["sha256"],
                                        "path": item["path"], "start_line": number, "end_line": number})
                    if len(symbols) >= 50_000:
                        gaps.append("symbol index bound reached")
                        break
            except (OSError, UnicodeError):
                gaps.append(f"{item['path']}: text decode failed")
            if len(symbols) >= 50_000:
                break
        doc = {"schema": "appsec-review/symbol-index/1", "items": symbols, "gaps": gaps}
        return {"artifact": _artifact(unit, "symbol-index.json", doc), "item_count": len(symbols), "gaps": gaps}

    def component_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        items = unit.output("component_discovery.catalog_components")["components"]
        doc = {"schema": "appsec-review/component-index/1", "items": items, "gaps": []}
        return {"artifact": _artifact(unit, "component-index.json", doc), "item_count": len(items), "gaps": []}

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
        doc = {"schema": "appsec-review/target-catalog/1", "source_fingerprint": unit.job.source_fingerprint,
               "artifacts": outputs, "validation": unit.output("publish_catalog.validate_catalog"),
               "security_findings": []}
        return {"schema": doc["schema"], "artifact": _artifact(unit, "target-catalog.json", doc),
                "gaps": doc["validation"]["gaps"]}

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
