from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any

from appsec_review.interchange import (
    GAP_SCHEMA, GapCode, path_gap_records, producer_gap,
)
from .c_symbols import extract_c_family_symbols
from appsec_review.jobs.cataloging import (
    BUILD_FILES, PROJECT_FILES, PROJECT_FILE_SUFFIXES, Bounds, inventory, write_json,
)
from appsec_review.jobs.delivery_scope import POLICY_IDENTITY, scope_fields, source_in_scope
from appsec_review.jobs.build_discovery import (
    discover_build_inventory, is_build_descriptor,
    android_descriptor_facts, descriptor_package, discover_build_units, required_image_profile,
    source_only_scopes, unsupported_build_gaps,
)
from appsec_review.indexing.target_documents import (
    ADDITIONAL_INTERFACE_KINDS, KINDS, PARSER_IDENTITY, InventoryIntegrityError,
    collect_target_documents, select_document_inventory,
)
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.runtime import Job, Unit, UnitContext, UnitExecutor
from appsec_review.retrieval.source_resolution import read_source_bytes
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import safe_path
from appsec_review.jobs.job_target_catalog.datasets import CONTRACT, DATASETS


TOPOLOGY = {
    "repository_discovery": ("partition_repository", "census_languages", "discover_projects"),
    "build_discovery": ("discover_build_systems", "discover_compile_commands", "catalog_build_targets"),
    "component_discovery": ("catalog_components", "catalog_dependencies"),
    "retrieval_indexes": ("build_path_index", "build_symbol_index", "build_component_index", "build_target_documents"),
    "publish_catalog": ("validate_catalog", "publish_handoff"),
}


class CatalogError(Exception):
    """Base error for bounded target catalog failures."""


class CatalogConfigurationError(CatalogError, ValueError):
    """Target catalog configuration or missing target root is invalid."""


class CatalogIntegrityError(CatalogError, ValueError):
    """Accepted target bytes, path custody or catalog artifact integrity failed."""


class CatalogDocumentIntegrityError(CatalogIntegrityError, InventoryIntegrityError):
    """Accepted target document path custody or SHA-256 integrity failed."""


class TargetCatalogFailed(CatalogError, RuntimeError):
    """Bounded target catalog execution failed."""


MAX_CPP_SYMBOLS = 50_000


def _target(unit: UnitContext) -> Path:
    if unit.job.target_root is None:
        raise CatalogConfigurationError("review target is required")
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
        tool_identity={"producer": "job_target_catalog"}, parser_identity="catalog-parser/3",
        normalizer_identity="retrieval-normalizer/1+" + POLICY_IDENTITY, mapping_identity="source-map/1",
    )


def _gap_text(value: Any) -> str:
    """Render producer-owned gap data for retrieval metadata deterministically."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        if value.get("schema") == GAP_SCHEMA:
            return str(value["reason"])
        path = value.get("path")
        reason = value.get("reason")
        if path is not None and reason is not None:
            return f"{path}: {reason}"
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _dedup_gaps(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    ordered: list[dict[str, Any]] = []
    for record in records:
        gid = str(record["gap_id"])
        if gid not in seen:
            seen.add(gid)
            ordered.append(dict(record))
    return ordered


def _gap_reasons(records: Iterable[Any]) -> list[str]:
    return [_gap_text(item) for item in records]


def _coverage_gap_ids(records: Iterable[Mapping[str, Any]]) -> str | None:
    ids = [str(record["gap_id"]) for record in records]
    return ",".join(ids[:10]) if ids else None


def _inventory_gap_items(partition: Mapping[str, Any]) -> list[dict[str, str]]:
    if "inventory_gaps" in partition:
        raw_items = partition["inventory_gaps"]
    else:
        raw_items = partition.get("gaps", ())
    items: list[dict[str, str]] = []
    for item in raw_items:
        if isinstance(item, Mapping):
            if item.get("schema") == GAP_SCHEMA:
                scope = str(item.get("scope_id") or "<inventory>")
                reason = str(item.get("reason") or "gap")
                prefix = f"{scope}: "
                if reason.startswith(prefix):
                    reason = reason[len(prefix):]
                items.append({"path": scope, "reason": reason})
            else:
                entry = {"path": str(item.get("path") or "."),
                         "reason": str(item.get("reason") or "gap")}
                detail = str(item.get("detail") or "").strip()
                if detail:
                    entry["detail"] = detail
                items.append(entry)
        else:
            text = str(item)
            if ": " in text:
                path_part, reason_part = text.split(": ", 1)
                items.append({"path": path_part, "reason": reason_part})
            else:
                items.append({"path": "<inventory>", "reason": text})
    return items


# Largest build descriptor build discovery reads to find build points. The root meson.build of a
# real project is well over 64 KiB (Freeciv's is 124 KiB), which was the bound until 2026-11-11.
BUILD_DESCRIPTOR_READ_BYTES = 1024 * 1024


def descriptor_reader(target: Path, accepted: Mapping[str, Mapping[str, Any]], *,
                      limit: int = BUILD_DESCRIPTOR_READ_BYTES):
    """A bounded reader of accepted target files for build discovery.

    Returns ``(read_text, changed, unread)``. ``read_text`` answers ``None`` for a path the catalog
    did not accept, a file that cannot be read as UTF-8, and a file over ``limit``; the last is
    recorded in ``unread`` with its size, because a descriptor that was not read is unknown, not a
    descriptor that declares no build. ``changed`` lists files that differ from the accepted bytes.
    """
    changed: list[str] = []
    unread: dict[str, int] = {}

    def read_text(relative: str) -> str | None:
        # Bounded build-script read for routing only; the bytes never become instructions.
        identity = accepted.get(relative)
        if identity is None:
            return None
        if int(identity["size_bytes"]) > limit:
            unread[relative] = int(identity["size_bytes"])
            return None
        try:
            path = safe_path(target, relative)
        except ValueError as error:
            raise CatalogIntegrityError(str(error)) from error
        if not path.is_file():
            return None
        try:
            raw = path.read_bytes()
            if (len(raw) != identity["size_bytes"] or
                    hashlib.sha256(raw).hexdigest() != identity["sha256"]):
                changed.append(relative)
                raise CatalogIntegrityError("engine/build descriptor differs from the accepted catalog")
            return raw.decode("utf-8")
        except (OSError, UnicodeError):
            return None

    return read_text, changed, unread


def unread_descriptor_gaps(unread: Mapping[str, int], *, limit: int = BUILD_DESCRIPTOR_READ_BYTES) -> list[str]:
    """One named gap per build descriptor that build discovery could not read for its size."""
    return [f"build descriptor not read: {path}: {size} bytes exceeds the {limit}-byte read bound; "
            "its build points and driven directories are unknown"
            for path, size in sorted(unread.items()) if is_build_descriptor(PurePosixPath(path))]


def _validate_config(context, result) -> None:
    if tuple(context.config.steps) != tuple(TOPOLOGY):
        raise CatalogConfigurationError("target catalog topology does not match configuration")
    for step, tasks in TOPOLOGY.items():
        if tuple(context.config.step(step).tasks) != tasks:
            raise CatalogConfigurationError(f"target catalog task order mismatch: {step}")


def build_job(*, fail_task: str | None = None) -> Job:
    def maybe_fail(unit: UnitContext) -> None:
        if unit.unit_id == fail_task:
            raise TargetCatalogFailed(f"injected bounded failure: {fail_task}")

    def partition(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        snapshot = inventory(_target(unit), Bounds(max_file_bytes=unit.job.config.inventory_max_file_bytes),
                             exclusions=unit.job.config.exclusions)
        snapshot["files"] = [{**item, **scope_fields({**item, "artifact_origin": "target-intake"})}
                             for item in snapshot["files"]]
        from appsec_review.config.assurance import SCOPE_VERSION, ScopeRole
        from appsec_review.jobs.artifact_kinds import ArtifactKind, binary_role
        from appsec_review.storage.shared import put_bytes, safe_path
        target_artifacts = []
        for candidate in snapshot["artifact_candidates"]:
            try:
                path = safe_path(_target(unit), candidate["path"])
            except ValueError as error:
                raise CatalogIntegrityError(str(error)) from error
            kind, file_format = binary_role(path)
            with path.open("rb") as stream:
                payload = stream.read(candidate["size_bytes"] + 1)
            if (len(payload) != candidate["size_bytes"]
                    or hashlib.sha256(payload).hexdigest() != candidate["sha256"]):
                raise CatalogIntegrityError("target artifact changed during bounded intake")
            reference = put_bytes(unit.job.run_root, payload)
            if (reference["sha256"] != candidate["sha256"]
                    or reference["size_bytes"] != candidate["size_bytes"]):
                raise CatalogIntegrityError("target artifact changed during intake publication")
            target_artifacts.append({
                **reference, "schema": "appsec-review/target-artifact-intake/1",
                "target_relative_path": candidate["path"],
                "workspace_path": candidate["path"], "kind": kind or ArtifactKind.RESOURCE.value,
                "format": file_format, "source_fingerprint": unit.job.source_fingerprint,
                "artifact_origin": "target-intake", "scope_role": ScopeRole.UNKNOWN.value,
                "scope_version": SCOPE_VERSION, "delivery_status": "unknown",
                "mapping": "exact-target-path", "mapping_confidence": 1.0,
            })
            target_artifacts[-1].update(scope_fields(target_artifacts[-1]))
        groups = Counter(item["path"].split("/", 1)[0] for item in snapshot["files"])
        doc = {"schema": "appsec-review/repository-partition/1", "source_fingerprint": unit.job.source_fingerprint,
               "partitions": [{"path": key, "file_count": groups[key]} for key in sorted(groups)],
               **snapshot, "target_artifacts": target_artifacts}
        gap_records = _dedup_gaps(path_gap_records(unit.unit_id, snapshot["gaps"]))
        return {"artifact": _artifact(unit, "repository-partition.json", doc),
                "files": snapshot["files"], "gaps": gap_records,
                "inventory_gaps": list(snapshot["gaps"]),
                "file_discovery": snapshot["file_discovery"],
                "target_artifacts": target_artifacts,
                "configured_exclusions": snapshot["configured_exclusions"],
                "excluded_assets": snapshot["excluded_assets"]}

    def census(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        counts = Counter(item["language"] or "Other" for item in unit.output("repository_discovery.partition_repository")["files"])
        doc = {"schema": "appsec-review/language-census/1",
               "languages": [{"language": key, "file_count": counts[key]} for key in sorted(counts)]}
        return {"artifact": _artifact(unit, "language-census.json", doc), **doc, "gaps": []}

    def projects(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        found = []
        engine_discovery = unit.output("build_discovery.discover_build_systems")["engine_discovery"]
        engine_roots = [PurePosixPath(project["root"]) for project in engine_discovery["projects"]]
        for item in unit.output("repository_discovery.partition_repository")["files"]:
            path = Path(item["path"])
            logical = PurePosixPath(item["path"])
            owner = next((root for root in engine_roots if root.as_posix() == "." or root in logical.parents), None)
            if owner is not None and (
                    path.suffix.lower() in PROJECT_FILE_SUFFIXES or
                    path.name == "package.json" and "Packages" in logical.relative_to(owner).parts[:-1]):
                continue
            if path.name in PROJECT_FILES or path.suffix.lower() in PROJECT_FILE_SUFFIXES:
                found.append({"manifest": item["path"], "root": path.parent.as_posix(), "sha256": item["sha256"]})
        for project in engine_discovery["projects"]:
            marker = next(item for item in project["markers"]
                          if PurePosixPath(item["path"]).name == "ProjectVersion.txt")
            found.append({"manifest": marker["path"], "root": project["root"],
                          "sha256": marker["sha256"], "engine": project["engine"]})
        gap_records = [
            producer_gap(GapCode.PRODUCER_REPORTED_GAP, str(text), unit_id=unit.unit_id,
                         scope_id="engine_discovery")
            for text in engine_discovery["gaps"]
        ]
        if not found:
            gap_records.append(producer_gap(GapCode.EMPTY_RESULT, "no recognized project manifests",
                                            unit_id=unit.unit_id, scope_id="projects"))
        gap_records = _dedup_gaps(gap_records)
        doc = {"schema": "appsec-review/project-catalog/1", "projects": found,
               "engine_observations": engine_discovery["observations"],
               "gaps": _gap_reasons(gap_records)}
        return {"artifact": _artifact(unit, "projects.json", doc), **doc, "gaps": gap_records}

    def build_systems(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        systems = []
        for item in unit.output("repository_discovery.partition_repository")["files"]:
            name = Path(item["path"]).name
            if name in BUILD_FILES or name in PROJECT_FILES or Path(item["path"]).suffix.lower() in PROJECT_FILE_SUFFIXES:
                systems.append({"path": item["path"], "kind": name, "sha256": item["sha256"]})
        files = unit.output("repository_discovery.partition_repository")["files"]
        target = _target(unit).resolve()
        accepted = {str(item["path"]): item for item in files}
        read_text, changed_descriptors, unread_descriptors = descriptor_reader(target, accepted)

        from appsec_review.jobs.engine_discovery import discover_unity
        engines = discover_unity(files, read_text=lambda descriptor, _limit: read_text(descriptor["path"]))
        if changed_descriptors:
            raise CatalogIntegrityError("engine/build descriptor differs from the accepted catalog: " +
                                        ", ".join(sorted(set(changed_descriptors))))
        inventory_out = discover_build_inventory(files, read_text=read_text, engine_discovery=engines)
        units = inventory_out["units"]
        orphans = inventory_out["orphaned_sources"]
        gap_records: list[dict[str, Any]] = [
            producer_gap(GapCode.PRODUCER_REPORTED_GAP, text, unit_id=unit.unit_id,
                         scope_id="unsupported_build")
            for text in unsupported_build_gaps(files, units)
        ]
        gap_records.extend(
            producer_gap(GapCode.PRODUCER_REPORTED_GAP, str(text), unit_id=unit.unit_id,
                         scope_id="engine_discovery")
            for text in engines["gaps"]
        )
        for path, size in sorted(unread_descriptors.items()):
            if is_build_descriptor(PurePosixPath(path)):
                reason = (f"build descriptor not read: {path}: {size} bytes exceeds the "
                          f"{BUILD_DESCRIPTOR_READ_BYTES}-byte read bound; "
                          "its build points and driven directories are unknown")
                gap_records.append(producer_gap(GapCode.TRUNCATED, reason, unit_id=unit.unit_id,
                                                scope_id=path))
        # Orphaned sources are knowledge the review reports (dead code, build drift, an abandoned
        # port, or a build we did not understand); they are a coverage fact here, never a build.
        if orphans:
            by_language = Counter(item["language"] for item in orphans)
            orphan_reason = "orphaned sources: " + ", ".join(
                f"{count} {language}" for language, count in sorted(by_language.items()))
            gap_records.append(producer_gap(GapCode.PRODUCER_REPORTED_GAP, orphan_reason,
                                            unit_id=unit.unit_id, scope_id="orphaned_sources"))
        if not gap_records and not units:
            gap_records.append(producer_gap(GapCode.EMPTY_RESULT, "no recognized build system",
                                            unit_id=unit.unit_id, scope_id="build_systems"))
        gap_records = _dedup_gaps(gap_records)
        gap_reasons = _gap_reasons(gap_records)
        # build-systems/4 (2026-11-08, plan §2.1 decision 1): units carry build points with member
        # paths/descriptors, ``drives``/``driven_by`` and ``descriptors``; ``folded_roots`` and
        # ``demoted_markers`` name every marker directory that is not a unit, with the reason.
        doc = {"schema": "appsec-review/build-systems/4", "systems": systems, "build_units": units,
               "orphaned_sources": orphans, "folded_roots": inventory_out["folded_roots"],
               "demoted_markers": inventory_out["demoted_markers"], "engine_discovery": engines,
               "source_only_scopes": source_only_scopes(files, units),
               "gaps": gap_reasons}
        unit.job.events.write("BUILD_SYSTEMS_DISCOVERED", unit_id=unit.unit_id, unit_count=len(units),
                              orphaned_source_count=len(orphans), source_only_scope_count=len(doc["source_only_scopes"]),
                              gap_count=len(doc["gaps"]))
        return {"artifact": _artifact(unit, "build-systems.json", doc), **doc,
                "gap_reasons": gap_reasons, "gaps": gap_records}

    def compile_commands(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        commands = [item for item in unit.output("repository_discovery.partition_repository")["files"]
                    if Path(item["path"]).name == "compile_commands.json"]
        gap_records = ([] if commands else [
            producer_gap(GapCode.PRODUCER_REPORTED_GAP, "compile_commands.json not present",
                         unit_id=unit.unit_id, scope_id="compile_commands.json")
        ])
        doc = {"schema": "appsec-review/compile-commands/1", "files": commands,
               "gaps": _gap_reasons(gap_records)}
        return {"artifact": _artifact(unit, "compile-commands.json", doc), **doc, "gaps": gap_records}

    def build_targets(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        systems_out = unit.output("build_discovery.discover_build_systems")
        build_units = systems_out["build_units"]
        files = unit.output("repository_discovery.partition_repository")["files"]
        targets = []
        for item in build_units:
            if item.get("build_system") == "unity":
                from appsec_review.jobs.engine_discovery import unity_configuration_fingerprint
                project = item["engine_project"]
                fingerprint = unity_configuration_fingerprint(project, unit.job.source_fingerprint)
                package = descriptor_package(_target(unit), item, files)
                package["inventory"] = list(item["markers"])
                facts = dict(item["descriptor_facts"])
                facts["configuration_fingerprint"] = fingerprint
            else:
                package = descriptor_package(_target(unit), item, files)
                # Packaging may omit descriptors already read by discovery, or retain only a subset.
                facts = {**(android_descriptor_facts(package) or {}),
                         **item.get("descriptor_facts", {})}
            target = {**item, "descriptor_package": package,
                      "project_type": facts.get("kind", "unity" if item.get("engine") else "generic") if facts else "generic",
                      "descriptor_facts": facts or {}}
            targets.append({**target, "required_image_profile": required_image_profile(target)})
        upstream_reasons = list(systems_out.get("gap_reasons", _gap_reasons(systems_out.get("gaps", ()))))
        doc = {"schema": "appsec-review/build-targets/2", "targets": targets,
               "engine_discovery": {
                   key: systems_out["engine_discovery"][key]
                   for key in ("counts", "observations", "gaps")},
               "gaps": upstream_reasons}
        return {"artifact": _artifact(unit, "build-targets.json", doc), **doc,
                "build_gap_reasons": upstream_reasons, "gaps": []}

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
        gap_records: list[dict[str, Any]] = []
        for component in unit.output("component_discovery.catalog_components")["components"]:
            manifest = component["manifest"]
            if not manifest:
                gap_records.append(producer_gap(
                    GapCode.PRODUCER_REPORTED_GAP,
                    f"{component['component_id']}: no manifest for dependency extraction",
                    unit_id=unit.unit_id, scope_id=str(component["component_id"]),
                ))
                continue
            path = _target(unit) / manifest
            try:
                if path.name == "package.json":
                    value = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(value, dict):
                        gap_records.append(producer_gap(
                            GapCode.PARSER_ERROR, f"{manifest}: package manifest must be an object",
                            unit_id=unit.unit_id, scope_id=str(manifest),
                        ))
                        continue
                    for section in ("dependencies", "devDependencies"):
                        declarations = value.get(section, {})
                        if not isinstance(declarations, dict):
                            gap_records.append(producer_gap(
                                GapCode.PARSER_ERROR, f"{manifest}#{section}: expected a dependency mapping",
                                unit_id=unit.unit_id, scope_id=f"{manifest}#{section}",
                            ))
                            continue
                        for name, version in sorted(declarations.items()):
                            if not isinstance(version, str):
                                scope_ref = f"{manifest}#{section}.{name}"
                                gap_records.append(producer_gap(
                                    GapCode.PARSER_ERROR, f"{scope_ref}: expected a dependency constraint string",
                                    unit_id=unit.unit_id, scope_id=scope_ref,
                                ))
                                continue
                            records.append({"component_id": component["component_id"], "name": name,
                                            "constraint": version, "source": manifest, "location": section})
                            records[-1].update(scope_fields({
                                "scope_role": "build_dependency" if section == "devDependencies" else "unknown",
                                "artifact_origin": "target-intake",
                                "delivery_evidence": {"kind": "manifest-dependency-declaration",
                                                      "path": manifest, "sha256": component["manifest_sha256"],
                                                      "section": section},
                            }))
                            if section == "dependencies":
                                scope_ref = f"{manifest}#{section}.{name}"
                                gap_records.append(producer_gap(
                                    GapCode.PRODUCER_REPORTED_GAP,
                                    f"{scope_ref}: dependency delivery status is unknown",
                                    unit_id=unit.unit_id, scope_id=scope_ref,
                                ))
                else:
                    gap_records.append(producer_gap(
                        GapCode.PRODUCER_REPORTED_GAP,
                        f"{manifest}: dependency parser deferred for this manifest type",
                        unit_id=unit.unit_id, scope_id=str(manifest),
                    ))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                gap_records.append(producer_gap(
                    GapCode.PARSER_ERROR,
                    f"{manifest}: parse failed ({type(exc).__name__})",
                    unit_id=unit.unit_id, scope_id=str(manifest),
                ))
        gap_records = _dedup_gaps(gap_records)
        doc = {"schema": "appsec-review/dependency-catalog/1", "dependencies": records,
               "gaps": _gap_reasons(gap_records)}
        return {"artifact": _artifact(unit, "dependencies.json", doc), **doc, "gaps": gap_records}

    def path_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        partition_out = unit.output("repository_discovery.partition_repository")
        fingerprint = _fingerprint(unit, "source", [partition_out["artifact"]])
        path = unit.job.run_root / "data" / "indices" / "source" / "attempts" / unit.job.config.job_id / unit.job.attempt_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="source", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint)
        gap_records: list[dict[str, Any]] = list(
            path_gap_records(unit.unit_id, _inventory_gap_items(partition_out))
        )
        for item in partition_out["files"]:
            if not source_in_scope(item):
                continue
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
                    gap_records.append(producer_gap(
                        GapCode.PARSER_ERROR, f"{item['path']}: text decode failed",
                        unit_id=unit.unit_id, scope_id=str(item["path"]),
                    ))
            location = SourceLocation(
                target_snapshot=unit.job.source_fingerprint, path=item["path"], file_sha256=item["sha256"],
                start_byte=0, end_byte=item["size_bytes"], start_line=1, end_line=line_count,
                start_column=1, end_column=1, producer_location={"inventory_path": item["path"]},
                mapping_method="inventory-exact", confidence=1.0,
            )
            builder.add_entity(EntityRecord(identity, item["path"], item["path"], text,
                                             {"language": item["language"], "size_bytes": item["size_bytes"],
                                              "generated": bool(item.get("generated")), **scope_fields(item)}, location))
        gap_records = _dedup_gaps(gap_records)
        builder.add_coverage("target-files", "complete" if not gap_records else "partial",
                             _coverage_gap_ids(gap_records))
        sha256 = builder.build()
        index = IndexIdentity("source", "appsec-review/retrieval-index/2", sha256, fingerprint,
                              path.relative_to(unit.job.run_root).as_posix(),
                              {"job": "job_target_catalog", "unit": unit.unit_id},
                              tuple(_gap_reasons(gap_records)))
        return {"artifact": _run_artifact(unit, path), "index_identity": asdict(index),
                "item_count": len(partition_out["files"]), "gaps": gap_records}

    def symbol_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        symbols = []
        partition_out = unit.output("repository_discovery.partition_repository")
        gap_records: list[dict[str, Any]] = list(
            path_gap_records(unit.unit_id, _inventory_gap_items(partition_out))
        )
        fingerprint = _fingerprint(unit, "analysis", [partition_out["artifact"]])
        path = unit.job.run_root / "data" / "indices" / "analysis" / "attempts" / unit.job.config.job_id / unit.job.attempt_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="analysis", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint)
        pattern = re.compile(r"^\s*(?:def|class|function|func|interface|struct|enum)\s+([A-Za-z_$][\w$]*)")
        truncated = False
        for item in partition_out["files"]:
            if not source_in_scope(item) or item["language"] is None:
                continue
            if len(symbols) >= MAX_CPP_SYMBOLS:
                truncated = True
                gap_records.append(producer_gap(
                    GapCode.TRUNCATED, "symbol index bound reached",
                    unit_id=unit.unit_id, scope_id="symbols",
                ))
                break
            if item["size_bytes"] > 16 * 1024 * 1024:
                gap_records.append(producer_gap(
                    GapCode.TRUNCATED, f"{item['path']}: symbol source byte bound reached",
                    unit_id=unit.unit_id, scope_id=str(item["path"]),
                ))
                continue
            try:
                source_path = safe_path(_target(unit), item["path"])
            except ValueError as error:
                raise CatalogIntegrityError(str(error)) from error
            try:
                if not source_path.is_file():
                    raise FileNotFoundError(item["path"])
                try:
                    raw = read_source_bytes(
                        unit.job.run_root, _target(unit), target_snapshot=unit.job.source_fingerprint,
                        path=item["path"], sha256=item["sha256"],
                    )
                except ValueError as error:
                    raise CatalogIntegrityError(str(error)) from error
                if len(raw) != item["size_bytes"]:
                    raise CatalogIntegrityError("symbol source size differs from the accepted catalog")
                decoded = raw.decode("utf-8", errors="strict")
                if item["language"] in {"C", "C++", "C/C++"}:
                    file_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, unit.job.source_fingerprint,
                                                     {"path": item["path"], "sha256": item["sha256"]})
                    for hit in extract_c_family_symbols(decoded, limit=MAX_CPP_SYMBOLS - len(symbols) + 1):
                        if len(symbols) >= MAX_CPP_SYMBOLS:
                            truncated = True
                            gap_records.append(producer_gap(
                                GapCode.TRUNCATED, "symbol index bound reached",
                                unit_id=unit.unit_id, scope_id="symbols",
                            ))
                            break
                        symbol_id = LogicalIdentity.derive(EntityKind.SYMBOL, unit.job.source_fingerprint,
                                                           {"path": item["path"], "line": hit.line, "name": hit.name})
                        location = SourceLocation(
                            target_snapshot=unit.job.source_fingerprint, path=item["path"], file_sha256=item["sha256"],
                            start_byte=hit.line_start_byte, end_byte=hit.line_end_byte,
                            start_line=hit.line, end_line=hit.line,
                            start_column=hit.start_column, end_column=hit.end_column,
                            producer_location={"parser": "c-family-declaration-scanner",
                                               "line": hit.line, "kind": hit.kind},
                            mapping_method="source-line-exact", confidence=1.0,
                        )
                        builder.add_entity(EntityRecord(symbol_id, hit.name, hit.name, hit.line_text,
                                                        {"language": item["language"],
                                                         "kind": hit.kind,
                                                         "generated": bool(item.get("generated")),
                                                         **scope_fields(item)}, location))
                        builder.add_relation(RelationRecord(RelationKind.DEFINES, file_id.value,
                                                            symbol_id.value, True, 1.0))
                        symbols.append(symbol_id.value)
                else:
                    offset = 0
                    for number, line in enumerate(decoded.splitlines(keepends=True), 1):
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
                            if len(symbols) >= MAX_CPP_SYMBOLS:
                                truncated = True
                                gap_records.append(producer_gap(
                                    GapCode.TRUNCATED, "symbol index bound reached",
                                    unit_id=unit.unit_id, scope_id="symbols",
                                ))
                                break
                            builder.add_entity(EntityRecord(symbol_id, match.group(1), match.group(1), line.rstrip(),
                                                            {"language": item["language"],
                                                             "generated": bool(item.get("generated")),
                                                             **scope_fields(item)}, location))
                            builder.add_relation(RelationRecord(RelationKind.DEFINES, file_id.value,
                                                                symbol_id.value, True, 1.0))
                            symbols.append(symbol_id.value)
                        offset += len(line.encode())
            except (OSError, UnicodeError):
                gap_records.append(producer_gap(
                    GapCode.PARSER_ERROR, f"{item['path']}: text decode failed",
                    unit_id=unit.unit_id, scope_id=str(item["path"]),
                ))
            if truncated:
                break
        gap_records = _dedup_gaps(gap_records)
        builder.add_coverage("declarations", "complete" if not gap_records else "partial",
                             _coverage_gap_ids(gap_records))
        index_path = builder.path
        sha256 = builder.build()
        index = {"name": "analysis", "schema": "appsec-review/retrieval-index/2", "sha256": sha256,
                 "fingerprint": fingerprint, "relative_path": index_path.relative_to(unit.job.run_root).as_posix(),
                 "producer": {"job": "job_target_catalog", "unit": unit.unit_id},
                 "gaps": _gap_reasons(gap_records)}
        return {"artifact": _run_artifact(unit, index_path), "index_identity": index,
                "item_count": len(symbols), "gaps": gap_records}

    def component_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        items = unit.output("component_discovery.catalog_components")["components"]
        artifact = unit.output("component_discovery.catalog_components")["artifact"]
        fingerprint = _fingerprint(unit, "components", [artifact])
        path = unit.job.run_root / "data" / "indices" / "components" / "attempts" / unit.job.config.job_id / unit.job.attempt_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name="components", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint)
        for item in items:
            identity = LogicalIdentity.derive(EntityKind.COMPONENT, unit.job.source_fingerprint,
                                              {"component_id": item["component_id"], "manifest": item["manifest"]})
            builder.add_entity(EntityRecord(identity, item["component_id"], item["component_id"],
                                             " ".join(str(value) for value in item.values() if value), item))
        builder.add_coverage("components", "complete")
        sha256 = builder.build()
        index = {"name": "components", "schema": "appsec-review/retrieval-index/2", "sha256": sha256,
                 "fingerprint": fingerprint, "relative_path": path.relative_to(unit.job.run_root).as_posix(),
                 "producer": {"job": "job_target_catalog", "unit": unit.unit_id}, "gaps": []}
        return {"artifact": _run_artifact(unit, path), "index_identity": index,
                "item_count": len(items), "gaps": []}

    def document_index(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        partition_out = unit.output("repository_discovery.partition_repository")
        entries = select_document_inventory(partition_out["files"])
        settings = unit.job.config.typed_settings
        fingerprint = index_fingerprint(
            name="documents", target_snapshot=unit.job.source_fingerprint,
            producer_artifacts=[partition_out["artifact"]],
            tool_identity={"producer": "job_target_catalog", "limits": {
                "files": settings.max_files, "file_bytes": settings.max_file_bytes,
                "records": settings.max_records, "chunk_lines": settings.max_chunk_lines,
                "chunk_bytes": settings.max_chunk_bytes, "parse_depth": settings.max_parse_depth,
                "parse_nodes": settings.max_parse_nodes}},
            parser_identity=f"{PARSER_IDENTITY}:{unit.job.review_policy.releases.values.get('target_documents', 'undeclared')}",
            normalizer_identity="retrieval-normalizer/1", mapping_identity="source-line-exact/1",
        )
        path = unit.job.run_root / "data" / "indices" / "documents" / "attempts" / unit.job.config.job_id / unit.job.attempt_id / f"{fingerprint}.sqlite"
        result = collect_target_documents(
            _target(unit), unit.job.source_fingerprint, entries,
            max_files=settings.max_files, max_file_bytes=settings.max_file_bytes,
            max_records=settings.max_records,
            max_chunk_lines=settings.max_chunk_lines, max_chunk_bytes=settings.max_chunk_bytes,
            max_parse_depth=settings.max_parse_depth, max_parse_nodes=settings.max_parse_nodes,
        )
        kinds = {entry["kind"] for entry in entries}
        coverage_kinds = (KINDS - ADDITIONAL_INTERFACE_KINDS) | kinds
        gap_records: list[dict[str, Any]] = [
            producer_gap(GapCode.PRODUCER_REPORTED_GAP, f"{kind}: no accepted target document",
                         unit_id=unit.unit_id, scope_id=f"target-documents:{kind}")
            for kind in sorted(coverage_kinds - kinds)
        ]
        collector_entries = []
        for item in result.gaps:
            doc_path = str(item.get("path") or "<inventory>")
            doc_reason = str(item.get("reason") or "gap")
            doc_detail = str(item.get("detail") or "").strip()
            collector_entries.append({
                "path": doc_path,
                "reason": f"{doc_reason} ({doc_detail})" if doc_detail else doc_reason,
            })
        gap_records.extend(path_gap_records(unit.unit_id, collector_entries))
        for item in _inventory_gap_items(partition_out):
            inv_reason = f"source inventory {item['path']}: {item['reason']}"
            if item.get("detail"):
                inv_reason = f"{inv_reason}: {item['detail']}"
            gap_records.append(producer_gap(
                GapCode.PRODUCER_REPORTED_GAP, inv_reason,
                unit_id=unit.unit_id, scope_id=item["path"],
            ))
        gap_records = _dedup_gaps(gap_records)
        if len(gap_records) > 200:
            omitted = len(gap_records) - 200
            gap_records = [
                *gap_records[:200],
                producer_gap(
                    GapCode.TRUNCATED,
                    f"target document gaps truncated: {omitted} additional gap(s)",
                    unit_id=unit.unit_id, scope_id="target-documents",
                ),
            ]
        builder = IndexBuilder(path, name="documents", fingerprint=fingerprint,
                               target_snapshot=unit.job.source_fingerprint)
        identities: dict[str, str] = {}
        line_offsets: dict[str, list[tuple[int, int]]] = {}
        for record in result.records:
            source_path = record["path"]
            if source_path not in line_offsets:
                target_root = _target(unit).resolve()
                source = (target_root / source_path).resolve()
                if target_root not in source.parents or not source.is_file():
                    raise CatalogDocumentIntegrityError(f"accepted target source missing or escaped: {source_path}")
                raw = source.read_bytes()
                if hashlib.sha256(raw).hexdigest() != record["file_sha256"]:
                    raise CatalogDocumentIntegrityError(f"accepted target source hash mismatch: {source_path}")
                offsets = []
                position = 0
                for line in raw.splitlines(keepends=True):
                    offsets.append((position, position + len(line)))
                    position += len(line)
                line_offsets[source_path] = offsets
            offsets = line_offsets[source_path]
            if not 1 <= record["line"] <= record["end_line"] <= len(offsets):
                raise CatalogIntegrityError(f"document source location cannot be resolved: {source_path}")
            start = offsets[record["line"] - 1][0]
            end = offsets[record["end_line"] - 1][1]
            identity = LogicalIdentity.derive(EntityKind.DOCUMENT_RECORD, unit.job.source_fingerprint,
                                              {"record_id": record["id"]})
            identities[record["id"]] = identity.value
            location = SourceLocation(
                target_snapshot=unit.job.source_fingerprint, path=source_path,
                file_sha256=record["file_sha256"], start_byte=start, end_byte=end,
                start_line=record["line"], end_line=record["end_line"], start_column=1,
                end_column=1, producer_location={"extractor": PARSER_IDENTITY, "line": record["line"]},
                mapping_method="source-line-exact", confidence=1.0,
            )
            builder.add_entity(EntityRecord(
                identity, record["id"], f"{record['kind']} {record['subtype']}: {record['text']}"[:256],
                record["text"], {"record_type": "target_document", "document_kind": record["kind"],
                                 "subtype": record["subtype"], "authority": record["authority"],
                                 "fields": record["fields"]}, location,
            ))
        for link in result.links:
            builder.add_relation(RelationRecord(
                RelationKind.REFERENCES, identities[link["from"]], identities[link["to"]],
                bool(link["exact"]), 1.0 if link["exact"] else 0.5,
                payload={"relation": link["relation"], "authority": link["authority"]},
            ))
        scoped_gap_id = {str(rec["scope_id"]): str(rec["gap_id"]) for rec in gap_records if rec.get("scope_id")}
        for kind in sorted(coverage_kinds):
            count = sum(record["kind"] == kind for record in result.records)
            area = f"target-documents:{kind}"
            status = "complete" if count and not gap_records else "partial" if count else "unavailable"
            coverage_gap = (
                None if status == "complete"
                else scoped_gap_id.get(area, str(gap_records[0]["gap_id"]) if gap_records else None)
            )
            builder.add_coverage(area, status, coverage_gap)
        builder.add_coverage("target-documents", "complete" if not gap_records else "partial",
                             _coverage_gap_ids(gap_records))
        sha = builder.build()
        index = IndexIdentity("documents", "appsec-review/retrieval-index/2", sha, fingerprint,
                              path.relative_to(unit.job.run_root).as_posix(),
                              {"job": "job_target_catalog", "unit": unit.unit_id},
                              tuple(_gap_reasons(gap_records)))
        return {"artifact": _run_artifact(unit, path), "index_identity": asdict(index),
                "item_count": len(result.records), "link_count": len(result.links), "gaps": gap_records}

    def validate_catalog(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        required = ("retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index",
                    "retrieval_indexes.build_component_index", "retrieval_indexes.build_target_documents")
        for dependency in required:
            artifact = unit.output(dependency)["artifact"]
            path = unit.job.run_root / artifact["path"]
            from appsec_review.storage import file_sha256
            if not path.is_file() or file_sha256(path) != artifact["sha256"]:
                raise CatalogIntegrityError(f"catalog artifact failed validation: {dependency}")
        upstream_gaps = sum((_gap_reasons(unit.output(item)["gaps"]) for item in required), [])
        return {"status": "VALID", "validated": list(required),
                "upstream_gaps": upstream_gaps, "gaps": []}

    def publish(unit: UnitContext) -> Mapping[str, Any]:
        maybe_fail(unit)
        outputs = {key: unit.output(key)["artifact"] for key in (
            "repository_discovery.partition_repository", "repository_discovery.census_languages",
            "repository_discovery.discover_projects", "build_discovery.discover_build_systems",
            "build_discovery.discover_compile_commands", "build_discovery.catalog_build_targets",
            "component_discovery.catalog_components", "component_discovery.catalog_dependencies",
            "retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index",
            "retrieval_indexes.build_component_index", "retrieval_indexes.build_target_documents")}
        build_inputs = [unit.output("build_discovery.discover_build_systems")["artifact"],
                        unit.output("build_discovery.discover_compile_commands")["artifact"],
                        unit.output("build_discovery.catalog_build_targets")["artifact"]]
        build_fingerprint = _fingerprint(unit, "build", build_inputs)
        build_path = unit.job.run_root / "data" / "indices" / "build" / "attempts" / unit.job.config.job_id / unit.job.attempt_id / f"{build_fingerprint}.sqlite"
        build_index = IndexBuilder(build_path, name="build", fingerprint=build_fingerprint,
                                   target_snapshot=unit.job.source_fingerprint)
        targets_out = unit.output("build_discovery.catalog_build_targets")
        targets = targets_out["targets"]
        for target in targets:
            identity = LogicalIdentity.derive(EntityKind.BUILD_ACTION, unit.job.source_fingerprint,
                                              {"id": target["build_unit_id"], "root": target.get("root")})
            build_index.add_entity(EntityRecord(identity, target["build_unit_id"], target.get("build_system", target["build_unit_id"]),
                                                " ".join(str(value) for value in target.values()), target))
        build_gap_reasons = list(
            targets_out.get("build_gap_reasons", _gap_reasons(targets_out.get("gaps", ())))
        )
        compile_files = unit.output("build_discovery.discover_compile_commands")["files"]
        for item in compile_files:
            identity = LogicalIdentity.derive(EntityKind.COMPILE_UNIT, unit.job.source_fingerprint,
                                              {"path": item["path"], "sha256": item["sha256"]})
            build_index.add_entity(EntityRecord(identity, item["path"], item["path"], item["path"],
                                                {"compile_database_sha256": item["sha256"]}))
        publish_gap_records: list[dict[str, Any]] = [
            producer_gap(GapCode.PRODUCER_REPORTED_GAP, reason, unit_id=unit.unit_id, scope_id="build")
            for reason in build_gap_reasons
        ]
        no_targets_gap_id: str | None = None
        if not targets:
            no_targets_record = producer_gap(
                GapCode.EMPTY_RESULT, "no build targets discovered",
                unit_id=unit.unit_id, scope_id="build-actions",
            )
            publish_gap_records.append(no_targets_record)
            no_targets_gap_id = str(no_targets_record["gap_id"])
        no_compile_gap_id: str | None = None
        if not compile_files:
            no_compile_record = producer_gap(
                GapCode.PRODUCER_REPORTED_GAP, "compile_commands.json not present",
                unit_id=unit.unit_id, scope_id="compile-units",
            )
            publish_gap_records.append(no_compile_record)
            no_compile_gap_id = str(no_compile_record["gap_id"])
        publish_gap_records = _dedup_gaps(publish_gap_records)
        build_index.add_coverage("build-actions", "complete" if targets else "partial", no_targets_gap_id)
        build_index.add_coverage("compile-units", "complete" if compile_files else "unavailable", no_compile_gap_id)
        build_sha = build_index.build()
        build_identity = {"name": "build", "schema": "appsec-review/retrieval-index/2", "sha256": build_sha,
                          "fingerprint": build_fingerprint,
                          "relative_path": build_path.relative_to(unit.job.run_root).as_posix(),
                          "producer": {"job": "job_target_catalog", "unit": unit.unit_id},
                          "gaps": build_gap_reasons}
        indexes = [IndexIdentity(**{**unit.output(name)["index_identity"],
                                   "gaps": tuple(unit.output(name)["index_identity"].get("gaps", ()))})
                   for name in ("retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index",
                                "retrieval_indexes.build_component_index", "retrieval_indexes.build_target_documents")]
        indexes.append(IndexIdentity(**{**build_identity, "gaps": tuple(build_gap_reasons)}))
        manifest_path = unit.job.run_root / "data" / "indices" / "manifests" / f"catalog-{unit.job.attempt_id}.json"
        write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                       target_root=_target(unit), indexes=indexes)
        raw_validation = dict(unit.output("publish_catalog.validate_catalog"))
        validation_gaps = list(
            raw_validation.pop("upstream_gaps", _gap_reasons(raw_validation.get("gaps", ())))
        )
        validation_doc = {**raw_validation, "gaps": validation_gaps}
        doc = {"schema": "appsec-review/target-catalog/1", "source_fingerprint": unit.job.source_fingerprint,
               "artifacts": outputs, "validation": validation_doc,
               "security_findings": []}
        artifact = _artifact(unit, "target-catalog.json", doc)
        unit.job.events.write("REVIEW_SCOPE_CATALOGED", unit_id=unit.unit_id,
            source_receipt=unit.output("repository_discovery.partition_repository")["artifact"],
            project_receipt=unit.output("repository_discovery.discover_projects")["artifact"],
            build_target_receipt=unit.output("build_discovery.catalog_build_targets")["artifact"],
            catalog_receipt=artifact, metrics_semantics="appsec-review/review-metrics-semantics/1")
        return {"schema": doc["schema"], "artifact": artifact,
                "index_manifest": _run_artifact(unit, manifest_path),
                "gaps": publish_gap_records}

    u = Unit
    units = (
        u("repository_discovery.partition_repository", partition),
        u("repository_discovery.census_languages", census, ("repository_discovery.partition_repository",)),
        u("build_discovery.discover_build_systems", build_systems, ("repository_discovery.partition_repository",)),
        u("repository_discovery.discover_projects", projects, ("repository_discovery.partition_repository",
                                                             "build_discovery.discover_build_systems")),
        u("build_discovery.discover_compile_commands", compile_commands, ("repository_discovery.partition_repository",)),
        u("build_discovery.catalog_build_targets", build_targets, ("build_discovery.discover_build_systems", "build_discovery.discover_compile_commands", "repository_discovery.partition_repository")),
        u("component_discovery.catalog_components", components, ("repository_discovery.discover_projects",)),
        u("component_discovery.catalog_dependencies", dependencies, ("component_discovery.catalog_components",)),
        u("retrieval_indexes.build_path_index", path_index, ("repository_discovery.partition_repository",)),
        u("retrieval_indexes.build_symbol_index", symbol_index, ("repository_discovery.partition_repository",)),
        u("retrieval_indexes.build_component_index", component_index, ("component_discovery.catalog_components",)),
        u("retrieval_indexes.build_target_documents", document_index, ("repository_discovery.partition_repository",)),
        u("publish_catalog.validate_catalog", validate_catalog, ("retrieval_indexes.build_path_index", "retrieval_indexes.build_symbol_index", "retrieval_indexes.build_component_index", "retrieval_indexes.build_target_documents")),
        u("publish_catalog.publish_handoff", publish, ("publish_catalog.validate_catalog",
          "build_discovery.catalog_build_targets", "component_discovery.catalog_dependencies",
          "repository_discovery.census_languages")),
    )
    implementation = None
    validation = None
    return Job("job_target_catalog", "target_catalog", UnitExecutor(units).execute,
               input_validators=(_validate_config,), schema_identity="appsec-review/target-catalog-job/1",
               implementation_identity=implementation, validation_identity=validation, units=units,
               strict_gaps=True, datasets=DATASETS, contract=CONTRACT)
