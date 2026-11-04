"""Unity metadata enrichment of the existing SPDX 2.3 writer result."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import re
from typing import Any

from appsec_review.jobs.engine_contracts import ENGINE_METADATA_SCHEMA
from appsec_review.storage import canonical_json

from .native_sbom_contracts import SbomBounds
from .sbom import validate_spdx


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _comment(**metadata: Any) -> str:
    return canonical_json({"schema": ENGINE_METADATA_SCHEMA, **metadata}).decode("utf-8").strip()


def enrich_unity_spdx(
    result: Mapping[str, Any], unity: Mapping[str, Any], *,
    source_fingerprint: str, bounds: SbomBounds,
) -> dict[str, Any]:
    """Preserve the accepted inventory and append only evidenced metadata identities.

    This runs after ``build_spdx`` and before its normal publication/validation path.
    No descriptor digest is a package checksum and no declaration is a resolved release.
    """
    enriched = deepcopy(dict(result))
    if not unity.get("projects") and not unity.get("gaps"):
        return enriched
    document, provenance = enriched["document"], enriched["provenance"]
    packages, relationships = document.setdefault("packages", []), document.setdefault("relationships", [])
    entries = provenance["packages"]
    engine_gaps = [{"kind": "unsupported_metadata", "scope": "unity",
                    "detail": detail, "evidence_ids": []} for detail in unity.get("gaps", [])]
    enriched["gaps"].extend(engine_gaps)
    provenance.setdefault("gaps", []).extend(engine_gaps)
    for project in sorted(unity.get("projects", []), key=lambda item: item["root"]):
        root, engine, inventory = project["root"], project["engine"], project["inventory"]
        common = {"engine": "unity", "root": root, "source_fingerprint": source_fingerprint}

        def package(kind: str, name: str, metadata: Mapping[str, Any], *,
                    version: str | None = None, identity: Any = None,
                    evidence: list[Mapping[str, Any]] | None = None) -> str:
            identifier = "SPDXRef-Unity-" + _digest({
                "root": root, "kind": kind, "name": name, "version": version, "identity": identity,
                "source_fingerprint": source_fingerprint,
            })
            if identifier in entries:
                return identifier
            record = {
                "SPDXID": identifier, "name": name, "filesAnalyzed": False,
                "downloadLocation": "NOASSERTION", "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
                "comment": _comment(**common, kind=kind, **metadata),
            }
            if version:
                record["versionInfo"] = version
            packages.append(record)
            entries[identifier] = {
                "baseline_packages": [], "native_candidate_ids": [], "evidence_ids": [],
                "merge_decisions": ["unity_metadata_identity"], "conflicts": [],
                "engine_metadata": {"schema": ENGINE_METADATA_SCHEMA, **common, "kind": kind,
                                    "descriptor_evidence": evidence or []},
            }
            relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                                  "relatedSpdxElement": identifier})
            return identifier

        def edge(parent: str, child: str, kind: str, **metadata: Any) -> None:
            relationships.append({"spdxElementId": parent, "relationshipType": kind,
                                  "relatedSpdxElement": child,
                                  "comment": _comment(**common, **metadata)})

        project_id = package("source-project", "Unity project " + root, {
            "root_state": project["descriptor_facts"]["root_state"],
            "engine_conflict": project["descriptor_facts"]["engine_conflict"],
            "builtin_module_count": len({item["name"] for item in inventory.get("engine_context", [])}),
            "builtin_module_inventory_field": "engine_context",
        }, evidence=project["markers"])
        editor_id = package("declared-editor", "Unity Editor", {
            "declared_revision": engine.get("declared_revision"), "executed": False,
        }, version=engine.get("declared_version"), evidence=[
            item for item in project["markers"] if item["path"].endswith("ProjectVersion.txt")])
        edge(editor_id, project_id, "BUILD_DEPENDENCY_OF", basis="declared_editor_not_execution")
        resolutions = {item["name"]: item for item in inventory.get("resolutions", [])}
        embedded_groups: dict[str, list[dict[str, Any]]] = {}
        for item in inventory.get("embedded_packages", []):
            embedded_groups.setdefault(item["name"], []).append(item)
        embedded = {name: items[0] for name, items in embedded_groups.items() if len(items) == 1}
        builtin_names = {item["name"] for item in inventory.get("engine_context", [])}
        declarations = {item["name"]: item for item in inventory.get("declarations", [])}
        names = set(resolutions) | set(embedded_groups) | set(declarations)
        # A lockfile child is a request even when its own resolution entry is unavailable.
        for item in [*resolutions.values(), *inventory.get("embedded_packages", [])]:
            names.update(name for name in item.get("dependencies", {})
                         if name not in builtin_names and not name.startswith("com.unity.modules."))
        ids = {}
        for name in sorted(names):
            resolution, metadata, declaration = resolutions.get(name), embedded.get(name), declarations.get(name)
            release = (metadata or resolution or {}).get("version")
            version_conflict = bool(metadata and resolution and metadata["version"] != resolution["version"])
            if version_conflict:
                release = None
            version = release if release and re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", release) else None
            requested = declaration.get("requested") if declaration else None
            evidence = [item["evidence"] for item in (declaration, resolution, metadata) if item]
            ids[name] = package("package", name, {
                "requested": requested, "resolution": release,
                "source": (metadata or resolution or {}).get("kind") or (resolution or {}).get("source"),
                "revision": (resolution or {}).get("revision"),
                "resolution_status": "metadata" if metadata else "locked" if resolution else "unresolved",
                "metadata_conflict": len(embedded_groups.get(name, [])) > 1,
                "version_conflict": version_conflict,
                "locked_version": resolution["version"] if version_conflict else None,
                "metadata_version": metadata["version"] if version_conflict else None,
            }, version=version, evidence=evidence)
        for name, items in sorted(embedded_groups.items()):
            if len(items) > 1:
                for item in items:
                    variant_id = package("embedded-package-candidate", name, {
                        "path": item["path"], "metadata_conflict": True,
                        "declared_version": item["version"],
                    }, version=item["version"], identity=item["path"], evidence=[item["evidence"]])
                    for child, requested in sorted(item.get("dependencies", {}).items()):
                        if child in ids:
                            edge(variant_id, ids[child], "DEPENDS_ON", requested=requested,
                                 basis="competing_embedded_package_metadata")
        for name, declaration in sorted(declarations.items()):
            edge(project_id, ids[name], "DEPENDS_ON", requested=declaration["requested"],
                 basis="manifest_direct_declaration")
        for name, item in sorted(embedded.items()):
            # Embedded metadata establishes inventory, not an unobserved project dependency.
            if name in resolutions and resolutions[name].get("version") != item["version"]:
                conflict = {"kind": "version_conflict", "scope": root + ":" + name,
                            "detail": "Unity lock and embedded package metadata versions differ",
                            "evidence_ids": []}
                enriched["gaps"].append(conflict)
                provenance.setdefault("gaps", []).append(conflict)
        for source, parents in (("packages_lock", resolutions), ("package_metadata", embedded)):
            for name, parent in sorted(parents.items()):
                for child, requested in sorted(parent.get("dependencies", {}).items()):
                    if child in ids:
                        edge(ids[name], ids[child], "DEPENDS_ON", requested=requested, basis=source)
        for plugin in inventory.get("plugins", []):
            plugin_id = package("native-plugin", plugin["name"], {
                "path": plugin["path"],
                "scope_evidence": {"descriptor": plugin["evidence"],
                                   "selector": "/PluginImporter/platformData"},
                "identity_status": "importer_metadata_only",
            }, identity=plugin["path"], evidence=[plugin["evidence"]])
            edge(project_id, plugin_id, "DEPENDS_ON", basis="cataloged_native_plugin_importer",
                 scope="importer_configuration_only")
    document["packages"] = sorted(packages, key=lambda item: item["SPDXID"])
    unique = {canonical_json(item): item for item in relationships}
    document["relationships"] = [unique[key] for key in sorted(unique)]
    fingerprint = _digest({"base_input_fingerprint": provenance["input_fingerprint"],
                           "schema": ENGINE_METADATA_SCHEMA, "unity": unity})
    provenance["input_fingerprint"] = fingerprint
    provenance["unity_metadata"] = {"schema": ENGINE_METADATA_SCHEMA,
                                    "inventory_sha256": _digest(unity),
                                    "project_count": len(unity.get("projects", []))}
    document["documentNamespace"] = "https://appsec-review.invalid/spdx/" + fingerprint
    validate_spdx(document, bounds=bounds)
    enriched["metrics"].update({
        "output_packages": len(packages), "output_relationships": len(document["relationships"]),
        "output_bytes": len(canonical_json(document)),
    })
    # Provenance is bounded by the same publication envelope as the standard document.
    if len(canonical_json(provenance)) > bounds.output_bytes:
        from .native_sbom_contracts import SpdxValidationError
        raise SpdxValidationError("Unity provenance exceeds publication output byte bound")
    return enriched
