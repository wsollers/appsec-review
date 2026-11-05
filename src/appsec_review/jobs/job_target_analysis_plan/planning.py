from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Collection, Mapping
import copy
import hashlib
from pathlib import PurePosixPath
from typing import Any

from appsec_review.storage import canonical_json
from appsec_review.jobs.build_discovery import (
    BUILD_RECIPE_SCHEMA, DISCOVERED_BUILD_SYSTEMS, validate_build_recipe,
)
from appsec_review.jobs.component_ownership import resolve_ownership
from appsec_review.jobs.build_topology import VARIANT_FIELDS, compile_build_topology, validate_build_topology
from appsec_review.tool_inputs import SOURCE_SUFFIXES as TOOL_SOURCE_SUFFIXES, supports_path


PLAN_SCHEMA = "appsec-review/target-analysis-plan/1"
PROPOSAL_SCHEMA = "appsec-review/target-analysis-proposal/3"
SUMMARY_SCHEMA = "appsec-review/target-analysis-summary/1"

SCANNERS = (
    "tool-blint", "tool-checkov", "tool-cppcheck", "tool-gitleaks", "tool-gosec", "tool-grype",
    "tool-hadolint", "tool-mobsfscan", "tool-opengrep", "tool-osv-scanner", "tool-phpcs",
    "tool-phpstan", "tool-pmd", "tool-psalm", "tool-semgrep", "tool-shellcheck",
    "tool-spotbugs", "tool-syft", "tool-trivy", "tool-zizmor",
)
MANDATORY_BASELINE = frozenset({"tool-gitleaks", "tool-semgrep", "tool-syft"})
# Discovery's own vocabulary plus systems a plan may name for components discovery does not mark.
BUILD_SYSTEMS = DISCOVERED_BUILD_SYSTEMS | frozenset({
    "bazel", "container", "node-gyp", "php-extension", "typescript",
})

SOURCE_SUFFIXES = TOOL_SOURCE_SUFFIXES


def _under(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(root + "/")


def _component_paths(files: tuple[Mapping[str, Any], ...], components: tuple[Mapping[str, Any], ...]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {str(item["component_id"]): [] for item in components}
    for item in files:
        path = str(item["path"])
        decision = resolve_ownership(path, components)
        for component_id in decision.component_ids:
            result[component_id].append(path)
    return result


def summarize_catalog(catalog: Mapping[str, Any], *, max_items: int, max_bytes: int,
                      sample_per_prefix: int) -> dict[str, Any]:
    files = tuple(sorted(catalog["files"], key=lambda item: str(item["path"])))
    components = tuple(sorted(catalog["components"], key=lambda item: str(item["component_id"])))
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for item in files:
        prefix = str(item["path"]).split("/", 1)[0]
        grouped[prefix].append(item)
    prefixes = []
    emitted = 0
    used_bytes = 0
    truncated = False
    for prefix in sorted(grouped):
        values = grouped[prefix]
        samples = []
        for item in values:
            encoded = len(str(item["path"]).encode("utf-8")) + 96
            if len(samples) >= sample_per_prefix or emitted >= max_items or used_bytes + encoded > max_bytes:
                truncated = True
                break
            samples.append({"path": item["path"], "sha256": item["sha256"],
                            "language": item.get("language"), "size_bytes": item["size_bytes"]})
            emitted += 1
            used_bytes += encoded
        prefixes.append({"prefix": prefix, "file_count": len(values), "sample": samples})
    languages = Counter(str(item.get("language") or "Other") for item in files)
    component_paths = _component_paths(files, components)
    summary = {
        "schema": SUMMARY_SCHEMA,
        "source_fingerprint": catalog["source_fingerprint"],
        "catalog_handoff_sha256": catalog["catalog_handoff_sha256"],
        "bounds": {"max_items": max_items, "max_bytes": max_bytes,
                   "sample_per_prefix": sample_per_prefix, "items_emitted": emitted,
                   "actual_bytes": 0, "truncated": truncated},
        "file_count": len(files),
        "language_counts": [{"language": name, "file_count": languages[name]} for name in sorted(languages)],
        "prefixes": prefixes,
        "components": [{"component_id": item["component_id"], "root": item["root"],
                        "manifest": item.get("manifest"),
                        "cataloged_file_count": len(component_paths[str(item["component_id"])])}
                       for item in components],
        "recognized_build_files": list(catalog["build_files"]),
        "compile_databases": list(catalog["compile_databases"]),
        "accepted_artifacts": list(catalog.get("accepted_artifacts", ())),
        "build_units": copy.deepcopy(list(catalog.get("build_units", ()))),
        "catalog_gaps": list(catalog.get("gaps", ())),
    }
    summary["summary_sha256"] = "0" * 64
    def item_count() -> int:
        return (len(summary["language_counts"]) + len(summary["prefixes"]) +
                sum(len(item["sample"]) for item in summary["prefixes"]) +
                len(summary["components"]) + len(summary["recognized_build_files"]) +
                len(summary["compile_databases"]) + len(summary["accepted_artifacts"]) +
                len(summary["build_units"]) + len(summary["catalog_gaps"]))

    def trim_one() -> bool:
        for unit in reversed(summary["build_units"]):
            documents = unit.get("descriptor_package", {}).get("documents", [])
            if documents:
                documents.pop()
                return True
        for key in ("catalog_gaps", "accepted_artifacts", "recognized_build_files",
                    "compile_databases", "components"):
            if summary[key]:
                summary[key].pop()
                return True
        for prefix in reversed(summary["prefixes"]):
            if prefix["sample"]:
                prefix["sample"].pop()
                return True
        if summary["prefixes"]:
            summary["prefixes"].pop()
            return True
        if summary["language_counts"]:
            summary["language_counts"].pop()
            return True
        return False

    while item_count() > max_items:
        if not trim_one():
            break
        summary["bounds"]["truncated"] = True
    while True:
        summary["bounds"]["actual_bytes"] = len(canonical_json(summary))
        actual = len(canonical_json(summary))
        if actual <= max_bytes:
            summary["bounds"]["actual_bytes"] = actual
            break
        if not trim_one():
            raise ValueError("summary byte budget is too small for required identity metadata")
        summary["bounds"]["truncated"] = True
    summary["bounds"]["items_emitted"] = sum(len(item["sample"]) for item in summary["prefixes"])
    hash_payload = dict(summary)
    hash_payload.pop("summary_sha256")
    summary["summary_sha256"] = hashlib.sha256(canonical_json(hash_payload)).hexdigest()
    return summary


def ambiguity_reasons(summary: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    roots = [str(item["root"]) for item in summary["components"]]
    duplicates = sorted(root for root, count in Counter(roots).items() if count > 1)
    if duplicates:
        reasons.append(f"multiple catalog components share build roots: {', '.join(duplicates[:8])}")
    languages = [item for item in summary["language_counts"] if item["language"] != "Other"]
    if len(languages) >= 4 and len(summary["components"]) > 1:
        reasons.append("mixed-language multi-component ownership may require contextual refinement")
    if any(str(gap).find("generated") >= 0 or str(gap).find("vendor") >= 0 for gap in summary["catalog_gaps"]):
        reasons.append("generated or vendored ownership is incomplete in the accepted catalog")
    if any(item.get("build_system") != "unity" for item in summary.get("build_units", ())):
        reasons.append("buildable units require inference-derived build recipes")
    return reasons


def _scanner_scope(tool_id: str, files: tuple[Mapping[str, Any], ...], artifacts: tuple[Mapping[str, Any], ...]) -> tuple[str, ...]:
    """Deterministic scanner scope from the single declared tool input support table.

    Planning and execution read the same declarations (appsec_review.tool_inputs), so a planned
    input is always one the tool can parse; anything else is never placed in a scanner scope.
    """
    if tool_id not in SCANNERS:
        return ()
    if tool_id in {"tool-spotbugs", "tool-blint"}:
        return tuple(str(item["path"]) for item in artifacts if supports_path(tool_id, str(item["path"])))
    return tuple(str(item["path"]) for item in files if supports_path(tool_id, str(item["path"])))


def history_priority(history: Mapping[str, Any] | None, catalog: Mapping[str, Any]) -> dict[str, Any]:
    """Project accepted churn-led history ranks onto accepted catalog identities only."""
    if history is None:
        return {"status": "UNAVAILABLE", "reason": "source history job is not in this graph",
                "handoff_sha256": None, "history_identity": None, "ranking": None, "components": [], "files": []}
    if history.get("stale_reason"):
        return {"status": "UNAVAILABLE", "reason": str(history["stale_reason"]), "handoff_sha256": None,
                "history_identity": None, "ranking": None, "components": [], "files": []}
    hashes = {str(item["path"]): str(item["sha256"]) for item in catalog["files"]}
    components = {str(item["component_id"]) for item in catalog["components"]}
    ranking = history.get("ranking", {})
    status = "AVAILABLE" if ranking.get("files") or ranking.get("components") else "UNAVAILABLE"
    reason = None if status == "AVAILABLE" else str(history.get("sources", {}).get("git", {}).get("reason") or
                                                    "no ranked history")
    return {
        "status": status, "reason": reason, "handoff_sha256": history.get("handoff_sha256"),
        "history_identity": history.get("history_identity"), "ranking": ranking.get("identity"),
        "components": [{**{key: item[key] for key in ("component_id", "rank", "score", "churn_lines", "change_count")},
                        **{key: item[key] for key in ("source_id",) if key in item}}
                       for item in ranking.get("components", ()) if item.get("component_id") in components],
        "files": [{**{key: item[key] for key in ("path", "sha256", "rank", "score", "churn_lines", "change_count")},
                   **{key: item[key] for key in ("source_id", "source_path", "pinned_revision") if key in item}}
                  for item in ranking.get("files", ()) if hashes.get(str(item.get("path"))) == item.get("sha256")],
    }


def deterministic_plan(catalog: Mapping[str, Any], summary: Mapping[str, Any],
                       history: Mapping[str, Any] | None = None) -> dict[str, Any]:
    files = tuple(sorted(catalog["files"], key=lambda item: str(item["path"])))
    artifacts = tuple(catalog.get("accepted_artifacts", ()))
    hashes = {str(item["path"]): str(item["sha256"]) for item in files}
    artifact_hashes = {str(item["path"]): str(item["sha256"]) for item in artifacts}
    all_hashes = {**hashes, **artifact_hashes}
    components = tuple(sorted(catalog["components"], key=lambda item: str(item["component_id"])))
    owned = _component_paths(files, components)
    selected = []
    skipped = []
    component_scanners: dict[str, list[str]] = {str(item["component_id"]): [] for item in components}
    for tool_id in SCANNERS:
        scope = _scanner_scope(tool_id, files, artifacts)
        if scope:
            reason = "mandatory baseline coverage" if tool_id in MANDATORY_BASELINE else "deterministic catalog applicability"
            selected.append({"scanner_id": tool_id, "scope": [{"path": path, "sha256": all_hashes[path]} for path in scope],
                             "provenance": "deterministic", "reason": reason,
                             "expected_index_family": "observations"})
            for component_id, component_paths in owned.items():
                if set(scope).intersection(component_paths):
                    component_scanners[component_id].append(tool_id)
        else:
            skipped.append({"scanner_id": tool_id, "reason": "no accepted catalog input satisfies deterministic applicability",
                            "mandatory": tool_id in MANDATORY_BASELINE})
    systems = [{"build_system": unit["build_system"], "root": unit["root"],
                "manifest": unit["markers"][0] if unit.get("markers") else None,
                "build_unit_id": unit["build_unit_id"],
                "provenance": unit.get("provenance", "deterministic-marker"), "confidence": "high"}
               for unit in catalog.get("build_units", ())]
    compile_databases = [{"path": item["path"], "sha256": item["sha256"], "status": "cataloged"}
                         for item in catalog["compile_databases"]]
    component_values = []
    for component in components:
        cid = str(component["component_id"])
        component_values.append({
            "component_id": cid, "root": component["root"], "manifest": component.get("manifest"),
            "scope": [{"path": path, "sha256": hashes[path]} for path in owned[cid]],
            "scanner_ids": sorted(component_scanners[cid]), "provenance": "deterministic",
            "confidence": "high", "reasons": ["accepted catalog component and exact path ownership"],
            "contradictions": [], "coverage_gaps": [],
        })
    gaps = [(f"{item.get('path')}: {item.get('reason')}" if isinstance(item, Mapping) else str(item))
            for item in catalog.get("gaps", ())]
    if not systems:
        gaps.append("build topology: no recognized build system in the accepted catalog")
    if not compile_databases:
        gaps.append("build topology: no accepted compile database; compiled-unit coverage is unavailable")
    gaps.append("build topology: logical descriptor targets do not establish compiled link outputs without accepted build artifacts")
    generated = [{"path": item.get("path"), "status": "excluded", "reason": item.get("reason")}
                 for item in catalog.get("gaps", ()) if isinstance(item, Mapping) and
                 item.get("reason") == "generated_file_excluded"]
    plan = {
        "schema": PLAN_SCHEMA, "source_fingerprint": catalog["source_fingerprint"],
        "catalog_handoff_sha256": catalog["catalog_handoff_sha256"],
        "summary_sha256": summary["summary_sha256"], "provenance": "deterministic",
        "components": component_values,
        "scanner_selections": selected, "scanner_non_selections": skipped,
        "build_topology": {
            "projects": list(catalog.get("projects", ())), "build_systems": systems,
            "build_actions": [{"action": "configure-and-build", "root": item["root"],
                               "family": item["family"], "build_system": item["build_system"],
                               "build_unit_id": item["build_unit_id"],
                               "markers": list(item.get("markers", ())),
                               "descriptor_package": dict(item.get("descriptor_package", {})),
                               "project_type": item.get("project_type", "generic"),
                               "descriptor_facts": dict(item.get("descriptor_facts", {})),
                               "engine": dict(item.get("engine", {})),
                               "engine_project": dict(item.get("engine_project", {})),
                               "native_components": [dict(value) for value in item.get("native_components", ())],
                               "required_image_profile": item.get("required_image_profile", item["family"]),
                               "build_variant": dict(item.get("build_variant", dict.fromkeys(VARIANT_FIELDS))),
                               "recipe": None, "requires_inference": item["build_system"] != "unity",
                               "executable": False}
                              for item in catalog.get("build_units", ())],
            "compile_databases": compile_databases,
            "compile_units": [{"compile_database": item["path"], "status": "cataloged-unexpanded"}
                              for item in compile_databases],
            "generated_sources": generated, "targets": list(artifacts),
            "source_only_scopes": [dict(value) for value in catalog.get("source_only_scopes", ())],
            "link_outputs": [item for item in artifacts if PurePosixPath(str(item["path"])).suffix.lower()
                             in {".exe", ".dll", ".so", ".dylib", ".a"}],
            "relationships": [{"kind": "component_build_root", "component_id": component["component_id"],
                               "build_root": component["root"]} for component in component_values],
        },
        "prerequisites": ["accepted target catalog", "verified immutable retrieval index set"],
        "expected_artifact_families": ["observations", "software-inventory", "configuration", "build"],
        "confidence": "high" if not gaps else "medium", "contradictions": [],
        "coverage_gaps": list(dict.fromkeys(gaps)), "model": {"status": "NOT_NEEDED", "proposal_sha256": None},
        "history_priority": history_priority(history, catalog),
    }
    _publish_build_graph(plan)
    return plan


def _publish_build_graph(plan: dict[str, Any]) -> None:
    topology = plan["build_topology"]
    environment = plan.get("build_environment")
    graph = compile_build_topology(
        topology["build_actions"], source_fingerprint=plan["source_fingerprint"],
        component_relationships=topology["relationships"], environment=environment)
    topology["executable_graph"] = graph
    from appsec_review.jobs.build_topology import topology_evidence_bundle, refine_build_topology
    topology["evidence_bundle"] = topology_evidence_bundle(
        topology["build_actions"], source_fingerprint=plan["source_fingerprint"], environment=environment)
    topology["planning_refinement"] = refine_build_topology(
        graph, topology["build_actions"], environment=environment)
    plan["coverage_gaps"] = list(dict.fromkeys([
        *(gap for gap in plan["coverage_gaps"] if not gap.startswith("executable build graph: ")),
        *(f"executable build graph: {gap['code']}: {gap['reason']}" for gap in graph["coverage_gaps"]),
    ]))


def validate_proposal(proposal: Mapping[str, Any], *, catalog: Mapping[str, Any],
                      allowed_components: Collection[str] | None = None,
                      allowed_paths: Collection[str] | None = None,
                      allowed_scanners: Collection[str] | None = None,
                      allowed_build_systems: Collection[str] | None = None) -> list[str]:
    errors: list[str] = []
    if (set(proposal) != {"schema", "action", "component_proposals", "build_recipes", "hints", "abstentions"}
            or proposal.get("schema") != PROPOSAL_SCHEMA or proposal.get("action") != "final"):
        return ["proposal must be a closed proposal/3 final response"]
    graph = compile_build_topology(catalog.get("build_units", ()),
                                   source_fingerprint=catalog["source_fingerprint"])
    fact_ids = {fact["fact_id"] for fact in graph["facts"]}
    hints = proposal.get("hints")
    if (not isinstance(hints, list) or len(hints) > 256
            or any(not isinstance(item, str) or item not in fact_ids for item in hints)):
        errors.append("hints must resolve deterministic whole-bundle fact identities")
    abstentions = proposal.get("abstentions")
    unit_ids = {item["build_unit_id"] for item in catalog.get("build_units", ())}
    abstained = set()
    if not isinstance(abstentions, list) or len(abstentions) > 256:
        errors.append("abstentions must be bounded")
    else:
        for item in abstentions:
            if (not isinstance(item, Mapping) or set(item) != {"build_unit_id", "reason"}
                    or item["build_unit_id"] not in unit_ids or item["build_unit_id"] in abstained
                    or not isinstance(item["reason"], str) or not item["reason"].strip()
                    or len(item["reason"].encode()) > 2048):
                errors.append("abstention must name one accepted unit and a bounded reason")
            else:
                abstained.add(item["build_unit_id"])
    values = proposal.get("component_proposals")
    if not isinstance(values, list) or len(values) > 256:
        return ["component_proposals must be a bounded list"]
    components = {str(item["component_id"]): item for item in catalog["components"]}
    paths = {str(item["path"]) for item in catalog["files"]}
    component_boundary = set(allowed_components) if allowed_components is not None else set(components)
    path_boundary = set(allowed_paths) if allowed_paths is not None else paths
    scanner_boundary = set(allowed_scanners) if allowed_scanners is not None else set(SCANNERS)
    system_boundary = set(allowed_build_systems) if allowed_build_systems is not None else set(BUILD_SYSTEMS)
    files = tuple(catalog["files"])
    artifacts = tuple(catalog.get("accepted_artifacts", ()))
    owned_paths = _component_paths(files, tuple(components.values()))
    unit_owners = {}
    component_systems = defaultdict(set)
    for node in graph["nodes"]:
        ownership = resolve_ownership(node["root"], components.values())
        if ownership.status == "owned":
            owner = ownership.component_ids[0]
            unit_owners[node["build_unit_id"]] = owner
            component_systems[owner].add(node["build_system"])
    derived_dependencies = {(unit_owners[edge["consumer_build_unit_id"]],
                             unit_owners[edge["producer_build_unit_id"]])
                            for edge in graph["edges"]
                            if edge["consumer_build_unit_id"] in unit_owners
                            and edge["producer_build_unit_id"] in unit_owners}
    seen_components: set[str] = set()
    edges: dict[str, set[str]] = {}
    for index, item in enumerate(values):
        where = f"component_proposals[{index}]"
        required = {"component_id", "scanner_ids", "build_systems", "scope_paths", "dependencies", "reason"}
        if not isinstance(item, Mapping) or set(item) != required:
            errors.append(f"{where}: unsupported or missing fields")
            continue
        component_id = str(item["component_id"])
        if component_id not in components or component_id not in component_boundary:
            errors.append(f"{where}: component is not an accepted bounded catalog identity")
        if component_id in seen_components:
            errors.append(f"{where}: component proposal is duplicated")
        seen_components.add(component_id)
        scanners = item["scanner_ids"]
        systems = item["build_systems"]
        scope = item["scope_paths"]
        dependencies = item["dependencies"]
        if (not isinstance(scanners, list) or len(scanners) > min(20, len(SCANNERS)) or
                any(not isinstance(value, str) or value not in SCANNERS or value not in scanner_boundary
                    for value in scanners) or
                len(scanners) != len(set(scanners))):
            errors.append(f"{where}: scanner selection is not allowlisted")
        if (not isinstance(systems, list) or len(systems) > min(24, len(BUILD_SYSTEMS)) or
                any(not isinstance(value, str) or value not in BUILD_SYSTEMS or value not in system_boundary
                    for value in systems) or
                len(systems) != len(set(systems))):
            errors.append(f"{where}: build system is not allowlisted")
        elif not set(systems) <= component_systems[component_id]:
            errors.append(f"{where}: build system is not derived from accepted component build units")
        scope_valid = (isinstance(scope, list) and len(scope) <= min(10000, len(paths)) and
                       all(isinstance(value, str) and len(value) <= 512 and value in paths and value in path_boundary and
                           value in owned_paths.get(component_id, ()) for value in scope) and
                       len(scope) == len(set(scope)))
        if not scope_valid:
            errors.append(f"{where}: scope is not an accepted bounded path beneath the component")
        elif isinstance(scanners, list):
            for scanner in scanners:
                if scanner in SCANNERS and (not scope or not set(scope) <= set(_scanner_scope(scanner, files, artifacts))):
                    errors.append(f"{where}: scope violates deterministic safety rules for {scanner}")
        dependencies_valid = (isinstance(dependencies, list) and len(dependencies) <= 128 and
                              all(isinstance(value, str) and value in components for value in dependencies) and
                              len(dependencies) == len(set(dependencies)) and component_id not in dependencies)
        if not dependencies_valid:
            errors.append(f"{where}: dependency is not an accepted component identity")
        else:
            edges[component_id] = set(dependencies)
            if any(dependency not in component_boundary for dependency in dependencies):
                errors.append(f"{where}: dependency is outside the bounded component request")
            if any((component_id, dependency) not in derived_dependencies for dependency in dependencies):
                errors.append(f"{where}: dependency is not derived from deterministic source relationships")
        reason = item["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 2048:
            errors.append(f"{where}: reason is missing or exceeds the bound")
    def cyclic(node: str, visiting: set[str], visited: set[str]) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        found = any(cyclic(child, visiting, visited) for child in edges.get(node, ()))
        visiting.remove(node)
        visited.add(node)
        return found
    visited: set[str] = set()
    if any(cyclic(node, set(), visited) for node in edges):
        errors.append("component proposal dependencies contain a cycle")
    recipes = proposal.get("build_recipes")
    units = {str(item["build_unit_id"]): item for item in catalog.get("build_units", ())}
    if not isinstance(recipes, list) or len(recipes) > 256:
        errors.append("build_recipes must be a bounded list")
    else:
        seen_recipes: set[str] = set()
        for index, recipe in enumerate(recipes):
            if not isinstance(recipe, Mapping):
                errors.append(f"build_recipes[{index}] must be an object")
                continue
            unit_id = str(recipe.get("build_unit_id", ""))
            if unit_id not in units:
                errors.append(f"build_recipes[{index}] does not reference an accepted build unit")
                continue
            if unit_id in seen_recipes:
                errors.append(f"build_recipes[{index}] duplicates a build unit")
            seen_recipes.add(unit_id)
            errors.extend(f"build_recipes[{index}]: {error}" for error in validate_build_recipe(recipe, units[unit_id]))
        if seen_recipes & abstained:
            errors.append("unit cannot have both a recipe and an abstention")
        missing = sorted(set(units) - seen_recipes - abstained)
        if missing:
            errors.append("build_recipes omitted accepted build units: " + ", ".join(missing[:8]))
    return errors


def merge_proposal(plan: Mapping[str, Any], proposal: Mapping[str, Any], catalog: Mapping[str, Any]) -> dict[str, Any]:
    if proposal.get("component_proposals") != []:
        errors = validate_proposal(proposal, catalog=catalog)
        if errors:
            raise ValueError("invalid bounded component proposal: " + "; ".join(errors))
    result = copy.deepcopy(dict(plan))
    path_hashes = {str(item["path"]): str(item["sha256"]) for item in catalog["files"]}
    components = {item["component_id"]: item for item in result["components"]}
    selected = {item["scanner_id"]: item for item in result["scanner_selections"]}
    for item in proposal["component_proposals"]:
        component = components[item["component_id"]]
        component["scanner_ids"] = sorted(set(component["scanner_ids"]) | set(item["scanner_ids"]))
        component["provenance"] = "model-assisted"
        for scanner_id in item["scanner_ids"]:
            scopes = set(item["scope_paths"])
            if scanner_id in selected:
                scopes.update(value["path"] for value in selected[scanner_id]["scope"])
            selected[scanner_id] = {"scanner_id": scanner_id,
                "scope": [{"path": path, "sha256": path_hashes[path]} for path in sorted(scopes)],
                "provenance": "model-assisted", "reason": str(item["reason"]),
                "expected_index_family": "observations"}
        for dependency in item["dependencies"]:
            relation = {"kind": "depends_on", "component_id": item["component_id"], "dependency_component_id": dependency}
            if relation not in result["build_topology"]["relationships"]:
                result["build_topology"]["relationships"].append(relation)
    recipes = {item["build_unit_id"]: item for item in proposal["build_recipes"]}
    for action in result["build_topology"]["build_actions"]:
        recipe = recipes.get(action.get("build_unit_id"))
        if recipe is not None:
            action["recipe"] = recipe
            action["requires_inference"] = False
    result["scanner_selections"] = [selected[key] for key in sorted(selected)]
    chosen = set(selected)
    result["scanner_non_selections"] = [item for item in result["scanner_non_selections"] if item["scanner_id"] not in chosen]
    result["provenance"] = "model-assisted"
    result["model"] = {"status": "ACCEPTED", "proposal_sha256": hashlib.sha256(canonical_json(proposal)).hexdigest()}
    _publish_build_graph(result)
    return result


def evidence_catalog(catalog, documents):
    """Augment only exact accepted inventory identities; ownership still comes from source rules."""
    documents = tuple(documents)
    if not documents:
        return catalog
    result = copy.deepcopy(dict(catalog))
    inventory = {item["path"]: item["sha256"] for item in catalog["files"]}
    captured = {}
    for document in documents:
        if (set(document) != {"path", "sha256", "content"}
                or inventory.get(document["path"]) != document["sha256"]
                or not isinstance(document["content"], str)
                or hashlib.sha256(document["content"].encode()).hexdigest() != document["sha256"]):
            raise ValueError("planning evidence does not resolve accepted source bytes")
        if document["path"] in captured and captured[document["path"]] != document:
            raise ValueError("conflicting planning evidence")
        captured[document["path"]] = document
    for unit in result.get("build_units", ()):
        package = unit.setdefault("descriptor_package", {})
        existing = {item["path"]: item for item in package.get("documents", ())}
        for path, document in captured.items():
            if _under(path, unit["root"]):
                if path in existing and existing[path] != document:
                    raise ValueError("planning evidence changed captured descriptor bytes")
                existing[path] = copy.deepcopy(document)
        package["documents"] = [existing[path] for path in sorted(existing)]
    return result


def model_safe(value):
    from appsec_review.jobs.job_build_environment_analysis.job import redact, SECRET
    if isinstance(value, Mapping):
        return {key: "[REDACTED]" if SECRET.search(str(key)) else model_safe(item)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [model_safe(item) for item in value]
    return redact(value) if isinstance(value, str) else value


def feedback_request(request, catalog, limits):
    """Offer exact additional inventory identities within the existing request-byte budget."""
    from dataclasses import asdict, replace
    roots = [unit["root"] for unit in catalog.get("build_units", ())]
    captured = {document["path"] for unit in catalog.get("build_units", ())
                for document in unit.get("descriptor_package", {}).get("documents", ())}
    eligible = sorted((item for item in catalog["files"]
                       if item["path"] not in captured and any(_under(item["path"], root) for root in roots)),
                      key=lambda item: item["path"])
    references = []
    offered = replace(request, summary={**request.summary, "evidence_inventory": references,
                                       "evidence_inventory_omitted": len(eligible)})
    for item in eligible:
        candidate = {key: item[key] for key in ("path", "sha256", "size_bytes")}
        references.append(candidate)
        offered = replace(offered, summary={**offered.summary,
            "evidence_inventory_omitted": len(eligible) - len(references)},
            allowed_paths=tuple(sorted({*request.allowed_paths, *(entry["path"] for entry in references)})))
        # Leave room for the first evidence response and repair metadata, not just identities.
        if len(canonical_json(model_safe(asdict(offered)))) > min(
                limits.max_request_bytes, request.max_input_tokens * 4) * 3 // 4:
            references.pop()
            return replace(offered, summary={**offered.summary, "evidence_inventory": list(references),
                "evidence_inventory_omitted": len(eligible) - len(references)},
                allowed_paths=tuple(sorted({*request.allowed_paths, *(entry["path"] for entry in references)})))
    return offered


def bounded_feedback(infer, request, *, catalog, limits, read_document, cache_root, identity,
                     clock=None, on_call=None, call_timeout_seconds=None):
    """One finite evidence/repair conversation. Only a validated complete final is reusable."""
    from dataclasses import asdict, replace
    import time
    from appsec_review.inference import ModelOutputError
    from appsec_review.storage.shared import safe_path, immutable_bytes
    from appsec_review.jobs.build_discovery import normalize_build_recipe
    clock = clock or time.monotonic
    call_timeout_seconds = limits.deadline_seconds if call_timeout_seconds is None else call_timeout_seconds
    if type(call_timeout_seconds) is not int or call_timeout_seconds < 1:
        raise ValueError("feedback model call timeout must be a positive integer")
    started = clock()
    metrics = {"request_bytes": 0, "response_bytes": 0, "evidence_bytes": 0, "evidence_rounds": 0}
    def finish(value):
        return {**value, "metrics": {**metrics, "elapsed_seconds": clock() - started}}
    inventory = {item["path"]: item for item in catalog["files"]}
    key = hashlib.sha256(canonical_json({
        "identity": identity, "request": asdict(request), "limits": asdict(limits),
        "source": catalog["source_fingerprint"], "call_timeout_seconds": call_timeout_seconds,
        "accepted_units": catalog.get("build_units", ()), "rules": "bounded-feedback/1",
    })).hexdigest()
    cache_path = safe_path(cache_root, key + ".json")
    if cache_path.is_file():
        if cache_path.stat().st_size > 2 * (limits.max_response_bytes + limits.max_evidence_bytes) + 4096:
            raise ValueError("feedback cache exceeds its bound")
        cached = json.loads(cache_path.read_bytes())
        if set(cached) != {"key", "proposal", "documents", "status"} or cached["key"] != key:
            raise ValueError("feedback cache identity mismatch")
        augmented = evidence_catalog(catalog, cached["documents"])
        documents = cached["documents"]
        if (cached["status"] != "COMPLETE" or not isinstance(documents, list)
                or len(documents) > limits.max_evidence_rounds * limits.max_documents
                or len({item["path"] for item in documents}) != len(documents)
                or sum(len(item["content"].encode()) for item in documents) > limits.max_evidence_bytes
                or any(len(item["content"].encode()) > limits.max_document_bytes for item in documents)
                or any(item["path"] not in request.allowed_paths for item in documents)
                or model_safe(documents) != documents or model_safe(cached["proposal"]) != cached["proposal"]
                or cached["proposal"].get("abstentions") != []
                or validate_proposal(cached["proposal"], catalog=augmented,
                    allowed_components=request.allowed_components, allowed_paths=request.allowed_paths,
                    allowed_scanners=request.allowed_scanners,
                    allowed_build_systems=request.allowed_build_systems)):
            raise ValueError("feedback cache is not a complete validated final")
        metrics["evidence_bytes"] = sum(len(item["content"].encode()) for item in documents)
        return finish({"status": "ACCEPTED", "proposal": cached["proposal"], "documents": documents,
                       "calls": 0, "errors": [], "gap": None, "cache_key": key, "cache_hit": True})
    documents, calls, rounds, errors = {}, 0, 0, []
    current = request
    while calls < limits.max_calls:
        remaining = limits.deadline_seconds - (clock() - started)
        if remaining <= 0:
            errors.append("internal_feedback_deadline")
            break
        current = replace(current, summary=model_safe(current.summary),
                          prior_response=model_safe(current.prior_response),
                          repair_errors=tuple(model_safe(current.repair_errors)))
        request_bytes = canonical_json(asdict(current))
        if len(request_bytes) > min(limits.max_request_bytes, current.max_input_tokens * 4):
            errors.append("feedback_request_byte_bound")
            break
        calls += 1
        metrics["request_bytes"] += len(request_bytes)
        if on_call:
            on_call("STARTED", calls, key, None)
        try:
            result = infer(current, timeout_seconds=max(
                1, min(int(remaining), call_timeout_seconds, limits.deadline_seconds)))
        except (ModelOutputError, TimeoutError) as exc:
            errors = ["model_output_invalid" if isinstance(exc, ModelOutputError) else "model_timeout"]
            if on_call:
                on_call("REJECTED", calls, key, type(exc).__name__)
            current = replace(current, repair_errors=tuple(errors), prior_response=None)
            continue
        if on_call:
            on_call("COMPLETED", calls, key, None, result)
        raw_size = len(result.raw_response.encode()) if result.raw_response is not None else 0
        response_size = max(raw_size, len(canonical_json(result.proposal)))
        metrics["response_bytes"] += response_size
        if clock() - started >= limits.deadline_seconds:
            errors = ["internal_feedback_deadline"]
            break
        if response_size > limits.max_response_bytes:
            errors = ["feedback_response_byte_bound"]
            current = replace(current, repair_errors=tuple(errors), prior_response=None)
            continue
        if not isinstance(result.proposal, Mapping):
            errors = ["model_response_must_be_an_object"]
            current = replace(current, repair_errors=tuple(errors), prior_response=None)
            continue
        proposal = copy.deepcopy(dict(result.proposal))
        if model_safe(proposal) != proposal:
            errors = ["sensitive_model_output_rejected"]
            current = replace(current, repair_errors=tuple(errors), prior_response=None)
            continue
        if proposal.get("schema") == PROPOSAL_SCHEMA and proposal.get("action") == "need_evidence":
            requests = proposal.get("requests")
            if (set(proposal) != {"schema", "action", "requests"} or not isinstance(requests, list)
                    or not 1 <= len(requests) <= limits.max_documents):
                errors = ["invalid_bounded_evidence_request"]
            elif rounds >= limits.max_evidence_rounds:
                errors = ["evidence_rounds_exhausted"]
                break
            else:
                rounds += 1
                metrics["evidence_rounds"] = rounds
                additions, request_errors = {}, []
                roots = [unit["root"] for unit in catalog.get("build_units", ())]
                for item in requests:
                    if (not isinstance(item, Mapping) or set(item) != {"path", "sha256", "reason"}
                            or not isinstance(item["path"], str)
                            or not isinstance(item["reason"], str) or not item["reason"].strip()
                            or len(item["reason"].encode()) > 2048
                            or item["path"] not in inventory
                            or item["path"] not in current.allowed_paths
                            or inventory[item["path"]]["sha256"] != item["sha256"]
                            or not any(_under(item["path"], root) for root in roots)):
                        request_errors.append("evidence_identity_or_scope_rejected")
                        continue
                    if item["path"] in documents or item["path"] in additions:
                        request_errors.append("evidence_request_makes_no_progress")
                        continue
                    if clock() - started >= limits.deadline_seconds:
                        request_errors.append("internal_feedback_deadline")
                        break
                    payload = read_document(inventory[item["path"]], limits.max_document_bytes)
                    if len(payload) > limits.max_document_bytes:
                        request_errors.append("evidence_document_byte_bound")
                        continue
                    if hashlib.sha256(payload).hexdigest() != item["sha256"]:
                        raise ValueError("requested evidence source identity changed")
                    try:
                        text = payload.decode("utf-8")
                    except UnicodeDecodeError:
                        request_errors.append("unsupported_evidence_encoding")
                        continue
                    if model_safe(text) != text:
                        request_errors.append("sensitive_evidence_withheld")
                        continue
                    additions[item["path"]] = {"path": item["path"], "sha256": item["sha256"],
                                               "content": text}
                if sum(len(item["content"].encode()) for item in (*documents.values(), *additions.values())
                       ) > limits.max_evidence_bytes:
                    request_errors.append("additive_evidence_byte_bound")
                if request_errors:
                    errors = sorted(set(request_errors))
                else:
                    documents.update(additions)
                    metrics["evidence_bytes"] = sum(len(item["content"].encode()) for item in documents.values())
                    current = replace(current, summary={**request.summary,
                        "evidence": [documents[path] for path in sorted(documents)]},
                        repair_errors=(), prior_response=None)
                    continue
        else:
            augmented = evidence_catalog(catalog, documents.values())
            units = {unit["build_unit_id"]: unit for unit in augmented.get("build_units", ())}
            recipes = proposal.get("build_recipes")
            if isinstance(recipes, list):
                proposal["build_recipes"] = [
                    normalize_build_recipe(recipe, units.get(str(recipe.get("build_unit_id"))))
                    if isinstance(recipe, Mapping) else recipe for recipe in recipes]
            errors = validate_proposal(proposal, catalog=augmented,
                allowed_components=current.allowed_components, allowed_paths=current.allowed_paths,
                allowed_scanners=current.allowed_scanners,
                allowed_build_systems=current.allowed_build_systems)
            if not errors:
                withheld = proposal["abstentions"]
                status = "PARTIAL" if withheld else "ACCEPTED"
                if not withheld:
                    immutable_bytes(cache_root, key + ".json", canonical_json({
                        "key": key, "status": "COMPLETE", "proposal": proposal,
                        "documents": list(documents.values())}))
                return finish({"status": status, "proposal": proposal, "documents": list(documents.values()),
                        "calls": calls, "errors": [], "gap": (
                            "model abstained: " + "; ".join(
                                f"{item['build_unit_id']}: {model_safe(item['reason'])}" for item in withheld)
                            if withheld else None), "cache_key": key, "cache_hit": False})
        current = replace(current, repair_errors=tuple(model_safe(errors[:20])), prior_response=None)
    return finish({"status": "BUDGET_EXCEEDED", "proposal": None, "documents": list(documents.values()),
            "calls": calls, "errors": model_safe(errors[:20]), "gap": (
                "bounded feedback exhausted: " + "; ".join(model_safe(errors[:20]))),
            "cache_key": key, "cache_hit": False})


def validate_plan(plan: Mapping[str, Any], catalog: Mapping[str, Any]) -> None:
    catalog = evidence_catalog(catalog, plan.get("planning_evidence", ()))
    if plan.get("schema") != PLAN_SCHEMA or plan.get("source_fingerprint") != catalog["source_fingerprint"]:
        raise ValueError("analysis plan identity does not match the accepted target catalog")
    paths = {str(item["path"]): str(item["sha256"]) for item in catalog["files"]}
    paths.update({str(item["path"]): str(item["sha256"]) for item in catalog.get("accepted_artifacts", ())})
    components = {str(item["component_id"]) for item in catalog["components"]}
    seen = set()
    for item in plan.get("scanner_selections", []):
        scanner = item.get("scanner_id")
        if scanner not in SCANNERS or scanner in seen:
            raise ValueError("analysis plan contains an unknown or duplicated scanner")
        seen.add(scanner)
        for scope in item.get("scope", []):
            if paths.get(str(scope.get("path"))) != scope.get("sha256"):
                raise ValueError("analysis plan scope is not an exact accepted catalog identity")
    accounted = seen | {item.get("scanner_id") for item in plan.get("scanner_non_selections", [])
                        if item.get("mandatory") is True and item.get("reason")}
    if not MANDATORY_BASELINE <= accounted:
        raise ValueError("analysis plan silently suppressed mandatory baseline coverage")
    for item in plan.get("components", []):
        if item.get("component_id") not in components:
            raise ValueError("analysis plan component is not accepted by the catalog")
    priority = plan.get("history_priority", {})
    if any(item.get("component_id") not in components for item in priority.get("components", [])):
        raise ValueError("analysis plan history priority names an unaccepted component")
    if any(paths.get(str(item.get("path"))) != item.get("sha256") for item in priority.get("files", [])):
        raise ValueError("analysis plan history priority is not an exact accepted catalog identity")
    systems = plan.get("build_topology", {}).get("build_systems", [])
    if any(item.get("build_system") not in BUILD_SYSTEMS for item in systems):
        raise ValueError("analysis plan contains an unregistered build system")
    if any(item.get("executable") is not False for item in plan.get("build_topology", {}).get("build_actions", [])):
        raise ValueError("analysis planning may not authorize executable build actions")
    units = {str(item["build_unit_id"]): item for item in catalog.get("build_units", ())}
    action_ids = [str(action.get("build_unit_id", ""))
                  for action in plan.get("build_topology", {}).get("build_actions", [])]
    if len(action_ids) != len(set(action_ids)) or set(action_ids) != set(units):
        raise ValueError("analysis plan must account for every accepted build unit exactly once")
    for action in plan.get("build_topology", {}).get("build_actions", []):
        unit_id = str(action.get("build_unit_id", ""))
        if unit_id not in units:
            raise ValueError("analysis plan build action is not an accepted build unit")
        accepted_unit = units[unit_id]
        if (action.get("markers") != accepted_unit.get("markers") or
                action.get("descriptor_package") != accepted_unit.get("descriptor_package") or
                action.get("family") != accepted_unit.get("family") or
                action.get("build_system") != accepted_unit.get("build_system") or
                action.get("engine", {}) != accepted_unit.get("engine", {}) or
                action.get("engine_project", {}) != accepted_unit.get("engine_project", {}) or
                action.get("descriptor_facts", {}) != accepted_unit.get("descriptor_facts", {}) or
                action.get("native_components", []) != list(accepted_unit.get("native_components", ())) or
                action.get("required_image_profile") != accepted_unit.get("required_image_profile", accepted_unit["family"]) or
                action.get("build_variant") != accepted_unit.get("build_variant", dict.fromkeys(VARIANT_FIELDS)) or
                action.get("root") != accepted_unit.get("root")):
            raise ValueError("analysis plan build action facts differ from the accepted catalog")
        recipe = action.get("recipe")
        if action.get("build_system") == "unity" and recipe is not None:
            raise ValueError("Unity builds require configured engine capability, not inferred recipes")
        if recipe is not None:
            errors = validate_build_recipe(recipe, units[unit_id])
            if errors:
                raise ValueError("analysis plan build recipe is invalid: " + "; ".join(errors))
    topology = plan.get("build_topology", {})
    graph = topology.get("executable_graph")
    if not isinstance(graph, Mapping):
        raise ValueError("analysis plan requires an accepted executable build graph")
    validate_build_topology(graph)
    expected = compile_build_topology(
        topology["build_actions"], source_fingerprint=catalog["source_fingerprint"],
        component_relationships=topology["relationships"], environment=plan.get("build_environment"))
    if graph != expected:
        raise ValueError("analysis plan build graph differs from accepted descriptor declarations")
