from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Collection, Mapping
import hashlib
from pathlib import PurePosixPath
from typing import Any

from appsec_review.storage import canonical_json
from appsec_review.jobs.build_discovery import BUILD_RECIPE_SCHEMA, validate_build_recipe


PLAN_SCHEMA = "appsec-review/target-analysis-plan/1"
PROPOSAL_SCHEMA = "appsec-review/target-analysis-proposal/2"
SUMMARY_SCHEMA = "appsec-review/target-analysis-summary/1"

SCANNERS = (
    "tool-blint", "tool-checkov", "tool-cppcheck", "tool-gitleaks", "tool-gosec", "tool-grype",
    "tool-hadolint", "tool-mobsfscan", "tool-osv-scanner", "tool-phpcs",
    "tool-phpstan", "tool-pmd", "tool-psalm", "tool-semgrep", "tool-shellcheck",
    "tool-spotbugs", "tool-syft", "tool-trivy", "tool-zizmor",
)
MANDATORY_BASELINE = frozenset({"tool-gitleaks", "tool-semgrep", "tool-syft"})
BUILD_SYSTEMS = frozenset({
    "autotools", "bazel", "cargo", "cmake", "composer", "container", "direct-native",
    "dotnet", "go", "gradle", "javac", "make", "maven", "meson", "msbuild", "node",
    "node-gyp", "php-extension", "python", "rustc", "typescript", "wasm",
})

SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".go", ".rs",
    ".c", ".h", ".cc", ".cpp", ".cs", ".rb", ".php", ".swift", ".sh",
}


def _under(path: str, root: str) -> bool:
    return root == "." or path == root or path.startswith(root + "/")


def _component_paths(files: tuple[Mapping[str, Any], ...], components: tuple[Mapping[str, Any], ...]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {str(item["component_id"]): [] for item in components}
    ordered = sorted(components, key=lambda item: (-len(PurePosixPath(str(item["root"])).parts), str(item["component_id"])))
    for item in files:
        path = str(item["path"])
        owner = next((component for component in ordered if _under(path, str(component["root"]))), None)
        if owner is not None:
            result[str(owner["component_id"])].append(path)
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
        "build_units": list(catalog.get("build_units", ())),
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
    if summary.get("build_units"):
        reasons.append("buildable units require inference-derived build recipes")
    return reasons


def _scanner_scope(tool_id: str, files: tuple[Mapping[str, Any], ...], artifacts: tuple[Mapping[str, Any], ...]) -> tuple[str, ...]:
    def paths(predicate) -> tuple[str, ...]:
        return tuple(str(item["path"]) for item in files if predicate(PurePosixPath(str(item["path"])), item))
    if tool_id in {"tool-gitleaks", "tool-syft"}:
        return tuple(str(item["path"]) for item in files)
    if tool_id == "tool-semgrep":
        return paths(lambda path, item: path.suffix.lower() in SOURCE_SUFFIXES)
    if tool_id == "tool-gosec":
        return paths(lambda path, item: path.suffix.lower() == ".go")
    if tool_id == "tool-cppcheck":
        return paths(lambda path, item: path.suffix.lower() in {
            ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"})
    if tool_id == "tool-mobsfscan":
        return paths(lambda path, item: path.suffix.lower() in {".java", ".kt", ".swift"})
    if tool_id == "tool-pmd":
        return paths(lambda path, item: path.suffix.lower() == ".java")
    if tool_id == "tool-shellcheck":
        return paths(lambda path, item: path.suffix.lower() == ".sh")
    if tool_id in {"tool-phpcs", "tool-phpstan", "tool-psalm"}:
        return paths(lambda path, item: path.suffix.lower() == ".php")
    if tool_id == "tool-spotbugs":
        return tuple(str(item["path"]) for item in artifacts if PurePosixPath(str(item["path"])).suffix.lower() in {".jar", ".war", ".ear", ".class"})
    if tool_id == "tool-osv-scanner":
        return paths(lambda path, item: path.name in {"requirements.txt", "poetry.lock", "Pipfile.lock"})
    if tool_id == "tool-grype":
        return tuple(str(item["path"]) for item in files)
    if tool_id == "tool-hadolint":
        return paths(lambda path, item: path.name == "Dockerfile" or path.name.startswith("Dockerfile."))
    if tool_id in {"tool-checkov", "tool-trivy"}:
        return paths(lambda path, item: path.suffix.lower() in {".tf", ".tfvars", ".hcl"} or path.name == "Dockerfile" or path.name.startswith("Dockerfile."))
    if tool_id == "tool-zizmor":
        return paths(lambda path, item: str(path).startswith(".github/workflows/") and path.suffix.lower() in {".yml", ".yaml"})
    if tool_id == "tool-blint":
        return tuple(str(item["path"]) for item in artifacts if PurePosixPath(str(item["path"])).suffix.lower() in {".dll", ".exe", ".so", ".dylib", ".a", ".o"})
    return ()


def deterministic_plan(catalog: Mapping[str, Any], summary: Mapping[str, Any]) -> dict[str, Any]:
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
    gaps.append("build topology: build targets and link outputs are not inferred without accepted build artifacts")
    generated = [{"path": item.get("path"), "status": "excluded", "reason": item.get("reason")}
                 for item in catalog.get("gaps", ()) if isinstance(item, Mapping) and
                 item.get("reason") == "generated_file_excluded"]
    return {
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
                               "recipe": None, "requires_inference": True, "executable": False}
                              for item in catalog.get("build_units", ())],
            "compile_databases": compile_databases,
            "compile_units": [{"compile_database": item["path"], "status": "cataloged-unexpanded"}
                              for item in compile_databases],
            "generated_sources": generated, "targets": list(artifacts),
            "link_outputs": [item for item in artifacts if PurePosixPath(str(item["path"])).suffix.lower()
                             in {".exe", ".dll", ".so", ".dylib", ".a"}],
            "relationships": [{"kind": "component_build_root", "component_id": component["component_id"],
                               "build_root": component["root"]} for component in component_values],
        },
        "prerequisites": ["accepted target catalog", "verified immutable retrieval index set"],
        "expected_artifact_families": ["observations", "software-inventory", "configuration", "build"],
        "confidence": "high" if not gaps else "medium", "contradictions": [],
        "coverage_gaps": list(dict.fromkeys(gaps)), "model": {"status": "NOT_NEEDED", "proposal_sha256": None},
    }


def validate_proposal(proposal: Mapping[str, Any], *, catalog: Mapping[str, Any],
                      allowed_components: Collection[str] | None = None,
                      allowed_paths: Collection[str] | None = None) -> list[str]:
    errors: list[str] = []
    if set(proposal) != {"schema", "component_proposals", "build_recipes"} or proposal.get("schema") != PROPOSAL_SCHEMA:
        return ["proposal must contain only the supported versioned schema, component_proposals, and build_recipes"]
    values = proposal.get("component_proposals")
    if not isinstance(values, list) or len(values) > 256:
        return ["component_proposals must be a bounded list"]
    components = {str(item["component_id"]): item for item in catalog["components"]}
    paths = {str(item["path"]) for item in catalog["files"]}
    component_boundary = set(allowed_components) if allowed_components is not None else set(components)
    path_boundary = set(allowed_paths) if allowed_paths is not None else paths
    files = tuple(catalog["files"])
    artifacts = tuple(catalog.get("accepted_artifacts", ()))
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
        if (not isinstance(scanners, list) or len(scanners) > len(SCANNERS) or
                any(not isinstance(value, str) or value not in SCANNERS for value in scanners) or
                len(scanners) != len(set(scanners))):
            errors.append(f"{where}: scanner selection is not allowlisted")
        if (not isinstance(systems, list) or len(systems) > len(BUILD_SYSTEMS) or
                any(not isinstance(value, str) or value not in BUILD_SYSTEMS for value in systems) or
                len(systems) != len(set(systems))):
            errors.append(f"{where}: build system is not allowlisted")
        root = str(components.get(component_id, {}).get("root", ""))
        scope_valid = (isinstance(scope, list) and len(scope) <= len(paths) and
                       all(isinstance(value, str) and value in paths and value in path_boundary and
                           _under(value, root) for value in scope) and
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
        missing = sorted(set(units) - seen_recipes)
        if missing:
            errors.append("build_recipes omitted accepted build units: " + ", ".join(missing[:8]))
    return errors


def merge_proposal(plan: Mapping[str, Any], proposal: Mapping[str, Any], catalog: Mapping[str, Any]) -> dict[str, Any]:
    import copy
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
    return result


def validate_plan(plan: Mapping[str, Any], catalog: Mapping[str, Any]) -> None:
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
    systems = plan.get("build_topology", {}).get("build_systems", [])
    if any(item.get("build_system") not in BUILD_SYSTEMS for item in systems):
        raise ValueError("analysis plan contains an unregistered build system")
    if any(item.get("executable") is not False for item in plan.get("build_topology", {}).get("build_actions", [])):
        raise ValueError("analysis planning may not authorize executable build actions")
    units = {str(item["build_unit_id"]): item for item in catalog.get("build_units", ())}
    for action in plan.get("build_topology", {}).get("build_actions", []):
        unit_id = str(action.get("build_unit_id", ""))
        if unit_id not in units:
            raise ValueError("analysis plan build action is not an accepted build unit")
        accepted_unit = units[unit_id]
        if (action.get("markers") != accepted_unit.get("markers") or
                action.get("descriptor_package") != accepted_unit.get("descriptor_package") or
                action.get("family") != accepted_unit.get("family") or
                action.get("build_system") != accepted_unit.get("build_system") or
                action.get("root") != accepted_unit.get("root")):
            raise ValueError("analysis plan build action facts differ from the accepted catalog")
        recipe = action.get("recipe")
        if recipe is not None:
            errors = validate_build_recipe(recipe, units[unit_id])
            if errors:
                raise ValueError("analysis plan build recipe is invalid: " + "; ".join(errors))
