"""Primary-purpose bucket joins over declarations, never observed run coverage."""

from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
import re

from appsec_review.jobs.cataloging import LANGUAGES
from appsec_review.review.capability import (
    IDENTITY_TOOLS, INDEX_PARAMETER_TOOLS, IN_PROCESS_TOOLS, TOOL_INDEXES,
)
from appsec_review.tool_inputs import InputSupport, TOOL_INPUT_SUPPORT


SCHEMA = "appsec-review/intelligence-buckets/1"
BINDING_GAP = "T-147"
APPLICABILITY_GAP = "T-157"
STATES = {"declared", "partial", "gap", "not_applicable"}
TOOL_CELLS = ("jobs", "tasks", "input_languages")
DATASET_CELLS = ("producer_languages", "retrieval_indexes", "mcp_tools", "review_roles")
SUMMARY_CELLS = ("producer_languages", "producers", "datasets", "stages",
                 "retrieval_indexes", "mcp_tools", "review_roles")
LANGUAGE_CELLS = ("producers", "datasets", "stages", "retrieval_indexes", "mcp_tools", "review_roles")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate bucket-document key: {key}")
        result[key] = value
    return result


def load_buckets(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)


def validate_buckets(document: dict, inventory: dict) -> None:
    if set(document) != {"schema", "buckets", "tools", "datasets", "semantics"}:
        raise ValueError("intelligence buckets have missing or unknown fields")
    if document["schema"] != SCHEMA:
        raise ValueError("unknown intelligence-bucket schema")
    buckets = document["buckets"]
    if not isinstance(buckets, dict) or not 1 <= len(buckets) <= 12:
        raise ValueError("declare between one and twelve intelligence buckets")
    for name, bucket in buckets.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name) or not isinstance(bucket, dict)
                or set(bucket) != {"definition"} or not isinstance(bucket["definition"], str)
                or not bucket["definition"].strip() or "\n" in bucket["definition"]):
            raise ValueError(f"bucket needs an identifier and one-line definition: {name}")
    expected = {
        "tools": {name for name, row in inventory["images"].items() if row["kind"] == "tool"},
        "datasets": {row["output_kind"] for job in inventory["jobs"].values()
                     for row in job["datasets"]},
    }
    for kind, names in expected.items():
        mapping = document[kind]
        if not isinstance(mapping, dict) or set(mapping) != names:
            actual = set(mapping) if isinstance(mapping, dict) else set()
            raise ValueError(f"{kind} bucket coverage differs: missing={sorted(names - actual)}, "
                             f"extra={sorted(actual - names)}")
        for name, bucket in mapping.items():
            if not isinstance(bucket, str) or bucket not in buckets:
                raise ValueError(f"{kind} {name} must have exactly one known bucket")
    if (not isinstance(document["semantics"], list) or not document["semantics"]
            or any(not isinstance(value, str) or not value.strip() for value in document["semantics"])):
        raise ValueError("bucket classification semantics must be explicit")


def cell(values, basis: str, *, gaps=(), not_applicable: bool = False) -> dict:
    values, gaps = sorted(set(values)), sorted(set(gaps))
    if not basis.strip():
        raise ValueError("matrix cell needs a source basis")
    if not_applicable:
        if values or gaps:
            raise ValueError("not-applicable cells cannot claim values or unresolved gaps")
        state = "not_applicable"
    elif gaps:
        state = "partial" if values else "gap"
    elif values:
        state = "declared"
    else:
        raise ValueError("empty matrix cell requires a named gap")
    return {"state": state, "values": values, "basis": basis, "gaps": gaps}


def combine(cells: list[dict], basis: str) -> dict:
    if not cells:
        return cell([], basis, gaps=[APPLICABILITY_GAP])
    values = [value for item in cells for value in item["values"]]
    gaps = [gap for item in cells for gap in item["gaps"]]
    return cell(values, basis, gaps=gaps,
                not_applicable=all(item["state"] == "not_applicable" for item in cells))


def support_record(support: InputSupport) -> dict:
    predicate = support.predicate
    return {
        "key": support.key, "description": support.description,
        "suffixes": sorted(support.suffixes), "names": sorted(support.names),
        "formats": sorted(support.formats), "any_input": support.any_input,
        "interpreters": sorted(support.interpreters),
        "excluded_formats": sorted(support.excluded_formats),
        "excluded_description": support.excluded_description,
        "predicate": (f"{predicate.__module__}.{predicate.__qualname__}" if predicate else None),
    }


def support_languages(support: InputSupport, languages: Mapping[str, str]) -> dict:
    basis = f"src/appsec_review/tool_inputs.py: {support.key}"
    if support.any_input:
        return cell([], basis + "; selection has no language filter, not universal analysis coverage",
                    not_applicable=True)
    if support.formats:
        return cell([], basis + "; selection is by artifact format, not source language",
                    not_applicable=True)
    known = {languages[suffix] for suffix in support.suffixes if suffix in languages}
    unmapped = sorted(support.suffixes - languages.keys())
    if unmapped or support.names or support.predicate is not None or not known:
        reason = "; no complete source-language declaration"
        if unmapped:
            reason += ": suffixes " + ", ".join(unmapped)
        return cell(known, basis + reason, gaps=[APPLICABILITY_GAP])
    return cell(known, basis + "; suffix labels from src/appsec_review/jobs/cataloging.py")


def producer_languages(job_id: str, job: dict) -> dict:
    declarations = job["settings"].get("languages")
    if isinstance(declarations, dict) and declarations:
        values = []
        missing = False
        for record in declarations.values():
            if not isinstance(record, dict) or "source_languages" not in record or "enabled" not in record:
                missing = True
                continue
            if record["enabled"]:
                values.extend(record["source_languages"])
        if missing or not values:
            return cell(values, f"{job_id}: no complete enabled producer-language declaration in the inventory",
                        gaps=[APPLICABILITY_GAP])
        return cell(values, f"appsec-review.toml: jobs.{job_id}.settings.languages.*.source_languages; "
                    "producer selectors, not per-dataset or observed coverage")
    if job["contract"]["target_access"] == "none":
        return cell([], f"{job_id}: typed contract.target_access=none; target-independent job",
                    not_applicable=True)
    return cell([], f"{job_id}: no explicit producer-language declaration in the inventory",
                gaps=[APPLICABILITY_GAP])


def eligible_roles(dataset: dict, tools: list[str], registry: dict) -> dict:
    usable = set(tools) & IN_PROCESS_TOOLS
    basis = "pipeline/guidance/registry.json role tools and src/appsec_review/review/capability.py"
    if tools and not usable:
        return cell([], basis + "; the declared MCP route is not grantable to review cells",
                    not_applicable=True)
    compatible = set()
    for tool in usable:
        if dataset["disposition"] != "indexed":
            if tool == "query_dataset_inventory":
                compatible.add(tool)  # Metadata access is not permission to read the payload.
        elif (tool in INDEX_PARAMETER_TOOLS or tool in IDENTITY_TOOLS
              or set(dataset["indexes"]) & TOOL_INDEXES.get(tool, frozenset())):
            compatible.add(tool)
    roles = [name for name, record in registry["roles"].items()
             if compatible & set(record.get("tools", []))]
    return cell(roles, basis + "; static eligibility only, requiring a run/package-scoped grant",
                gaps=[] if roles else [APPLICABILITY_GAP])


def row_gaps(row: dict, names) -> list[str]:
    return sorted({gap for name in names for gap in row[name]["gaps"]})


def build_matrices(inventory: dict, taxonomy: dict, todo_ids: set[str], *,
                   supports: Mapping[str, InputSupport] = TOOL_INPUT_SUPPORT,
                   languages: Mapping[str, str] = LANGUAGES) -> dict:
    validate_buckets(taxonomy, inventory)
    launches: dict[str, list[dict]] = {name: [] for name in taxonomy["tools"]}
    for job_id, job in sorted(inventory["jobs"].items()):
        for step in job["steps"].values():
            for task in step["tasks"].values():
                for tool in task["tools"]:
                    if tool not in launches:
                        raise ValueError(f"bound task tool is not in the canonical tool catalog: {tool}")
                    launches[tool].append({
                        "job": job_id, "task": task["id"], "source": task["source"],
                        "line": task["line"], "job_enabled": job["enabled"],
                    })
    tools = []
    for tool_id, bucket in sorted(taxonomy["tools"].items()):
        bound = sorted(launches[tool_id], key=lambda row: (row["job"], row["task"]))
        selected = [support for key, support in sorted(supports.items())
                    if tool_id in key.split(":")]
        row = {
            "tool": tool_id, "bucket": bucket,
            "catalog_state": inventory["images"][tool_id]["state"],
            "launch_bindings": bound,
            "jobs": cell([row["job"] for row in bound], "source-bound task adapter declarations",
                         gaps=[] if bound else [BINDING_GAP]),
            "tasks": cell([f"{row['job']}.{row['task']}" for row in bound],
                          "source-bound task adapter declarations",
                          gaps=[] if bound else [BINDING_GAP]),
            "input_support": [support_record(value) for value in selected],
            "input_languages": combine(
                [support_languages(value, languages) for value in selected],
                "declared input compatibility, not rule coverage or observed execution"),
        }
        row["gap"] = row_gaps(row, TOOL_CELLS)
        tools.append(row)
    datasets = []
    for job_id, job in sorted(inventory["jobs"].items()):
        for dataset in job["datasets"]:
            indexed = dataset["disposition"] == "indexed"
            routes = dataset["mcp_tools"]
            if set(routes) - inventory["mcp_tools"].keys():
                raise ValueError(f"dataset names an unknown MCP route: {job_id}/{dataset['output_kind']}")
            row = {
                "bucket": taxonomy["datasets"][dataset["output_kind"]],
                "producer": job_id, "job_enabled": job["enabled"],
                "target_access": job["contract"]["target_access"],
                "dataset": dataset["output_kind"], "schema": dataset["schema"],
                "family": dataset["family"], "stage": dataset["disposition"],
                "authority": dataset["authority"], "sensitivity": dataset["sensitivity"],
                "store": dataset["store"], "description": dataset["description"],
                "producer_languages": producer_languages(job_id, job),
                "retrieval_indexes": cell(
                    dataset["indexes"], "typed DatasetDeclaration.indexes"
                    if indexed else f"typed DatasetDeclaration.disposition={dataset['disposition']}; "
                    "no payload index is declared",
                    not_applicable=not indexed),
                "mcp_tools": cell(routes, dataset["query_route"], gaps=[] if routes else [BINDING_GAP]),
                "review_roles": eligible_roles(dataset, routes, inventory["guidance"]),
                "access": "indexed_evidence" if indexed else "sanitized_metadata_only",
                "source": f"docs/generated/inventory.json: jobs.{job_id}.datasets",
            }
            row["gap"] = row_gaps(row, DATASET_CELLS)
            datasets.append(row)
    datasets.sort(key=lambda row: (row["bucket"], row["producer"], row["dataset"]))
    summaries = []
    for bucket, definition in sorted(taxonomy["buckets"].items()):
        rows = [row for row in datasets if row["bucket"] == bucket]
        row = {"bucket": bucket, "definition": definition["definition"]}
        for name in DATASET_CELLS:
            row[name] = combine([item[name] for item in rows], "union of detailed declaration rows")
        for name, field in (("producers", "producer"), ("datasets", "dataset"), ("stages", "stage")):
            row[name] = cell([item[field] for item in rows], "typed dataset publication declarations",
                             gaps=[] if rows else [APPLICABILITY_GAP])
        row["gap"] = row_gaps(row, SUMMARY_CELLS)
        summaries.append(row)
    language_names = sorted(set(languages.values()) | {
        language for row in datasets for language in row["producer_languages"]["values"]
    })
    language_rows = []
    for bucket in sorted(taxonomy["buckets"]):
        declarations = [row for row in datasets if row["bucket"] == bucket]
        unbound = [row for row in declarations if row["producer_languages"]["state"] in {"gap", "partial"}]
        for language in language_names:
            selected = [row for row in declarations if language in row["producer_languages"]["values"]
                        or row["producer_languages"]["state"] == "not_applicable"]
            # A job-wide language selector is not a dataset-by-language publication contract.
            unresolved = bool(unbound) or any(row["target_access"] != "none" for row in selected)
            gaps = [APPLICABILITY_GAP] if unresolved or not selected else []
            basis = "producer selectors or target-independent contracts; dataset-language coverage is not asserted"
            row = {
                "bucket": bucket, "language": language,
                "producers": cell([item["producer"] for item in selected], basis, gaps=gaps),
                "datasets": cell([f"{item['producer']}/{item['dataset']}" for item in selected],
                                 basis, gaps=gaps),
                "stages": cell([item["stage"] for item in selected], "candidate dataset declarations",
                               gaps=[] if selected else [APPLICABILITY_GAP]),
                "unbound_producers": sorted({item["producer"] for item in unbound}),
                "unbound_datasets": sorted(f"{item['producer']}/{item['dataset']}" for item in unbound),
                "target_independent_producers": sorted({item["producer"] for item in selected
                                                       if item["target_access"] == "none"}),
            }
            for name in ("retrieval_indexes", "mcp_tools", "review_roles"):
                row[name] = combine([item[name] for item in selected], "candidate dataset declarations")
            row["gap"] = row_gaps(row, LANGUAGE_CELLS)
            language_rows.append(row)
    result = {
        "tools": tools, "datasets": datasets, "buckets": summaries,
        "languages": language_names, "language_rows": language_rows,
        "non_tool_catalog_entries": {
            name: {"kind": image["kind"], "state": image["state"]}
            for name, image in sorted(inventory["images"].items()) if image["kind"] != "tool"
        },
    }
    validate_matrices(result, taxonomy, todo_ids, inventory, languages=languages)
    return result


def validate_cell(value: dict, todo_ids: set[str], *, allow_na: bool) -> None:
    if not isinstance(value, dict) or set(value) != {"state", "values", "basis", "gaps"}:
        raise ValueError("matrix cell has missing or unknown fields")
    state, values, gaps = value["state"], value["values"], value["gaps"]
    if (not isinstance(state, str) or state not in STATES
            or not isinstance(value["basis"], str) or not value["basis"].strip()):
        raise ValueError("matrix cell needs a known state and a source basis")
    for label, sequence in (("values", values), ("gaps", gaps)):
        if (not isinstance(sequence, list) or any(not isinstance(item, str) or not item for item in sequence)
                or sequence != sorted(set(sequence))):
            raise ValueError(f"matrix cell {label} must be sorted unique strings")
    if set(gaps) - todo_ids or any(not re.fullmatch(r"T-\d{3}", gap) for gap in gaps):
        raise ValueError("matrix gap names an unknown TODO id")
    if state == "not_applicable":
        if not allow_na or values or gaps:
            raise ValueError("not-applicable cell is not justified by its source contract")
    elif state == "declared":
        if not values or gaps:
            raise ValueError("declared matrix cell must have values and no unresolved gap")
    elif state == "partial":
        if not values or not gaps:
            raise ValueError("partial matrix cell requires known values and a named gap")
    elif values or not gaps:
        raise ValueError("empty matrix cell requires a named gap")


def validate_matrices(matrices: dict, taxonomy: dict, todo_ids: set[str], inventory: dict, *,
                      languages: Mapping[str, str] = LANGUAGES) -> None:
    tools, datasets, summaries = matrices["tools"], matrices["datasets"], matrices["buckets"]
    if len(tools) != len(taxonomy["tools"]) or {row["tool"] for row in tools} != set(taxonomy["tools"]):
        raise ValueError("tool matrix does not cover the bucket map exactly")
    if {row["dataset"] for row in datasets} != set(taxonomy["datasets"]):
        raise ValueError("availability matrix does not cover every dataset")
    if len({(row["producer"], row["dataset"]) for row in datasets}) != len(datasets):
        raise ValueError("availability matrix repeats a producer/dataset row")
    expected = {(job_id, dataset["output_kind"]): dataset
                for job_id, job in inventory["jobs"].items() for dataset in job["datasets"]}
    if {(row["producer"], row["dataset"]) for row in datasets} != set(expected):
        raise ValueError("availability matrix loses a producer/dataset declaration")
    if len(summaries) != len(taxonomy["buckets"]) or {row["bucket"] for row in summaries} != set(taxonomy["buckets"]):
        raise ValueError("availability summary does not cover every bucket")
    for row in tools:
        if (row["bucket"] != taxonomy["tools"][row["tool"]] or not row["catalog_state"]
                or row["catalog_state"] != inventory["images"][row["tool"]]["state"]):
            raise ValueError("tool matrix classification differs from its source")
        for name in TOOL_CELLS:
            allow_na = name == "input_languages" and bool(row["input_support"]) and all(
                record["any_input"] or record["formats"] for record in row["input_support"])
            validate_cell(row[name], todo_ids, allow_na=allow_na)
        if row["gap"] != row_gaps(row, TOOL_CELLS):
            raise ValueError("tool row gap summary is incomplete")
    for row in datasets:
        if row["bucket"] != taxonomy["datasets"][row["dataset"]]:
            raise ValueError("dataset matrix classification differs from its source")
        source = expected[(row["producer"], row["dataset"])]
        if (row["stage"] != source["disposition"] or row["schema"] != source["schema"]
                or row["authority"] != source["authority"] or row["sensitivity"] != source["sensitivity"]
                or row["family"] != source["family"] or row["store"] != source["store"]
                or type(row["job_enabled"]) is not bool
                or row["job_enabled"] != inventory["jobs"][row["producer"]]["enabled"]
                or row["target_access"] != inventory["jobs"][row["producer"]]["contract"]["target_access"]):
            raise ValueError("dataset matrix changes its source contract")
        for name in DATASET_CELLS:
            allow_na = (
                name == "producer_languages" and row["target_access"] == "none"
                or name == "retrieval_indexes" and row["stage"] in {"artifact_only", "protected"}
                or name == "review_roles" and bool(row["mcp_tools"]["values"])
                and not (set(row["mcp_tools"]["values"]) & IN_PROCESS_TOOLS)
            )
            validate_cell(row[name], todo_ids, allow_na=bool(allow_na))
        if row["gap"] != row_gaps(row, DATASET_CELLS):
            raise ValueError("dataset row gap summary is incomplete")
    for row in summaries:
        children = [item for item in datasets if item["bucket"] == row["bucket"]]
        for name in SUMMARY_CELLS:
            allow_na = name in DATASET_CELLS and bool(children) and all(
                child[name]["state"] == "not_applicable" for child in children)
            validate_cell(row[name], todo_ids, allow_na=allow_na)
        if row["gap"] != row_gaps(row, SUMMARY_CELLS):
            raise ValueError("bucket row gap summary is incomplete")
    language_rows = matrices["language_rows"]
    language_names = matrices["languages"]
    expected_languages = sorted(set(languages.values()) | {
        language for job_id, job in inventory["jobs"].items()
        for language in producer_languages(job_id, job)["values"]
    })
    if not language_names or language_names != expected_languages:
        raise ValueError("matrix language universe differs from its source declarations")
    expected_cells = {(bucket, language) for bucket in taxonomy["buckets"] for language in language_names}
    if (len(language_rows) != len(expected_cells)
            or {(row["bucket"], row["language"]) for row in language_rows} != expected_cells):
        raise ValueError("matrix omits a bucket/language cell")
    for row in language_rows:
        selected = [item for item in datasets if item["bucket"] == row["bucket"]
                    and (row["language"] in item["producer_languages"]["values"]
                         or item["producer_languages"]["state"] == "not_applicable")]
        for name in LANGUAGE_CELLS:
            allow_na = name in {"retrieval_indexes", "mcp_tools", "review_roles"} and bool(selected) and all(
                item[name]["state"] == "not_applicable" for item in selected)
            validate_cell(row[name], todo_ids, allow_na=allow_na)
        if row["gap"] != row_gaps(row, LANGUAGE_CELLS):
            raise ValueError("language row gap summary is incomplete")


def cell_text(value: dict, *, limit: int = 3) -> str:
    if value["state"] == "not_applicable":
        return "Not applicable (source-backed)"
    if not value["values"]:
        return "Undeclared; see gap"
    text = ", ".join(f"`{item}`" for item in value["values"][:limit])
    remaining = len(value["values"]) - limit
    if remaining > 0:
        text += f" (+{remaining} in JSON)"
    if value["gaps"]:
        text += "; incomplete declarations"
    return text


def gap_text(ids: list[str]) -> str:
    return ", ".join(f"[{value}](../TODO.md)" for value in ids) or "None"


def matrix_documents(matrices: dict, taxonomy: dict, tool_policy: dict) -> dict[str, dict]:
    scope = {
        "kind": "declarations_only",
        "not_claimed": [
            "host image availability", "executed tool calls", "accepted run coverage",
            "per-dataset language coverage", "issued run/package capabilities",
        ],
        "not_applicable": "A populated source-backed state, never an unknown cell disguised as success.",
    }
    return {
        "docs/generated/matrix-tool-bucket.json": {
            "schema": "appsec-review/docs-tool-bucket-matrix/1", "scope": scope,
            "classification_semantics": taxonomy["semantics"], "tool_policy": tool_policy,
            "rows": matrices["tools"],
            "non_tool_catalog_entries": matrices["non_tool_catalog_entries"],
        },
        "docs/generated/matrix-bucket-availability.json": {
            "schema": "appsec-review/docs-bucket-availability-matrix/1", "scope": scope,
            "classification_semantics": taxonomy["semantics"], "tool_policy": tool_policy,
            "language_universe_basis": "Catalog census labels plus configured producer source_languages; "
            "not an exhaustive list of languages understood by external engines.",
            "languages": matrices["languages"], "language_rows": matrices["language_rows"],
            "buckets": matrices["buckets"], "datasets": matrices["datasets"],
        },
    }


def matrix_markdown(matrices: dict) -> dict[str, str]:
    # Import at rendering time: documentation owns the shared table formatter and calls this projection.
    from scripts.documentation import table

    tools = [
        "# Tool-to-intelligence-bucket matrix", "",
        "[Full matrix](matrix-tool-bucket.json) | [Authored bucket map](../intelligence-buckets.json)", "",
        "Only canonical catalog entries with `kind = tool` are rows here; non-tool entries are "
        "listed separately in JSON. Configured CodeQL tooling is not invented as a catalog tool ID.",
        "Bindings are source declarations, not observed launches. Input compatibility is not rule "
        "coverage; the JSON retains input selectors, global tool policy and unresolved language metadata.",
        "",
        table(("Tool", "Bucket", "Bound jobs / tasks", "Declared input languages", "Catalog state", "Gap"), (
            (f"`{row['tool']}`", f"`{row['bucket']}`",
             cell_text(row["jobs"]) + "<br>" + cell_text(row["tasks"]),
             cell_text(row["input_languages"]), row["catalog_state"], gap_text(row["gap"]))
            for row in matrices["tools"]
        )),
        "", "Not applicable means an explicit source-backed selector (for example arbitrary input "
        "or artifact format), not universal language coverage. Image state and job enablement are "
        "separate facts; neither proves a tool ran.", "",
    ]
    availability = [
        "# Bucket-to-availability matrix", "",
        "[Full per-language matrix and dataset rows](matrix-bucket-availability.json) | "
        "[Authored bucket map](../intelligence-buckets.json)", "",
        "This is a summary of declarations, not a run-coverage report. The JSON includes every "
        "bucket/language pair, configured candidates, unbound producers and each producer/dataset row.",
        "The language universe comes from catalog census labels and configured producer selectors, "
        "not inferred external-engine support.",
        "A producer's configured language selectors do not prove that every dataset is published "
        "for those languages. Target-independent jobs are identified separately.",
        "Eligible roles are the registry allowlist intersected with in-process tool/index compatibility; "
        "an actual run/package-scoped capability is still required. Protected and artifact-only "
        "routes expose sanitized metadata, not payloads. Bucket grouping never changes evidence authority.",
        "",
        table(("Bucket", "Producer language selectors", "Producers / datasets", "Declared stages",
               "Index / MCP", "Eligible roles", "Gap"), (
            (f"`{row['bucket']}`", cell_text(row["producer_languages"]),
             f"{len(row['producers']['values'])} producers / {len(row['datasets']['values'])} dataset IDs"
             + ("; undeclared" if not row["datasets"]["values"] else ""),
             cell_text(row["stages"]),
             cell_text(row["retrieval_indexes"]) + "<br>" + cell_text(row["mcp_tools"]),
             cell_text(row["review_roles"]), gap_text(row["gap"]))
            for row in matrices["buckets"]
        )),
        "", "Every missing or partially declared cell names a TODO gap. Source-backed not-applicable "
        "states preserve intentional boundaries, such as a protected payload having no index; they "
        "do not request wider access.",
        "Code-graph-specific follow-ups remain in [T-115](../TODO.md) through [T-126](../TODO.md); "
        "their scope is not duplicated here.", "",
    ]
    return {
        "docs/generated/matrix-tool-bucket.md": "\n".join(tools),
        "docs/generated/matrix-bucket-availability.md": "\n".join(availability),
    }
