"""Bounded projections of admitted state, never a new source of retrieval authority."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any

from appsec_review.storage import canonical_json
from .fragments import GuidanceError

CARD_SCHEMA = "appsec-review/capability-artifact-card/1"
MAX_CARD_BYTES = 32768
MAX_ITEMS = 64
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,255}$")
_PROTECTED = {"AGENTS.md", "CLAUDE.md"}
_LIMITS = ("max_queries", "max_turns", "page_size", "max_depth", "max_result_bytes",
           "max_input_tokens", "max_output_tokens", "max_requests_per_turn", "max_source_lines",
           "max_calls", "max_documents", "max_request_bytes", "max_response_bytes")
_REMAINING = ("remaining_queries", "remaining_turns", "final_required")
CITATIONS = {
    "review": "Use cell-local labels such as S1/K1, or already admitted asr:<kind>:<sha256> identities. "
              "Never invent a label, path citation, or another cell's reference.",
    "allowed_evidence_ref": "evidence_refs contains exact strings from allowed_evidence_refs.",
    "brief_id": "Reference files, functions and entry points only by the F, N and E ids of the supplied brief; "
                "an id the brief does not list is refused. A plan orders hunting and establishes nothing.",
    "inventory_path_sha256": "need_evidence requests contain exactly path, sha256 and reason; copy the "
                             "path/hash pair from evidence_inventory. Recipes name admitted build-unit IDs.",
    "supplied_build_context": "No citation field is accepted. Explain the supplied diagnostics in reason; "
                             "use only admitted repair_options. A proposal is not a successful build.",
    "build_evidence_id": "Each evidence_ids entry is a supplied build_action_id, compile_unit_id, "
                         "artifact_id or artifact sha256; absent producers do not establish a result.",
    "candidate_path": "Copy only supplied candidate IDs and catalog/supporting paths. A catalog path "
                      "is context, not evidence that an unread file establishes a release.",
    "native_source_ref": "Each citations item is exactly {path, start_line, end_line, quote}. Copy a "
                         "supplied excerpt path, inclusive displayed lines and exact text from that span.",
    "poc_source_location": "Use the brief's labels and accepted declaration/source locations in the "
                           "specified answer fields; no invented functions, paths or executed-result claims.",
    "relation_id": "evidence_ids contains exact supplied relation_id strings, not source paths, "
                    "claim IDs, arbitrary hashes or the planner's argument.",
    "owasp_typed_reference": "Copy a complete accepted typed reference, including source_identity and "
                             "locator, from evidence or expansion. A source identity alone is not a citation.",
    "lead_fact": "Name a supplied lead_id exactly once; tool_fact is null or that lead's supplied "
                 "tool_fact id. Triage is prioritization, not a verified finding.",
    "cited_line": "Each claim cites a supplied excerpt as exactly {path, line} or a supplied deterministic "
                  "facet as exactly {assignment_id}. Values come from allowed_values; nothing else is evidence.",
}


def _safe_id(value: Any) -> bool:
    return (isinstance(value, str) and bool(_ID.fullmatch(value)) and ".." not in value
            and not any(part in _PROTECTED or part.startswith(".") and part != "."
                        for part in PurePosixPath(value).parts)
            and not value.startswith(("http:", "https:", "file:", "ghp_", "github_pat_", "sk_live_")))


def _ids(values: Sequence[Any]) -> list[str]:
    return sorted({value for value in values if _safe_id(value)})


def _counts(value: Mapping[str, Any], keys: Sequence[str]) -> dict[str, int | bool]:
    return {key: value[key] for key in keys if key in value and (
        type(value[key]) is int and value[key] >= 0 or key == "final_required" and type(value[key]) is bool)}


def dataset(name: str, *, available: bool, authority: str = "context",
            producer: str | None = None, accepted_sha256: str | None = None) -> dict[str, Any]:
    if not _safe_id(name) or authority not in {"direct", "context", "provisional"}:
        raise GuidanceError("invalid card dataset")
    row: dict[str, Any] = {"name": name, "availability": "available" if available else "not_supplied",
                           "evidence_authority": authority, "producer": None, "accepted_sha256": None}
    if producer is not None:
        if not re.fullmatch(r"job_[a-z0-9_]+", producer):
            raise GuidanceError("invalid card producer identity")
        row["producer"] = producer
    if accepted_sha256 is not None:
        if not _SHA.fullmatch(accepted_sha256):
            raise GuidanceError("invalid card accepted identity")
        row["accepted_sha256"] = accepted_sha256
    return row


def seal_card(value: Mapping[str, Any], *, max_bytes: int = MAX_CARD_BYTES) -> dict[str, Any]:
    """Canonical order and hard byte cap. Never silently truncate a tool schema or grant."""
    card = json.loads(canonical_json(dict(value)))
    card.pop("sha256", None)
    card["sha256"] = hashlib.sha256(canonical_json(card)).hexdigest()
    if len(canonical_json(card)) > max_bytes:
        raise GuidanceError(f"Capability & Artifact Card exceeds its {max_bytes}-byte bound")
    return card


def verify_card(card: Mapping[str, Any]) -> dict[str, Any]:
    if card.get("schema") != CARD_SCHEMA or seal_card(card) != card:
        raise GuidanceError("Capability & Artifact Card identity changed")
    return dict(card)


def _bounded_card(card: dict[str, Any]) -> dict[str, Any]:
    # Keep complete operation schemas and one availability row per dataset. Additional identity
    # samples are optional presentation, never grants; omitted counts remain part of the hash.
    while len(canonical_json({**card, "sha256": "0" * 64})) > MAX_CARD_BYTES:
        scopes = [key for key in sorted(card["scope"], reverse=True)
                  if isinstance(card["scope"][key], list) and card["scope"][key]]
        duplicate = next((index for index in range(len(card["datasets"]) - 1, 0, -1)
                          if card["datasets"][index]["name"] == card["datasets"][index - 1]["name"]), None)
        if scopes:
            card["scope"][scopes[0]].pop()
        elif duplicate is not None:
            card["datasets"].pop(duplicate)
        else:
            raise GuidanceError("Capability & Artifact Card schemas exceed its byte bound")
        card["coverage"]["omitted_card_items"] += 1
    return seal_card(card)


def review_tool_catalog(tools: Sequence[str]) -> list[dict[str, Any]]:
    from appsec_review.mcp.schema import TOOLS
    from appsec_review.review.capability import EXPAND_SCHEMA, EXPAND_TOOL, LOCATOR_TOOLS
    by_name = {tool["name"]: tool for tool in TOOLS}
    locator = {"type": "object", "required": ["path", "line"],
               "properties": {"path": {"type": "string"}, "line": {"type": "integer", "minimum": 1}}}
    catalog = []
    for name in sorted(tools):
        if name == EXPAND_TOOL:
            catalog.append({"name": name, "parameters": EXPAND_SCHEMA, "description": (
                "More about one item you can already see: the labelled rows that bear on a label (a sink, guard, "
                "function, flow, call site), within your grant. Give exactly one of label, ref or files; files "
                "names a file listed under the package files and offset pages it.")})
        elif name in by_name:
            schema = by_name[name]["inputSchema"]
            description = by_name[name].get("description", "")
            if name in LOCATOR_TOOLS:
                schema = {**schema, "properties": {**schema["properties"], "locator": locator}}
                description += (" Instead of a path, give locator {path, line} naming a file and line shown in the "
                                "package; the application resolves it to identities in the package scope.")
            catalog.append({"name": name, "description": description, "parameters": schema})
        else:
            raise GuidanceError("card names an unlisted review operation")
    return catalog


# These are read routes, not grants. Each selector mirrors the corresponding retrieval
# reader's index and producer/shard discriminator. Counts refer to backing rows, not
# matching results for a particular argument, completeness, or confirmed findings.
@dataclass(frozen=True)
class _Source:
    index: str
    kinds: tuple[str, ...] = ()
    job: str = ""
    producer_kind: str = ""
    query_set: str = ""
    shard_prefix: str = ""
    projection: str = ""
    shard: str = ""

    def accepts(self, row: Mapping[str, Any]) -> bool:
        producer = row["producer"]
        return ((not self.job or producer.get("job") == self.job)
                and (not self.producer_kind or producer.get("kind") == self.producer_kind)
                and (not self.query_set or producer.get("query_set") == self.query_set)
                and (not self.shard_prefix or row["shard_id"].startswith(self.shard_prefix))
                and (not self.shard or row["shard_id"] == self.shard))

    def count(self, row: Mapping[str, Any]) -> int | None:
        if self.projection:
            return row.get("projection_counts", {}).get(self.projection)
        if self.kinds:
            counts = row.get("kind_counts")
            return sum(counts.get(kind, 0) for kind in self.kinds) if counts is not None else None
        return row.get("entity_count")


_TREE = "job_tree_sitter_ast"
_GRAPH_KINDS = ("sink_site", "range_fact", "guard_fact", "call_site", "entry_point", "dataflow_path", "flow_summary")
_DATASETS = {
    "source": (_Source("source", ("source_file", "source_span")),),
    "syntax": (_Source("analysis", job=_TREE, projection="syntax"),),
    "cfg": (_Source("analysis", job=_TREE, projection="cfg_function"),),
    "alternate_cpg": (_Source("analysis", shard="alternate-cpg"), _Source("analysis", producer_kind="alternate_cpg")),
    "code_graph": (_Source("graph", _GRAPH_KINDS),),
    "codeql_databases": (_Source("graph", ("codeql_database",), producer_kind="codeql_database"),),
    "codeql_observations": (_Source("observations", ("tool_observation",), shard_prefix="codeql-"),),
    "scanner_observations": (_Source("observations", ("tool_observation",)),),
    "artifacts": (_Source("artifacts"),),
    "build_security": (_Source("build_security"),),
    "ci_configuration": tuple(_Source(index, shard_prefix="ci_") for index in ("observations", "evidence")),
    "debug_symbols": (_Source("debug_symbols"),),
    "binary": (_Source("binary", ("binary_function", "binary_call_site", "binary_import", "binary_string")),),
    "change_context": (_Source("history", ("change_context_signal",), shard_prefix="change-context"),),
    "hotspots": (_Source("priority", ("priority_item",)),),
    "precomputed": (_Source("precomputed", ("precomputed_fact",)),),
    "dataset_inventory": (_Source("inventory"),),
    "threat_boundaries": (_Source("precomputed", ("precomputed_fact",), query_set="threat_boundaries"),),
    "control_evidence": (_Source("precomputed", ("precomputed_fact",), query_set="control_evidence"),),
    "document_context": (_Source("precomputed", ("precomputed_fact",), query_set="document_context"),
                         _Source("observations", job="job_document_issue_analysis"),
                         _Source("observations", shard_prefix="document")),
    "engineering_signals": (_Source("history"), _Source("priority"),
                            _Source("precomputed", query_set="history_context"),
                            *(_Source(index, job=job) for index in ("analysis", "observations", "evidence")
                              for job in ("job_test_coverage", "job_profile_data"))),
    "dependency_advisories": (_Source("precomputed", query_set="dependency_advisories"),
                              *(_Source(index, job="job_dependency_intelligence")
                                for index in ("observations", "inventory"))),
    "sanitizer_readiness": tuple(_Source(index, projection="sanitizer_readiness")
                                for index in ("build_security", "inventory")),
}
_TOOL_DATASET = {
    "read_excerpt": "source", "query_syntax": "syntax", "query_cfg_function": "cfg",
    "query_guard_dominators": "cfg", "query_cpg_slice": "alternate_cpg", "query_call_paths": "alternate_cpg",
    "query_code_graph": "code_graph", "list_codeql_databases": "codeql_databases",
    "query_codeql_neighborhood": "codeql_databases", "query_codeql": "codeql_observations",
    "query_observations": "scanner_observations", "query_artifacts": "artifacts",
    "query_build_security": "build_security", "query_ci_configuration": "ci_configuration",
    "query_debug_symbols": "debug_symbols", "query_change_context": "change_context", "query_hotspots": "hotspots",
    "query_dataset_inventory": "dataset_inventory", "query_precomputed": "precomputed",
    "query_threat_boundaries": "threat_boundaries", "query_owasp_gaps": "control_evidence",
    "query_doc_drift": "document_context", "query_engineering_signals": "engineering_signals",
    "query_sca_reachability": "dependency_advisories", "query_sanitizer_readiness": "sanitizer_readiness",
}


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def catalog_digest(catalog: Sequence[Mapping[str, Any]]) -> str:
    return _digest(catalog)


def review_population(core: Any, indexes: Sequence[str]) -> dict[str, dict[str, Any]]:
    """Verified run-local backing populations. A missing measurement is not a zero count."""
    admitted = set(indexes)
    inventory = core.dataset_inventory(sorted(admitted)) if admitted and hasattr(core, "dataset_inventory") else {}
    populations = {}
    for name, selectors in {**_DATASETS, "indexed_entities": tuple(_Source(i) for i in sorted(admitted))}.items():
        sources = [s for s in selectors if s.index in admitted]
        matches = {(s.index, row["shard_id"]): (row, s.count(row)) for s in sources
                   for row in inventory.get(s.index, ()) if s.accepts(row)}
        bindings = [(index, shard, row["sha256"]) for (index, shard), (row, _) in sorted(matches.items())]
        unknown = any(s.index not in inventory for s in sources) or any(n is None for _, n in matches.values())
        count = sum(n for _, n in matches.values() if n is not None)
        gap_count = sum(len(row["coverage_gaps"]) for row, _ in matches.values())
        state, reason = (
            ("not_admitted", "index_not_admitted") if not sources else
            ("partial", "population_unknown") if unknown else
            ("partial", "producer_coverage_gap") if gap_count else
            ("unavailable", "no_accepted_shard") if not bindings else
            ("unavailable", "no_backing_rows") if count == 0 else ("available", None))
        producers = {row["producer"].get("job") for row, _ in matches.values()}
        producer = next(iter(producers)) if len(producers) == 1 else None
        populations[name] = {
            "name": name, "availability": state, "evidence_authority": "direct" if name == "source" else "context",
            "row_count": None if unknown or not sources else count, "known_row_count": count,
            "shard_count": len(bindings), "coverage_gap_count": gap_count, "gap": reason,
            "producer": producer if isinstance(producer, str) and re.fullmatch(r"job_[a-z0-9_]+", producer) else None,
            "accepted_sha256": bindings[0][2] if len(bindings) == 1 else None,
            "bindings_sha256": _digest(bindings) if bindings else None,
        }
    return populations


def populated_review_tools(candidates: Sequence[str], indexes: Sequence[str], population: Mapping[str, Any]
                           ) -> tuple[str, ...]:
    """Only narrow the caller's role allowlist; the capability still enforces every request."""
    from appsec_review.review.capability import TOOL_INDEXES
    generic = {"expand", "find", "search", "trace", "resolve_evidence"}
    return tuple(sorted(tool for tool in set(candidates)
                        if TOOL_INDEXES.get(tool, frozenset()).issubset(indexes)
                        and (tool == "coverage" and bool(indexes) or
                             population[_TOOL_DATASET.get(tool, "indexed_entities")]["known_row_count"] > 0
                             and (tool in generic or tool in _TOOL_DATASET))))


def review_query_sources(tools: Sequence[str], population: Mapping[str, Any]) -> tuple[str, ...]:
    """Distinct graph/structural routes usable by this role, never inferred from worker text."""
    from .skills import REVIEW_QUERY_DATASETS
    return tuple(sorted({source for name in tools if (source := _TOOL_DATASET.get(name)) in REVIEW_QUERY_DATASETS
                         and population[source]["known_row_count"] > 0}))


def review_admission(core: Any, capability: Any) -> dict[str, Any]:
    capability.verify()
    if core.manifest_sha256 != capability.manifest_sha256:
        raise GuidanceError("card manifest differs from the issued capability")
    population = review_population(core, capability.indexes)
    # This is an attribution lookup, not the availability decision. A miss cannot certify
    # the absence of a dataset. Retain each checked response's own qualification in the hash.
    seeds = sorted(capability.entities)[:MAX_ITEMS]
    receipts = {}
    if seeds and capability.indexes and hasattr(core, "resolve_identities"):
        resolved = core.resolve_identities(seeds, indexes=capability.indexes)
        for eid in seeds:
            response = resolved[eid]
            rows = response["results"]
            if rows and rows[0]["identity"] != eid:
                raise GuidanceError("seed attribution returned a different entity")
            found = rows[0] if rows else None
            binding = None
            if found:
                shards = [shard for shard in response["indexes"] if (shard["name"], shard["shard_id"]) ==
                          (found["index"], found["shard_id"])]
                if len(shards) != 1 or found["index"] not in capability.indexes:
                    raise GuidanceError("seed attribution has no unique admitted shard")
                binding = shards[0]["sha256"]
            receipts[eid] = {"status": response["status"], "shard_sha256": binding,
                             "content_sha256": _digest(found) if found else None,
                             "truncated": response["truncated"], "coverage_gap_count": len(response["coverage_gaps"]),
                             "coverage_gaps_sha256": _digest(response["coverage_gaps"])}
    return {"datasets": list(population.values()), "manifest_sha256": capability.manifest_sha256,
            "package_sha256": capability.package_sha256, "seed_receipts": receipts,
            "seed_receipts_sha256": _digest(receipts),
            "producer_lookup_omitted": len(capability.entities) - len(receipts)}


def _population_row(raw: Mapping[str, Any]) -> dict[str, Any]:
    name = raw["name"]
    state = raw["availability"]
    if name not in {*_DATASETS, "indexed_entities"} or state not in {"available", "unavailable", "not_admitted", "partial"}:
        raise GuidanceError("invalid review dataset state")
    row = dataset(name, available=False, authority=raw["evidence_authority"], producer=raw.get("producer"),
                  accepted_sha256=raw.get("accepted_sha256"))
    row["availability"] = state
    bindings = raw["bindings_sha256"]
    if bindings is not None and not _SHA.fullmatch(str(bindings)):
        raise GuidanceError("invalid review shard-set digest")
    row["bindings_sha256"] = bindings
    for key in ("row_count", "known_row_count", "shard_count", "coverage_gap_count"):
        value = raw[key]
        if (value is not None or key != "row_count") and (type(value) is not int or value < 0):
            raise GuidanceError("invalid review dataset count")
        row[key] = value
    if raw["gap"] not in {None, "index_not_admitted", "population_unknown", "producer_coverage_gap",
                           "no_accepted_shard", "no_backing_rows"}:
        raise GuidanceError("invalid review dataset gap")
    row["gap"] = raw["gap"]
    return row


def _operation(name: str, properties: Mapping[str, Any], required: Sequence[str]) -> dict[str, Any]:
    return {"name": name, "parameters": {"type": "object", "additionalProperties": False,
            "required": list(required), "properties": dict(properties)}}


def request_card(request: Any) -> dict[str, Any]:
    """Select only known request fields; target text and opaque metadata are never traversed."""
    is_review = hasattr(request, "task_input")
    task = request.task_input if is_review else request.summary
    capability = task.get("capability", {}) if is_review else {}
    protocol = task.get("turn_protocol", {}) if is_review else {}
    admission = task.get("artifact_admission", {})
    scope: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    operations: list[Mapping[str, Any]] = []
    citation = "review"
    omissions = 0
    gaps = 0
    catalog_sha = None

    def scope_ids(key: str, values: Sequence[Any]) -> None:
        nonlocal omissions
        selected = _ids(values)
        scope[key] = selected[:MAX_ITEMS]
        omissions += max(0, len(selected) - MAX_ITEMS)

    def scope_files(values: Sequence[Any]) -> None:
        nonlocal omissions
        selected = sorted({(row["path"], row["sha256"]) for row in values if isinstance(row, Mapping)
                           and _safe_id(row.get("path")) and _SHA.fullmatch(str(row.get("sha256", "")))})
        scope["file_identities"] = [{"path": path, "sha256": sha} for path, sha in selected[:MAX_ITEMS]]
        omissions += max(0, len(selected) - MAX_ITEMS)

    if is_review:
        from .workers import REVIEW_DISPATCHED, WORKBENCH_DISPATCHED
        if request.role in REVIEW_DISPATCHED and request.role not in {"lead_triager", "hunt_planner"}:
            from appsec_review.review.capability import IN_PROCESS_TOOLS
            granted = set(capability.get("tools", ()))
            expected = {item["name"]: item for item in review_tool_catalog(sorted(granted))}
            catalog = protocol.get("tool_catalog", ())
            for operation in catalog:
                if operation["name"] not in granted or operation["name"] not in IN_PROCESS_TOOLS:
                    raise GuidanceError("card operation is not granted to the review cell")
                if operation != expected[operation["name"]]:
                    raise GuidanceError("card operation differs from the exact tool catalog")
            if sorted(row["name"] for row in catalog) != sorted(granted):
                raise GuidanceError("review catalog must identify every granted operation exactly once")
            catalog_sha = catalog_digest(catalog)
            rows = [_population_row(row) for row in admission.get("datasets", ())]
            for key in ("manifest_sha256", "package_sha256", "seed_receipts_sha256"):
                if _SHA.fullmatch(str(admission.get(key, ""))):
                    scope[key] = admission[key]
            for key in ("capability_sha256", "read_view_sha256"):
                if _SHA.fullmatch(str(capability.get(key, ""))):
                    scope[key] = capability[key]
            for key in ("entities", "entity_prefixes", "graph_scopes", "indexes"):
                values = sorted(set(capability.get(key, ())))
                scope[key + "_count"] = len(values)
                scope[key + "_sha256"] = _digest(values)
            omissions += sum(int(admission.get(key, 0)) for key in
                             ("producer_lookup_omitted", "dataset_rows_omitted"))
            gaps = int(admission.get("material_gap_count", 0))
            omissions += sum(value for value in admission.get("view_omitted", {}).values()
                             if type(value) is int and value >= 0)
        elif request.role == "hunt_planner":
            # The planner reads one bounded attack-surface brief (review/hunt_plan.py): paths, names, lines and
            # counts from accepted indices under short ids. It cites those ids; it retrieves nothing.
            citation = "brief_id"
            brief = task.get("brief", {}) if isinstance(task.get("brief"), Mapping) else {}
            scope_ids("paths", [row.get("path") for row in brief.get("files", ()) if isinstance(row, Mapping)])
            rows = [dataset("attack_surface_brief", available=bool(brief.get("files")), authority="context")]
            gaps = len(brief.get("gaps", ()))
        elif request.role == "lead_triager":
            citation = "lead_fact"
            scope_ids("lead_ids", [row.get("lead_id") for row in task.get("findings", ())])
            rows = [dataset("lead_excerpts", available=bool(task.get("findings")), authority="provisional")]
        elif request.role in WORKBENCH_DISPATCHED:
            citation = "owasp_typed_reference"
            # The assembled request (owasp_workbench/batching.py) carries each evidence record once under
            # `evidence`; rows cite it by evidence_ids. Per-package `evidence_references` is the older shape.
            shared = task.get("evidence", {})
            refs = [item["reference"] for item in (shared.values() if isinstance(shared, Mapping) else ())
                    if isinstance(item, Mapping) and isinstance(item.get("reference"), Mapping)]
            refs += [item["reference"] for package in task.get("packages", ())
                     for item in package.get("evidence_references", ())]
            scope_ids("identities", [ref.get("source_identity") for ref in refs])
            rows = [dataset("accepted_component_evidence", available=bool(refs))]
            bindings = sorted({ref["publication"]["sha256"] for ref in refs
                               if isinstance(ref.get("publication"), Mapping)
                               and _SHA.fullmatch(str(ref["publication"].get("sha256", "")))})
            scope_ids("accepted_shard_identities", bindings)
            operations = [_operation("retrieve", {
                "source_identity": {"type": "string"},
                "locator": {"oneOf": [
                    {"type": "null"},
                    {"type": "object", "additionalProperties": False,
                     "required": ["kind", "path", "file_sha256", "lines", "source_custody"],
                     "properties": {"kind": {"const": "source"}, "path": {"type": "string"},
                                    "file_sha256": {"type": "string"},
                                    "lines": {"type": "array", "minItems": 2, "maxItems": 2,
                                              "items": {"type": "integer", "minimum": 1}},
                                    "source_custody": {"type": ["object", "null"]}}},
                    {"type": "object", "additionalProperties": False,
                     "required": ["kind", "pointer", "artifact_sha256"],
                     "properties": {"kind": {"enum": ["artifact", "structured_fact"]},
                                    "pointer": {"type": "string"},
                                    "artifact_sha256": {"type": ["string", "null"]}}},
                ]}},
                ("source_identity", "locator"))]
            operations[0]["constraints"] = {
                "source_identity_must_be_admitted": True,
                "locator_must_match_accepted_identity_and_custody": True,
                "source_lines_must_be_ordered_within_subject_and_configured_cap": True}
        elif request.role == "poc_writer":
            from appsec_review.jobs.job_poc_generation.writer import tool_catalog
            citation = "poc_source_location"
            body = task.get("input", {})
            scope_ids("paths", [row.get("path") for row in body.get("declarations", ())])
            scope_files(body.get("declarations", ()))
            rows = [dataset("accepted_declarations", available=bool(body.get("declarations")), authority="direct"),
                    dataset("build_facts", available=bool(body.get("build_facts")))]
            expected = {item["name"]: item for item in tool_catalog()}
            for operation in protocol.get("tool_catalog", ()):
                if operation["name"] not in expected or operation["parameters"] != expected[
                        operation["name"]]["parameters"]:
                    raise GuidanceError("card names an unlisted PoC operation or altered schema")
                operations.append(expected[operation["name"]])
            gaps = len(body.get("gaps", ()))
        elif request.role in {"remediation_writer", "remediation_reviewer"}:
            citation = "relation_id"
            body = task.get("task", {})
            refs = body.get("accepted_evidence", ())
            scope_ids("relation_ids", [row.get("relation_id") for row in refs])
            scope_ids("paths", [row.get("path") for row in body.get("source_files", ())])
            scope_files(body.get("source_files", ()))
            rows = [dataset("accepted_evidence_relations", available=bool(refs)),
                    dataset("accepted_source", available=bool(body.get("source_files")), authority="direct")]
            if "retrieve" in task.get("protocol", {}).get("actions", ()):
                operations = [_operation("retrieve", {
                    "path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1}}, ("path", "start_line", "end_line"))]
                operations[0]["constraints"] = {"max_window_lines": 120, "path_must_be_admitted": True}
            gaps = len(body.get("source_gaps", ()))
    else:
        from .workers import SPECIALIZED_WORKERS
        selected = next((worker for worker in SPECIALIZED_WORKERS.values() if worker.response == request.schema), None)
        citation = selected.citation if selected else "supplied_build_context"
        scope_ids("paths", request.allowed_paths)
        scope_ids("build_unit_ids", request.allowed_build_units)
        scope_ids("component_ids", request.allowed_components)
        if citation == "allowed_evidence_ref":
            scope_ids("evidence_refs", task.get("allowed_evidence_refs", ()))
            rows = [dataset("native_candidate", available=bool(task.get("candidate")), authority="provisional")]
        elif citation in {"candidate_path", "native_source_ref"}:
            body = task.get("payload", {})
            scope_ids("candidate_ids", [body.get("candidate_id"), *(
                row.get("candidate_id") for row in body.get("candidates", ()) if isinstance(row, Mapping))])
            scope_ids("paths", body.get("available_files", ()) if citation == "candidate_path" else
                      [row.get("path") for row in body.get("files", ()) if isinstance(row, Mapping)])
            scope_files(body.get("files", ()))
            rows = [dataset("component_local_excerpts" if citation == "native_source_ref" else "candidate_catalog",
                            available=any(isinstance(row, Mapping) for row in body.get("files", ()))
                            if citation == "native_source_ref" else bool(
                                body.get("candidates") or body.get("available_files")),
                            authority="direct" if citation == "native_source_ref" else "context")]
        elif citation == "build_evidence_id":
            refs = [row.get(key) for name, keys in (("actions", ("build_action_id", "compile_unit_id")),
                    ("artifacts", ("artifact_id", "sha256"))) for row in task.get(name, ()) for key in keys]
            scope_ids("evidence_refs", refs)
            rows = [dataset(name, available=bool(task.get(name))) for name in
                    ("actions", "artifacts", "deterministic_results")]
        elif citation == "cited_line":
            # T-5008 collation model pass: the supplied excerpts and deterministic facets are the only scope.
            excerpts = [row for row in task.get("excerpts", ()) if isinstance(row, Mapping)]
            scope_ids("paths", [*request.allowed_paths, *(row.get("path") for row in excerpts)])
            scope_ids("assignment_ids", [row.get("assignment_id") for row in task.get("deterministic_facets", ())
                                         if isinstance(row, Mapping)])
            rows = [dataset("first_party_excerpts", available=bool(excerpts), authority="direct"),
                    dataset("deterministic_facets", available=bool(task.get("deterministic_facets")))]
        elif citation == "inventory_path_sha256":
            scope_files([*task.get("evidence_inventory", ()), *(
                row for unit in task.get("build_units", ())
                for row in unit.get("descriptor_package", {}).get("documents", ()))])
            rows = [dataset("accepted_descriptors", available=any(
                unit.get("descriptor_package", {}).get("documents") for unit in task.get("build_units", ())),
                            authority="direct"),
                    dataset("evidence_inventory", available=bool(task.get("evidence_inventory")))]
            if task.get("feedback_limits") is not None:
                operations = [_operation("need_evidence", {
                    "path": {"type": "string"}, "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "reason": {"type": "string"}}, ("path", "sha256", "reason"))]
            omissions += int(task.get("evidence_inventory_omitted", 0))
        else:
            rows = [dataset("accepted_recipe", available=bool(task.get("accepted_recipe"))),
                    dataset("probe_diagnostics", available=bool(task.get("failure")), authority="provisional")]
        gaps = len(task.get("coverage_gaps", ()))

    # These are explicit job-selected artifact bindings, not arbitrary producer metadata.
    if not is_review:
        by_name = {row["name"]: row for row in rows}
        for binding in admission.get("datasets", ()):
            name = binding.get("name")
            if name not in by_name:
                raise GuidanceError("artifact admission names an unrelated worker dataset")
            prior = by_name[name]
            by_name[name] = dataset(name, available=prior["availability"] == "available",
                                   authority=prior["evidence_authority"],
                                   producer=binding.get("producer"), accepted_sha256=binding.get("accepted_sha256"))
        rows = list(by_name.values())
    limits = {**_counts(capability, _LIMITS), **_counts(protocol, _LIMITS),
              **_counts(task.get("capability_limits", {}), _LIMITS),
              **_counts(task.get("feedback_limits", {}), _LIMITS),
              "max_input_tokens": request.max_input_tokens, "max_output_tokens": request.max_output_tokens}
    remaining = {"remaining_queries": limits["max_queries"]} if "max_queries" in limits else {}
    if "max_turns" in limits:
        remaining.update(remaining_turns=limits["max_turns"], final_required=limits["max_turns"] == 1)
    if is_review:
        remaining.update(_counts(task.get("remaining_budget", {}), _REMAINING))
        for turn in request.transcript:
            if turn.get("from") == "application" or turn.get("speaker") == "application":
                remaining.update(_counts(turn, _REMAINING))
        supplied = task.get("protocol")
        if isinstance(supplied, Mapping) and type(supplied.get("queries_remaining")) is int:
            remaining["remaining_queries"] = supplied["queries_remaining"]
    identity = request.guidance_bundle_sha256 if is_review else task.get("guidance_bundle_sha256")
    card = {
        "schema": CARD_SCHEMA, "title": "Capability & Artifact Card", "role": request.role if _safe_id(request.role) else
        "build_recipe_worker", "transport": "application_mediated; no direct model tools",
        "guidance_bundle_sha256": identity if isinstance(identity, str) and _SHA.fullmatch(identity) else None,
        "datasets": sorted(rows, key=lambda row: (row["name"], row.get("accepted_sha256") or "")),
        "operations": sorted(operations, key=lambda row: row["name"]),
        "citation_contract": {"id": citation, "rule": CITATIONS[citation], "response_schema": request.schema},
        "scope": scope, "limits": limits, "remaining": remaining,
        "coverage": {"named_gap_count": gaps, "omitted_card_items": omissions,
                     "unbound_dataset_identities": sum(not (row["accepted_sha256"] or row.get("bindings_sha256")) for row in rows),
                     "absence_is_not_evidence": True,
                     "raw_protected_artifacts": "not available; only admitted projections"},
    }
    if catalog_sha is not None:
        card["catalog_sha256"] = catalog_sha
        card["operations"] = sorted(granted)
        populated = {row["name"] for row in rows if row["known_row_count"] > 0}
        alternatives = ("query_cpg_slice", "query_call_paths", "query_cfg_function",
                        "query_guard_dominators", "query_syntax", "read_excerpt", "find")
        card["fallback_tools"] = [tool for tool in alternatives
                                  if tool in granted and _TOOL_DATASET.get(tool, "indexed_entities") in populated]
    return _bounded_card(card)
