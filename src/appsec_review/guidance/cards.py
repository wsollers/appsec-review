"""Bounded projections of admitted state, never a new source of retrieval authority."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
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


def review_admission(core: Any, capability: Any) -> dict[str, Any]:
    """Project only granted indexes and producers resolved by exact in-scope seed identities.

    No inventory query or target-tree walk is used. Unresolved producers stay unknown, rather than
    copying all same-index shard identities from the run. These metadata reads consume no worker grant.
    """
    capability.verify()
    if core.manifest_sha256 != capability.manifest_sha256:
        raise GuidanceError("card manifest differs from the issued capability")
    manifest = getattr(core, "manifest", {})
    shards = {(row["name"], row.get("shard_id", "default")): row for row in manifest.get("indexes", ())}
    resolved: dict[str, list[Mapping[str, Any]]] = {}
    for identity in sorted(capability.entities)[:MAX_ITEMS] if shards else ():
        response = core.find(identity=identity, indexes=list(capability.indexes), limit=1)
        for row in response["results"]:
            shard = shards.get((row.get("index"), row.get("shard_id", "default")))
            if shard is not None and row.get("identity") == identity:
                resolved.setdefault(str(row["index"]), []).append(shard)
    rows = []
    for name in sorted(capability.indexes):
        matching = resolved.get(name, ())
        if matching:
            for shard in sorted({row["sha256"]: row for row in matching}.values(), key=lambda row: row["sha256"]):
                producer = shard.get("producer", {}).get("job")
                rows.append(dataset(name, available=True, authority="direct" if name == "source" else "context",
                                    producer=producer if isinstance(producer, str) and
                                    re.fullmatch(r"job_[a-z0-9_]+", producer) else None,
                                    accepted_sha256=shard["sha256"]))
        else:
            rows.append(dataset(name, available=any(key[0] == name for key in shards)))
    return {"datasets": rows[:MAX_ITEMS], "manifest_sha256": capability.manifest_sha256,
            "package_sha256": capability.package_sha256,
            "producer_lookup_omitted": max(0, len(capability.entities) - MAX_ITEMS),
            "dataset_rows_omitted": max(0, len(rows) - MAX_ITEMS)}


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
        if request.role in REVIEW_DISPATCHED and request.role != "lead_triager":
            from appsec_review.review.capability import IN_PROCESS_TOOLS
            granted = set(capability.get("tools", ()))
            expected = {item["name"]: item for item in review_tool_catalog(sorted(granted))}
            for operation in protocol.get("tool_catalog", ()):
                if operation["name"] not in granted or operation["name"] not in IN_PROCESS_TOOLS:
                    raise GuidanceError("card operation is not granted to the review cell")
                if operation["parameters"] != expected[operation["name"]]["parameters"]:
                    raise GuidanceError("card operation differs from the exact parameter schema")
                operations.append(expected[operation["name"]])
            rows = [dataset(row["name"], available=row["availability"] == "available",
                            authority=row["evidence_authority"], producer=row.get("producer"),
                            accepted_sha256=row.get("accepted_sha256"))
                    for row in admission.get("datasets", ())]
            for key in ("manifest_sha256", "package_sha256"):
                if _SHA.fullmatch(str(admission.get(key, ""))):
                    scope[key] = admission[key]
            if _SHA.fullmatch(str(capability.get("capability_sha256", ""))):
                scope["capability_sha256"] = capability["capability_sha256"]
            scope_ids("identities", capability.get("entities", ()))
            scope_ids("graph_scopes", capability.get("graph_scopes", ()))
            omissions += sum(int(admission.get(key, 0)) for key in
                             ("producer_lookup_omitted", "dataset_rows_omitted"))
            gaps = int(admission.get("material_gap_count", 0))
            omissions += sum(value for value in admission.get("view_omitted", {}).values()
                             if type(value) is int and value >= 0)
        elif request.role == "lead_triager":
            citation = "lead_fact"
            scope_ids("lead_ids", [row.get("lead_id") for row in task.get("findings", ())])
            rows = [dataset("lead_excerpts", available=bool(task.get("findings")), authority="provisional")]
        elif request.role in WORKBENCH_DISPATCHED:
            citation = "owasp_typed_reference"
            refs = [item["reference"] for package in task.get("packages", ())
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
            from appsec_review.jobs.job_poc_generation.writer import _tool_catalog
            citation = "poc_source_location"
            body = task.get("input", {})
            scope_ids("paths", [row.get("path") for row in body.get("declarations", ())])
            scope_files(body.get("declarations", ()))
            rows = [dataset("accepted_declarations", available=bool(body.get("declarations")), authority="direct"),
                    dataset("build_facts", available=bool(body.get("build_facts")))]
            expected = {item["name"]: item for item in _tool_catalog()}
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
                     "unbound_dataset_identities": sum(row["accepted_sha256"] is None for row in rows),
                     "absence_is_not_evidence": True,
                     "raw_protected_artifacts": "not available; only admitted projections"},
    }
    return _bounded_card(card)
