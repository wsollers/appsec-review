"""Bounded operation questions and generated-map context, never finding evidence."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import json
from typing import Any

from appsec_review.graph.contract import GRAPH_FACT_SCHEMA, SinkClass, SourceClass, ineligibility_reasons
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError
from appsec_review.review.scope import AcceptedScope, ScopeGap

RULE = "appsec-review/behavior-context/1"
MODEL_JOB = "job_threat_model_generation"
QUESTIONS = {
    "memory_write": "Can controlled size or lifetime violate the destination's bounds or ownership?",
    "memory_read": "Can a feasible input read outside the live object's bounds?",
    "allocation_size": "Can controlled size overflow or exhaust resources before allocation is bounded?",
    "integer_conversion": "Can conversion change the value used by a security-relevant size or index check?",
    "command_execution": "Can controlled data change the executed command rather than a bounded argument?",
    "sql_query": "Is controlled data separated from SQL syntax on every relevant path?",
    "code_injection": "Can controlled input reach executable syntax or code loading?",
    "deserialization": "Can untrusted serialized data select dangerous types or behavior?",
    "path_access": "Does canonicalized access remain within the authorized resource boundary?",
    "server_side_request": "Can an attacker select a forbidden destination across redirects or resolution?",
    "crypto_misuse": "Does the primitive and its key lifecycle protect the intended data?",
}
DEFAULT_QUESTION = "Which input can reach this operation, and which effective control preserves its invariant?"


class DiscoveryBound(ValueError):
    """A supplied map cannot fit the configured read bound, not an integrity failure."""


@dataclass(frozen=True, slots=True)
class Operation:
    operation_id: str
    component_id: str
    build_unit_id: str | None
    source_id: str
    path: str
    file_sha256: str
    start_line: int
    end_line: int
    anchors: tuple[tuple[str, str], ...]
    classes: tuple[str, ...]
    start_byte: int | None = None
    end_byte: int | None = None

    def record(self, model: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
        return {
            "schema": RULE, "authority": "routing_context", "operation_id": self.operation_id,
            "path": self.path, "file_sha256": self.file_sha256,
            "start_line": self.start_line, "end_line": self.end_line,
            "start_byte": self.start_byte, "end_byte": self.end_byte,
            "source_id": self.source_id, "anchor_ids": [identity for identity, _ in self.anchors],
            "classes": list(self.classes),
            "questions": sorted({QUESTIONS.get(kind, DEFAULT_QUESTION) for kind in self.classes}),
            "model_context": [dict(item) for item in model],
            "limitations": ["An operation is not whole-file coverage or deployed exposure.",
                            "Retrieve original evidence to establish each claim predicate."],
        }


def graph_operations(scope: AcceptedScope, *, limit: int) -> tuple[tuple[Operation, ...], tuple[ScopeGap, ...]]:
    """Group original entry/sink facts by their physical site, independent of tags or producer count."""
    if type(limit) is not int or limit < 1:
        raise ValueError("operation discovery limit must be positive")
    shards = scope.producer("code_graph").shards
    if not shards:
        return (), (ScopeGap("behavior", "run", "missing", "no accepted graph operations; path fallback retained"),)
    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = defaultdict(list)
    gaps: list[ScopeGap] = []
    for number, row in enumerate(scope.store.entities(shards, kinds=("entry_point", "sink_site"), limit=limit + 1)):
        if number == limit:
            gaps.append(ScopeGap("behavior", "run", "truncated",
                                 f"operation discovery reached {limit} records; path fallback retained"))
            break
        identity = row["identity"]
        payload, location = row["payload"], row.get("location")
        kind = row["kind"]
        if (payload.get("schema") != GRAPH_FACT_SCHEMA or payload.get("family") != kind
                or not isinstance(location, Mapping) or ineligibility_reasons(payload)):
            gaps.append(ScopeGap("behavior", identity, "partial", "operation fact is not exact and eligible"))
            continue
        result = payload.get("result") or {}
        classification = result.get("source_class" if kind == "entry_point" else "sink_class")
        vocabulary = SourceClass if kind == "entry_point" else SinkClass
        if classification not in {item.value for item in vocabulary} or classification in {"internal", "unclassified"}:
            gaps.append(ScopeGap("behavior", identity, "partial", "operation has no security-relevant class"))
            continue
        path = location.get("path")
        source, component, build = scope.source_for(path), scope.component_for(path), scope.build_unit_for(path)
        declared = payload.get("scope") or {}
        if (source is None or component is None
                or declared.get("component_id") not in (None, component.component_id)
                or declared.get("build_unit_id") not in (None, build.build_unit_id if build else None)):
            gaps.append(ScopeGap("behavior", identity, "ambiguous", "operation source/component/build ownership unresolved"))
            continue
        first, last = location.get("start_line"), location.get("end_line")
        # ShardSet's bounded location projection omits snapshot; AcceptedScope verified the shard's.
        if (type(first) is not int or type(last) is not int or not 1 <= first <= last
                or location.get("target_snapshot") not in (None, scope.target_snapshot)):
            raise IntegrityError("operation location differs from accepted source scope")
        key = (component.component_id, build.build_unit_id if build else None, source.identity, path,
               location["file_sha256"], first, last, location.get("start_byte"), location.get("end_byte"))
        groups[key].append({"identity": identity, "role": "entry_point" if kind == "entry_point" else "sink",
                            "class": classification})
    operations = []
    for key, rows in groups.items():
        component, build, source, path, digest, first, last, *_ = key
        operations.append(Operation(
            "operation-" + sha256_hex({"rule": RULE, "site": list(key)}), component, build, source, path,
            digest, first, last, tuple(sorted({(row["identity"], row["role"]) for row in rows})),
            tuple(sorted({str(row["class"]) for row in rows})), key[-2], key[-1]))
    return tuple(sorted(operations, key=lambda item: item.operation_id)), tuple(gaps)


def opportunity_sites(rows: Sequence[Mapping[str, Any]]) -> frozenset[tuple[Any, ...]]:
    """Only invoked source-located capability/entry tags count; multiple labels for a site count once."""
    sites: set[tuple[Any, ...]] = set()
    for row in rows:
        payload = row.get("payload") or {}
        tag = payload.get("tag")
        if (payload.get("basis") != "invoked" or not isinstance(tag, str)
                or not tag.startswith(("func:", "surface:entry:"))):
            continue
        subject = payload.get("subject") or {}
        if subject.get("component_ownership") not in (None, "owned", "shared"):
            continue
        for evidence in payload.get("evidence", ()):
            location = evidence.get("location")
            if not isinstance(location, Mapping):
                continue
            start, end = location.get("start_line"), location.get("end_line")
            if (not evidence.get("ref") or not location.get("path") or not location.get("file_sha256")
                    or type(start) is not int or type(end) is not int or not 1 <= start <= end):
                continue
            sites.add((location["path"], location["file_sha256"], start, end,
                       location.get("start_byte"), location.get("end_byte")))
    return frozenset(sites)


def project_model(dfd: Mapping[str, Any], model: Mapping[str, Any], evidence: Mapping[str, Any],
                  result: Mapping[str, Any], *, run_id: str, snapshot: str,
                  operations: Sequence[Operation], resolve: Callable[[Mapping[str, Any]], bool],
                  limit: int) -> tuple[dict[str, tuple[dict[str, Any], ...]], tuple[ScopeGap, ...]]:
    """Join generated flow questions to original operation anchors, never by similar prose."""
    from appsec_review.threat_model.validate import validate_documents
    if type(limit) is not int or limit < 1:
        raise ValueError("model context limit must be positive")
    validate_documents(dfd, model, evidence, result)
    origin = dfd["origin"]
    if (origin["run_id"] != run_id or origin["target_snapshot"] != snapshot
            or origin["authority"] != "routing_context" or origin["target_supplied"] is not False):
        raise IntegrityError("generated model belongs to another review scope or authority")
    refs = {item["ref"]: item for item in evidence["references"]}
    wanted = {identity for operation in operations for identity, _ in operation.anchors}
    by_anchor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    checked: set[str] = set()
    gaps: list[ScopeGap] = []
    for flow in dfd["flows"]:
        anchors = []
        for inline in flow["evidence"]:
            ref = refs[inline["ref"]]
            if any(inline.get(key) != ref.get(key) for key in
                   ("entity_id", "entity_kind", "publication", "locator", "content_sha256")):
                raise IntegrityError("generated flow citation differs from its evidence registry")
            if ref["entity_id"] not in wanted:
                continue
            if ref["ref"] not in checked:
                if not resolve(ref):
                    raise IntegrityError("generated flow source is not in the accepted evidence scope")
                checked.add(ref["ref"])
            anchors.append(ref["entity_id"])
        if not anchors:
            continue
        threats = sorted(item["id"] for item in model["threats"] if flow["id"] in item["flow_ids"])
        if len(threats) > limit:
            gaps.append(ScopeGap("behavior_model", flow["id"], "truncated",
                                 f"{len(threats) - limit} candidate threat references omitted"))
        context = {"flow_id": flow["id"], "interaction": flow["interaction"], "basis": flow["basis"],
                   "boundary_ids": sorted(flow["crosses"]),
                   "threat_ids": threats[:limit],
                   "authority": "routing_context"}
        for anchor in sorted(set(anchors)):
            if len(by_anchor[anchor]) < limit:
                by_anchor[anchor].append(context)
            else:
                gaps.append(ScopeGap("behavior_model", anchor, "truncated", "generated context limit reached"))
    joined = {}
    for operation in operations:
        records = {sha256_hex(row): row for identity, _ in operation.anchors for row in by_anchor[identity]}
        kept = [records[key] for key in sorted(records)]
        if len(kept) > limit:
            gaps.append(ScopeGap("behavior_model", operation.operation_id, "truncated",
                                 f"{len(kept) - limit} generated contexts omitted"))
        joined[operation.operation_id] = tuple(kept[:limit])
    if result["gaps"] or dfd["unknowns"] or model["unknowns"]:
        gaps.append(ScopeGap("behavior_model", "run", "partial",
                             "generated map retains unresolved producer gaps or unknowns"))
    return joined, tuple(gaps)


def load_model(scope: AcceptedScope, operations: Sequence[Operation], *, core: Any,
               max_bytes: int, limit: int) -> tuple[dict[str, tuple[dict[str, Any], ...]], tuple[ScopeGap, ...],
                                                  Mapping[str, Any] | None]:
    from appsec_review.runtime.consume import accepted_upstream
    from appsec_review.runtime.inputs import observe_output
    from appsec_review.storage.shared import safe_path, verify_reference
    accepted = accepted_upstream(scope.run_root, MODEL_JOB, required=False)
    if accepted is None:
        return {}, (ScopeGap("behavior_model", "run", "missing",
                             "generated model not supplied; original graph and path fallback retained"),), None
    output = accepted.handoff["outputs"]["publication.publish_handoff"]
    bound = {(row["path"], row["sha256"]) for row in accepted.handoff["artifacts"]}
    used = 0

    def read(reference: Mapping[str, Any], output_kind: str) -> Mapping[str, Any]:
        nonlocal used
        if (reference["path"], reference["sha256"]) not in bound:
            raise IntegrityError("generated-model artifact is not bound to the admitted handoff")
        path = safe_path(scope.run_root, reference["path"])
        if used + path.stat().st_size > max_bytes:
            raise DiscoveryBound("generated-model artifacts exceed max_behavior_artifact_bytes")
        used += path.stat().st_size
        observe_output(scope.run_root, MODEL_JOB, output_kind, reference)
        return json.loads(verify_reference(scope.run_root, reference).read_bytes())

    try:
        result = read(output["artifact"], "threat_model_documents")
        artifacts = result["artifacts"]
        dfd = read(artifacts["dfd.json"], "generated_dfd")
        model = read(artifacts["threat-model.json"], "generated_threat_model")
        evidence = read(artifacts["evidence.json"], "generated_model_evidence")
    except DiscoveryBound as exc:
        return {}, (ScopeGap("behavior_model", "run", "truncated", str(exc)),), None
    shards = {(row["name"], row.get("shard_id", "default"), row["sha256"]) for row in scope.shards}

    def resolve(reference: Mapping[str, Any]) -> bool:
        publication = reference["publication"]
        if (publication["index"], publication["shard_id"], publication["sha256"]) not in shards:
            return False
        found = core.find(identity=reference["entity_id"], limit=1)
        return (not found["truncated"] and len(found["results"]) == 1
                and found["results"][0]["kind"] == reference["entity_kind"]
                and found["results"][0]["index"] == publication["index"]
                and found["results"][0]["shard_id"] == publication["shard_id"])

    joined, gaps = project_model(dfd, model, evidence, result, run_id=scope.run_id,
                                snapshot=scope.target_snapshot, operations=operations, resolve=resolve, limit=limit)
    return joined, gaps, {"handoff": accepted.identity, "artifacts": {
        **{key: dict(artifacts[key]) for key in ("dfd.json", "threat-model.json", "evidence.json")},
        "result.json": dict(output["artifact"])}}
