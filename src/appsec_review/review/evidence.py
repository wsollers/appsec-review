"""Evidence admissibility and re-resolution of model citations (design R3).

A model citation reaches the ledger only as an :class:`EvidenceRelation` produced here, after the
cited logical identity has been re-resolved against the accepted manifest. Anything that cannot be
resolved becomes an ``evidence_gap``; truncated or incomplete resolution is recorded with
``complete=False`` and can never satisfy an obligation.

``evidence-admissibility/3`` changes one mapping of the graph-fact branch added in ``/2``: a ``dominating`` guard or
a bounded range recorded as ``contradicts`` on ``missing_or_ineffective_guard`` stands only when
:mod:`appsec_review.graph.bounds` shows from the exported facts that it bounds the destination and the citing role is
blue, verifier or judge; otherwise the relation is recorded as ``qualifies`` and carries the reason.

``evidence-admissibility/2`` added the graph-fact branch (docs/architecture/code-graph-precomputation.md
section 6): a cited ``call_site``, ``sink_site``, ``entry_point``, ``dataflow_path``, ``guard_fact`` or
``range_fact`` is ``DIRECT_FOR_MAPPED_PREDICATE`` only for the predicates ``graph-fact-predicates/1``
maps for its family (after the family's source-class condition), and only when the payload of the
entity re-resolved from the accepted manifest is a ``graph-fact/1`` record of that family whose
``admissibility.direct_eligible`` is ``true`` and whose ``graph-fact-admissibility/1`` conditions
re-check clean. ``flow_summary`` and every ineligible fact are ``INDIRECT``. The payload is read from
the ``find`` result inside :func:`resolve_relation`; nothing a model writes can set it.
"""
from __future__ import annotations

from typing import Any, Collection, Iterable, Mapping

from appsec_review.graph.contract import (
    ADMISSIBILITY_RULE as GRAPH_FACT_ADMISSIBILITY_RULE, FAMILY_KINDS, GRAPH_FACT_SCHEMA, Family,
    ineligibility_reasons, mapped_predicates,
)
from appsec_review.graph.bounds import fact_bounds_destination, sink_destination_bytes
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import (  # make_gap is re-exported for compatibility
    MAX_GAP_REASON, Admissibility, EvidenceRelation, Gap, GapClass, IntegrityError, Predicate, RelationKind,
    make_gap,
)
from appsec_review.review import admission
from appsec_review.review.obligations import ADMISSIBILITY_RULES_VERSION
EVIDENCE_RELATION_KINDS = frozenset({RelationKind.SUPPORTS, RelationKind.CONTRADICTS, RelationKind.QUALIFIES})
SATISFYING_ADMISSIBILITY = frozenset({Admissibility.DIRECT, Admissibility.DIRECT_FOR_MAPPED_PREDICATE})

# R3: kinds whose content can bear on a predicate. What each can establish for WHICH predicate is the
# closed ``predicate-admission/2`` table (review/admission.py): DIRECT, ANALYST_ASSESSED or INDIRECT.
DIRECT_KINDS: frozenset[EntityKind] = frozenset({
    EntityKind.SOURCE_SPAN, EntityKind.AST_NODE, EntityKind.IR_ENTITY, EntityKind.SYMBOL,
    EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT, EntityKind.OBJECT_FILE, EntityKind.LIBRARY,
    EntityKind.EXECUTABLE, EntityKind.BUILD_ARTIFACT, EntityKind.PACKAGE, EntityKind.ARCHIVE_MEMBER,
    EntityKind.BYTECODE_MODULE, EntityKind.MANAGED_ASSEMBLY, EntityKind.WASM_MODULE,
    EntityKind.EVIDENCE_ARTIFACT, EntityKind.BINARY_FUNCTION, EntityKind.BINARY_CALL_SITE,
})
# R3: direct only for the predicate(s) the producing rule's versioned mapping names.
MAPPED_KINDS: frozenset[EntityKind] = frozenset({EntityKind.TOOL_OBSERVATION})
# R3: may guide search, never satisfies an obligation. Every kind R3 does not list as direct or
# mapped is also treated as indirect (default deny); this set names the ones R3 lists explicitly.
INDIRECT_KINDS: frozenset[EntityKind] = frozenset({
    EntityKind.HOTSPOT, EntityKind.PRIORITY_ITEM, EntityKind.HISTORY_SIGNAL, EntityKind.CHANGE,
    EntityKind.CHANGE_CONTEXT_SIGNAL, EntityKind.REVIEW_SIGNAL, EntityKind.TAG_ASSIGNMENT,
    EntityKind.REVIEW_UNIT,
})
# R3: reference context. OSV, NVD, CISA KEV and FIRST EPSS records (advisories, the scanner-reported
# dependency identities they are matched to, and the precomputed facts that join them to pinned
# feeds, such as ``dependency_advisories`` and ``reference_intelligence``) describe an advisory or a
# weakness in general, never this target. They are INDIRECT for every predicate: they may guide
# search and scoring context but never satisfy an obligation alone. A dependency claim still needs
# target evidence, e.g. the resolved package version from an SBOM, lockfile or artifact inventory
# (``package``/``archive_member`` entities, which are direct for ``affected_construct``).
REFERENCE_KINDS: frozenset[EntityKind] = frozenset({
    EntityKind.ADVISORY, EntityKind.DEPENDENCY_PACKAGE, EntityKind.PRECOMPUTED_FACT,
})
INDIRECT_KINDS = INDIRECT_KINDS | REFERENCE_KINDS
# R3 (evidence-admissibility/2): code-graph fact kinds. Direct only for the predicates the family's
# versioned mapping names, and only when the re-resolved payload is direct-eligible; ``flow_summary``
# has no mapped predicate and is therefore indirect for every predicate.
GRAPH_KINDS: frozenset[EntityKind] = frozenset(FAMILY_KINDS.values())
_EVIDENCE_BEARING = frozenset({EntityKind.TOOL_OBSERVATION, EntityKind.EVIDENCE_ARTIFACT,
                               EntityKind.FINDING_PACKAGE})
if admission.ADMITTED_KINDS != DIRECT_KINDS:     # the table must cover exactly the kinds classify() sends to it
    raise ImportError("predicate-admission table and DIRECT_KINDS differ")
# Binary-derived kinds: a citation must resolve to a binary hash, a function address and pseudo-C lines.
BINARY_KINDS: frozenset[EntityKind] = frozenset({
    EntityKind.BINARY_FUNCTION, EntityKind.BINARY_CALL_SITE, EntityKind.BINARY_IMPORT, EntityKind.BINARY_STRING,
})
BINARY_CITATION_GAP = "binary-derived evidence must cite binary hash, function address and pseudo-C line"

# R3 (evidence-admissibility/3): roles that may contradict ``missing_or_ineffective_guard`` with a graph fact.
# Red's counterevidence is always ``qualifies``.
GUARD_CONTRADICTION_ROLES: frozenset[str] = frozenset({"blue_team_refuter", "independent_verifier", "judge"})
_GUARD_KINDS = frozenset({EntityKind.GUARD_FACT, EntityKind.RANGE_FACT})
NOT_BOUNDING_REASON = "guard_not_shown_to_bound_destination"
MAX_RELATION_REASON = 200


def graph_fact_predicates(entity_kind: EntityKind | str, fact_payload: Mapping[str, Any] | None
                          ) -> frozenset[Predicate]:
    """Predicates a re-resolved graph fact may satisfy directly; empty means indirect for all.

    Fail-closed: the payload must be a ``graph-fact/1`` record whose family is the cited kind, whose
    published ``graph-fact-admissibility/1`` block says ``direct_eligible: true`` with no reasons,
    and whose conditions re-check clean here. Any other shape, including a missing payload, an
    unknown family or a kind/family mismatch, yields no predicate (default deny).
    """
    kind = EntityKind(entity_kind)
    if kind not in GRAPH_KINDS or not isinstance(fact_payload, Mapping):
        return frozenset()
    if fact_payload.get("schema") != GRAPH_FACT_SCHEMA or fact_payload.get("family") != kind.value:
        return frozenset()
    block = fact_payload.get("admissibility")
    if not isinstance(block, Mapping) or block.get("rule") != GRAPH_FACT_ADMISSIBILITY_RULE:
        return frozenset()
    if block.get("direct_eligible") is not True or list(block.get("ineligibility_reasons") or ()) != []:
        return frozenset()
    if ineligibility_reasons(fact_payload):
        return frozenset()
    result = fact_payload.get("result")
    return mapped_predicates(Family(kind.value), result if isinstance(result, Mapping) else {})


def classify(entity_kind: EntityKind | str, predicate: Predicate,
             tool_rule_mapping: Collection[Predicate] = (),
             fact_payload: Mapping[str, Any] | None = None) -> Admissibility:
    """Classify a cited entity for ``predicate`` per the R3 table (``evidence-admissibility/3``).

    ``tool_rule_mapping`` is the set of predicates the producing rule's versioned mapping names for
    a ``tool_observation``; it is ignored for every other kind. ``fact_payload`` is the payload of a
    graph-fact entity as re-resolved from the accepted manifest; it is ignored for every other kind,
    and a graph kind without it is indirect.
    """
    kind = EntityKind(entity_kind)
    predicate = Predicate(predicate)
    if kind in REFERENCE_KINDS:            # reference context: indirect for every predicate
        return Admissibility.INDIRECT
    if kind in DIRECT_KINDS:               # predicate-admission/2: relevance is per (kind, predicate)
        return admission.admission(kind, predicate)
    if kind in MAPPED_KINDS:
        mapped = {Predicate(item) for item in tool_rule_mapping}
        return Admissibility.DIRECT_FOR_MAPPED_PREDICATE if predicate in mapped else Admissibility.INDIRECT
    if kind in GRAPH_KINDS:
        return (Admissibility.DIRECT_FOR_MAPPED_PREDICATE if predicate in graph_fact_predicates(kind, fact_payload)
                else Admissibility.INDIRECT)
    return Admissibility.INDIRECT


def _sink_destination(core: RetrievalCore, sink: Any) -> int | None:
    """The destination size the accepted guard facts of ``sink`` agree on, else ``None`` (fail closed)."""
    if not isinstance(sink, str) or not sink:
        return None
    try:
        limit = min(100, core.limits.max_results)
        related = core.trace(identity=sink, relations=("GUARDS",), depth=1, limit=limit)
        results = []
        for row in related["results"]:
            if row.get("target_id") != sink or row.get("source_id") is None:
                continue
            found = core.find(identity=row["source_id"], limit=1)["results"]
            payload = found[0].get("payload") if found and found[0].get("kind") == EntityKind.GUARD_FACT.value else None
            if isinstance(payload, Mapping) and isinstance(payload.get("result"), Mapping):
                results.append(payload["result"])
    except Exception:  # noqa: BLE001 - an unreadable lookup means "not shown", never a contradiction
        return None
    return sink_destination_bytes(results)


def guard_relation_kind(core: RetrievalCore, entity_kind: EntityKind, payload: Mapping[str, Any] | None,
                        role: str | None) -> tuple[RelationKind, str | None]:
    """The kind recorded for a direct ``contradicts`` citation of a guard or range fact (``evidence-admissibility/3``).

    ``contradicts`` stands only when the exported facts show the fact bounds its destination and ``role`` may
    contradict; otherwise ``qualifies`` with the reason. The decision never reads model text.
    """
    result = payload.get("result") if isinstance(payload, Mapping) else None
    sink = result.get("sink", {}).get("sink_site") if isinstance(result, Mapping) and isinstance(
        result.get("sink"), Mapping) else None
    destination = _sink_destination(core, sink) if entity_kind is EntityKind.RANGE_FACT else None
    bound = fact_bounds_destination(entity_kind.value, result if isinstance(result, Mapping) else None, destination)
    if not bound.bounds:
        return RelationKind.QUALIFIES, f"{NOT_BOUNDING_REASON}:{bound.reason}"[:MAX_RELATION_REASON]
    if role not in GUARD_CONTRADICTION_ROLES:
        return RelationKind.QUALIFIES, f"contradiction_role_not_permitted:{role}"[:MAX_RELATION_REASON]
    return RelationKind.CONTRADICTS, None


def satisfies(relation: EvidenceRelation) -> bool:
    """Whether ``relation`` may count toward an obligation: complete and (mapped-)direct."""
    return relation.complete and relation.admissibility in SATISFYING_ADMISSIBILITY


def _content_record(entity: Mapping[str, Any], excerpt: str | None) -> dict[str, Any]:
    record = {key: entity.get(key) for key in ("identity", "kind", "native_id", "name", "payload", "location")}
    if excerpt is not None:
        record["excerpt"] = excerpt
    return record


def _locator(entity: Mapping[str, Any]) -> str:
    location = entity.get("location")
    if location:
        return (f"{location['path']}:{location['start_line']}-{location['end_line']}"
                f"#b{location['start_byte']}-{location['end_byte']}@{location['file_sha256']}")
    return f"{entity['index']}/{entity['shard_id']}:{entity['identity']}"


def binary_anchor(entity: Mapping[str, Any]) -> tuple[str, str, int, int] | None:
    """``(binary_sha256, function_address, start_line, end_line)`` of a binary-derived entity.

    Binary evidence is cited by binary hash, function address and pseudo-C line. The anchor exists
    only when the accepted entity carries a pseudo-C location whose logical path names the same
    binary and function as its payload; anything else (an import, a string, a function Ghidra did
    not decompile) has no anchor and cannot be cited as evidence.
    """
    from appsec_review.retrieval.source_resolution import parse_binary_source_path
    location = entity.get("location")
    payload = entity.get("payload")
    if not isinstance(location, Mapping) or not isinstance(payload, Mapping):
        return None
    parsed = parse_binary_source_path(str(location.get("path", "")))
    if parsed is None or parsed != (payload.get("binary_sha256"), payload.get("function_address")):
        return None
    return parsed[0], parsed[1], int(location["start_line"]), int(location["end_line"])


def resolve_relation(core: RetrievalCore, *, claim_id: str, predicate: Predicate, kind: RelationKind,
                     entity_id: str, producing_cell_id: str, retrieval_receipt_sha256: str | None,
                     rule_predicates: Iterable[Predicate] = (), round: int = 0,
                     role: str | None = None) -> EvidenceRelation | Gap:
    """Re-resolve one citation against the accepted manifest and return a relation or gap.

    ``role`` is the citing cell's role value; it only matters for a ``contradicts`` citation of a guard or range fact.
    """
    predicate = Predicate(predicate)
    kind = RelationKind(kind)
    if kind not in EVIDENCE_RELATION_KINDS:
        raise ValueError("evidence relations are supports, contradicts, or qualifies")

    def gap(reason: str) -> Gap:
        return make_gap(GapClass.EVIDENCE_GAP, claim_id, reason, predicate=predicate, round=round)

    try:
        parsed = LogicalIdentity.parse(entity_id)
    except ValueError:
        return gap("citation is not a canonical logical identity")
    found = core.find(identity=parsed.value, limit=1)
    if not found["results"]:
        return gap("citation did not resolve in the accepted manifest")
    entity = found["results"][0]
    if entity.get("identity") != parsed.value or entity.get("kind") != parsed.kind.value:
        raise IntegrityError("accepted index returned an entity that differs from the cited identity")
    complete = not found["truncated"]
    excerpt: str | None = None
    if parsed.kind in BINARY_KINDS and binary_anchor(entity) is None:
        return gap(BINARY_CITATION_GAP)
    if entity.get("location") is not None:
        response = core.read_excerpt(identity=parsed.value, context_lines=0)
        if not response["results"]:
            return gap("cited source location did not re-resolve")
        resolved = response["results"][0]
        excerpt = str(resolved["excerpt"])
        complete = complete and not response["truncated"] and not resolved.get("excerpt_truncated", False)
    if parsed.kind in _EVIDENCE_BEARING:
        response = core.resolve_evidence(identity=parsed.value)
        result = response["results"][0] if response["results"] else {}
        if not result.get("entity"):
            return gap("cited evidence did not re-resolve")
        complete = complete and not response["truncated"] and not response["coverage_gaps"]
    shard_id = f"{entity['index']}/{entity['shard_id']}"
    content_sha256 = sha256_hex(_content_record(entity, excerpt))
    locator = _locator(entity)
    # The graph payload is the accepted entity's, never the citation's: a model cannot set it.
    payload = entity.get("payload") if parsed.kind in GRAPH_KINDS else None
    admissibility = classify(parsed.kind, predicate, tuple(rule_predicates),
                             payload if isinstance(payload, Mapping) else None)
    reason: str | None = None
    if (kind is RelationKind.CONTRADICTS and predicate is Predicate.MISSING_OR_INEFFECTIVE_GUARD
            and parsed.kind in _GUARD_KINDS and admissibility is Admissibility.DIRECT_FOR_MAPPED_PREDICATE):
        kind, reason = guard_relation_kind(core, parsed.kind, payload if isinstance(payload, Mapping) else None, role)
    body = {
        "claim_id": claim_id, "predicate": predicate.value, "kind": kind.value, "entity_id": parsed.value,
        "entity_kind": parsed.kind.value, "admissibility": admissibility.value, "shard_id": shard_id,
        "content_sha256": content_sha256, "locator": locator, "complete": complete,
        "producing_cell_id": producing_cell_id, "retrieval_receipt_sha256": retrieval_receipt_sha256,
        "manifest_sha256": core.manifest_sha256, "admissibility_rules": ADMISSIBILITY_RULES_VERSION,
        "predicate_admission": admission.VERSION,
    }
    if reason is not None:
        body["reason"] = reason
    return EvidenceRelation(
        relation_id=make_id("evidence_relation", 1, body), claim_id=claim_id, predicate=predicate, kind=kind,
        entity_id=parsed.value, entity_kind=parsed.kind.value, admissibility=admissibility,
        shard_id=shard_id, content_sha256=content_sha256, locator=locator, complete=complete,
        producing_cell_id=producing_cell_id, retrieval_receipt_sha256=retrieval_receipt_sha256, reason=reason,
    )
