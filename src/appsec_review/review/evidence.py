"""Evidence admissibility and re-resolution of model citations (design R3).

A model citation reaches the ledger only as an :class:`EvidenceRelation` produced here, after the
cited logical identity has been re-resolved against the accepted manifest. Anything that cannot be
resolved becomes an ``evidence_gap``; truncated or incomplete resolution is recorded with
``complete=False`` and can never satisfy an obligation.
"""
from __future__ import annotations

from typing import Any, Collection, Iterable, Mapping

from appsec_review.retrieval.core import RetrievalCore
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import (  # make_gap is re-exported for compatibility
    MAX_GAP_REASON, Admissibility, EvidenceRelation, Gap, GapClass, IntegrityError, Predicate, RelationKind,
    make_gap,
)

ADMISSIBILITY_RULES_VERSION = "evidence-admissibility/1"
EVIDENCE_RELATION_KINDS = frozenset({RelationKind.SUPPORTS, RelationKind.CONTRADICTS, RelationKind.QUALIFIES})
SATISFYING_ADMISSIBILITY = frozenset({Admissibility.DIRECT, Admissibility.DIRECT_FOR_MAPPED_PREDICATE})

# R3: kinds that are direct evidence for the construct the predicate names.
DIRECT_KINDS: frozenset[EntityKind] = frozenset({
    EntityKind.SOURCE_SPAN, EntityKind.AST_NODE, EntityKind.IR_ENTITY, EntityKind.SYMBOL,
    EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT, EntityKind.OBJECT_FILE, EntityKind.LIBRARY,
    EntityKind.EXECUTABLE, EntityKind.BUILD_ARTIFACT, EntityKind.PACKAGE, EntityKind.ARCHIVE_MEMBER,
    EntityKind.BYTECODE_MODULE, EntityKind.MANAGED_ASSEMBLY, EntityKind.WASM_MODULE,
    EntityKind.EVIDENCE_ARTIFACT,
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
_EVIDENCE_BEARING = frozenset({EntityKind.TOOL_OBSERVATION, EntityKind.EVIDENCE_ARTIFACT,
                               EntityKind.FINDING_PACKAGE})


def classify(entity_kind: EntityKind | str, predicate: Predicate,
             tool_rule_mapping: Collection[Predicate] = ()) -> Admissibility:
    """Classify a cited entity for ``predicate`` per the R3 table.

    ``tool_rule_mapping`` is the set of predicates the producing rule's versioned mapping names for
    a ``tool_observation``; it is ignored for every other kind.
    """
    kind = EntityKind(entity_kind)
    predicate = Predicate(predicate)
    if kind in DIRECT_KINDS:
        return Admissibility.DIRECT
    if kind in MAPPED_KINDS:
        mapped = {Predicate(item) for item in tool_rule_mapping}
        return Admissibility.DIRECT_FOR_MAPPED_PREDICATE if predicate in mapped else Admissibility.INDIRECT
    return Admissibility.INDIRECT


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


def resolve_relation(core: RetrievalCore, *, claim_id: str, predicate: Predicate, kind: RelationKind,
                     entity_id: str, producing_cell_id: str, retrieval_receipt_sha256: str | None,
                     rule_predicates: Iterable[Predicate] = (), round: int = 0) -> EvidenceRelation | Gap:
    """Re-resolve one citation against the accepted manifest and return a relation or gap."""
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
    admissibility = classify(parsed.kind, predicate, tuple(rule_predicates))
    body = {
        "claim_id": claim_id, "predicate": predicate.value, "kind": kind.value, "entity_id": parsed.value,
        "entity_kind": parsed.kind.value, "admissibility": admissibility.value, "shard_id": shard_id,
        "content_sha256": content_sha256, "locator": locator, "complete": complete,
        "producing_cell_id": producing_cell_id, "retrieval_receipt_sha256": retrieval_receipt_sha256,
        "manifest_sha256": core.manifest_sha256, "admissibility_rules": ADMISSIBILITY_RULES_VERSION,
    }
    return EvidenceRelation(
        relation_id=make_id("evidence_relation", 1, body), claim_id=claim_id, predicate=predicate, kind=kind,
        entity_id=parsed.value, entity_kind=parsed.kind.value, admissibility=admissibility,
        shard_id=shard_id, content_sha256=content_sha256, locator=locator, complete=complete,
        producing_cell_id=producing_cell_id, retrieval_receipt_sha256=retrieval_receipt_sha256,
    )
