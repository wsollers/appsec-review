"""Blind verifier independence check (design R6).

Provider or model-family distinctness is recorded through :func:`provider_distinct` but is not
required unless the caller's policy passes ``require_distinct_provider=True``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Collection, Iterable

from appsec_review.review.evidence import satisfies
from appsec_review.review.models import EvidenceRelation, Gap, GapClass, Predicate, RelationKind, make_gap


@dataclass(frozen=True, slots=True)
class ActorRecord:
    """The identity facts of one worker cell needed to judge independence."""

    actor_id: str
    provider: str
    model: str
    conversation_id: str
    prior_response_sha256: str | None = None
    cache_key: str | None = None


def provider_distinct(verifier: ActorRecord, others: Iterable[ActorRecord]) -> bool:
    """``independence.provider_distinct``: the verifier's provider differs from every other actor's."""
    return all(verifier.provider != other.provider for other in others)


def verify_independence(verifier_actor: ActorRecord, other_actors: Iterable[ActorRecord],
                        verifier_request_bytes: bytes, forbidden_markers: Iterable[str | bytes],
                        verifier_relations: Iterable[EvidenceRelation],
                        required_predicates: Collection[Predicate], verifier_receipts: Collection[str], *,
                        claim_id: str, require_distinct_provider: bool = False,
                        round: int = 0) -> tuple[bool, list[Gap]]:
    """Return whether the verifier result is independent, with one ``independence_gap`` per failure.

    ``forbidden_markers`` are red/blue narrative, disposition, and identity strings that must not
    occur in the stored verifier request bytes; every other actor's id is always forbidden too.
    """
    others = list(other_actors)
    reasons: list[tuple[str, Predicate | None]] = []
    if any(other.actor_id == verifier_actor.actor_id for other in others):
        reasons.append(("verifier_actor_not_distinct", None))
    if verifier_actor.prior_response_sha256 is not None:
        reasons.append(("verifier_conversation_has_prior_response", None))
    if not verifier_actor.conversation_id or any(
            other.conversation_id == verifier_actor.conversation_id for other in others):
        reasons.append(("verifier_conversation_not_fresh", None))
    if verifier_actor.cache_key is not None and any(
            other.cache_key == verifier_actor.cache_key for other in others):
        reasons.append(("verifier_shares_cache_entry", None))
    markers: set[bytes] = set()
    for marker in [*forbidden_markers, *(other.actor_id for other in others)]:
        encoded = marker.encode("utf-8") if isinstance(marker, str) else bytes(marker)
        if not encoded:
            raise ValueError("forbidden markers must be non-empty")
        markers.add(encoded)
    if any(marker in verifier_request_bytes for marker in markers):
        reasons.append(("verifier_request_contains_forbidden_marker", None))
    receipts = set(verifier_receipts)
    supported: set[Predicate] = set()
    for relation in verifier_relations:
        if (relation.claim_id == claim_id and relation.kind is RelationKind.SUPPORTS and satisfies(relation)
                and relation.retrieval_receipt_sha256 is not None
                and relation.retrieval_receipt_sha256 in receipts):
            supported.add(relation.predicate)
    for predicate in sorted({Predicate(item) for item in required_predicates} - supported,
                            key=lambda item: item.value):
        reasons.append(("verifier_lacks_independent_support", predicate))
    if require_distinct_provider and not provider_distinct(verifier_actor, others):
        reasons.append(("verifier_provider_not_distinct", None))
    gaps = sorted((make_gap(GapClass.INDEPENDENCE_GAP, claim_id, reason, predicate=predicate, round=round)
                   for reason, predicate in reasons), key=lambda item: item.gap_id)
    return not gaps, gaps
