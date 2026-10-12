"""Deterministic evidence-qualified adjudication (design R5).

``adjudicate`` is a pure function. It counts only complete direct (or direct-for-mapped-predicate)
evidence relations and asks only whether each predicate has such support or contradiction; it never
counts opinions, so repeating a relation or adding indirect relations cannot change the outcome.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Collection, Iterable

from appsec_review.review.evidence import make_gap, satisfies
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import (
    Claim, ClaimState, EvidenceRelation, Gap, GapClass, Predicate, RelationKind,
)
from appsec_review.review import obligations

RULES_VERSION = "adjudication-rules/1"


class DecidingRow(StrEnum):
    DUPLICATE = "r1_duplicate"
    OUT_OF_SCOPE = "r2_out_of_scope"
    UNRESOLVED_CONTRADICTION = "r3_unresolved_contradiction"
    DIRECT_CONTRADICTION = "r4_direct_contradiction"
    CONFIRMED = "r5_confirmed"
    SUPPORTED = "r6_supported"
    INSUFFICIENT_EVIDENCE = "r7_insufficient_evidence"


class PredicateOutcome(StrEnum):
    SATISFIED = "satisfied"          # direct support, no direct contradiction
    CONTRADICTED = "contradicted"    # direct contradiction, no direct support
    CONFLICTED = "conflicted"        # both; unresolved in slice 1
    UNRESOLVED = "unresolved"        # neither


# Row 4 precedence when several required predicates are contradicted: the table's listed order.
_CONTRADICTION_STATES: tuple[tuple[Predicate, ClaimState], ...] = (
    (Predicate.SOURCE_TO_SINK_REACHABILITY, ClaimState.NOT_REACHABLE),
    (Predicate.CONFIGURATION_ENABLES, ClaimState.NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION),
)

POLICY_SHA256 = sha256_hex({
    "rules": RULES_VERSION, "obligations": obligations.POLICY_SHA256,
    "rows": [row.value for row in DecidingRow],
    "contradiction_states": [[p.value, s.value] for p, s in _CONTRADICTION_STATES],
    "counted_admissibility": ["direct", "direct_for_mapped_predicate"], "requires_complete": True,
})


@dataclass(frozen=True, slots=True)
class PredicateStatus:
    predicate: Predicate
    required: bool
    outcome: PredicateOutcome
    supporting: tuple[str, ...]      # counted relation ids, sorted
    contradicting: tuple[str, ...]   # counted relation ids, sorted


@dataclass(frozen=True, slots=True)
class Adjudication:
    adjudication_id: str
    claim_id: str
    prior_state: ClaimState
    state: ClaimState
    deciding_row: DecidingRow
    predicates: tuple[PredicateStatus, ...]
    verifier_independent: bool
    duplicate_of: str | None
    gaps: tuple[Gap, ...]
    counted_relation_ids: tuple[str, ...]
    policy_sha256: str = POLICY_SHA256
    linked_gap_ids: tuple[str, ...] = field(default_factory=tuple)

    @property
    def gap_ids(self) -> tuple[str, ...]:
        return tuple(sorted({gap.gap_id for gap in self.gaps} | set(self.linked_gap_ids)))


def _predicate_statuses(claim: Claim, relations: Iterable[EvidenceRelation],
                        required: frozenset[Predicate]) -> tuple[tuple[PredicateStatus, ...], tuple[str, ...]]:
    support: dict[Predicate, set[str]] = {item: set() for item in Predicate}
    contra: dict[Predicate, set[str]] = {item: set() for item in Predicate}
    for relation in relations:
        if relation.claim_id != claim.claim_id:
            raise ValueError("evidence relation belongs to a different claim")
        if not satisfies(relation):
            continue
        if relation.kind is RelationKind.SUPPORTS:
            support[relation.predicate].add(relation.relation_id)
        elif relation.kind is RelationKind.CONTRADICTS:
            contra[relation.predicate].add(relation.relation_id)
    statuses = []
    for predicate in sorted(Predicate, key=lambda item: item.value):
        has_support, has_contra = bool(support[predicate]), bool(contra[predicate])
        outcome = (PredicateOutcome.CONFLICTED if has_support and has_contra
                   else PredicateOutcome.SATISFIED if has_support
                   else PredicateOutcome.CONTRADICTED if has_contra
                   else PredicateOutcome.UNRESOLVED)
        statuses.append(PredicateStatus(predicate, predicate in required, outcome,
                                        tuple(sorted(support[predicate])), tuple(sorted(contra[predicate]))))
    counted = sorted(set().union(*support.values(), *contra.values()))
    return tuple(statuses), tuple(counted)


def adjudicate(claim: Claim, relations: Iterable[EvidenceRelation], verifier_independent: bool,
               scope_entities: Collection[str], existing_claim_ids: Collection[str],
               prior_state: ClaimState = ClaimState.PROPOSED, *, verifier_gap: Gap | None = None,
               round: int = 0) -> Adjudication:
    """Apply the R5 table to ``claim``; the first matching row wins.

    ``existing_claim_ids`` are canonical claims adjudicated earlier in canonical order.
    ``scope_entities`` is the package scope plus accepted components. ``verifier_gap`` is the failed
    verifier cell's ``worker_gap``; it is linked whenever given.
    """
    required = obligations.required_predicates(claim.preconditions)
    statuses, counted = _predicate_statuses(claim, relations, required)
    by_predicate = {status.predicate: status for status in statuses}
    gaps: list[Gap] = []
    duplicate_of: str | None = None

    def gap(reason: str, predicate: Predicate | None = None) -> Gap:
        return make_gap(GapClass.EVIDENCE_GAP, claim.claim_id, reason, predicate=predicate, round=round)

    def required_with(outcome: PredicateOutcome) -> list[Predicate]:
        return [s.predicate for s in statuses if s.required and s.outcome is outcome]

    existing = set(existing_claim_ids)
    scope = set(scope_entities)
    if claim.claim_id in existing or (claim.duplicate_of is not None and claim.duplicate_of in existing):
        row, state = DecidingRow.DUPLICATE, ClaimState.DUPLICATE
        duplicate_of = claim.duplicate_of if claim.duplicate_of in existing else claim.claim_id
    elif all(entity not in scope for entity in claim.affected_entities):
        row, state = DecidingRow.OUT_OF_SCOPE, ClaimState.OUT_OF_SCOPE
    elif conflicted := required_with(PredicateOutcome.CONFLICTED):
        row, state = DecidingRow.UNRESOLVED_CONTRADICTION, ClaimState.INSUFFICIENT_EVIDENCE
        gaps.extend(gap("unresolved_contradiction", predicate) for predicate in conflicted)
    elif contradicted := required_with(PredicateOutcome.CONTRADICTED):
        row, state = DecidingRow.DIRECT_CONTRADICTION, ClaimState.CONTRADICTED
        for predicate, mapped in _CONTRADICTION_STATES:
            if predicate in contradicted:
                state = mapped
                break
    elif all(by_predicate[p].outcome is PredicateOutcome.SATISFIED for p in required) and verifier_independent:
        row, state = DecidingRow.CONFIRMED, ClaimState.CONFIRMED
    elif required_with(PredicateOutcome.SATISFIED):
        row, state = DecidingRow.SUPPORTED, ClaimState.SUPPORTED
    else:
        row, state = DecidingRow.INSUFFICIENT_EVIDENCE, ClaimState.INSUFFICIENT_EVIDENCE
    if row in {DecidingRow.SUPPORTED, DecidingRow.INSUFFICIENT_EVIDENCE}:
        gaps.extend(gap("missing_direct_evidence", predicate)
                    for predicate in required_with(PredicateOutcome.UNRESOLVED))
    gaps.sort(key=lambda item: item.gap_id)
    linked = (verifier_gap.gap_id,) if verifier_gap is not None else ()
    body = {
        "claim_id": claim.claim_id, "prior_state": ClaimState(prior_state).value, "state": state.value,
        "deciding_row": row.value, "duplicate_of": duplicate_of, "verifier_independent": bool(verifier_independent),
        "predicates": [{"predicate": s.predicate.value, "required": s.required, "outcome": s.outcome.value,
                        "supporting": list(s.supporting), "contradicting": list(s.contradicting)}
                       for s in statuses],
        "gap_ids": sorted({item.gap_id for item in gaps} | set(linked)),
        "policy_sha256": POLICY_SHA256,
    }
    return Adjudication(
        adjudication_id=make_id("adjudication", 1, body), claim_id=claim.claim_id,
        prior_state=ClaimState(prior_state), state=state, deciding_row=row, predicates=statuses,
        verifier_independent=bool(verifier_independent), duplicate_of=duplicate_of, gaps=tuple(gaps),
        counted_relation_ids=counted, linked_gap_ids=linked,
    )
