"""Claim identity normalization (design R7).

Identity covers the sorted accepted affected entities, the validated CWE, the security predicate
(a ``security-predicates/1`` member), and the sorted closed preconditions. Statement prose, lane,
package, and origin are excluded, so the same condition found in both lanes merges by identity.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Callable, Collection, Iterable, Sequence

from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review.identity import make_id
from appsec_review.review.models import (
    SECURITY_PREDICATES_VERSION, Claim, Gap, GapClass, Lane, SecurityPredicate, make_gap,
)
from appsec_review.review.obligations import parse_precondition

# Version 2: the security predicate is a closed security-predicates/1 member and the vocabulary
# version is part of the identity body (claim ids changed once with this vocabulary).
CLAIM_IDENTITY_VERSION = 2
_CWE = re.compile(r"^CWE-0*([1-9][0-9]{0,5})$")

SymbolLookup = Callable[[str], "str | None"]


@dataclass(frozen=True, slots=True)
class ClaimNormalization:
    claim: Claim
    gaps: tuple[Gap, ...] = field(default_factory=tuple)


def normalize_cwe(value: str) -> str | None:
    """Return ``CWE-<n>`` for a syntactically valid CWE id, else ``None``."""
    text = "".join(str(value).split()).upper()
    if text.isdigit():
        text = f"CWE-{text}"
    match = _CWE.fullmatch(text)
    return f"CWE-{int(match.group(1))}" if match else None


def normalize_security_predicate(value: str | SecurityPredicate) -> tuple[SecurityPredicate, bool]:
    """Return ``(member, known)``. Spelling is canonicalized (case, whitespace, hyphens) as for
    preconditions; a value that is still not a ``security-predicates/1`` member is ``OTHER`` with
    ``known`` false, so the caller records the loss. It is never silently mapped elsewhere."""
    text = re.sub(r"[\s\-]+", "_", str(value).strip().lower())
    try:
        return SecurityPredicate(text), True
    except ValueError:
        return SecurityPredicate.OTHER, False


def normalize_entities(entities: Iterable[str], enclosing_symbol: SymbolLookup | None = None) -> tuple[str, ...]:
    """Return sorted unique accepted identities, mapping spans to an enclosing symbol when known."""
    normalized: set[str] = set()
    for value in entities:
        identity = LogicalIdentity.parse(str(value).strip())
        if identity.kind is EntityKind.SOURCE_SPAN and enclosing_symbol is not None:
            symbol = enclosing_symbol(identity.value)
            if symbol is not None:
                resolved = LogicalIdentity.parse(symbol)
                if resolved.kind is not EntityKind.SYMBOL:
                    raise ValueError("enclosing symbol lookup returned a non-symbol identity")
                identity = resolved
        normalized.add(identity.value)
    if not normalized:
        raise ValueError("a claim requires at least one affected entity")
    return tuple(sorted(normalized))


def claim_identity(affected_entities: Sequence[str], weakness_cwe: str | None,
                   security_predicate: SecurityPredicate | str, preconditions: Sequence[str]) -> str:
    """The canonical claim id; ``security_predicate`` must be a ``security-predicates/1`` member."""
    return make_id("claim", CLAIM_IDENTITY_VERSION, {
        "affected_entities": list(affected_entities), "weakness_cwe": weakness_cwe,
        "security_predicate": SecurityPredicate(security_predicate).value,
        "security_predicates": SECURITY_PREDICATES_VERSION, "preconditions": list(preconditions),
    })


def normalize_claim(*, lane: Lane, package_id: str, affected_entities: Iterable[str], weakness_cwe: str | None,
                    security_predicate: str | SecurityPredicate, preconditions: Iterable[str], statement: str,
                    accepted_cwe_ids: Collection[str], enclosing_symbol: SymbolLookup | None = None,
                    origin_cell_ids: Iterable[str] = (), round: int = 0) -> ClaimNormalization:
    """Normalize a worker claim; malformed entities or preconditions raise ``ValueError``.

    A CWE that is malformed or absent from ``accepted_cwe_ids`` (the accepted MITRE CWE reference,
    no parent roll-up) is dropped from identity and reported as an ``evidence_gap``. A security
    predicate outside ``security-predicates/1`` becomes ``other`` and is likewise reported as an
    ``evidence_gap`` on the claim: the claim survives, but its identity lost precision. (Worker
    results cannot reach this branch: their schemas close the field to the vocabulary, so a worker
    that invents a predicate fails cell validation as a ``schema_error`` instead.)
    """
    entities = normalize_entities(affected_entities, enclosing_symbol)
    predicate, known_predicate = normalize_security_predicate(security_predicate)
    conditions = tuple(sorted({parse_precondition(item).value for item in preconditions}))
    cwe: str | None = None
    rejected_cwe = False
    if weakness_cwe is not None and str(weakness_cwe).strip():
        candidate = normalize_cwe(weakness_cwe)
        accepted = {normalize_cwe(item) for item in accepted_cwe_ids} - {None}
        if candidate is not None and candidate in accepted:
            cwe = candidate
        else:
            rejected_cwe = True
    claim_id = claim_identity(entities, cwe, predicate, conditions)
    gaps: list[Gap] = []
    if rejected_cwe:
        gaps.append(make_gap(GapClass.EVIDENCE_GAP, claim_id,
                             "weakness is not an accepted CWE reference identity", round=round))
    if not known_predicate:
        gaps.append(make_gap(GapClass.EVIDENCE_GAP, claim_id,
                             f"security predicate is not a {SECURITY_PREDICATES_VERSION} member; "
                             f"normalized to other", round=round))
    claim = Claim(
        claim_id=claim_id, lane=Lane(lane), package_id=package_id, affected_entities=entities,
        weakness_cwe=cwe, security_predicate=predicate, preconditions=conditions,
        statement=" ".join(str(statement).split()),
        origin_cell_ids=tuple(sorted(set(origin_cell_ids))),
    )
    return ClaimNormalization(claim, tuple(gaps))


def possible_duplicates(claims: Iterable[Claim]) -> tuple[tuple[str, str], ...]:
    """Nominate claim pairs that share an affected entity but differ in CWE (never merged)."""
    unique = {claim.claim_id: claim for claim in claims}
    ordered = [unique[key] for key in sorted(unique)]
    pairs: list[tuple[str, str]] = []
    for index, left in enumerate(ordered):
        left_entities = set(left.affected_entities)
        for right in ordered[index + 1:]:
            if left.weakness_cwe != right.weakness_cwe and left_entities.intersection(right.affected_entities):
                pairs.append((left.claim_id, right.claim_id))
    return tuple(pairs)
