"""The adjudication judge: which claims get one, and what it is shown (docs/architecture/review-judge-and-poc.md).

A judge decides which of two sides, shown as **A and B in a deterministic shuffled order**, is correct about one
claim. Everything here is a pure function of the review's own records:

* :func:`side_assignment` -- which role stands behind A and B, from ``sha256(manifest || claim || "judge-order")``.
  The map is stored in the judge cell's terminal record and is never in the request.
* :func:`selected` -- the ``when = "all" | "disagreement"`` rule.
* :func:`red_side` / :func:`blue_side` -- the two sides as stances, per-predicate stances with their cited identities,
  and a reason, taken from the cells' expanded results.
* :func:`present` -- the bounded, labelled, role-blind rendering the judge is shown: sides A and B with citations by
  label, and the rows either side cited that the package has no label for, re-presented under ``J`` labels.

The judge never sets a claim state; its relations carry ``provenance = "adjudication_judge"`` and R5 does not count
them. What a judge may be shown is decided here and where its request is built, never in the shared compact layer.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import re
from typing import Any

from appsec_review.review.compact import PREDICATES, STANCE_ORDER, UNRESOLVED
from appsec_review.review.package_view import PackageView

JUDGE_TASK = "adjudicate_claim"
ORDER_TAG = "judge-order"
JUDGE_PERSONA = "generalist"
PROVENANCE = "adjudication_judge"
REMOVED = "[removed]"
BLUE_DISAGREEING = frozenset({"contradicts", "qualifies", UNRESOLVED})


def side_assignment(manifest_sha256: str, claim_id: str, index: int = 0) -> dict[str, str]:
    """``{"A": role, "B": role}`` with role in ``red`` / ``blue``.

    Side A is red when the low bit of ``sha256(manifest_sha256 || claim_id || "judge-order")`` (the last byte of the
    digest, read big-endian) is 0 and blue when it is 1. It is reproducible for replay and unrelated to role.
    """
    tag = ORDER_TAG if index == 0 else f"{ORDER_TAG}/{index}"
    digest = hashlib.sha256((manifest_sha256 + claim_id + tag).encode("utf-8")).digest()
    first = "red" if digest[-1] & 1 == 0 else "blue"
    return {"A": first, "B": "blue" if first == "red" else "red"}


# ------------------------------------------------------------------------------------------------
# Selection


def selected(when: str, *, red_affirmed: bool, blue_dispositions: Sequence[str | None]) -> bool:
    """Whether a claim gets a judge under ``when``.

    ``red_affirmed``: red affirmed at least one predicate with a citation. ``blue_dispositions`` has one entry per blue
    cell: its disposition, or ``None`` when the cell produced no usable answer. ``all`` judges every affirmed claim.
    ``disagreement`` judges an affirmed claim when any blue cell contradicts, qualifies, leaves a predicate unresolved or
    gave no answer (no answer is not agreement), or when the blue cells disagree with each other.
    """
    if when not in ("all", "disagreement"):
        raise ValueError(f"unknown judge selection: {when}")
    if not red_affirmed:
        return False
    if when == "all":
        return True
    return (any(item is None or item in BLUE_DISAGREEING for item in blue_dispositions)
            or len(set(blue_dispositions)) > 1)


# ------------------------------------------------------------------------------------------------
# The two sides


@dataclass(slots=True)
class SideInput:
    """One side's position: an overall stance, its stance and cited identities per predicate, and its reason."""

    stance: str = UNRESOLVED
    predicates: dict[str, tuple[str, list[str]]] = field(default_factory=dict)   # predicate -> (stance, identities)
    why: str = ""
    order: tuple[str, ...] = STANCE_ORDER       # which stance wins when one predicate has several

    def merge(self, predicate: str, stance: str, refs: Iterable[str]) -> None:
        old_stance, old_refs = self.predicates.get(predicate, (UNRESOLVED, []))
        better = _strongest((old_stance, stance), self.order)
        merged = old_refs + [ref for ref in refs if ref not in old_refs]
        self.predicates[predicate] = (better, merged)


def _strongest(stances: Iterable[str], order: Sequence[str] = STANCE_ORDER) -> str:
    found = set(stances)
    return next((item for item in order if item in found), UNRESOLVED)


def red_side(items: Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]]) -> SideInput:
    """The red side of one claim from ``(proposal, red result)`` pairs of the cells that proposed it.

    Supporting references are ``supports``; counter-references are ``qualifies``. The reason is the proposals'
    statements, not their cell narrative. Nothing here names a cell, role or persona.
    """
    side = SideInput(stance="supports", order=("supports", "qualifies", "contradicts", UNRESOLVED))
    statements: list[str] = []
    for proposal, result in items:
        by_id = {str(ref["local_id"]): ref for ref in result.get("evidence_refs", ())}
        for key, kind in (("evidence_ids", "supports"), ("counterevidence_ids", "qualifies")):
            for local in proposal.get(key, ()):
                ref = by_id.get(str(local))
                if ref is not None:
                    side.merge(str(ref["predicate"]), kind, [str(ref["entity_id"])])
        statement = " ".join(str(proposal.get("statement", "")).split())
        if statement and statement not in statements:
            statements.append(statement)
    side.why = " ".join(statements)
    return side


def red_affirms(side: SideInput) -> bool:
    return any(stance == "supports" and refs for stance, refs in side.predicates.values())


def blue_side(results: Iterable[Mapping[str, Any] | None]) -> tuple[SideInput, list[str | None]]:
    """The blue side from each blue cell's expanded result (``None`` for a cell with no usable answer).

    Returns the merged side and one disposition per cell. A side with no answer at all is ``unresolved`` with a
    plain statement of that, never an opinion.
    """
    side = SideInput()
    dispositions: list[str | None] = []
    reasons: list[str] = []
    for result in results:
        if result is None:
            dispositions.append(None)
            continue
        dispositions.append(str(result.get("disposition")))
        for relation in result.get("proposed_relations", ()):
            side.merge(str(relation["predicate"]), str(relation["kind"]), [str(relation["entity_id"])])
        reason = " ".join(str(result.get("rationale", "")).split())
        if reason and reason not in reasons:
            reasons.append(reason)
    answered = [item for item in dispositions if item is not None]
    side.stance = _strongest(answered) if answered else UNRESOLVED
    side.why = " | ".join(reasons) if reasons else (
        "no answer was produced for this side" if not answered else "this side stated no reason")
    return side, dispositions


# ------------------------------------------------------------------------------------------------
# What the judge is shown


def scrub(text: str, markers: Iterable[str]) -> tuple[str, int]:
    """``text`` with every marker (role, task, persona, actor and model names) replaced; and how many were."""
    count = 0
    for marker in sorted({item for item in markers if item}, key=lambda item: (-len(item), item)):
        text, n = re.subn(re.escape(marker), REMOVED, text, flags=re.IGNORECASE)
        count += n
    return text, count


def _bounded(text: str, limit: int) -> tuple[str, int]:
    if len(text) <= limit:
        return text, 0
    return text[:max(0, limit - 1)].rstrip() + "…", len(text) - (limit - 1)


@dataclass(frozen=True, slots=True)
class Presentation:
    """The judge's view of the two sides: the request fields, the view with its ``J`` labels, and what was left out."""

    sides: dict[str, Any]
    cited_rows: dict[str, dict[str, Any]]
    view: PackageView
    omitted: dict[str, dict[str, int]]          # side letter -> counts of omissions, as shown in the request
    rows: tuple[str, ...]                       # the identities behind the J labels, in label order


def present(sides: Mapping[str, SideInput], assignment: Mapping[str, str], view: PackageView, *, max_why: int,
            max_rows: int, markers: Iterable[str] = (),
            describe: Callable[[str], str] = lambda ref: ref) -> Presentation:
    """Render ``sides`` (keyed by role) as sides A and B of ``assignment`` for ``view``'s cell.

    Each side keeps at most ``max_rows`` distinct cited identities, in predicate order; the rest are counted. A cited
    identity with a package label keeps it; any other is given the next ``J`` label and shown under ``cited_rows``
    with ``describe(ref)``. A side's reason is scrubbed of ``markers`` and cut to ``max_why`` characters. Omissions are
    counted in the side's ``omitted`` object; a side with none carries no such key.
    """
    markers = list(markers)
    kept: dict[str, dict[str, tuple[str, list[str]]]] = {}
    counts: dict[str, dict[str, int]] = {}
    order: list[str] = []
    for letter in ("A", "B"):
        side = sides[assignment[letter]]
        remaining: list[str] = []
        shown: dict[str, tuple[str, list[str]]] = {}
        dropped: set[str] = set()
        for predicate in PREDICATES:
            if predicate not in side.predicates:
                continue
            stance, refs = side.predicates[predicate]
            keep = []
            for ref in refs:
                if ref in remaining or len(remaining) < max_rows:
                    if ref not in remaining:
                        remaining.append(ref)
                    keep.append(ref)
                else:
                    dropped.add(ref)
            shown[predicate] = (stance, keep)
        kept[letter] = shown
        counts[letter] = {"cited_rows": len(dropped)} if dropped else {}
        order.extend(ref for ref in remaining if ref not in order)
    probe, labelled = view.with_extra(order, prefix="J")
    existing = set(view.labels.values())
    new_rows = [ref for ref in order if ref not in existing]
    cited_rows = {labelled[ref]: {"ref": ref, "summary": describe(ref)} for ref in new_rows}
    rendered: dict[str, Any] = {}
    for letter in ("A", "B"):
        side = sides[assignment[letter]]
        reason, redactions = scrub(side.why or "no reason stated", markers)
        reason, cut = _bounded(reason, max_why)
        omitted = dict(counts[letter])
        if cut:
            omitted["why_characters"] = cut
        if redactions:
            omitted["removed_identifying_terms"] = redactions
        entry: dict[str, Any] = {
            "stance": side.stance,
            "per_predicate": {predicate: {"stance": stance, "cites": [labelled[ref] for ref in refs]}
                              for predicate, (stance, refs) in kept[letter].items()},
            "why": reason}
        if omitted:
            entry["omitted"] = omitted
            counts[letter] = omitted
        rendered[letter] = entry
    return Presentation(rendered, cited_rows, probe, counts, tuple(new_rows))


__all__ = ["JUDGE_PERSONA", "JUDGE_TASK", "PROVENANCE", "Presentation", "SideInput", "blue_side", "present",
           "red_affirms", "red_side", "scrub", "selected", "side_assignment"]
