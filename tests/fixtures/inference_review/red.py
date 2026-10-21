"""Build ``red-compact/1`` final results for scripted red workers.

A scripted worker reads the package leads from its cell input and answers in the compact form a model gives
(review-protocol/2): claims with label (here: raw identity) citations, and every lead that no claim develops
listed under ``no_claim``, which is never clean coverage. The application expands the answer into
``red-discovery-result/1`` (``review.compact.expand_red``) before any validator runs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

COMPACT_SCHEMA = "appsec-review/red-compact/1"


@dataclass(frozen=True)
class Proposal:
    local_id: str
    affected: Sequence[str]
    cwe: str | None
    predicate: str
    preconditions: Sequence[str]
    statement: str
    support: Sequence[tuple[str, str]] = ()          # (R4 predicate, entity id) supporting references
    leads: Sequence[str] = ()                        # source lead (observation) ids
    counter: Sequence[tuple[str, str]] = ()          # (R4 predicate, entity id) counterevidence
    missing: Sequence[str] = ()                      # named gaps
    poc_basis: Mapping[str, Any] | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)


def lead_refs(task_input: Mapping[str, Any]) -> list[str]:
    return [lead["ref"] for lead in task_input["input"]["package"]["leads"]]


def _by_predicate(pairs: Sequence[tuple[str, str]]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for predicate, ref in pairs:
        bucket = found.setdefault(predicate, [])
        if ref not in bucket:
            bucket.append(ref)
    return found


def red_result(task_input: Mapping[str, Any], proposals: Sequence[Proposal] = (), *, blocked: Sequence[str] = (),
               omit_leads: bool = False) -> dict[str, Any]:
    """The compact answer of a scripted red worker for the leads in ``task_input``."""
    leads = lead_refs(task_input)
    claims = []
    for proposal in proposals:
        claim: dict[str, Any] = {
            "id": proposal.local_id, "leads": list(proposal.leads), "security_predicate": proposal.predicate,
            "statement": proposal.statement, "support": _by_predicate(proposal.support),
            "affected": list(proposal.affected), **dict(proposal.extra)}
        if proposal.cwe:
            claim["cwe"] = proposal.cwe
        if proposal.preconditions:
            claim["preconditions"] = list(proposal.preconditions)
        if proposal.counter:
            claim["counter"] = _by_predicate(proposal.counter)
        if proposal.missing:
            claim["missing"] = list(proposal.missing)
        if proposal.poc_basis is not None:
            claim["poc_basis"] = dict(proposal.poc_basis)
        claims.append(claim)
    developed = {lead for proposal in proposals for lead in proposal.leads}
    result: dict[str, Any] = {"claims": claims}
    if not omit_leads:
        result["no_claim"] = [{"lead": lead, "why": "this bounded lens proposed nothing for the lead"}
                              for lead in leads if lead not in developed and lead not in blocked]
        result["blocked"] = [{"lead": lead, "why": "the lens could not assess the lead"} for lead in blocked]
    return result
