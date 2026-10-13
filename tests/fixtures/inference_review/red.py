"""Build ``red-discovery-result/1`` final results for scripted red workers.

A scripted worker reads the echo block and the package lead menu from its cell input and returns a
result that accounts for every lead exactly once: ``proposal`` for the leads its proposals develop,
``no_proposal`` for every other lead (which is never clean coverage).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

RED_SCHEMA = "appsec-review/red-discovery-result/1"


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
    requests: Sequence[Mapping[str, Any]] = ()       # evidence requests (predicate, requested_kind, scope)
    taint: Mapping[str, Any] | None = None           # one taint path, already in schema shape
    extra_refs: Sequence[Mapping[str, Any]] = field(default_factory=tuple)


def invocation(task_input: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    payload = task_input["input"]
    return dict(payload["echo"]), [lead["observation_id"] for lead in payload["package"]["lead_menu"]]


def evidence_ref(local_id: str, entity_id: str, predicate: str, relation: str = "supports") -> dict[str, Any]:
    return {"local_id": local_id, "entity_id": entity_id, "shard_id": None, "shard_sha256": None,
            "relation": relation, "predicate": predicate,
            "locator": {"kind": "unresolved", "reason": "the scripted worker relies on re-resolution"}}


def red_result(task_input: Mapping[str, Any], proposals: Sequence[Proposal] = (), *,
               chain_seeds: Sequence[Mapping[str, Any]] = (), gaps: Sequence[Mapping[str, Any]] = ()
               ) -> dict[str, Any]:
    echo, leads = invocation(task_input)
    refs: list[dict[str, Any]] = []
    built: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []
    for proposal in proposals:
        evidence_ids = []
        for index, (predicate, entity) in enumerate(proposal.support):
            local = f"{proposal.local_id}-e{index}"
            refs.append(evidence_ref(local, entity, predicate))
            evidence_ids.append(local)
        refs.extend(dict(item) for item in proposal.extra_refs)
        for index, request in enumerate(proposal.requests):
            requests.append({"local_id": f"{proposal.local_id}-r{index}", "proposal_id": proposal.local_id,
                             "reason": "the scripted worker could not decide this predicate", **request})
        path_ids = []
        if proposal.taint is not None:
            paths.append({**proposal.taint, "proposal_id": proposal.local_id})
            path_ids.append(proposal.taint["local_id"])
        built.append({
            "local_id": proposal.local_id, "source_lead_ids": list(proposal.leads),
            "affected_entities": list(proposal.affected), "statement": proposal.statement,
            "mechanism": f"{proposal.statement} [mechanism]",
            "weakness": {"namespace": "CWE", "id": proposal.cwe} if proposal.cwe else None,
            "security_predicate": proposal.predicate,
            "attacker_entry": {"entity_id": None, "control": f"{proposal.statement} [attacker control]",
                               "preconditions": list(proposal.preconditions)},
            "trigger": f"{proposal.statement} [trigger]",
            "suspected_consequence": f"{proposal.statement} [consequence]",
            "assumptions": [], "evidence_ids": evidence_ids, "counterevidence_ids": [], "obligation_ids": [],
            "taint_path_ids": path_ids})
    accounting = []
    for lead in leads:
        developing = [item["local_id"] for item in built if lead in item["source_lead_ids"]]
        accounting.append({"observation_id": lead, "outcome": "proposal" if developing else "no_proposal",
                           "proposal_ids": developing, "gap_ids": [],
                           "reason": "developed into a proposal" if developing else
                           "this bounded lens proposed nothing for the lead"})
    return {"schema": RED_SCHEMA, **echo, "result_status": "partial" if gaps else "completed",
            "lead_accounting": accounting, "proposals": built, "proof_obligations": [], "taint_paths": paths,
            "chain_seeds": list(chain_seeds), "evidence_refs": refs, "evidence_requests": requests,
            "gaps": list(gaps)}
