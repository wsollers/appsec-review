#!/usr/bin/env python3
"""Derive step for the stage claim-review pool (07/08/09/12).

The reviewer model supplies only judgment: one decision per upstream ``claim_id`` with its
verdict text and the upstream citation / proof-obligation ids it relies on
(``claim-review-pool-persona.schema.json``).  This module owns the bookkeeping the model used to
copy by hand (model-bookkeeping audit, item 1 / section 3.8):

* reviewer / verifier identity (all ten ``claim-lifecycle-actor`` fields) from the trusted
  request and the upstream claim's generations;
* citation ids resolved against the upstream claim's own citation set, replaced by the canonical
  upstream objects (a model-typed citation object is never published; only its ``citation_id`` is
  read), deduplicated and in upstream order;
* proof-obligation statements from the upstream record (the model gives id + status + citation ids);
* the candidate wrapper (``candidate_id``, ``subject_id``, ``claim_class``, ``evidence_sha256``) and
  the canonical JSON ``assertion`` string.

Nothing is invented.  An unknown claim id, an unknown obligation id, a missing claim or obligation,
or a decision left with no resolvable citation rejects the reply with repair details (the invoker's
bounded repair loop re-asks the model).  An unknown citation id next to at least one resolvable one
is dropped and reported as an invoker limitation.  Before returning, the derived decisions are run
through the stage's own ``claim_lifecycle_core`` rules so a disposition/obligation inconsistency is
also sent back to the model instead of failing the merge later.  The final strict schemas
(candidates + decision) still run afterwards, unchanged.
"""
from __future__ import annotations

import json
from typing import Any

import claim_lifecycle_core as core
from claude_cli_invoker import InvokerOutputError
from execution_state import Blocked
from schema_validate import SchemaStore, validate_document

PERSONA_SCHEMA = "claim-review-pool-persona.schema.json"
DECISION_SCHEMA = "claim-review-decision.schema.json"
POOL_CLASSES = {"07-red-team-adversarial": "candidate_only",
                "08-blue-team-refutation": "refutation",
                "09-independent-verification": "verification_observation",
                "12-scoring-prioritization": "verification_observation"}
ROLES = {"07-red-team-adversarial": "red-team-adversary",
         "08-blue-team-refutation": "blue-team-refuter",
         "09-independent-verification": "independent-verifier"}
ACTOR_FIELD = {"07-red-team-adversarial": "reviewer", "08-blue-team-refutation": "reviewer",
               "09-independent-verification": "verifier"}
UPSTREAM_ARRAYS = {"07-red-team-adversarial": "candidates", "08-blue-team-refutation": "hypotheses",
                   "09-independent-verification": "reviews",
                   "12-scoring-prioritization": "verifications"}
# The upstream record fields whose citation objects a stage decision may cite (the same sets
# claim_lifecycle_core checks: 07 candidate citations; 08 + red review_citations; 09 + blue
# refutation_citations).
CITABLE = {"07-red-team-adversarial": ("citations",),
           "08-blue-team-refutation": ("citations", "review_citations"),
           "09-independent-verification": ("citations", "refutation_citations")}
# Model-facing decision fields per stage: (required, optional).
PERSONA_FIELDS = {
    "07-red-team-adversarial": ({"claim_id", "attacker_case", "citation_ids"},
                                {"dissent_ids", "cwe", "attack_refs", "capec_refs"}),
    "08-blue-team-refutation": ({"claim_id", "disposition", "rationale", "proof_obligations",
                                 "citation_ids"}, {"dissent_ids"}),
    "09-independent-verification": ({"claim_id", "disposition", "method", "proof_obligations",
                                     "citation_ids"}, {"dissent_ids", "cwe"}),
    "12-scoring-prioritization": ({"claim_id", "factors", "rationale"}, {"cwe", "cvss_v4", "remediation"}),
}
ACTOR_REASON = "Bounded stage reviewer selected by the accepted reviewer-pool specification."
# The persona schema's disposition enum is shared by 08 and 09; each stage's own record schema accepts
# fewer. Checked here so a cross-stage value gets a repair round that names the claim and the fix
# (09 re-run 2026-10-04 answered SURVIVING, the 08 outcome, and failed only at the closed schema).
STAGE_DISPOSITIONS = {
    "08-blue-team-refutation": ("REFUTED", "SURVIVING", "UNRESOLVED"),
    "09-independent-verification": ("REFUTED", "UNRESOLVED", "BLOCKED"),  # no new evidence here: never VERIFIED
}
DISPOSITION_HINTS = {
    ("09-independent-verification", "SURVIVING"): (
        "SURVIVING is the 08 outcome; at 09 a claim that survived refutation but has no new independent "
        "evidence is UNRESOLVED, with the obligation(s) still needing that evidence marked UNRESOLVED"),
}

# Orchestrator-owned keys a model may still echo out of habit; they are ignored, never trusted.
# Candidate-wrapper bookkeeping, plus every field the decision schema declares where the persona schema
# does not (ADR-0013: Python derives it). `citations` is one: Python builds it from citation_ids, and
# only the citation ids a legacy echo names are read. Hand-written, not built with contract_derive,
# because claim_reviewer_pool.py (which would list that module) is also hashed by the intake
# persona-tool pool; tests/test_contract_derive.py fails when a schema-derived field is missing here.
_ORCHESTRATOR_KEYS = frozenset({"reviewer", "verifier", "citations", "statement", "candidate_id", "subject_id",
                                "claim_class", "evidence_sha256", "assertion"})
_OBLIGATION_KEYS = frozenset({"citations", "statement"})
_CORE = {"07-red-team-adversarial": core.red_team, "08-blue-team-refutation": core.blue_team,
         "09-independent-verification": core.verify, "12-scoring-prioritization": core.score}


def canonical_assertion(decision: dict[str, Any]) -> str:
    return json.dumps(decision, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def upstream_from_bytes(stage: str, data: bytes) -> dict[str, Any]:
    """The accepted upstream document the reviewer read: 07 reads the raw L01 ledger, which is
    projected to its candidate view exactly as the lifecycle loader does; later stages read the
    previous stage's result as is."""
    value = json.loads(data)
    if stage == "07-red-team-adversarial" and isinstance(value, dict) and "entries" in value:
        value = core._ledger_view(value)
    return value


def upstream_records(stage: str, upstream: dict[str, Any]) -> list[dict[str, Any]]:
    return list(upstream.get(UPSTREAM_ARRAYS[stage]) or [])


def actor(stage: str, request: dict[str, Any], request_sha256: str,
          record: dict[str, Any]) -> dict[str, Any]:
    """All ten claim-lifecycle-actor fields from the trusted request and the upstream claim."""
    path = f"requests/{request['attempt_id']}.json"
    return {"job_id": stage, "attempt_id": request["attempt_id"], "role_id": ROLES[stage],
            "source_generation": record["source_generation"],
            "component_generation": record["component_generation"],
            "artifact_path": path, "artifact_sha256": request_sha256,
            "permission_receipt_path": path, "permission_receipt_sha256": request_sha256,
            "reason": ACTOR_REASON}


def _ids(values: Any, where: str, errors: list[str]) -> list[str]:
    """Citation ids from a list of bare ids or (legacy) citation objects; only the id is read."""
    result = []
    for index, value in enumerate(values if isinstance(values, list) else []):
        if isinstance(value, dict):
            value = value.get("citation_id")
        if isinstance(value, str) and value:
            result.append(value)
        else:
            errors.append(f"{where}[{index}]: expected a citation id string")
    return result


def _strip(row: dict[str, Any], owned: frozenset[str], where: str, errors: list[str]) -> dict[str, Any]:
    """``row`` without orchestrator-owned keys; the ids of an echoed ``citations`` join citation_ids."""
    kept = {key: item for key, item in row.items() if key not in owned}
    if "citations" in row:
        legacy = _ids(row["citations"], f"{where}.citations", errors)
        kept["citation_ids"] = list(kept.get("citation_ids") or []) + legacy
    return kept


def _normalize(stage: str, value: Any) -> tuple[Any, list[str]]:
    """Accept the persona reply and the legacy full-candidate reply; return persona decisions."""
    errors: list[str] = []
    if isinstance(value, dict) and isinstance(value.get("candidates"), dict):
        value = value["candidates"]
    if isinstance(value, list):
        value = {"decisions": value}
    if isinstance(value, dict) and "decisions" not in value and isinstance(value.get("candidates"), list):
        rows = []
        for index, candidate in enumerate(value["candidates"]):
            decision = candidate.get("decision") if isinstance(candidate, dict) else None
            if decision is None and isinstance(candidate, dict):
                decision = candidate.get("assertion")
                if isinstance(decision, str):
                    try:
                        decision = json.loads(decision)
                    except ValueError:
                        errors.append(f"candidates[{index}].assertion: not a JSON decision")
                        continue
            rows.append(decision)
        value = {"decisions": rows}
    if not isinstance(value, dict) or not isinstance(value.get("decisions"), list):
        return value, errors
    decisions = []
    for index, row in enumerate(value["decisions"]):
        if not isinstance(row, dict):
            decisions.append(row)
            continue
        row = _strip(row, _ORCHESTRATOR_KEYS, f"decisions[{index}]", errors)
        if isinstance(row.get("proof_obligations"), list):
            obligations = []
            for position, item in enumerate(row["proof_obligations"]):
                if isinstance(item, dict):
                    item = _strip(item, _OBLIGATION_KEYS,
                                  f"decisions[{index}].proof_obligations[{position}]", errors)
                obligations.append(item)
            row["proof_obligations"] = obligations
        if stage == "12-scoring-prioritization":
            row.pop("citation_ids", None)
        decisions.append(row)
    return {"decisions": decisions}, errors


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _precheck_binding(stage: str, evidence_sha256: str) -> dict[str, Any]:
    return {"job_id": "claim-review-pool-precheck", "attempt_id": "precheck",
            "pointer_sha256": "sha256:" + "0" * 64,
            "artifact_path": core.STAGES[stage][1], "artifact_sha256": evidence_sha256}


MAX_ABSENT_HINTS = 20


def _decision_requirements(stage: str, claim_id: str, record: dict[str, Any]) -> str:
    required, _optional = PERSONA_FIELDS[stage]
    citations = sorted({citation["citation_id"] for field in CITABLE.get(stage, ())
                        for citation in record.get(field) or []})
    text = (f"claim {claim_id} has no decision: write one (read this claim's record in the shard to judge it; "
            f"that lookup is allowed) with fields {sorted(required)}")
    if citations:
        text += f"; citation_ids from {citations}"
    if "proof_obligations" in required:
        obligations = [item["obligation_id"] for item in record.get("proof_obligations") or []]
        text += f"; proof_obligations answering every one of {obligations}"
    return text


def derive(stage: str, upstream: dict[str, Any], reply: Any, *, request: dict[str, Any],
           request_sha256: str, evidence_sha256: str,
           store: SchemaStore | None = None,
           carry: dict[str, dict[str, Any]] | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return (claim-review-pool-candidates document, limitations) or raise InvokerOutputError.

    ``carry`` holds well-formed decisions from this invocation's earlier, rejected rounds; a claim the
    current reply omits is taken from it, so a repair round that drops a different claim each time
    still converges. Run 20261004T054551Z-357581 (09, 41-claim shards): every repair round fixed the
    claim it was told about and omitted another, so the invocation failed after three paid rounds.
    The rejected reply's well-formed rows are attached to the error as ``rows`` for the next round."""
    if stage not in POOL_CLASSES:
        raise InvokerOutputError(f"claim review derive: unknown stage {stage!r}")
    store = store or SchemaStore()
    value, errors = _normalize(stage, reply)
    errors += [f"reply: {error}" for error in validate_document(value, PERSONA_SCHEMA, store)]
    if errors:
        raise InvokerOutputError(f"reviewer reply fails {PERSONA_SCHEMA}: {len(errors)} error(s)",
                                 errors)
    records = {record["claim_id"]: record for record in upstream_records(stage, upstream)}
    required, optional = PERSONA_FIELDS[stage]
    limitations: list[str] = []
    by_claim: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(value["decisions"]):
        where = f"decisions[{index}]"
        claim_id = row["claim_id"]
        missing, extra = sorted(required - set(row)), sorted(set(row) - required - optional)
        if missing or extra:
            errors.append(f"{where} ({claim_id}): stage {stage} decisions need exactly "
                          f"{sorted(required)} (optional {sorted(optional)}); missing {missing}, "
                          f"not allowed {extra}")
            continue
        if claim_id not in records:
            errors.append(f"{where}: claim_id {claim_id!r} is not an upstream claim")
            continue
        allowed_dispositions = STAGE_DISPOSITIONS.get(stage)
        if allowed_dispositions and row.get("disposition") not in allowed_dispositions:
            value_shown = row.get("disposition") if isinstance(row.get("disposition"), str) else "<other>"
            hint = DISPOSITION_HINTS.get((stage, value_shown))
            errors.append(f"claim {claim_id}: disposition {value_shown} is not allowed at {stage}; use one of "
                          f"{list(allowed_dispositions)}" + (f" ({hint})" if hint else ""))
        if claim_id in by_claim:
            if by_claim[claim_id] == row:
                limitations.append(f"claim {claim_id}: identical duplicate decision collapsed")
            else:
                errors.append(f"{where}: claim_id {claim_id!r} has more than one different decision")
            continue
        by_claim[claim_id] = row
    for claim_id in sorted(set(records) - set(by_claim)):
        if carry and claim_id in carry:
            by_claim[claim_id] = carry[claim_id]
            limitations.append(f"claim {claim_id}: decision carried from an earlier repair round")
    absent = sorted(set(records) - set(by_claim))
    if absent:
        errors.append(f"no decision for upstream claim_id(s) {absent}; every upstream claim needs one")
        # Name what each missing decision must contain (ids only), so a repair round can write it without
        # re-reading the whole shard. Run 20261001T064759Z-4a8586 (08, reviewer-00): round 0 skipped one
        # of 96 claims; the repair, told only "no decision for claim X", guessed and missed its three
        # proof obligations and its one citation.
        for claim_id in absent[:MAX_ABSENT_HINTS]:
            errors.append(_decision_requirements(stage, claim_id, records[claim_id]))
    if errors:
        error = InvokerOutputError(f"reviewer reply does not cover the upstream claims: {len(errors)} error(s)",
                                   errors)
        error.rows = dict(by_claim)
        raise error

    decisions: dict[str, dict[str, Any]] = {}
    for claim_id in sorted(by_claim):
        row, record = by_claim[claim_id], records[claim_id]
        decision: dict[str, Any] = {"claim_id": claim_id}
        if stage == "12-scoring-prioritization":
            decision.update(factors=row["factors"], rationale=row["rationale"])
            for key in ("cwe", "cvss_v4", "remediation"):  # judgment only; Python validates/computes
                if row.get(key) is not None:
                    decision[key] = row[key]
            decisions[claim_id] = decision
            continue
        citable: dict[str, dict[str, Any]] = {}
        for field in CITABLE[stage]:
            for citation in record.get(field) or []:
                citable.setdefault(citation["citation_id"], citation)
        order = list(citable)

        def resolve(ids: list[str], where: str) -> list[str]:
            known = []
            for item in _unique(ids):
                if item in citable:
                    known.append(item)
                else:
                    limitations.append(f"claim {claim_id}: {where} cites {item!r}, which is not an "
                                       f"upstream citation of this claim; dropped")
            return known

        cited = resolve(row["citation_ids"], "decision")
        obligations = None
        if "proof_obligations" in row:
            upstream_obligations = {item["obligation_id"]: item for item in record["proof_obligations"]}
            given: dict[str, dict[str, Any]] = {}
            for position, item in enumerate(row["proof_obligations"]):
                oid = item["obligation_id"]
                if oid not in upstream_obligations:
                    errors.append(f"claim {claim_id}: proof_obligations[{position}] obligation_id "
                                  f"{oid!r} is not an upstream obligation (allowed: "
                                  f"{sorted(upstream_obligations)})")
                elif oid in given and given[oid] != item:
                    errors.append(f"claim {claim_id}: obligation {oid!r} is given twice with "
                                  f"different statuses or citations")
                given.setdefault(oid, item)
            missing = sorted(set(upstream_obligations) - set(given))
            if missing:
                errors.append(f"claim {claim_id}: proof_obligations must answer every upstream "
                              f"obligation; missing {missing}")
            obligations = []
            for oid, upstream_item in upstream_obligations.items():
                item = given.get(oid)
                if item is None:
                    continue
                ids = resolve(item.get("citation_ids") or [], f"obligation {oid}")
                cited += [x for x in ids if x not in cited]
                obligations.append({"obligation_id": oid, "statement": upstream_item["statement"],
                                    "status": item["status"],
                                    "citations": [citable[x] for x in order if x in set(ids)]})
        if not cited:
            errors.append(f"claim {claim_id}: citation_ids must name at least one upstream citation "
                          f"of this claim (allowed: {order})")
            continue
        decision[ACTOR_FIELD[stage]] = actor(stage, request, request_sha256, record)
        for key in ("attacker_case", "disposition", "rationale", "method", "cwe", "attack_refs", "capec_refs"):
            if key in row:
                decision[key] = row[key]
        if obligations is not None:
            decision["proof_obligations"] = obligations
        decision["citations"] = [citable[x] for x in order if x in set(cited)]
        decision["dissent_ids"] = sorted(set(row.get("dissent_ids") or []))
        decisions[claim_id] = decision
    if errors:
        raise InvokerOutputError(f"reviewer decisions do not resolve against the upstream claims: "
                                 f"{len(errors)} error(s)", errors)

    for claim_id, decision in decisions.items():
        problems = validate_document({"stage": stage, "decision": decision}, DECISION_SCHEMA, store)
        if problems:  # derive bug or a model value the persona schema allowed; never silent
            errors.append(f"claim {claim_id}: derived decision fails {DECISION_SCHEMA}: {problems[0]}")
    if errors:
        raise InvokerOutputError("derived decisions fail the closed decision schema", errors)
    # The stage's own evidence/obligation/disposition rules, so the model gets a repair round
    # instead of the merge failing after the pool (the merge re-runs the same rules).
    try:
        _CORE[stage](upstream, _precheck_binding(stage, evidence_sha256),
                     {"decisions": [decisions[key] for key in sorted(decisions)]})
    except Blocked as exc:
        raise InvokerOutputError(f"reviewer decisions violate the {stage} rules: {exc}",
                                 [f"{stage} rule: {exc}"]) from None
    candidates = [{"candidate_id": f"decision-{claim_id}", "subject_id": claim_id,
                   "assertion": canonical_assertion(decisions[claim_id]),
                   "evidence_sha256": evidence_sha256, "claim_class": POOL_CLASSES[stage]}
                  for claim_id in sorted(decisions)]
    return {"candidates": candidates}, [note[:500] for note in _unique(limitations)]
