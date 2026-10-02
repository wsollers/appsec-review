#!/usr/bin/env python3
"""Lane-14 refutation and merge rules (ADR-0016 decisions 4, 6, 7, 9, 10).

* :func:`batches` groups composed chains for the ``attack-chain-refuter`` pool: at most
  ``chains_refuted_max`` chains (ranked), ``chain_refutation_batch`` per cell. The rest keep their
  composed state with refutation ``not_run`` and a gap.
* :func:`derive` turns a refuter reply (``attack-chain-refuter-persona.schema.json``: judgment only,
  one outcome per chain of the batch) into outcomes. ``broken`` and ``narrowed`` name the link or
  edge and cite at least one resolvable id: a citation of the chain itself (a linked claim's
  citation id, a fact ref of a link or hop) or a file the supporting-evidence menu pins. Anything
  else goes back through the invoker repair loop, as does a mechanism that carries code or asserts
  that a chain, exploit or vulnerability is verified (:func:`attack_chain_derive.assertion_errors`).
  The refuter cannot change a claim's ledger state; it decides only the chain.
* :func:`apply` sets each chain's refutation and recomputes its state and weakest link with
  :func:`attack_chain_derive.chain_state`. Refuted chains are dropped from the published list with
  the recorded reason; nothing ever rises above ``supported``.
* :func:`ledger` publishes the hash-linked attack-chain ledger (``chain_composed``,
  ``chain_refutation``, ``chain_state_derived``) bound to the claim-ledger head and the 09 pointer,
  after checking every ``causal_claim_ids`` entry resolves to a link candidate.
* :func:`rank` is the deterministic report order (decision 9).
"""
from __future__ import annotations

import json
from typing import Any, Iterable

import attack_chain_derive as chains_derive
from claude_cli_invoker import InvokerOutputError
from execution_state import Blocked, digest
from schema_validate import SchemaStore, validate_document

PERSONA_SCHEMA = "attack-chain-refuter-persona.schema.json"
LEDGER_SCHEMA = "attack-chain-ledger.schema.json"
BATCH_SCHEMA_ID = "appsec-review/attack-chain-refutation-batch/1.0"
LEDGER_SCHEMA_ID = "appsec-review/attack-chain-ledger/1.0"
BATCH_ROOT_ID = "chain-refutation-batch"
MENU_ROOTS = ("evidence-menu", "supporting-evidence")
DISPOSITIONS = ("broken", "narrowed", "holds", "cannot_assess")
STATE_RANK = {"supported": 0, "plausible": 1, "hypothesis": 2, "refuted": 3}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
MECHANISM_CHARS = 1200
_ORCHESTRATOR_KEYS = {"refuter", "citations", "state", "weakest", "candidate_id", "subject_id", "batch_id"}
_ALIASES = {"verdict": "disposition", "outcome": "disposition", "reason": "mechanism", "rationale": "mechanism",
            "explanation": "mechanism", "evidence": "citation_ids", "citation_refs": "citation_ids"}


def _clip(text: Any, limit: int) -> str:
    return chains_derive._clip(text, limit)


def boundaries(chain: dict[str, Any], facts: dict[str, dict[str, Any]]) -> set[str]:
    """Trust boundaries the chain's model_flow hops cross (threat-model flow facts)."""
    return {boundary for edge in chain["edges"] for ref in edge["fact_refs"]
            for boundary in (facts.get(ref) or {}).get("boundary_ids", [])}


def rank(chains: Iterable[dict[str, Any]], *, facts: dict[str, dict[str, Any]] | None = None,
         severities: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Decision 9: state, impact kind (code_execution first), highest 12 severity among verified
    links, trust boundaries crossed, fewer links, chain id."""
    facts, severities = facts or {}, severities or {}

    def key(chain: dict[str, Any]) -> tuple:
        verified = [link["claim_id"] for link in chain["links"] if link["claim_id"] and link["link_state"] == "verified"]
        severity = max((SEVERITY_RANK.get(severities.get(claim_id), 0) for claim_id in verified), default=0)
        crossed = boundaries(chain, facts) if facts else set(chain.get("boundaries_crossed") or [])
        return (STATE_RANK[chain["state"]], chains_derive.IMPACT_KINDS.index(chain["impact_kind"]), -severity,
                -len(crossed), len(chain["links"]), chain["chain_id"])
    return sorted(chains, key=key)


def batch_document(run_id: str, chains: list[dict[str, Any]], facts: dict[str, dict[str, Any]],
                   claims: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """One refuter request: the chains (weakest link named), the facts they cite and their claims."""
    refs = sorted({link["fact_ref"] for chain in chains for link in chain["links"] if link["fact_ref"]} |
                  {ref for chain in chains for edge in chain["edges"] for ref in edge["fact_refs"]} |
                  {edge["fact_ref"] for chain in chains for edge in chain["edges"] if edge["fact_ref"]})
    claim_ids = sorted({claim_id for chain in chains for claim_id in chain["causal_claim_ids"]})
    rows = [{key: chain[key] for key in ("chain_id", "objective", "impact_kind", "narrative", "links", "edges",
                                          "state", "weakest")} for chain in chains]
    return {"schema": BATCH_SCHEMA_ID, "run_id": run_id,
            "batch_id": "batch-" + digest([chain["chain_id"] for chain in chains])[:16],
            "chains": rows, "facts": [facts[ref] for ref in refs if ref in facts],
            "claims": [{key: claims[claim_id][key] for key in ("claim_id", "hypothesis", "link_state",
                        "verification_status", "component_ids", "locations")} for claim_id in claim_ids
                       if claim_id in claims]}


def batch_bytes(batch: dict[str, Any]) -> bytes:
    return chains_derive.workspace_bytes(batch)


def read_batch(data: bytes) -> dict[str, Any]:
    try:
        batch = json.loads(data)
    except ValueError as exc:
        raise InvokerOutputError("refutation batch (readable input 0) is not JSON") from exc
    if not isinstance(batch, dict) or batch.get("schema") != BATCH_SCHEMA_ID:
        raise InvokerOutputError("refutation batch (readable input 0) is not an attack-chain refutation batch")
    return batch


def batches(run_id: str, composed: list[dict[str, Any]], *, facts: dict[str, dict[str, Any]],
            claims: dict[str, dict[str, Any]], bounds: dict[str, int],
            severities: dict[str, str] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(refutation batches, gaps). Refuted-at-composition chains are never sent."""
    candidates = rank([chain for chain in composed if chain["state"] != "refuted"], facts=facts,
                      severities=severities)
    sent = candidates[:bounds["chains_refuted_max"]]
    gaps = [{"scope": "chain", "id": chain["chain_id"], "reason": "refutation-cap",
             "detail": f"chain ranked beyond chains_refuted_max ({bounds['chains_refuted_max']}); "
                       f"refutation not run, state capped at {chain['state']}"}
            for chain in candidates[bounds["chains_refuted_max"]:]]
    size = bounds["chain_refutation_batch"]
    groups = [sent[index:index + size] for index in range(0, len(sent), size)]
    return [batch_document(run_id, group, facts, claims) for group in groups], gaps


def _citable(chain: dict[str, Any], facts: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for link in chain["links"]:
        for citation in link["citations"]:
            key = citation["citation_id"] if citation["kind"] == "claim-citation" else citation["fact_id"]
            rows.setdefault(key, citation)
    for edge in chain["edges"]:
        for ref in edge["fact_refs"] + ([edge["fact_ref"]] if edge["fact_ref"] else []):
            if ref in facts:
                fact = facts[ref]
                rows.setdefault(ref, {"kind": "fact", "fact_id": ref, "item_id": fact["item_id"],
                                      "locator": fact["locator"], "artifact": fact["artifact"],
                                      "label": fact["label"]})
    return rows


def _menu_citation(ref: str, menu: dict[str, str]) -> dict[str, Any] | None:
    body, _sep, locator = ref.partition("#")
    root, sep, path = body.partition(":")
    if not sep or root not in MENU_ROOTS or f"{root}:{path}" not in menu:
        return None
    return {"kind": "menu-file", "root": root, "path": path, "sha256": menu[f"{root}:{path}"],
            "locator": _clip(locator, 200) if locator else None}


def _normalize(reply: Any) -> tuple[Any, list[str]]:
    notes: list[str] = []
    value = reply
    if isinstance(value, list):
        value = {"chains": value}
    if isinstance(value, dict) and "chains" not in value:
        for key in ("outcomes", "refutations", "results", "decisions"):
            if isinstance(value.get(key), list):
                value = {"chains": value[key]}
                break
    if not isinstance(value, dict) or not isinstance(value.get("chains"), list):
        return value, notes
    rows = []
    for index, row in enumerate(value["chains"]):
        if isinstance(row, dict):
            item = {}
            for key, part in row.items():
                if key in _ORCHESTRATOR_KEYS:
                    continue
                canonical = _ALIASES.get(key, key)
                if canonical in item and canonical != key:
                    continue
                item[canonical] = part
            if isinstance(item.get("disposition"), str):
                item["disposition"] = item["disposition"].strip().lower().replace(" ", "_")
            if isinstance(item.get("citation_ids"), str):
                item["citation_ids"] = [item["citation_ids"]]
            row = item
        rows.append(row)
    return {"chains": rows}, notes


def derive(batch: dict[str, Any], reply: Any, *, refuter: dict[str, Any], menu: dict[str, str] | None = None,
           store: SchemaStore | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return ({batch_id, outcomes}, limitations) or raise InvokerOutputError."""
    store = store or SchemaStore()
    menu = menu or {}
    value, notes = _normalize(reply)
    errors = [f"reply: {error}" for error in validate_document(value, PERSONA_SCHEMA, store)]
    if errors:
        raise InvokerOutputError(f"refuter reply fails {PERSONA_SCHEMA}: {len(errors)} error(s)", errors[:40])
    chains = {chain["chain_id"]: chain for chain in batch["chains"]}
    facts = {fact["fact_id"]: fact for fact in batch["facts"]}
    given: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(value["chains"]):
        where = f"chains[{index}]"
        if row["chain_id"] not in chains:
            errors.append(f"{where}: chain_id {row['chain_id']!r} is not a chain of this batch "
                          f"(allowed: {sorted(chains)})")
        elif row["chain_id"] in given and given[row["chain_id"]] != row:
            errors.append(f"{where}: chain {row['chain_id']} has more than one different outcome")
        else:
            given.setdefault(row["chain_id"], row)
    missing = sorted(set(chains) - set(given))
    if missing:
        errors.append(f"no outcome for chain(s) {missing}; every chain of the batch needs one")
    if errors:
        raise InvokerOutputError("refuter reply does not cover the batch", errors)
    outcomes = []
    for chain_id in sorted(given):
        row, chain = given[chain_id], chains[chain_id]
        where = f"chain {chain_id}"
        disposition, target = row["disposition"], row.get("target")
        if disposition in {"broken", "narrowed"}:
            if not isinstance(target, dict):
                errors.append(f"{where}: {disposition} names the link or edge it breaks or narrows (target)")
                continue
            bound = len(chain["links"]) if target["kind"] == "link" else len(chain["edges"])
            if not 0 <= target["index"] < bound:
                errors.append(f"{where}: target {target['kind']} {target['index']} does not exist "
                              f"({bound} {target['kind']}s)")
                continue
            if not (row.get("mechanism") or "").strip():
                errors.append(f"{where}: {disposition} needs the mechanism (which check, sanitisation or "
                              f"precondition, at which hop)")
                continue
        elif target is not None:
            notes.append(f"{where}: target ignored for disposition {disposition}")
            target = None
        citable = _citable(chain, facts)
        citations, unknown = [], []
        for ref in dict.fromkeys(row.get("citation_ids") or []):
            item = citable.get(ref) or _menu_citation(ref, menu)
            (citations.append(item) if item else unknown.append(ref))
        if unknown:
            notes.append(f"{where}: citation(s) {unknown[:5]} resolve to neither the chain nor a pinned menu "
                         f"file; dropped")
        if disposition in {"broken", "narrowed"} and not citations:
            errors.append(f"{where}: {disposition} needs at least one resolvable citation: a citation id or fact "
                          f"ref of this chain, or 'supporting-evidence:<pinned path>[#locator]' "
                          f"(allowed chain ids: {sorted(citable)[:20]})")
            continue
        mechanism = row.get("mechanism")
        if mechanism and chains_derive._PAYLOAD_RE.search(mechanism):
            errors.append(f"{where}: describe the break; do not include code, commands or encoded payloads")
            continue
        wording = chains_derive.assertion_errors(mechanism or "", f"{where} mechanism")
        if wording:
            errors.extend(wording)
            continue
        outcomes.append({"chain_id": chain_id, "disposition": disposition,
                         "target": {"kind": target["kind"], "index": target["index"]} if target else None,
                         "mechanism": _clip(mechanism, MECHANISM_CHARS) if mechanism else None,
                         "refuter": refuter, "citations": citations})
    if errors:
        raise InvokerOutputError(f"refuter outcomes do not resolve against the batch: {len(errors)} error(s)", errors)
    return {"batch_id": batch["batch_id"], "outcomes": outcomes}, [note[:500] for note in dict.fromkeys(notes)]


def candidates(document: dict[str, Any], evidence_sha256: str) -> dict[str, Any]:
    """The invoker's strict candidates document: one candidate per chain outcome."""
    return {"candidates": [{"candidate_id": "refute-" + digest(row)[:24], "subject_id": row["chain_id"],
                            "assertion": json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
                            "evidence_sha256": evidence_sha256, "claim_class": "candidate_only"}
                           for row in document["outcomes"]]}


def not_run(reason: str) -> dict[str, Any]:
    return {"disposition": "not_run", "target": None, "mechanism": reason, "refuter": None, "citations": []}


def apply(composed: list[dict[str, Any]], outcomes: dict[str, dict[str, Any]],
          not_run_reasons: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(published chains, dropped refuted chains) with the refutation recorded and the state recomputed."""
    published, dropped = [], []
    for chain in sorted(composed, key=lambda row: row["chain_id"]):
        outcome = outcomes.get(chain["chain_id"])
        refutation = ({key: outcome[key] for key in ("disposition", "target", "mechanism", "refuter", "citations")}
                      if outcome else not_run(not_run_reasons.get(chain["chain_id"], "refutation did not run")))
        state, weakest = chains_derive.chain_state(chain["links"], chain["edges"],
                                                   None if refutation["disposition"] == "not_run" else refutation)
        if refutation["disposition"] == "not_run" and weakest["reason"] == "refutation did not run":
            weakest = {**weakest, "reason": f"refutation not run: {refutation['mechanism']}"}
        final = {**chain, "refutation": refutation, "state": state, "weakest": weakest}
        if state == "refuted":
            dropped.append({"chain_id": chain["chain_id"], "cluster_id": chain["cluster_id"],
                            "reason": _clip(f"{weakest['reason']}: {refutation['mechanism'] or 'no mechanism'}", 600)})
        else:
            published.append(final)
    return published, dropped


def _entry(sequence: int, event_type: str, chain_id: str, payload: dict[str, Any], previous: str | None) -> dict[str, Any]:
    entry = {"sequence": sequence, "event_type": event_type, "chain_id": chain_id, "payload": payload,
             "previous_entry_hash": previous}
    return {**entry, "entry_hash": "sha256:" + digest(entry)}


def ledger(run_id: str, *, claim_ledger_head_sha256: str | None, verification_pointer_sha256: str,
           link_candidates: Iterable[str], composed: list[dict[str, Any]], outcomes: dict[str, dict[str, Any]],
           published: list[dict[str, Any]], dropped: list[dict[str, Any]], gaps: list[dict[str, Any]],
           coverage: dict[str, Any], facts: dict[str, dict[str, Any]] | None = None,
           severities: dict[str, str] | None = None, store: SchemaStore | None = None) -> dict[str, Any]:
    """The hash-linked attack-chain ledger (decision 7)."""
    known = set(link_candidates)
    final = {chain["chain_id"]: chain for chain in published}
    final.update({row["chain_id"]: None for row in dropped})
    entries, previous = [], None
    for chain in sorted(composed, key=lambda row: row["chain_id"]):
        causal = chain["causal_claim_ids"]
        if len(causal) != len(set(causal)) or not set(causal) <= known:
            raise Blocked("attack-chain ledger: causal claim id is duplicated or not a link candidate")
        if chain["chain_id"] not in final:
            raise Blocked("attack-chain ledger: composed chain has no final state")
        record = {key: value for key, value in chain.items() if key not in {"refutation", "state", "weakest"}}
        for event_type, payload in (
                ("chain_composed", {"cluster_id": chain["cluster_id"], "composer": chain["composer"],
                                    "record_sha256": "sha256:" + digest(record)}),
                ("chain_refutation", (outcomes.get(chain["chain_id"]) and
                                      {key: outcomes[chain["chain_id"]][key] for key in
                                       ("disposition", "target", "refuter")}) or {"disposition": "not_run",
                                                                                  "target": None, "refuter": None}),
                ("chain_state_derived", {"state": final[chain["chain_id"]]["state"] if final[chain["chain_id"]] else
                                         "refuted"})):
            entry = _entry(len(entries), event_type, chain["chain_id"], payload, previous)
            entries.append(entry); previous = entry["entry_hash"]
    ranked = rank(published, facts=facts, severities=severities)
    document = {"schema": LEDGER_SCHEMA_ID, "run_id": run_id, "claim_ledger_head_sha256": claim_ledger_head_sha256,
                "verification_pointer_sha256": verification_pointer_sha256, "entries": entries, "head_hash": previous,
                "chains": [{**chain, "rank": position + 1,
                            "boundaries_crossed": sorted(boundaries(chain, facts or {}))}
                           for position, chain in enumerate(ranked)],
                "dropped": sorted(dropped, key=lambda row: row["chain_id"]),
                "gaps": sorted(gaps, key=lambda row: (row["scope"], row["id"], row["reason"])),
                "coverage": coverage, "claim_limits": dict(chains_derive.CLAIM_LIMITS),
                "note": "Chains are prioritisation context composed from reviewed claims; none is a verified "
                        "finding and none assigns severity."}
    store = store or SchemaStore()
    problems = validate_document(document, LEDGER_SCHEMA, store)
    for chain in document["chains"]:
        problems += validate_document({key: value for key, value in chain.items()
                                       if key not in {"rank", "boundaries_crossed"}},
                                      chains_derive.RECORD_SCHEMA, store)
    if problems:
        raise Blocked(f"attack-chain ledger fails its closed schema ({problems[0]})")
    return document


def verify_ledger(document: dict[str, Any]) -> None:
    """Re-check the hash chain (tamper evidence for the report and re-derivation)."""
    previous = None
    for sequence, entry in enumerate(document["entries"]):
        body = {key: value for key, value in entry.items() if key != "entry_hash"}
        if (entry["sequence"] != sequence or entry["previous_entry_hash"] != previous or
                entry["entry_hash"] != "sha256:" + digest(body)):
            raise Blocked("attack-chain ledger: hash chain is broken")
        previous = entry["entry_hash"]
    if document["head_hash"] != previous:
        raise Blocked("attack-chain ledger: head hash does not match the last entry")
