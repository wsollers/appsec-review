#!/usr/bin/env python3
"""Derive step for the lane-14 composer pool (persona reply -> strict attack-chain records).

The ``attack-chain-composer`` persona sees one cluster workspace (``attack-chain-workspace``,
readable input 0) and supplies judgment only (``attack-chain-composer-persona.schema.json``): which
claims or facts form a chain, the stage of each link, its prerequisites and the citation ids it
relies on, which fact ref justifies each hop, the objective, impact kind and a short narrative, or
an explicit ``no_chain_reason``. This module keeps the books (ADR-0016 decisions 3, 4, 5.3, 12):

* every link ref resolves to a workspace claim or fact; citation ids resolve against that claim's
  own citations (a fact link cites the fact itself); canonical citation objects replace the ids;
* the stage order (``entry`` -> ``execution`` -> ``privilege_gain`` -> ``persistence`` |
  ``lateral_movement`` -> ``impact``), exactly one ``entry`` first and one ``impact`` last,
  ``chain_links_max`` and ``chains_per_cluster_max``;
* the edge basis: a hop whose fact ref is on a seeded ``code_fact`` / ``model_flow`` adjacency edge
  between the two links is that basis; a claimed basis whose ref does not join both endpoints is
  downgraded to ``synthetic`` and the downgrade recorded;
* ``chain_id``, link states, ``causal_claim_ids``, ``fact_refs``, the chain state and its weakest
  link (:func:`chain_state`), deduplication;
* optional link ``attack_refs`` (ADR-0026): ATT&CK technique ids validated against the in-ceiling
  MITRE snapshot and the link stage's tactics; a drop, or a missing or stale snapshot, is a recorded
  limitation that withholds the label. Labels never change a link state, an edge or the chain state.

An unknown id, an illegal stage order, a missing hop or a bound overrun raises
``InvokerOutputError`` so the invoker's bounded repair loop re-asks the model. The model never
names a finding, file, line or hash that is not already in the workspace. Chains are descriptions
of how reviewed weaknesses combine: a narrative that carries code or an encoded payload is sent back
for repair, and every narrative must name at least one of its chain's claim ids.
"""
from __future__ import annotations

import json
import re
from typing import Any

import attack_reference
from claude_cli_invoker import InvokerOutputError
from execution_state import digest
from schema_validate import SchemaStore, validate_document

PERSONA_SCHEMA = "attack-chain-composer-persona.schema.json"
RECORD_SCHEMA = "attack-chain-record.schema.json"
CANDIDATES_SCHEMA = "attack-chain-candidates.schema.json"
WORKSPACE_SCHEMA_ID = "appsec-review/attack-chain-workspace/1.0"
WORKSPACE_ROOT_ID = "chain-workspace"
STAGE_RANK = {"entry": 0, "execution": 1, "privilege_gain": 2, "persistence": 3, "lateral_movement": 3,
              "impact": 4}
ONCE_STAGES = ("entry", "persistence", "lateral_movement", "impact")
IMPACT_KINDS = ("code_execution", "data_disclosure", "data_tampering", "denial_of_service",
                "credential_theft", "exfiltration")
LINK_STRENGTH = {"refuted": 0, "open": 1, "narrowed": 2, "verified": 3}
EDGE_STRENGTH = {"synthetic": 1, "model_flow": 2, "code_fact": 3}
OBJECTIVE_CHARS = 300
NARRATIVE_CHARS = 1500
TEXT_CHARS = 400
PREREQUISITES_MAX = 6
CLAIM_LIMITS = {"finding_created": False, "severity_assigned": False}
# Code fences, shell prompts and escaped byte runs are payload material, not a chain description.
_PAYLOAD_RE = re.compile(r"```|(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){6,}|<script\b|\$\(\s*[a-z]",
                         re.IGNORECASE)
_ORCHESTRATOR_KEYS = {"chain_id", "cluster_id", "state", "weakest", "link_state", "causal_claim_ids",
                      "fact_refs", "composer", "claim_limits", "refutation", "citations", "basis",
                      "downgraded_from", "index", "adjacency_edge_id", "mitre_reference"}
_PROMOTION_KEYS = {"severity", "cvss", "cvss_score", "risk", "priority", "verified", "finding"}


def _clip(text: Any, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def read_workspace(data: bytes) -> dict[str, Any]:
    try:
        workspace = json.loads(data)
    except ValueError as exc:
        raise InvokerOutputError("chain workspace (readable input 0) is not JSON") from exc
    if not isinstance(workspace, dict) or workspace.get("schema") != WORKSPACE_SCHEMA_ID:
        raise InvokerOutputError("chain workspace (readable input 0) is not an attack-chain workspace")
    return workspace


def workspace_bytes(workspace: dict[str, Any]) -> bytes:
    return (json.dumps(workspace, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("utf-8")


def _strip(row: Any, where: str, notes: list[str]) -> Any:
    if not isinstance(row, dict):
        return row
    out = {}
    for key, value in row.items():
        if key in _ORCHESTRATOR_KEYS:
            continue
        if key in _PROMOTION_KEYS:
            notes.append(f"{where}: ignored {key!r}; chains are prioritisation context, not rated findings")
            continue
        out[key] = value
    return out


def normalize(reply: Any) -> tuple[Any, list[str]]:
    """Accept the persona shape and the wrappers models send (a clusters list of one, a bare list)."""
    notes: list[str] = []
    value = reply
    if isinstance(value, dict) and isinstance(value.get("clusters"), list) and len(value["clusters"]) == 1:
        value = value["clusters"][0]
    if isinstance(value, list):
        value = {"chains": value}
    if not isinstance(value, dict):
        return value, notes
    value = {key: item for key, item in value.items() if key != "cluster_id"}
    value.setdefault("no_chain_reason", None)
    if not isinstance(value.get("chains"), list):
        return value, notes
    chains = []
    for index, chain in enumerate(value["chains"]):
        where = f"chains[{index}]"
        chain = _strip(chain, where, notes)
        if isinstance(chain, dict):
            for key in ("links", "edges"):
                if isinstance(chain.get(key), list):
                    chain[key] = [_strip(row, f"{where}.{key}[{n}]", notes) for n, row in enumerate(chain[key])]
            for link in chain.get("links") or []:
                if isinstance(link, dict) and isinstance(link.get("prerequisites"), list):
                    link["prerequisites"] = [{"text": item, "requires_link_indexes": []} if isinstance(item, str)
                                             else item for item in link["prerequisites"]]
        chains.append(chain)
    value["chains"] = chains
    return value, notes


def chain_state(links: list[dict[str, Any]], edges: list[dict[str, Any]],
                refutation: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
    """(state, weakest) per ADR-0016 decision 4. ``refutation`` is None when refutation did not run,
    else ``{"disposition": broken|narrowed|holds|cannot_assess, "target": {kind, index} | None}``."""
    elements = []
    for link in links:
        elements.append((LINK_STRENGTH[link["link_state"]], 2 * link["index"], "link", link["index"],
                         f"link {link['index']} ({link['stage']}) is {link['link_state']}"))
    for edge in edges:
        elements.append((EDGE_STRENGTH[edge["basis"]], 2 * edge["from"] + 1, "edge", edge["from"],
                         f"edge {edge['from']}->{edge['to']} is {edge['basis']}"))
    strength, _position, kind, index, reason = min(elements)
    weakest = {"kind": kind, "index": index, "reason": reason}
    disposition = (refutation or {}).get("disposition")
    target = (refutation or {}).get("target")
    if disposition == "broken" and target:
        return "refuted", {"kind": target["kind"], "index": target["index"],
                           "reason": f"refuter broke {target['kind']} {target['index']}"}
    if any(link["link_state"] == "refuted" for link in links):
        return "refuted", weakest
    if any(link["link_state"] == "open" for link in links) or any(edge["basis"] == "synthetic" for edge in edges):
        return "hypothesis", weakest
    if disposition == "narrowed" and target:
        return "plausible", {"kind": target["kind"], "index": target["index"],
                             "reason": f"refuter narrowed {target['kind']} {target['index']}"}
    if (disposition != "holds" or any(link["link_state"] == "narrowed" for link in links)
            or any(edge["basis"] == "model_flow" for edge in edges)):
        if disposition not in {"holds", "narrowed"} and strength == 3:
            weakest["reason"] = ("refutation did not run" if disposition is None else
                                 "refuter could not assess the chain")
        return "plausible", weakest
    return "supported", weakest


def _adjacent(workspace: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    pairs: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for edge in workspace["adjacency"]:
        if edge["basis"] in {"code_fact", "model_flow"}:
            pairs.setdefault((edge["from"], edge["to"]), []).append(edge)
            pairs.setdefault((edge["to"], edge["from"]), []).append(edge)
    return pairs


def _mitre(chains: list[Any]) -> tuple[Any, dict[str, Any] | None]:
    """The MITRE reference for link labels, loaded only when a link carries ``attack_refs``."""
    if not any(isinstance(link, dict) and link.get("attack_refs") is not None
               for chain in chains if isinstance(chain, dict) for link in chain.get("links") or []):
        return None, None
    return attack_reference.load()


def _labels(row: dict[str, Any], at: str, mitre: tuple[Any, dict[str, Any] | None], notes: list[str],
            seen: list[dict[str, Any]]) -> list[str] | None:
    if row.get("attack_refs") is None:
        return None
    reference, gap = mitre
    screened = attack_reference.screen(row["attack_refs"], [], tactic=attack_reference.CHAIN_STAGE_TACTICS[row["stage"]],
                                       reference=reference, gap=gap)
    for item in screened["gaps"]:
        shown = item.get("ref") or ", ".join(item.get("withheld") or [])
        notes.append(f"{at}: ATT&CK label {shown} withheld ({item['code']}); labels are never evidence")
    seen.append(screened["reference"])
    return screened["attack_refs"]


def _chain(workspace: dict[str, Any], chain: dict[str, Any], where: str, *, claims: dict[str, dict[str, Any]],
           facts: dict[str, dict[str, Any]], pairs: dict, links_max: int, errors: list[str],
           notes: list[str], mitre: tuple[Any, dict[str, Any] | None] = (None, None)) -> dict[str, Any] | None:
    start = len(errors)
    rows = chain["links"]
    if not 2 <= len(rows) <= links_max:
        errors.append(f"{where}: a chain has 2 to {links_max} links (chain_links_max); got {len(rows)}")
        return None
    links, refs, labelled = [], [], []
    for index, row in enumerate(rows):
        at = f"{where}.links[{index}]"
        given = [key for key in ("claim_id", "fact_ref") if row.get(key)]
        if len(given) != 1:
            errors.append(f"{at}: give exactly one of claim_id or fact_ref")
            continue
        ref = row[given[0]]
        if given[0] == "claim_id" and ref not in claims:
            errors.append(f"{at}: claim_id {ref!r} is not a claim of this workspace (allowed: {sorted(claims)[:20]})")
            continue
        if given[0] == "fact_ref" and ref not in facts:
            errors.append(f"{at}: fact_ref {ref!r} is not a fact of this workspace")
            continue
        if ref in refs:
            errors.append(f"{at}: {ref!r} appears twice in one chain; a chain is acyclic")
            continue
        refs.append(ref)
        if given[0] == "claim_id":
            citable = {item["citation_id"]: item for item in claims[ref]["citations"]}
            ids = list(dict.fromkeys(row.get("citation_ids") or []))
            unknown = [item for item in ids if item not in citable]
            known = [item for item in ids if item in citable]
            if not known:
                errors.append(f"{at}: citation_ids must name at least one citation of claim {ref} "
                              f"(allowed: {sorted(citable)})")
                continue
            if unknown:
                notes.append(f"{at}: citation id(s) {unknown[:5]} are not citations of {ref}; dropped")
            citations = [{"kind": "claim-citation", **citable[item]} for item in citable if item in set(known)]
            state = claims[ref]["link_state"]
        else:
            fact = facts[ref]
            extra = [item for item in (row.get("citation_ids") or []) if item != ref]
            if extra:
                notes.append(f"{at}: a fact link cites the fact itself; {extra[:5]} ignored")
            citations = [{"kind": "fact", "fact_id": ref, "item_id": fact["item_id"], "locator": fact["locator"],
                          "artifact": fact["artifact"], "label": fact["label"]}]
            state = "verified" if fact["deterministic"] else "open"
        prerequisites = []
        for position, item in enumerate((row.get("prerequisites") or [])[:PREREQUISITES_MAX]):
            required = sorted(set(item.get("requires_link_indexes") or []))
            if any(not isinstance(n, int) or isinstance(n, bool) or not 0 <= n < index for n in required):
                errors.append(f"{at}.prerequisites[{position}]: requires_link_indexes must name earlier "
                              f"links of this chain (0..{index - 1})")
            prerequisites.append({"text": _clip(item["text"], TEXT_CHARS), "requires_link_indexes": required})
        links.append({"index": index, "stage": row["stage"], "claim_id": ref if given[0] == "claim_id" else None,
                      "fact_ref": ref if given[0] == "fact_ref" else None, "link_state": state,
                      "prerequisites": prerequisites, "citations": citations})
        labels = _labels(row, at, mitre, notes, labelled)
        if labels is not None:
            links[-1]["attack_refs"] = labels
    if len(errors) > start:
        return None
    stages = [link["stage"] for link in links]
    if stages[0] != "entry" or stages[-1] != "impact":
        errors.append(f"{where}: the first link is the one 'entry' and the last the one 'impact' (got {stages})")
    for stage in ONCE_STAGES:
        if stages.count(stage) > 1:
            errors.append(f"{where}: stage {stage!r} appears {stages.count(stage)} times; at most once")
    ranks = [STAGE_RANK[stage] for stage in stages]
    if ranks != sorted(ranks):
        errors.append(f"{where}: stages may be skipped but not reordered: entry, execution, privilege_gain, "
                      f"persistence|lateral_movement, impact (got {stages})")
    given_edges: dict[tuple[int, int], dict[str, Any]] = {}
    for position, edge in enumerate(chain["edges"]):
        pair = (edge["from"], edge["to"])
        if edge["to"] != edge["from"] + 1 or not 0 <= edge["from"] < len(links) - 1:
            errors.append(f"{where}.edges[{position}]: an edge joins link i to link i+1 (got {pair})")
        elif pair in given_edges and given_edges[pair] != edge:
            errors.append(f"{where}.edges[{position}]: hop {pair} is given twice")
        else:
            given_edges[pair] = edge
    missing = [f"{i}->{i + 1}" for i in range(len(links) - 1) if (i, i + 1) not in given_edges]
    if missing:
        errors.append(f"{where}: every hop needs an edge; missing {missing}")
    if len(errors) > start:
        return None
    edges = []
    for i in range(len(links) - 1):
        edge = given_edges[(i, i + 1)]
        claimed, ref = edge["basis_claimed"], edge.get("fact_ref")
        if ref is not None and ref not in facts:
            errors.append(f"{where}.edges {i}->{i + 1}: fact_ref {ref!r} is not a fact of this workspace")
            continue
        match = next((row for row in pairs.get((refs[i], refs[i + 1]), []) if ref in row["fact_refs"]), None) \
            if ref is not None else None
        if match is not None and claimed != "synthetic":
            basis, downgraded = match["basis"], None
            if match["basis"] != claimed:
                notes.append(f"{where}: edge {i}->{i + 1} claimed {claimed}; its ref is a {match['basis']} edge")
        else:
            basis, downgraded = "synthetic", (claimed if claimed != "synthetic" else None)
            if downgraded:
                notes.append(f"{where}: edge {i}->{i + 1} claimed {claimed} but its fact ref does not join "
                             f"both links; recorded as synthetic")
        edges.append({"from": i, "to": i + 1, "basis": basis, "fact_ref": ref,
                      "fact_refs": match["fact_refs"] if basis != "synthetic" and match else [],
                      "adjacency_edge_id": match["edge_id"] if basis != "synthetic" and match else None,
                      "downgraded_from": downgraded, "rationale": _clip(edge["rationale"], TEXT_CHARS)})
    if len(errors) > start:
        return None
    causal = [link["claim_id"] for link in links if link["claim_id"]]
    if not causal:
        errors.append(f"{where}: a chain composes at least one reviewed claim of the workspace")
        return None
    narrative = _clip(chain["narrative"], NARRATIVE_CHARS)
    if not any(claim_id in narrative for claim_id in causal):
        errors.append(f"{where}: the narrative must name at least one of its claim ids ({causal})")
    if _PAYLOAD_RE.search(chain["narrative"]) or _PAYLOAD_RE.search(chain["objective"]):
        errors.append(f"{where}: describe how the reviewed weaknesses combine; do not include code, commands "
                      f"or encoded payloads")
    if len(errors) > start:
        return None
    identity = {"links": refs, "edges": [[edge["basis"], edge["fact_refs"]] for edge in edges]}
    state, weakest = chain_state(links, edges, None)
    record = {"chain_id": "chain-" + digest(identity)[:24], "cluster_id": workspace["cluster_id"],
              "objective": _clip(chain["objective"], OBJECTIVE_CHARS), "impact_kind": chain["impact_kind"],
              "narrative": narrative, "links": links, "edges": edges, "causal_claim_ids": causal,
              "fact_refs": [link["fact_ref"] for link in links if link["fact_ref"]],
              "weakest": weakest, "refutation": None, "state": state, "composer": None,
              "claim_limits": dict(CLAIM_LIMITS)}
    if any(labelled):
        record["mitre_reference"] = next(item for item in labelled if item)
    return record


def derive(workspace: dict[str, Any], reply: Any, *, composer: dict[str, Any],
           store: SchemaStore | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return ({cluster_id, no_chain_reason, chains}, limitations) or raise InvokerOutputError."""
    store = store or SchemaStore()
    value, notes = normalize(reply)
    errors = [f"reply: {error}" for error in validate_document(value, PERSONA_SCHEMA, store)]
    if errors:
        raise InvokerOutputError(f"composer reply fails {PERSONA_SCHEMA}: {len(errors)} error(s)", errors[:40])
    limits = workspace["bounds"]
    chains, reason = value["chains"], value.get("no_chain_reason")
    if not chains and not (isinstance(reason, str) and reason.strip()):
        errors.append("an empty chains list needs a no_chain_reason for the cluster")
    if chains and reason:
        notes.append("no_chain_reason ignored: the reply also proposes chains")
        reason = None
    if len(chains) > limits["chains_per_cluster_max"]:
        errors.append(f"at most {limits['chains_per_cluster_max']} chains per cluster (chains_per_cluster_max); "
                      f"got {len(chains)}")
    if errors:
        raise InvokerOutputError("composer reply breaks the chain bounds", errors)
    claims = {claim["claim_id"]: claim for claim in workspace["claims"]}
    facts = {fact["fact_id"]: fact for fact in workspace["facts"]}
    pairs = _adjacent(workspace)
    mitre = _mitre(chains)
    records: dict[str, dict[str, Any]] = {}
    for index, chain in enumerate(chains):
        record = _chain(workspace, chain, f"chains[{index}]", claims=claims, facts=facts, pairs=pairs,
                        links_max=limits["chain_links_max"], errors=errors, notes=notes, mitre=mitre)
        if record is None:
            continue
        record["composer"] = composer
        if record["chain_id"] in records:
            notes.append(f"chains[{index}]: same links and edges as an earlier chain; collapsed")
            continue
        problems = validate_document(record, RECORD_SCHEMA, store)
        if problems:   # derive bug or a value the persona schema allowed; never silent
            errors.append(f"chains[{index}]: derived record fails {RECORD_SCHEMA}: {problems[0]}")
            continue
        records[record["chain_id"]] = record
    if errors:
        raise InvokerOutputError(f"composer chains do not resolve against the workspace: {len(errors)} error(s)",
                                 errors)
    return ({"cluster_id": workspace["cluster_id"], "no_chain_reason": _clip(reason, TEXT_CHARS) if reason else None,
             "chains": [records[key] for key in sorted(records)]}, [note[:500] for note in dict.fromkeys(notes)])


def candidates(document: dict[str, Any], evidence_sha256: str) -> dict[str, Any]:
    """The invoker's strict candidates document: one candidate per chain, or one no-chain record."""
    rows = [{"candidate_id": chain["chain_id"], "subject_id": document["cluster_id"],
             "assertion": json.dumps(chain, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
             "evidence_sha256": evidence_sha256, "claim_class": "candidate_only"} for chain in document["chains"]]
    if not rows:
        rows = [{"candidate_id": "no-chain-" + digest(document)[:24], "subject_id": document["cluster_id"],
                 "assertion": json.dumps({"no_chain_reason": document["no_chain_reason"]}, sort_keys=True,
                                         separators=(",", ":"), ensure_ascii=False),
                 "evidence_sha256": evidence_sha256, "claim_class": "candidate_only"}]
    return {"candidates": rows}


def chain_claims(value: dict[str, Any], inputs: tuple, allowed: tuple, result_filename: str) -> list[dict[str, Any]]:
    """Invoker claim builder: one candidate_only claim per candidate, cited to the workspace bytes."""
    if "candidate_only" not in allowed:
        raise InvokerOutputError("attack-chain candidates exceed the invocation claim ceiling")
    workspace = next((item for item in inputs if item.root == WORKSPACE_ROOT_ID), inputs[0] if inputs else None)
    if workspace is None:
        raise InvokerOutputError("attack-chain cell has no workspace input")
    return [{"claim_id": row["candidate_id"], "claim_class": "candidate_only",
             "statement": _clip(f"attack-chain candidate {row['candidate_id']} for {row['subject_id']}", 300),
             "file": result_filename,
             "citations": [{"root": workspace.root, "path": workspace.path, "sha256": workspace.sha256,
                            "locator": row["subject_id"]}]} for row in value["candidates"]]
