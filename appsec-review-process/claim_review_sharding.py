#!/usr/bin/env python3
"""Deterministic claim sharding and reviewer-persona assignment for the 07/08/09/12 pools (ADR-0021).

Pure Python bookkeeping, no model call: given the stage's accepted claim population it decides
which reviewer instance reviews which claims (shard only: every claim is reviewed exactly once per
stage) and which registry persona each instance runs as.

Sharding
    1. Claims linked by ``causal_claim_ids`` or ``supersedes_claim_id`` are one atomic unit (the
       stage rules check those links inside one reviewed population, so they may not be split).
    2. Units are grouped by locus: the first cited source file (``locator_json.path``), else the
       sorted component ids, else the claim id; claims about the same file/component stay together.
    3. A locus group larger than the balanced share (total size / instances) is split, in claim-id
       order, into chunks no larger than that share (an atomic unit is never split).
    4. Chunks are assigned largest-first to the currently lightest shard (ties: lower index); size is
       the canonical JSON byte length of the claim record, a stable estimate of its prompt cost.
    5. Shards are renumbered by their smallest claim id so the plan does not depend on dict order.

Persona assignment
    Each stage has an ordered registry list of reviewer personas (``stage_personas`` in the
    ``claim-review-pool-cell`` job template). A shard's persona is the unused persona whose record
    text best matches the shard's claim text (token overlap weighted by frequency); ties go to the
    stage list rotated by shard index, so equal scores still spread across the list. Personas are
    distinct within a stage until the list is exhausted, then the rotation starts again.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from typing import Any, Iterable, Mapping

_STOP = frozenset("""
about above after again against also among and any are aren because been before being below
between both but can cannot claim claims could did does doing down during each every few for from
further had has have having here how into its itself just more most must no nor not now off once
only other our out over own same should some such than that the their them then there these they
this those through too under until upon very was were what when where which while who whom why
will with within without would you your candidate condition verification required review reviewer
evidence upstream accepted status stage
""".split())


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def claim_size(record: Mapping[str, Any]) -> int:
    return len(_canonical(record))


def _locus(record: Mapping[str, Any]) -> str:
    for citation in record.get("citations") or []:
        try:
            locator = json.loads(citation.get("locator_json") or "null")
        except (TypeError, ValueError):
            locator = None
        if isinstance(locator, dict) and isinstance(locator.get("path"), str) and locator["path"]:
            return "file:" + locator["path"]
    components = sorted(str(item) for item in record.get("component_ids") or [])
    if components:
        return "component:" + ",".join(components)
    return "claim:" + str(record["claim_id"])


def _atomic_units(records: list[Mapping[str, Any]]) -> list[list[str]]:
    ids = sorted(record["claim_id"] for record in records)
    parent = {claim_id: claim_id for claim_id in ids}

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left: str, right: str) -> None:
        a, b = find(left), find(right)
        if a != b:
            parent[max(a, b)] = min(a, b)

    for record in records:
        links = list(record.get("causal_claim_ids") or [])
        if record.get("supersedes_claim_id"):
            links.append(record["supersedes_claim_id"])
        for other in links:
            if other in parent:
                union(record["claim_id"], other)
    units: dict[str, list[str]] = {}
    for claim_id in ids:
        units.setdefault(find(claim_id), []).append(claim_id)
    return sorted(units.values(), key=lambda unit: unit[0])


def plan_shards(records: Iterable[Mapping[str, Any]], instances: int) -> list[list[str]]:
    """Claim ids per shard: deterministic, balanced by size, linked claims and loci kept together."""
    records = list(records)
    if not records:
        return []
    if instances < 1:
        raise ValueError("claim review sharding: at least one reviewer instance is required")
    by_id = {record["claim_id"]: record for record in records}
    if len(by_id) != len(records):
        raise ValueError("claim review sharding: duplicate claim ids")
    size = {claim_id: claim_size(record) for claim_id, record in by_id.items()}
    total = sum(size.values())
    share = max(1, math.ceil(total / instances))
    groups: dict[str, list[list[str]]] = {}
    for unit in _atomic_units(records):
        locus = min(_locus(by_id[claim_id]) for claim_id in unit)
        groups.setdefault(locus, []).append(unit)
    chunks: list[list[str]] = []
    for locus in sorted(groups):
        current: list[str] = []
        weight = 0
        for unit in sorted(groups[locus], key=lambda item: item[0]):
            unit_size = sum(size[claim_id] for claim_id in unit)
            if current and weight + unit_size > share:
                chunks.append(current)
                current, weight = [], 0
            current = current + unit
            weight += unit_size
        if current:
            chunks.append(current)
    weights = [sum(size[claim_id] for claim_id in chunk) for chunk in chunks]
    order = sorted(range(len(chunks)), key=lambda index: (-weights[index], min(chunks[index])))
    count = min(instances, len(chunks))
    shards: list[list[str]] = [[] for _ in range(count)]
    loads = [0] * count
    for index in order:
        target = min(range(count), key=lambda slot: (loads[slot], slot))
        shards[target].extend(chunks[index])
        loads[target] += weights[index]
    return sorted((sorted(shard) for shard in shards if shard), key=lambda shard: shard[0])


def shard_units(records: Iterable[Mapping[str, Any]], shard: Iterable[str]) -> int:
    """Estimated model input units (tokens) of one shard's claim records: bytes / 4, rounded up."""
    wanted = set(shard)
    return math.ceil(sum(claim_size(record) for record in records if record["claim_id"] in wanted) / 4)


def plan_within_limit(records: list[Mapping[str, Any]], instances: int, *, units_max: int,
                      instances_max: int) -> list[list[str]]:
    """``plan_shards`` with the smallest instance count >= ``instances`` whose every shard fits
    ``units_max``; raises ValueError when even ``instances_max`` instances cannot fit."""
    count = max(1, instances)
    while True:
        shards = plan_shards(records, count)
        if all(shard_units(records, shard) <= units_max for shard in shards):
            return shards
        if count >= instances_max or len(shards) < count:
            raise ValueError("claim review sharding: a shard exceeds the per-instance input limit "
                             f"({units_max} units) even with {count} reviewer instances")
        count += 1


def _tokens(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [token for item in value.values() for token in _tokens(item)]
    if isinstance(value, (list, tuple)):
        return [token for item in value for token in _tokens(item)]
    if not isinstance(value, str):
        return []
    words = re.split(r"[^a-z0-9]+", value.lower())
    return [word[:-1] if word.endswith("s") and len(word) > 4 else word
            for word in words if len(word) >= 3 and word not in _STOP]


def claim_terms(record: Mapping[str, Any]) -> Counter:
    """Words a reviewer persona can match: the claim's own text, route, components and cited files."""
    fields = [record.get(name) for name in ("hypothesis", "route_id", "component_ids", "attacker_case",
                                            "refutation_rationale", "verification_method")]
    for citation in record.get("citations") or []:
        fields += [citation.get("producer_job_id"), citation.get("locator_json"), citation.get("observed_fact")]
    return Counter(_tokens(fields))


def persona_terms(persona: Mapping[str, Any]) -> frozenset:
    """Words from the persona record's own stance: name, failure mode, assumptions, inputs, outputs."""
    return frozenset(_tokens([persona.get(name) for name in (
        "display_name", "primary_failure_mode_caught", "assumptions", "required_inputs", "outputs")]))


def assign_personas(stage: str, shards: list[list[str]], records: Iterable[Mapping[str, Any]],
                    candidates: list[str], personas: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """One persona per shard, deterministic: best term match, distinct until the list is exhausted."""
    if not candidates:
        raise ValueError(f"claim review sharding: stage {stage} has no reviewer personas")
    by_id = {record["claim_id"]: record for record in records}
    terms = {persona_id: persona_terms(personas[persona_id]) for persona_id in candidates}
    offset = int(hashlib.sha256(stage.encode("utf-8")).hexdigest()[:8], 16) % len(candidates)
    used: set[str] = set()
    result = []
    for index, shard in enumerate(shards):
        words = Counter()
        for claim_id in shard:
            words.update(claim_terms(by_id[claim_id]))
        if len(used) == len(candidates):
            used = set()
        rotated = candidates[(offset + index) % len(candidates):] + candidates[:(offset + index) % len(candidates)]
        scored = [(-sum(count for word, count in words.items() if word in terms[persona_id]),
                   rotated.index(persona_id), persona_id)
                  for persona_id in candidates if persona_id not in used]
        score, _position, chosen = min(scored)
        used.add(chosen)
        result.append({"shard_index": index, "persona_id": chosen, "match_score": -score,
                       "claim_ids": list(shard)})
    return result


def shard_document(stage_array: str, upstream: Mapping[str, Any], claim_ids: Iterable[str]) -> dict[str, Any]:
    """The accepted upstream document restricted to one shard's claims (every other field kept)."""
    wanted = set(claim_ids)
    return {**upstream, stage_array: [record for record in upstream[stage_array]
                                      if record["claim_id"] in wanted]}


def shard_bytes(document: Mapping[str, Any]) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode("utf-8")
