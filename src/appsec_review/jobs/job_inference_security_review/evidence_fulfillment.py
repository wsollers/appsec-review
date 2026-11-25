"""Deterministic Round 2 evidence-request fulfillment, skill bundle attachment, and thinking budgets (T-173)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from appsec_review.guidance.compose import bundle_sha256, section_sha256, verify_bundle
from appsec_review.guidance.fragments import GuidanceError
from appsec_review.guidance.skills import REVIEW_QUERY_SKILL as EVIDENCE_QUERYING_SKILL_ID, load_runtime_skill
from appsec_review.retrieval.core import retrieval_caller
from appsec_review.review.fact_summary import summarize_fact
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError, Role

DEFAULT_MAX_EVIDENCE_REQUESTS = 4
MAX_CITATIONS_PER_REQUEST = 3

DEFAULT_QUERYING_SKILL_ROLES = frozenset({
    Role.HYPOTHESIS_HUNTER,
    Role.RED_TEAM_ANALYST,
    Role.BLUE_TEAM_REFUTER,
    Role.INDEPENDENT_VERIFIER,
    Role.ADJUDICATION_JUDGE,
    Role.ATTACK_CHAIN_ANALYST,
})

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_./:-]{2,120}")
_LINE_RE = re.compile(r"([A-Za-z0-9_./-]+\.[A-Za-z0-9_+]+):(\d+)")
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "into", "that", "this", "check", "verify",
    "confirm", "whether", "need", "needs", "line", "lines", "file", "function", "method",
    "guard", "guards", "slice", "slices", "path", "paths", "caller", "callers", "callee",
    "callees", "source", "sink", "taint", "claim", "predicate", "evidence", "request",
})


def attach_querying_skill_to_bundle(
    repository_root: Path,
    bundle: dict[str, Any],
    *,
    role: Role,
    task: str,
    job_id: str = "job_inference_security_review",
    force: bool = False,
) -> dict[str, Any]:
    """Append querying guidance once, preserving the role/persona/binary selection, and reseal."""
    eligible = force or role in DEFAULT_QUERYING_SKILL_ROLES or (
        role is Role.BLUE_TEAM_REFUTER and task == "chain_refuter"
    )
    if not eligible:
        return bundle
    procedures = next((sec for sec in bundle["sections"] if sec["name"] == "procedures"), None)
    if procedures is None:
        raise GuidanceError("selected evidence querying skill requires a procedures section")
    items = list(procedures.get("items", ()))
    if any(item.get("id") == EVIDENCE_QUERYING_SKILL_ID for item in items):
        return bundle
    skill = load_runtime_skill(repository_root, EVIDENCE_QUERYING_SKILL_ID, job_id=job_id,
                               fallback_to_package=False)
    items.append({"id": skill.name, "path": skill.path, "text": skill.text, "source_sha256": skill.sha256})
    procedures["items"] = items
    procedures["sha256"] = section_sha256(procedures)
    bundle["section_sha256"]["procedures"] = procedures["sha256"]
    bundle["sha256"] = bundle_sha256(bundle)
    verify_bundle(bundle)
    return bundle


@dataclass(frozen=True)
class EvidenceFulfillmentOutcome:
    """Resolved Round 2 evidence records, referenced package entities, and telemetry counters."""

    fulfilled_items: tuple[dict[str, Any], ...]
    extra_entities: tuple[str, ...]
    fulfilled_count: int
    unfulfilled_count: int


def _extract_query_terms(need: str) -> tuple[list[tuple[str, int]], list[str]]:
    line_refs = [(m.group(1), int(m.group(2))) for m in _LINE_RE.finditer(need)]
    tokens: list[str] = []
    for raw in _TOKEN_RE.findall(need):
        cleaned = raw.strip(".:/-")
        low = cleaned.lower()
        if len(cleaned) >= 3 and low not in _STOPWORDS and cleaned not in tokens:
            tokens.append(cleaned)
    return line_refs, tokens[:8]


def _citation_from_record(record: Mapping[str, Any], response: Mapping[str, Any]) -> dict[str, Any]:
    payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
    loc = record.get("location") if isinstance(record.get("location"), Mapping) else None
    shards = [item for item in response["indexes"]
              if (item["name"], item["shard_id"]) == (record["index"], record["shard_id"])]
    if len(shards) != 1:
        raise IntegrityError("follow-up evidence is not bound to one accepted shard")
    citation: dict[str, Any] = {
        "entity_id": str(record["identity"]),
        "kind": str(record.get("kind", "")),
        "name": str(record.get("name", ""))[:200],
        "index": str(record.get("index", "")),
        "shard_id": str(record.get("shard_id", "")),
        "shard_sha256": shards[0]["sha256"],
        "content_sha256": sha256_hex(record),
        "index_manifest_sha256": response["index_manifest"]["sha256"],
        "coverage_gaps": list(response["coverage_gaps"]),
        "truncated": response["truncated"],
        "summary": summarize_fact(str(record.get("kind", "")), payload, line=loc.get("start_line") if isinstance(loc, Mapping) and isinstance(loc.get("start_line"), int) else None)[:400],
    }
    if loc:
        citation["location"] = dict(loc)
    for key in ("guard_polarity", "resolution_tier", "verdict", "control_id"):
        if key in payload and payload[key] is not None:
            citation[key] = str(payload[key])[:120]
    return citation


def _matches_record(
    record: Mapping[str, Any],
    *,
    line_refs: Sequence[tuple[str, int]],
    tokens: Sequence[str],
) -> int:
    score = 0
    name = str(record.get("name", ""))
    kind = str(record.get("kind", ""))
    loc = record.get("location") if isinstance(record.get("location"), Mapping) else {}
    path = str(loc.get("path", ""))
    start = loc.get("start_line")
    end = loc.get("end_line") or start
    payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
    haystack = f"{name} {kind} {path} {payload.get('guard_polarity', '')} {payload.get('symbol', '')}".lower()

    for ref_path, ref_line in line_refs:
        if path and (path.endswith(ref_path) or ref_path.endswith(Path(path).name)):
            score += 3
            if isinstance(start, int) and isinstance(end, int) and start <= ref_line <= end:
                score += 5
    for token in tokens:
        t_low = token.lower()
        if t_low == name.lower():
            score += 5
        elif t_low in haystack:
            score += 2
    return score


def fulfill_evidence_requests(
    core: Any,
    package_entities: Sequence[str],
    pending_requests: Sequence[Mapping[str, Any]],
    *,
    unfulfilled_prior: int = 0,
    max_requests: int = DEFAULT_MAX_EVIDENCE_REQUESTS,
) -> EvidenceFulfillmentOutcome:
    """Deliver canonical pending-obligation evidence within package scope, not semantic satisfaction."""
    if max_requests < 0:
        raise ValueError("max_requests must be non-negative")
    allowed = frozenset(package_entities)
    admitted = list(pending_requests[:max_requests])
    overflow = max(0, len(pending_requests) - len(admitted))

    records_by_id: dict[str, Mapping[str, Any]] = {}
    responses_by_id: dict[str, Mapping[str, Any]] = {}
    if admitted and allowed:
        # Each identity keeps its own shard binding, truncation and gaps. No combined
        # envelope may be attributed to a citation from a different lookup.
        identities = sorted(allowed)
        with retrieval_caller(job_id="job_inference_security_review", caller_kind="evidence_fulfillment"):
            responses = core.resolve_identities(identities)
        for eid in identities:
            response = responses[eid]
            if response.get("status") != "ok":
                continue
            found = response["results"]
            if found:
                if found[0]["identity"] != eid:
                    raise IntegrityError("follow-up retrieval returned a different entity")
                records_by_id[eid] = found[0]
                responses_by_id[eid] = response

    fulfilled_items: list[dict[str, Any]] = []
    extra_entities: set[str] = set()
    fulfilled_count = 0
    unfulfilled_count = unfulfilled_prior + overflow

    for req in admitted:
        obligation_id = str(req["obligation_id"])
        question = str(req["question"])
        anchors = [str(a) for a in req.get("anchors", ()) if str(a) in allowed]
        line_refs, tokens = _extract_query_terms(question)

        citations: list[dict[str, Any]] = []
        seen_eids: set[str] = set()

        for anchor_id in anchors:
            rec = records_by_id.get(anchor_id)
            if rec is not None and anchor_id not in seen_eids:
                seen_eids.add(anchor_id)
                extra_entities.add(anchor_id)
                citations.append(_citation_from_record(rec, responses_by_id[anchor_id]))
                if len(citations) >= MAX_CITATIONS_PER_REQUEST:
                    break

        if len(citations) < MAX_CITATIONS_PER_REQUEST and (line_refs or tokens):
            scored: list[tuple[int, str, Mapping[str, Any]]] = []
            for eid, rec in records_by_id.items():
                if eid in seen_eids:
                    continue
                match_score = _matches_record(rec, line_refs=line_refs, tokens=tokens)
                if match_score > 0:
                    scored.append((match_score, eid, rec))
            scored.sort(key=lambda item: (-item[0], item[1]))
            for _score, eid, rec in scored[: MAX_CITATIONS_PER_REQUEST - len(citations)]:
                seen_eids.add(eid)
                extra_entities.add(eid)
                citations.append(_citation_from_record(rec, responses_by_id[eid]))

        if citations:
            fulfilled_count += 1
            fulfilled_items.append({
                "obligation_id": obligation_id,
                "claim_id": str(req.get("claim_id", "")),
                "predicate": str(req.get("predicate", "")),
                "requested_kind": req["requested_kind"],
                "question": question[:500],
                "resolved_citations": citations,
            })
        else:
            unfulfilled_count += 1

    return EvidenceFulfillmentOutcome(
        fulfilled_items=tuple(fulfilled_items),
        extra_entities=tuple(sorted(extra_entities)),
        fulfilled_count=fulfilled_count,
        unfulfilled_count=unfulfilled_count,
    )
