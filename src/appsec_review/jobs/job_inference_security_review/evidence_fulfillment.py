"""Deterministic Round 2 evidence-request fulfillment, skill bundle attachment, and thinking budgets (T-173)."""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from appsec_review.config.inference_review import ModelProfileSettings
from appsec_review.guidance.compose import bundle_sha256, section_sha256, verify_bundle
from appsec_review.guidance.fragments import GuidanceError
from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.review.budget import JobBudget
from appsec_review.review.fact_summary import summarize_fact
from appsec_review.review.models import Role

EVIDENCE_QUERYING_SKILL_ID = "evidence-and-graph-querying"
DEFAULT_MAX_EVIDENCE_REQUESTS = 4
MAX_CITATIONS_PER_REQUEST = 3
THINKING_MIN_OUTPUT_TOKENS = 4096
THINKING_REASONING_LEVELS = frozenset({"medium", "high", "xhigh", "max"})

DEFAULT_QUERYING_SKILL_ROLES = frozenset({
    Role.RED_TEAM_ANALYST,
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


def effective_max_output_tokens(
    profile: ModelProfileSettings,
    *,
    budget: JobBudget | None = None,
    floor: int = THINKING_MIN_OUTPUT_TOKENS,
) -> int:
    """Enforce a safe minimum output-token floor when model thinking/reasoning is active."""
    if profile.reasoning not in THINKING_REASONING_LEVELS:
        return profile.max_output_tokens
    effective_floor = floor
    if budget is not None:
        effective_floor = min(effective_floor, budget.limits.max_output_tokens)
    return max(profile.max_output_tokens, effective_floor)


def ensure_thinking_profile_floor(
    profile: ModelProfileSettings,
    *,
    budget: JobBudget | None = None,
    floor: int = THINKING_MIN_OUTPUT_TOKENS,
) -> ModelProfileSettings:
    """Return ``profile`` with ``max_output_tokens`` raised to at least the thinking floor."""
    target = effective_max_output_tokens(profile, budget=budget, floor=floor)
    if target == profile.max_output_tokens:
        return profile
    return replace(profile, max_output_tokens=target)


def attach_querying_skill_to_bundle(
    repository_root: Path,
    bundle: dict[str, Any],
    *,
    role: Role,
    task: str,
    job_id: str = "job_inference_security_review",
    force: bool = False,
) -> dict[str, Any]:
    """Deterministically attach ``evidence-and-graph-querying`` to eligible review bundles and reseal."""
    eligible = force or role in DEFAULT_QUERYING_SKILL_ROLES or (
        role is Role.BLUE_TEAM_REFUTER and task == "chain_refuter"
    )
    if not eligible:
        return bundle
    procedures = next((sec for sec in bundle["sections"] if sec["name"] == "procedures"), None)
    if procedures is None:
        return bundle
    items = list(procedures.get("items", ()))
    if any(item.get("id") == EVIDENCE_QUERYING_SKILL_ID for item in items) or len(items) >= 2:
        return bundle
    try:
        skill = load_runtime_skill(repository_root, EVIDENCE_QUERYING_SKILL_ID, job_id=job_id)
    except GuidanceError:
        if force:
            raise
        return bundle
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


def _citation_from_record(record: Mapping[str, Any]) -> dict[str, Any]:
    payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
    loc = record.get("source_location") if isinstance(record.get("source_location"), Mapping) else None
    citation: dict[str, Any] = {
        "entity_id": str(record["entity_id"]),
        "kind": str(record.get("kind", "")),
        "name": str(record.get("name", ""))[:200],
        "index": str(record.get("index", "")),
        "shard_id": str(record.get("shard_id", "")),
        "shard_sha256": str(record.get("shard_sha256", "")),
        "content_sha256": str(record.get("content_sha256", "")),
        "summary": summarize_fact(str(record.get("kind", "")), payload, line=loc.get("start_line") if isinstance(loc, Mapping) and isinstance(loc.get("start_line"), int) else None)[:400],
    }
    if loc:
        citation["location"] = {
            "path": str(loc.get("path", ""))[:500],
            "start_line": loc.get("start_line"),
            "end_line": loc.get("end_line"),
        }
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
    loc = record.get("source_location") if isinstance(record.get("source_location"), Mapping) else {}
    path = str(loc.get("path", ""))
    start = loc.get("start_line")
    end = loc.get("end_line") or start
    payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
    haystack = f"{name} {kind} {path} {payload.get('guard_polarity', '')} {payload.get('symbol', '')}".lower()

    for ref_path, ref_line in line_refs:
        if path.endswith(ref_path) or ref_path.endswith(path and Path(path).name or ref_path):
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
    """Deterministically resolve bounded Round 1 ``requests_evidence`` against ``core`` within package scope."""
    allowed = frozenset(package_entities)
    admitted = list(pending_requests[:max_requests])
    overflow = max(0, len(pending_requests) - len(admitted))

    records_by_id: dict[str, Mapping[str, Any]] = {}
    if admitted and allowed and hasattr(core, "find"):
        for eid in sorted(allowed):
            found = core.find(identity=eid, limit=1).get("results", ())
            if found:
                records_by_id[eid] = found[0]

    fulfilled_items: list[dict[str, Any]] = []
    extra_entities: set[str] = set()
    fulfilled_count = 0
    unfulfilled_count = unfulfilled_prior + overflow

    for req in admitted:
        request_id = str(req.get("request_id", ""))
        need = str(req.get("need", ""))
        anchors = [str(a) for a in req.get("anchors", ()) if str(a) in allowed]
        line_refs, tokens = _extract_query_terms(need)

        citations: list[dict[str, Any]] = []
        seen_eids: set[str] = set()

        for anchor_id in anchors:
            rec = records_by_id.get(anchor_id)
            if rec is not None and anchor_id not in seen_eids:
                seen_eids.add(anchor_id)
                extra_entities.add(anchor_id)
                citations.append(_citation_from_record(rec))
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
                citations.append(_citation_from_record(rec))

        if citations:
            fulfilled_count += 1
            fulfilled_items.append({
                "request_id": request_id,
                "claim_id": str(req.get("claim_id", "")),
                "predicate": str(req.get("predicate", "")),
                "need": need[:500],
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
