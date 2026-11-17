"""Preserve chain-elevated composed severity alongside standalone severity (T-173)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from appsec_review.guidance.skills import RuntimeSkill, load_runtime_skill
from appsec_review.jobs.job_attack_chain_composition.contracts import SEVERITY_RANK, max_severity

from .contracts import AdjudicatedFindingSeverity, FindingAdjudicationSettings

EVIDENCE_QUERYING_SKILL_ID = "evidence-and-graph-querying"
_ACTIVE_CHAIN_STATUSES = frozenset({"confirmed", "qualified_supported"})


def load_adjudication_querying_skill(
    repository_root: Path,
    *,
    job_id: str = "job_finding_adjudication",
) -> RuntimeSkill:
    """Load the hash-pinned ``evidence-and-graph-querying`` runtime skill for adjudication workers."""
    return load_runtime_skill(repository_root, EVIDENCE_QUERYING_SKILL_ID, job_id=job_id)


def resolve_finding_chain_severity(
    claim_id: str,
    *,
    standalone_severity: str | None,
    chain_records: Iterable[Mapping[str, Any]],
    settings: FindingAdjudicationSettings | None = None,
) -> AdjudicatedFindingSeverity:
    """Resolve chain-elevated severity for ``claim_id`` without overwriting standalone severity."""
    cfg = settings or FindingAdjudicationSettings()
    chain_ids: list[str] = []
    composed_candidates: list[str] = []
    crossings: list[dict[str, Any]] = []
    seen_crossings: set[tuple[Any, ...]] = set()

    for record in chain_records:
        status = str(record.get("status", "confirmed"))
        if status not in _ACTIVE_CHAIN_STATUSES:
            continue
        members = record.get("component_claim_ids") or record.get("step_claim_ids") or ()
        if claim_id not in members:
            continue
        cid = str(record.get("chain_id", ""))
        if cid:
            chain_ids.append(cid)
        c_sev = record.get("composed_severity")
        if isinstance(c_sev, str) and c_sev in SEVERITY_RANK:
            composed_candidates.append(c_sev)
        for crossing in record.get("chain_boundary_crossings") or ():
            if not isinstance(crossing, Mapping):
                continue
            key = (
                crossing.get("edge_index"), crossing.get("from_claim_id"), crossing.get("to_claim_id"),
                crossing.get("crossing_kind"), crossing.get("from_scope"), crossing.get("to_scope"),
            )
            if key not in seen_crossings and len(crossings) < 32:
                seen_crossings.add(key)
                crossings.append(dict(crossing))

    composed = max_severity(*composed_candidates) if cfg.preserve_chain_elevated_severity else None
    if composed is not None and standalone_severity in SEVERITY_RANK:
        composed = max_severity(standalone_severity, composed)
    effective = max_severity(standalone_severity, composed)
    elevated = bool(
        composed in SEVERITY_RANK
        and (standalone_severity not in SEVERITY_RANK or SEVERITY_RANK[composed] > SEVERITY_RANK[standalone_severity])
    )
    return AdjudicatedFindingSeverity(
        claim_id=claim_id, standalone_severity=standalone_severity, composed_severity=composed,
        effective_severity=effective, chain_elevated=elevated,
        attack_chain_ids=tuple(sorted(set(chain_ids))), chain_boundary_crossings=tuple(crossings),
    )
