"""Deterministic multi-step cross-unit / cross-boundary chain composition and elevation (T-173)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.guidance.skills import RuntimeSkill, load_runtime_skill
from appsec_review.review.identity import sha256_hex

from .contracts import (
    AttackChainCompositionSettings,
    BoundaryCrossing,
    ChainCompositionReport,
    ChainStepFinding,
    ComposedAttackChain,
    SEVERITY_RANK,
    max_severity,
)

EVIDENCE_QUERYING_SKILL_ID = "evidence-and-graph-querying"

_PIVOT_PREDICATES = frozenset({
    "ssrf", "info_disclosure", "information_disclosure", "sensitive_data_exposure",
    "authn_bypass", "authentication_bypass", "authz_bypass", "authorization_bypass",
    "broken_access_control", "missing_authentication", "missing_authorization",
    "insecure_configuration", "spec_drift", "csrf", "open_redirect", "path_traversal", "idor",
})

_CRITICAL_SINK_TOKENS = (
    "command_injection", "os_command_injection", "code_injection", "remote_code_execution",
    "sql_injection", "deserialization", "unsafe_deserialization", "memory_corruption",
    "buffer_overflow", "heap_overflow", "stack_overflow", "use_after_free",
    "arbitrary_file_write", "xxe",
)

_CRITICAL_SINK_CWES = frozenset({
    "CWE-77", "CWE-78", "CWE-89", "CWE-94", "CWE-119", "CWE-120",
    "CWE-121", "CWE-122", "CWE-416", "CWE-502", "CWE-611", "CWE-787",
})

_HIGH_IMPACT_SINK_TOKENS = _CRITICAL_SINK_TOKENS + (
    "privilege_escalation", "authz_bypass", "authorization_bypass",
    "authn_bypass", "authentication_bypass", "path_traversal", "arbitrary_file_read",
    "ssrf", "secret_exposure", "credential_exposure", "token_forgery", "account_takeover",
)

_HIGH_IMPACT_CWES = _CRITICAL_SINK_CWES | frozenset({
    "CWE-22", "CWE-269", "CWE-284", "CWE-285", "CWE-287", "CWE-306",
    "CWE-862", "CWE-863", "CWE-918",
})


def load_chain_querying_skill(repository_root: Path, *, job_id: str = "job_inference_security_review") -> RuntimeSkill:
    """Load the hash-pinned ``evidence-and-graph-querying`` runtime skill for chain workers."""
    return load_runtime_skill(repository_root, EVIDENCE_QUERYING_SKILL_ID, job_id=job_id)


def _norm(text: str | None) -> str:
    return (text or "").strip().lower().replace("-", "_").replace(" ", "_")


def _is_pivot(step: ChainStepFinding) -> bool:
    pred = _norm(step.security_predicate)
    if step.has_spec_drift or "drift" in pred or "spec" in pred:
        return True
    return pred in _PIVOT_PREDICATES or any(token in pred for token in (
        "ssrf", "bypass", "disclosure", "leak", "exposure", "redirect", "config", "idor", "traversal"
    ))


def _is_critical_sink(step: ChainStepFinding) -> bool:
    pred = _norm(step.security_predicate)
    if (step.weakness_cwe or "").upper() in _CRITICAL_SINK_CWES:
        return True
    return any(token in pred for token in _CRITICAL_SINK_TOKENS)


def _is_high_impact_sink(step: ChainStepFinding) -> bool:
    pred = _norm(step.security_predicate)
    if _is_critical_sink(step) or (step.weakness_cwe or "").upper() in _HIGH_IMPACT_CWES:
        return True
    return any(token in pred for token in _HIGH_IMPACT_SINK_TOKENS)


def _edge_crossings(
    edge_index: int,
    left: ChainStepFinding,
    right: ChainStepFinding,
    edge_meta: Mapping[str, Any] | None,
) -> list[BoundaryCrossing]:
    crossings: list[BoundaryCrossing] = []
    meta = edge_meta or {}
    satisfied_dims = set(meta.get("satisfied_dimensions", ()))

    left_tb = left.trust_boundary.strip()
    right_tb = right.trust_boundary.strip()
    if (left_tb and right_tb and left_tb != right_tb) or "trust_boundary" in satisfied_dims:
        crossings.append(BoundaryCrossing(
            edge_index=edge_index, from_claim_id=left.claim_id, to_claim_id=right.claim_id,
            crossing_kind="trust_boundary",
            from_scope=left_tb or left.unit_key or "external_entry",
            to_scope=right_tb or right.unit_key or "internal_sink",
        ))

    if left.has_spec_drift or "drift" in _norm(left.security_predicate):
        crossings.append(BoundaryCrossing(
            edge_index=edge_index, from_claim_id=left.claim_id, to_claim_id=right.claim_id,
            crossing_kind="spec_drift_pivot",
            from_scope=left.unit_key or left.security_predicate or "documented_contract",
            to_scope=right.unit_key or right.security_predicate or "handler_behavior",
        ))

    if "privilege" in satisfied_dims or (
        _is_pivot(left) and ("privilege" in _norm(right.security_predicate) or _is_high_impact_sink(right))
        and not crossings
    ):
        crossings.append(BoundaryCrossing(
            edge_index=edge_index, from_claim_id=left.claim_id, to_claim_id=right.claim_id,
            crossing_kind="privilege_boundary",
            from_scope=left.trust_boundary or left.unit_key or left.security_predicate or "caller_context",
            to_scope=right.trust_boundary or right.unit_key or right.security_predicate or "elevated_sink",
        ))

    if left.unit_key and right.unit_key and left.unit_key != right.unit_key:
        crossings.append(BoundaryCrossing(
            edge_index=edge_index, from_claim_id=left.claim_id, to_claim_id=right.claim_id,
            crossing_kind="cross_unit", from_scope=left.unit_key, to_scope=right.unit_key,
        ))
    return crossings


def evaluate_chain_elevation(
    steps: Sequence[ChainStepFinding],
    *,
    edge_metadata: Sequence[Mapping[str, Any]] = (),
    settings: AttackChainCompositionSettings | None = None,
) -> tuple[str | None, tuple[BoundaryCrossing, ...]]:
    """Compute ``(composed_severity, chain_boundary_crossings)`` for an ordered chain of steps."""
    cfg = settings or AttackChainCompositionSettings()
    if len(steps) < 2 or len(steps) > cfg.max_steps:
        return None, ()

    all_crossings: list[BoundaryCrossing] = []
    for idx, (left, right) in enumerate(zip(steps, steps[1:])):
        meta = edge_metadata[idx] if idx < len(edge_metadata) else None
        all_crossings.extend(_edge_crossings(idx, left, right, meta))

    deduped: list[BoundaryCrossing] = []
    seen_keys: set[tuple[int, str]] = set()
    for item in all_crossings:
        key = (item.edge_index, item.crossing_kind)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(item)

    baseline = max_severity(*(step.standalone_severity for step in steps)) or "medium"
    if baseline == "critical":
        return "critical", tuple(deduped[:16])

    crossing_kinds = {item.crossing_kind for item in deduped}
    has_boundary = bool(
        (cfg.admit_medium_cross_boundary and crossing_kinds & {"trust_boundary", "privilege_boundary", "spec_drift_pivot"})
        or (cfg.admit_medium_cross_unit and "cross_unit" in crossing_kinds)
    )
    medium_or_higher_count = sum(SEVERITY_RANK.get(step.standalone_severity, 0) >= SEVERITY_RANK["medium"] for step in steps)
    reaches_critical_sink = any(_is_critical_sink(step) for step in steps[1:])
    reaches_high_sink = any(_is_high_impact_sink(step) for step in steps[1:])
    starts_with_pivot = any(_is_pivot(step) for step in steps[:-1])

    composed = baseline
    if medium_or_higher_count >= 2 and has_boundary:
        if reaches_critical_sink and (starts_with_pivot or baseline == "high" or len(steps) >= 3):
            composed = "critical"
        elif len(steps) >= 3 and len(deduped) >= 2 and reaches_high_sink:
            composed = "critical"
        elif baseline == "high" and reaches_high_sink:
            composed = "critical"
        elif starts_with_pivot or reaches_high_sink or len(steps) >= 3:
            composed = max_severity(baseline, "high") or "high"

    return composed, tuple(deduped[:16])


def _pair_admitted(
    left: ChainStepFinding,
    right: ChainStepFinding,
    edge_meta: Mapping[str, Any] | None,
    settings: AttackChainCompositionSettings,
) -> bool:
    if left.claim_id == right.claim_id:
        return False
    if left.state not in {"confirmed", "supported"} or right.state not in {"confirmed", "supported"}:
        return False
    left_rank = SEVERITY_RANK.get(left.standalone_severity, 0)
    right_rank = SEVERITY_RANK.get(right.standalone_severity, 0)
    if left_rank >= SEVERITY_RANK["high"] or right_rank >= SEVERITY_RANK["high"]:
        return True
    if left_rank >= SEVERITY_RANK["medium"] and right_rank >= SEVERITY_RANK["medium"]:
        crossings = _edge_crossings(0, left, right, edge_meta)
        kinds = {item.crossing_kind for item in crossings}
        if settings.admit_medium_cross_boundary and kinds & {"trust_boundary", "privilege_boundary", "spec_drift_pivot"}:
            return True
        if settings.admit_medium_cross_unit and "cross_unit" in kinds:
            return True
    return False


def compose_multi_step_chains(
    findings: Iterable[ChainStepFinding],
    candidate_edges: Iterable[Mapping[str, Any]],
    *,
    settings: AttackChainCompositionSettings | None = None,
) -> ChainCompositionReport:
    """Compose cycle-free multi-step attack chains up to ``settings.max_steps`` (default 6)."""
    cfg = settings or AttackChainCompositionSettings()
    by_id = {item.claim_id: item for item in sorted(findings, key=lambda f: f.claim_id)}
    adjacency: dict[str, list[tuple[str, Mapping[str, Any]]]] = {claim_id: [] for claim_id in by_id}
    admitted_edges = 0
    for raw_edge in candidate_edges:
        left_id = str(raw_edge.get("from_claim_id", ""))
        right_id = str(raw_edge.get("to_claim_id", ""))
        if left_id not in by_id or right_id not in by_id:
            continue
        if not _pair_admitted(by_id[left_id], by_id[right_id], raw_edge, cfg):
            continue
        adjacency[left_id].append((right_id, raw_edge))
        admitted_edges += 1
    for claim_id in adjacency:
        adjacency[claim_id].sort(key=lambda item: item[0])

    raw_paths: list[tuple[tuple[str, ...], tuple[Mapping[str, Any], ...]]] = []
    expansions = 0

    def dfs(path: list[str], edges_so_far: list[Mapping[str, Any]]) -> None:
        nonlocal expansions
        if len(path) >= 2:
            raw_paths.append((tuple(path), tuple(edges_so_far)))
        if len(path) >= cfg.max_steps or expansions >= cfg.max_expansions:
            return
        for next_id, edge_meta in adjacency.get(path[-1], ()):
            if next_id in path:
                continue
            if expansions >= cfg.max_expansions:
                break
            expansions += 1
            path.append(next_id)
            edges_so_far.append(edge_meta)
            dfs(path, edges_so_far)
            edges_so_far.pop()
            path.pop()

    for start_id in sorted(by_id):
        if expansions >= cfg.max_expansions:
            break
        dfs([start_id], [])

    scored: list[ComposedAttackChain] = []
    for claim_ids, edge_metas in raw_paths:
        steps = [by_id[cid] for cid in claim_ids]
        composed, crossings = evaluate_chain_elevation(steps, edge_metadata=edge_metas, settings=cfg)
        if composed is None:
            continue
        standalone_max = max_severity(*(s.standalone_severity for s in steps)) or "medium"
        elevated = SEVERITY_RANK[composed] > SEVERITY_RANK[standalone_max]
        objective = f"{steps[0].security_predicate} -> {steps[-1].security_predicate} ({len(steps)} steps)"
        chain_id = f"chain-{sha256_hex({'kind': 'attack_chain', 'version': 1, 'steps': list(claim_ids), 'objective': objective})}"
        scored.append(ComposedAttackChain(
            chain_id=chain_id, step_claim_ids=claim_ids,
            standalone_severities=tuple(s.standalone_severity for s in steps),
            composed_severity=composed, chain_boundary_crossings=crossings, elevated=elevated,
            objective=objective[:1000], rationale=f"composed_severity={composed}; crossings={len(crossings)}",
        ))

    kept: list[ComposedAttackChain] = []
    for candidate in sorted(
        scored,
        key=lambda item: (-SEVERITY_RANK[item.composed_severity], -int(item.elevated), -len(item.step_claim_ids), item.step_claim_ids),
    ):
        seq = candidate.step_claim_ids
        subsumed = any(
            len(other.step_claim_ids) > len(seq)
            and SEVERITY_RANK[other.composed_severity] >= SEVERITY_RANK[candidate.composed_severity]
            and any(other.step_claim_ids[i:i + len(seq)] == seq for i in range(len(other.step_claim_ids) - len(seq) + 1))
            for other in kept
        )
        if not subsumed:
            kept.append(candidate)
        if len(kept) >= cfg.max_candidates_per_composition:
            break

    medium_elevated = sum(
        1 for item in kept
        if all(sev == "medium" for sev in item.standalone_severities) and item.composed_severity in {"high", "critical"}
    )
    telemetry = {
        "admitted_edges": admitted_edges, "expansions_used": expansions, "chains_composed": len(kept),
        "chains_elevated": sum(1 for item in kept if item.elevated),
        "medium_to_high_or_critical_chains": medium_elevated,
        "max_chain_length_observed": max((len(item.step_claim_ids) for item in kept), default=0),
        "boundary_crossings_total": sum(len(item.chain_boundary_crossings) for item in kept),
    }
    return ChainCompositionReport(chains=tuple(kept), telemetry=telemetry)
