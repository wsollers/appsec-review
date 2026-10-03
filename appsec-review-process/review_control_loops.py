#!/usr/bin/env python3
"""Deterministic review feedback, quorum, rescope, retest, and completion controls.

This module is deliberately side-effect free.  It is the policy core used by lifecycle workers;
it never runs a tool, applies a patch, declares a vulnerability fixed without a same-environment
retest, or publishes a final report without an exact human signoff.
"""
from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
import re
from typing import Any, Iterable

from execution_state import Blocked, digest

SHA = "sha256:"
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _sha(value: Any) -> str:
    return SHA + digest(value)


def _unique(rows: Iterable[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        identity = row.get(key) if isinstance(row, dict) else None
        if not isinstance(identity, str) or not identity or identity in result:
            raise Blocked(f"review controls: duplicate or invalid {label}")
        result[identity] = deepcopy(row)
    return result


def deterministic_merge(run_id: str, expected_workers: list[dict[str, str]],
                        worker_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge every expected worker result without allowing omission to look like consensus."""
    expected = _unique(expected_workers, "worker_id", "expected worker")
    results = _unique(worker_results, "worker_id", "worker result")
    if set(results) - set(expected):
        raise Blocked("review controls: result from an unexpected worker")
    missing = sorted(set(expected) - set(results))
    candidates: dict[str, dict[str, Any]] = {}
    conflicts: dict[str, set[str]] = defaultdict(set)
    for worker_id in sorted(results):
        result = results[worker_id]
        if expected[worker_id].get("run_id") != run_id or result.get("run_id") != run_id:
            raise Blocked("review controls: worker is not bound to this run")
        if result.get("producer_id") != expected[worker_id].get("producer_id"):
            raise Blocked("review controls: worker producer identity changed")
        if result.get("status") not in {"OK", "OK_WITH_GAPS", "FAILED", "BLOCKED", "CANCELED"}:
            raise Blocked("review controls: worker status is not closed")
        rows = result.get("candidates")
        if not isinstance(rows, list):
            raise Blocked("review controls: worker candidates are not a list")
        if result["status"] not in {"OK", "OK_WITH_GAPS"} and rows:
            raise Blocked("review controls: unsuccessful worker emitted candidates")
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                    "candidate_id", "subject_id", "assertion", "evidence_sha256", "claim_class"}:
                raise Blocked("review controls: candidate shape is invalid")
            if row["claim_class"] not in {"candidate_only", "refutation", "verification_observation"}:
                raise Blocked("review controls: candidate claim class is unauthorized")
            candidate_id = row["candidate_id"]
            semantic = _sha({key: row[key] for key in ("subject_id", "assertion", "claim_class")})
            prior = candidates.get(candidate_id)
            normalized = {**row, "semantic_sha256": semantic, "worker_ids": [worker_id],
                          "producer_ids": [result["producer_id"]]}
            if prior is None:
                candidates[candidate_id] = normalized
            elif any(prior[key] != normalized[key] for key in
                     ("subject_id", "assertion", "claim_class", "semantic_sha256")):
                conflicts[candidate_id].update((*prior["worker_ids"], worker_id))
            else:
                if prior["evidence_sha256"] != row["evidence_sha256"]:
                    # Different evidence is retained as diversity, never silently collapsed.
                    conflicts[candidate_id].update((*prior["worker_ids"], worker_id))
                prior["worker_ids"] = sorted(set(prior["worker_ids"] + [worker_id]))
                prior["producer_ids"] = sorted(set(prior["producer_ids"] + [result["producer_id"]]))
    conflict_rows = [{"candidate_id": key, "worker_ids": sorted(value)}
                     for key, value in sorted(conflicts.items())]
    merged = [candidates[key] for key in sorted(candidates) if key not in conflicts]
    value = {"schema": "appsec-review/deterministic-pool-merge/1.0", "run_id": run_id,
             "expected_worker_ids": sorted(expected), "observed_worker_ids": sorted(results),
             "missing_worker_ids": missing, "candidates": merged, "conflicts": conflict_rows}
    value["merge_sha256"] = _sha(value)
    return value


def evidence_qualified_quorum(run_id: str, merge: dict[str, Any], *, minimum_producers: int,
                              require_complete_pool: bool = True) -> dict[str, Any]:
    """Admit candidates only when independent producer diversity meets the explicit threshold."""
    if type(minimum_producers) is not int or minimum_producers < 1:
        raise Blocked("review controls: quorum minimum must be positive")
    expected_hash = merge.get("merge_sha256")
    if merge.get("run_id") != run_id:
        raise Blocked("review controls: merge is not bound to this run")
    if expected_hash != _sha({key: value for key, value in merge.items() if key != "merge_sha256"}):
        raise Blocked("review controls: merge hash is invalid")
    if require_complete_pool and merge.get("missing_worker_ids"):
        raise Blocked("review controls: complete-pool quorum has missing workers")
    decisions = []
    for row in merge.get("candidates", []):
        producers = sorted(set(row.get("producer_ids", [])))
        decision = "ADMITTED" if len(producers) >= minimum_producers else "INSUFFICIENT_DIVERSITY"
        decisions.append({"candidate_id": row["candidate_id"], "decision": decision,
                          "producer_ids": producers, "required_producers": minimum_producers,
                          "evidence_sha256": row["evidence_sha256"]})
    for conflict in merge.get("conflicts", []):
        decisions.append({"candidate_id": conflict["candidate_id"], "decision": "CONFLICTING_EVIDENCE",
                          "producer_ids": [], "required_producers": minimum_producers,
                          "evidence_sha256": None})
    return {"schema": "appsec-review/evidence-qualified-quorum/1.0", "run_id": run_id,
            "merge_sha256": expected_hash, "complete_pool_required": require_complete_pool,
            "decisions": sorted(decisions, key=lambda item: item["candidate_id"])}


def dependency_index(run_id: str, nodes: list[str], edges: list[dict[str, str]]) -> dict[str, Any]:
    """Create an acyclic upstream->downstream index used for affected-only rescope."""
    if len(nodes) != len(set(nodes)) or any(not isinstance(node, str) or not node for node in nodes):
        raise Blocked("review controls: dependency nodes are invalid")
    downstream: dict[str, set[str]] = {node: set() for node in nodes}
    indegree = {node: 0 for node in nodes}
    seen = set()
    for edge in edges:
        pair = (edge.get("upstream"), edge.get("downstream")) if isinstance(edge, dict) else (None, None)
        if pair in seen or pair[0] not in downstream or pair[1] not in downstream or pair[0] == pair[1]:
            raise Blocked("review controls: dependency edge is invalid")
        seen.add(pair); downstream[pair[0]].add(pair[1]); indegree[pair[1]] += 1
    queue = deque(sorted(node for node, degree in indegree.items() if degree == 0)); ordered = []
    while queue:
        node = queue.popleft(); ordered.append(node)
        for child in sorted(downstream[node]):
            indegree[child] -= 1
            if indegree[child] == 0: queue.append(child)
    if len(ordered) != len(nodes):
        raise Blocked("review controls: dependency graph contains a cycle")
    return {"schema": "appsec-review/classification-dependency-index/1.0", "run_id": run_id,
            "nodes": sorted(nodes), "edges": [{"upstream": a, "downstream": b} for a, b in sorted(seen)],
            "topological_order": ordered, "index_sha256": _sha({"nodes": sorted(nodes), "edges": sorted(seen)})}


def bounded_rescope(run_id: str, index: dict[str, Any], changed_nodes: list[str], *, iteration: int,
                    max_iterations: int, previous_plan: dict[str, Any] | None = None,
                    baseline: bool = False) -> dict[str, Any]:
    """Affected-only rescope; ``baseline`` marks the first generation, where nothing was accepted to rescope."""
    if type(iteration) is not int or type(max_iterations) is not int or not 1 <= iteration <= max_iterations:
        raise Blocked("review controls: rescope iteration is outside its bound")
    nodes = set(index.get("nodes", [])); changed = set(changed_nodes)
    if not changed or not changed <= nodes:
        raise Blocked("review controls: rescope changes are empty or unknown")
    downstream: dict[str, set[str]] = defaultdict(set)
    for edge in index.get("edges", []): downstream[edge["upstream"]].add(edge["downstream"])
    affected = set(changed); queue = deque(sorted(changed))
    while queue:
        for child in sorted(downstream[queue.popleft()]):
            if child not in affected: affected.add(child); queue.append(child)
    if iteration == 1 and previous_plan is not None:
        raise Blocked("review controls: first rescope iteration cannot have a predecessor")
    if baseline and iteration != 1:
        raise Blocked("review controls: an initial baseline is only the first rescope iteration")
    if iteration > 1:
        if (not isinstance(previous_plan, dict) or previous_plan.get("run_id") != run_id or
                previous_plan.get("index_sha256") != index.get("index_sha256") or
                previous_plan.get("iteration") != iteration - 1 or
                previous_plan.get("max_iterations") != max_iterations):
            raise Blocked("review controls: rescope predecessor chain is invalid")
    prior = set(previous_plan.get("affected_nodes", []) if previous_plan else [])
    no_progress = bool(prior) and affected == prior
    state = ("INITIAL_BASELINE" if baseline else "NO_PROGRESS" if no_progress else
             "ITERATION_LIMIT" if iteration == max_iterations else "RESCOPE_REQUIRED")
    return {"schema": "appsec-review/bounded-rescope-plan/1.0", "run_id": run_id,
            "index_sha256": index["index_sha256"], "iteration": iteration,
            "max_iterations": max_iterations, "changed_nodes": sorted(changed),
            "affected_nodes": sorted(affected), "preserved_nodes": sorted(nodes - affected), "state": state}


def completeness_audit(run_id: str, expected: list[dict[str, str]], observed: list[dict[str, str]],
                       declared_gaps: list[dict[str, str]], *, subject_sha256: str) -> dict[str, Any]:
    if not SHA_RE.fullmatch(subject_sha256):
        raise Blocked("review controls: completeness subject binding is invalid")
    expected_by_id = _unique(expected, "obligation_id", "expected obligation")
    observed_by_id = _unique(observed, "obligation_id", "observed obligation")
    gaps_by_id = _unique(declared_gaps, "obligation_id", "declared gap")
    unknown = (set(observed_by_id) | set(gaps_by_id)) - set(expected_by_id)
    if unknown or set(observed_by_id) & set(gaps_by_id):
        raise Blocked("review controls: completeness evidence is contradictory or unknown")
    for row in observed_by_id.values():
        if set(row) != {"obligation_id", "evidence_sha256"} or not SHA_RE.fullmatch(row["evidence_sha256"]):
            raise Blocked("review controls: observed obligation lacks evidence binding")
    for row in gaps_by_id.values():
        if set(row) != {"obligation_id", "reason", "evidence_sha256"} or not SHA_RE.fullmatch(row["evidence_sha256"]):
            raise Blocked("review controls: declared gap lacks evidence binding")
    missing = sorted(set(expected_by_id) - set(observed_by_id) - set(gaps_by_id))
    false_gaps = sorted(key for key in gaps_by_id if gaps_by_id[key].get("reason") in {"", None})
    return {"schema": "appsec-review/completeness-audit/1.0", "run_id": run_id,
            "subject_sha256": subject_sha256,
            "expected_count": len(expected_by_id), "observed_ids": sorted(observed_by_id),
            "declared_gap_ids": sorted(gaps_by_id), "missing_ids": missing,
            "false_gap_ids": false_gaps,
            "observed_evidence": [observed_by_id[key] for key in sorted(observed_by_id)],
            "gap_evidence": [gaps_by_id[key] for key in sorted(gaps_by_id)],
            "complete": not missing and not false_gaps}


def synthetic_feedback(run_id: str, audit: dict[str, Any], routes: dict[str, str], *, iteration: int,
                       max_iterations: int, previous_feedback: dict[str, Any] | None = None) -> dict[str, Any]:
    missing = sorted(audit.get("missing_ids", []))
    if any(item not in routes for item in missing):
        raise Blocked("review controls: missing obligation lacks a bounded route")
    if iteration == 1 and previous_feedback is not None:
        raise Blocked("review controls: first feedback iteration cannot have a predecessor")
    if iteration > 1:
        if (not isinstance(previous_feedback, dict) or previous_feedback.get("run_id") != run_id or
                previous_feedback.get("iteration") != iteration - 1 or
                previous_feedback.get("max_iterations") != max_iterations):
            raise Blocked("review controls: feedback predecessor chain is invalid")
    prior = sorted(previous_feedback.get("unresolved_obligation_ids", []) if previous_feedback else [])
    if not missing:
        terminal = "COMPLETE"
    elif iteration >= max_iterations:
        terminal = "UNRESOLVED_AND_REPORTED"
    elif prior and missing == prior:
        terminal = "NO_PROGRESS"
    else:
        terminal = "TARGETED_ANALYSIS_REQUIRED"
    hypotheses = [{"hypothesis_id": "synthetic-" + digest({"obligation": item, "iteration": iteration})[:24],
                   "obligation_id": item, "target_job_id": routes[item], "claim_class": "candidate_only"}
                  for item in missing] if terminal == "TARGETED_ANALYSIS_REQUIRED" else []
    return {"schema": "appsec-review/synthetic-feedback/1.0", "run_id": run_id,
            "audit_sha256": _sha(audit),
            "iteration": iteration, "max_iterations": max_iterations, "terminal_state": terminal,
            "hypotheses": hypotheses, "unresolved_obligation_ids": missing}


def remediation_proposals(run_id: str, verified_claims: list[dict[str, Any]],
                          proposals: list[dict[str, Any]]) -> dict[str, Any]:
    claims = _unique(verified_claims, "claim_id", "verified claim")
    proposal_map = _unique(proposals, "proposal_id", "remediation proposal")
    rows = []
    for proposal_id in sorted(proposal_map):
        proposal = proposal_map[proposal_id]; claim_id = proposal.get("claim_id")
        if set(proposal) != {"proposal_id", "claim_id", "state", "author_id", "change_ref",
                             "rationale", "target_components"}:
            raise Blocked("review controls: remediation proposal shape is invalid")
        if claim_id not in claims or claims[claim_id].get("status") != "VERIFIED":
            raise Blocked("review controls: remediation proposal lacks a verified claim")
        if proposal.get("state") not in {"PROPOSED", "AUTHORIZED", "DECLINED"}:
            raise Blocked("review controls: remediation proposal state is invalid")
        if (not proposal.get("change_ref") or not proposal.get("rationale") or
                not isinstance(proposal.get("target_components"), list)):
            raise Blocked("review controls: remediation proposal content is incomplete")
        rows.append({**proposal, "fixed": False})
    return {"schema": "appsec-review/remediation-proposals/1.0", "run_id": run_id,
            "proposals": rows, "patches_applied": False}


def same_environment_retest(run_id: str, proposal: dict[str, Any], original_environment: dict[str, str],
                            retest: dict[str, Any], verifier: dict[str, str]) -> dict[str, Any]:
    if proposal.get("state") != "AUTHORIZED":
        raise Blocked("review controls: retest requires an authorized proposal")
    required_environment = {"source_sha256", "build_sha256", "target_sha256", "change_ref"}
    if set(original_environment) != required_environment or any(
            not isinstance(original_environment[key], str) or not original_environment[key]
            for key in required_environment):
        raise Blocked("review controls: original retest environment binding is incomplete")
    if any(not SHA_RE.fullmatch(original_environment[key])
           for key in ("source_sha256","build_sha256","target_sha256")):
        raise Blocked("review controls: retest environment hashes are invalid")
    if original_environment["change_ref"] != proposal.get("change_ref"):
        raise Blocked("review controls: retest change differs from the authorized proposal")
    if retest.get("environment") != original_environment:
        raise Blocked("review controls: retest environment differs from the verified environment")
    identities = (proposal.get("author_id"), retest.get("executor_id"), verifier.get("producer_id"))
    if any(not isinstance(identity, str) or not identity for identity in identities) or len(set(identities)) != 3:
        raise Blocked("review controls: retest verification is not independent")
    if retest.get("proposal_id") != proposal.get("proposal_id"):
        raise Blocked("review controls: retest is not bound to its proposal")
    result = retest.get("result")
    if result not in {"PASSED", "FAILED", "BUILD_FAILED", "REGRESSION", "STALE_SOURCE"}:
        raise Blocked("review controls: retest result is invalid")
    state = "FIXED" if result == "PASSED" and verifier.get("decision") == "VERIFIED" else "NOT_FIXED"
    return {"schema": "appsec-review/same-environment-retest/1.0", "run_id": run_id,
            "proposal_id": proposal["proposal_id"], "claim_id": proposal["claim_id"],
            "environment_sha256": _sha(original_environment), "result": result,
            "verifier_id": verifier.get("producer_id"), "state": state}


def completion_gate(run_id: str, draft_report: dict[str, Any], audit: dict[str, Any],
                    feedback: dict[str, Any], signoff: dict[str, Any] | None, *,
                    draft_report_sha256: str | None = None) -> dict[str, Any]:
    report_sha = draft_report_sha256 or _sha(draft_report)
    if not SHA_RE.fullmatch(report_sha):
        raise Blocked("review controls: draft report byte hash is invalid")
    blockers = []
    if draft_report.get("status") != "DRAFT_EVIDENCE_BACKED": blockers.append("draft_status_invalid")
    if not audit.get("complete"): blockers.append("coverage_incomplete")
    if feedback.get("terminal_state") not in {"COMPLETE", "UNRESOLVED_AND_REPORTED"}:
        blockers.append("feedback_not_terminal")
    if signoff is None:
        blockers.append("human_signoff_missing")
    else:
        required = {"signoff_id", "reviewer_id", "report_sha256", "decision", "signed_at"}
        if set(signoff) != required or signoff.get("report_sha256") != report_sha or \
                signoff.get("decision") not in {"APPROVED", "REJECTED"}:
            blockers.append("human_signoff_invalid")
    approved = not blockers and signoff is not None and signoff["decision"] == "APPROVED"
    return {"schema": "appsec-review/final-publication-gate/1.0", "run_id": run_id,
            "draft_report_sha256": report_sha, "eligible": approved,
            "publication_status": "FINAL_APPROVED" if approved else "BLOCKED",
            "blockers": sorted(blockers), "human_signoff": deepcopy(signoff)}
