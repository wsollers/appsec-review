"""Bounded model assistance for unresolved native repository identities only."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
import hashlib
from pathlib import Path
import subprocess
from typing import Any

from appsec_review.inference import Infer, ModelRequest
from appsec_review.inference.errors import ExecutionLimit, ModelOutputError, ProviderError, failure_category
from appsec_review.inference.execution import Execution, RetryPolicy
from appsec_review.storage import canonical_json

from .resolution import allowed_evidence_refs, apply_model_resolution


PROPOSAL_SCHEMA = "appsec-review/native-dependency-resolution-proposal/1"
PERSONA_ID = "dependency_repository_investigator"
ROLE_ID = "native_dependency_resolver"
TASK_ID = "native_repository_resolution"
RUNTIME_SKILL_ID = "native-dependency-resolution"


def _guidance(repository_root: Path, run_root: Path, model: Mapping[str, Any]) -> tuple[str, str]:
    from appsec_review.guidance.workers import publish_worker_guidance
    return publish_worker_guidance(repository_root, run_root, "dependency_repository", model=model)


@dataclass
class ResolutionBudget:
    """One unit's bound on a worker that keeps failing its contract (T-5022).

    ``failure_limit`` is the typed ``inference_failure_limit`` setting: once that many candidate
    sets have ended in a model failure, the remaining unresolved candidates are gaps, not calls.
    An identical candidate set (candidate, evidence allowlist, hosts) is asked once per unit; its
    outcome, including a failure, is reused for every dependency that carries it.
    """

    failure_limit: int
    failures: int = 0
    outcomes: dict[str, tuple[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.failure_limit) is not int or self.failure_limit < 1:
            raise ValueError("inference_failure_limit must be a positive integer")

    @property
    def exhausted(self) -> bool:
        return self.failures >= self.failure_limit


def _candidate_key(summary: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json({key: summary[key] for key in (
        "candidate", "allowed_evidence_refs", "supported_repository_hosts")})).hexdigest()


def _reuse(dependency: Mapping[str, Any], dependency_id: str, outcome: tuple[str, Any], *,
           supported_hosts: tuple[str, ...]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    kind, value = outcome
    if kind == "proposal":
        return apply_model_resolution(dependency, value, supported_hosts=supported_hosts), None
    if kind == "gap":
        return dict(dependency), {**value, "dependency_id": dependency_id,
                                  "detail": (value["detail"] + " (identical candidate set already asked; "
                                             "not re-asked)")[:4096]}
    return dict(dependency), None


def resolve_with_inference(dependency: Mapping[str, Any], *, repository_root: Path, run_root: Path,
                           model: Mapping[str, Any], supported_hosts: tuple[str, ...], infer: Infer | None,
                           max_candidate_bytes: int, budget: ResolutionBudget | None = None
                           ) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Resolve one native candidate or return a dependency-scoped gap record."""
    dependency_id = str(dependency["dependency_id"])
    if dependency.get("repository") is not None or "native_candidate" not in dependency:
        return dict(dependency), None
    if not bool(model.get("enabled")):
        return dict(dependency), {"dependency_id": dependency_id, "kind": "model_unavailable",
                                  "detail": "native repository inference is disabled"}
    if infer is None:
        return dict(dependency), {"dependency_id": dependency_id, "kind": "model_unavailable",
                                  "detail": "native repository inference transport is unavailable"}
    candidate = dependency["native_candidate"]
    payload = canonical_json(candidate)
    if len(payload) > max_candidate_bytes:
        return dict(dependency), {"dependency_id": dependency_id, "kind": "bounds",
                                  "detail": "native candidate exceeds the inference input byte bound"}
    guidance, guidance_sha = _guidance(repository_root, run_root, model)
    summary = {"candidate": candidate,
               "allowed_evidence_refs": sorted(allowed_evidence_refs(dependency, candidate)),
               "supported_repository_hosts": list(supported_hosts),
               "guidance_bundle_sha256": guidance_sha}
    key = _candidate_key(summary)
    if budget is not None and key in budget.outcomes:
        return _reuse(dependency, dependency_id, budget.outcomes[key], supported_hosts=supported_hosts)
    if budget is not None and budget.exhausted:
        return dict(dependency), {
            "dependency_id": dependency_id, "kind": "model_failure_bound",
            "detail": (f"native repository inference stopped after {budget.failures} candidate sets "
                       f"failed the response contract (inference_failure_limit={budget.failure_limit})")}
    request = ModelRequest(
        schema=PROPOSAL_SCHEMA, persona=PERSONA_ID, role=ROLE_ID, guidance=guidance,
        summary=summary, allowed_scanners=(), allowed_build_systems=(), allowed_components=(),
        allowed_paths=(), allowed_build_units=(), provider=str(model["provider"]), model=str(model["model"]),
        reasoning=str(model["reasoning"]), max_input_tokens=int(model["max_input_tokens"]),
        max_output_tokens=int(model["max_output_tokens"]),
    )
    if len(canonical_json(summary)) + len(guidance.encode()) > request.max_input_tokens * 4:
        return dict(dependency), {"dependency_id": dependency_id, "kind": "bounds",
                                  "detail": "native inference request exceeds its token-derived byte bound"}
    from appsec_review.runtime import execution_safety as safety
    policy = RetryPolicy(int(model["retries"]) + 1, True, True, True)
    engine = Execution(timeout_seconds=int(model["timeout_seconds"]), max_calls=policy.attempts,
                       guidance_sha256=guidance_sha)
    errors: list[str] = []
    failure_class: str | None = None
    retry_reason = None
    for attempt in range(1, policy.attempts + 1):
        try:
            result = engine.call(infer, request, timeout_seconds=int(model["timeout_seconds"]),
                                 retry_count=attempt - 1, retry_reason=retry_reason)
            proposal = result.proposal
            if (proposal.get("schema") == PROPOSAL_SCHEMA and
                    proposal.get("candidate_id") == candidate.get("candidate_id") and
                    proposal.get("repository") is None and proposal.get("confidence") == 0):
                if budget is not None:
                    budget.outcomes[key] = ("none", None)
                return dict(dependency), None
            try:
                resolved = apply_model_resolution(dependency, proposal, supported_hosts=supported_hosts)
            except ValueError as exc:
                raise ModelOutputError(str(exc)) from exc
            if budget is not None:
                budget.outcomes[key] = ("proposal", dict(proposal))
            return resolved, None
        except (ModelOutputError, ProviderError, TimeoutError, subprocess.TimeoutExpired, ExecutionLimit) as exc:
            failure_class = getattr(exc, "failure_class", None) or failure_category(exc).value
            errors = [f"{failure_class}: {type(exc).__name__}: {exc}"[:2048]]
            safety.retain_failure("dependency.inference", exc, dependency_id=dependency_id,
                                  failure_class=failure_class)
            safety.fail(errors[0], action="dependency.inference")
            try:
                retry = engine.retry(attempt, exc, policy)
            except ExecutionLimit:
                retry = False
            if not retry:
                break
            retry_reason = failure_category(exc).value
            request = replace(request, repair_errors=tuple(errors), prior_response=None)
    gap = {"dependency_id": dependency_id, "kind": "model_failure", "failure_class": failure_class,
           "detail": errors[0] if errors else "native repository inference failed"}
    if budget is not None:
        budget.failures += 1
        budget.outcomes[key] = ("gap", {key_: value for key_, value in gap.items() if key_ != "dependency_id"})
    return dict(dependency), gap


__all__ = ["PERSONA_ID", "PROPOSAL_SCHEMA", "ROLE_ID", "RUNTIME_SKILL_ID", "TASK_ID",
           "ResolutionBudget", "resolve_with_inference"]
