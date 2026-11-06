"""Bounded multi-turn prompt experiments using the production cell and retrieval contracts.

Scripted transports test protocol behavior, not model quality. Live acceptance is separately
opted in, uses the same cell path, and still measures only the supplied synthetic corpus.
Answer keys never enter task input. Quality aggregation remains in ``review.evaluation``.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import time
from typing import Any, Mapping

from appsec_review.config import InferenceSecurityReviewSettings
from appsec_review.guidance import compose_bundle, pin_bundle, render_prompt
from appsec_review.inference import Infer, ModelResult, ReviewModelRequest, infer
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.jobs.job_security_tagging.crosswalk import load_crosswalk
from appsec_review.jobs.job_security_tagging.taxonomy import load_vocabulary
from appsec_review.retrieval import RetrievalCore
from appsec_review.review.budget import JobBudget
from appsec_review.review.capability import CellCapability
from appsec_review.review.cells import CellBudgetExceeded, CellOutcome, CellSpec, run_cell
from appsec_review.review.compact import expand_red, expand_verifier
from appsec_review.review.evaluation import assess, procedure_variant
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import CellStatus, Lane, Role
from appsec_review.review.package_view import PackageView
from appsec_review.review.red_discovery import RedInvocation, admission_errors
from appsec_review.storage import atomic_json, file_sha256

REPORT_SCHEMA = "appsec-review/prompt-competence/1"
ROLE = Role.INDEPENDENT_VERIFIER
ROLE_TASKS = {
    ROLE: ("blind_verifier", "verifier-result", "verifier-compact"),
    Role.HYPOTHESIS_HUNTER: ("entry_down", "red-discovery-result", "red-compact"),
    Role.RED_TEAM_ANALYST: ("lead_red_preconditions", "red-discovery-result", "red-compact"),
}
LIMITATION = (
    "Scripted answers establish protocol regressions only, not live model efficacy. "
    "Live results measure this synthetic corpus, not production recall or exploitability."
)


@dataclass(frozen=True)
class CompetenceResult:
    outcome: CellOutcome
    row: Mapping[str, Any]
    requests: tuple[ReviewModelRequest, ...]


def run_competence_case(
    root: Path, case: Mapping[str, Any], settings: InferenceSecurityReviewSettings, *,
    core: RetrievalCore, capability: CellCapability, view: PackageView,
    source_labels: Mapping[str, str], output: Path, transport: Infer | None = None,
    live: bool = False, budget: JobBudget | None = None, variant: str = "full",
) -> CompetenceResult:
    """Run one discovery or verifier experiment against an accepted, run-owned corpus index.

    ``source_labels`` maps the held-out answer key's labels to accepted logical identities;
    ``view`` is the initial admitted package. Merely being granted retrieval does not make an
    identity citable: ``run_cell`` and the production compact expander decide that.
    ``output`` must be new; capture is deliberately separate from hash-only cell receipts.
    """
    if transport is None and not live:
        raise ValueError("live inference requires explicit live=True")
    role = capability.role
    if role not in ROLE_TASKS:
        raise ValueError("unsupported competence role")
    task, result_schema, compact_schema = ROLE_TASKS[role]
    if set(source_labels) != {source["label"] for source in case["sources"]}:
        raise ValueError("source labels must exactly cover the answer-key sources")
    profile = settings.profile_for(role)
    if not profile.enabled:
        raise ValueError("the configured competence model is disabled")
    if capability.max_queries > profile.max_queries or capability.max_turns > profile.max_turns:
        raise ValueError("experiment capability exceeds the configured model bounds")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    schemas = SchemaSet(root / SCHEMA_DIRECTORY)
    claim_id = (make_id("claim", 1, {"package": capability.package_id, "condition": case["condition"]})
                if role is ROLE else None)
    invocation = (RedInvocation(role, capability.round, capability.package_sha256, view.lead_refs)
                  if role is not ROLE else None)
    payload: dict[str, Any] = {
        "task": task, "package": dict(view.document),
    }
    if role is ROLE:
        payload["claim"] = {
            "claim_id": claim_id, "weakness_cwe": case["cwe"],
            "security_predicate": case["condition"], "preconditions": [],
            "affected": [{"label": label, "name": case["question"]} for label in view.labels],
            "required_predicates": ["affected_construct", "attacker_input_control",
                                    "source_to_sink_reachability", "missing_or_ineffective_guard",
                                    "security_impact"],
        }
    else:
        payload.update(round=capability.round, known_claims=[], pending_requests=[])
        if role is Role.HYPOTHESIS_HUNTER:
            payload["strategy"] = task
    taxonomy = root / "data" / "reference" / "taxonomy"
    vocabulary = load_vocabulary(taxonomy / "vocabulary.json", file_sha256(taxonomy / "vocabulary.json"))
    crosswalk = load_crosswalk(taxonomy / "crosswalk.json", file_sha256(taxonomy / "crosswalk.json"), vocabulary)
    bundle = compose_bundle(
        root, role=role.value, persona=case["persona"], stack=case["stack"], task=task,
        task_input=payload, capability={
            "granted_tools": [tool for tool in capability.tools if tool != "expand"],
            "max_queries": capability.max_queries, "max_turns": capability.max_turns,
            "page_size": capability.page_size},
        vocabulary=vocabulary, crosswalk=crosswalk,
    )
    bundle = procedure_variant(bundle, variant)
    pin_bundle(core.run_root, bundle)
    lane = Lane.HUNT if role is Role.HYPOTHESIS_HUNTER else Lane.LEAD
    spec = CellSpec(
        manifest_sha256=core.manifest_sha256, lane=lane, package_id=capability.package_id,
        package_sha256=capability.package_sha256, claim_id=claim_id, role=role,
        persona=case["persona"], stack_profile=case["stack"],
        strategy=task if lane is Lane.HUNT else None, task=task,
        task_input=payload, round=capability.round, round_delta_sha256=None,
        evidence_set=tuple(sorted(view.packaged_refs)), guidance_bundle_sha256=bundle["sha256"],
        guidance_text=render_prompt(bundle), provider=profile.provider, model=profile.model,
        reasoning=profile.reasoning, max_input_tokens=profile.max_input_tokens,
        max_output_tokens=profile.max_output_tokens, timeout_seconds=profile.timeout_seconds,
        output_schema=f"appsec-review/{compact_schema}/1",
        validator_version=("competence-verifier/1" if invocation is None else
                           "competence-red/1:" + sha256_hex(settings.red_output.record())),
        view=view, expand=(lambda compact, labels: expand_verifier(
            compact, labels, claim_id=claim_id, schema_errors=schemas.errors)) if invocation is None else (
            lambda compact, labels: expand_red(
                compact, labels, invocation=invocation, schema_errors=schemas.errors)),
    )
    configuration = settings.as_document()
    atomic_json(output / "settings.json", configuration)
    atomic_json(output / "case.json", dict(case))
    atomic_json(output / "capability.json", capability.body())
    send = transport or infer
    budget = budget or JobBudget.for_run(core.run_root, settings.budgets)
    requests: list[ReviewModelRequest] = []
    answers: list[ModelResult] = []
    deadline = time.monotonic() + profile.timeout_seconds
    charged_queries = 0

    def capture(request: ReviewModelRequest, *, timeout_seconds: int) -> ModelResult:
        nonlocal charged_queries
        used = (capability.max_queries - request.transcript[-1]["remaining_queries"]
                if request.transcript else 0)
        budget.charge(retrieval_queries=used - charged_queries)
        charged_queries = used
        if not budget.cell_launch_allowed():
            raise CellBudgetExceeded(f"job budget exhausted ({budget.usage_exhausted()})")
        remaining = min(deadline - time.monotonic(),
                        settings.budgets.timeout_seconds - (budget.clock() - budget.snapshot().started_at))
        estimate = (len(json.dumps(asdict(request))) + 3) // 4
        if remaining < 1 or estimate > profile.max_input_tokens:
            raise CellBudgetExceeded("request input or time budget")
        requests.append(request)
        atomic_json(output / f"turn-{len(requests)}-request.json", asdict(request))
        try:
            answer = send(request, timeout_seconds=min(timeout_seconds, int(remaining)))
        except Exception:
            budget.charge(model_turns=1, input_tokens=estimate, output_tokens=profile.max_output_tokens)
            raise
        answers.append(answer)
        atomic_json(output / f"turn-{len(requests)}-answer.json", dict(answer.proposal))
        input_tokens = answer.input_tokens if answer.input_tokens is not None else estimate
        output_tokens = answer.output_tokens if answer.output_tokens is not None else profile.max_output_tokens
        budget.charge(model_turns=1, input_tokens=input_tokens, output_tokens=output_tokens)
        if (input_tokens > profile.max_input_tokens or output_tokens > profile.max_output_tokens
                or time.monotonic() > deadline):
            raise CellBudgetExceeded("response token or time budget")
        return answer

    def validate(result: Mapping[str, Any]) -> list[str]:
        errors = schemas.errors(result_schema, result)
        if invocation is not None and not errors:
            errors.extend(admission_errors(result, invocation, settings.red_output))
        if claim_id is not None and result.get("claim_id") != claim_id:
            errors.append("result names a different claim")
        return errors

    outcome = run_cell(spec, infer=capture, core=core, capability=capability,
                       receipts_root=core.run_root / "data" / "competence-cells",
                       validate_final=validate, max_attempts=1)
    budget.charge(retrieval_queries=outcome.counts["queries"] - charged_queries)
    row: dict[str, Any] = {
        "schema": REPORT_SCHEMA, "case_id": case["id"],
        "role": role.value, "variant": variant,
        "execution": "live" if live else "scripted", "limitation": LIMITATION,
        "case_sha256": sha256_hex(case), "settings_sha256": sha256_hex(configuration),
        "source_labels_sha256": sha256_hex(source_labels),
        "model": asdict(profile), "guidance_sha256": bundle["sha256"],
        "manifest_sha256": core.manifest_sha256, "capability_sha256": capability.capability_sha256,
        "cell_status": outcome.record.status.value, "counts": dict(outcome.counts),
        "input_tokens": (sum(answer.input_tokens for answer in answers)
                         if answers and len(answers) == len(requests)
                         and all(answer.input_tokens is not None for answer in answers) else None),
        "output_tokens": (sum(answer.output_tokens for answer in answers)
                          if answers and len(answers) == len(requests)
                          and all(answer.output_tokens is not None for answer in answers) else None),
        "status": "invalid", "errors": [gap.reason for gap in outcome.gaps],
        "receipts": [path.relative_to(core.run_root).as_posix() for path in outcome.receipt_paths],
    }
    if answers:
        row["proposal"] = dict(answers[-1].proposal)
    if outcome.record.status is CellStatus.SUCCEEDED:
        # Assess only citations actually retained by the production expander, never fixture
        # labels or a transport's unsupported logical identities.
        grounded_case = deepcopy(dict(case))
        for source in grounded_case["sources"]:
            source["label"] = source_labels[source["label"]]
        grounded_case["decisive_labels"] = [source_labels[label] for label in case["decisive_labels"]]
        compact = deepcopy(dict(answers[-1].proposal["result"]))
        if invocation is None:
            for predicate, position in compact["per_predicate"].items():
                position["cites"] = outcome.result["citations"].get(predicate, [])
            compact["evidence_requests"] = outcome.result["evidence_requests"]
        else:
            proposals = {item["local_id"]: item for item in outcome.result["proposals"]}
            refs = {item["local_id"]: item for item in outcome.result["evidence_refs"]}
            blocked_leads = {item["observation_id"] for item in outcome.result["lead_accounting"]
                             if item["outcome"] == "blocked"}
            # An unresolvable blocked label is auto-accounted as missing by the expander;
            # no_claim also takes precedence over blocked for the same lead.
            compact["blocked"] = [
                item for item in compact.get("blocked", ())
                if view.labels.get(item if isinstance(item, str) else item["lead"],
                                   item if isinstance(item, str) else item["lead"]) in blocked_leads
            ]
            for claim in compact["claims"]:
                proposal = proposals[claim["id"]]
                claim["affected"] = proposal["affected_entities"]
                claim["support"] = {}
                for identity in proposal["evidence_ids"]:
                    ref = refs[identity]
                    claim["support"].setdefault(ref["predicate"], []).append(ref["entity_id"])
        row.update(assess(grounded_case, role.value, {"action": "final", "result": compact}, schemas))
    atomic_json(output / "result.json", row)
    return CompetenceResult(outcome, row, tuple(requests))
