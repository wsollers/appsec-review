"""Application-mediated OWASP worker and blinded independent assessment at the inference seam."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import time
from typing import Any, Mapping, Sequence

from appsec_review.config.owasp import OwaspSettings
from appsec_review.inference import Infer, ModelResult, ReviewModelRequest
from appsec_review.inference.errors import ExecutionLimit, ModelOutputError, ProviderError, failure_category
from appsec_review.inference.execution import CallContext, Execution, RetryPolicy
from appsec_review.inference.recording import recorded
from appsec_review.inference.usage import total_reported
from appsec_review.observability import PipelineLog
from appsec_review.retrieval.core import retrieval_caller
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import consume_named, publish_named, safe_path
from .batching import REQUEST_RULE, Part, estimate_tokens, plan_parts
from .evidence import EvidenceResolver, prerequisite_binding, redact
from .guidance import compose, pin_bundle
from .obligations import VERSION, procedure_for, subjects
from .standards import digest


TURN_SCHEMA = "appsec-review/owasp-assessment-turn/1"
OUTCOMES = {"satisfied", "not_satisfied", "cannot_verify"}
RESULT_RULE = "owasp-assessment-acceptance/4"


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)[0]
    if isinstance(value, Mapping):
        return {key: _clean(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_clean(child) for child in value]
    return value


def _semantic(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _semantic(child) for key, child in value.items()
                if key not in {"publication", "retrieval_manifest", "package_id", "evidence_id", "evidence_ids",
                               "guidance", "guidance_by_role"}}
    if isinstance(value, (tuple, list)):
        return [_semantic(child) for child in value]
    return value


def _text(value: object, field: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 4000 or not empty and not value.strip():
        raise ValueError(f"{field} must be a bounded {'string' if empty else 'nonempty string'}")
    return redact(value)[0]


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError(f"{field} must be a bounded string array")
    return [_text(item, field) for item in value]


def _locator(value: object, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, Mapping):
        raise ValueError("OWASP citation locator must be an object")
    kind = _text(value.get("kind"), "locator.kind")
    if kind == "source":
        span = value.get("lines")
        if (not isinstance(span, list) or len(span) != 2 or any(type(n) is not int for n in span)
                or not 1 <= span[0] <= span[1]):
            raise ValueError("OWASP citation locator.lines must be an ordered integer pair")
        for field in ("path", "file_sha256"):
            _text(value.get(field), f"locator.{field}")
        if value.get("source_custody") is not None and not isinstance(value["source_custody"], Mapping):
            raise ValueError("OWASP citation source custody must be an object or null")
    elif kind in {"artifact", "structured_fact"}:
        _text(value.get("pointer"), "locator.pointer")
    else:
        raise ValueError("OWASP citation locator kind is invalid")


def _validate_retrieval(proposal: Mapping[str, Any]) -> None:
    requests = proposal.get("requests")
    if (set(proposal) != {"schema", "action", "requests"} or not isinstance(requests, list)
            or not 1 <= len(requests) <= 8):
        raise ValueError("OWASP retrieval requests must be a bounded array")
    for query in requests:
        if not isinstance(query, Mapping) or set(query) != {"source_identity", "locator"}:
            raise ValueError("OWASP retrieval request has an invalid shape")
        _text(query["source_identity"], "source_identity")
        _locator(query["locator"], optional=True)


def validate_final(proposal: Mapping[str, Any], packages: Sequence[Mapping[str, Any]]) -> None:
    if set(proposal) != {"schema", "action", "results"} or proposal.get("schema") != TURN_SCHEMA or proposal["action"] != "final":
        raise ValueError("OWASP final response does not match the turn contract")
    results = proposal["results"]
    expected = {package["row_id"]: {item["obligation_id"] for item in package["proof_obligations"]
                                    if item.get("supported")} for package in packages}
    if not isinstance(results, list) or len(results) != len(expected):
        raise ValueError("OWASP proposal must account for each dispatched row exactly once")
    seen = set()
    for row in results:
        if not isinstance(row, Mapping) or set(row) != {"row_id", "obligations"}:
            raise ValueError("OWASP row response has an invalid shape")
        row_id = _text(row["row_id"], "row_id")
        if row_id not in expected or row_id in seen:
            raise ValueError("OWASP proposal has an unknown or duplicate row")
        seen.add(row_id)
        obligations = row["obligations"]
        if not isinstance(obligations, list) or len(obligations) != len(expected[row_id]):
            raise ValueError("OWASP proposal omitted material obligations")
        ids = set()
        for item in obligations:
            fields = {"obligation_id", "subject_id", "outcome", "rationale", "supporting", "contradictory",
                      "assumptions", "evidence_requests", "hypotheses", "limitations"}
            if not isinstance(item, Mapping) or set(item) != fields:
                raise ValueError("OWASP obligation response has an invalid shape")
            identity = _text(item["obligation_id"], "obligation_id")
            outcome = _text(item["outcome"], "outcome")
            _text(item["subject_id"], "subject_id")
            if identity not in expected[row_id] or identity in ids or outcome not in OUTCOMES:
                raise ValueError("OWASP proposal has a duplicate, unknown or invalid obligation")
            ids.add(identity)
            _text(item["rationale"], "rationale")
            for key in ("assumptions", "evidence_requests", "limitations"):
                _strings(item[key], key)
            for key in ("supporting", "contradictory"):
                if not isinstance(item[key], list) or len(item[key]) > 12 or any(
                        not isinstance(ref, Mapping) for ref in item[key]):
                    raise ValueError("OWASP citations must be bounded typed reference arrays")
                for ref in item[key]:
                    _text(ref.get("source_identity"), "citation.source_identity")
                    _locator(ref.get("locator"))
            if not isinstance(item["hypotheses"], list) or len(item["hypotheses"]) > 4:
                raise ValueError("OWASP hypotheses exceed bound")
            for hypothesis in item["hypotheses"]:
                if not isinstance(hypothesis, Mapping) or set(hypothesis) != {"mechanism", "severity", "ship_blocking"}:
                    raise ValueError("OWASP hypothesis has an invalid shape")
                _text(hypothesis["mechanism"], "mechanism")
                if (_text(hypothesis["severity"], "severity") not in {"unknown", "info", "low", "medium", "high", "critical"}
                        or type(hypothesis["ship_blocking"]) is not bool):
                    raise ValueError("OWASP hypothesis severity/ship_blocking is invalid")


def _guidance(root: Path, run_root: Path, batch: Mapping[str, Any], role: str) -> tuple[dict[str, str], str]:
    bundle = compose(root, role=role, persona=batch["assignment"]["persona"], task={
        "task_id": batch["batch_id"], "question": (
            "Independently assess the underlying named obligations and accepted evidence. "
            "No previous worker conclusion is supplied. Return the task's structured turn contract."
            if role == "independent_reviewer" else
            "Investigate the named obligations using only accepted evidence and bounded expansion. "
            "Return the task's structured turn contract; unknown is not a failure."),
        "proof_obligations": [VERSION], "prohibited_claims": [
            "component-wide safety", "compliance certification", "a confirmed vulnerability",
            "runtime state inferred from static evidence", "absence inferred from missing evidence",
        ]})
    pinned = pin_bundle(run_root, bundle)
    from appsec_review.guidance.compose import render_prompt
    return pinned, render_prompt(bundle)


def prepare_guidance(root: Path, run_root: Path, batch: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    return {role: _guidance(root, run_root, batch, role)[0]
            for role in ("control_assessor", "independent_reviewer")}


def _package_guidance(root: Path, run_root: Path, batch: Mapping[str, Any], role: str,
                      packages: Sequence[Mapping[str, Any]]) -> tuple[dict[str, str], str]:
    pins = [package.get("guidance_by_role") for package in packages]
    if not any(pin is not None for pin in pins):
        return _guidance(root, run_root, batch, role)
    if any(not isinstance(pin, Mapping) or role not in pin for pin in pins):
        raise ValueError("OWASP packages have incomplete per-role guidance")
    guidance = dict(pins[0][role])
    if any(pin[role] != guidance for pin in pins):
        raise ValueError("OWASP packages disagree on per-role guidance")
    from appsec_review.guidance.compose import load_pinned_prompt
    text = load_pinned_prompt(run_root, guidance["bundle_sha256"])
    expected_path = f"data/guidance/{guidance['bundle_sha256']}/bundle.json"
    if guidance.get("path") != expected_path:
        raise ValueError("OWASP guidance path differs from its pinned identity")
    bundle = json.loads((run_root / expected_path).read_text(encoding="utf-8"))
    tasks = [section for section in bundle["sections"] if section["name"] == "task"]
    if bundle["role_id"] != role or len(tasks) != 1 or tasks[0]["id"] != batch["batch_id"]:
        raise ValueError("OWASP pinned guidance belongs to another role or batch")
    return guidance, text


@retrieval_caller(job_id="job_owasp_control_assessment", caller_kind="owasp_assessment")
def _rebind(proposal: Mapping[str, Any], resolver: EvidenceResolver,
            packages: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    value = json.loads(json.dumps(proposal))
    components = {item["row_id"]: item["component"]["component_id"] for item in packages}
    for row in value["results"]:
        for item in row["obligations"]:
            for key in ("supporting", "contradictory"):
                rebound = []
                for ref in item[key]:
                    fresh = resolver.materialize(ref["source_identity"], component_id=components[row["row_id"]],
                                                 locator=ref["locator"])["reference"]
                    if _semantic(fresh) != _semantic(ref):
                        raise ValueError("cached OWASP evidence content/scope changed")
                    rebound.append(fresh)
                item[key] = rebound
    return value


_CONTRACT = {
    "schema": TURN_SCHEMA, "actions": ["retrieve", "final"],
    "retrieve": {"requests": [{"source_identity": "an allowed expansion identity", "locator": None}]},
    "final": {"results": [{"row_id": "supplied row id", "obligations": [{
        "obligation_id": "supplied supported obligation id", "subject_id": "supplied subject id",
        "outcome": "satisfied|not_satisfied|cannot_verify", "rationale": "concise reasoning",
        "supporting": [], "contradictory": [], "assumptions": [], "evidence_requests": [],
        "hypotheses": [], "limitations": [],
    }]}]}, "citation": "Copy a complete typed reference from accepted evidence or expansion.",
    "hypothesis": {"mechanism": "concrete potential failure mechanism",
                   "severity": "unknown|info|low|medium|high|critical", "ship_blocking": False},
}


def _request(view: Mapping[str, Any], *, batch: Mapping[str, Any], role: str, guidance: Mapping[str, str],
             text: str, profile: Mapping[str, Any], settings: OwaspSettings,
             transcript: Sequence[Mapping[str, Any]], queries: int, turn: int, retry: int,
             part: int | None) -> ReviewModelRequest:
    """One worker turn over a batch part's assembled view (batching.assemble); the budget check reads it."""
    task = {"mode": "assessment", **_clean(view), "contract": _CONTRACT,
            "capability_limits": {"max_queries": settings.max_queries, "max_turns": settings.max_turns,
                                  "max_source_lines": settings.max_source_lines},
            "remaining_budget": {"remaining_queries": max(0, settings.max_queries - queries),
                                 "remaining_turns": settings.max_turns - turn,
                                 "final_required": turn + 1 == settings.max_turns
                                 or queries >= settings.max_queries}}
    return ReviewModelRequest(
        TURN_SCHEMA, role, str(batch["assignment"]["persona"] or "general"), "owasp",
        guidance["bundle_sha256"], text, task, tuple(transcript),
        str(profile["provider"]), str(profile["model"]), str(profile["reasoning"]),
        int(profile["max_input_tokens"]), int(profile["max_output_tokens"]),
        cell_id=f"owasp:{batch['batch_id']}:{role}:{turn}:{retry}" + (f":part{part}" if part is not None else ""))


def _calibration(attempts: Sequence[Mapping[str, Any]]) -> dict[str, int | None]:
    """Compare like-for-like dispatch totals; verified reuse and replay are not new provider work."""
    dispatched = [a for a in attempts if a.get("dispatched") and a.get("usage_source") != "replay"]
    return {key: total_reported([a.get(key) for a in dispatched]) for key in
            ("estimated_input_tokens", "input_tokens", "output_tokens", "cache_tokens", "input_estimate_delta")}


def _merge_status(parts: Sequence[Mapping[str, Any]]) -> str:
    statuses = [item["status"] for item in parts]
    if statuses and all(status == "reused" for status in statuses):
        return "reused"
    if statuses and all(status in {"succeeded", "reused"} for status in statuses):
        return "succeeded"
    return next(status for status in statuses if status not in {"succeeded", "reused"})


def investigate(*, repository_root: Path, run_root: Path, batch: Mapping[str, Any],
                packages: Sequence[Mapping[str, Any]], role: str, profile: Mapping[str, Any],
                settings: OwaspSettings, resolver: EvidenceResolver, infer: Infer,
                attempt_id: str = "-", unit_id: str = "validation.assessment") -> dict[str, Any]:
    """Assess a batch in as many request-sized parts as its input budget needs (D-owasp_control_assessment-1).

    Each part is assembled once (shared evidence, component context and procedures by id), estimated
    with the real request, and split or trimmed by ``batching.plan_parts`` before any model call. Row
    statuses and gaps are reported per row so a trimmed or undispatched row names its own cause.
    """
    step_id, task_id = unit_id.split(".")
    log = PipelineLog(run_root)
    correlation = {"run_id": resolver.scope.run_id, "job_id": "job_owasp_control_assessment",
                   "attempt_id": attempt_id, "step_id": step_id, "task_id": task_id}
    guidance, text = _package_guidance(repository_root, run_root, batch, role, packages)
    budget = int(profile["max_input_tokens"])

    def estimate(view: Mapping[str, Any]) -> int:
        return estimate_tokens(_request(view, batch=batch, role=role, guidance=guidance, text=text,
                                        profile=profile, settings=settings, transcript=(), queries=0,
                                        turn=0, retry=0, part=None))

    parts = plan_parts(packages, estimate=estimate, budget=budget)
    outcomes: list[dict[str, Any]] = []
    outcomes_by_row: dict[str, list[dict[str, Any]]] = {}
    row_gaps: dict[str, list[str]] = {}
    for number, part in enumerate(parts):
        for row_id, gaps in part.gaps.items():
            row_gaps.setdefault(row_id, []).extend(gaps)
        if not part.dispatch:
            outcome = {"status": "input_budget", "proposal": None, "attempts": [], "retrieval_requests": 0,
                       "estimate": part.estimate}
            log.write("OWASP_MODEL_ATTEMPT", **correlation, details={
                "batch_id": batch["batch_id"], "role": role, "outcome": "input_budget", "dispatched": False,
                "input_tokens_estimated": part.estimate, "estimated_input_tokens": part.estimate,
                "input_tokens": None, "output_tokens": None, "cache_tokens": None, "input_estimate_delta": None,
                "max_input_tokens": budget, "part": number,
                "row_ids": list(part.row_ids)})
        else:
            outcome = _investigate_part(part, number=number, parts=len(parts), run_root=run_root, batch=batch,
                                        role=role, profile=profile, settings=settings, resolver=resolver,
                                        infer=infer, guidance=guidance, text=text, log=log,
                                        correlation=correlation)
        outcomes.append(outcome)
        for row_id in part.row_ids:
            outcomes_by_row.setdefault(row_id, []).append(outcome)
            if outcome["proposal"] is None:
                row_gaps.setdefault(row_id, []).extend(
                    f"{attempt['error_class']}: {attempt['error']}"
                    for attempt in outcome["attempts"] if attempt.get("error"))
    row_status = {row_id: _merge_status(items) for row_id, items in outcomes_by_row.items()}
    merged_rows: dict[str, dict[str, Any]] = {}
    for outcome in outcomes:
        if outcome["proposal"] is None:
            continue
        for row in outcome["proposal"]["results"]:
            rid = str(row["row_id"])
            if rid not in merged_rows:
                merged_rows[rid] = {**row, "obligations": list(row.get("obligations", ()))}
            else:
                seen_ids = {item.get("obligation_id") for item in merged_rows[rid]["obligations"]}
                merged_rows[rid]["obligations"].extend(
                    item for item in row.get("obligations", ()) if item.get("obligation_id") not in seen_ids
                )
    results = list(merged_rows.values())
    proposal = ({"schema": TURN_SCHEMA, "action": "final", "results": results}
                if any(outcome["proposal"] is not None for outcome in outcomes) else None)
    receipts = [outcome["receipt"] for outcome in outcomes if outcome.get("receipt")]
    value: dict[str, Any] = {
        "status": _merge_status(outcomes) if outcomes else "succeeded", "proposal": proposal,
        "attempts": [item for outcome in outcomes for item in outcome["attempts"]],
        "guidance": guidance, "retrieval_requests": sum(outcome["retrieval_requests"] for outcome in outcomes),
        "receipt": receipts[0] if len(receipts) == 1 else None, "receipts": receipts,
        "parts": [{"row_ids": list(part.row_ids), "input_tokens_estimated": part.estimate,
                   **_calibration(outcome["attempts"]),
                   "dispatch": part.dispatch, "trimmed": part.view.get("trimmed"), "status": outcome["status"]}
                  for part, outcome in zip(parts, outcomes, strict=True)],
        "row_status": row_status, "row_gaps": {key: sorted(set(item)) for key, item in row_gaps.items()},
    }
    if value["status"] == "reused":
        value["reuse_basis"] = [item for outcome in outcomes for item in outcome.get("reuse_basis", [])]
    return value


def _investigate_part(part: Part, *, number: int, parts: int, run_root: Path, batch: Mapping[str, Any],
                      role: str, profile: Mapping[str, Any], settings: OwaspSettings,
                      resolver: EvidenceResolver, infer: Infer, guidance: Mapping[str, str], text: str,
                      log: PipelineLog, correlation: Mapping[str, Any]) -> dict[str, Any]:
    packages = part.packages
    key = digest({"mode": settings.mode.value, "packages": _semantic(packages),
                  "request": {"rule": REQUEST_RULE, "trimmed": part.view.get("trimmed")},
                  "guidance": guidance["bundle_sha256"], "model_policy": dict(profile),
                  "rules": RESULT_RULE, "limits": asdict(settings)})
    from appsec_review.storage.shared import current as _current_shared
    _active = _current_shared()
    _attempt = correlation.get("attempt_id")
    if not isinstance(_attempt, str) or not _attempt or _attempt == "-":
        _attempt = _active.attempt_id if _active is not None else None
    _whole_job = False
    if _active is not None:
        try:
            _whole_job = _active._claim().get("recovery_boundary") == "whole_job"
        except (ValueError, KeyError, OSError):
            _whole_job = False
    _receipt_rel = (
        f"data/indexes/owasp/receipts/{_attempt}/{key}.json"
        if _attempt else f"data/indexes/owasp/receipts/{key}.json"
    )
    receipt = safe_path(run_root, _receipt_rel)
    _receipt_candidates: list[Path] = [receipt]
    if not _whole_job:
        _receipts_root = safe_path(run_root, "data/indexes/owasp/receipts")
        if _receipts_root.is_dir():
            for _candidate in sorted(_receipts_root.glob(f"*/{key}.json"), reverse=True):
                if _candidate not in _receipt_candidates:
                    _receipt_candidates.append(_candidate)
        _legacy_receipt = safe_path(run_root, f"data/indexes/owasp/receipts/{key}.json")
        if _legacy_receipt not in _receipt_candidates:
            _receipt_candidates.append(_legacy_receipt)
    for _candidate in _receipt_candidates:
        if not _candidate.is_file():
            continue
        consume_named(run_root, _candidate, namespace="owasp-shard")
        cached = json.loads(_candidate.read_text(encoding="utf-8"))
        if cached.get("key") != key or cached.get("mode") != "assessment":
            raise ValueError("OWASP reuse receipt has incompatible mode or identity")
        try:
            validate_final(cached["proposal"], packages)
            proposal = _rebind(cached["proposal"], resolver, packages)
            validate_final(proposal, packages)
        except (ValueError, KeyError, OSError) as exc:
            # A changed reference is a reuse denial, never permission to copy prior conclusions.
            resolver.metrics["denials"] += 1
            log.write("OWASP_REUSE_DENIED", **correlation, details={
                "batch_id": batch["batch_id"], "role": role, "error_class": type(exc).__name__})
            break
        else:
            log.write("OWASP_MODEL_REUSED", **correlation, details={
                "batch_id": batch["batch_id"], "role": role, "receipt_sha256": file_sha256(_candidate),
                "receipt_path": _candidate.relative_to(run_root).as_posix(),
                "guidance_bundle_sha256": guidance["bundle_sha256"], "new_model_calls": 0})
            return {"status": "reused", "proposal": proposal, "attempts": [],
                    "receipt": _candidate.relative_to(run_root).as_posix(),
                    "retrieval_requests": 0, "reuse_basis": cached["attempts"]}
    transcript: list[Mapping[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    # Expansion stays bound to the part's own accepted evidence, including material trimmed from the request.
    allowed = {item["reference"]["source_identity"]: package["component"]["component_id"]
               for package in packages for item in package["evidence_references"]}
    for package in packages:
        for identity in package.get("expansion_identities", ()):
            allowed.setdefault(identity, package["component"]["component_id"])
    queries = 0
    terminal = "turn_limit"
    policy = RetryPolicy(int(profile["retries"]) + 1, True, True, True)
    engine = Execution(timeout_seconds=int(profile["timeout_seconds"]),
                       max_calls=settings.max_turns * policy.attempts,
                       max_response_bytes=int(profile["max_output_tokens"]) * 4,
                       context=CallContext(run_root, **correlation, batch_id=str(batch["batch_id"])))
    current_view = part.view
    max_tokens = int(profile["max_input_tokens"])
    part_tag = number if parts > 1 else None
    for turn in range(settings.max_turns):
        retry_reason = None
        for retry in range(policy.attempts):
            request = _request(current_view, batch=batch, role=role, guidance=guidance, text=text, profile=profile,
                               settings=settings, transcript=transcript, queries=queries, turn=turn, retry=retry,
                               part=part_tag)
            estimate = estimate_tokens(request)
            if estimate > max_tokens and transcript:
                from .batching import trim as _trim_turn
                trimmed_view, _, trimmed_after = _trim_turn(
                    current_view,
                    estimate=lambda candidate: estimate_tokens(_request(
                        candidate, batch=batch, role=role, guidance=guidance, text=text, profile=profile,
                        settings=settings, transcript=transcript, queries=queries, turn=turn, retry=retry,
                        part=part_tag)),
                    budget=max_tokens, before=estimate)
                if trimmed_after <= max_tokens:
                    current_view = trimmed_view
                    request = _request(current_view, batch=batch, role=role, guidance=guidance, text=text,
                                       profile=profile, settings=settings, transcript=transcript, queries=queries,
                                       turn=turn, retry=retry, part=part_tag)
                    estimate = trimmed_after
            if estimate > max_tokens:
                terminal = "input_budget"
                attempt = {
                    "role": role, "guidance": guidance["bundle_sha256"],
                    "row_ids": list(part.row_ids), "part": number, "dispatched": False,
                    "requested_provider": profile["provider"], "requested_model": profile["model"],
                    "served_provider": None, "served_model": None,
                    "input_tokens_reported": None, "output_tokens_reported": None,
                    "cache_tokens_reported": None,
                    "input_tokens_estimated": estimate, "output_tokens_estimated": None,
                    "turn": turn, "retry": retry, "request_sha256": digest(asdict(request)),
                    "outcome": "input_budget", "error_class": "input_budget",
                    "error": f"turn {turn} request estimate {estimate} tokens exceeds max_input_tokens {max_tokens} after trimming",
                    "estimated_input_tokens": estimate, "input_tokens": None,
                    "output_tokens": None, "cache_tokens": None, "input_estimate_delta": None,
                    "duration_ms": 0,
                }
                attempts.append(attempt)
                log.write("OWASP_MODEL_ATTEMPT", **correlation, details={
                    **{key: value for key, value in attempt.items() if key != "error"},
                    "max_input_tokens": max_tokens,
                    "batch_id": batch["batch_id"], "cell_id": request.cell_id})
                break
            attempt = {"role": role, "guidance": guidance["bundle_sha256"],
                       "row_ids": list(part.row_ids), "part": number, "dispatched": False,
                       "requested_provider": profile["provider"], "requested_model": profile["model"],
                       "served_provider": None, "served_model": None,
                       "input_tokens_reported": None, "output_tokens_reported": None,
                       "cache_tokens_reported": None,
                       "input_tokens_estimated": estimate, "output_tokens_estimated": None,
                       "turn": turn, "retry": retry, "request_sha256": digest(asdict(request))}
            call_started = time.monotonic()
            receipt_count = len(engine.receipts)
            retry_error = None
            try:
                result: ModelResult = engine.call(recorded(infer), request,
                    timeout_seconds=int(profile["timeout_seconds"]), retry_count=retry,
                    retry_reason=retry_reason)
                attempt.update({
                    "output_tokens_estimated": (len(canonical_json(result.proposal)) + 3) // 4,
                    "response_sha256": digest(result.proposal),
                    "raw_response_sha256": hashlib.sha256(result.raw_response.encode()).hexdigest()
                    if result.raw_response is not None else None,
                })
                proposal = result.proposal
                try:
                    if not isinstance(proposal, Mapping) or proposal.get("schema") != TURN_SCHEMA:
                        raise ValueError("OWASP model returned a malformed turn")
                    if proposal.get("action") == "final":
                        validate_final(proposal, packages)
                    elif proposal.get("action") == "retrieve":
                        _validate_retrieval(proposal)
                    else:
                        raise ValueError("OWASP model returned an unsupported action")
                except ValueError as exc:
                    raise ModelOutputError(str(exc)) from exc
                terminal = "succeeded"
                attempt["outcome"] = terminal
            except (ModelOutputError, ProviderError, TimeoutError, subprocess.TimeoutExpired, ExecutionLimit) as exc:
                terminal = ("timeout" if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)) else
                            exc.code if isinstance(exc, ExecutionLimit) else "invalid_or_provider_error")
                attempt.update({"outcome": terminal, "error_class": type(exc).__name__,
                                "error": redact(str(exc))[0][:1000]})
                proposal = None
                retry_error = exc
            finally:
                if len(engine.receipts) > receipt_count:
                    call = engine.receipts[-1]
                    attempt.update({"served_provider": call.served_provider, "served_model": call.served_model,
                                    "usage_source": call.usage.source,
                                    "usage_unavailable_reason": call.usage.unavailable_reason,
                                    "dispatched": call.dispatched,
                                    **{key + "_reported": value for key, value in call.usage.actual.items()}})
            measured = attempt["input_tokens_reported"]
            attempt.update(estimated_input_tokens=estimate, input_tokens=measured,
                           output_tokens=attempt["output_tokens_reported"], cache_tokens=attempt["cache_tokens_reported"],
                           input_estimate_delta=estimate - measured if measured is not None else None)
            attempt["duration_ms"] = max(0, int((time.monotonic() - call_started) * 1000))
            attempts.append(attempt)
            log.write("OWASP_MODEL_ATTEMPT", **correlation, details={
                **{key: value for key, value in attempt.items() if key != "error"},
                "batch_id": batch["batch_id"], "cell_id": request.cell_id})
            if proposal is not None:
                break
            try:
                if not engine.retry(retry + 1, retry_error, policy):
                    break
            except ExecutionLimit:
                terminal = "execution_deadline"
                break
            retry_reason = failure_category(retry_error).value
        if terminal != "succeeded":
            break
        if proposal["action"] == "final":
            safe = _clean(proposal)
            publish_named(run_root, receipt, canonical_json({
                "schema": "appsec-review/owasp-model-receipt/1", "key": key, "mode": "assessment",
                "proposal": safe, "attempts": attempts,
                "retrieval_requests": queries,
            }), namespace="owasp-shard", computation={"key": key})
            return {"status": "succeeded", "proposal": safe, "attempts": attempts,
                    "receipt": receipt.relative_to(run_root).as_posix(), "retrieval_requests": queries}
        requests = proposal["requests"]
        responses = []
        for query in requests:
            try:
                engine.deadline.remaining()
            except ExecutionLimit:
                terminal = "execution_deadline"
                break
            queries += 1
            query_started = time.monotonic()
            retrieval = {"batch_id": batch["batch_id"], "role": role, "cell_id": request.cell_id,
                         "query_number": queries, "terminal_status": "SUCCEEDED"}
            if queries > settings.max_queries:
                terminal = "retrieval_budget"
                log.write("OWASP_RETRIEVAL_COMPLETED", **correlation, details={
                    **retrieval, "terminal_status": "SKIPPED", "reason": "retrieval_budget"})
                break
            if (not isinstance(query, Mapping) or set(query) != {"source_identity", "locator"}
                    or query["source_identity"] not in allowed):
                resolver.metrics["denials"] += 1
                responses.append({"denied": "identity is outside this batch's accepted component evidence"})
                log.write("OWASP_RETRIEVAL_COMPLETED", **correlation, details={
                    **retrieval, "terminal_status": "DENIED", "reason": "outside_batch_scope"})
                continue
            try:
                with retrieval_caller(job_id="job_owasp_control_assessment", caller_kind="owasp_assessment",
                                      cell_id=request.cell_id, role=role, turn=turn):
                    responses.append(resolver.materialize(query["source_identity"],
                        component_id=allowed[query["source_identity"]], locator=query["locator"],
                        max_lines=settings.max_source_lines))
            except (ValueError, OSError, UnicodeError) as exc:
                resolver.metrics["denials"] += 1
                responses.append({"gap": f"{type(exc).__name__}: {exc}"})
                retrieval.update(terminal_status="FAILED", error_class=type(exc).__name__)
            log.write("OWASP_RETRIEVAL_COMPLETED", **correlation, details={
                **retrieval, "duration_ms": max(0, int((time.monotonic() - query_started) * 1000)),
                "truncated": bool(responses[-1].get("truncated"))})
        transcript.extend(({"request": _clean(proposal)}, {"evidence": _clean(responses)}))
        if terminal in {"retrieval_budget", "execution_deadline"}:
            break
        terminal = "turn_limit"
    return {"status": terminal, "proposal": None, "attempts": attempts, "retrieval_requests": queries}


@retrieval_caller(job_id="job_owasp_control_assessment", caller_kind="owasp_assessment")
def accept_obligations(package: Mapping[str, Any], proposal: Mapping[str, Any] | None,
                       resolver: EvidenceResolver | None) -> list[dict[str, Any]]:
    proposals = {item["obligation_id"]: item for item in proposal["obligations"]} if proposal else {}
    accepted = []
    for obligation in package["proof_obligations"]:
        item = proposals.get(obligation["obligation_id"])
        value = {"obligation": dict(obligation), "outcome": "cannot_verify", "supporting": [],
                 "contradictory": [], "citation_checks": [], "hypotheses": [], "assumptions": [],
                 "evidence_requests": [], "limitations": [], "gaps": []}
        if not obligation.get("supported") or item is None:
            value["gaps"] = [obligation.get("reason", "model did not return this obligation")]
            value["evidence_requests"] = list(value["gaps"])
            accepted.append(value)
            continue
        if resolver is None:
            raise ValueError("supported obligation requires an accepted evidence resolver")
        value.update({key: item[key] for key in ("rationale", "assumptions", "evidence_requests", "limitations")})
        rule = procedure_for(package["control"])
        resolved_citations = []
        for relation in ("supporting", "contradictory"):
            for ref in item[relation]:
                check = {"reference": dict(ref), "resolution": "rejected", "subject_binding": False,
                         "predicate_support": "unestablished"}
                try:
                    resolved = resolver.resolve(ref, component_id=package["component"]["component_id"])
                    check["resolution"] = "resolved"
                    if rule is None or item["subject_id"] != obligation["subject_id"]:
                        raise ValueError("authentic evidence does not concern the obligation's named subject")
                    check["subject_binding"] = obligation["subject_id"] in subjects(rule, resolved)
                    if not check["subject_binding"] and rule.language != "c-cpp":
                        raise ValueError("authentic evidence does not concern the obligation's named subject")
                    if (resolved["truncated"] or resolved.get("redaction", {}).get("applied")
                            or any("ambiguous" in gap for gap in resolved["limitations"])
                            or not resolved.get("source_subject", {}).get("complete")):
                        raise ValueError("incomplete, redacted or ambiguous evidence cannot establish an obligation")
                    if (rule.recognizer == "python_http_operation/1"
                            and resolved["source_subject"]["kind"] != "module"):
                        raise ValueError("complete function does not resolve external authorization policy, "
                                         "middleware, consumer identity or service-guard prerequisites")
                    resolved_citations.append((relation, resolved, check))
                except (ValueError, OSError, UnicodeError) as exc:
                    check["reason"] = f"{type(exc).__name__}: {exc}"
                    value["gaps"].append(check["reason"])
                value["citation_checks"].append(check)
        primary = [resolved for _, resolved, check in resolved_citations if check["subject_binding"]]
        admitted = {
            *(record["reference"]["source_identity"] for record in package.get("evidence_references", ())),
            *package.get("expansion_identities", ()),
        }
        for relation, resolved, check in resolved_citations:
            try:
                if not check["subject_binding"]:
                    if resolved["reference"]["source_identity"] not in admitted:
                        raise ValueError("prerequisite citation is outside this package's admitted context")
                    bindings = []
                    reasons = []
                    for subject in primary:
                        try:
                            bindings.append(prerequisite_binding(subject, resolved))
                        except ValueError as exc:
                            reasons.append(str(exc))
                    if not bindings:
                        raise ValueError("authentic evidence does not concern the obligation's named subject "
                                         "or a source-bound caller/callee prerequisite"
                                         + (": " + "; ".join(sorted(set(reasons))) if reasons else ""))
                    check["prerequisite_binding"] = bindings[0]
                check["predicate_support"] = "analyst_assessed; not a direct extractor fact"
                value[relation].append(resolved["reference"])
            except ValueError as exc:
                check["reason"] = f"{type(exc).__name__}: {exc}"
                value["gaps"].append(check["reason"])
        outcome = item["outcome"]
        if outcome in {"satisfied", "not_satisfied"} and (item["assumptions"] or item["evidence_requests"]):
            value["gaps"].append("material prerequisites remain assumed or requested, not established")
        if outcome == "satisfied" and (not value["supporting"] or value["contradictory"]):
            value["gaps"].append("satisfied proposal has unresolved material proof requirements")
        if outcome == "not_satisfied" and not value["contradictory"]:
            value["gaps"].append("adverse proposal lacks resolving subject-bound contradiction evidence")
        primary_relation = "supporting" if outcome == "satisfied" else "contradictory"
        if outcome != "cannot_verify" and not any(
                relation == primary_relation and check["subject_binding"]
                for relation, _, check in resolved_citations):
            value["gaps"].append("decisive proposal requires primary subject evidence, not prerequisite context alone")
        if obligation["evidence_mode"] in {"dynamic_runtime", "manual_observation"}:
            value["gaps"].append("no accepted environment-bound runtime/manual evidence adapter is available")
        value["outcome"] = outcome if not value["gaps"] else "cannot_verify"
        if value["outcome"] == "not_satisfied":
            value["hypotheses"] = list(item["hypotheses"])
        if value["outcome"] == "cannot_verify" and not value["evidence_requests"]:
            value["evidence_requests"] = ["Obtain decisive subject-bound evidence for the invariant and alternate paths."]
        accepted.append(value)
    return accepted


def run_batch(*, repository_root: Path, run_root: Path, batch: Mapping[str, Any],
              packages: Sequence[Mapping[str, Any]], settings: OwaspSettings,
              worker_profile: Mapping[str, Any], reviewer_profile: Mapping[str, Any],
              resolver: EvidenceResolver | None, infer: Infer, independent: bool = True,
              worker_result: Mapping[str, Any] | None = None,
              validation_retrieval: Mapping[str, int] | None = None,
              attempt_id: str = "-", unit_id: str = "validation.assessment") -> dict[str, Any]:
    ready = [package for package in packages if any(item.get("supported") for item in package["proof_obligations"])]
    if ready and resolver is None:
        raise ValueError("dispatchable obligations require an accepted evidence resolver")
    retrieval_metrics = (resolver.metrics if resolver is not None else
                         {"attempts": 0, "denials": 0, "truncations": 0, "missing": 0})
    retrieval_before = dict(retrieval_metrics)
    ready_ids = {package["row_id"] for package in ready}
    empty = {"status": "not_dispatched", "proposal": None, "attempts": []}
    worker = dict(worker_result) if worker_result is not None else investigate(repository_root=repository_root, run_root=run_root, batch=batch, packages=ready,
        role="control_assessor", profile=worker_profile, settings=settings, resolver=resolver, infer=infer,
        attempt_id=attempt_id, unit_id=unit_id) if ready else empty
    # A new request context with the original evidence, no worker answer or transcript.
    reviewer = investigate(repository_root=repository_root, run_root=run_root, batch=batch, packages=ready,
        role="independent_reviewer", profile=reviewer_profile, settings=settings, resolver=resolver, infer=infer,
        attempt_id=attempt_id, unit_id=unit_id) if ready and independent else empty
    worker_rows = {row["row_id"]: row for row in worker["proposal"]["results"]} if worker["proposal"] else {}
    review_rows = {row["row_id"]: row for row in reviewer["proposal"]["results"]} if reviewer["proposal"] else {}
    results = []
    for package in packages:
        row_worker = worker if package["row_id"] in ready_ids else empty
        row_reviewer = reviewer if package["row_id"] in ready_ids else empty
        assessed = accept_obligations(package, worker_rows.get(package["row_id"]), resolver)
        reviewed_obligations = accept_obligations(package, review_rows.get(package["row_id"]), resolver)
        reviewed_ids = {item["obligation_id"]
                        for item in (review_rows.get(package["row_id"]) or {}).get("obligations", ())}
        states, disagreements, gaps, refs, observations = [], [], [], [], []
        for first, second in zip(assessed, reviewed_obligations, strict=True):
            status = first["outcome"]
            review_status = second["outcome"]
            reviewed = first["obligation"]["obligation_id"] in reviewed_ids and bool(first["obligation"].get("supported"))
            disposition = ("independently_assessed" if reviewed and status == review_status
                           and status != "cannot_verify" else "dissent" if reviewed and status != review_status
                           else "unresolved" if reviewed else "pending")
            if disposition == "dissent":
                disagreements.append({"obligation_id": first["obligation"]["obligation_id"],
                                      "worker": status, "reviewer": review_status,
                                      "worker_rationale": first.get("rationale"),
                                      "reviewer_rationale": second.get("rationale")})
            if status == "satisfied" and disposition != "independently_assessed":
                status = "cannot_verify"
            first.update({"disposition": disposition, "independent_assessment": second,
                          "final_outcome": status})
            states.append(status)
            refs.extend((*first["supporting"], *first["contradictory"], *second["supporting"], *second["contradictory"]))
            gaps.extend((*first["gaps"], *second["gaps"]))
            for hypothesis in first["hypotheses"]:
                observations.append({
                    **hypothesis, "observation_id": digest({"row": package["row_id"], "hypothesis": hypothesis}),
                    "state": "provisional_independently_assessed" if disposition == "independently_assessed"
                             else "awaiting_independent_verification",
                    "obligation_id": first["obligation"]["obligation_id"],
                    "evidence": first["contradictory"], "verification_outcome": disposition,
                })
        status = ("not_satisfied" if "not_satisfied" in states else "satisfied"
                  if states and all(item == "satisfied" for item in states) else "cannot_verify")
        supported_items = [item for item in assessed if item["obligation"].get("supported")]
        has_verified_violation = (
            status == "not_satisfied"
            and any(item["final_outcome"] == "not_satisfied" and item["disposition"] == "independently_assessed"
                    for item in supported_items)
        )
        verification = (
            "dissent" if disagreements else
            "independently_assessed" if (
                (supported_items and all(item["disposition"] == "independently_assessed" for item in supported_items))
                or has_verified_violation
            ) else
            "pending" if not reviewed_ids else "unresolved"
        )
        if status == "cannot_verify":
            gaps.append("material obligations remain unresolved; no safe/unsafe conclusion")
        # A batch dispatched in parts (batching.plan_parts) reports each row's own status and budget gaps.
        row_completion = row_worker.get("row_status", {}).get(package["row_id"], row_worker["status"])
        for role, result in (("worker", row_worker), ("reviewer", row_reviewer)):
            role_status = result.get("row_status", {}).get(package["row_id"], result["status"])
            if role_status not in {"succeeded", "reused"}:
                gaps.append(f"{role}: {role_status}")
            gaps.extend(f"{role}: {gap}" for gap in result.get("row_gaps", {}).get(package["row_id"], ()))
        results.append({
            "row_id": package["row_id"], "package_id": package["package_id"],
            "status": status, "execution_completion": row_completion,
            "verification_status": verification, "coverage_completeness": "partial"
            if not states or any(state == "cannot_verify" for state in states) else "scoped",
            "assessment_mode": "assessment", "obligations": assessed,
            "observations": observations, "disagreements": disagreements,
            "worker_attempt_count": sum(attempt.get("dispatched", False)
                and package["row_id"] in attempt.get("row_ids", ()) for attempt in row_worker["attempts"]),
            "reviewer_attempt_count": sum(attempt.get("dispatched", False)
                and package["row_id"] in attempt.get("row_ids", ()) for attempt in row_reviewer["attempts"]),
            "evidence_used": list({digest(ref): ref for ref in refs}.values()),
            "gaps": sorted(set(gaps)),
            "limitations": sorted(set([*package.get("limitations", ()),
                *(text for item in assessed for text in item["limitations"]),
                *(text for item in reviewed_obligations for text in item["limitations"])])),
            "lead_eligible": bool(observations),
            "interpretation": "analyst_assessed; underlying evidence required for every downstream security predicate",
        })
    attempts = [*worker["attempts"], *reviewer["attempts"]]
    known_input = [item["input_tokens_reported"] for item in attempts if item["input_tokens_reported"] is not None]
    known_output = [item["output_tokens_reported"] for item in attempts if item["output_tokens_reported"] is not None]
    retrieval = {key: value - retrieval_before.get(key, 0) + (validation_retrieval or {}).get(key, 0)
                 for key, value in retrieval_metrics.items()}
    return {
        "schema": "appsec-review/validator-batch-result/1", "batch_id": batch["batch_id"],
        "fingerprint": batch["fingerprint"], "terminal_state": "succeeded"
        if worker["status"] in {"succeeded", "reused"} else "failed"
        if worker["proposal"] is not None or any(item.get("dispatched") for item in worker["attempts"])
        else "not_dispatched",
        "results": results, "worker": worker, "independent_review": reviewer,
        "metrics": {**_calibration(attempts), "model_calls": sum(item.get("dispatched", True) for item in attempts), "attempts": attempts,
                    "model_requested_retrievals": sum(
                        result.get("retrieval_requests", 0) for result in (worker, reviewer)),
                    "retrieval": retrieval, "cost_usd": None,
                    "reused_model_results": sum(item["status"] == "reused" for item in (worker, reviewer)),
                    "input_tokens_reported": sum(known_input) if attempts and len(known_input) == len(attempts) else None,
                    "output_tokens_reported": sum(known_output) if attempts and len(known_output) == len(attempts) else None,
                    "known_input_tokens_subtotal": sum(known_input) if known_input else None,
                    "known_output_tokens_subtotal": sum(known_output) if known_output else None,
                    "unknown_usage_attempts": sum(item["input_tokens_reported"] is None
                                                  or item["output_tokens_reported"] is None for item in attempts)},
    }
