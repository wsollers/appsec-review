"""Application-mediated OWASP worker and blinded independent assessment at the inference seam."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Mapping, Sequence

from appsec_review.config.owasp import OwaspSettings
from appsec_review.inference import Infer, ModelResult, ReviewModelRequest
from appsec_review.inference.recording import recorded
from appsec_review.observability import PipelineLog
from appsec_review.observability.model_calls import call_model
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import consume_named, publish_named, safe_path
from .evidence import EvidenceResolver, redact
from .guidance import compose, pin_bundle
from .obligations import VERSION, procedure_for, subjects
from .standards import digest


TURN_SCHEMA = "appsec-review/owasp-assessment-turn/1"
OUTCOMES = {"satisfied", "not_satisfied", "cannot_verify"}
RESULT_RULE = "owasp-assessment-acceptance/1"


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
                               "guidance"}}
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
        row_id = row["row_id"]
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
            identity = item["obligation_id"]
            if identity not in expected[row_id] or identity in ids or item["outcome"] not in OUTCOMES:
                raise ValueError("OWASP proposal has a duplicate, unknown or invalid obligation")
            ids.add(identity)
            _text(item["rationale"], "rationale")
            for key in ("assumptions", "evidence_requests", "limitations"):
                _strings(item[key], key)
            for key in ("supporting", "contradictory"):
                if not isinstance(item[key], list) or len(item[key]) > 12 or any(
                        not isinstance(ref, Mapping) for ref in item[key]):
                    raise ValueError("OWASP citations must be bounded typed reference arrays")
            if not isinstance(item["hypotheses"], list) or len(item["hypotheses"]) > 4:
                raise ValueError("OWASP hypotheses exceed bound")
            for hypothesis in item["hypotheses"]:
                if not isinstance(hypothesis, Mapping) or set(hypothesis) != {"mechanism", "severity", "ship_blocking"}:
                    raise ValueError("OWASP hypothesis has an invalid shape")
                _text(hypothesis["mechanism"], "mechanism")
                if (hypothesis["severity"] not in {"unknown", "info", "low", "medium", "high", "critical"}
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
    return pinned, canonical_json(bundle).decode()


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


def investigate(*, repository_root: Path, run_root: Path, batch: Mapping[str, Any],
                packages: Sequence[Mapping[str, Any]], role: str, profile: Mapping[str, Any],
                settings: OwaspSettings, resolver: EvidenceResolver, infer: Infer,
                attempt_id: str = "-", unit_id: str = "validation.assessment") -> dict[str, Any]:
    step_id, task_id = unit_id.split(".")
    log = PipelineLog(run_root)
    correlation = {"run_id": resolver.scope.run_id, "job_id": "job_owasp_control_assessment",
                   "attempt_id": attempt_id, "step_id": step_id, "task_id": task_id}
    guidance, text = _guidance(repository_root, run_root, batch, role)
    key = digest({"mode": settings.mode.value, "packages": _semantic(packages),
                  "guidance": guidance["bundle_sha256"], "model_policy": dict(profile),
                  "rules": RESULT_RULE, "limits": asdict(settings)})
    receipt = safe_path(run_root, f"data/indexes/owasp/receipts/{key}.json")
    if receipt.is_file():
        consume_named(run_root, receipt, namespace="owasp-shard")
        cached = json.loads(receipt.read_text(encoding="utf-8"))
        if cached.get("key") != key or cached.get("mode") != "assessment":
            raise ValueError("OWASP reuse receipt has incompatible mode or identity")
        try:
            proposal = _rebind(cached["proposal"], resolver, packages)
            validate_final(proposal, packages)
        except (ValueError, KeyError, OSError) as exc:
            # A changed reference is a reuse denial, never permission to copy prior conclusions.
            resolver.metrics["denials"] += 1
            log.write("OWASP_REUSE_DENIED", **correlation, details={
                "batch_id": batch["batch_id"], "role": role, "error_class": type(exc).__name__})
        else:
            log.write("OWASP_MODEL_REUSED", **correlation, details={
                "batch_id": batch["batch_id"], "role": role, "receipt_sha256": file_sha256(receipt),
                "receipt_path": receipt.relative_to(run_root).as_posix(),
                "guidance_bundle_sha256": guidance["bundle_sha256"], "new_model_calls": 0})
            return {"status": "reused", "proposal": proposal, "attempts": [],
                    "guidance": guidance, "receipt": receipt.relative_to(run_root).as_posix(),
                    "retrieval_requests": 0,
                    "reuse_basis": cached["attempts"]}
    task = {
        "mode": "assessment", "packages": _clean(packages),
        "contract": {"schema": TURN_SCHEMA, "actions": ["retrieve", "final"],
            "retrieve": {"requests": [{"source_identity": "an allowed expansion identity", "locator": None}]},
            "final": {"results": [{"row_id": "supplied row id", "obligations": [{
                "obligation_id": "supplied supported obligation id", "subject_id": "supplied subject id",
                "outcome": "satisfied|not_satisfied|cannot_verify", "rationale": "concise reasoning",
                "supporting": [], "contradictory": [], "assumptions": [], "evidence_requests": [],
                "hypotheses": [], "limitations": [],
            }]}]}, "citation": "Copy a complete typed reference from accepted evidence or expansion.",
            "hypothesis": {"mechanism": "concrete potential failure mechanism",
                           "severity": "unknown|info|low|medium|high|critical", "ship_blocking": False}},
    }
    transcript: list[Mapping[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    allowed = {item["reference"]["source_identity"]: package["component"]["component_id"]
               for package in packages for item in package["evidence_references"]}
    queries = 0
    terminal = "turn_limit"
    started = time.monotonic()
    for turn in range(settings.max_turns):
        for retry in range(int(profile["retries"]) + 1):
            remaining = int(profile["timeout_seconds"]) - (time.monotonic() - started)
            if remaining <= 0:
                terminal = "timeout"
                break
            request = ReviewModelRequest(
                TURN_SCHEMA, role, str(batch["assignment"]["persona"] or "general"), "owasp",
                guidance["bundle_sha256"], text, task, tuple(transcript),
                str(profile["provider"]), str(profile["model"]), str(profile["reasoning"]),
                int(profile["max_input_tokens"]), int(profile["max_output_tokens"]),
                cell_id=f"owasp:{batch['batch_id']}:{role}:{turn}:{retry}")
            estimate = (len(canonical_json(asdict(request))) + 3) // 4
            if estimate > int(profile["max_input_tokens"]):
                terminal = "input_budget"
                break
            attempt = {"role": role, "guidance": guidance["bundle_sha256"],
                       "requested_provider": profile["provider"], "requested_model": profile["model"],
                       "served_provider": None, "served_model": None,
                       "input_tokens_reported": None, "output_tokens_reported": None,
                       "cache_tokens_reported": None,
                       "input_tokens_estimated": estimate, "output_tokens_estimated": None,
                       "turn": turn, "retry": retry, "request_sha256": digest(asdict(request))}
            call_started = time.monotonic()
            try:
                result: ModelResult = call_model(recorded(infer), request,
                    timeout_seconds=max(1, int(remaining)), run_root=run_root, **correlation,
                    batch_id=batch["batch_id"], turn=turn, retry_count=retry)
                if any(value is not None and (type(value) is not int or value < 0)
                       for value in (result.input_tokens, result.output_tokens, result.cache_tokens)):
                    raise ValueError("OWASP provider returned invalid token usage")
                attempt.update({
                    "served_provider": result.served_provider, "served_model": result.served_model,
                    "input_tokens_reported": result.input_tokens, "output_tokens_reported": result.output_tokens,
                    "cache_tokens_reported": result.cache_tokens,
                    "output_tokens_estimated": (len(canonical_json(result.proposal)) + 3) // 4,
                    "response_sha256": digest(result.proposal),
                    "raw_response_sha256": hashlib.sha256(result.raw_response.encode()).hexdigest()
                    if result.raw_response is not None else None,
                })
                if ((result.input_tokens is not None and result.input_tokens > profile["max_input_tokens"])
                        or (result.output_tokens is not None and result.output_tokens > profile["max_output_tokens"])
                        or attempt["output_tokens_estimated"] > profile["max_output_tokens"]
                        or time.monotonic() - started > profile["timeout_seconds"]):
                    raise ValueError("OWASP model exceeded token/time budget")
                proposal = result.proposal
                if not isinstance(proposal, Mapping) or proposal.get("schema") != TURN_SCHEMA:
                    raise ValueError("OWASP model returned a malformed turn")
                if proposal.get("action") == "final":
                    validate_final(proposal, packages)
                elif proposal.get("action") != "retrieve":
                    raise ValueError("OWASP model returned an unsupported action")
                terminal = "succeeded"
                attempt["outcome"] = terminal
            except Exception as exc:
                # Provider/output failures are terminal evidence gaps, with their class retained.
                terminal = "timeout" if isinstance(exc, TimeoutError) else "invalid_or_provider_error"
                attempt.update({"outcome": terminal, "error_class": type(exc).__name__,
                                "error": redact(str(exc))[0][:1000]})
                proposal = None
            attempt["duration_ms"] = max(0, int((time.monotonic() - call_started) * 1000))
            attempts.append(attempt)
            log.write("OWASP_MODEL_ATTEMPT", **correlation, details={
                **{key: value for key, value in attempt.items() if key != "error"},
                "batch_id": batch["batch_id"], "cell_id": request.cell_id})
            if proposal is not None:
                break
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
                    "guidance": guidance, "receipt": receipt.relative_to(run_root).as_posix(),
                    "retrieval_requests": queries}
        requests = proposal.get("requests")
        if set(proposal) != {"schema", "action", "requests"} or not isinstance(requests, list) or not 1 <= len(requests) <= 8:
            terminal = "invalid_retrieval"
            break
        responses = []
        for query in requests:
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
        if terminal == "retrieval_budget":
            break
        terminal = "turn_limit"
    return {"status": terminal, "proposal": None, "attempts": attempts, "guidance": guidance,
            "retrieval_requests": queries}


def accept_obligations(package: Mapping[str, Any], proposal: Mapping[str, Any] | None,
                       resolver: EvidenceResolver) -> list[dict[str, Any]]:
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
        value.update({key: item[key] for key in ("rationale", "assumptions", "evidence_requests", "limitations")})
        rule = procedure_for(package["control"])
        for relation in ("supporting", "contradictory"):
            for ref in item[relation]:
                check = {"reference": dict(ref), "resolution": "rejected", "subject_binding": False,
                         "predicate_support": "unestablished"}
                try:
                    resolved = resolver.resolve(ref, component_id=package["component"]["component_id"])
                    check["resolution"] = "resolved"
                    if (rule is None or item["subject_id"] != obligation["subject_id"]
                            or obligation["subject_id"] not in subjects(rule, resolved)):
                        raise ValueError("authentic evidence does not concern the obligation's named subject")
                    check["subject_binding"] = True
                    if resolved["truncated"] or any("ambiguous" in gap for gap in resolved["limitations"]):
                        raise ValueError("truncated or ambiguous evidence cannot establish an obligation")
                    check["predicate_support"] = "analyst_assessed; not a direct extractor fact"
                    value[relation].append(resolved["reference"])
                except (ValueError, OSError, UnicodeError) as exc:
                    check["reason"] = f"{type(exc).__name__}: {exc}"
                    value["gaps"].append(check["reason"])
                value["citation_checks"].append(check)
        outcome = item["outcome"]
        if outcome in {"satisfied", "not_satisfied"} and (item["assumptions"] or item["evidence_requests"]):
            value["gaps"].append("material prerequisites remain assumed or requested, not established")
        if outcome == "satisfied" and (not value["supporting"] or value["contradictory"]):
            value["gaps"].append("satisfied proposal has unresolved material proof requirements")
        if outcome == "not_satisfied" and not value["contradictory"]:
            value["gaps"].append("adverse proposal lacks resolving subject-bound contradiction evidence")
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
              resolver: EvidenceResolver, infer: Infer, independent: bool = True,
              worker_result: Mapping[str, Any] | None = None,
              validation_retrieval: Mapping[str, int] | None = None,
              attempt_id: str = "-", unit_id: str = "validation.assessment") -> dict[str, Any]:
    retrieval_before = dict(resolver.metrics)
    ready = [package for package in packages if any(item.get("supported") for item in package["proof_obligations"])]
    ready_ids = {package["row_id"] for package in ready}
    empty = {"status": "missing_evidence", "proposal": None, "attempts": []}
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
        states, disagreements, gaps, refs, observations = [], [], [], [], []
        for first, second in zip(assessed, reviewed_obligations, strict=True):
            status = first["outcome"]
            review_status = second["outcome"]
            reviewed = bool(review_rows.get(package["row_id"])) and first["obligation"].get("supported")
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
        verification = ("dissent" if disagreements else "independently_assessed"
                        if assessed and all(item["disposition"] == "independently_assessed" for item in assessed)
                        else "pending" if row_reviewer["proposal"] is None else "unresolved")
        if status == "cannot_verify":
            gaps.append("material obligations remain unresolved; no safe/unsafe conclusion")
        for role, result in (("worker", row_worker), ("reviewer", row_reviewer)):
            if result["status"] not in {"succeeded", "reused"}:
                gaps.append(f"{role}: {result['status']}")
        results.append({
            "row_id": package["row_id"], "package_id": package["package_id"],
            "status": status, "execution_completion": row_worker["status"],
            "verification_status": verification, "coverage_completeness": "partial"
            if any(state == "cannot_verify" for state in states) else "scoped",
            "assessment_mode": "assessment", "obligations": assessed,
            "observations": observations, "disagreements": disagreements,
            "worker_attempt_count": len(row_worker["attempts"]),
            "reviewer_attempt_count": len(row_reviewer["attempts"]),
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
                 for key, value in resolver.metrics.items()}
    return {
        "schema": "appsec-review/validator-batch-result/1", "batch_id": batch["batch_id"],
        "fingerprint": batch["fingerprint"], "terminal_state": "succeeded"
        if worker["status"] in {"succeeded", "reused"} else "failed",
        "results": results, "worker": worker, "independent_review": reviewer,
        "metrics": {"model_calls": len(attempts), "attempts": attempts,
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
