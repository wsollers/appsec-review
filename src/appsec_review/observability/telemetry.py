from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
from typing import Any, Mapping

from appsec_review.observability.events import PipelineLog
from appsec_review.storage import canonical_json


SCHEMA = "appsec-review/telemetry-event/1"
FINDING_STATES = {"CANDIDATE", "REFUTED", "CONFIRMED"}
TERMINAL_EVENTS = {"SUCCEEDED", "COMPLETED", "COMPLETED_WITH_GAPS", "FAILED",
                   "BLOCKED", "PARTIAL", "NOT_APPLICABLE"}


def validate_event(record: Mapping[str, Any]) -> None:
    required = {"schema", "sequence", "timestamp", "event_type", "event_id", "run_id",
                "job_id", "attempt_id", "trigger", "orchestrator", "details"}
    if record.get("schema") != SCHEMA or not required <= set(record):
        raise ValueError("unsupported or incomplete telemetry event")
    if not isinstance(record["sequence"], int) or record["sequence"] < 1:
        raise ValueError("telemetry sequence is invalid")
    if len(str(record["event_id"])) != 64:
        raise ValueError("telemetry event identity is invalid")


def identity_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


class FindingLifecycle:
    """Append-only finding state transitions; scanner observations are never findings."""

    def __init__(self, run_root: Path):
        self.log = PipelineLog(run_root)

    def transition(self, *, run_id: str, finding_package_id: str, new_state: str,
                   evidence_identities: tuple[str, ...], actor_class: str,
                   reason_hash: str, job_id: str = "finding_lifecycle",
                   attempt_id: str = "-") -> Mapping[str, Any]:
        if new_state not in FINDING_STATES:
            raise ValueError("invalid finding state")
        if actor_class not in {"deterministic", "model", "human"}:
            raise ValueError("invalid finding actor class")
        if not finding_package_id or not evidence_identities or len(reason_hash) != 64:
            raise ValueError("finding transition requires package, evidence, and reason identities")
        records, _ = self.log.read()
        transitions = [item for item in records if item.get("event_type") == "FINDING_TRANSITION" and
                       item.get("details", {}).get("finding_package_id") == finding_package_id]
        prior = transitions[-1]["details"]["new_state"] if transitions else None
        if prior == new_state:
            candidate_hash = identity_hash({"state": new_state,
                                            "evidence_identities": sorted(evidence_identities),
                                            "reason_hash": reason_hash})
            if transitions[-1]["details"].get("transition_hash") != candidate_hash:
                raise ValueError("finding transition conflicts with the existing terminal state")
            return transitions[-1]
        allowed = prior is None and new_state == "CANDIDATE" or prior == "CANDIDATE" and new_state in {"REFUTED", "CONFIRMED"}
        if not allowed:
            raise ValueError(f"invalid finding transition: {prior or 'NONE'} -> {new_state}")
        transition_hash = identity_hash({"state": new_state,
                                         "evidence_identities": sorted(evidence_identities),
                                         "reason_hash": reason_hash})
        return self.log.write("FINDING_TRANSITION", run_id=run_id, job_id=job_id,
                              attempt_id=attempt_id, details={
            "finding_package_id": finding_package_id, "prior_state": prior, "new_state": new_state,
            "evidence_identities": sorted(evidence_identities),
            "evidence_count": len(set(evidence_identities)), "actor_class": actor_class,
            "reason_hash": reason_hash, "transition_hash": transition_hash,
        })


def aggregate_run_metrics(run_root: Path) -> Mapping[str, Any]:
    records, torn = PipelineLog(run_root).read()
    for record in records:
        validate_event(record)
    event_counts = Counter(str(record["event_type"]) for record in records)
    dispositions = Counter()
    tool_calls = Counter()
    finding_states = Counter()
    durations_ms = Counter()
    tokens = Counter()
    for record in records:
        details = record.get("details", {})
        disposition = details.get("disposition") or details.get("terminal_status") or details.get("completion_status")
        if disposition:
            dispositions[str(disposition)] += 1
        if record["event_type"] in {"TOOL_INVOCATION_COMPLETED", "MCP_TOOL_COMPLETED"}:
            tool_calls[str(details.get("tool_id") or details.get("mcp_tool") or "unknown")] += 1
        if record["event_type"] == "FINDING_TRANSITION":
            finding_states[str(details.get("new_state"))] += 1
        if isinstance(details.get("duration_ms"), int):
            durations_ms[str(record["event_type"])] += details["duration_ms"]
        for key in ("input_tokens", "output_tokens", "cache_tokens"):
            if isinstance(details.get(key), int):
                tokens[key] += details[key]
    return {"schema": "appsec-review/run-metrics/1", "run_id": Path(run_root).name,
            "event_count": len(records), "event_counts": dict(sorted(event_counts.items())),
            "dispositions": dict(sorted(dispositions.items())),
            "tool_calls": dict(sorted(tool_calls.items())),
            "finding_states": dict(sorted(finding_states.items())),
            "duration_ms_by_event": dict(sorted(durations_ms.items())),
            "model_tokens": dict(sorted(tokens.items())), "torn_tail_ignored": torn}


def emit_model_event(log: PipelineLog, *, event_type: str, run_id: str, invocation_id: str,
                     provider: str, model: str, reasoning_level: str,
                     guidance_bundle_sha256: str, request_sha256: str,
                     terminal_status: str | None = None, duration_ms: int | None = None,
                     retry_count: int = 0, input_tokens: int | None = None,
                     output_tokens: int | None = None, cache_tokens: int | None = None,
                     error_class: str | None = None, **correlation: Any) -> Mapping[str, Any]:
    if event_type not in {"MODEL_CALL_STARTED", "MODEL_CALL_COMPLETED"}:
        raise ValueError("invalid model telemetry event")
    details = {"model_invocation_id": invocation_id, "provider": provider, "model": model,
               "reasoning_level": reasoning_level, "guidance_bundle_sha256": guidance_bundle_sha256,
               "request_sha256": request_sha256, "retry_count": retry_count,
               "terminal_status": terminal_status, "duration_ms": duration_ms,
               "input_tokens": input_tokens, "output_tokens": output_tokens,
               "cache_tokens": cache_tokens, "error_class": error_class, **correlation}
    return log.write(event_type, run_id=run_id, job_id=str(correlation.get("job_id", "inference")),
                     attempt_id=str(correlation.get("attempt_id", "-")), details=details)
