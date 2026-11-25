"""Pre-dispatch check of a development input override against the consumer's real lookup.

``check_lookup`` builds the job's read context exactly as a fresh attempt would (the same claimed
upstream pins, contract and ``Job.resolve_development_inputs``), but describes the edited working
copy instead of snapshotting it, then calls the consumer's own lookup function inside the same
input-read scope. It never claims an attempt, launches Dagster, or writes to the run.
"""
from __future__ import annotations

from dataclasses import replace
import importlib
import json
from pathlib import Path
import tempfile
import traceback
from types import MappingProxyType
from typing import Any, Callable, Sequence

from appsec_review.config import AppConfig


def lookup_function(spec: str) -> Callable[..., Any]:
    module, _, name = spec.partition(":")
    if not module.startswith("appsec_review.") or not name:
        raise ValueError("--lookup must be appsec_review.<module>:<function>")
    value: Any = importlib.import_module(module)
    for part in name.split("."):
        value = getattr(value, part)
    if not callable(value):
        raise ValueError(f"{spec} is not callable")
    return value


def _latest_claim(run_root: Path, job_id: str) -> dict[str, Any] | None:
    attempts = sorted((run_root / "data/jobs" / job_id / "attempts").glob("attempt_*/claim.json"))
    return json.loads(attempts[-1].read_bytes()) if attempts else None


def check_lookup(config: AppConfig, run_root: Path, job_id: str, lookup: Callable[..., Any],
                 arguments: Sequence[Any] = (), *, original: bool = False) -> dict[str, Any]:
    """Run ``lookup(run_root, *arguments)`` with the job's inputs resolved as its next attempt would."""
    from appsec_review.observability import EventLog, PipelineLog
    from appsec_review.runtime.inputs import input_read_scope, selected_handoffs
    from appsec_review.runtime.job import JobContext
    from appsec_review.runtime.registry import builtin_registry
    from appsec_review.runtime.selection import active_job_ids
    job = builtin_registry().build(job_id)
    job_config = config.job(job_id)
    if not original and job_config.development is None:
        raise ValueError(f"no development input override is configured for {job_id} in profile {config.profile}")
    claim = _latest_claim(run_root, job_id)
    upstream = (dict(claim.get("upstream_handoffs", {})) if claim is not None else
                selected_handoffs(job, run_root, None, enabled=set(active_job_ids(config, config.jobs))))
    with tempfile.TemporaryDirectory(prefix="appsec-dev-check-") as scratch:
        events = EventLog(Path(scratch) / "events.jsonl", PipelineLog(Path(scratch)), {
            "run_id": run_root.name, "job_id": job_id, "attempt_id": "development-check",
            "trigger": "manual", "orchestrator": "development-check", "dagster_run_id": "-"})
        context = JobContext(
            run_id=run_root.name, attempt_id="development-check", trigger="manual",
            repository_root=config.runtime.repository_root, run_root=run_root,
            attempt_root=run_root / "data/jobs" / job_id / "attempts" / "development-check",
            metadata_root=config.runtime.metadata_dir, orchestration=MappingProxyType({}),
            config=job_config, events=events, tools=config.tools, review_policy=config.review_policy,
            evidence_target_snapshot=(claim or {}).get("evidence_target_snapshot"),
            source_fingerprint=str((claim or {}).get("source_fingerprint", "none")),
            upstream_handoffs=MappingProxyType(upstream),
            optional_prior_handoffs=MappingProxyType(dict((claim or {}).get("optional_prior_handoffs", {}))),
            contract=job.contract, external_input_selection=(claim or {}).get("external_input_selection"))
        records = () if original else job.resolve_development_inputs(context, snapshot=False)
        context = replace(context, development_inputs=records)
        outcome: dict[str, Any] = {"job_id": job_id, "inputs": "original" if original else "development",
                                   "upstream_handoffs": upstream, "development_inputs": list(records)}
        reads = None
        try:
            with input_read_scope(context) as reads:
                outcome["result"] = lookup(run_root, *arguments)
            outcome["status"] = "returned"
        except Exception as error:  # noqa: BLE001 - the lookup's own exception is the answer
            outcome.update(status="raised", exception={"type": type(error).__name__, "message": str(error)},
                           traceback=traceback.format_exc(limit=8))
        outcome["reads"] = reads.document()["reads"] if reads is not None else []
        return outcome
