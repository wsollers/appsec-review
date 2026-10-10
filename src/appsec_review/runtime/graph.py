from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

from appsec_review.config import AppConfig
from appsec_review.observability import PipelineLog
from appsec_review.runtime.job import Job
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import FileLock, atomic_json


class GraphRunner:
    """Run or resume an ordered semantic-job graph under one application claim lock."""

    def __init__(self, config: AppConfig, jobs: Sequence[Job]):
        self.config = config
        self.jobs = tuple(jobs)
        if len({job.job_id for job in jobs}) != len(jobs):
            raise ValueError("graph job ids must be unique")

    def plan(self, run_id: str, source_fingerprint: str, *, force_from: str | None = None,
             target_root: Path | None = None):
        run_root = JobRunner(self.config).runs.resolve(run_id)
        return ResumePlanner(self.config, run_root, self.jobs, source_fingerprint,
                             target_root=target_root).plan(force_from=force_from)

    def run(
        self,
        *,
        target_root: Path,
        source_fingerprint: str,
        run_id: str | None = None,
        force_from: str | None = None,
        trigger: str = "manual",
        orchestration: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        runner = JobRunner(self.config)
        correlation = dict(orchestration or {})
        if correlation.get("system") and correlation.get("run_id") and any(
            not re.fullmatch(r"[A-Za-z0-9_.-]+", correlation[key]) for key in ("system", "run_id")
        ):
            raise ValueError("orchestration identity is not safe for a receipt path")
        if run_id is None:
            run_id, run_root = runner.runs.create(datetime.now(timezone.utc))
        else:
            run_root = runner.runs.resolve(run_id)
        with FileLock(run_root / "data" / "resume.lock"):
            runner._bind_configuration(run_root)
            graph_started = datetime.now(timezone.utc)
            PipelineLog(run_root).write("RUN_STARTED", run_id=run_id, trigger=trigger,
                orchestrator=dict(orchestration or {}).get("system", "application"),
                details={"source_fingerprint": source_fingerprint})
            PipelineLog(run_root).write("GRAPH_STARTED", run_id=run_id, trigger=trigger,
                orchestrator=dict(orchestration or {}).get("system", "application"),
                details={"source_fingerprint": source_fingerprint})
            decisions = ResumePlanner(self.config, run_root, self.jobs, source_fingerprint,
                                      target_root=target_root).plan(force_from=force_from)
            upstream: dict[str, str] = {}
            outcomes: dict[str, Any] = {}
            execute = False
            try:
                for job, decision in zip(self.jobs, decisions, strict=True):
                    if decision.action == "REUSE" and not execute:
                        upstream[job.job_id] = str(decision.handoff_sha256)
                        pointer = json.loads((run_root / "data/jobs" / job.job_id / "latest.json").read_text())
                        handoff = json.loads((run_root / pointer["handoff_path"]).read_text())
                        outcomes[job.job_id] = {"decision": decision.as_dict(),
                                                "attempt_id": handoff["attempt_id"],
                                                "handoff_sha256": decision.handoff_sha256,
                                                "attempt_root": str((run_root / pointer["handoff_path"]).parent)}
                        continue
                    execute = True
                    outcome = runner.run(job, run_id=run_id, trigger=trigger, orchestration=orchestration,
                        target_root=target_root, source_fingerprint=source_fingerprint,
                        upstream_handoffs=upstream)
                    upstream[job.job_id] = str(outcome["handoff_sha256"])
                    outcomes[job.job_id] = {"decision": decision.as_dict(), **outcome}
            except BaseException as exc:
                PipelineLog(run_root).write("GRAPH_FAILED", run_id=run_id, level="ERROR", trigger=trigger,
                    orchestrator=dict(orchestration or {}).get("system", "application"),
                    message="application graph stopped at failed job",
                    details={"error_type": type(exc).__name__, "completed_handoffs": upstream})
                raise
            graph_status = ("COMPLETED_WITH_GAPS" if any(
                value.get("status", {}).get("status") == "COMPLETED_WITH_GAPS"
                for value in outcomes.values()) else "SUCCEEDED")
            PipelineLog(run_root).write(
                "GRAPH_COMPLETED_WITH_GAPS" if graph_status == "COMPLETED_WITH_GAPS" else "GRAPH_SUCCEEDED",
                run_id=run_id, trigger=trigger,
                orchestrator=dict(orchestration or {}).get("system", "application"),
                details={"handoffs": upstream, "completion_status": graph_status,
                         "duration_ms": max(0, int((datetime.now(timezone.utc) - graph_started).total_seconds() * 1000))})
            PipelineLog(run_root).write("RUN_COMPLETED", run_id=run_id, trigger=trigger,
                orchestrator=dict(orchestration or {}).get("system", "application"),
                details={"completion_status": graph_status, "handoffs": upstream})
            orchestration_receipt = None
            if correlation.get("system") and correlation.get("run_id"):
                receipt_path = (run_root / "data" / "orchestration" / correlation["system"] /
                                f"{correlation['run_id']}.json")
                atomic_json(receipt_path, {
                    "schema": "appsec-review/orchestration-receipt/1",
                    "status": "SUCCEEDED",
                    "application_run_id": run_id,
                    "orchestrator": correlation,
                    "decisions": [decision.as_dict() for decision in decisions],
                    "handoff_sha256": upstream,
                })
                orchestration_receipt = str(receipt_path)
            return {"run_id": run_id, "status": graph_status,
                    "decisions": [decision.as_dict() for decision in decisions], "jobs": outcomes,
                    "orchestration_receipt": orchestration_receipt}
