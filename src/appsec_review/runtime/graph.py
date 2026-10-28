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
from appsec_review.runtime.resume import ResumeDecision, ResumePlanner
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import FileLock, atomic_json


# The last job that runs before a deferred target fingerprint exists: it creates the target.
ACQUISITION_JOB = "job_target_acquisition"


class GraphRunner:
    """Run or resume an ordered semantic-job graph under one application claim lock.

    With ``source_fingerprint=None`` the target does not exist yet: the leading jobs up to and
    including :data:`ACQUISITION_JOB` run target-independently, then the composed target root is
    fingerprinted and the remaining jobs are planned and run against it.
    """

    def __init__(self, config: AppConfig, jobs: Sequence[Job]):
        self.config = config
        self.jobs = tuple(jobs)
        if len({job.job_id for job in jobs}) != len(jobs):
            raise ValueError("graph job ids must be unique")

    def _split(self) -> int:
        ids = [job.job_id for job in self.jobs]
        if ACQUISITION_JOB not in ids:
            raise ValueError(f"a deferred target fingerprint requires {ACQUISITION_JOB} in the graph")
        position = ids.index(ACQUISITION_JOB) + 1
        if any(job.propagate_handoff or not job.always_execute for job in self.jobs[:position]):
            raise ValueError("jobs before a deferred target fingerprint must be non-propagating live gates")
        return position

    def plan(self, run_id: str, source_fingerprint: str | None, *, force_from: str | None = None,
             target_root: Path | None = None):
        """Explain resume decisions; ``None`` plans the target-reading suffix against the current
        target, and the leading live gates always run."""
        run_root = JobRunner(self.config).runs.resolve(run_id)
        if source_fingerprint is not None:
            return ResumePlanner(self.config, run_root, self.jobs, source_fingerprint,
                                 target_root=target_root).plan(force_from=force_from)
        position = self._split()
        head = ResumePlanner(self.config, run_root, self.jobs[:position], "none").plan(
            force_from=force_from if force_from in {job.job_id for job in self.jobs[:position]} else None,
            emit_event=False)
        from appsec_review.jobs.cataloging import source_fingerprint as fingerprint_of
        if target_root is None or not Path(target_root).is_dir():
            tail = tuple(ResumeDecision(job.job_id, "RUN", ("target is not acquired yet",))
                         for job in self.jobs[position:])
            return head + tail
        suffix_force = force_from if force_from in {job.job_id for job in self.jobs[position:]} else None
        return head + ResumePlanner(self.config, run_root, self.jobs[position:], fingerprint_of(target_root),
                                    target_root=target_root).plan(
            force_from=suffix_force, invalidated=force_from is not None and suffix_force is None)

    def run(
        self,
        *,
        target_root: Path,
        source_fingerprint: str | None,
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
        deferred = source_fingerprint is None
        position = self._split() if deferred else 0
        with FileLock(run_root / "data" / "resume.lock"):
            runner._bind_configuration(run_root)
            graph_started = datetime.now(timezone.utc)
            PipelineLog(run_root).write("RUN_STARTED", run_id=run_id, trigger=trigger,
                orchestrator=dict(orchestration or {}).get("system", "application"),
                details={"source_fingerprint": source_fingerprint or "deferred"})
            PipelineLog(run_root).write("GRAPH_STARTED", run_id=run_id, trigger=trigger,
                orchestrator=dict(orchestration or {}).get("system", "application"),
                details={"source_fingerprint": source_fingerprint or "deferred"})
            head_ids = {job.job_id for job in self.jobs[:position]}
            decisions: list[ResumeDecision] = list(ResumePlanner(
                self.config, run_root, self.jobs[:position], "none").plan(
                force_from=force_from if force_from in head_ids else None)) if deferred else list(
                ResumePlanner(self.config, run_root, self.jobs, source_fingerprint,
                              target_root=target_root).plan(force_from=force_from))
            upstream: dict[str, str] = {}
            completed_handoffs: dict[str, str] = {}
            outcomes: dict[str, Any] = {}
            try:
                index = 0
                while index < len(self.jobs):
                    if deferred and index == position:
                        # The acquisition gate created or re-verified the target; bind it now.
                        from appsec_review.jobs.cataloging import source_fingerprint as fingerprint_of
                        source_fingerprint = fingerprint_of(target_root)
                        PipelineLog(run_root).write("TARGET_FINGERPRINTED", run_id=run_id, trigger=trigger,
                            orchestrator=dict(orchestration or {}).get("system", "application"),
                            details={"source_fingerprint": source_fingerprint})
                        suffix_force = force_from if force_from not in head_ids else None
                        decisions.extend(ResumePlanner(
                            self.config, run_root, self.jobs[position:], source_fingerprint,
                            target_root=target_root).plan(
                            force_from=suffix_force, initial_upstream=upstream,
                            invalidated=force_from is not None and suffix_force is None))
                    job, decision = self.jobs[index], decisions[index]
                    index += 1
                    job_target = None if deferred and index <= position else target_root
                    job_fingerprint = "none" if deferred and index <= position else source_fingerprint
                    if decision.action == "REUSE":
                        completed_handoffs[job.job_id] = str(decision.handoff_sha256)
                        if job.propagate_handoff:
                            upstream[job.job_id] = str(decision.handoff_sha256)
                        pointer = json.loads((run_root / "data/jobs" / job.job_id / "latest.json").read_text())
                        handoff = json.loads((run_root / pointer["handoff_path"]).read_text())
                        outcomes[job.job_id] = {"decision": decision.as_dict(),
                                                "attempt_id": handoff["attempt_id"],
                                                "handoff_sha256": decision.handoff_sha256,
                                                "attempt_root": str((run_root / pointer["handoff_path"]).parent)}
                        continue
                    outcome = runner.run(job, run_id=run_id, trigger=trigger, orchestration=orchestration,
                        target_root=job_target, source_fingerprint=job_fingerprint,
                        upstream_handoffs=upstream)
                    completed_handoffs[job.job_id] = str(outcome["handoff_sha256"])
                    if job.propagate_handoff:
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
                details={"handoffs": completed_handoffs, "completion_status": graph_status,
                         "duration_ms": max(0, int((datetime.now(timezone.utc) - graph_started).total_seconds() * 1000))})
            PipelineLog(run_root).write("RUN_COMPLETED", run_id=run_id, trigger=trigger,
                orchestrator=dict(orchestration or {}).get("system", "application"),
                details={"completion_status": graph_status, "handoffs": completed_handoffs})
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
                    "handoff_sha256": completed_handoffs,
                })
                orchestration_receipt = str(receipt_path)
            return {"run_id": run_id, "status": graph_status,
                    "decisions": [decision.as_dict() for decision in decisions], "jobs": outcomes,
                    "orchestration_receipt": orchestration_receipt}
