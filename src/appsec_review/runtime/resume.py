from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from appsec_review.config import AppConfig
from appsec_review.observability import PipelineLog
from appsec_review.runtime.job import Job
from appsec_review.storage import canonical_json, file_sha256


@dataclass(frozen=True, slots=True)
class ResumeDecision:
    job_id: str
    action: str
    reasons: tuple[str, ...]
    handoff_sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"job_id": self.job_id, "action": self.action, "reasons": list(self.reasons),
                "handoff_sha256": self.handoff_sha256}


def job_config_sha256(config: AppConfig, job_id: str) -> str:
    job = config.job(job_id)
    value = {
        "job_id": job.job_id, "name": job.name, "workers": job.workers,
        "settings": dict(job.settings),
        "steps": {
            key: {"workers": step.workers, "settings": dict(step.settings),
                  "tasks": {task_id: {"workers": task.workers, "settings": dict(task.settings)}
                            for task_id, task in step.tasks.items()}}
            for key, step in job.steps.items()
        },
    }
    return hashlib.sha256(canonical_json(value)).hexdigest()


class ResumePlanner:
    def __init__(self, config: AppConfig, run_root: Path, jobs: Sequence[Job], source_fingerprint: str):
        self.config = config
        self.run_root = Path(run_root)
        self.jobs = tuple(jobs)
        self.source_fingerprint = source_fingerprint

    def _accepted(self, job: Job, upstream: Mapping[str, str]) -> tuple[list[str], str | None]:
        latest = self.run_root / "data" / "jobs" / job.job_id / "latest.json"
        if not latest.is_file():
            return ["no accepted handoff"], None
        try:
            pointer = json.loads(latest.read_text(encoding="utf-8"))
            handoff_path = (self.run_root / pointer["handoff_path"]).resolve()
            if self.run_root.resolve() not in handoff_path.parents:
                return ["handoff path escapes run"], None
            if not handoff_path.is_file():
                return ["accepted handoff is missing"], None
            handoff_hash = file_sha256(handoff_path)
            if handoff_hash != pointer["handoff_sha256"]:
                return ["accepted handoff hash changed"], None
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
            return [f"accepted handoff is corrupt: {type(exc).__name__}"], None
        expected = job.identities()
        checks = {
            "handoff schema": (handoff.get("schema"), "appsec-review/job-handoff/1"),
            "status": (handoff.get("status"), "ACCEPTED"),
            "resolved configuration": (handoff.get("resolved_config_sha256"), self.config.source_sha256),
            "job configuration": (handoff.get("job_config_sha256"), job_config_sha256(self.config, job.job_id)),
            "target fingerprint": (handoff.get("source_fingerprint"), self.source_fingerprint),
            "implementation": (handoff.get("implementation_identity"), expected["implementation"]),
            "schema": (handoff.get("schema_identity"), expected["schema"]),
            "validator": (handoff.get("validation_identity"), expected["validation"]),
            "upstream handoffs": (handoff.get("upstream_handoff_sha256", {}), dict(upstream)),
            "tool": (handoff.get("tool_identity"), {"python": os.sys.version.split()[0]}),
        }
        reasons = [f"{label} identity changed" for label, pair in checks.items() if pair[0] != pair[1]]
        if not handoff.get("artifacts"):
            reasons.append("accepted handoff has no artifact identities")
        for artifact in handoff.get("artifacts", []):
            try:
                path = (self.run_root / artifact["path"]).resolve()
                if self.run_root.resolve() not in path.parents or not path.is_file():
                    reasons.append(f"artifact missing: {artifact.get('path')}")
                elif file_sha256(path) != artifact["sha256"]:
                    reasons.append(f"artifact changed: {artifact.get('path')}")
            except (KeyError, OSError):
                reasons.append("artifact identity is corrupt")
        return reasons, handoff_hash

    def plan(self, *, force_from: str | None = None, emit_event: bool = True) -> tuple[ResumeDecision, ...]:
        ids = [job.job_id for job in self.jobs]
        if force_from is not None and force_from not in ids:
            raise ValueError(f"force-from job is not in graph: {force_from}")
        upstream: dict[str, str] = {}
        invalidated = False
        decisions: list[ResumeDecision] = []
        for job in self.jobs:
            if force_from == job.job_id:
                invalidated = True
                decision = ResumeDecision(job.job_id, "RUN", ("forced rerun from named job",))
            elif invalidated:
                decision = ResumeDecision(job.job_id, "INVALIDATE", ("transitive downstream invalidation",))
            else:
                reasons, handoff_hash = self._accepted(job, upstream)
                if reasons:
                    invalidated = True
                    decision = ResumeDecision(job.job_id, "RUN", tuple(reasons))
                else:
                    decision = ResumeDecision(job.job_id, "REUSE", ("all declared identities and artifacts match",), handoff_hash)
                    upstream[job.job_id] = str(handoff_hash)
            decisions.append(decision)
        if emit_event:
            PipelineLog(self.run_root).write("RESUME_PLANNED", run_id=self.run_root.name,
                message="resume decisions computed", details={"decisions": [item.as_dict() for item in decisions]})
        return tuple(decisions)
