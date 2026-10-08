from __future__ import annotations

from datetime import datetime, timezone
import traceback
from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.config import AppConfig
from appsec_review.observability import EventLog
from appsec_review.runtime.job import Job, JobContext
from appsec_review.storage import RunStore, atomic_bytes, atomic_json, file_sha256


class JobRunner:
    def __init__(self, config: AppConfig):
        self.config = config
        self.runs = RunStore(config.runtime.runs_dir)

    def _bind_configuration(self, run_root) -> None:
        destination = run_root / "data" / "configuration"
        manifest_path = destination / "manifest.json"
        if manifest_path.exists():
            import json

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("source_sha256") != self.config.source_sha256:
                raise ValueError("run is already bound to a different configuration")
            if file_sha256(destination / "appsec-review.toml") != self.config.source_sha256:
                raise ValueError("run-owned configuration hash mismatch")
            return
        destination.mkdir(parents=True, exist_ok=True)
        atomic_bytes(destination / "appsec-review.toml", self.config.source_path.read_bytes())
        atomic_json(manifest_path, {
            "schema": "appsec-review/run-configuration/1",
            "source_sha256": self.config.source_sha256,
        })

    def run(
        self,
        job: Job,
        *,
        run_id: str | None = None,
        trigger: str = "manual",
        orchestration: Mapping[str, str] | None = None,
        now: datetime | None = None,
    ) -> Mapping[str, Any]:
        instant = now or datetime.now(timezone.utc)
        if run_id is None:
            run_id, run_root = self.runs.create(instant)
        else:
            run_root = self.runs.resolve(run_id)
        self._bind_configuration(run_root)
        job_config = self.config.job(job.job_id)
        if job.name != job_config.name:
            raise ValueError(f"job name mismatch: code={job.name} config={job_config.name}")

        attempts = run_root / "data" / "jobs" / job.job_id / "attempts"
        attempts.mkdir(parents=True, exist_ok=True)
        for serial in range(1, 10_000):
            attempt_id = f"attempt_{serial:04d}"
            attempt_root = attempts / attempt_id
            try:
                attempt_root.mkdir()
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError(f"attempt id space exhausted for {run_id}/{job.job_id}")

        events = EventLog(attempt_root / "logs" / "events.jsonl")
        orchestration = dict(orchestration or {})
        if any(not isinstance(key, str) or not isinstance(value, str)
               for key, value in orchestration.items()):
            raise ValueError("orchestration correlation must contain string keys and values")
        context = JobContext(
            run_id=run_id,
            attempt_id=attempt_id,
            trigger=trigger,
            repository_root=self.config.runtime.repository_root,
            run_root=run_root,
            attempt_root=attempt_root,
            metadata_root=self.config.runtime.metadata_dir,
            orchestration=MappingProxyType(orchestration),
            config=job_config,
            events=events,
        )
        started = instant.isoformat()
        atomic_json(attempt_root / "status.json", {
            "job_id": job.job_id,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "trigger": trigger,
            "orchestration": orchestration,
            "status": "RUNNING",
            "started_at": started,
        })
        events.write("JOB_STARTED", job_id=job.job_id, run_id=run_id, attempt_id=attempt_id,
                     trigger=trigger, orchestration=orchestration)
        try:
            result = dict(job.execute(context))
            atomic_json(attempt_root / "result.json", result)
            if result.get("status") == "FAILED":
                failed = ", ".join(result.get("failed_units", ())) or "one or more units"
                raise RuntimeError(f"job reported partial failure: {failed}")
            completed = datetime.now(timezone.utc).isoformat()
            status = {
                "job_id": job.job_id,
                "run_id": run_id,
                "attempt_id": attempt_id,
                "trigger": trigger,
                "orchestration": orchestration,
                "status": "SUCCEEDED",
                "started_at": started,
                "completed_at": completed,
            }
            atomic_json(attempt_root / "status.json", status)
            events.write("JOB_SUCCEEDED", job_id=job.job_id, run_id=run_id, attempt_id=attempt_id)
            return {"status": status, "result": result, "attempt_root": str(attempt_root)}
        except BaseException as exc:
            failed = datetime.now(timezone.utc).isoformat()
            status = {
                "job_id": job.job_id,
                "run_id": run_id,
                "attempt_id": attempt_id,
                "trigger": trigger,
                "orchestration": orchestration,
                "status": "FAILED",
                "started_at": started,
                "completed_at": failed,
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
            atomic_json(attempt_root / "status.json", status)
            (attempt_root / "logs" / "traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
            events.write("JOB_FAILED", job_id=job.job_id, run_id=run_id, attempt_id=attempt_id,
                         error_type=type(exc).__name__)
            raise
