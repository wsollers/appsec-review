from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import traceback
from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.config import AppConfig
from appsec_review.observability import EventLog, PipelineLog
from appsec_review.runtime.resume import job_config_sha256
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
            "sources": [{"path": str(self.config.source_path), "sha256": self.config.source_sha256}],
        })

    def run(
        self,
        job: Job,
        *,
        run_id: str | None = None,
        trigger: str = "manual",
        orchestration: Mapping[str, str] | None = None,
        now: datetime | None = None,
        target_root: Path | None = None,
        source_fingerprint: str = "none",
        upstream_handoffs: Mapping[str, str] | None = None,
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

        orchestration = dict(orchestration or {})
        if any(not isinstance(key, str) or not isinstance(value, str)
               for key, value in orchestration.items()):
            raise ValueError("orchestration correlation must contain string keys and values")
        pipeline = PipelineLog(run_root)
        events = EventLog(attempt_root / "logs" / "events.jsonl", pipeline, {
            "run_id": run_id, "job_id": job.job_id, "attempt_id": attempt_id,
            "trigger": trigger, "orchestrator": orchestration.get("system", "application"),
        })
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
            target_root=target_root.resolve() if target_root else None,
            source_fingerprint=source_fingerprint,
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
            result_path = attempt_root / "result.json"
            identities = job.identities()
            artifacts = [{
                "path": result_path.relative_to(run_root).as_posix(),
                "sha256": file_sha256(result_path),
                "size_bytes": result_path.stat().st_size,
            }]
            def collect(value: Any) -> None:
                if isinstance(value, Mapping):
                    if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                        candidate = (run_root / value["path"]).resolve()
                        if run_root.resolve() in candidate.parents and candidate.is_file():
                            actual_sha256 = file_sha256(candidate)
                            if actual_sha256 != value["sha256"]:
                                raise ValueError(f"result artifact hash mismatch: {value['path']}")
                            entry = {"path": candidate.relative_to(run_root).as_posix(),
                                     "sha256": actual_sha256, "size_bytes": candidate.stat().st_size}
                            if entry["path"] not in {item["path"] for item in artifacts}:
                                artifacts.append(entry)
                    for child in value.values():
                        collect(child)
                elif isinstance(value, (list, tuple)):
                    for child in value:
                        collect(child)
            collect(result)
            handoff_outputs = {}
            for unit_id, output in result.get("outputs", {}).items():
                if isinstance(output, Mapping):
                    handoff_outputs[unit_id] = {
                        key: output[key] for key in (
                            "schema", "artifact", "identity", "pointer", "metadata_path",
                            "item_count", "gaps", "index_manifest",
                        ) if key in output
                    }
            handoff = {
                "schema": "appsec-review/job-handoff/1",
                "job_id": job.job_id,
                "attempt_id": attempt_id,
                "status": "ACCEPTED",
                "outputs": handoff_outputs,
                "artifacts": artifacts,
                "upstream_handoff_sha256": dict(upstream_handoffs or {}),
                "resolved_config_sha256": self.config.source_sha256,
                "job_config_sha256": job_config_sha256(self.config, job.job_id),
                "source_fingerprint": source_fingerprint,
                "implementation_identity": identities["implementation"],
                "schema_identity": identities["schema"],
                "validation_identity": identities["validation"],
                "started_at": started,
                "completed_at": completed,
                "resolving_paths": {"attempt": attempt_root.relative_to(run_root).as_posix(),
                                    "result": result_path.relative_to(run_root).as_posix()},
                "tool_identity": {"python": os.sys.version.split()[0]},
            }
            handoff_path = attempt_root / "handoff.json"
            atomic_json(handoff_path, handoff)
            handoff_hash = file_sha256(handoff_path)
            manifests = [output["index_manifest"] for output in result.get("outputs", {}).values()
                         if isinstance(output, Mapping) and isinstance(output.get("index_manifest"), Mapping)]
            if manifests:
                manifest = manifests[-1]
                manifest_path = (run_root / str(manifest.get("path", ""))).resolve()
                if run_root.resolve() not in manifest_path.parents or not manifest_path.is_file():
                    raise ValueError("index manifest path escapes run or is unavailable")
                if file_sha256(manifest_path) != manifest.get("sha256"):
                    raise ValueError("index manifest artifact hash mismatch")
                atomic_json(run_root / "data" / "indices" / "accepted.json", {
                    "schema": "appsec-review/accepted-index-set/1",
                    "run_id": run_id,
                    "handoff_path": handoff_path.relative_to(run_root).as_posix(),
                    "handoff_sha256": handoff_hash,
                    "manifest_path": manifest_path.relative_to(run_root).as_posix(),
                    "manifest_sha256": manifest["sha256"],
                })
            events.write("HANDOFF_ACCEPTED", handoff_sha256=handoff_hash,
                         handoff_path=handoff_path.relative_to(run_root).as_posix())
            latest = attempt_root.parent.parent / "latest.json"
            atomic_json(latest, {
                "schema": "appsec-review/latest-handoff/1",
                "attempt_id": attempt_id,
                "handoff_path": handoff_path.relative_to(run_root).as_posix(),
                "handoff_sha256": handoff_hash,
            })
            return {"status": status, "result": result, "attempt_root": str(attempt_root),
                    "handoff": handoff, "handoff_sha256": handoff_hash}
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
