from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import traceback
import time
from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.config import AppConfig
from appsec_review.observability import EventLog, PipelineLog, write_run_metrics
from appsec_review.retrieval.index import MANIFEST_SCHEMA as RETRIEVAL_MANIFEST_SCHEMA
from appsec_review.runtime.resume import ResumePlanner, job_config_sha256
from appsec_review.runtime.job import Job, JobContext
from appsec_review.runtime.units import UnitContext, UnitExecutor
from appsec_review.storage import RunStore, FileLock, LockUnavailable, atomic_bytes, atomic_json, file_sha256


def _accepted_retrieval_manifest(run_root: Path, manifests: list[Mapping[str, Any]]):
    selected = None
    for manifest in manifests:
        manifest_path = (run_root / str(manifest.get("path", ""))).resolve()
        if run_root.resolve() not in manifest_path.parents or not manifest_path.is_file():
            raise ValueError("index manifest path escapes run or is unavailable")
        if file_sha256(manifest_path) != manifest.get("sha256"):
            raise ValueError("index manifest artifact hash mismatch")
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        if document.get("schema") == RETRIEVAL_MANIFEST_SCHEMA:
            selected = manifest, manifest_path
    return selected


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
            if manifest.get("resolved_sha256") != self.config.resolved_sha256:
                raise ValueError("run is already bound to a different configuration")
            if file_sha256(destination / "appsec-review.toml") != manifest.get("source_sha256"):
                raise ValueError("run-owned configuration hash mismatch")
            if file_sha256(destination / "resolved.json") != self.config.resolved_sha256:
                raise ValueError("run-owned resolved configuration hash mismatch")
            return
        destination.mkdir(parents=True, exist_ok=True)
        atomic_bytes(destination / "appsec-review.toml", self.config.source_path.read_bytes())
        atomic_bytes(destination / "resolved.json", self.config.resolved_json)
        atomic_json(manifest_path, {
            "schema": "appsec-review/run-configuration/2",
            "source_sha256": self.config.source_sha256,
            "resolved_sha256": self.config.resolved_sha256,
            "sources": [{"path": str(self.config.source_path), "sha256": self.config.source_sha256}],
            "resolved": {"path": "resolved.json", "sha256": self.config.resolved_sha256},
        })

    def _context_from_claim(self, job: Job, claim: Mapping[str, Any]) -> JobContext:
        run_root = self.runs.resolve(str(claim["run_id"]))
        attempt_root = (run_root / str(claim["attempt_path"])).resolve()
        if run_root.resolve() not in attempt_root.parents or not attempt_root.is_dir():
            raise ValueError("attempt claim escapes the application run")
        orchestration = dict(claim.get("orchestration", {}))
        events = EventLog(attempt_root / "logs" / "events.jsonl", PipelineLog(run_root), {
            "run_id": claim["run_id"], "job_id": job.job_id, "attempt_id": claim["attempt_id"],
            "trigger": claim["trigger"], "orchestrator": orchestration.get("system", "application"),
            "dagster_run_id": orchestration.get("run_id", "-"),
        })
        target = claim.get("target_root")
        return JobContext(
            run_id=str(claim["run_id"]), attempt_id=str(claim["attempt_id"]),
            trigger=str(claim["trigger"]), repository_root=self.config.runtime.repository_root,
            run_root=run_root, attempt_root=attempt_root, metadata_root=self.config.runtime.metadata_dir,
            orchestration=MappingProxyType(orchestration), config=self.config.job(job.job_id), events=events,
            tools=self.config.tools,
            target_root=Path(str(target)).resolve() if target else None,
            source_fingerprint=str(claim.get("source_fingerprint", "none")),
        )

    def begin_attempt(
        self, job: Job, *, run_id: str | None = None, trigger: str = "manual",
        orchestration: Mapping[str, str] | None = None, now: datetime | None = None,
        target_root: Path | None = None, source_fingerprint: str = "none",
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
        if not job.units:
            raise ValueError(f"job does not expose orchestratable units: {job.job_id}")
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
        correlation = dict(orchestration or {})
        if any(not isinstance(key, str) or not isinstance(value, str) for key, value in correlation.items()):
            raise ValueError("orchestration correlation must contain string keys and values")
        claim = {
            "schema": "appsec-review/attempt-claim/1", "run_id": run_id,
            "job_id": job.job_id, "attempt_id": attempt_id,
            "attempt_path": attempt_root.relative_to(run_root).as_posix(), "trigger": trigger,
            "orchestration": correlation,
            "target_root": str(target_root.resolve()) if target_root else None,
            "source_fingerprint": source_fingerprint,
            "upstream_handoffs": dict(upstream_handoffs or {}),
            "started_at": instant.isoformat(),
        }
        atomic_json(attempt_root / "claim.json", claim)
        context = self._context_from_claim(job, claim)
        records, _ = PipelineLog(run_root).read()
        if not any(item.get("event_type") == "RUN_STARTED" for item in records):
            PipelineLog(run_root).write("RUN_STARTED", run_id=run_id, trigger=trigger,
                                        orchestrator=correlation.get("system", "application"),
                                        details={"dagster_run_id": correlation.get("run_id")})
            PipelineLog(run_root).write("GRAPH_STARTED", run_id=run_id, trigger=trigger,
                                        orchestrator=correlation.get("system", "application"),
                                        details={"dagster_run_id": correlation.get("run_id")})
        status = {key: claim[key] for key in ("job_id", "run_id", "attempt_id", "trigger", "orchestration", "started_at")}
        atomic_json(attempt_root / "status.json", {**status, "status": "RUNNING"})
        context.events.write("JOB_STARTED", job_id=job.job_id, run_id=run_id, attempt_id=attempt_id,
                             trigger=trigger, orchestration=correlation)
        try:
            for validator in job.input_validators:
                validator(context, None)
        except BaseException as exc:
            self._fail_attempt(context, claim, exc)
            raise
        return claim

    def begin_or_reuse_attempt(self, job: Job, **kwargs: Any) -> Mapping[str, Any]:
        run_id = kwargs.get("run_id")
        upstream = dict(kwargs.get("upstream_handoffs") or {})
        source_fingerprint = str(kwargs.get("source_fingerprint", "none"))
        if run_id is not None:
            run_root = self.runs.resolve(str(run_id))
            reasons, handoff_hash = ResumePlanner(
                self.config, run_root, (job,), source_fingerprint).accepted(job, upstream)
            if not reasons and handoff_hash is not None:
                pointer = json.loads((run_root / "data" / "jobs" / job.job_id / "latest.json").read_text(encoding="utf-8"))
                handoff_path = (run_root / pointer["handoff_path"]).resolve()
                handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
                claim = {"schema": "appsec-review/attempt-claim/1", "run_id": str(run_id),
                         "job_id": job.job_id, "attempt_id": handoff["attempt_id"],
                         "attempt_path": str(handoff["resolving_paths"]["attempt"]),
                         "trigger": str(kwargs.get("trigger", "manual")),
                         "orchestration": dict(kwargs.get("orchestration") or {}),
                         "target_root": str(kwargs["target_root"].resolve()) if kwargs.get("target_root") else None,
                         "source_fingerprint": source_fingerprint, "upstream_handoffs": upstream,
                         "started_at": handoff["started_at"], "reused": True,
                         "handoff_path": handoff_path.relative_to(run_root).as_posix(),
                         "handoff_sha256": handoff_hash}
                PipelineLog(run_root).write("JOB_REUSED", run_id=str(run_id), job_id=job.job_id,
                                            attempt_id=handoff["attempt_id"],
                                            trigger=str(kwargs.get("trigger", "manual")),
                                            orchestrator=dict(kwargs.get("orchestration") or {}).get("system", "application"),
                                            details={"handoff_sha256": handoff_hash,
                                                     "dagster_run_id": dict(kwargs.get("orchestration") or {}).get("run_id")})
                return claim
        return self.begin_attempt(job, **kwargs)

    @staticmethod
    def _unit(job: Job, unit_id: str):
        for unit in job.units:
            if unit.unit_id == unit_id:
                return unit
        raise KeyError(f"unknown job unit: {job.job_id}.{unit_id}")

    @staticmethod
    def _with_lock(path: Path, operation) -> None:
        deadline = time.monotonic() + 30
        while True:
            try:
                with FileLock(path):
                    operation()
                return
            except LockUnavailable:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)

    def _start_step(self, job: Job, context: JobContext, step_id: str) -> None:
        step_root = context.attempt_root / "steps" / step_id
        marker = step_root / "lifecycle.json"
        def write() -> None:
            if marker.exists():
                return
            started = datetime.now(timezone.utc).isoformat()
            atomic_json(marker, {"step_id": step_id, "status": "STARTED", "started_at": started})
            context.events.write("STEP_STARTED", unit_id=f"{step_id}.-", step_id=step_id)
        self._with_lock(step_root / "lifecycle.lock", write)

    def _complete_step(self, job: Job, context: JobContext, step_id: str) -> None:
        step_root = context.attempt_root / "steps" / step_id
        marker = step_root / "lifecycle.json"
        def write() -> None:
            current = json.loads(marker.read_text(encoding="utf-8")) if marker.exists() else {}
            if current.get("status") != "STARTED":
                return
            step_units = [unit for unit in job.units if unit.unit_id.startswith(step_id + ".")]
            receipts = []
            dispositions = []
            for unit in step_units:
                _, task_id = unit.unit_id.split(".")
                root = step_root / "tasks" / task_id
                if not (root / "status.json").is_file() or not (root / "result.json").is_file():
                    return
                receipt = json.loads((root / "status.json").read_text(encoding="utf-8"))
                if receipt.get("status") != "SUCCEEDED":
                    return
                receipts.append(receipt)
                output = json.loads((root / "result.json").read_text(encoding="utf-8"))
                if output.get("terminal_status"):
                    dispositions.append(str(output["terminal_status"]))
            completed = datetime.now(timezone.utc).isoformat()
            status = ("COMPLETED_WITH_GAPS" if any(value not in {"SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}
                                                    for value in dispositions) else "SUCCEEDED")
            started_at = datetime.fromisoformat(current["started_at"])
            duration = max(0, int((datetime.fromisoformat(completed) - started_at).total_seconds() * 1000))
            atomic_json(marker, {**current, "status": status, "completed_at": completed,
                                 "duration_ms": duration, "dispositions": dispositions})
            context.events.write(f"STEP_{status}", unit_id=f"{step_id}.-", step_id=step_id,
                                 completion_status=status, duration_ms=duration,
                                 dispositions=dispositions)
        self._with_lock(step_root / "lifecycle.lock", write)

    def execute_or_reuse_unit(self, job: Job, claim: Mapping[str, Any], unit_id: str) -> Mapping[str, Any]:
        context = self._context_from_claim(job, claim)
        if claim.get("reused"):
            result = json.loads((context.attempt_root / "result.json").read_text(encoding="utf-8"))
            output = dict(result.get("outputs", {}).get(unit_id, {}))
            context.events.write("TASK_REUSED", unit_id=unit_id, producer=output.get("tool_id"),
                                 disposition=output.get("terminal_status"),
                                 shard_identity=output.get("index_identity"),
                                 prior_attempt_id=context.attempt_id)
            return output
        unit = self._unit(job, unit_id)
        step_id, task_id = unit.unit_id.split(".")
        unit_root = context.attempt_root / "steps" / step_id / "tasks" / task_id
        status_path, result_path = unit_root / "status.json", unit_root / "result.json"
        if status_path.is_file() and result_path.is_file():
            status = json.loads(status_path.read_text(encoding="utf-8"))
            if status.get("status") == "SUCCEEDED" and status.get("result_sha256") == file_sha256(result_path):
                result = json.loads(result_path.read_text(encoding="utf-8"))
                context.events.write("TASK_REUSED", unit_id=unit_id,
                                     producer=result.get("tool_id"), disposition=result.get("terminal_status"),
                                     shard_identity=result.get("index_identity"))
                return result
        units_by_id = {candidate.unit_id: candidate for candidate in job.units}
        required_outputs: set[str] = set()
        stack = list(unit.dependencies)
        while stack:
            dependency = stack.pop()
            if dependency in required_outputs:
                continue
            required_outputs.add(dependency)
            dependency_unit = units_by_id.get(dependency)
            if dependency_unit is None:
                raise ValueError(f"unit declares an unknown dependency: {dependency}")
            stack.extend(dependency_unit.dependencies)
        outputs: dict[str, Mapping[str, Any]] = {}
        for dependency_unit in job.units:
            dependency = dependency_unit.unit_id
            if dependency not in required_outputs:
                continue
            dependency_step, dependency_task = dependency.split(".")
            root = context.attempt_root / "steps" / dependency_step / "tasks" / dependency_task
            if not (root / "status.json").is_file():
                raise ValueError(f"dependency receipt is unavailable: {dependency}")
            receipt = json.loads((root / "status.json").read_text(encoding="utf-8"))
            result_file = root / "result.json"
            if receipt.get("status") != "SUCCEEDED":
                raise ValueError(f"dependency receipt is unavailable: {dependency}")
            if not result_file.is_file() or receipt.get("result_sha256") != file_sha256(result_file):
                raise ValueError(f"completed unit result changed: {dependency}")
            outputs[dependency] = json.loads(result_file.read_text(encoding="utf-8"))
        missing = sorted(required_outputs - set(outputs))
        if missing:
            raise ValueError(f"dependency results are unavailable: {missing}")
        unit_root.mkdir(parents=True, exist_ok=True)
        self._start_step(job, context, step_id)
        started = datetime.now(timezone.utc).isoformat()
        running = {"unit_id": unit_id, "step_id": step_id, "task_id": task_id, "status": "RUNNING",
                   "started_at": started, "dependencies": list(unit.dependencies),
                   "dagster_run_id": dict(context.orchestration).get("run_id"),
                   "dagster_node": dict(context.orchestration).get("node", unit_id)}
        atomic_json(status_path, running)
        context.events.write("TASK_STARTED", unit_id=unit_id)
        unit_context = UnitContext(context, unit_id, step_id, task_id, unit_root, MappingProxyType(outputs))
        try:
            for validator in unit.input_validators:
                validator(unit_context, None)
            result = dict(unit.handler(unit_context))
            for validator in unit.output_validators:
                validator(unit_context, result)
            atomic_json(result_path, result)
            completed = datetime.now(timezone.utc).isoformat()
            receipt = {**running, "status": "SUCCEEDED", "completed_at": completed,
                       "result_sha256": file_sha256(result_path),
                       "producer": result.get("tool_id"), "disposition": result.get("terminal_status"),
                       "shard_identity": result.get("index_identity")}
            atomic_json(status_path, receipt)
            disposition = result.get("terminal_status")
            task_event = ("TASK_COMPLETED_WITH_GAPS" if disposition not in {None, "SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"}
                          else "TASK_SUCCEEDED")
            context.events.write(task_event, unit_id=unit_id, producer=result.get("tool_id"),
                                 disposition=result.get("terminal_status"),
                                 shard_identity=result.get("index_identity"),
                                 duration_ms=max(0, int((datetime.fromisoformat(completed) -
                                                         datetime.fromisoformat(started)).total_seconds() * 1000)))
            self._complete_step(job, context, step_id)
            return result
        except BaseException as exc:
            failed = datetime.now(timezone.utc).isoformat()
            (unit_root / "traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
            atomic_json(status_path, {**running, "status": "FAILED", "completed_at": failed,
                                      "error": {"type": type(exc).__name__, "message": str(exc)}})
            context.events.write("TASK_FAILED", unit_id=unit_id, error_type=type(exc).__name__)
            raise

    def _fail_attempt(self, context: JobContext, claim: Mapping[str, Any], exc: BaseException) -> None:
        failed = datetime.now(timezone.utc).isoformat()
        status = {"job_id": context.config.job_id, "run_id": context.run_id,
                  "attempt_id": context.attempt_id, "trigger": context.trigger,
                  "orchestration": dict(context.orchestration), "status": "FAILED",
                  "started_at": claim["started_at"], "completed_at": failed,
                  "error": {"type": type(exc).__name__, "message": str(exc)}}
        atomic_json(context.attempt_root / "status.json", status)
        (context.attempt_root / "logs" / "traceback.txt").parent.mkdir(parents=True, exist_ok=True)
        (context.attempt_root / "logs" / "traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
        context.events.write("JOB_FAILED", job_id=context.config.job_id, run_id=context.run_id,
                             attempt_id=context.attempt_id, error_type=type(exc).__name__)
        write_run_metrics(context.run_root)

    def finalize_attempt(self, job: Job, claim: Mapping[str, Any]) -> Mapping[str, Any]:
        context = self._context_from_claim(job, claim)
        if claim.get("reused"):
            handoff_path = context.run_root / str(claim["handoff_path"])
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            if file_sha256(handoff_path) != claim["handoff_sha256"]:
                raise ValueError("reused handoff changed during Dagster execution")
            result = json.loads((context.attempt_root / "result.json").read_text(encoding="utf-8"))
            status = json.loads((context.attempt_root / "status.json").read_text(encoding="utf-8"))
            write_run_metrics(context.run_root)
            return {"status": status, "result": result, "attempt_root": str(context.attempt_root),
                    "handoff": handoff, "handoff_sha256": claim["handoff_sha256"], "reused": True}
        receipts: dict[str, Mapping[str, Any]] = {}
        outputs: dict[str, Mapping[str, Any]] = {}
        try:
            for unit in job.units:
                step_id, task_id = unit.unit_id.split(".")
                root = context.attempt_root / "steps" / step_id / "tasks" / task_id
                status_path, result_path = root / "status.json", root / "result.json"
                if not status_path.is_file() or not result_path.is_file():
                    raise ValueError(f"unit has no terminal receipt: {unit.unit_id}")
                receipt = json.loads(status_path.read_text(encoding="utf-8"))
                if receipt.get("status") != "SUCCEEDED" or receipt.get("result_sha256") != file_sha256(result_path):
                    raise ValueError(f"unit result integrity failed: {unit.unit_id}")
                receipts[unit.unit_id] = receipt
                outputs[unit.unit_id] = json.loads(result_path.read_text(encoding="utf-8"))
            result = UnitExecutor.summarize(job.units, receipts, outputs)
            result = dict(job.finalize_result(context, result))
            for validator in job.output_validators:
                validator(context, result)
            atomic_json(context.attempt_root / "result.json", result)
            return self._publish_attempt(job, context, claim, result)
        except BaseException as exc:
            self._fail_attempt(context, claim, exc)
            raise

    def _publish_attempt(self, job: Job, context: JobContext, claim: Mapping[str, Any],
                         result: Mapping[str, Any]) -> Mapping[str, Any]:
        completed = datetime.now(timezone.utc).isoformat()
        completion_status = str(result.get("status", "SUCCEEDED"))
        status = {"job_id": job.job_id, "run_id": context.run_id, "attempt_id": context.attempt_id,
                  "trigger": context.trigger, "orchestration": dict(context.orchestration),
                  "status": completion_status, "started_at": claim["started_at"], "completed_at": completed}
        atomic_json(context.attempt_root / "status.json", status)
        duration_ms = max(0, int((datetime.fromisoformat(completed) -
                                  datetime.fromisoformat(str(claim["started_at"]))).total_seconds() * 1000))
        context.events.write("JOB_COMPLETED_WITH_GAPS" if completion_status == "COMPLETED_WITH_GAPS" else "JOB_SUCCEEDED",
                             job_id=job.job_id, run_id=context.run_id,
                             attempt_id=context.attempt_id, completion_status=completion_status,
                             duration_ms=duration_ms)
        write_run_metrics(context.run_root)
        result_path = context.attempt_root / "result.json"
        artifacts = [{"path": result_path.relative_to(context.run_root).as_posix(),
                      "sha256": file_sha256(result_path), "size_bytes": result_path.stat().st_size}]

        def collect(value: Any) -> None:
            if isinstance(value, Mapping):
                if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                    candidate = (context.run_root / value["path"]).resolve()
                    if context.run_root.resolve() in candidate.parents and candidate.is_file():
                        actual = file_sha256(candidate)
                        if actual != value["sha256"]:
                            raise ValueError(f"result artifact hash mismatch: {value['path']}")
                        entry = {"path": candidate.relative_to(context.run_root).as_posix(),
                                 "sha256": actual, "size_bytes": candidate.stat().st_size}
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
                handoff_outputs[unit_id] = {key: output[key] for key in (
                    "schema", "artifact", "identity", "pointer", "metadata_path", "item_count",
                    "gaps", "index_manifest", "index_identity", "terminal_status", "dispositions",
                ) if key in output}
        identities = job.identities()
        handoff = {"schema": "appsec-review/job-handoff/1", "job_id": job.job_id,
                   "attempt_id": context.attempt_id, "status": "ACCEPTED",
                   "completion_status": completion_status, "outputs": handoff_outputs,
                   "artifacts": artifacts, "upstream_handoff_sha256": dict(claim.get("upstream_handoffs", {})),
                   "resolved_config_sha256": self.config.resolved_sha256,
                   "job_config_sha256": job_config_sha256(self.config, job.job_id),
                   "source_fingerprint": context.source_fingerprint,
                   "implementation_identity": identities["implementation"],
                   "schema_identity": identities["schema"], "validation_identity": identities["validation"],
                   "started_at": claim["started_at"], "completed_at": completed,
                   "resolving_paths": {"attempt": context.attempt_root.relative_to(context.run_root).as_posix(),
                                       "result": result_path.relative_to(context.run_root).as_posix()},
                   "tool_identity": {"python": os.sys.version.split()[0]}}
        handoff_path = context.attempt_root / "handoff.json"
        atomic_json(handoff_path, handoff)
        handoff_hash = file_sha256(handoff_path)
        manifests = [output["index_manifest"] for output in result.get("outputs", {}).values()
                     if isinstance(output, Mapping) and isinstance(output.get("index_manifest"), Mapping)]
        accepted_manifest = _accepted_retrieval_manifest(context.run_root, manifests)
        if accepted_manifest is not None:
            manifest, manifest_path = accepted_manifest
            atomic_json(context.run_root / "data" / "indices" / "accepted.json", {
                "schema": "appsec-review/accepted-index-set/1", "run_id": context.run_id,
                "handoff_path": handoff_path.relative_to(context.run_root).as_posix(),
                "handoff_sha256": handoff_hash,
                "manifest_path": manifest_path.relative_to(context.run_root).as_posix(),
                "manifest_sha256": manifest["sha256"]})
        context.events.write("HANDOFF_ACCEPTED", handoff_sha256=handoff_hash,
                             handoff_path=handoff_path.relative_to(context.run_root).as_posix(),
                             completion_status=completion_status)
        atomic_json(context.attempt_root.parent.parent / "latest.json", {
            "schema": "appsec-review/latest-handoff/1", "attempt_id": context.attempt_id,
            "handoff_path": handoff_path.relative_to(context.run_root).as_posix(),
            "handoff_sha256": handoff_hash})
        return {"status": status, "result": result, "attempt_root": str(context.attempt_root),
                "handoff": handoff, "handoff_sha256": handoff_hash}

    def run(
        self, job: Job, *, run_id: str | None = None, trigger: str = "manual",
        orchestration: Mapping[str, str] | None = None, now: datetime | None = None,
        target_root: Path | None = None, source_fingerprint: str = "none",
        upstream_handoffs: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        return self._run_legacy(job, run_id=run_id, trigger=trigger, orchestration=orchestration,
                                now=now, target_root=target_root,
                                source_fingerprint=source_fingerprint,
                                upstream_handoffs=upstream_handoffs)

    def _run_legacy(
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
        existing, _ = pipeline.read()
        if not any(item.get("event_type") == "RUN_STARTED" for item in existing):
            pipeline.write("RUN_STARTED", run_id=run_id, trigger=trigger,
                           orchestrator=orchestration.get("system", "application"),
                           details={"dagster_run_id": orchestration.get("run_id")})
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
            tools=self.config.tools,
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
            completion_status = str(result.get("status", "SUCCEEDED"))
            status = {
                "job_id": job.job_id,
                "run_id": run_id,
                "attempt_id": attempt_id,
                "trigger": trigger,
                "orchestration": orchestration,
                "status": completion_status,
                "started_at": started,
                "completed_at": completed,
            }
            atomic_json(attempt_root / "status.json", status)
            events.write("JOB_COMPLETED_WITH_GAPS" if completion_status == "COMPLETED_WITH_GAPS" else "JOB_SUCCEEDED",
                         job_id=job.job_id, run_id=run_id, attempt_id=attempt_id,
                         completion_status=completion_status,
                         duration_ms=max(0, int((datetime.fromisoformat(completed) -
                                                datetime.fromisoformat(started)).total_seconds() * 1000)))
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
                            "dispositions", "index_identity", "terminal_status",
                        ) if key in output
                    }
            handoff = {
                "schema": "appsec-review/job-handoff/1",
                "job_id": job.job_id,
                "attempt_id": attempt_id,
                "status": "ACCEPTED",
                "completion_status": completion_status,
                "outputs": handoff_outputs,
                "artifacts": artifacts,
                "upstream_handoff_sha256": dict(upstream_handoffs or {}),
                "resolved_config_sha256": self.config.resolved_sha256,
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
            accepted_manifest = _accepted_retrieval_manifest(run_root, manifests)
            if accepted_manifest is not None:
                manifest, manifest_path = accepted_manifest
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
            write_run_metrics(run_root)
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
            write_run_metrics(run_root)
            raise
