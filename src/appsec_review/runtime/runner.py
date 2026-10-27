from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import replace
import json
import os
from pathlib import Path
import traceback
import time
from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.config import AppConfig
from appsec_review.config.assurance import AssuranceMode
from appsec_review.inference.recording import unit_scope
from appsec_review.observability import EventLog, PipelineLog, write_run_metrics
from appsec_review.observability.spans import operation_span
from appsec_review.retrieval.index import MANIFEST_SCHEMA as RETRIEVAL_MANIFEST_SCHEMA
from appsec_review.retrieval.core import materialize_attempt_input_manifest
from appsec_review.runtime.resume import ResumePlanner, job_config_sha256
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.job import Job, JobContext
from appsec_review.runtime.units import UnitContext, UnitExecutor
from appsec_review.storage import RunStore, FileLock, LockUnavailable, atomic_bytes, atomic_json, file_sha256
from appsec_review.storage.shared import publication_scope, safe_path, verify_reference
from appsec_review.storage.validation import validation_scope, verified_digest


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
            "sources": [dict(layer) for layer in self.config.layers],
            "resolved": {"path": "resolved.json", "sha256": self.config.resolved_sha256},
        })

    def _context_from_claim(self, job: Job, claim: Mapping[str, Any]) -> JobContext:
        policy = self.config.review_policy
        if "review_policy" not in claim and policy.mode is not AssuranceMode.STRICT:
            raise ValueError("legacy attempt requires strict re-admission before managed assurance")
        if "review_policy" in claim and claim["review_policy"] != policy.view():
            raise ValueError("attempt claim review policy differs from frozen configuration")
        run_root = self.runs.resolve(str(claim["run_id"]))
        if policy.mode is AssuranceMode.FIRST_PARTY_MANAGED:
            from appsec_review.storage.admission import verify_claim
            verify_claim(run_root, claim)
            if (claim.get("job_id") != job.job_id
                    or claim.get("repository_root") != str(self.config.runtime.repository_root)
                    or claim.get("resolved_config_sha256") != self.config.resolved_sha256):
                raise ValueError("managed attempt claim job or configuration mismatch")
        context = self._context(job, claim)
        if policy.mode is AssuranceMode.FIRST_PARTY_MANAGED:
            persisted = json.loads((context.attempt_root / "claim.json").read_bytes())
            verify_claim(run_root, persisted)
            if not claim.get("reused") and (
                    persisted["managed_claim_authentication"] != claim["managed_claim_authentication"]):
                raise ValueError("managed attempt claim changed after preparation")
            if claim.get("reused"):
                from appsec_review.storage.admission import admit_upstreams
                from appsec_review.storage.shared import verify_handoff
                handoff_path = safe_path(run_root, str(claim["handoff_path"]))
                if file_sha256(handoff_path) != claim["handoff_sha256"]:
                    raise ValueError("reused handoff changed during Dagster execution")
                with validation_scope(run_root, target_snapshot=context.evidence_target_snapshot):
                    admit_upstreams(context, claim.get("upstream_handoffs", {}))
                    verify_handoff(run_root, json.loads(handoff_path.read_bytes()))
        return context

    def _context(self, job: Job, claim: Mapping[str, Any]) -> JobContext:
        """Construct internal preparation state; external claims use _context_from_claim."""
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
            review_policy=self.config.review_policy,
            evidence_target_snapshot=claim.get("evidence_target_snapshot"),
            target_root=Path(str(target)).resolve() if target else None,
            source_fingerprint=str(claim.get("source_fingerprint", "none")),
            input_manifest_path=(run_root / str(claim["input_manifest_path"])).resolve()
                                if claim.get("input_manifest_path") else None,
            input_manifest_sha256=(str(claim["input_manifest_sha256"])
                                   if claim.get("input_manifest_sha256") else None),
        )

    def _check_target_inputs(self, job: Job, target_root: Path | None, source_fingerprint: str) -> None:
        from appsec_review.runtime.launch import TARGET_INDEPENDENT_JOBS
        if self.config.review_policy.mode is AssuranceMode.FIRST_PARTY_MANAGED and source_fingerprint == "none":
            if target_root is not None or job.job_id not in TARGET_INDEPENDENT_JOBS:
                raise ValueError("managed absent-target claim is not a target-independent job")
            return
        self.config.review_policy.check_target(target_root)

    def begin_attempt(
        self, job: Job, *, run_id: str | None = None, trigger: str = "manual",
        orchestration: Mapping[str, str] | None = None, now: datetime | None = None,
        target_root: Path | None = None, source_fingerprint: str = "none",
        upstream_handoffs: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        instant = now or datetime.now(timezone.utc)
        self._check_target_inputs(job, target_root, source_fingerprint)
        if run_id is None:
            run_id, run_root = self.runs.create(instant)
        else:
            run_root = self.runs.resolve(run_id)
        self._bind_configuration(run_root)
        from appsec_review.storage.admission import prepare_custody
        prepare_custody(run_root, self.config.review_policy)
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
            "repository_root": str(self.config.runtime.repository_root),
            "resolved_config_sha256": self.config.resolved_sha256,
            "review_policy": self.config.review_policy.view(),
            "upstream_handoffs": dict(upstream_handoffs or {}),
            "input_identity": job.probe_input_identity(target_root),
            "dataset_contract": dataset_contract(
                job.job_id, sorted(set(job_config.steps) | {unit.unit_id.split(".")[0] for unit in job.units}),
                job.datasets),
            "started_at": instant.isoformat(),
        }
        context = self._context(job, claim)
        from appsec_review.runtime.scope import review_scope
        from appsec_review.storage.admission import admit_upstreams, resolve_evidence_target, sign_claim
        try:
            with review_scope(self.config.runtime.repository_root, run_root, target_root), \
                    validation_scope(run_root), operation_span(context.events, "attempt.prepare_inputs"):
                if self.config.review_policy.mode is AssuranceMode.FIRST_PARTY_MANAGED:
                    snapshot = resolve_evidence_target(context, claim["upstream_handoffs"])
                    claim["evidence_target_snapshot"] = snapshot
                    context = replace(context, evidence_target_snapshot=snapshot)
                admit_upstreams(context, claim["upstream_handoffs"])
                input_manifest_path, input_manifest_sha = materialize_attempt_input_manifest(
                    run_root=run_root, attempt_root=attempt_root, run_id=str(run_id),
                    target_snapshot=source_fingerprint, target_root=target_root,
                    upstream_handoffs=claim["upstream_handoffs"],
                    evidence_target_snapshot=context.evidence_target_snapshot,
                )
            if input_manifest_path is not None:
                claim["input_manifest_path"] = input_manifest_path.relative_to(run_root).as_posix()
                claim["input_manifest_sha256"] = input_manifest_sha
            if self.config.review_policy.mode is AssuranceMode.FIRST_PARTY_MANAGED:
                claim["managed_claim_authentication"] = sign_claim(run_root, claim)
        except BaseException as exc:
            atomic_json(attempt_root / "claim.json", claim)
            self._fail_attempt(context, claim, exc)
            raise
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
            with publication_scope(context):
                admit_upstreams(context, claim["upstream_handoffs"])
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
        self._check_target_inputs(job, kwargs.get("target_root"), source_fingerprint)
        if run_id is not None:
            run_root = self.runs.resolve(str(run_id))
            reasons, handoff_hash = ResumePlanner(
                self.config, run_root, (job,), source_fingerprint,
                target_root=kwargs.get("target_root")).accepted(job, upstream)
            if not reasons and handoff_hash is not None:
                pointer = json.loads((run_root / "data" / "jobs" / job.job_id / "latest.json").read_text(encoding="utf-8"))
                handoff_path = safe_path(run_root, pointer["handoff_path"])
                if file_sha256(handoff_path) != handoff_hash:
                    raise ValueError("accepted handoff changed during reuse admission")
                handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
                original_claim_path = f"{handoff['resolving_paths']['attempt']}/claim.json"
                original_claim_reference = next(
                    (item for item in handoff["artifacts"] if item["path"] == original_claim_path), None)
                if original_claim_reference is None:
                    raise ValueError("accepted handoff does not bind its original attempt claim")
                original_claim = json.loads(
                    verify_reference(run_root, original_claim_reference).read_text(encoding="utf-8"))
                expected_claim = {"run_id": str(run_id), "job_id": job.job_id,
                                  "attempt_id": handoff["attempt_id"],
                                  "attempt_path": handoff["resolving_paths"]["attempt"]}
                if not isinstance(original_claim, Mapping) or any(
                        original_claim.get(key) != value for key, value in expected_claim.items()):
                    raise ValueError("accepted attempt claim binding differs from its handoff")
                self._context_from_claim(job, original_claim)
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
                if "review_policy" in original_claim:
                    claim["review_policy"] = original_claim["review_policy"]
                if self.config.review_policy.mode is AssuranceMode.FIRST_PARTY_MANAGED:
                    from appsec_review.storage.admission import sign_claim
                    claim.update(
                        evidence_target_snapshot=original_claim["evidence_target_snapshot"],
                        repository_root=str(self.config.runtime.repository_root),
                        resolved_config_sha256=self.config.resolved_sha256,
                    )
                    for key in ("input_manifest_path", "input_manifest_sha256"):
                        if key in original_claim:
                            claim[key] = original_claim[key]
                    claim["managed_claim_authentication"] = sign_claim(run_root, claim)
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
            with operation_span(context.events, "unit.execute", unit_id=unit_id), \
                    publication_scope(context), unit_scope(run_root=context.run_root, job_id=job.job_id,
                            repository_root=context.repository_root, target_root=context.target_root):
                from appsec_review.storage.admission import admit_upstreams
                admit_upstreams(context, claim.get("upstream_handoffs", {}))
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
        (context.attempt_root / "logs" / "traceback.txt").write_text("".join(traceback.format_exception(exc)), encoding="utf-8")
        context.events.write("JOB_FAILED", job_id=context.config.job_id, run_id=context.run_id,
                             attempt_id=context.attempt_id, error_type=type(exc).__name__)
        write_run_metrics(context.run_root)

    def fail_attempt(self, job: Job, claim: Mapping[str, Any], exc: BaseException) -> None:
        """Record a claimed attempt as FAILED after one of its units raised."""

        self._fail_attempt(self._context_from_claim(job, claim), claim, exc)

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
            with publication_scope(context):
                from appsec_review.storage.admission import admit_upstreams
                admit_upstreams(context, claim.get("upstream_handoffs", {}))
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
        with publication_scope(context), operation_span(context.events, "publication.handoff"):
            return self._publish_attempt_scoped(job, context, claim, result)

    def _publish_attempt_scoped(self, job: Job, context: JobContext, claim: Mapping[str, Any],
                               result: Mapping[str, Any]) -> Mapping[str, Any]:
        from appsec_review.storage.admission import admit_upstreams
        admit_upstreams(context, claim.get("upstream_handoffs", {}))
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
        claim_path = context.attempt_root / "claim.json"
        artifacts.append({"path": claim_path.relative_to(context.run_root).as_posix(),
                          "sha256": file_sha256(claim_path), "size_bytes": claim_path.stat().st_size})
        for unit in job.units:
            step_id, task_id = unit.unit_id.split(".")
            unit_root = context.attempt_root / "steps" / step_id / "tasks" / task_id
            for name in ("status.json", "result.json"):
                path = unit_root / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError(f"unit terminal receipt is missing or unsafe: {unit.unit_id}/{name}")
                artifacts.append({"path": path.relative_to(context.run_root).as_posix(),
                                  "sha256": file_sha256(path), "size_bytes": path.stat().st_size})
        collected = {item["path"]: item["sha256"] for item in artifacts}

        def collect(value: Any) -> None:
            if isinstance(value, Mapping):
                if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                    candidate = (context.run_root / value["path"]).resolve()
                    if context.run_root.resolve() in candidate.parents and candidate.is_file():
                        relative = candidate.relative_to(context.run_root).as_posix()
                        if relative in collected:
                            if collected[relative] != value["sha256"]:
                                raise ValueError(f"result artifact has conflicting identities: {value['path']}")
                        else:
                            actual = verified_digest(context.run_root, candidate, value["sha256"])
                            if actual != value["sha256"]:
                                raise ValueError(f"result artifact hash mismatch: {value['path']}")
                            entry = {"path": relative, "sha256": actual, "size_bytes": candidate.stat().st_size}
                            artifacts.append(entry)
                            collected[entry["path"]] = actual
                for child in value.values():
                    collect(child)
            elif isinstance(value, (list, tuple)):
                for child in value:
                    collect(child)
        collect(result)
        from appsec_review.storage.shared import attempt_artifacts
        collect(attempt_artifacts(context.run_root, context.attempt_root))
        handoff_outputs = {}
        for unit_id, output in result.get("outputs", {}).items():
            if isinstance(output, Mapping):
                handoff_outputs[unit_id] = {key: output[key] for key in (
                    "schema", "artifact", "identity", "pointer", "metadata_path", "item_count",
                    "gaps", "index_manifest", "index_identity", "terminal_status", "dispositions",
                ) if key in output}
        identities = job.identities(self.config.runtime.repository_root, self.config.review_policy.releases)
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
                   "tool_identity": {"python": os.sys.version.split()[0]},
                   "input_identity": claim.get("input_identity")}
        if context.evidence_target_snapshot is not None:
            handoff["evidence_target_snapshot"] = context.evidence_target_snapshot
        handoff_path = context.attempt_root / "handoff.json"
        from appsec_review.storage.admission import create_admission
        admission = create_admission(context, handoff)
        if admission is not None:
            handoff["validation_record"] = admission
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
        """Claim a fresh attempt and run it to a published handoff in process.

        The lifecycle is the one every driver uses (``appsec_review.runtime.launch``): claim,
        each unit in dependency order, finalize. Callers that already planned reuse, such as the
        graph runner, always execute here.
        """
        from appsec_review.runtime.launch import complete

        claim = self.begin_attempt(job, run_id=run_id, trigger=trigger, orchestration=orchestration, now=now,
                                   target_root=target_root, source_fingerprint=source_fingerprint,
                                   upstream_handoffs=upstream_handoffs)
        return complete(self, job, claim)
