from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from appsec_review.config import AppConfig
from appsec_review.observability import PipelineLog
from appsec_review.runtime.job import Job
from appsec_review.interchange import HANDOFF_SCHEMA, decode_handoff
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.runtime.dependencies import graph_dependencies, input_projection
from appsec_review.orchestration.topology import upstream_closure


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
    def jsonable(value: Any) -> Any:
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, Mapping):
            return {str(key): jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [jsonable(item) for item in value]
        return value
    value = {
        "job_id": job.job_id, "name": job.name, "workers": job.workers,
        "settings": jsonable(job.settings),
        "build_capture": jsonable(asdict(job.build_capture)) if job.build_capture else None,
        "steps": {
            key: {"workers": step.workers, "settings": dict(step.settings),
                  "tasks": {task_id: {"workers": task.workers, "settings": dict(task.settings)}
                            for task_id, task in step.tasks.items()}}
            for key, step in job.steps.items()
        },
    }
    return hashlib.sha256(canonical_json(value)).hexdigest()


class ResumePlanner:
    def __init__(self, config: AppConfig, run_root: Path, jobs: Sequence[Job], source_fingerprint: str,
                 target_root: Path | None = None, *, orchestration: Mapping[str, str] | None = None,
                 dependencies: Mapping[str, Sequence[str]] | None = None,
                 propagating: set[str] | None = None):
        self.config = config
        self.target_root = target_root
        self.run_root = Path(run_root)
        self.jobs = tuple(jobs)
        self.source_fingerprint = source_fingerprint
        self.orchestration = dict(orchestration or {})
        self.dependencies = dict(dependencies) if dependencies is not None else graph_dependencies(self.jobs)
        self.propagating = propagating if propagating is not None else {
            job.job_id for job in jobs if job.propagate_handoff}

    def _accepted(self, job: Job, upstream: Mapping[str, str], *,
                  ignore_upstream: bool = False) -> tuple[list[str], str | None]:
        contract = None
        if job.job_id == "job_target_analysis_plan":
            from appsec_review.jobs.job_build_environment_analysis.job import planning_environment_inputs
            contract, upstream = planning_environment_inputs(
                self.config, self.run_root, self.source_fingerprint, self.orchestration, upstream)
        if job.always_execute:
            return ["job requires a fresh execution for every graph dispatch"], None
        latest = self.run_root / "data" / "jobs" / job.job_id / "latest.json"
        if not latest.is_file():
            return ["no accepted handoff"], None
        try:
            pointer = json.loads(latest.read_text(encoding="utf-8"))
            from appsec_review.storage.shared import safe_path
            handoff_path = safe_path(self.run_root, pointer["handoff_path"])
            if not handoff_path.is_file():
                return ["accepted handoff is missing"], None
            handoff_hash = file_sha256(handoff_path)
            if handoff_hash != pointer["handoff_sha256"]:
                return ["accepted handoff hash changed"], None
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
            if handoff.get("schema") != HANDOFF_SCHEMA:
                return ["handoff_schema_changed"], handoff_hash
            handoff = decode_handoff(handoff, run_id=self.run_root.name, job_id=job.job_id)
            from appsec_review.runtime.repair import verify_publication
            verify_publication(self.run_root, handoff, handoff_hash)
            from appsec_review.runtime.repair import forced_by_repair
            if forced_by_repair(self.run_root, job.job_id, handoff):
                return ["admitted repair requires a fresh immutable attempt"], handoff_hash
            attempts = latest.parent / "attempts"
            if any(path.name > handoff["attempt_id"] for path in attempts.iterdir() if path.is_dir()):
                return ["a newer unaccepted attempt supersedes the accepted job"], handoff_hash
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
            return [f"accepted handoff is corrupt: {type(exc).__name__}"], None
        expected = job.identities(self.config.runtime.repository_root, self.config.review_policy.releases)
        if "undeclared" in expected.values():
            return ["missing_release_identity"], handoff_hash
        checks = {
            "handoff schema": (handoff.get("schema"), HANDOFF_SCHEMA),
            "status": (handoff.get("status"), "ACCEPTED"),
            "resolved configuration": (handoff.get("resolved_config_sha256"), self.config.resolved_sha256),
            "job configuration": (handoff.get("job_config_sha256"), job_config_sha256(self.config, job.job_id)),
            "target fingerprint": (handoff.get("source_fingerprint"), self.job_fingerprint(job)),
            "implementation": (handoff.get("implementation_identity"), expected["implementation"]),
            "schema": (handoff.get("schema_identity"), expected["schema"]),
            "validator": (handoff.get("validation_identity"), expected["validation"]),
            "upstream handoffs": (handoff.get("upstream_handoff_sha256", {}), dict(upstream)),
            "tool": (handoff.get("tool_identity"), {"python": os.sys.version.split()[0]}),
            "dataset contract": (handoff["dataset_contract_sha256"], dataset_contract(
                job.job_id, sorted(set(self.config.job(job.job_id).steps)
                                   | {unit.unit_id.split(".")[0] for unit in job.units}), job.datasets,
                job_contract=job.contract.document() if job.contract is not None else None)["sha256"]),
        }
        if ignore_upstream:
            # A descendant of a job that will run: its own identities are checked now, the pinned
            # upstream handoffs only at dispatch, when the upstream has actually published.
            del checks["upstream handoffs"]
        if any(value is not None for value in (job.input_identity, job.run_input_identity, job.external_input_identity)):
            target = None if self.job_fingerprint(job) == "none" else self.target_root
            checks["input"] = (handoff.get("input_identity"), job.probe_input_identity(
                target, self.run_root, repository_root=self.config.runtime.repository_root))
        reasons = [f"{label} identity changed" for label, pair in checks.items() if pair[0] != pair[1]]
        if job.job_id == "job_target_analysis_plan":
            from appsec_review.jobs.job_target_analysis_plan.job import load_accepted_plan
            from appsec_review.jobs.job_build_environment_analysis.job import load_environment
            # A planner reused by a graph still consumes the current accepted environment.
            current = load_environment(self.run_root, self.source_fingerprint, contract)
            stored = load_accepted_plan(self.run_root).get("build_environment")
            if stored != current:
                reasons.append("planning environment availability identity changed")
        if job.job_id in {"job_project_build", "job_language_build", "job_build_iteration"}:
            try:
                from appsec_review.jobs.build_topology_artifacts import _read, guard_build_cache
                result_path = handoff["resolving_paths"]["result"]
                result_ref = next(item for item in handoff["artifacts"] if item["path"] == result_path)
                guard_build_cache(
                    self.run_root, job.job_id, _read(self.run_root, result_ref),
                    configuration={"build_selection": self.config.job(
                        "job_project_build").settings["build_selection"]},
                    releases=self.config.review_policy.releases.view(),
                    source_fingerprint=self.source_fingerprint)
            except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
                reasons.append(f"build topology cache admission failed: {error}")
        if not handoff.get("artifacts"):
            reasons.append("accepted handoff has no artifact identities")
        try:
            from appsec_review.storage.shared import verify_handoff
            verify_handoff(self.run_root, handoff)
            from appsec_review.runtime.release import read_document
            from appsec_review.runtime.repair import deployment_identity
            claim = read_document(safe_path(self.run_root, handoff["resolving_paths"]["attempt"] + "/claim.json"))
            if claim.get("deployment_identity") != deployment_identity(self.config.runtime.repository_root):
                reasons.append("deployment image/scripts identity changed")
            from appsec_review.runtime.release import load_release
            from appsec_review.runtime.repair import ComputationAdmission
            from appsec_review.storage.shared import verify_receipt
            release = load_release(self.config.runtime.repository_root)
            if release is not None:
                admission = ComputationAdmission(
                    release, self.config.review_policy.releases.view(), self.config.resolved_sha256,
                    deployment_identity(self.config.runtime.repository_root), job.job_id, job.schema_identity)
                for artifact in handoff["artifacts"]:
                    parts = PurePosixPath(artifact["path"]).parts
                    if (len(parts) == 8 and parts[:2] == ("data", "jobs")
                            and parts[3] == "attempts" and parts[5] == "shared"):
                        receipt = verify_receipt(self.run_root, artifact)
                        if receipt.get("producer_receipt") is not None:
                            admission.verify(self.run_root, receipt)
            if handoff["coverage"]["retry_required"]:
                reasons.append("accepted job contains a retriable failed producer")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            reasons.append(f"shared provenance integrity failed: {exc}")
            from appsec_review.storage.shared import safe_path
            for artifact in handoff.get("artifacts", []):
                try:
                    path = safe_path(self.run_root, artifact["path"])
                    if not path.is_file():
                        reasons.append(f"artifact missing: {artifact['path']}")
                        break
                    if file_sha256(path) != artifact["sha256"]:
                        reasons.append(f"artifact changed: {artifact['path']}")
                        break
                except (OSError, ValueError, KeyError, TypeError):
                    reasons.append("artifact reference is invalid")
                    break
        return reasons, handoff_hash

    def accepted(self, job: Job, upstream: Mapping[str, str], *,
                 ignore_upstream: bool = False) -> tuple[tuple[str, ...], str | None]:
        try:
            reasons, handoff_hash = self._accepted(job, upstream, ignore_upstream=ignore_upstream)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return (f"resume admission unavailable: {type(exc).__name__}: {exc}",), None
        return tuple(reasons), handoff_hash

    def job_fingerprint(self, job: Job) -> str:
        from appsec_review.runtime.launch import TARGET_INDEPENDENT_JOBS
        from appsec_review.runtime.contracts import TargetAccess
        independent = (job.contract.target_access is not TargetAccess.CHECKOUT if job.contract is not None
                       else job.job_id in TARGET_INDEPENDENT_JOBS)
        return "none" if independent else self.source_fingerprint

    def plan(self, *, force_from: str | None = None, emit_event: bool = True,
             initial_upstream: Mapping[str, str] | None = None,
             invalidated: bool = False) -> tuple[ResumeDecision, ...]:
        """Decide each job; ``initial_upstream`` and ``invalidated`` continue a plan whose leading jobs
        already ran (a deferred-fingerprint graph plans its target-reading suffix after acquisition)."""
        ids = [job.job_id for job in self.jobs]
        if force_from is not None and force_from not in ids:
            raise ValueError(f"force-from job is not in graph: {force_from}")
        upstream: dict[str, str] = dict(initial_upstream or {})
        decisions: list[ResumeDecision] = []
        dirty: set[str] = set()
        from appsec_review.runtime.dependencies import semantic_dependencies
        inputs = semantic_dependencies(self.jobs, self.dependencies)
        for job in self.jobs:
            ancestors = set(upstream_closure(job.job_id, inputs, set(inputs)))
            selected = input_projection(job, upstream, self.dependencies, self.propagating)
            if force_from == job.job_id:
                dirty.add(job.job_id)
                decision = ResumeDecision(job.job_id, "RUN", ("forced rerun from named job",))
            elif invalidated:
                dirty.add(job.job_id)
                decision = ResumeDecision(job.job_id, "INVALIDATE", ("transitive downstream invalidation",))
            elif ancestors & dirty:
                # An ancestor will run, so this job's upstream pins are unknown until dispatch. When
                # everything that is its own still verifies, the runtime decides at dispatch (REVALIDATE:
                # reuse only if every pinned upstream is then equivalent, else run); otherwise it runs.
                dirty.add(job.job_id)
                reasons, handoff_hash = self.accepted(job, selected, ignore_upstream=True)
                if reasons:
                    decision = ResumeDecision(job.job_id, "INVALIDATE",
                                              ("transitive downstream invalidation", *reasons))
                else:
                    decision = ResumeDecision(
                        job.job_id, "REVALIDATE",
                        ("upstream will run; own identities and accepted handoff match, reuse decided at dispatch",),
                        handoff_hash)
            else:
                reasons, handoff_hash = self.accepted(job, selected)
                if reasons:
                    if job.propagate_handoff:
                        dirty.add(job.job_id)
                    decision = ResumeDecision(job.job_id, "RUN", tuple(reasons))
                else:
                    decision = ResumeDecision(job.job_id, "REUSE", ("all declared identities and artifacts match",), handoff_hash)
                    if job.propagate_handoff:
                        upstream[job.job_id] = str(handoff_hash)
            decisions.append(decision)
        if emit_event:
            PipelineLog(self.run_root).write("RESUME_PLANNED", run_id=self.run_root.name,
                message="resume decisions computed", details={"decisions": [item.as_dict() for item in decisions]})
        return tuple(decisions)
