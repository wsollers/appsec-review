"""Explicit, immutable implementation repair admission; no commands or reviews are replayed here."""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence
from uuid import uuid4

from appsec_review.config import AppConfig
from appsec_review.runtime.job import Job
from appsec_review.runtime.release import digest, load_release, read_document
from appsec_review.storage import FileLock, atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import immutable_bytes, reference, safe_path, verify_reference

REPAIR_SCHEMA = "appsec-review/repair-admission/1"
PLAN_SCHEMA = "appsec-review/repair-plan/1"
COMPATIBILITY = "appsec-review/same-input-contracts/1"
PUBLICATION_PROTOCOL = "appsec-review/committed-publication/1"
WORKER_PROTOCOL = "appsec-review/recovery-worker/1"


def deployment_identity(repository_root: Path) -> dict[str, Any]:
    release = load_release(repository_root)
    image = os.environ.get("APPSEC_REVIEW_IMAGE_ID")
    if image is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("APPSEC_REVIEW_IMAGE_ID must be an immutable SHA-256 image ID")
    return {"image_id": image, "scripts_sha256": release["scripts_sha256"] if release else None,
            "python": os.sys.version.split()[0]}


def current_binding(run_root: Path) -> dict[str, Any] | None:
    path = run_root / "data/recovery/current.json"
    if not path.exists():
        return None
    value = read_document(path)
    if value.get("schema") != "appsec-review/implementation-binding/1":
        raise ValueError("unsupported implementation binding")
    release = value.get("release")
    if release is not None:
        from appsec_review.runtime.release import validate_release
        stored = validate_release(read_document(verify_reference(run_root, release)))
        if stored["sha256"] != value.get("release_sha256"):
            raise ValueError("implementation binding release identity mismatch")
    elif value.get("release_sha256") is not None:
        raise ValueError("implementation binding is missing its release manifest")
    repair = value.get("repair")
    if repair is not None:
        document = read_document(verify_reference(run_root, repair))
        if (document.get("schema") != REPAIR_SCHEMA or document.get("admitted") is not True
                or document.get("run_id") != run_root.name
                or document.get("release_sha256") != value["release_sha256"]
                or document.get("deployment") != value["deployment"]):
            raise ValueError("repair publication does not match the implementation binding")
    return value


def _release_ref(run_root: Path, release: Mapping[str, Any] | None):
    return (immutable_bytes(run_root, f"data/recovery/releases/{release['sha256']}.json",
                            canonical_json(release)) if release else None)


def bind_release(config: AppConfig, run_root: Path) -> dict[str, Any]:
    release = load_release(config.runtime.repository_root)
    release_sha = release["sha256"] if release else None
    deployment = deployment_identity(config.runtime.repository_root)
    current = current_binding(run_root)
    if current is not None:
        if current["release_sha256"] != release_sha or current["deployment"] != deployment:
            raise ValueError("implementation changed: plan-repair and admit-repair are required before restart")
        return current
    if any((run_root / "data/jobs").glob("*/attempts/*/claim.json")):
        raise ValueError("historical run requires explicit repair admission before restart")
    current = {"schema": "appsec-review/implementation-binding/1", "release_sha256": release_sha,
               "release": _release_ref(run_root, release), "deployment": deployment, "repair": None}
    atomic_json(run_root / "data/recovery/current.json", current)
    return current


@contextmanager
def worker_scope(config: AppConfig, run_root: Path, *, preparing_job: str | None = None):
    """Register a worker under the same gate that excludes concurrent repair admission."""
    from appsec_review.runtime.resources import process_identity
    from appsec_review.storage import bounded_file_lock
    token = uuid4().hex
    path = run_root / f"data/recovery/workers/{token}.json"
    record = {"schema": WORKER_PROTOCOL, "pid": os.getpid(),
              "process_identity": process_identity(os.getpid()), "status": "ACTIVE",
              "preparing_job": preparing_job,
              "pid_namespace": os.readlink("/proc/self/ns/pid") if os.name == "posix" else None}
    with bounded_file_lock(run_root / "data/recovery/admission.lock", 30):
        if preparing_job is not None:
            prior = any((run_root / f"data/jobs/{preparing_job}/attempts").glob("*/status.json"))
            simultaneous = any(
                value.get("status") == "ACTIVE" and value.get("preparing_job") == preparing_job
                for value in (read_document(path) for path in (run_root / "data/recovery/workers").glob("*.json")))
            if prior or simultaneous:
                reasons = stopped_reasons(config, run_root)
                if reasons:
                    raise ValueError("replacement attempt refused: " + "; ".join(reasons))
        atomic_json(path, record)
    try:
        yield
    finally:
        atomic_json(path, {**record, "status": "EXITED"})


def stopped_reasons(config: AppConfig, run_root: Path) -> tuple[str, ...]:
    """Read-only stop inspection. Retained leases are never silently reconciled or cleared."""
    from appsec_review.config.native_dagster import native_execution_requested
    from appsec_review.runtime.resources import process_identity
    reasons = []
    if native_execution_requested():
        reasons.append("native cancellation/cleanup is not commissioned for repair admission")
    for path in sorted((run_root / "data/recovery/workers").glob("*.json")):
        worker = read_document(path)
        if worker.get("schema") != WORKER_PROTOCOL or worker.get("status") not in {"ACTIVE", "EXITED"}:
            reasons.append("worker cleanup state is unknown")
        elif worker["status"] == "ACTIVE":
            local = process_identity(os.getpid())
            if (not local or not worker.get("process_identity")
                    or local.split(":")[0] != worker["process_identity"].split(":")[0]
                    or worker.get("pid_namespace") != os.readlink("/proc/self/ns/pid")):
                reasons.append("worker belongs to an unverified host or PID namespace")
            elif process_identity(worker["pid"]) == worker["process_identity"]:
                reasons.append("a registered worker is still active")
    safety_path = run_root / "data/configuration/execution-safety.json"
    if safety_path.exists():
        envelope = read_document(safety_path)
        journal = config.runtime.metadata_dir / "dagster-safety" / f"{envelope['dagster_run_id']}.json"
        if not journal.exists():
            reasons.append("stopped controller and cleanup cannot be verified")
        else:
            state = read_document(journal)
            if (state.get("policy") != envelope or state.get("application_run_id") != run_root.name
                    or state.get("status") not in {"STOPPED", "COMPLETED"}
                    or not state.get("completed_at") or state.get("active")
                    or state.get("cancellation") in {"UNCERTAIN", "REQUESTED", "REQUEST_ACCEPTED"}):
                reasons.append("controller cancellation or retained permits require cleanup verification")
        # Its UUID is part of the immutable safety envelope. Do not pretend a new controller
        # can reopen it; such runs require a separately authorized successor submission.
        reasons.append("frozen first-error controller cannot restart in-place; submit a new run")
    ledger = config.runtime.metadata_dir / "resource-admission/leases.json"
    if ledger.exists():
        leases = read_document(ledger)
        if leases.get("schema") != "appsec-review/resource-leases/1" or not isinstance(leases.get("leases"), dict):
            reasons.append("resource lease ledger is unsupported")
        elif any(not entry.get("persistent") for entry in leases["leases"].values()):
            reasons.append("retained host resource leases require existing cleanup verification")
    for path in sorted((run_root / "data/jobs").glob("*/attempts/*/claim.json")):
        claim = read_document(path)
        if claim.get("worker_protocol") != WORKER_PROTOCOL:
            reasons.append("historical worker stop state is unknown")
        if claim.get("orchestration", {}).get("system") == "dagster" and not safety_path.exists():
            # A failed step is not proof that the Dagster run worker cannot launch another step.
            dispatch_id = claim["orchestration"].get("run_id", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", dispatch_id):
                reasons.append("Dagster dispatch identity is unavailable")
                continue
            stopped = run_root / f"data/recovery/dispatches/{dispatch_id}.json"
            if not stopped.exists():
                reasons.append("Dagster dispatch stop requires verify-repair-stop, not just a failed step")
            else:
                receipt = read_document(stopped)
                if (receipt.get("schema") != "appsec-review/verified-dispatch-stop/1"
                        or receipt.get("run_id") != run_root.name or receipt.get("dispatch_id") != dispatch_id
                        or receipt.get("worker_status") not in {"SUCCESS", "NOT_FOUND"}
                        or receipt.get("terminal") is not True):
                    reasons.append("Dagster dispatch stop receipt is invalid")
    for path in sorted((run_root / "data/jobs").glob("*/attempts/*/status.json")):
        if not (path.parent / "claim.json").exists() and read_document(path).get("status") == "RUNNING":
            reasons.append("historical worker stop state is unknown")
    return tuple(sorted(set(reasons)))


def verify_dispatch_stop(config: AppConfig, run_root: Path, dispatch_id: str, *, instance=None) -> dict[str, Any]:
    """Use the launcher's health API, never a captured command or an operator boolean."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", dispatch_id):
        raise ValueError("invalid Dagster dispatch id")
    from appsec_review.config.native_dagster import native_execution_requested
    if native_execution_requested():
        raise ValueError("native cancellation/cleanup is not commissioned")
    if instance is None:
        from dagster import DagsterInstance
        with DagsterInstance.get() as configured:
            return verify_dispatch_stop(config, run_root, dispatch_id, instance=configured)
    run = instance.get_run_by_id(dispatch_id)
    if run is None or run.tags.get("appsec/application_run_id") != run_root.name or not run.is_finished:
        raise ValueError("Dagster dispatch is absent, belongs to another run, or is not terminal")
    launcher = instance.run_launcher
    if not launcher.supports_check_run_worker_health:
        raise ValueError("Dagster launcher cannot verify stopped workers; cleanup remains uncertain")
    health = launcher.check_run_worker_health(run)
    status = health.status.value
    if status not in {"SUCCESS", "NOT_FOUND"}:
        raise ValueError(f"Dagster worker stop is unconfirmed: {status}")
    value = {"schema": "appsec-review/verified-dispatch-stop/1", "run_id": run_root.name,
             "dispatch_id": dispatch_id, "terminal": True, "worker_status": status}
    immutable_bytes(run_root, f"data/recovery/dispatches/{dispatch_id}.json", canonical_json(value))
    return value


def verify_publication(run_root: Path, handoff: Mapping[str, Any], handoff_sha256: str) -> None:
    attempt = safe_path(run_root, handoff["resolving_paths"]["attempt"])
    marker = read_document(attempt / "published.json")
    if (marker.get("schema") != PUBLICATION_PROTOCOL
            or marker.get("handoff_sha256") != handoff_sha256
            or marker.get("status_sha256") != file_sha256(attempt / "status.json")
            or read_document(attempt / "status.json").get("status") != handoff["completion_status"]):
        raise ValueError("job publication is not committed or its completion status changed")


def forced_by_repair(run_root: Path, job_id: str, handoff: Mapping[str, Any]) -> bool:
    binding = current_binding(run_root)
    if not binding or binding["repair"] is None:
        return False
    repair = read_document(verify_reference(run_root, binding["repair"]))
    decision = next((item for item in repair["decisions"] if item["job_id"] == job_id), None)
    if decision is None:
        raise ValueError("job was not included in the admitted repair graph")
    if decision["action"] == "REUSE":
        return False
    claim = read_document(safe_path(run_root, handoff["resolving_paths"]["attempt"] + "/claim.json"))
    return claim.get("repair_admission_sha256") != binding["repair"]["sha256"]


def check_successor(config: AppConfig, run_root: Path, envelope: Mapping[str, Any] | None) -> None:
    path = run_root / "data/recovery/successor.json"
    if not path.exists():
        return
    document = read_document(path)
    if (document.get("schema") != "appsec-review/successor-import/1"
            or document["plan"]["resolved_config_sha256"] != config.resolved_sha256):
        raise ValueError("successor must retain the original resolved review configuration")
    required = document.get("required_execution_safety")
    if required is not None and (
            envelope is None or envelope.get("mode") != required["mode"]
            or envelope.get("dagster_run_id") == required["prior_dispatch_id"]
            or envelope.get("submission", {}).get("target_commit") != required["target_commit"]):
        raise ValueError("successor requires a fresh authorized first-error execution-safety envelope")


def plan_repair(config: AppConfig, run_root: Path, jobs: Sequence[Job], source_fingerprint: str, *,
                target_root: Path | None = None, force_from: str | None = None,
                historical_rerun: bool = False, dependencies: Mapping[str, Sequence[str]] | None = None,
                successor: bool = False) -> dict[str, Any]:
    from appsec_review.runtime.resume import ResumePlanner
    from appsec_review.runtime.dependencies import graph_dependencies
    release = load_release(config.runtime.repository_root)
    current = current_binding(run_root)
    config_manifest = read_document(run_root / "data/configuration/manifest.json")
    reasons = list(stopped_reasons(config, run_root))
    if successor:
        reasons = [reason for reason in reasons if reason !=
                   "frozen first-error controller cannot restart in-place; submit a new run"]
    if release is None:
        reasons.append("repaired implementation has no build-time release manifest")
    if (config_manifest.get("resolved_sha256") != config.resolved_sha256
            or file_sha256(run_root / "data/configuration/resolved.json") != config.resolved_sha256
            or file_sha256(run_root / "data/configuration/appsec-review.toml") != config_manifest["source_sha256"]):
        reasons.append("repair must retain the original target policy and frozen configuration")
    historical = current is None or current.get("release") is None
    if historical and not historical_rerun:
        reasons.append("historical implementation is unverified; explicit historical-rerun is required")
    dependencies = graph_dependencies(jobs, dependencies)
    decisions = ResumePlanner(config, run_root, jobs, source_fingerprint, target_root=target_root,
                              dependencies=dependencies).plan(force_from=force_from, emit_event=False,
                                                              invalidated=historical or successor)
    snapshots, unit_decisions = {}, {}
    for job in jobs:
        if release is not None and job.job_id not in release["jobs"]:
            reasons.append(f"repaired release does not declare {job.job_id}")
        # Changing a wire contract cannot be approved by declaring a source-code repair.
        claims = sorted((run_root / f"data/jobs/{job.job_id}/attempts").glob("*/claim.json"))
        if claims:
            claim = read_document(claims[-1])
            snapshots[job.job_id] = {
                "claim": reference(run_root, claims[-1]),
                "status": reference(run_root, claims[-1].parent / "status.json")
                if (claims[-1].parent / "status.json").exists() else None,
            }
            if claim.get("source_fingerprint") not in {
                    source_fingerprint, "none" if job.always_execute else source_fingerprint}:
                from appsec_review.runtime.launch import TARGET_INDEPENDENT_JOBS
                if job.job_id not in TARGET_INDEPENDENT_JOBS:
                    reasons.append(f"original target fingerprint differs for {job.job_id}")
            if claim.get("component_identities", {}).get("schema") != job.schema_identity:
                reasons.append(f"unsupported schema compatibility change for {job.job_id}")
            from appsec_review.runtime.datasets import dataset_contract
            expected_contract = dataset_contract(
                job.job_id, sorted(set(config.job(job.job_id).steps)
                                   | {unit.unit_id.split(".")[0] for unit in job.units}), job.datasets)
            if claim.get("dataset_contract", {}).get("sha256") != expected_contract["sha256"]:
                reasons.append(f"unsupported dataset compatibility change for {job.job_id}")
        from appsec_review.runtime.checkpoints import select_units
        from appsec_review.runtime.resume import job_config_sha256
        from appsec_review.runtime.dependencies import input_projection
        hashes = {item.job_id: item.handoff_sha256 for item in decisions if item.action == "REUSE"}
        candidate = {
            "job_id": job.job_id, "resolved_config_sha256": config.resolved_sha256,
            "job_config_sha256": job_config_sha256(config, job.job_id),
            "component_identities": job.identities(config.runtime.repository_root, config.review_policy.releases),
            "source_fingerprint": ResumePlanner(config, run_root, (job,), source_fingerprint).job_fingerprint(job),
            "upstream_handoffs": input_projection(job.job_id, hashes, dependencies,
                                                 {item.job_id for item in jobs if item.propagate_handoff}),
            "input_identity": job.probe_input_identity(target_root, run_root),
            "deployment_identity": deployment_identity(config.runtime.repository_root),
        }
        unit_decisions[job.job_id] = (
            {unit.unit_id: {"action": "RUN", "reason": "historical/successor evidence is not imported as success"}
             for unit in job.units} if historical or successor else select_units(run_root, job, candidate))
    value = {
        "schema": PLAN_SCHEMA, "compatibility": COMPATIBILITY, "run_id": run_root.name,
        "base_binding_sha256": digest(current), "resolved_config_sha256": config.resolved_sha256,
        "source_fingerprint": source_fingerprint, "release_sha256": release["sha256"] if release else None,
        "deployment": deployment_identity(config.runtime.repository_root),
        "historical_rerun": historical_rerun, "force_from": force_from,
        "successor": successor, "attempt_snapshots": snapshots, "unit_decisions": unit_decisions,
        "dependencies": {key: list(value) for key, value in dependencies.items()},
        "decisions": [item.as_dict() for item in decisions], "refusals": sorted(set(reasons)),
        "admissible": not reasons,
    }
    return {**value, "plan_sha256": digest(value)}


def admit_repair(config: AppConfig, run_root: Path, jobs: Sequence[Job], plan: Mapping[str, Any], *,
                 target_root: Path | None = None,
                 dependencies: Mapping[str, Sequence[str]] | None = None) -> dict[str, Any]:
    with FileLock(run_root / "data/resume.lock"), FileLock(run_root / "data/recovery/admission.lock"):
        fresh = plan_repair(config, run_root, jobs, plan["source_fingerprint"], target_root=target_root,
                            force_from=plan.get("force_from"), historical_rerun=plan.get("historical_rerun", False),
                            dependencies=dependencies, successor=plan.get("successor", False))
        if canonical_json(fresh) != canonical_json(plan):
            raise ValueError("repair plan changed; inspect a fresh plan before admission")
        if not fresh["admissible"]:
            raise ValueError("repair refused: " + "; ".join(fresh["refusals"]))
        release = load_release(config.runtime.repository_root)
        if release is None or release["sha256"] != fresh["release_sha256"]:
            raise ValueError("repaired release changed before admission publication")
        if fresh["successor"]:
            from datetime import datetime, timezone
            from appsec_review.runtime.runner import JobRunner
            runner = JobRunner(config)
            successor_id, successor_root = runner.runs.create(datetime.now(timezone.utc))
            safety_path = run_root / "data/configuration/execution-safety.json"
            required = None
            if safety_path.exists():
                envelope = read_document(safety_path)
                required = {"mode": envelope["mode"], "prior_dispatch_id": envelope["dagster_run_id"],
                            "target_commit": envelope["submission"]["target_commit"]}
            immutable_bytes(successor_root, "data/recovery/successor.json", canonical_json({
                "schema": "appsec-review/successor-import/1", "source_run_id": run_root.name,
                "plan": fresh, "imported_successes": [],
                "required_execution_safety": required,
                "reason": "old evidence is retained in the source run; every job requires fresh admission",
            }))
            if required is None:
                runner._bind_configuration(successor_root)
            return {"successor_run_id": successor_id, "source_run_id": run_root.name,
                    "imported_successes": [], "requires_execution_safety": required is not None,
                    "binding": current_binding(successor_root)}
        repair_ref = immutable_bytes(run_root, f"data/recovery/repairs/{fresh['plan_sha256']}.json",
                                     canonical_json({**fresh, "schema": REPAIR_SCHEMA, "admitted": True}))
        binding = {"schema": "appsec-review/implementation-binding/1",
                   "release_sha256": release["sha256"], "release": _release_ref(run_root, release),
                   "deployment": fresh["deployment"], "repair": repair_ref}
        # This single atomic pointer is the commit point. Orphaned manifests never grant admission.
        atomic_json(run_root / "data/recovery/current.json", binding)
        return binding
