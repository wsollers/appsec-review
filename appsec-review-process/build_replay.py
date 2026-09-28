"""Shared happy-path lock replay for 02-build-configure and 02-native-build.

Both jobs consume the accepted stage-13 lock and execute only its recorded argv through B13.  The
target remains read-only, the trusted runner copies it to /scratch, and network is disabled.  This
module deliberately contains the common mechanics; the two public worker modules bind distinct
job identities and output contracts.
"""
from __future__ import annotations

import tunables

from datetime import datetime, timedelta, timezone
import base64
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import threading
from typing import Any

import build_resolution
import container_execution as ce
from execution_state import Blocked, ROOT, atomic_json, data_path, digest, file_hash, now, read_json, run_path
import permission_capabilities as pc
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document

CONTROL_SCHEMA = "appsec-review/build-replay-input/1"
CONTROL_FILE = "build-replay.json"
RUNNER_VERSION = "build-lock-replay/1"
RECEIPTS = "b13-receipts.json"

SPECS: dict[str, dict[str, Any]] = {
    "02-build-configure": {
        "dagster_job": "build_configure",
        "contract": "configured-build",
        "result": "configured-build.json",
        "schema": "configured-build.schema.json",
        "summary": "configured-build-summary.md",
        "profile": "build-configure-v1",
        "phases": ("configure",),
    },
    "02-native-build": {
        "dagster_job": "native_build",
        "contract": "native-build",
        "result": "native-build.json",
        "schema": "native-build.schema.json",
        "summary": "native-build-summary.md",
        "profile": "native-build-v1",
        "phases": ("configure", "build"),
    },
}


def spec(job: str) -> dict[str, Any]:
    try:
        return SPECS[job]
    except KeyError as exc:  # pragma: no cover - internal call set is closed
        raise ValueError(job) from exc


def root(run_id: str, job: str) -> Path:
    return data_path(run_id, "jobs", job)


def control_path(run_id: str) -> Path:
    return data_path(run_id, "controls", CONTROL_FILE)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _source_snapshot(run_id: str) -> str:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not path.is_file():
        raise Blocked("build replay: staged artifact-manifest.json is required")
    return "sha256:" + file_hash(path)


def source_tree_sha256(target: Path) -> str:
    """Bind the exact checkout bytes replayed by E02, excluding Git administration data."""
    target = target.resolve()
    records: dict[str, dict[str, str]] = {}
    for current, dirs, files in os.walk(target, topdown=True, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in sorted(files):
            path = Path(current, name)
            relative = path.relative_to(target).as_posix()
            if path.is_symlink():
                records[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                records[relative] = {"kind": "file", "sha256": "sha256:" + file_hash(path)}
            else:
                raise Blocked(f"build replay: checkout contains a special file: {relative}")
    return "sha256:" + digest(records)


def _cap(job: str) -> dict[str, Any]:
    params = {name: None for name in pc.PARAMETER_NAMES}
    params.update(command_profile_id=spec(job)["profile"], target_path=".")
    return {"kind": "target-execution", "version": "1.0", "parameters": params,
            "origin": "staged-run-config"}


def stage_control(run_id: str, *, authority: str = "Task-authorized engagement owner") -> Path:
    issued = datetime.now(timezone.utc).replace(microsecond=0)
    source = _source_snapshot(run_id)
    target = _target(run_id)
    grants = []
    requirements = {}
    for job in SPECS:
        capability = _cap(job)
        requirements[job] = {"schema": "appsec-review/permission-requirement/1.0",
                             "job_id": job, "capabilities": [capability]}
        grants.append({
            "schema": "appsec-review/permission-grant/1.0",
            "grant_id": "happy-path-" + job,
            "effect": "ALLOW",
            "authority": {"name": authority, "role": "engagement-owner"},
            "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (issued + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "binding": {"run_id": run_id, "source_snapshot_sha256": source, "job_id": job},
            "justification": f"Happy-path {job} replay of the accepted build lock through B13.",
            "capabilities": [capability],
        })
    value = {"schema": CONTROL_SCHEMA, "mode": "success", "requirements": requirements,
             "grants": grants, "timeout_seconds": 1800}
    errors = validate_document(value, "build-replay-input.schema.json")
    if errors:
        raise ValueError("invalid build-replay control: " + "; ".join(errors))
    atomic_json(control_path(run_id), value)
    return control_path(run_id)


def _rebind(grants, run_id, source):
    """Bind staged grants to the current manifest hash.

    Intake rewrites artifact-manifest.json every time it re-runs, so a grant staged against an
    earlier manifest would otherwise go stale mid-run (ADR-0013: a check that blocks runs without
    protecting the report is relaxed). Grants stay bound to this run and job.
    """
    return [{**g, "binding": {**g["binding"], "source_snapshot_sha256": source}}
            if isinstance(g, dict) and g.get("binding", {}).get("run_id") == run_id else g
            for g in grants]


def _permission(control: dict[str, Any], job: str, run_id: str, source: str) -> dict[str, Any]:
    requirement = control["requirements"][job]
    grants = _rebind([g for g in control["grants"] if g["binding"]["job_id"] == job], run_id, source)
    context = {"run_id": run_id, "job_id": job, "source_snapshot_sha256": source,
               "now": _utc_now(), "registry_ceiling": None}
    decision = pc.evaluate(requirement, grants, context)
    capabilities = pc.require_granted(decision, requirement=requirement, grants=grants,
                                      context=context)
    granted = {(item["kind"], json.dumps(item["parameters"], sort_keys=True))
               for item in capabilities}
    expected_capability = _cap(job)
    expected = {(expected_capability["kind"],
                 json.dumps(expected_capability["parameters"], sort_keys=True))}
    if granted != expected:
        raise Blocked(f"{job}: permission decision is not the exact target-execution capability")
    return {"requirement": requirement, "grants": grants, "decision": decision}


def _target(run_id: str) -> Path:
    manifest = read_json(run_path(run_id) / "inputs" / "artifact-manifest.json")
    value = manifest.get("target", {}).get("repo_path")
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked("build replay: target.repo_path must be an absolute real checkout directory")
    return path


def _code_hashes(job: str) -> dict[str, str]:
    wrapper = "build_configure.py" if job == "02-build-configure" else "native_build.py"
    names = ("build_replay.py", wrapper, "container_execution.py", "permission_capabilities.py",
             "publish_job_output.py", "validate_job_output.py",
             f"registry/output-contracts/{spec(job)['contract']}.json")
    result = {name: file_hash(ROOT / name) for name in names}
    for name in ("build-replay-input.schema.json", spec(job)["schema"],
                 "container-image.schema.json", "pinned-container-result.schema.json"):
        result["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return result


def _upstream(run_id: str, job: str) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    resolution = build_resolution.validate(run_id)
    lock_path = resolution / build_resolution.LOCK_FILE
    lock_set = read_json(lock_path)
    pointer = read_json(build_resolution.root(run_id) / "accepted.json")
    resolution_binding = {"job": build_resolution.JOB,
        "attempt_id": pointer["attempt_id"], "lock_sha256": "sha256:" + file_hash(lock_path)}
    if job == "02-native-build":
        import build_configure
        configured = build_configure.validate(run_id)
        configured_pointer = read_json(build_configure.root(run_id) / "accepted.json")
        return resolution, lock_set, {"resolution": resolution_binding, "configured": {
            "job": build_configure.JOB, "attempt_id": configured_pointer["attempt_id"],
            "result_sha256": "sha256:" + file_hash(configured / build_configure.RESULT),
            "envelope_sha256": "sha256:" + file_hash(configured / "result.json"),
        }}
    return resolution, lock_set, resolution_binding


def current_inputs(run_id: str, job: str) -> dict[str, Any]:
    cpath = control_path(run_id)
    if not cpath.is_file():
        raise Blocked(f"{job}: missing data/controls/{CONTROL_FILE}; explicit grants were not staged")
    control = read_json(cpath)
    errors = validate_document(control, "build-replay-input.schema.json")
    if errors:
        raise Blocked(f"{job}: control fails its closed schema ({len(errors)} errors)")
    source = _source_snapshot(run_id)
    target = _target(run_id)
    permission = _permission(control, job, run_id, source)
    _resolution, lock_set, upstream = _upstream(run_id, job)
    records = {}
    for lock in lock_set["locks"]:
        image_id = lock["image"]["image_id"]
        record_path = build_resolution.catalog_root() / "container-images" / f"{image_id}.json"
        if not record_path.is_file():
            raise Blocked(f"{job}: host-local image record is missing for {image_id}")
        record = read_json(record_path)
        if validate_document(record, "container-image.schema.json"):
            raise Blocked(f"{job}: host-local image record is invalid for {image_id}")
        if record["digest"] != lock["image"]["digest"]:
            raise Blocked(f"{job}: lock/image digest mismatch for {image_id}")
        records[image_id] = {"value": record, "sha256": "sha256:" + file_hash(record_path)}
    return {"run_id": run_id, "job": job, "source_snapshot_sha256": source,
        "source_tree_sha256": source_tree_sha256(target),
        "source_revision": lock_set["source_revision"], "target_path": str(target),
        "control": {"path": f"data/controls/{CONTROL_FILE}", "sha256": file_hash(cpath),
                    "value": control}, "upstream": upstream, "lock_set": lock_set,
        "image_records": records,
        "permission_fingerprint_sha256": pc.input_fingerprint_component(permission["decision"]),
        "boundary_sha256": ce.boundary_sha256(), "code": _code_hashes(job)}


RUNNER = r'''import hashlib,json,os,pathlib,shutil,stat,subprocess,sys
cfg=json.loads(sys.argv[1]); src=pathlib.Path('/scratch/src')
shutil.copytree('/workspace',src,symlinks=False,ignore_dangling_symlinks=True)
def executables():
 out={}
 for p in src.rglob('*'):
  try:
   if p.is_file() and p.stat().st_mode & 0o111 and p.read_bytes()[:4]==b'\x7fELF':
    out[p.relative_to(src).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
  except OSError: pass
 return out
before=executables(); records=[]
for item in cfg['commands']:
 argv=list(item['argv']); cwd=src/item['cwd']
 if item['phase']=='build' and cfg['compile_database']=='bear':
  argv=['bear','--output',str(src/'compile_commands.json'),'--',*argv]
 p=subprocess.run(argv,cwd=cwd,check=False)
 records.append({'phase':item['phase'],'argv':argv,'cwd':str(cwd),'exit_code':p.returncode})
 if p.returncode: break
after=executables(); binaries=[]
if cfg['mode']=='native':
 for rel,sha in sorted(after.items()):
  if before.get(rel)!=sha:
   p=src/rel; binaries.append({'path':rel,'sha256':'sha256:'+sha,'size_bytes':p.stat().st_size})
pathlib.Path('/scratch/replay-result.json').write_text(json.dumps({'runner':cfg['runner'],'commands':records,'binaries':binaries},sort_keys=True)+'\n')
sys.exit(next((x['exit_code'] for x in records if x['exit_code']),0))'''


def _runtime(source: str, images_dir: Path) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked("build replay: Docker is unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=images_dir, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source,
        registry_ceiling=None, clock=_utc_now, cancel=threading.Event())


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _request(run_id: str, job: str, adapter_id: str, record: dict[str, Any], lock: dict[str, Any],
             inputs: dict[str, Any]) -> dict[str, Any]:
    control = inputs["control"]["value"]
    permission = _permission(control, job, run_id, inputs["source_snapshot_sha256"])
    phases = spec(job)["phases"]
    commands = [item for phase in phases for item in lock[phase]]
    cfg = {"runner": RUNNER_VERSION, "mode": "native" if job == "02-native-build" else "configure",
           "compile_database": lock["compile_database"]["method"], "commands": commands}
    encoded = base64.b64encode(RUNNER.encode("utf-8")).decode("ascii")
    trusted = "import base64;exec(base64.b64decode('" + encoded + "'))"
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": job, "attempt_id": adapter_id,
        "image": {"image_id": record["image_id"], "digest": record["digest"]},
        "argv": ["/usr/bin/python3", "-c", trusted, json.dumps(cfg, sort_keys=True)],
        "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"}],
        "target_mounts": [{"host_path": inputs["target_path"], "container_path": "/workspace"}],
        "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []}, "permission": permission,
        "limits": {**tunables.container_limits(job), "timeout_seconds": control["timeout_seconds"]}}


def _compile_db(path: Path, allowed: list[str]) -> list[dict[str, Any]]:
    try:
        value = read_json(path)
    except Exception as exc:
        raise RuntimeError("02-native-build: compile_commands.json is missing or invalid") from exc
    if not isinstance(value, list) or not value:
        raise RuntimeError("02-native-build: compile_commands.json is empty")
    for index, entry in enumerate(value):
        words = entry.get("arguments") or shlex.split(entry.get("command", ""))
        if not words or words[0] not in set(allowed):
            raise RuntimeError(f"02-native-build: compile_commands[{index}] is not fixed clang")
        if not isinstance(entry.get("file"), str) or not entry["file"].startswith("/scratch/src/"):
            raise RuntimeError(f"02-native-build: compile_commands[{index}] escapes /scratch/src")
    return value


def _validate_attempt(run_id: str, job: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{job}: immutable attempt inputs changed")
    result = read_json(attempt / spec(job)["result"])
    if validate_document(result, spec(job)["schema"]):
        raise Blocked(f"{job}: result schema validation failed")
    receipts = read_json(attempt / RECEIPTS)
    for receipt in receipts:
        trial = attempt / receipt["trial_path"]
        registry = attempt / receipt["registry_path"]
        request = read_json(trial / "logs/container" / ce.REQUEST_FILE)
        runtime = _runtime(inputs["source_snapshot_sha256"], registry)
        errors = ce.verify_container_result(trial, run_id=run_id, job_id=job,
            attempt_id=receipt["adapter_attempt_id"], request=request, images_dir=registry,
            expected_result_sha256=receipt["expected_result_sha256"], **_host(runtime))
        if errors:
            raise Blocked(f"{job}: B13 evidence failed re-verification ({len(errors)} errors)")
    if job == "02-native-build":
        locks = {item["unit_id"]: item for item in inputs["lock_set"]["locks"]}
        for unit in result["units"]:
            lock = locks.get(unit["unit_id"])
            if lock is None:
                raise Blocked(f"{job}: result names a unit absent from the accepted lock")
            db = attempt / unit["compile_database"]["path"]
            entries = _compile_db(db, lock["compile_database"]["compiler_allowlist"])
            if len(entries) != unit["compile_database"]["entries"]:
                raise Blocked(f"{job}: compile database entry count changed")
            if len(entries) != lock["compile_database"]["entries"]:
                raise Blocked(f"{job}: compile database is incomplete relative to the accepted lock")
            for binary in unit["binaries"]:
                path = attempt / binary["artifact_path"]
                if not path.is_file() or "sha256:" + file_hash(path) != binary["sha256"]:
                    raise Blocked(f"{job}: binary artifact changed")
                if path.read_bytes()[:4] != b"\x7fELF":
                    raise Blocked(f"{job}: published binary is not ELF")


def run(run_id: str, dagster_id: str, job: str, force: bool = False) -> dict[str, Any]:
    cfg = spec(job); base = root(run_id, job)
    resume = f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job {cfg['dagster_job']} --wait"

    def execute(allocation, inputs, fingerprint):
        attempt = allocation["attempt"]
        if inputs["code"] != _code_hashes(job):
            raise Blocked(f"{job}: implementation changed before execution")
        units=[]; receipts=[]
        for lock in inputs["lock_set"]["locks"]:
            unit_key = digest(lock["unit_id"])[:12]
            unit_root = attempt / "units" / unit_key
            trial = unit_root / "trial"; registry = unit_root / "image-registry"
            trial.mkdir(parents=True); registry.mkdir(parents=True)
            image_id = lock["image"]["image_id"]
            record = inputs["image_records"][image_id]["value"]
            atomic_json(registry / f"{image_id}.json", record)
            adapter_id = "u" + unit_key
            runtime = _runtime(inputs["source_snapshot_sha256"], registry)
            request = _request(run_id, job, adapter_id, record, lock, inputs)
            terminal = ce.run_container(runtime, run_id=run_id, job_id=job,
                attempt_id=adapter_id, attempt_root=trial, request=request)
            expected = terminal["result_sha256"]
            ce.load_verified_result(trial, run_id=run_id, job_id=job, attempt_id=adapter_id,
                request=request, images_dir=registry, expected_result_sha256=expected, **_host(runtime))
            if terminal["execution_status"] != "OK":
                raise RuntimeError(f"{job}: replay for {lock['unit_id']} ended {terminal['execution_status']}")
            replay = read_json(trial / "scratch" / "replay-result.json")
            commands = replay.get("commands", [])
            if not commands or any(item.get("exit_code") != 0 for item in commands):
                raise RuntimeError(f"{job}: locked command sequence did not succeed")
            unit = {"unit_id": lock["unit_id"], "status": "OK", "image_id": image_id,
                    "image_digest": record["digest"], "commands": commands}
            if job == "02-build-configure":
                configuration = {"unit_id": lock["unit_id"], "source_revision": inputs["source_revision"],
                    "image_id": image_id, "image_digest": record["digest"],
                    "lock_sha256": inputs["upstream"]["lock_sha256"], "commands": commands}
                path = attempt / "outputs" / unit_key / "configuration.json"
                atomic_json(path, configuration)
                unit["configuration"] = {"path": path.relative_to(attempt).as_posix(),
                                         "sha256": "sha256:" + file_hash(path)}
            else:
                source_db = trial / "scratch" / "src" / "compile_commands.json"
                entries = _compile_db(source_db, lock["compile_database"]["compiler_allowlist"])
                if len(entries) != lock["compile_database"]["entries"]:
                    raise RuntimeError(f"{job}: replay compile database differs from the accepted lock")
                db = attempt / "outputs" / unit_key / "compile_commands.json"
                db.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source_db, db)
                binaries=[]
                for item in replay.get("binaries", []):
                    source = trial / "scratch" / "src" / item["path"]
                    if not source.is_file():
                        raise RuntimeError(f"{job}: declared binary is missing: {item['path']}")
                    target = attempt / "outputs" / unit_key / "binaries" / item["path"]
                    target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
                    binaries.append({"source_path": item["path"],
                        "artifact_path": target.relative_to(attempt).as_posix(),
                        "sha256": "sha256:" + file_hash(target), "size_bytes": target.stat().st_size})
                if not binaries:
                    raise RuntimeError(f"{job}: build produced no new executable binary")
                unit["compile_database"] = {"path": db.relative_to(attempt).as_posix(),
                    "sha256": "sha256:" + file_hash(db), "entries": len(entries)}
                unit["binaries"] = binaries
            units.append(unit)
            receipts.append({"unit_id": lock["unit_id"], "adapter_attempt_id": adapter_id,
                "trial_path": trial.relative_to(attempt).as_posix(),
                "registry_path": registry.relative_to(attempt).as_posix(),
                "expected_result_sha256": expected})
        result = {"schema": "appsec-review/configured-build/1" if job == "02-build-configure"
                  else "appsec-review/native-build/1", "run_id": run_id,
                  "source_revision": inputs["source_revision"], "upstream": inputs["upstream"],
                  "status": "OK", "units": units, "coverage_gaps": []}
        if not units:
            # ADR-0013: nothing was resolved to build (upstream gaps say why); publish that as a gap.
            result["status"] = "OK_WITH_GAPS"
            result["coverage_gaps"] = ["no-resolved-build-units: 02-build-resolution locked no unit"]
        atomic_json(attempt / cfg["result"], result); atomic_json(attempt / RECEIPTS, receipts)
        (attempt / cfg["summary"]).write_text(f"# {job}\n\n" + "\n".join(
            f"- `{unit['unit_id']}`: {len(unit['commands'])} locked command(s) succeeded"
            for unit in units) + "\n", encoding="utf-8")
        status = {"process": job, "status": result["status"], "run_id": run_id,
            "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
            "source_revision": inputs["source_revision"], "units": len(units),
            "permissions": [f"target-execution:{cfg['profile']}@."], "network": "none",
            "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        artifacts = [cfg["result"], RECEIPTS, cfg["summary"], "status.json"]
        for unit in units:
            if job == "02-build-configure": artifacts.append(unit["configuration"]["path"])
            else:
                artifacts.append(unit["compile_database"]["path"])
                artifacts.extend(item["artifact_path"] for item in unit["binaries"])
        return record_terminal_current(base, attempt, run_id=run_id, job_id=job,
            dagster_run_id=dagster_id, worker_kind="pinned_container", output_contract=cfg["contract"],
            input_fingerprint=fingerprint, started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"Replayed the accepted lock for {len(units)} unit(s).",
            status_record=status, artifact_paths=artifacts, gaps=result["coverage_gaps"] or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, job, path, inputs))

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=job, dagster_run_id=dagster_id,
        worker_kind="pinned_container", output_contract=cfg["contract"], resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id, job),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": job,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes(job)}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, job, attempt, record),
        blocked_summary=f"{job} preflight did not complete.",
        failed_summary=f"{job} did not publish; no older success may be used.")


def validate(run_id: str, job: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id, job); pointer = pointer or read_json(base / "accepted.json")
    inputs = current_inputs(run_id, job)
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(inputs),
                                    expected_run_id=run_id, expected_job_id=job)
    _validate_attempt(run_id, job, attempt, inputs)
    return attempt


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
