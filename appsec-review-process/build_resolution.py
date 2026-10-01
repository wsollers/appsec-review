"""02-build-resolution: render, provision, trial and lock accepted per-unit build plans.

The model-authored plan has already passed ``build_plan.check``.  This worker owns every effect:
it re-derives the two permission grants, renders one closed Dockerfile, builds only that image,
and runs one trusted argv runner through B13.  The target is mounted read-only; the runner copies
it to B13's sole writable ``/scratch`` mount before executing the plan.  Native builds are wrapped
with Bear and accepted only when the resulting compile database is non-empty and clang-only.
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
import subprocess
import threading
from typing import Any

import build_plan
import container_execution as ce
from execution_state import (Blocked, Lock, ROOT, atomic_json, data_path, digest, file_hash, now,
                             read_json, run_path)
import permission_capabilities as pc
import cow_install as cow
from publish_job_output import coordinate_worker_lifecycle, record_terminal_current, validate_published
from schema_validate import validate_document
import registry_paths

JOB = "02-build-resolution"
DAGSTER_JOB = "build_resolution"
CONTRACT = "build-resolution"
RESULT = "build-resolution.json"
LOCK_FILE = "build-lock.json"
SUMMARY = "build-resolution-summary.md"
RECEIPTS = "b13-receipts.json"
CONTROL_FILE = "build-resolution.json"
CONTROL_SCHEMA = "appsec-review/build-resolution-input/1"
RENDERER_VERSION = "build-resolution-dockerfile/1"
RUNNER_VERSION = "build-resolution-runner/1"
COMMAND_PROFILE = "build-resolution-v1"
# D-28 (William, 2026-10-01): trial builds run on Docker's default bridge so package managers can
# fetch dependencies. Staged into the control (fingerprinted); a control without it stays offline.
BUILD_NETWORK = "unrestricted"
APT_MIRROR = {"scheme": "http", "host": "archive.ubuntu.com", "port": 80,
              "suite": "noble", "components": ["main", "universe"]}
CODE_FILES = ("build_resolution.py", "build_plan.py", "container_execution.py",
              "permission_capabilities.py", "publish_job_output.py", "validate_job_output.py",
              registry_paths.contract_rel("build-resolution"))


def root(run_id: str) -> Path:
    return data_path(run_id, "jobs", JOB)


def control_path(run_id: str) -> Path:
    return data_path(run_id, "controls", CONTROL_FILE)


def catalog_root() -> Path:
    return Path(os.environ.get("APPSEC_BUILD_IMAGES_ROOT", ROOT / "data" / "build-images"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cap(kind: str, *, origin: str, target_path: str | None = None) -> dict[str, Any]:
    params = {name: None for name in pc.PARAMETER_NAMES}
    if kind == "package-restore":
        params.update(scheme=APT_MIRROR["scheme"], host=APT_MIRROR["host"],
                      port=APT_MIRROR["port"], ecosystem="apt")
    elif kind == "target-execution":
        params.update(command_profile_id=COMMAND_PROFILE, target_path=target_path or ".")
    else:  # pragma: no cover - closed internal call set
        raise ValueError(kind)
    return {"kind": kind, "version": "1.0", "parameters": params, "origin": origin}


def _source_snapshot(run_id: str) -> str:
    path = run_path(run_id) / "inputs" / "artifact-manifest.json"
    if not path.is_file():
        raise Blocked(f"{JOB}: staged artifact-manifest.json is required")
    return "sha256:" + file_hash(path)


def stage_control(run_id: str, mode: str = "success", reuse: str = "auto",
                  *, authority: str = "Task-authorized engagement owner") -> Path:
    """Stage the two explicit grants authorized for SAT stage 13.

    The grant is bound to this run, job and source snapshot and expires after one day.  It permits
    apt only from the one declared Ubuntu mirror and target execution only for the closed command
    profile in the repository root.  It grants no general network, credentials, mutation or tests.
    """
    issued = datetime.now(timezone.utc).replace(microsecond=0)
    source = _source_snapshot(run_id)
    capabilities = [_cap("package-restore", origin="staged-run-config"),
                    _cap("target-execution", origin="staged-run-config")]
    grant = {
        "schema": "appsec-review/permission-grant/1.0",
        "grant_id": "stage13-build-resolution",
        "effect": "ALLOW", "authority": {"name": authority, "role": "engagement-owner"},
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (issued + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "binding": {"run_id": run_id, "source_snapshot_sha256": source, "job_id": JOB},
        "justification": "Stage 13: bounded apt provisioning and offline trial execution in B13.",
        "capabilities": capabilities,
    }
    value = {
        "schema": CONTROL_SCHEMA, "mode": mode, "build_resolution_attempts": 6,
        "build_image_reuse": reuse, "build_command_timeout_seconds": tunables.value(JOB, "container_timeout_seconds"),
        "image_build_timeout_seconds": 1800, "apt_mirror": APT_MIRROR,
        "build_network": BUILD_NETWORK,
        "permission": {"requirement": {
            "schema": "appsec-review/permission-requirement/1.0", "job_id": JOB,
            "capabilities": [_cap("package-restore", origin="staged-run-config"),
                             _cap("target-execution", origin="staged-run-config")],
        }, "grants": [grant]},
    }
    errors = validate_document(value, "build-resolution-input.schema.json")
    if errors:
        raise ValueError("invalid build-resolution control: " + "; ".join(errors))
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


def _permission(control: dict[str, Any], run_id: str, source: str, at: str) -> dict[str, Any]:
    permission = {**control["permission"]}
    permission["grants"] = _rebind(permission["grants"], run_id, source)
    context = {"run_id": run_id, "job_id": JOB, "source_snapshot_sha256": source,
               "now": at, "registry_ceiling": None}
    decision = pc.evaluate(permission["requirement"], permission["grants"], context)
    caps = pc.require_granted(decision, requirement=permission["requirement"],
                              grants=permission["grants"], context=context)
    keys = {(c["kind"], json.dumps(c["parameters"], sort_keys=True)) for c in caps}
    required = {(k, json.dumps(_cap(k, origin="staged-run-config")["parameters"], sort_keys=True))
                for k in ("package-restore", "target-execution")}
    if keys != required:
        raise Blocked(f"{JOB}: permission decision is not the exact two-capability boundary")
    return {"requirement": permission["requirement"], "grants": permission["grants"],
            "decision": decision}


def _target(run_id: str) -> Path:
    manifest = read_json(run_path(run_id) / "inputs" / "artifact-manifest.json")
    value = manifest.get("target", {}).get("repo_path")
    path = Path(value) if isinstance(value, str) else Path()
    if not value or not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise Blocked(f"{JOB}: target.repo_path must be an absolute real checkout directory")
    return path


def _code_hashes() -> dict[str, str]:
    result = {name: file_hash(ROOT / name) for name in CODE_FILES}
    for name in ("build-image.schema.json", "build-resolution-input.schema.json",
                 "build-resolution.schema.json", "buildenv-lock.schema.json",
                 "container-image.schema.json", "pinned-container-result.schema.json"):
        result["schemas/" + name] = file_hash(ROOT.parent / "schemas" / name)
    return result


def current_inputs(run_id: str) -> dict[str, Any]:
    cpath = control_path(run_id)
    if not cpath.is_file():
        raise Blocked(f"{JOB}: missing data/controls/{CONTROL_FILE}; explicit grants were not staged")
    control = read_json(cpath)
    errors = validate_document(control, "build-resolution-input.schema.json")
    if errors:
        raise Blocked(f"{JOB}: control fails its closed schema ({len(errors)} errors)")
    source = _source_snapshot(run_id)
    permission = _permission(control, run_id, source, _utc_now())
    plan_attempt = build_plan.validate(run_id)
    plan_path = plan_attempt / build_plan.RESULT
    plan = read_json(plan_path)
    target = _target(run_id)
    registry = ce.load_image_registry(ce.IMAGES_DIR)
    bases = {}
    for item in plan["plans"]:
        base = item["image"]["base"]
        if base not in registry:
            raise Blocked(f"{JOB}: base image {base} has no current B16 record")
        build_reference = base + ":local"
        if _inspect(build_reference) != registry[base]["digest"]:
            raise Blocked(f"{JOB}: local base tag {build_reference} drifted from its B16 image id")
        bases[base] = {"digest": registry[base]["digest"], "build_reference": build_reference,
                       "reference": ce.image_reference(registry[base]),
                       "record_sha256": "sha256:" + digest(registry[base])}
        fallback = _fallback_name(base)
        if fallback and fallback in registry and _inspect(fallback + ":local") == registry[fallback]["digest"]:
            bases[fallback] = {"digest": registry[fallback]["digest"], "build_reference": fallback + ":local",
                               "reference": ce.image_reference(registry[fallback]),
                               "record_sha256": "sha256:" + digest(registry[fallback])}
    return {
        "job": JOB, "run_id": run_id, "source_snapshot_sha256": source,
        "source_revision": plan["source_revision"], "target_path": str(target),
        "control": {"path": f"data/controls/{CONTROL_FILE}", "sha256": file_hash(cpath),
                    "value": control},
        "plan": {"attempt_id": plan_attempt.name, "sha256": file_hash(plan_path), "value": plan},
        "base_images": bases,
        "permission_fingerprint_sha256": pc.input_fingerprint_component(permission["decision"]),
        "boundary_sha256": ce.boundary_sha256(), "code": _code_hashes(),
    }


def _render(plan: dict[str, Any], base_ref: str, mirror: dict[str, Any]) -> str:
    packages = sorted({p["name"] for p in plan["image"]["apt_packages"]})
    install = " ".join(packages) if packages else ""
    # No apt packages, no apt at all: the update alone needs the mirror, and on the Debian-based
    # buildenvs (go, php, python, rust, typescript) the Ubuntu sources fail with exit 100
    # (appsec-multi-vuln 20261001T032047Z-fd64eb, 15 of 23 gaps).
    apt = [
        f"RUN {cow.APT_SOURCES} && apt-get update && "
        f"apt-get install -y --no-install-recommends {install} && rm -rf /var/lib/apt/lists/*",
    ] if install else []
    return "\n".join([
        f"# {RENDERER_VERSION}", f"FROM {base_ref}", "USER root",
        "ARG DEBIAN_FRONTEND=noninteractive",
        *apt,
        "USER worker", "WORKDIR /scratch",
        "ENV CC=/opt/llvm/bin/clang CXX=/opt/llvm/bin/clang++", "",
    ])


def _spec(plan: dict[str, Any], base: dict[str, Any], mirror: dict[str, Any]) -> tuple[str, str]:
    body = {"renderer": RENDERER_VERSION, "base": base, "mirror": mirror,
            "packages": sorted({p["name"] for p in plan["image"]["apt_packages"]})}
    fingerprint = "sha256:" + digest(body)
    return "image_build_" + fingerprint.split(":", 1)[1][:12], fingerprint


def _docker() -> str:
    value = os.environ.get("APPSEC_DOCKER_BIN") or shutil.which("docker")
    if not value:
        raise Blocked(f"{JOB}: Docker CLI is unavailable")
    return str(Path(value).resolve())


def _inspect(reference: str) -> str | None:
    result = subprocess.run([_docker(), "image", "inspect", "--format", "{{.Id}}", reference],
                            capture_output=True, text=True, timeout=60, check=False)
    value = result.stdout.strip()
    return value if result.returncode == 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", value) else None


def _catalog(image_id: str) -> tuple[Path, Path]:
    root = catalog_root()
    return root / "catalog" / f"{image_id}.json", root / "container-images" / f"{image_id}.json"


def _build_image(unit_attempt: Path, image_id: str, fingerprint: str, dockerfile: str,
                 control: dict[str, Any], force: bool) -> tuple[dict[str, Any], bool]:
    catalog_path, container_path = _catalog(image_id)
    tag = "appsec-build/" + image_id.replace("_", "-") + ":local"
    if not force and control["build_image_reuse"] in ("auto", "require") \
            and catalog_path.is_file() and container_path.is_file():
        catalog = read_json(catalog_path); record = read_json(container_path)
        if validate_document(catalog, "build-image.schema.json"):
            raise Blocked(f"{JOB}: catalog schema validation failed for {image_id}")
        if validate_document(record, "container-image.schema.json"):
            raise Blocked(f"{JOB}: container-image schema validation failed for {image_id}")
        if catalog.get("spec_fingerprint_sha256") != fingerprint:
            raise Blocked(f"{JOB}: catalog fingerprint mismatch for {image_id}")
        present = _inspect(record["digest"])
        if present != record["digest"]:
            raise Blocked(f"{JOB}: catalogued image {image_id} is not present at its immutable id")
        return record, True
    if control["build_image_reuse"] == "require":
        raise Blocked(f"{JOB}: build_image_reuse=require but {image_id} is not catalogued")
    context = unit_attempt / "image-context"; context.mkdir(parents=True)
    (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    logs = unit_attempt / "image-build-logs"; logs.mkdir()
    argv = [_docker(), "build", "--pull=false", "--network=default", "--tag", tag,
            "--file", str(context / "Dockerfile"), str(context)]
    atomic_json(unit_attempt / "image-build-command.json", {
        "argv": argv, "network_authority": {"kind": "package-restore", "ecosystem": "apt",
        **APT_MIRROR}, "spec_fingerprint_sha256": fingerprint})
    with (logs / "stdout.log").open("wb") as out, (logs / "stderr.log").open("wb") as err:
        proc = subprocess.Popen(argv, stdout=out, stderr=err, start_new_session=True)
        try:
            code = proc.wait(timeout=control["image_build_timeout_seconds"])
        except subprocess.TimeoutExpired:
            proc.terminate()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
            raise RuntimeError(f"{JOB}: image build timed out")
    if code:
        raise RuntimeError(f"{JOB}: image build exited {code}")
    image_digest = _inspect(tag)
    if image_digest is None:
        raise RuntimeError(f"{JOB}: built tag has no immutable image id")
    record = {
        "schema": "appsec-review/container-image/1.0", "image_id": image_id,
        "repository": "appsec-build/" + image_id.replace("_", "-"),
        "digest": image_digest, "digest_kind": "image-id",
        "dockerfile_sha256": "sha256:" + digest(dockerfile),
        "build_fingerprint_sha256": fingerprint,
        "build_attempt_id": unit_attempt.name,
        "purpose": "Stage-13 rendered build environment; target content is mounted only at trial time.",
        "provenance": "02-build-resolution closed renderer under an apt package-restore grant.",
    }
    errors = validate_document(record, "container-image.schema.json")
    if errors:
        raise RuntimeError(f"{JOB}: rendered image record is invalid ({len(errors)} errors)")
    return record, False


RUNNER = r'''import json,os,pathlib,shutil,subprocess,sys
cfg=json.loads(sys.argv[1]); src=pathlib.Path('/scratch/src')
shutil.copytree('/workspace',src,symlinks=False,ignore_dangling_symlinks=True)
records=[]
for item in cfg['commands']:
    argv=list(item['argv']); cwd=src/item['cwd']
    if item['phase']=='build' and cfg['compile_database']=='bear':
        argv=['bear','--output',str(src/'compile_commands.json'),'--',*argv]
    p=subprocess.run(argv,cwd=cwd,check=False)
    records.append({'phase':item['phase'],'argv':argv,'cwd':str(cwd),'exit_code':p.returncode})
    if p.returncode: break
if cfg['mode']=='exit-nonzero' and all(x['exit_code']==0 for x in records):
    records.append({'phase':'qualification-fault','argv':['/bin/false'],'cwd':str(src),'exit_code':42})
pathlib.Path('/scratch/trial-result.json').write_text(json.dumps({'runner':cfg['runner'],'commands':records},sort_keys=True)+'\n')
sys.exit(next((x['exit_code'] for x in records if x['exit_code']),0))'''


def _runtime(source: str, images_dir: Path) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    if defaults["docker_executable"] is None:
        raise Blocked(f"{JOB}: Docker is unavailable")
    return ce.ContainerRuntime(docker_executable=defaults["docker_executable"], docker_host=None,
        images_dir=images_dir, host_flavor=defaults["host_flavor"],
        container_user=defaults["container_user"], source_snapshot_sha256=source,
        registry_ceiling=None, clock=_utc_now, cancel=threading.Event())


def _repo_commands(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Plan commands carry cwd relative to the unit root (build_plan.check joins root + cwd); the
    trial and replay runners run from the repository root. Re-anchor once here, so the lock is
    repository-relative (appsec-multi-vuln: every projects/cpp/case-* unit ran cmake at the repo
    root and failed with "does not appear to contain CMakeLists.txt")."""
    import posixpath
    root = posixpath.normpath(plan.get("root") or ".")

    def anchored(cwd: str) -> str:
        cwd = posixpath.normpath(cwd or ".")
        # A planner sometimes writes the cwd already rooted at the unit (cwd == root, or below it):
        # joining again doubled it (projects/cpp/case-027/projects/cpp/case-027) and the trial
        # raised before running anything (appsec-multi-vuln 20261001T032047Z-fd64eb: 8 of 28 plan
        # commands). build_plan.check accepts both spellings, so read both here.
        if root != "." and (cwd == root or cwd.startswith(root + "/")):
            return cwd
        return posixpath.normpath(posixpath.join(root, cwd))

    return [{**c, "cwd": anchored(c.get("cwd") or ".")} for c in plan["commands"]]


def _request(run_id: str, attempt_id: str, unit_attempt: Path, record: dict[str, Any],
             plan: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    control = inputs["control"]["value"]
    permission = _permission(control, run_id, inputs["source_snapshot_sha256"], _utc_now())
    cfg = {"runner": RUNNER_VERSION, "mode": control["mode"],
           # Always bear: the lock (and so the replay) records the compile database as bear's
           # src/compile_commands.json; a cmake-export plan put it in build/ and the trial
           # reported "no compile_commands.json" for a successful build (freeciv21).
           "compile_database": "bear", "commands": _repo_commands(plan)}
    encoded_runner = base64.b64encode(RUNNER.encode("utf-8")).decode("ascii")
    trusted_runner = "import base64;exec(base64.b64decode('" + encoded_runner + "'))"
    return {"schema": ce.REQUEST_ID, "run_id": run_id, "job_id": JOB, "attempt_id": attempt_id,
        "image": {"image_id": record["image_id"], "digest": record["digest"]},
        "argv": ["/usr/bin/python3", "-c", trusted_runner, json.dumps(cfg, sort_keys=True)],
        "environment": [{"name": "LANG", "value": "C"}, {"name": "LC_ALL", "value": "C"}],
        "target_mounts": [{"host_path": inputs["target_path"], "container_path": "/workspace"}],
        "scratch_path": "scratch", "log_path": "logs/container",
        "network": {"mode": "unrestricted-build" if control.get("build_network") == "unrestricted" else "none",
                    "destinations": []}, "permission": permission,
        "limits": {**tunables.container_limits(JOB),
                   "timeout_seconds": control["build_command_timeout_seconds"]}}


def _host(runtime: ce.ContainerRuntime) -> dict[str, Any]:
    return {"host_flavor": runtime.host_flavor, "docker_host": runtime.docker_host,
            "docker_executable": runtime.docker_executable, "container_user": runtime.container_user}


def _compile_db(path: Path, allowed: list[str]) -> list[dict[str, Any]]:
    try: value = read_json(path)
    except Exception as exc: raise RuntimeError(f"{JOB}: compile_commands.json is missing or invalid") from exc
    if not isinstance(value, list) or not value:
        raise RuntimeError(f"{JOB}: compile_commands.json is empty")
    # bear also records clang's internal frontend re-exec (`clang-21 -cc1 ...`, multi-vuln); it
    # duplicates the driver entry and is not a compile command. Drop it and keep the file in step.
    kept = [e for e in value if isinstance(e, dict) and
            (e.get("arguments") or shlex.split(e.get("command", "")))[1:2] != ["-cc1"]]
    if len(kept) != len(value):
        value = kept
        atomic_json(path, value)
        if not value:
            raise RuntimeError(f"{JOB}: compile_commands.json is empty")
    allowed_set = set(allowed)
    for index, entry in enumerate(value):
        words = entry.get("arguments") or shlex.split(entry.get("command", ""))
        compiler = words[0] if words else ""
        if compiler not in allowed_set:
            raise RuntimeError(f"{JOB}: compile_commands[{index}] compiler is not the fixed clang path")
        source = entry.get("file")
        if not isinstance(source, str) or not source.startswith("/scratch/src/"):
            raise RuntimeError(f"{JOB}: compile_commands[{index}] names a file outside the trial copy")
    return value


def _publish_catalog(image_id: str, record: dict[str, Any], fingerprint: str, dockerfile: str,
                     inputs: dict[str, Any], plan: dict[str, Any], unit_attempt: Path,
                     packages: list[str] | None = None) -> None:
    catalog_path, container_path = _catalog(image_id)
    catalog = {"schema": "appsec-review/build-image/1", "image_id": image_id,
        "tag": "appsec-build/" + image_id.replace("_", "-") + ":local",
        "local_image_id": record["digest"], "digest_kind": "image-id",
        "spec_fingerprint_sha256": fingerprint,
        "dockerfile": dockerfile, "dockerfile_sha256": record["dockerfile_sha256"],
        "base": plan["image"]["base"],
        "base_digest": inputs["base_images"][plan["image"]["base"]]["digest"],
        "apt_packages": sorted(packages if packages is not None else (p["name"] for p in plan["image"]["apt_packages"])),
        "apt_mirror": APT_MIRROR,
        "validated_builds": [{"run_id": inputs.get("run_id"), "source_revision": inputs["source_revision"],
            "plan_sha256": "sha256:" + inputs["plan"]["sha256"], "attempt_id": unit_attempt.name,
            "validated_at": now()}]}
    errors = validate_document(catalog, "build-image.schema.json")
    if errors:
        raise RuntimeError(f"{JOB}: build-image catalog entry is invalid ({len(errors)} errors)")
    with Lock(catalog_root() / "catalog.lock"):
        if catalog_path.exists() or container_path.exists():
            old = read_json(catalog_path); old_record = read_json(container_path)
            if old.get("spec_fingerprint_sha256") != fingerprint or old_record != record:
                raise Blocked(f"{JOB}: refusing to replace an immutable build-image catalog entry")
            return
        atomic_json(catalog_path, catalog); atomic_json(container_path, record)


def _cow_spec(run_id: str, unit_key: str, round_no: int, base_info: dict[str, Any], packages: list[str],
              image: str, dockerfile: str, attempt_name: str) -> tuple[str, str]:
    """Catalog identity of a copy-on-write build image. It covers every field of the record
    _publish_catalog compares: an entry is immutable, so a re-launch that renders a different
    Dockerfile (f436cbc dropped the apt step for no-package units) or numbers the unit differently
    needs a new id, not the old one (20261001T032047Z-fd64eb: "refusing to replace")."""
    fingerprint = "sha256:" + digest({"renderer": RENDERER_VERSION, "base": base_info, "packages": packages,
                                      "run_id": run_id, "unit": unit_key, "round": round_no, "image": image,
                                      "dockerfile_sha256": "sha256:" + digest(dockerfile),
                                      "attempt": attempt_name})
    return "image_build_" + fingerprint.split(":", 1)[1][:12], fingerprint


def _cow_record(image_id: str, image: str, dockerfile: str, fingerprint: str, unit_attempt: Path) -> dict[str, Any]:
    record = {
        "schema": "appsec-review/container-image/1.0", "image_id": image_id,
        "repository": "appsec-build/" + image_id.replace("_", "-"),
        "digest": image, "digest_kind": "image-id",
        "dockerfile_sha256": "sha256:" + digest(dockerfile),
        "build_fingerprint_sha256": fingerprint, "build_attempt_id": unit_attempt.name,
        "purpose": "Disposable copy-on-write build layer over a sealed buildenv; target content is mounted only at trial time.",
        "provenance": "02-build-resolution copy-on-write install session under an apt package-restore grant.",
    }
    errors = validate_document(record, "container-image.schema.json")
    if errors:
        raise RuntimeError(f"{JOB}: copy-on-write image record is invalid ({len(errors)} errors)")
    return record


def _prune_trial_source(trial: Path) -> None:
    """Drop the trial's copy of the source tree and build outputs (freeciv21: ~720 MB per trial,
    11 GB per job). The container result binds only the logs; the compile database is copied to
    outputs/ first. Without this every re-validation hashes gigabytes of throwaway build trees."""
    src = trial / "scratch" / "src"
    if src.is_dir() and not src.is_symlink():
        shutil.rmtree(src, ignore_errors=True)


def _trial_text(trial: Path) -> str:
    parts = []
    for path in sorted((trial / "logs").rglob("*.log")) if (trial / "logs").is_dir() else []:
        try:
            parts.append(path.read_text(encoding="utf-8", errors="replace")[-400000:])
        except OSError:
            pass
    return "\n".join(parts)


def _fallback_name(base: str) -> str | None:
    try:
        return tunables.value(JOB, "base_fallback_" + base.replace("-", "_"))
    except tunables.TunableMissing:
        return None


def _resolve_unit_cow(run_id, attempt, plan, number, unit_key, inputs, control, gaps,
                      defer_conflict=False, label=""):
    """Build one unit in copy-on-write install rounds over its sealed base (see cow_install).

    Round 0 installs the plan's apt names that exist. Each trial failure is read for missing
    CMake package configs, pkg-config modules, headers and programs; apt-file maps them to
    packages, which go into another thin layer over the last one. Stops on success, when a round
    finds nothing new, or after build_resolution_attempts rounds (all logged). Returns the success
    tuple, or None after recording a gap."""
    unit_root = attempt / "units" / (unit_key + label)
    unit_root.mkdir(parents=True, exist_ok=True)
    log = unit_root / "install.log"
    base_info = inputs["base_images"][plan["image"]["base"]]
    planned = sorted({p["name"] for p in plan["image"]["apt_packages"]})
    installs = {"base": plan["image"]["base"], "base_digest": base_info["digest"], "planned": planned,
                "dropped_unknown": [], "rounds": [], "packages": [], "unresolved": []}
    try:
        resolver = cow.resolver_image(base_info["digest"], log=log)
        known, unknown = cow.check_names(resolver, planned, log=log)
        installs["dropped_unknown"] = unknown
        image = base_info["digest"]
        if known:
            image = cow.install_layer(image, known, repository="appsec-build/cow-" + unit_key, run_id=run_id,
                                      unit=unit_key, round_no=0, log=log)
        installs["packages"] = list(known)
        installs["rounds"].append({"round": 0, "installed": known, "from": "plan", "image": image})
    except (cow.InstallFailed, subprocess.TimeoutExpired) as exc:
        gaps.append(f"{plan['unit_id']}: copy-on-write install failed before the first trial ({exc}); "
                    f"see {log.relative_to(attempt).as_posix()}")
        return None
    rounds = max(1, int(control.get("build_resolution_attempts") or 3))
    last_failure = "no trial ran"
    for round_no in range(1, rounds + 1):
        unit_attempt = unit_root / "resolution-attempts" / f"{number:03d}-r{round_no}"
        unit_attempt.mkdir(parents=True)
        packages = sorted(installs["packages"])
        dockerfile = _render({"image": {"apt_packages": [{"name": p} for p in packages]}},
                             base_info["build_reference"], control["apt_mirror"])
        image_id, fingerprint = _cow_spec(run_id, unit_key, round_no, base_info, packages, image,
                                          dockerfile, unit_attempt.name)
        record = _cow_record(image_id, image, dockerfile, fingerprint, unit_attempt)
        registry = unit_attempt / "image-registry"; registry.mkdir()
        atomic_json(registry / f"{image_id}.json", record)
        trial = unit_attempt / "trial"; trial.mkdir()
        adapter_id = "u" + unit_key + f"r{round_no}"
        runtime = _runtime(inputs["source_snapshot_sha256"], registry)
        request = _request(run_id, adapter_id, unit_attempt, record, plan, inputs)
        terminal = ce.run_container(runtime, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                                    attempt_root=trial, request=request)
        expected = terminal["result_sha256"]
        ce.load_verified_result(trial, run_id=run_id, job_id=JOB, attempt_id=adapter_id,
                                request=request, images_dir=registry,
                                expected_result_sha256=expected, **_host(runtime))
        result_path = trial / "scratch" / "trial-result.json"
        commands = read_json(result_path).get("commands", []) if result_path.is_file() else []
        failed = next((c for c in commands if c.get("exit_code") != 0), None)
        db_source = trial / "scratch" / "src" / "compile_commands.json"
        if terminal["execution_status"] == "OK" and commands and failed is None and db_source.is_file():
            installs["rounds"].append({"round": round_no, "trial": "OK"})
            return (unit_attempt, record, image_id, fingerprint, dockerfile, trial, registry, adapter_id,
                    expected, commands, db_source, installs)
        last_failure = (f"{' '.join(map(str, (failed or {}).get('argv') or [])) or terminal['execution_status']} "
                        f"(exit {(failed or {}).get('exit_code')}); see {trial.relative_to(attempt).as_posix()}")
        if failed is None and commands and not db_source.is_file():
            last_failure = "build succeeded but produced no compile_commands.json"
            break
        trial_text = _trial_text(trial)
        _prune_trial_source(trial)
        conflicts = cow.version_conflicts(trial_text)
        if conflicts:
            installs["version_conflicts"] = conflicts
        downloads = cow.offline_downloads(trial_text)
        if downloads:
            installs["offline_downloads"] = downloads
            round_record = {"round": round_no, "trial": "FAILED", "failure": last_failure,
                            "needs": [], "resolved": {}, "installing": [], "offline_downloads": downloads}
            installs["rounds"].append(round_record)
            if "adapted_commands" not in installs:
                # The build fetches at build time and the trial is offline. Turn the project's
                # download switches off (the plan should have) and try again; the lock records the
                # adapted commands.
                source = Path(inputs["target_path"]) / plan.get("root", ".")
                guards = cow.download_guards(source)
                adapted = cow.with_options_off(plan["commands"], guards) if guards else plan["commands"]
                if adapted != plan["commands"]:
                    installs["adapted_commands"] = adapted
                    installs["adapted_options"] = [f"-D{g}=OFF" for g in guards]
                    round_record["adapting"] = installs["adapted_options"]
                    plan = {**plan, "commands": adapted}
                    continue
            break   # no package fixes a build-time download; configure's optional misses are noise
        needs = cow.missing_from_logs(trial_text)
        mapped = cow.packages_for(resolver, needs, log=log, prefer=set(planned)) if needs else {}
        new = sorted({pkg for pkg in mapped.values() if pkg} - set(installs["packages"]))
        installs["unresolved"] = sorted(key for key, pkg in mapped.items() if not pkg)
        installs["rounds"].append({"round": round_no, "trial": "FAILED", "failure": last_failure,
                                   "needs": [f"{n['kind']}:{n['name']}" for n in needs],
                                   "resolved": {k: v for k, v in mapped.items() if v}, "installing": new})
        if not new:
            break
        try:
            image = cow.install_layer(image, new, repository="appsec-build/cow-" + unit_key, run_id=run_id,
                                      unit=unit_key, round_no=round_no, log=log)
        except (cow.InstallFailed, subprocess.TimeoutExpired) as exc:
            last_failure = f"install round {round_no} failed ({exc})"
            break
        installs["packages"] = sorted(set(installs["packages"]) | set(new))
        installs["rounds"][-1]["image"] = image
    atomic_json(unit_root / "installs.json", installs)
    if defer_conflict and (installs.get("version_conflicts") or installs["dropped_unknown"]):
        # too-old versions, or apt names this release does not have (freeciv21/ai on noble:
        # libkf6archive-dev): the caller retries once on the newer sealed base
        return "VERSION_CONFLICT"
    gaps.append(f"{plan['unit_id']}: build on {installs['base']} did not succeed after {len(installs['rounds']) - 1} trial round(s): "
                f"{last_failure}"
                + (f"; dropped unknown apt names: {', '.join(installs['dropped_unknown'])}" if installs["dropped_unknown"] else "")
                + (f"; the build downloads at build time and the trial is offline: {', '.join(installs['offline_downloads'])} "
                   + (f"(retried with {' '.join(installs['adapted_options'])})" if installs.get("adapted_options")
                      else "(no CMake download switch found)") if installs.get("offline_downloads") else "")
                + (f"; unresolved: {', '.join(installs['unresolved'])}" if installs["unresolved"] else "")
                + (f"; version conflicts (not fixable from the pinned apt mirror): {'; '.join(installs['version_conflicts'])}"
                   if installs.get("version_conflicts") else "")
                + f"; installs: {(unit_root / 'installs.json').relative_to(attempt).as_posix()}")
    return None


def _validate_attempt(run_id: str, attempt: Path, inputs: dict[str, Any]) -> None:
    if read_json(attempt / "inputs.json") != inputs:
        raise Blocked(f"{JOB}: immutable attempt inputs changed")
    result = read_json(attempt / RESULT); lock = read_json(attempt / LOCK_FILE)
    if validate_document(result, "build-resolution.schema.json"):
        raise Blocked(f"{JOB}: result schema validation failed")
    if validate_document(lock, "buildenv-lock.schema.json"):
        raise Blocked(f"{JOB}: lock schema validation failed")
    if result["plan"] != {"attempt_id": inputs["plan"]["attempt_id"], "sha256": inputs["plan"]["sha256"]}:
        raise Blocked(f"{JOB}: result no longer binds the accepted plan")
    receipts = read_json(attempt / RECEIPTS)
    for receipt in receipts:
        trial = attempt / receipt["trial_path"]
        request = read_json(trial / "logs/container" / ce.REQUEST_FILE)
        runtime = _runtime(inputs["source_snapshot_sha256"], attempt / receipt["registry_path"])
        errors = ce.verify_container_result(trial, run_id=run_id, job_id=JOB,
            attempt_id=receipt["adapter_attempt_id"], request=request, images_dir=runtime.images_dir,
            expected_result_sha256=receipt["expected_result_sha256"], **_host(runtime))
        if errors:
            raise Blocked(f"{JOB}: B13 trial evidence failed re-verification ({len(errors)} errors)")
        db = attempt / receipt["compile_commands_path"]
        _compile_db(db, inputs["plan"]["value"]["toolchain"]["compile_database_compilers"])
    for unit in result["units"]:
        catalog_path, container_path = _catalog(unit["image_id"])
        if not catalog_path.is_file() or not container_path.is_file():
            raise Blocked(f"{JOB}: successful image is no longer catalogued")
        catalog = read_json(catalog_path)
        if validate_document(catalog, "build-image.schema.json"):
            raise Blocked(f"{JOB}: build-image catalog schema validation failed")
        if read_json(container_path)["digest"] != unit["image_digest"]:
            raise Blocked(f"{JOB}: catalogued image digest changed")


def run(run_id: str, dagster_id: str, force: bool = False) -> dict[str, Any]:
    base = root(run_id)
    resume = f"python -B appsec-review-process/launch_job.py --run-id {run_id} --job {DAGSTER_JOB} --wait"

    def execute(allocation, inputs, fingerprint):
        attempt = allocation["attempt"]; control = inputs["control"]["value"]
        if inputs["code"] != _code_hashes():
            raise Blocked(f"{JOB}: implementation changed before execution")
        units=[]; locks=[]; receipts=[]; gaps=[]; install_files=[]
        plans = inputs["plan"]["value"]["plans"]
        if not plans:
            gaps.append("no-build-units-planned")
        for number, plan in enumerate(plans, 1):
            # ADR-0013: a unit that cannot be built here is a coverage gap, not a failed run.
            feasibility = plan.get("feasibility") or {}
            if feasibility.get("tier") == "C" or not plan.get("commands"):
                reason = (feasibility.get("reasons") or ["no build commands planned"])[0]
                gaps.append(f"{plan['unit_id']}: not buildable in this environment (tier {feasibility.get('tier')}): {reason}")
                continue
            unit_key = digest(plan["unit_id"])[:12]
            fallback = _fallback_name(plan["image"]["base"])
            outcome = _resolve_unit_cow(run_id, attempt, plan, number, unit_key, inputs, control, gaps,
                                        defer_conflict=bool(fallback and fallback in inputs["base_images"]))
            if outcome == "VERSION_CONFLICT":
                plan = {**plan, "image": {**plan["image"], "base": fallback}}
                outcome = _resolve_unit_cow(run_id, attempt, plan, number, unit_key, inputs, control, gaps,
                                            label="-" + fallback)
            if outcome is None:
                continue
            (unit_attempt, record, image_id, spec_fingerprint, dockerfile, trial, registry, adapter_id,
             expected, commands, db_source, installs) = outcome
            if installs.get("adapted_commands"):
                plan = {**plan, "commands": installs["adapted_commands"]}   # the lock replays what built
            reused = False
            installs_path = attempt / "outputs" / unit_key / "installs.json"
            installs_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_json(installs_path, installs)
            install_files.append(installs_path.relative_to(attempt).as_posix())
            try:
                entries = _compile_db(db_source, inputs["plan"]["value"]["toolchain"]["compile_database_compilers"])
            except RuntimeError as exc:   # ADR-0013: one unit's unusable compile DB is that unit's gap
                gaps.append(f"{plan['unit_id']}: built, but its compile database is unusable: {exc}")
                continue
            db_target = attempt / "outputs" / unit_key / "compile_commands.json"
            db_target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(db_source, db_target)
            _prune_trial_source(trial)
            lock = {"unit_id": plan["unit_id"],
                "image": {"image_id": image_id, "digest": record["digest"], "digest_kind": "image-id"},
                "dockerfile_sha256": record["dockerfile_sha256"],
                "plan_sha256": "sha256:" + inputs["plan"]["sha256"],
                "configure": [c for c in _repo_commands(plan) if c["phase"] == "configure"],
                "build": [c for c in _repo_commands(plan) if c["phase"] == "build"],
                "compile_database": {"method": "bear", "path": "compile_commands.json",
                    "entries": len(entries), "compiler_allowlist": inputs["plan"]["value"]["toolchain"]["compile_database_compilers"]},
                "successful_attempt": {"resolution_attempt": unit_attempt.relative_to(attempt).as_posix(),
                    "image_reused": reused, "expected_result_sha256": expected},
                "permission_fingerprint_sha256": inputs["permission_fingerprint_sha256"]}
            locks.append(lock)
            receipts.append({"unit_id": plan["unit_id"], "adapter_attempt_id": adapter_id,
                "trial_path": trial.relative_to(attempt).as_posix(),
                "registry_path": registry.relative_to(attempt).as_posix(),
                "compile_commands_path": db_target.relative_to(attempt).as_posix(),
                "expected_result_sha256": expected})
            units.append({"unit_id": plan["unit_id"], "status": "OK", "image_id": image_id,
                "image_digest": record["digest"], "attempt_id": unit_attempt.name,
                "lock_sha256": digest(lock), "compile_commands": len(entries), "commands": commands})
            _publish_catalog(image_id, record, spec_fingerprint, dockerfile, inputs, plan, unit_attempt,
                             packages=installs["packages"])
        lock_set = {"schema": "appsec-review/buildenv-lock-set/1",
                    "source_revision": inputs["source_revision"],
                    "plan": {"attempt_id": inputs["plan"]["attempt_id"], "sha256": inputs["plan"]["sha256"]},
                    "locks": locks}
        result = {"schema": "appsec-review/build-resolution/1", "run_id": run_id,
                  "source_revision": inputs["source_revision"], "plan": lock_set["plan"],
                  "status": "OK_WITH_GAPS" if gaps else "OK", "units": units, "coverage_gaps": gaps}
        atomic_json(attempt / LOCK_FILE, lock_set); atomic_json(attempt / RESULT, result)
        atomic_json(attempt / RECEIPTS, receipts)
        (attempt / SUMMARY).write_text("# Build resolution\n\n" + "\n".join(
            f"- `{u['unit_id']}`: {u['compile_commands']} clang compile commands; `{u['image_id']}`"
            for u in units) + "\n" + "".join(f"- gap: {g}\n" for g in gaps), encoding="utf-8")
        status = {"process": JOB, "status": result["status"], "run_id": run_id,
                  "dagster_run_id": dagster_id, "attempt_id": allocation["attempt_id"],
                  "source_revision": inputs["source_revision"], "units": len(units),
                  "permissions": ["package-restore:apt@archive.ubuntu.com:80",
                                  "target-execution:build-resolution-v1@."],
                  "network": "image-build; trial=" + ("unrestricted (D-28)" if control.get("build_network") == "unrestricted" else "none"), "ended_at": now()}
        atomic_json(attempt / "status.json", status)
        artifacts = [RESULT, LOCK_FILE, RECEIPTS, SUMMARY, "status.json"] + [
            r["compile_commands_path"] for r in receipts] + install_files
        pointer = record_terminal_current(base, attempt, run_id=run_id, job_id=JOB,
            dagster_run_id=dagster_id, worker_kind="pinned_container", output_contract=CONTRACT,
            input_fingerprint=fingerprint, started_at=allocation["started_at"], execution_status=result["status"],
            summary=f"Resolved {len(units)} build unit(s) through the pinned-container boundary; {len(gaps)} gap(s).",
            status_record=status, artifact_paths=artifacts, gaps=gaps or None,
            pre_envelope_validate=lambda path, _status: _validate_attempt(run_id, path, inputs))
        return pointer

    return coordinate_worker_lifecycle(base, run_id=run_id, job_id=JOB, dagster_run_id=dagster_id,
        worker_kind="pinned_container", output_contract=CONTRACT, resume_command=resume,
        derive_inputs=lambda: current_inputs(run_id),
        fingerprint_inputs=lambda value: "sha256:" + digest(value), execute_attempt=execute,
        preflight_failure_inputs=lambda exc: {"run_id": run_id, "job": JOB,
            "preflight_error": f"{type(exc).__name__}: {exc}", "code": _code_hashes()}, force=force,
        post_validate=lambda attempt, _envelope, record: _validate_attempt(run_id, attempt, record),
        blocked_summary="Build resolution preflight did not complete.",
        failed_summary="Build resolution did not publish; no older success may be used.")


def validate(run_id: str, pointer: dict[str, Any] | None = None) -> Path:
    base = root(run_id); pointer = pointer or read_json(base / "accepted.json")
    record = current_inputs(run_id)
    attempt, _ = validate_published(base, pointer, "sha256:" + digest(record),
                                    expected_run_id=run_id, expected_job_id=JOB)
    _validate_attempt(run_id, attempt, record)
    return attempt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="command", required=True)
    stage = sub.add_parser("stage-control"); stage.add_argument("run_id"); stage.add_argument("--mode", default="success")
    stage.add_argument("--reuse", default="auto")
    check = sub.add_parser("validate"); check.add_argument("run_id")
    args = parser.parse_args()
    if args.command == "stage-control": print(stage_control(args.run_id, args.mode, args.reuse))
    else: print(validate(args.run_id))


# ADR-0013: drop shared runtime modules from this job's code fingerprint.
_code_hashes_all = _code_hashes


def _code_hashes(*args, **kwargs):
    from execution_state import drop_shared_runtime
    return drop_shared_runtime(_code_hashes_all(*args, **kwargs))
