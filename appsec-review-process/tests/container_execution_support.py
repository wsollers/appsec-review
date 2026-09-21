"""Shared builders for the pinned-container adapter tests (B13). Not a test module."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import container_execution as ce  # noqa: E402
import permission_capabilities as pc  # noqa: E402

RUN, JOB, ATTEMPT = "run-b13", "job-b13", "attempt-b13"
IDS = {"run_id": RUN, "job_id": JOB, "attempt_id": ATTEMPT}
SNAPSHOT = "sha256:" + "a" * 64
NOW = "2026-09-20T12:00:00Z"
FIXTURE_IMAGE_ID = "fixture-harmless"
# Never echoed: a hostile value carries this marker and every message is searched for it.
MARKER = "zq-hostile-marker"


def fixture_record() -> dict:
    return ce.load_image_registry(ce.IMAGES_DIR)[FIXTURE_IMAGE_ID]


def context(now: str = NOW, job_id: str = JOB, run_id: str = RUN) -> dict:
    return {"run_id": run_id, "job_id": job_id, "source_snapshot_sha256": SNAPSHOT, "now": now,
            "registry_ceiling": None}


def entry(kind: str, origin: str, **parameters) -> dict:
    return {"kind": kind, "version": "1.0", "origin": origin,
            "parameters": {name: parameters.get(name) for name in pc.PARAMETER_NAMES}}


def permission(capabilities: list[tuple[str, dict]] | None = None, *, now: str = NOW,
               job_id: str = JOB, run_id: str = RUN) -> dict:
    """A requirement, the grants that allow exactly it, and the GRANTED decision."""
    capabilities = capabilities or []
    requirement = {"schema": "appsec-review/permission-requirement/1.0", "job_id": job_id,
                   "capabilities": [entry(kind, "registry", **p) for kind, p in capabilities]}
    grants = []
    if capabilities:
        grants.append({
            "schema": "appsec-review/permission-grant/1.0", "grant_id": "grant-b13", "effect": "ALLOW",
            "authority": {"name": "Test Owner", "role": "engagement-owner"},
            "issued_at": "2026-09-20T00:00:00Z", "expires_at": "2026-09-21T00:00:00Z",
            "binding": {"run_id": run_id, "source_snapshot_sha256": SNAPSHOT, "job_id": job_id},
            "justification": "fixture grant for the adapter tests",
            "capabilities": [entry(kind, "operator", **p) for kind, p in capabilities]})
    decision = pc.evaluate(requirement, grants, context(now, job_id, run_id))
    return {"requirement": requirement, "grants": grants, "decision": decision}


def limits(**over) -> dict:
    return {"timeout_seconds": 60, "memory_bytes": 64 * 1024 * 1024, "cpu_millis": 500, "pids": 32,
            "tmpfs_bytes": 4 * 1024 * 1024, "stdout_limit_bytes": 65536, "stderr_limit_bytes": 65536,
            **over}


def request(target: Path | None, argv: list, **over) -> dict:
    record = fixture_record()
    value = {
        "schema": ce.REQUEST_ID, **IDS,
        "image": {"image_id": record["image_id"], "digest": record["digest"]},
        "argv": argv,
        "environment": [{"name": "LANG", "value": "C"}],
        "target_mounts": ([] if target is None else
                          [{"host_path": str(target), "container_path": "/workspace"}]),
        "scratch_path": "scratch",
        "log_path": "logs/container",
        "network": {"mode": "none", "destinations": []},
        "permission": permission(),
        "limits": limits(),
    }
    value.update(deepcopy(over))
    return json.loads(json.dumps(value))


def runtime(**over) -> ce.ContainerRuntime:
    defaults = ce.host_defaults()
    fields = {
        "docker_executable": defaults["docker_executable"] or Path(sys.executable).resolve(),
        "docker_host": None, "images_dir": ce.IMAGES_DIR, "host_flavor": defaults["host_flavor"],
        "container_user": defaults["container_user"] if defaults["container_user"] != "0:0" else "10001:10001",
        "source_snapshot_sha256": SNAPSHOT, "registry_ceiling": None, "clock": lambda: NOW,
        "cancel": threading.Event(),
    }
    fields.update(over)
    return ce.ContainerRuntime(**fields)


def run(rt: ce.ContainerRuntime, attempt_root: Path, req, **ids):
    return ce.run_container(rt, **{**IDS, **ids}, attempt_root=attempt_root, request=req)


def host_facts() -> dict:
    """The integrator's host facts the verification path needs for the target-mount rule: the same
    two fields of the runtime that run_container reads."""
    rt = runtime()
    return {"host_flavor": rt.host_flavor, "docker_host": rt.docker_host}


def verify(attempt_root: Path, req, **over) -> list[str]:
    return ce.verify_container_result(attempt_root, **{**IDS, "request": req,
                                                       "images_dir": ce.IMAGES_DIR, **host_facts(), **over})
