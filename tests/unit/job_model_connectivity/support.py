"""Small run-owned fixtures, not a graph, provider client or target checkout."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from appsec_review.jobs.job_model_connectivity import build_job
from appsec_review.runtime import UnitContext


JOB_ID = "job_model_connectivity"
SCHEMA = "appsec-review/model-preflight/1"
RESOLVE = "connectivity.resolve_models"
VERIFY = "connectivity.verify_models"
PUBLISH = "publication.publish_handoff"


def configuration(*, timeout=37):
    steps = {
        "connectivity": SimpleNamespace(tasks=("resolve_models", "verify_models")),
        "publication": SimpleNamespace(tasks=("publish_handoff",)),
    }
    return SimpleNamespace(steps=steps, step=steps.__getitem__, settings={"timeout_seconds": timeout})


def context(tmp_path: Path, unit_id: str, outputs=None, *, timeout=37) -> UnitContext:
    step, task = unit_id.split(".")
    run_root = tmp_path / "run"
    events = []
    job = SimpleNamespace(
        run_root=run_root,
        config=configuration(timeout=timeout),
        events=SimpleNamespace(write=lambda name, **details: events.append((name, details)), records=events),
    )
    return UnitContext(
        job=job, unit_id=unit_id, step_id=step, task_id=task,
        unit_root=run_root / "data/jobs" / JOB_ID / "attempts/attempt_0001/steps" / step / "tasks" / task,
        outputs={} if outputs is None else outputs,
    )


def handler(unit_id: str, *, check_models=None):
    return next(unit.handler for unit in build_job(check_models=check_models).units if unit.unit_id == unit_id)


def model(job_id: str, provider: str, name: str, *, enabled=True, reason=None):
    record = {
        "job_id": job_id, "setting": "settings.model", "provider": provider,
        "model": name, "enabled": enabled,
    }
    if reason is not None:
        record["reason"] = reason
    return record


def write_configuration(run_root: Path, document: dict) -> None:
    directory = run_root / "data/configuration"
    directory.mkdir(parents=True)
    data = json.dumps(document, sort_keys=True).encode()
    (directory / "resolved.json").write_bytes(data)
    (directory / "manifest.json").write_text(
        json.dumps({"resolved_sha256": hashlib.sha256(data).hexdigest()}), encoding="utf-8",
    )


def serving(calls: list):
    def check(provider, names, *, timeout_seconds):
        calls.append((provider, tuple(names), timeout_seconds))
        return {
            "provider": provider, "transport": True, "method": "probe", "error": None,
            "models": {name: {"available": True, "detail": "fixture answered"} for name in names},
        }
    return check
