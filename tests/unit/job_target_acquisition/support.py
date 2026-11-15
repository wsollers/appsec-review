"""Synthetic, per-test inputs; no acquisition process or target checkout is used."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from appsec_review.jobs.job_target_acquisition import build_job
from appsec_review.runtime import UnitContext


JOB_ID = "job_target_acquisition"
SCHEMA = "appsec-review/target-acquisition-job/2"
SYSTEM_SCHEMA = "appsec-review/target-system-acquisition/1"
ATTEMPT = f"data/jobs/{JOB_ID}/attempts/attempt_0001"
SELECTION = "selection.resolve_system"
ACQUISITION = "acquisition.acquire_components"
PUBLICATION = "publication.publish_handoff"
CONFIGURATION = "data/configuration/appsec-review.toml"
COMPONENTS = ("service", "library")


def frozen_text(*, parallel: int = 4, components=COMPONENTS) -> str:
    return (
        '[target_acquisition]\n'
        'targets_dir = "checkouts"\n'
        'records_dir = "acquisition-records"\n'
        f"max_parallel_components = {parallel}\n"
        '[[target_acquisition.systems]]\n'
        'id = "sys"\n'
        + "".join(
            '[[target_acquisition.systems.components]]\n'
            f'id = "{component}"\n'
            f'url = "https://example.invalid/{component}.git"\n'
            f'commit = "{"a" * 40}"\n'
            for component in components
        )
    )


def unit_context(tmp_path: Path, unit_id: str, *, outputs=None, target_root=None, frozen=None):
    run_root = tmp_path / "run"
    configuration = run_root / CONFIGURATION
    configuration.parent.mkdir(parents=True, exist_ok=True)
    configuration.write_text(frozen_text() if frozen is None else frozen, encoding="utf-8")
    step_id, task_id = unit_id.split(".")
    unit_root = run_root / ATTEMPT / "steps" / step_id / "tasks" / task_id
    unit_root.mkdir(parents=True, exist_ok=True)
    events = []
    job = SimpleNamespace(
        repository_root=tmp_path, run_root=run_root, attempt_root=run_root / ATTEMPT,
        target_root=target_root,
        events=SimpleNamespace(write=lambda event, **fields: events.append((event, fields))),
    )
    return UnitContext(job, unit_id, step_id, task_id, unit_root, outputs or {}), events


def handler(unit_id: str, **kwargs):
    return next(unit.handler for unit in build_job(**kwargs).units if unit.unit_id == unit_id)


def artifact_document(context, identity):
    path = context.job.run_root / identity["path"]
    data = path.read_bytes()
    assert identity["sha256"] == hashlib.sha256(data).hexdigest()
    if "size_bytes" in identity:
        assert identity["size_bytes"] == len(data)
    return json.loads(data)


def plan(*, requested=True, system_id="sys"):
    return {
        "schema": SCHEMA, "requested": requested, "system_id": system_id,
        "artifact": {
            "path": f"{ATTEMPT}/steps/selection/tasks/resolve_system/target-acquisition-plan.json",
            "sha256": "1" * 64, "size_bytes": 17,
        },
    }


def backend_result(*, status="COMPLETE", gaps=()):
    return {
        "status": status, "acquisition_id": "sys@fixture",
        "target_path": "checkouts/sys", "manifest": None, "manifest_sha256": None,
        "tree_sha256": "2" * 64, "verification": "acquisition-records/sys/verification.json",
        "completed_at": "2026-01-02T03:04:05Z",
        "components": {
            "service": {
                "status": "COMPLETE", "action": "acquired", "acquisition_id": "service@fixture",
                "target_path": "checkouts/sys/service", "manifest": "service-manifest.json",
                "manifest_sha256": "3" * 64, "tree_sha256": "4" * 64,
                "error": None, "failure_record": None, "private_backend_field": "must not be copied",
            },
            "library": {"status": "VERIFIED", "action": "verified"},
        },
        "gaps": list(gaps), "error": None, "private_backend_field": "must not be copied",
    }


def fake_backend(monkeypatch, context, result):
    from appsec_review.target_acquisition import acquire

    calls = []
    records = context.job.repository_root / "acquisition-records" / "sys"
    records.mkdir(parents=True, exist_ok=True)

    def acquire_system(**kwargs):
        calls.append(("acquire", kwargs))
        return result

    def system_paths(repository_root, settings, system_id):
        calls.append(("paths", repository_root, settings, system_id))
        return repository_root / "checkouts" / system_id, records

    monkeypatch.setattr(acquire, "acquire_system", acquire_system)
    monkeypatch.setattr(acquire, "system_paths", system_paths)
    return calls, records
