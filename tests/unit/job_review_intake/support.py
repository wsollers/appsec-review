"""Synthetic, per-test inputs for direct intake handler calls."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from appsec_review.config.exclusions import PathExclusions
from appsec_review.jobs.job_review_intake import job as intake

ROOT = Path(__file__).resolve().parents[3]
JOB_ID = "job_review_intake"
HOST_BYTES = (
    'schema = "appsec-review/host-pins/1"\npreinstalled_runtimes = []\n'
    '[images]\n"fixture:unit" = "sha256:' + "a" * 64 + '"\n'
).encode()


def dump(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def configuration(run_root: Path, document=None, *, sources=None):
    root = run_root / "data/configuration"
    root.mkdir(parents=True, exist_ok=True)
    if document is None:
        document = {
            "runtime": {"data_dir": "data"},
            "jobs": {},
            "configuration_profile": {"name": "dev", "path": None},
            "configuration_host_pins": {
                "sha256": hashlib.sha256(HOST_BYTES).hexdigest(),
                "document": {
                    "schema": "appsec-review/host-pins/1", "preinstalled_runtimes": [],
                    "images": {"fixture:unit": "sha256:" + "a" * 64},
                },
            },
        }
    if sources is None:
        sources = [
            {"path": "fixture/appsec-review.toml", "sha256": "b" * 64},
            {"layer": "host-pins", "sha256": hashlib.sha256(HOST_BYTES).hexdigest()},
        ]
    dump(root / "resolved.json", document)
    manifest = {
        "sources": sources,
        "resolved_sha256": hashlib.sha256((root / "resolved.json").read_bytes()).hexdigest(),
    }
    dump(root / "manifest.json", manifest)
    (root / "host-pins.toml").write_bytes(HOST_BYTES)
    (root / "appsec-review.toml").write_text("[runtime]\ndata_dir = 'data'\n", encoding="utf-8")
    return document, manifest


def context(tmp_path: Path, unit_id: str, outputs=None):
    steps = {step: SimpleNamespace(tasks=tasks) for step, tasks in intake.TOPOLOGY.items()}
    config = SimpleNamespace(
        steps=steps, step=lambda name: steps[name], inventory_max_file_bytes=128,
        exclusions=PathExclusions(), settings={"model_preflight": {"timeout_seconds": 19}},
    )
    run_root = tmp_path / "run"
    step_id, task_id = unit_id.split(".")
    unit_root = run_root / f"data/jobs/{JOB_ID}/attempts/attempt_0001/steps/{step_id}/tasks/{task_id}"
    unit_root.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    events = []
    job = SimpleNamespace(
        run_root=run_root, repository_root=tmp_path, target_root=target,
        source_fingerprint="planned", config=config,
        events=SimpleNamespace(write=lambda event, **fields: events.append((event, fields))),
    )
    values = {} if outputs is None else outputs
    return SimpleNamespace(
        job=job, unit_id=unit_id, unit_root=unit_root, step_id=step_id, task_id=task_id,
        outputs=values, output=lambda key: values[key], events=events,
    )


def handler(unit_id: str, **kwargs):
    return next(unit.handler for unit in intake.build_job(**kwargs).units if unit.unit_id == unit_id)


def artifact(unit, result):
    path = unit.job.run_root / result["artifact"]["path"]
    assert result["artifact"] == {
        "path": path.relative_to(unit.job.run_root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size_bytes": path.stat().st_size,
    }
    return json.loads(path.read_text(encoding="utf-8"))


def publish_context(tmp_path, *, coverage=(), acquisition=None):
    return context(tmp_path, "publish_intake.publish_handoff", {
        "resolve_configuration.freeze_config": {"path": "data/configuration/appsec-review.toml", "sha256": "a" * 64},
        "prepare_target.resolve_target": {"path": "fixture/target", "kind": "directory"},
        "prepare_target.fingerprint_target": {
            "sha256": "b" * 64, "coverage": {"coverage_gaps": list(coverage)}, "acquisition": acquisition},
        "model_preflight.verify_models": {"schema": intake.PREFLIGHT_SCHEMA, "verified": ["p/m"]},
        "binary_evidence.resolve_publications": {"schema": intake.BINARY_EVIDENCE_SCHEMA, "binaries": []},
    })
