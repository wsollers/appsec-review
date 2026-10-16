"""A small on-disk application run in the shape JobRunner leaves it."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

RUN_ID = "2026-10-16-0004"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def make_job(run_root: Path, job_id: str, *, dagster_run_id: str, gaps=(), findings=(), status="SUCCEEDED",
             started="2026-10-16T20:21:14.042894+00:00", artifact_text="{\"items\": [1, 2]}",
             upstream=None) -> Path:
    attempt = run_root / "data" / "jobs" / job_id / "attempts" / "attempt_0001"
    relative_attempt = attempt.relative_to(run_root).as_posix()
    write_json(attempt / "claim.json", {"run_id": run_root.name, "job_id": job_id,
                                       "orchestration": {"system": "dagster", "run_id": dagster_run_id}})
    write_json(attempt / "status.json", {"status": status, "run_id": run_root.name, "started_at": started})
    artifact = attempt / "artifacts" / "out.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(artifact_text, encoding="utf-8")
    result = write_json(attempt / "result.json", {
        "schema": "appsec-review/unit-execution/2", "status": status,
        "steps": {"work": "SUCCEEDED"}, "failed_units": [], "skipped_units": [],
        "units": {"work.scan": {"status": "SUCCEEDED", "disposition": None, "producer": "tool-x",
                                "completed_at": started, "dagster_run_id": dagster_run_id}},
        "outputs": {"work.scan": {
            "gaps": list(gaps), "findings": list(findings), "duration_ms": 1234,
            "path": f"/opt/app/runs/{run_root.name}/{relative_attempt}/artifacts/out.json",
            "image_id": "sha256:" + "a" * 64,
            "scratch": "/opt/project/.appsec-review-build-scratch.T70GHa",
        }},
    })
    handoff = write_json(attempt / "handoff.json", {
        "schema": "appsec-review/job-handoff/1", "status": "ACCEPTED", "job_id": job_id,
        "attempt_id": "attempt_0001", "completion_status": status, "schema_identity": f"{job_id}/1",
        "upstream_handoff_sha256": dict(upstream or {}),
        "resolving_paths": {"attempt": relative_attempt, "result": f"{relative_attempt}/result.json"},
        "artifacts": [
            {"path": f"{relative_attempt}/result.json", "sha256": sha(result), "size_bytes": result.stat().st_size},
            {"path": f"{relative_attempt}/artifacts/out.json", "sha256": sha(artifact),
             "size_bytes": artifact.stat().st_size},
        ],
    })
    write_json(run_root / "data" / "jobs" / job_id / "latest.json", {
        "schema": "appsec-review/latest-handoff/1", "attempt_id": "attempt_0001",
        "handoff_path": f"{relative_attempt}/handoff.json", "handoff_sha256": sha(handoff)})
    return attempt
