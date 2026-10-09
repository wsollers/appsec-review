from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.runtime import Job, JobRunner, Unit, UnitExecutor
from appsec_review.runtime.runner import _accepted_retrieval_manifest
from tests.capture_fakes import build_capture_toml


def write_config(root: Path) -> Path:
    path = root / "appsec-review.toml"
    path.write_text(
        """
[runtime]
runs_dir = "runs"
data_dir = "data"

[jobs.job_fixture]
name = "fixture"
workers = 1
""".strip() + "\n\n" + build_capture_toml(),
        encoding="utf-8",
    )
    return path


def test_job_composes_validators_around_handler(tmp_path: Path) -> None:
    calls: list[str] = []

    def pre(context, result):
        assert result is None
        calls.append("pre")

    def handler(context):
        calls.append("handler")
        return {"value": 7}

    def post(context, result):
        assert result == {"value": 7}
        calls.append("post")

    job = Job("job_fixture", "fixture", handler, (pre,), (post,))
    outcome = JobRunner(load_config(write_config(tmp_path))).run(
        job,
        now=datetime(2026, 10, 8, tzinfo=timezone.utc),
    )

    assert calls == ["pre", "handler", "post"]
    assert outcome["status"]["status"] == "SUCCEEDED"
    assert outcome["status"]["run_id"] == "2026-10-08-0001"
    configuration = tmp_path / "runs" / "2026-10-08-0001" / "data" / "configuration"
    assert (configuration / "appsec-review.toml").read_bytes() == (tmp_path / "appsec-review.toml").read_bytes()
    assert json.loads((configuration / "manifest.json").read_text(encoding="utf-8"))["source_sha256"]


def test_specialized_manifest_does_not_replace_global_retrieval_manifest(tmp_path: Path) -> None:
    standard = tmp_path / "data" / "indices" / "standard.json"
    specialized = tmp_path / "data" / "indexes" / "owasp" / "specialized.json"
    for path, schema in ((standard, "appsec-review/index-manifest/1"),
                         (specialized, "appsec-review/owasp-index-manifest/1")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": schema}), encoding="utf-8")
    artifacts = [{
        "path": path.relative_to(tmp_path).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    } for path in (standard, specialized)]

    selected = _accepted_retrieval_manifest(tmp_path, artifacts)

    assert selected is not None
    assert selected[1] == standard.resolve()
    assert _accepted_retrieval_manifest(tmp_path, artifacts[1:]) is None


def test_failed_job_has_a_terminal_receipt(tmp_path: Path) -> None:
    def fail(context):
        raise RuntimeError("expected failure")

    job = Job("job_fixture", "fixture", fail)
    runner = JobRunner(load_config(write_config(tmp_path)))
    with pytest.raises(RuntimeError, match="expected failure"):
        runner.run(job, now=datetime(2026, 10, 8, tzinfo=timezone.utc))

    status_path = next((tmp_path / "runs").glob("*/data/jobs/job_fixture/attempts/*/status.json"))
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["status"] == "FAILED"
    assert status["error"]["type"] == "RuntimeError"


def test_unit_executor_attempts_independent_branch_and_skips_only_dependents(tmp_path: Path) -> None:
    calls: list[str] = []

    def fail(context):
        calls.append(context.unit_id)
        raise RuntimeError("branch failure")

    def succeed(context):
        calls.append(context.unit_id)
        return {"ok": True}

    executor = UnitExecutor((
        Unit("first.fetch", fail),
        Unit("second.fetch", succeed),
        Unit("first.publish", succeed, ("first.fetch",)),
        Unit("second.publish", succeed, ("second.fetch",)),
    ))
    runner = JobRunner(load_config(write_config(tmp_path)))
    with pytest.raises(RuntimeError, match="partial failure"):
        runner.run(Job("job_fixture", "fixture", executor.execute),
                   now=datetime(2026, 10, 8, tzinfo=timezone.utc))

    result_path = next((tmp_path / "runs").glob("*/data/jobs/job_fixture/attempts/*/result.json"))
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert calls == ["first.fetch", "second.fetch", "second.publish"]
    assert result["units"]["first.fetch"]["status"] == "FAILED"
    assert result["units"]["first.publish"]["status"] == "SKIPPED"
    assert result["units"]["second.publish"]["status"] == "SUCCEEDED"
