from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.runtime import Job, JobRunner


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
""".strip(),
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
