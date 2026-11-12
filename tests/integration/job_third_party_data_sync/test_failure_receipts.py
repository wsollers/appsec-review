"""A real three-unit KEV branch retains HTTP/parser failures without running the whole job graph."""
from __future__ import annotations

from dataclasses import replace
import json

import pytest

from appsec_review.config import load_config
from appsec_review.interchange import TASK_RECEIPT_SCHEMA
from appsec_review.jobs.job_third_party_data_sync.job import build_job
from appsec_review.observability import EventLog
from appsec_review.runtime import JobContext, UnitExecutor
from tests.fixtures.reference_feeds import kev_document, kev_entry

from .support import JOB_ID, ROOT, Response, https_server


@pytest.mark.parametrize(("response", "failed_task", "error_type"), [
    (Response(b"", status=503), "fetch", "HTTPError"),
    (Response(b"{}"), "normalize", "ValueError"),
], ids=["http-failure", "malformed-catalog"])
def test_boundary_failure_writes_receipts_and_blocks_publication(
        tmp_path, monkeypatch, response, failed_task, error_type):
    routes = {"/kev.json": Response(json.dumps(kev_document([kev_entry("CVE-2026-0001")])).encode())}
    with https_server(routes, monkeypatch) as (base, requests):
        config = load_config(ROOT / "appsec-review.toml").job(JOB_ID)
        kev = replace(config.step("kev_sync"), settings={
            **config.step("kev_sync").settings, "url": base + "/kev.json",
            "allowed_hosts": ["127.0.0.1"], "timeout_seconds": 2,
        })
        config = replace(config, steps={**config.steps, "kev_sync": kev})
        context = JobContext(
            run_id="2026-11-12-0001", attempt_id="attempt_0001", trigger="integration",
            repository_root=tmp_path, run_root=tmp_path,
            attempt_root=tmp_path / f"data/jobs/{JOB_ID}/attempts/attempt_0001",
            metadata_root=tmp_path / "metadata", orchestration={}, config=config,
            events=EventLog(tmp_path / "data/logs/pipeline.jsonl"),
        )
        branch = UnitExecutor(tuple(unit for unit in build_job().units if unit.unit_id.startswith("kev_sync.")))
        good = branch.execute(context)
        assert good["status"] == "SUCCEEDED"
        pointer = tmp_path / "data/feeds/kev/current.json"
        before = pointer.read_bytes()
        metadata = tmp_path / "metadata/feeds/kev.json"
        before_metadata = metadata.read_bytes()
        routes["/kev.json"] = response
        failed = replace(context, attempt_id="attempt_0002",
                         attempt_root=tmp_path / f"data/jobs/{JOB_ID}/attempts/attempt_0002")
        result = branch.execute(failed)
        failed_id = f"kev_sync.{failed_task}"
        assert result["status"] == "FAILED" and result["steps"] == {"kev_sync": "FAILED"}
        assert result["failed_units"] == [failed_id]
        assert result["skipped_units"] == (
            ["kev_sync.normalize", "kev_sync.publish"] if failed_task == "fetch" else ["kev_sync.publish"])
        task = failed.attempt_root / f"steps/kev_sync/tasks/{failed_task}"
        receipt = json.loads((task / "status.json").read_bytes())
        assert receipt["schema"] == TASK_RECEIPT_SCHEMA and receipt["status"] == "FAILED"
        assert receipt["error"]["type"] == error_type and receipt["error"]["message"]
        assert error_type in (task / "traceback.txt").read_text()
        assert not (task / "result.json").exists()
        skipped = json.loads((failed.attempt_root / "steps/kev_sync/tasks/publish/status.json").read_bytes())
        assert skipped["status"] == "SKIPPED" and skipped["blocked_by"] == ["kev_sync.normalize"]
        assert pointer.read_bytes() == before and metadata.read_bytes() == before_metadata
        events = [json.loads(line) for line in
                  (task / "logs/events.jsonl").read_text().splitlines()]
        assert [event["event"] for event in events] == ["TASK_STARTED", "TASK_FAILED"]
        assert len(requests) == 2
