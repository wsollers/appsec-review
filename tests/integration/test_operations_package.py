"""Manual only: isolated Dagster/collector endpoints; never production services."""
from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen

from appsec_review.observability.diagnostics import read_execution_receipt
from appsec_review.observability.events import PipelineLog
from appsec_review.observability.operator import OperatorFollower
from appsec_review.observability.otlp import BoundedOTLP
from appsec_review.storage import atomic_json
from appsec_review.storage.verify import run_artifact


def test_real_writers_receipts_dagster_and_collector(tmp_path):
    assert os.environ.get("APPSEC_OPERATIONS_ISOLATED_SERVICES") == "1", "explicit isolated-service opt-in required"
    dagster = os.environ["APPSEC_OPERATIONS_DAGSTER_URL"]
    collector = os.environ["APPSEC_OPERATIONS_OTLP_URL"]
    log = PipelineLog(tmp_path)
    log.write("JOB_STARTED", run_id=tmp_path.name, job_id="job", attempt_id="attempt-1")
    receipt = tmp_path / "data/execution.json"
    atomic_json(receipt, {"schema": "appsec-review/container-execution/1", "timed_out": True,
                         "exit_code": -9, "stderr_sha256": "e" * 64})
    identity = run_artifact(tmp_path, receipt)
    event = log.write("TOOL_INVOCATION_COMPLETED", run_id=tmp_path.name,
                      details={"execution_receipt": identity})
    assert read_execution_receipt(tmp_path, identity)["category"] == "timeout"
    request = Request(dagster, data=json.dumps({"query": "{ runsOrError(limit: 10) { __typename ... on Runs "
                      "{ results { runId status startTime endTime tags { key value } } } } }"}).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=10) as response:
        payload = json.load(response)["data"]["runsOrError"]
    assert payload["__typename"] == "Runs"
    follower = OperatorFollower(tmp_path)
    follower.poll()
    assert follower.snapshot(dispatches=payload["results"])["operational_status"] == "UNKNOWN"
    def send(batch):
        with urlopen(Request(collector, data=json.dumps(batch).encode(),
                             headers={"Content-Type": "application/json"}), timeout=10) as response:
            assert 200 <= response.status < 300
    exporter = BoundedOTLP(send, enabled=True)
    assert exporter.offer(event) == "queued"
    assert exporter.flush()["status"] == "exported"


def test_interrupted_writer_and_restart_preserve_lifecycle(tmp_path):
    log = PipelineLog(tmp_path)
    log.write("JOB_STARTED", run_id=tmp_path.name, job_id="job", attempt_id="attempt-1")
    with log.path.open("ab") as stream:
        stream.write(b'{"interrupted":')
    follower = OperatorFollower(tmp_path)
    assert follower.poll() == "torn_tail"
    assert follower.snapshot()["analysis_completeness"] == "unknown"
    resumed = PipelineLog(tmp_path)
    resumed.write("JOB_FAILED", run_id=tmp_path.name, job_id="job", attempt_id="attempt-1")
    resumed.write("JOB_STARTED", run_id=tmp_path.name, job_id="job", attempt_id="attempt-2")
    follower.poll()
    assert follower.snapshot()["jobs"][1]["retry_attempts_observed"] == 1
