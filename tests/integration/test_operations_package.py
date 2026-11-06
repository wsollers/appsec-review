"""Manual only: isolated Dagster/collector endpoints; never production services."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
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


def test_interrupted_writer_process_and_restart_preserve_lifecycle(tmp_path):
    interrupted_program = r"""
from pathlib import Path
import os, sys
from appsec_review.observability.events import PipelineLog
from appsec_review.storage import FileLock
root = Path(sys.argv[1])
log = PipelineLog(root)
log.write("RUN_STARTED", run_id=root.name)
log.write("JOB_STARTED", run_id=root.name, job_id="job", attempt_id="attempt-1")
with FileLock(log.lock_path):
    with log.path.open("ab") as stream:
        stream.write(b'{"sequence":3')
        stream.flush()
        os.fsync(stream.fileno())
    sys.stdin.buffer.read(1)
"""
    restarted_program = r"""
from pathlib import Path
import sys
from appsec_review.observability.events import PipelineLog
root = Path(sys.argv[1])
log = PipelineLog(root)
log.write("RUN_STARTED", run_id=root.name)
log.write("JOB_STARTED", run_id=root.name, job_id="job", attempt_id="attempt-2")
log.write("JOB_SUCCEEDED", run_id=root.name, job_id="job", attempt_id="attempt-2")
log.write("RUN_COMPLETED", run_id=root.name, details={"completion_status": "SUCCEEDED"})
"""
    process = subprocess.Popen(
        [sys.executable, "-c", interrupted_program, str(tmp_path)], stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    follower = OperatorFollower(tmp_path)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if follower.poll() == "torn_tail":
                break
            assert process.poll() is None, "fixture writer exited before the interruption point"
            time.sleep(0.02)
        assert follower.read_status == "torn_tail"
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        if process.stdin:
            process.stdin.close()
        if process.stderr:
            process.stderr.close()
    assert process.returncode != 0
    assert follower.snapshot()["analysis_completeness"] == "unknown"
    resumed = PipelineLog(tmp_path)
    recovered = resumed.write("JOB_FAILED", run_id=tmp_path.name, job_id="job", attempt_id="attempt-1")
    assert recovered["details"]["log_recovery"]["incomplete_tail_bytes"] > 0
    subprocess.run([sys.executable, "-c", restarted_program, str(tmp_path)],
                   check=True, capture_output=True, timeout=10)
    follower.poll()
    report = follower.snapshot()
    assert [job["status"] for job in report["jobs"]] == ["FAILED", "SUCCEEDED"]
    assert report["jobs"][1]["retry_attempts_observed"] == 1
    assert report["operational_status"] == "SUCCEEDED"
