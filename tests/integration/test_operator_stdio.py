"""Manual stdio interoperability checks. Do not run as an offline unit gate."""

import json
from pathlib import Path
import subprocess
import sys

from tests.test_retrieval_core import RUN_ID, _fixture


def exchange(runs, calls):
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "manual-integration", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        *({"jsonrpc": "2.0", "id": index + 2, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}}
          for index, (name, arguments) in enumerate(calls)),
    ]
    result = subprocess.run(
        [sys.executable, "-m", "appsec_review.mcp.stdio", "--runs-dir", str(runs), "--run-id", RUN_ID],
        input="".join(json.dumps(request) + "\n" for request in requests), text=True,
        capture_output=True, check=True, timeout=20, cwd=Path(__file__).parents[2])
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(responses) == len(calls) + 1
    return responses[1:]


def test_explicit_accepted_fixture_retrieval_and_stdio_permission_negatives(tmp_path):
    runs, ids = _fixture(tmp_path)
    responses = exchange(runs, [
        ("find", {"identity": ids["symbol"]}),
        ("read_excerpt", {"identity": ids["symbol"]}),
        ("query_artifacts", {"path": "/etc/passwd"}),
        ("inspect_dagster", {"dispatch_id": RUN_ID, "query": "mutation { launch }"}),
        ("execute_shell", {"command": "touch forbidden"}),
    ])
    assert responses[0]["result"]["structuredContent"]["results"][0]["identity"] == ids["symbol"]
    assert responses[1]["result"]["isError"] is False
    assert all(response["error"]["code"] == -32602 for response in responses[2:])
    assert not (runs / RUN_ID / "data/logs/pipeline.jsonl").exists()


def test_unaccepted_run_is_inspectable_but_retrieval_is_not_success(tmp_path):
    root = tmp_path / RUN_ID
    root.mkdir()
    responses = exchange(tmp_path, [("inspect_run", {}), ("coverage", {})])
    assert responses[0]["result"]["structuredContent"]["results"][0]["availability"] == "unaccepted"
    assert responses[1]["result"]["isError"] is True
