"""Offline real HTTP/stdio/PowerShell boundaries, with exact owned process cleanup."""
from __future__ import annotations

import base64
import json
import os
from uuid import uuid4

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as intake
from appsec_review.jobs.job_target_catalog import build_job as catalog
from appsec_review.mcp.schema import TOOLS
from appsec_review.observability import PipelineLog, write_run_metrics
from appsec_review.runtime import GraphRunner
from tests.fixtures.process_lifecycle.support import (
    LINUX, case, completed, kill_owned, prepare, process, read, wait_for,
)
from tests.fixtures.process_lifecycle.transports import submission_server


@pytest.mark.parametrize("barrier", ["intent", "remote-ack", "ack"])
def test_killed_submitter_keeps_durable_intent_and_refuses_duplicate_until_exact_reconciliation(barrier):
    with case(f"submission-{barrier}") as workspace:
        root = prepare(workspace)
        original, next_id = str(uuid4()), str(uuid4())
        with submission_server() as (url, server):
            if barrier == "remote-ack":
                server["acknowledge"].clear()
            action = "submit-intent" if barrier == "intent" else "submit-ack"
            with process(root, action, url, original) as submitter:
                if barrier == "remote-ack":
                    assert server["accepted"].wait(10)
                    assert not (root / "ack-received.json").exists()
                else:
                    wait_for(lambda: (root / f"{'intent-persisted' if barrier == 'intent' else 'ack-received'}.json").exists(),
                             timeout=10)
                journal = root / "runs/metadata/dagster-submission/active.json"
                before = journal.read_bytes()
                assert read(journal)["state"] == "UNCERTAIN"
                kill_owned(submitter)
                assert submitter.returncode != 0
            server["acknowledge"].set()
            refused = completed(root, "refuse-submission", url, next_id)
            assert "no resubmission is allowed" in refused["refused"]
            assert journal.read_bytes() == before
            assert len(server["launches"]) == (0 if barrier == "intent" else 1)
            if barrier == "intent":
                # No server receipt exists: absence is not a terminal identity proof.
                with process(root, "reconcile-submission", url, original) as retry:
                    retry.wait(timeout=10)
                    assert retry.returncode != 0
                assert journal.read_bytes() == before
            else:
                with process(root, "reconcile-submission", url, str(uuid4())) as wrong:
                    wrong.wait(timeout=10)
                    assert wrong.returncode != 0
                assert journal.read_bytes() == before
                with process(root, "reconcile-submission", url, original) as active:
                    active.wait(timeout=10)
                    assert active.returncode != 0
                assert journal.read_bytes() == before
                server["status"] = "SUCCESS"
                reconciled = completed(root, "reconcile-submission", url, original)
                assert reconciled["state"] == "RECONCILED"
                next_record = completed(root, "begin-next", url, next_id)
                assert next_record["dagster_run_id"] == next_id
                archived = read(journal.parent / f"{original}.json")
                assert archived == reconciled
                assert len(server["launches"]) == 1
            workspace.emit("ACCEPTANCE_SUBMISSION_OBSERVED", barrier=barrier,
                           launch_count=len(server["launches"]), original_run_id=original)


@pytest.mark.parametrize("fault", ["fsync", "replace"])
def test_submission_storage_failure_dispatches_nothing(fault):
    with case(f"submission-{fault}-failure") as workspace:
        root = prepare(workspace)
        with submission_server() as (url, server):
            result = completed(root, "storage-failure", url, str(uuid4()), fault)
            assert result["error"] == f"fixture {fault} unavailable"
            assert server["launches"] == []
            assert not (root / "runs/metadata/dagster-submission/active.json").exists()


def _accepted_run(workspace, root):
    config = load_config(root / "appsec-review.toml", profile="dev", overlay="")
    outcome = GraphRunner(config, [intake(), catalog()]).run(
        target_root=root / "target", source_fingerprint=source_fingerprint(root / "target"))
    return outcome["run_id"]


def _exchange(root, runs, run_id, requests, *arguments, exit_code=0):
    with process(root, "mcp", "--runs-dir", runs, "--run-id", run_id, *arguments) as server:
        server.communicate("".join(
            item if isinstance(item, str) else json.dumps(item) + "\n"
            for item in requests), timeout=15)
        assert server.returncode == exit_code, sorted(root.glob("mcp-*.stderr"))[-1].read_text(encoding="utf-8")
    output = sorted(root.glob("mcp-*.stdout"))[-1].read_text(encoding="utf-8")
    return [json.loads(line) for line in output.splitlines()]


def _request(number, method, **params):
    return {"jsonrpc": "2.0", "id": number, "method": method, "params": params}


def test_real_mcp_initialization_discovery_tools_errors_and_recovery():
    with case("mcp-protocol") as workspace:
        root = prepare(workspace)
        run_id = _accepted_run(workspace, root)
        responses = _exchange(root, workspace.runs_dir, run_id, [
            _request(1, "initialize", protocolVersion="2025-06-18", capabilities={},
                     clientInfo={"name": "acceptance", "version": "1"}),
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            _request(2, "tools/list"), _request(3, "ping"),
            _request(4, "tools/call", name="coverage", arguments={}),
            _request(5, "tools/call", name="search", arguments={"query": "main.py"}),
            _request(6, "not-a-method"),
            {"jsonrpc": "1.0", "id": 7, "method": "ping"},
            _request(8, "tools/call", name="not-a-tool", arguments={}),
            _request(9, "tools/call", name="find", arguments={"limit": "invalid"}),
            _request(10, "ping"),
        ])
        assert [response["id"] for response in responses] == list(range(1, 11))
        assert responses[0]["result"]["protocolVersion"] == "2025-06-18"
        assert responses[1]["result"]["tools"] == list(TOOLS)
        assert responses[2]["result"] == responses[-1]["result"] == {}
        assert responses[3]["result"]["structuredContent"]["run_id"] == run_id
        assert responses[4]["result"]["structuredContent"]["run_id"] == run_id
        assert responses[5]["error"]["code"] == -32601
        assert responses[6]["error"]["code"] == -32602
        assert responses[7]["error"]["code"] == -32602
        assert responses[8]["error"]["code"] == -32602
        run_root = workspace.runs_dir / run_id
        metrics = write_run_metrics(run_root)
        events, _ = PipelineLog(run_root).read()
        calls = [item for item in events if item["event_type"] == "MCP_TOOL_COMPLETED"]
        assert len(calls) == metrics["event_counts"]["MCP_TOOL_COMPLETED"] == 3
        assert len({item["details"]["mcp_invocation_id"] for item in calls}) == 3
        assert [item["details"]["terminal_status"] for item in calls] == ["SUCCEEDED", "SUCCEEDED", "FAILED"]


def test_real_mcp_manifest_pin_mismatch_fails_closed():
    with case("mcp-manifest-pin") as workspace:
        root = prepare(workspace)
        run_id = _accepted_run(workspace, root)
        responses = _exchange(root, workspace.runs_dir, run_id, [
            _request(1, "tools/call", name="coverage", arguments={}), _request(2, "ping"),
        ], "--manifest-sha256", "0" * 64, exit_code=1)
        assert responses == []
        errors = sorted(root.glob("mcp-*.stderr"))[-1].read_text(encoding="utf-8")
        assert "MCP session manifest pin does not match accepted index set" in errors
        assert _exchange(root, workspace.runs_dir, run_id, [_request(3, "ping")])[0]["result"] == {}


def test_real_mcp_malformed_first_message_does_not_kill_session_or_reuse_previous_id():
    with case("mcp-parse-recovery") as workspace:
        root = prepare(workspace)
        run_id = _accepted_run(workspace, root)
        responses = _exchange(root, workspace.runs_dir, run_id, [
            "{\n", _request(1, "ping"), "{\n", _request(2, "ping")])
        assert [item["id"] for item in responses] == [None, 1, None, 2]
        assert all(responses[index]["error"]["code"] == -32700 for index in (0, 2))
        assert responses[1]["result"] == responses[3]["result"] == {}


@pytest.mark.skipif(not LINUX, reason="production admission listener requires Linux SO_PEERCRED")
def test_real_unix_listener_cannot_be_replaced_and_disconnect_closes_admission():
    with case("unix-listener") as workspace:
        result = completed(workspace.root, "unix-listener")
        assert result["status"] == "STOPPED"
        assert result["active"] == {}
        assert result["first_error"]["reason"].startswith("controller failure:")


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell dispatch uses Windows path semantics")
def test_real_powershell_dispatch_preserves_spaces_unc_distribution_and_exit_status():
    with case("powershell-dispatch") as workspace:
        result = completed(workspace.root, "powershell-dispatch")
        assert result["returncode"] == 37, result["stderr"]
        output = workspace.root / "wsl-arguments.txt"
        arguments = [[base64.b64decode(value).decode() for value in line.split("|")]
                     for line in output.read_text(encoding="utf-8-sig").splitlines()]
        assert len(arguments) == 3
        assert all(item[:3] == ["-d", "Fixture Distro", "-e"] for item in arguments)
        assert arguments[0][3:5] == ["wslpath", "-a"]
        assert arguments[1][3:5] == ["wslpath", "-a"]
        dispatched = arguments[2]
        assert dispatched[3:5] == ["bash", "/mnt/c/fixture with spaces/operator.sh"]
        assert dispatched[dispatched.index("--target") + 1] == "/mnt/c/fixture with spaces/operator.sh"
        assert "--dry-run" in dispatched
        assert dispatched[dispatched.index("--") + 1:] == ["literal $HOME", "semi;colon", "c'd"]
