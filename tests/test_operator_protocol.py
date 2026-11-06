from io import StringIO
import json

import pytest
from jsonschema import Draft202012Validator

from appsec_review.mcp import stdio
from appsec_review.mcp.operator import OperatorMcpAdapter
from appsec_review.mcp.operator_schema import OPERATOR_TOOLS
from appsec_review.mcp.schema import TOOLS
from appsec_review.retrieval.core import RetrievalGap, RetrievalIntegrityError


class Adapter:
    def __init__(self, result=None, error=None):
        self.result = result or {"content": [], "isError": False}
        self.error = error
        self.calls = []

    def mcp_result(self, name, arguments):
        self.calls.append((name, arguments))
        if self.error:
            raise self.error
        return self.result


def request(method, params=None, **extra):
    return {"jsonrpc": "2.0", "id": 9, "method": method,
            **({"params": params} if params is not None else {}), **extra}


def test_initialize_catalog_and_ping_contracts():
    adapter = Adapter()
    result = stdio.dispatch(adapter, request("initialize", {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "offline-unit", "version": "1"}}))["result"]
    assert result["protocolVersion"] == stdio.PROTOCOL_VERSION
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    catalog = stdio.dispatch(adapter, request("tools/list"))["result"]["tools"]
    assert catalog == list((*TOOLS, *OPERATOR_TOOLS))
    assert len({item["name"] for item in catalog}) == len(catalog)
    for tool in catalog:
        Draft202012Validator.check_schema(tool["inputSchema"])
        assert tool["inputSchema"]["additionalProperties"] is False
    assert stdio.dispatch(adapter, request("ping"))["result"] == {}
    assert not adapter.calls


@pytest.mark.parametrize("method", ["notifications/initialized", "notifications/cancelled",
                                   "unknown_notification", "tools/call", "ping"])
def test_notifications_never_respond_or_execute(method):
    adapter = Adapter()
    assert stdio.dispatch(adapter, {"jsonrpc": "2.0", "method": method,
                                    "params": {"name": "inspect_run"}}) is None
    assert not adapter.calls


@pytest.mark.parametrize("value", [None, [], 1, "request", {}, {"jsonrpc": "1.0", "method": "ping"},
    {"jsonrpc": "2.0", "id": True, "method": "ping"},
    {"jsonrpc": "2.0", "id": 1.5, "method": "ping"},
    {"jsonrpc": "2.0", "id": {}, "method": "ping"},
    {"jsonrpc": "2.0", "id": 1, "method": None},
    {"jsonrpc": "2.0", "id": 1, "method": "ping", "result": {}}])
def test_invalid_request_shapes_are_transport_errors(value):
    assert stdio.dispatch(Adapter(), value)["error"]["code"] == -32600


@pytest.mark.parametrize("payload", [b"{", b"\xff", b'{"id":1,"id":2}', b'{"number":NaN}',
                                     b'{"number":Infinity}'])
def test_invalid_json_does_not_disclose_input_or_reuse_id(payload):
    response = stdio.dispatch_message(Adapter(), payload)
    assert response["id"] is None
    assert response["error"] == {"code": -32700, "message": "invalid JSON"}


@pytest.mark.parametrize("method,params", [
    ("initialize", {}), ("initialize", {"protocolVersion": 1}),
    ("ping", {"ignored": True}), ("tools/list", {"cursor": "forged"}),
    ("tools/call", []), ("tools/call", {"name": "inspect_run", "arguments": []}),
    ("tools/call", {"name": "read_logs", "arguments": {"limit": True}}),
    ("tools/call", {"name": "read_logs", "arguments": {"limit": 101}}),
    ("tools/call", {"name": "read_logs", "arguments": {"cursor": "x" * 4097}}),
    ("tools/call", {"name": "inspect_attempt", "arguments": {"job_id": "../elsewhere"}}),
    ("tools/call", {"name": "read_logs", "arguments": {"path": "/etc/passwd"}}),
    ("tools/call", {"name": "inspect_dagster", "arguments": {"query": "mutation { run }"}}),
    ("tools/call", {"name": "execute_shell"}),
    ("tools/call", {"name": "inspect_run", "_meta": []}),
])
def test_invalid_params_do_not_reach_adapter(method, params):
    adapter = Adapter()
    assert stdio.dispatch(adapter, request(method, params))["error"]["code"] == -32602
    assert not adapter.calls


@pytest.mark.parametrize("error,code", [
    (RetrievalGap("secret"), "accepted_manifest_unavailable"),
    (RetrievalIntegrityError("secret"), "retrieval_integrity_failure"),
    (FileNotFoundError("secret"), "selected_data_unavailable"),
    (ValueError("secret"), "tool_request_failed"),
    (RuntimeError("secret"), "tool_request_failed"),
])
def test_tool_failures_are_results_not_transport_errors(error, code, caplog):
    result = stdio.dispatch(Adapter(error=error), request("tools/call", {"name": "inspect_run"}))
    assert "error" not in result
    assert result["result"]["isError"] is True
    assert result["result"]["structuredContent"]["code"] == code
    assert "secret" not in json.dumps(result) + caplog.text


def test_internal_error_and_unknown_method_are_transport_errors(caplog):
    result = stdio.dispatch(Adapter(error=KeyError("secret")), request("tools/call", {"name": "inspect_run"}))
    assert result["error"]["code"] == -32603
    assert "secret" not in json.dumps(result) + caplog.text
    assert stdio.dispatch(Adapter(), request("shell/execute"))["error"]["code"] == -32601


def test_input_depth_size_and_output_size_bounds():
    assert stdio.dispatch_message(Adapter(), b" " * (stdio.MAX_REQUEST_BYTES + 1))["error"]["code"] == -32600
    nested = []
    for _ in range(stdio.MAX_JSON_DEPTH + 1):
        nested = [nested]
    assert stdio.dispatch(Adapter(), request("ping", {"nested": nested}))["error"]["code"] == -32600
    oversized = Adapter(result={"content": [{"text": "x" * stdio.MAX_RESPONSE_BYTES}]})
    response = stdio.dispatch(oversized, request("tools/call", {"name": "inspect_run"}))
    assert response["result"]["structuredContent"]["code"] == "response_byte_bound_exceeded"


def test_stdio_main_uses_only_protocol_stdout_and_requires_explicit_selection(tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit) as error:
        stdio.main([])
    assert error.value.code == 2
    capsys.readouterr()
    for invalid in ["latest", "../run", "7a7ee5ee-40b2-4c9f-acfb-d5e97bddf015"]:
        with pytest.raises(SystemExit):
            stdio.main(["--run-id", invalid])
    assert not capsys.readouterr().out
    monkeypatch.setattr(stdio.sys, "stdin", StringIO(
        '{"jsonrpc":"2.0","method":"notifications/initialized"}\n{\n'
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_run"}}\n'))
    assert stdio.main(["--runs-dir", str(tmp_path), "--run-id", "2026-11-06-0001"]) == 0
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(lines) == 2 and lines[0]["error"]["code"] == -32700
    assert lines[1]["result"]["structuredContent"]["coverage_gaps"] == ["application_run_unavailable"]
    assert not list(tmp_path.iterdir())


def test_oversized_frame_terminates_without_unbounded_drain(monkeypatch, capsys):
    monkeypatch.setattr(stdio.sys, "stdin", StringIO("x" * (stdio.MAX_REQUEST_BYTES + 100)))
    assert stdio.main(["--run-id", "2026-11-06-0001"]) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == -32600


def test_direct_adapter_rejects_unknown_or_invalid_tool_arguments(tmp_path):
    adapter = OperatorMcpAdapter(tmp_path, "2026-11-06-0001")
    for name, args in [("read_logs", {"limit": 0}), ("inspect_run", {"run_id": "latest"}),
                       ("execute", {}), ("inspect_attempt", {"job_id": "job_test", "attempt_id": "../"})]:
        with pytest.raises(ValueError):
            adapter.call(name, args)
