"""Read-only, explicit-run operator MCP over bounded newline-delimited JSON-RPC."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys
from typing import Any, Protocol, Sequence

from jsonschema import Draft202012Validator

from appsec_review.mcp.operator import OperatorMcpAdapter, validate_selection
from appsec_review.mcp.operator_schema import OPERATOR_TOOLS
from appsec_review.mcp.schema import TOOLS as RETRIEVAL_TOOLS
from appsec_review.retrieval.core import RetrievalGap, RetrievalIntegrityError

PROTOCOL_VERSION = "2025-06-18"
MAX_REQUEST_BYTES = 128 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
TOOLS = (*RETRIEVAL_TOOLS, *OPERATOR_TOOLS)
_VALIDATORS = {item["name"]: Draft202012Validator(item["inputSchema"]) for item in TOOLS}
LOGGER = logging.getLogger(__name__)


class Adapter(Protocol):
    def mcp_result(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="appsec-review-mcp")
    value.add_argument("--runs-dir", type=Path, default=Path("runs"))
    value.add_argument("--run-id", required=True, help="explicit application run ID, never a Dagster UUID")
    value.add_argument("--manifest-sha256", help="optional mandatory accepted-manifest pin")
    value.add_argument("--dagster-endpoint", help="trusted read-only GraphQL endpoint; disabled by default")
    return value


def _error(identifier: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": identifier, "error": {"code": code, "message": message}}


def _tool_error(code: str) -> dict[str, Any]:
    value = {"schema": "appsec-review/operator-error/1", "code": code}
    return {"isError": True, "structuredContent": value,
            "content": [{"type": "text", "text": json.dumps(value, sort_keys=True)}]}


def _bounded_shape(value: Any) -> bool:
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            return False
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return True


def dispatch(adapter: Adapter, request: Any) -> dict[str, Any] | None:
    """Dispatch without processes, servers, network setup, or exception-content disclosure."""
    try:
        size = len(json.dumps(request, allow_nan=False).encode())
    except (ValueError, TypeError, RecursionError):
        return _error(None, -32600, "invalid request")
    if size > MAX_REQUEST_BYTES or not _bounded_shape(request):
        return _error(None, -32600, "request exceeds protocol bounds")
    if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0"
            or not isinstance(request.get("method"), str) or not request["method"]
            or set(request) - {"jsonrpc", "id", "method", "params"}
            or ("id" in request and not (request["id"] is None or type(request["id"]) is int
                                         or isinstance(request["id"], str)))):
        return _error(None, -32600, "invalid request")
    identifier = request.get("id")
    if "id" not in request:
        # Notifications (including cancellation and initialized) never execute a tool or get a reply.
        return None
    method = request["method"]
    params = request.get("params", {})
    if not isinstance(params, dict):
        return _error(identifier, -32602, "parameters must be an object")
    if method == "initialize":
        if (set(params) - {"protocolVersion", "capabilities", "clientInfo"}
                or not isinstance(params.get("protocolVersion"), str)
                or not isinstance(params.get("capabilities"), dict)
                or not isinstance(params.get("clientInfo"), dict)
                or not all(isinstance(params["clientInfo"].get(key), str) for key in ("name", "version"))):
            return _error(identifier, -32602, "invalid initialization parameters")
        result = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": "appsec-review-operator", "version": "3"}}
    elif method == "tools/list":
        if params:
            return _error(identifier, -32602, "the bounded tool catalog has no continuation cursor")
        result = {"tools": list(TOOLS)}
    elif method == "tools/call":
        if (set(params) - {"name", "arguments", "_meta"} or not isinstance(params.get("name"), str)
                or not isinstance(params.get("arguments", {}), dict)
                or ("_meta" in params and not isinstance(params["_meta"], dict))):
            return _error(identifier, -32602, "invalid tool call parameters")
        name, arguments = params["name"], params.get("arguments", {})
        if name not in _VALIDATORS:
            return _error(identifier, -32602, "unknown tool")
        if not _VALIDATORS[name].is_valid(arguments):
            return _error(identifier, -32602, "arguments do not match the tool schema")
        try:
            result = adapter.mcp_result(name, arguments)
        except RetrievalIntegrityError:
            LOGGER.warning("operator tool failed: retrieval integrity")
            result = _tool_error("retrieval_integrity_failure")
        except RetrievalGap:
            LOGGER.warning("operator tool failed: accepted manifest unavailable")
            result = _tool_error("accepted_manifest_unavailable")
        except FileNotFoundError:
            LOGGER.warning("operator tool failed: selected data unavailable")
            result = _tool_error("selected_data_unavailable")
        except (ValueError, RuntimeError, OSError) as error:
            LOGGER.warning("operator tool failed: %s", type(error).__name__)
            result = _tool_error("tool_request_failed")
        except Exception as error:
            LOGGER.error("operator internal error: %s", type(error).__name__)
            return _error(identifier, -32603, "internal error")
    elif method == "ping":
        if params:
            return _error(identifier, -32602, "ping takes no parameters")
        result = {}
    else:
        return _error(identifier, -32601, "method not found")
    response = {"jsonrpc": "2.0", "id": identifier, "result": result}
    try:
        payload = json.dumps(response, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        LOGGER.error("operator returned an invalid protocol result")
        return _error(identifier, -32603, "invalid result")
    if len(payload.encode()) > MAX_RESPONSE_BYTES:
        LOGGER.warning("operator response exceeded protocol byte bound")
        return {"jsonrpc": "2.0", "id": identifier, "result": _tool_error("response_byte_bound_exceeded")}
    return response


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError("non-finite JSON number")


def dispatch_message(adapter: Adapter, payload: str | bytes) -> dict[str, Any] | None:
    try:
        size = len(payload.encode() if isinstance(payload, str) else payload)
    except UnicodeError:
        return _error(None, -32700, "invalid UTF-8")
    if size > MAX_REQUEST_BYTES:
        return _error(None, -32600, "request exceeds protocol byte bound")
    try:
        request = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        return _error(None, -32700, "invalid JSON")
    return dispatch(adapter, request)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser()
    args = arguments.parse_args(argv)
    try:
        validate_selection(args.run_id, args.manifest_sha256)
        adapter = OperatorMcpAdapter(args.runs_dir, args.run_id,
                                     manifest_sha256=args.manifest_sha256,
                                     dagster_endpoint=args.dagster_endpoint)
    except ValueError:
        arguments.error("invalid explicit run selection, manifest pin, or trusted Dagster endpoint")
    source = getattr(sys.stdin, "buffer", sys.stdin)
    while True:
        line = source.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return 0
        response = dispatch_message(adapter, line)
        if response is not None:
            sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
            sys.stdout.flush()
        # Do not drain an attacker-controlled infinite oversized frame.
        if len(line.encode() if isinstance(line, str) else line) > MAX_REQUEST_BYTES:
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
