"""Minimal local stdio MCP server pinned to one accepted review run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence

from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.mcp.schema import TOOLS
from appsec_review.retrieval import RetrievalCore


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="appsec-review-mcp")
    value.add_argument("--runs-dir", type=Path, default=Path("runs"))
    value.add_argument("--run-id", required=True)
    value.add_argument("--manifest-sha256", help="optional mandatory accepted-manifest pin")
    return value


def dispatch(adapter: RetrievalMcpAdapter, request: dict[str, Any]) -> dict[str, Any] | None:
    identifier = request.get("id")
    method = request.get("method")
    if method == "notifications/initialized":
        return None
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": "appsec-review-retrieval", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": list(TOOLS)}
    elif method == "tools/call":
        params = request.get("params") or {}
        result = adapter.mcp_result(str(params.get("name", "")), params.get("arguments") or {})
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": identifier,
                "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": identifier, "result": result}


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    adapter = RetrievalMcpAdapter(RetrievalCore(args.runs_dir, args.run_id,
                                                manifest_sha256=args.manifest_sha256))
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise ValueError("invalid JSON-RPC request")
            response = dispatch(adapter, request)
        except Exception as exc:
            response = {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None,
                        "error": {"code": -32602, "message": str(exc)[:1024]}}
        if response is not None:
            sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
