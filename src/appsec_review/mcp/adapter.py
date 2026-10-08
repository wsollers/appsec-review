"""Authorization and serialization adapter; retrieval behavior stays in the core."""

from __future__ import annotations

import json
import time
from typing import Any, Mapping

from appsec_review.mcp.schema import TOOLS
from appsec_review.mcp.owasp import query_owasp_workbench
from appsec_review.retrieval import RetrievalCore


class RetrievalMcpAdapter:
    def __init__(self, core: RetrievalCore):
        self.core = core
        self._tools = {item["name"] for item in TOOLS}

    def call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if name not in self._tools:
            raise ValueError("unknown MCP retrieval tool")
        if not isinstance(arguments, Mapping):
            raise ValueError("tool arguments must be an object")
        allowed = set(next(item for item in TOOLS if item["name"] == name)["inputSchema"]["properties"])
        unknown = set(arguments) - allowed
        if unknown:
            raise ValueError(f"unknown tool arguments: {sorted(unknown)}")
        method = (lambda **values: query_owasp_workbench(
            self.core.run_root.parent, self.core.run_id, values
        )) if name == "query_owasp_workbench" else getattr(self.core, name)
        started = time.monotonic()
        token, invocation = self.core.begin_mcp_invocation(name, arguments)
        try:
            result = method(**dict(arguments))
        except BaseException as exc:
            self.core.complete_mcp_invocation(token, invocation, error=exc,
                                              duration_ms=max(0, int((time.monotonic() - started) * 1000)))
            raise
        self.core.complete_mcp_invocation(token, invocation, response=result,
                                          duration_ms=max(0, int((time.monotonic() - started) * 1000)))
        return result

    def mcp_result(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        result = self.call(name, arguments)
        return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                "structuredContent": result, "isError": False}
