"""Authorization and serialization adapter; retrieval behavior stays in the core."""

from __future__ import annotations

import json
from typing import Any, Mapping

from appsec_review.mcp.schema import TOOLS
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
        method = getattr(self.core, name)
        return method(**dict(arguments))

    def mcp_result(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        result = self.call(name, arguments)
        return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                "structuredContent": result, "isError": False}
