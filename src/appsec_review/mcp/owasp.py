from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from appsec_review.owasp_workbench.indexes import WorkbenchIndex


QUERY_TOOL_SCHEMA = {
    "name": "query_owasp_workbench",
    "description": "Query accepted immutable OWASP workbench shards for one application run.",
    "inputSchema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "family": {"enum": ["standards", "component-classification", "applicability",
                                  "validation-work", "control-result", "finding-package"]},
            "standard": {"type": "string"}, "version": {"type": "string"},
            "profile": {"type": "string"}, "control": {"type": "string"},
            "component": {"type": "string"}, "project": {"type": "string"},
            "evidence_mode": {"type": "string"}, "validator": {"type": "string"},
            "batch": {"type": "string"}, "disposition": {"type": "string"},
            "shard": {"type": "string"}, "limit": {"type": "integer", "minimum": 1,
            "maximum": 100}, "cursor": {"type": "string"}
        }
    }
}


def query_owasp_workbench(runs_dir: Path, run_id: str,
                          arguments: Mapping[str, Any]) -> dict[str, Any]:
    allowed = set(QUERY_TOOL_SCHEMA["inputSchema"]["properties"])
    if set(arguments) - allowed:
        raise ValueError("OWASP MCP query contains unsupported parameters")
    try:
        return WorkbenchIndex(runs_dir, run_id).query(**dict(arguments))
    except FileNotFoundError:
        return {"schema": "appsec-review/owasp-query-response/1", "run_id": run_id,
                "manifest_identity": None, "results": [],
                "pagination": {"limit": int(arguments.get("limit", 50)), "offset": 0,
                               "next_cursor": None, "truncated": False},
                "ambiguity": [],
                "coverage_gaps": ["accepted OWASP workbench index is unavailable"]}
