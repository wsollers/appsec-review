"""Operator-only schemas; these are never added to review-worker capabilities."""

from typing import Any

JOB = {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,127}$"}
ATTEMPT = {"type": "string", "pattern": "^attempt_[0-9]{4,10}$"}
HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
PAGE = {
    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
    "cursor": {"type": "string", "minLength": 1, "maxLength": 4096},
}


def _tool(name: str, description: str, properties: dict[str, Any],
          required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"name": name, "description": description,
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
            "inputSchema": {"type": "object", "additionalProperties": False,
                            "properties": properties, "required": list(required)}}


OPERATOR_TOOLS = (
    _tool("inspect_run", "Inspect the explicitly selected application run, not a Dagster dispatch.", {}),
    _tool("list_jobs", "Page job identities in this run; existence does not imply acceptance.", PAGE),
    _tool("list_attempts", "Page attempts of one exact job, without choosing the latest.",
          {"job_id": JOB, **PAGE}, ("job_id",)),
    _tool("inspect_attempt", "Inspect an exact attempt's structural status and protected failure references.",
          {"job_id": JOB, "attempt_id": ATTEMPT}, ("job_id", "attempt_id")),
    _tool("read_logs", "Page bounded structural pipeline events. Messages and raw details are withheld.",
          {**PAGE, "job_id": JOB, "attempt_id": ATTEMPT,
           "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
           "event_type": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]{0,95}$"}}),
    _tool("inspect_recovery_plan", "Inspect an exact recorded RESUME_PLANNED event, never compute or execute recovery.",
          {"offset": {"type": "integer", "minimum": 0, "maximum": 2**63 - 1}, "sha256": HASH},
          ("offset", "sha256")),
    _tool("inspect_dagster", "Read one explicitly named Dagster dispatch at the startup-configured endpoint.",
          {"dispatch_id": {"type": "string",
                           "pattern": "^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$"}},
          ("dispatch_id",)),
)
