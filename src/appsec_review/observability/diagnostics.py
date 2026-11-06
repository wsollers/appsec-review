"""Allowlisted reporting of execution outcomes, never raw diagnostics."""
from __future__ import annotations

import re
from typing import Any, Mapping

_HASH = re.compile(r"[0-9a-f]{64}")


def execution_category(value: Mapping[str, Any]) -> str:
    status = str(value.get("terminal_status") or value.get("status") or "").upper()
    error = value.get("error_class") or value.get("error_type")
    if value.get("oom_killed") is True or status in {"OOM", "OOM_KILLED"}:
        return "oom"
    if value.get("timed_out") is True or status in {"TIMED_OUT", "TIMEOUT"} or error in {
        "TimeoutError", "TimeoutExpired",
    }:
        return "timeout"
    if status in {"CANCELED", "CANCELLED"} or error in {"CancelledError", "KeyboardInterrupt"}:
        return "cancelled"
    if status in {"REUSED", "REPLAYED", "CACHED"}:
        return "reused"
    code = value.get("exit_code", value.get("returncode"))
    if type(code) is int:
        return "success" if code == 0 else "exit_failure"
    if status in {"SUCCEEDED", "SUCCESS", "COMPLETED"}:
        return "success"
    if status in {"FAILED", "FAILURE", "ERROR"}:
        return "failure"
    return "unknown"


def diagnostic_reference(value: Any) -> dict[str, str] | None:
    if not isinstance(value, Mapping):
        return None
    digest, path = value.get("sha256"), value.get("path")
    if not isinstance(digest, str) or not _HASH.fullmatch(digest):
        return None
    # Paths are display hints, not authority, and can themselves contain secrets.
    return {"sha256": digest, "resolution": "run_owned_receipt_required"}


def execution_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    refs = {}
    for name in ("stdout", "stderr", "metrics_receipt", "execution_receipt", "receipt"):
        reference = diagnostic_reference(value.get(name))
        digest = value.get(name + "_sha256")
        if reference is None and isinstance(digest, str) and _HASH.fullmatch(digest):
            reference = {"sha256": digest, "resolution": "run_owned_receipt_required"}
        if reference:
            refs[name] = reference
    code = value.get("exit_code", value.get("returncode"))
    return {"category": execution_category(value),
            "exit_code": code if type(code) is int else None, "diagnostics": refs}
