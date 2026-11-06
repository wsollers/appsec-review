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
    digest = value.get("sha256")
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


def read_execution_receipt(run_root: Any, identity: Mapping[str, Any], *,
                           max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    """Verify an existing run-owned receipt before interpreting its diagnostic fields."""
    import json
    from pathlib import Path, PurePosixPath
    from appsec_review.storage.verify import verify_run_artifact

    relative = identity.get("path")
    if not isinstance(relative, str) or "\\" in relative:
        raise ValueError("invalid execution receipt path")
    path = Path(run_root)
    pure = PurePosixPath(relative)
    if pure.is_absolute() or pure.as_posix() != relative or ".." in pure.parts:
        raise ValueError("invalid execution receipt path")
    for part in pure.parts:
        path /= part
        if path.is_symlink():
            raise ValueError("symlinked execution receipt")
    if not 1 <= max_bytes <= 16 * 1024 * 1024 or path.stat().st_size > max_bytes:
        raise ValueError("execution receipt exceeds verification bound")
    path = verify_run_artifact(run_root, identity)
    value = json.loads(path.read_bytes())
    supported = {"appsec-review/container-execution/1",
                 "appsec-review/tree-sitter-invocation/1"}
    if not isinstance(value, dict) or value.get("schema") not in supported:
        raise ValueError("unsupported execution receipt schema")
    return {"schema": "appsec-review/execution-summary/1", **execution_summary(value),
            "receipt": diagnostic_reference(identity), "integrity": "hash_verified"}
