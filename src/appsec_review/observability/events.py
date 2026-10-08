from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import platform
from pathlib import Path
import re
import time
from typing import Any, Mapping

from appsec_review.storage import FileLock, LockUnavailable


MAX_RECORD_BYTES = 64 * 1024
_SECRET = re.compile(r"(?i)(api[_-]?key|authorization|password|secret|token)")
_CONTENT = re.compile(r"(?i)^(prompt|response|raw_model_output|model_output|source_text|query_text)$")


def _bounded(value: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return "<truncated>"
    if isinstance(value, Mapping):
        return {
            str(key)[:128]: "<redacted>" if (
                _CONTENT.fullmatch(str(key)) or
                (_SECRET.search(str(key)) and not str(key).lower().endswith(("_tokens", "_token_count", "_sha256", "_id")))
            )
            else _bounded(child, depth=depth + 1)
            for key, child in list(value.items())[:200]
        }
    if isinstance(value, (list, tuple)):
        return [_bounded(child, depth=depth + 1) for child in list(value)[:200]]
    if isinstance(value, str):
        return "<redacted>" if _SECRET.search(value) else value[:8192]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:8192]


def _valid_lines(payload: bytes) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    offset = 0
    for line in payload.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            break
        try:
            record = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            break
        if not isinstance(record, dict):
            break
        records.append(record)
        offset += len(line)
    return records, offset


class PipelineLog:
    """One crash-recovering, process-safe JSONL stream for an application run."""

    def __init__(self, run_root: Path):
        self.path = Path(run_root) / "data" / "logs" / "pipeline.jsonl"
        self.lock_path = self.path.with_suffix(".lock")

    def write(
        self,
        event_type: str,
        *,
        run_id: str,
        job_id: str = "-",
        attempt_id: str = "-",
        step_id: str | None = None,
        task_id: str | None = None,
        level: str = "INFO",
        trigger: str = "application",
        orchestrator: str = "application",
        message: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = FileLock(self.lock_path)
        deadline = time.monotonic() + 30.0
        while True:
            try:
                lock.__enter__()
                break
            except LockUnavailable:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.005)
        try:
            payload = self.path.read_bytes() if self.path.exists() else b""
            records, valid_length = _valid_lines(payload)
            if valid_length != len(payload):
                with self.path.open("r+b") as stream:
                    stream.truncate(valid_length)
                    stream.flush()
                    os.fsync(stream.fileno())
            sequence = int(records[-1]["sequence"]) + 1 if records else 1
            record = {
                "schema": "appsec-review/telemetry-event/1",
                "sequence": sequence,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": level.upper(),
                "event_type": event_type,
                "run_id": run_id,
                "job_id": job_id,
                "attempt_id": attempt_id,
                "step_id": step_id,
                "task_id": task_id,
                "process": {"pid": os.getpid(), "name": platform.node() or "unknown"},
                "trigger": trigger,
                "orchestrator": orchestrator,
                "message": message or event_type.replace("_", " ").lower(),
                "details": _bounded(dict(details or {})),
            }
            record["event_id"] = __import__("hashlib").sha256(
                f"{run_id}:{sequence}:{event_type}".encode()).hexdigest()
            line = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
            if len(line) > MAX_RECORD_BYTES:
                record["details"] = {"truncated": True, "original_size": len(line)}
                line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
            with self.path.open("ab") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            return record
        finally:
            lock.__exit__(None, None, None)

    def read(self) -> tuple[list[dict[str, Any]], bool]:
        if not self.path.exists():
            return [], False
        payload = self.path.read_bytes()
        records, valid_length = _valid_lines(payload)
        return records, valid_length != len(payload)


class EventLog:
    """Local attempt log which mirrors every event through the central run log."""

    def __init__(self, path: Path, pipeline: PipelineLog | None = None, base: Mapping[str, Any] | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.pipeline = pipeline
        self.base = dict(base or {})

    def write(self, event: str, **fields: Any) -> None:
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
        if self.pipeline:
            merged = {**self.base, **fields}
            unit_id = str(merged.get("unit_id", ""))
            step_id, _, task_id = unit_id.partition(".")
            self.pipeline.write(
                event,
                run_id=str(merged.get("run_id", "-")),
                job_id=str(merged.get("job_id", "-")),
                attempt_id=str(merged.get("attempt_id", "-")),
                step_id=step_id or None,
                task_id=task_id or None,
                level="ERROR" if event.endswith("FAILED") else "INFO",
                trigger=str(merged.get("trigger", "application")),
                orchestrator=str(merged.get("orchestrator", "application")),
                details=fields,
            )
