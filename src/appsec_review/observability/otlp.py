"""Optional bounded OTLP/HTTP JSON batches, derived from events and disabled by default."""
from __future__ import annotations

from collections import deque
import hashlib
from typing import Any, Callable, Mapping

from appsec_review.observability.diagnostics import execution_event_summary
from appsec_review.observability.telemetry import validate_event


class BoundedOTLP:
    def __init__(self, exporter: Callable[[Mapping[str, Any]], None], *, enabled: bool = False,
                 capacity: int = 256, batch_size: int = 32):
        if not 1 <= batch_size <= capacity <= 10000:
            raise ValueError("invalid OTLP queue bounds")
        self.exporter, self.enabled = exporter, enabled
        self.capacity, self.batch_size = capacity, batch_size
        self.pending: deque[dict[str, Any]] = deque()
        self.failures = 0

    def offer(self, event: Mapping[str, Any]) -> str:
        if not self.enabled:
            return "disabled"
        validate_event(event)
        if len(self.pending) >= self.capacity:
            return "backpressure_retry_same_event"
        # Hash even identifiers: a target-controlled ID may contain source or a credential.
        attributes = [{"key": key, "value": {"stringValue": hashlib.sha256(
            str(event.get(key) or "").encode()).hexdigest()}}
            for key in ("run_id", "job_id", "attempt_id", "event_id")]
        category = execution_event_summary(event)["category"]
        self.pending.append({"body": {"stringValue": category}, "attributes": attributes})
        return "queued"

    def flush(self) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled", "pending": 0}
        batch = list(self.pending)[:self.batch_size]
        if not batch:
            return {"status": "idle", "pending": 0}
        payload = {"resourceLogs": [{"resource": {"attributes": []},
                                    "scopeLogs": [{"scope": {"name": "appsec-review-derived"},
                                                   "logRecords": batch}]}]}
        try:
            self.exporter(payload)
        except (OSError, RuntimeError, ValueError) as exc:
            self.failures += 1
            return {"status": "export_failed", "error_class": type(exc).__name__,
                    "pending": len(self.pending), "failures": self.failures}
        for _ in batch:
            self.pending.popleft()
        return {"status": "exported", "count": len(batch), "pending": len(self.pending),
                "delivery": "at_least_once_deduplicate_event_id"}
