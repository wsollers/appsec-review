"""Bounded read projections over existing run receipts and the pipeline event stream."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Callable, Mapping

from jsonschema import Draft202012Validator

from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.mcp.operator_schema import OPERATOR_TOOLS
from appsec_review.mcp.schema import TOOLS
from appsec_review.observability import PipelineLog
from appsec_review.observability.events import MAX_RECORD_BYTES
from appsec_review.retrieval import RetrievalCore
from appsec_review.retrieval.core import RetrievalGap, RetrievalIntegrityError
from appsec_review.storage.shared import safe_path

SCHEMA = "appsec-review/operator-response/1"
LOG_PATH = "data/logs/pipeline.jsonl"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_SCAN_BYTES = 1024 * 1024
MAX_DIRECTORY_ENTRIES = 4096
CURSOR_TTL_SECONDS = 300
LOGGER = logging.getLogger(__name__)
_RUN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4}")
_HASH = re.compile(r"[0-9a-f]{64}")
_JOB = re.compile(r"[a-z][a-z0-9_]{0,127}")
_ATTEMPT = re.compile(r"attempt_[0-9]{4,10}")
_STATUSES = frozenset({"RUNNING", "FAILED", "SUCCEEDED", "SKIPPED", "COMPLETED_WITH_GAPS",
                       "ACCEPTED", "REJECTED", "CANCELED", "CANCELLED"})


def validate_selection(run_id: str, manifest_sha256: str | None = None) -> None:
    if not isinstance(run_id, str) or not _RUN.fullmatch(run_id):
        raise ValueError("an explicit application run ID is required (YYYY-MM-DD-NNNN)")
    if manifest_sha256 is not None and (not isinstance(manifest_sha256, str) or not _HASH.fullmatch(manifest_sha256)):
        raise ValueError("manifest pin must be a lowercase SHA-256")


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _identity(info: os.stat_result) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


@contextmanager
def _open_regular(path: Path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("operator input is not a regular file")
        yield stream


class CursorCodec:
    """Session-private authenticated cursors; scope includes tool, filters, run and manifest."""

    def __init__(self, clock: Callable[[], float] = time.time):
        self.clock = clock
        self.key = secrets.token_bytes(32)

    def encode(self, scope: Any, position: Any) -> str:
        body = _json({"scope": scope, "position": position,
                      "expires_at": self.clock() + CURSOR_TTL_SECONDS})
        return base64.urlsafe_b64encode(body + hmac.digest(self.key, body, "sha256")).decode().rstrip("=")

    def decode(self, cursor: str, scope: Any) -> Any:
        try:
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
            body, signature = raw[:-32], raw[-32:]
            if not hmac.compare_digest(signature, hmac.digest(self.key, body, "sha256")):
                raise ValueError
            value = json.loads(body)
            if value["scope"] != scope or value["expires_at"] <= self.clock():
                raise ValueError
            return value["position"]
        except (ValueError, KeyError, TypeError) as error:
            raise ValueError("cursor is expired, invalid, or bound to another request") from error


class DiagnosticLog(PipelineLog):
    """Operator queries must not modify the observed run to audit their own reads."""

    def write(self, event_type: str, **fields: Any) -> dict[str, Any]:
        LOGGER.info("operator retrieval event=%s", event_type)
        return {}


class OperatorMcpAdapter:
    def __init__(self, runs_dir: Path, run_id: str, *, manifest_sha256: str | None = None,
                 dagster_endpoint: str | None = None):
        validate_selection(run_id, manifest_sha256)
        self.runs_dir = Path(runs_dir).absolute()
        self.run_id = run_id
        self.manifest_sha256 = manifest_sha256
        self.run_root = safe_path(self.runs_dir, run_id)
        self.cursors = CursorCodec()
        self._workbench_identity = None
        self.dagster = None
        if dagster_endpoint is not None:
            from appsec_review.mcp.dagster import DagsterReader
            self.dagster = DagsterReader(dagster_endpoint, run_id)
        self._schemas = {tool["name"]: Draft202012Validator(tool["inputSchema"])
                         for tool in (*TOOLS, *OPERATOR_TOOLS)}

    def _root(self) -> Path:
        root = safe_path(self.runs_dir, self.run_id)
        if root != self.run_root:
            raise ValueError("application run root changed")
        return root

    def _read(self, relative: str) -> tuple[dict[str, Any], dict[str, Any]]:
        path = safe_path(self._root(), relative)
        with _open_regular(path) as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("operator document is not a regular file")
            payload = stream.read(MAX_DOCUMENT_BYTES + 1)
            if len(payload) > MAX_DOCUMENT_BYTES:
                raise ValueError("operator document exceeds byte bound")
            if _identity(before) != _identity(os.fstat(stream.fileno())):
                raise ValueError("operator document changed during read")
        value = json.loads(payload)
        if not isinstance(value, dict):
            raise ValueError("operator document must be an object")
        return value, {"path": relative, "sha256": hashlib.sha256(payload).hexdigest(),
                       "size_bytes": len(payload), "acceptance": "not_asserted"}

    def _core(self) -> RetrievalCore:
        self._root()
        try:
            pointer, _ = self._read("data/indices/accepted.json")
        except FileNotFoundError as error:
            raise RetrievalGap("accepted index manifest is unavailable") from error
        if pointer.get("schema") != "appsec-review/accepted-index-set/1":
            raise RetrievalGap("accepted index pointer schema is unsupported")
        if pointer.get("run_id") != self.run_id:
            raise RetrievalIntegrityError("accepted pointer application run mismatch")
        for field in ("handoff_path", "manifest_path"):
            relative = pointer.get(field)
            if not isinstance(relative, str):
                raise RetrievalIntegrityError("invalid accepted pointer path")
            safe_path(self.run_root, relative)
        core = RetrievalCore(self.runs_dir, self.run_id, manifest_sha256=self.manifest_sha256,
                             log=DiagnosticLog(self.run_root))
        self.manifest_sha256 = core.manifest_sha256
        return core

    def _response(self, tool: str, results: list[dict[str, Any]], *, gaps: tuple[str, ...] = (),
                  cursor: str | None = None) -> dict[str, Any]:
        return {"schema": SCHEMA, "tool": tool, "application_run_id": self.run_id,
                "manifest_sha256": self.manifest_sha256, "results": results,
                "coverage_gaps": list(gaps), "pagination": {"next_cursor": cursor},
                "authority": "read_only_projection_not_restart_admission"}

    def _scope(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        return {"run_id": self.run_id, "manifest_sha256": self.manifest_sha256,
                "query": hashlib.sha256(_json([tool, {key: value for key, value in arguments.items()
                                                    if key != "cursor"}])).hexdigest()}

    def inspect_run(self) -> dict[str, Any]:
        if not self._root().is_dir():
            return self._response("inspect_run", [], gaps=("application_run_unavailable",))
        try:
            pointer, _ = self._read("data/indices/accepted.json")
        except FileNotFoundError:
            return self._response("inspect_run", [{"availability": "unaccepted"}],
                                  gaps=("accepted_index_manifest_unavailable",))
        if pointer.get("schema") != "appsec-review/accepted-index-set/1":
            return self._response("inspect_run", [{"availability": "unsupported"}],
                                  gaps=("accepted_index_pointer_schema_unsupported",))
        self._core()
        return self._response("inspect_run", [{"availability": "accepted"}])

    def _directory_page(self, tool: str, arguments: Mapping[str, Any], relative: str,
                        pattern: re.Pattern[str], field: str) -> dict[str, Any]:
        directory = safe_path(self._root(), relative)
        if not directory.is_dir():
            return self._response(tool, [], gaps=("requested_job_or_attempt_inventory_unavailable",))
        snapshot = _identity(directory.stat())
        names = []
        with os.scandir(directory) as entries:
            for number, entry in enumerate(entries):
                if number >= MAX_DIRECTORY_ENTRIES:
                    raise ValueError("operator directory inventory exceeds scan bound")
                if pattern.fullmatch(entry.name):
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        raise ValueError("invalid job or attempt directory")
                    names.append(entry.name)
        names.sort()
        scope = self._scope(tool, arguments)
        position = self.cursors.decode(arguments["cursor"], scope) if "cursor" in arguments else {
            "offset": 0, "snapshot": snapshot}
        if position["snapshot"] != snapshot or _identity(directory.stat()) != snapshot:
            raise ValueError("operator inventory changed; restart pagination")
        offset, limit = position["offset"], arguments.get("limit", 20)
        page = names[offset:offset + limit]
        cursor = self.cursors.encode(scope, {"offset": offset + len(page), "snapshot": snapshot}) \
            if offset + len(page) < len(names) else None
        return self._response(tool, [{field: name} for name in page],
                              gaps=() if page else ("no_matching_job_or_attempt",), cursor=cursor)

    def list_jobs(self, **arguments: Any) -> dict[str, Any]:
        return self._directory_page("list_jobs", arguments, "data/jobs", _JOB, "job_id")

    def list_attempts(self, **arguments: Any) -> dict[str, Any]:
        return self._directory_page("list_attempts", arguments,
                                    f"data/jobs/{arguments['job_id']}/attempts", _ATTEMPT, "attempt_id")

    def inspect_attempt(self, job_id: str, attempt_id: str) -> dict[str, Any]:
        base = f"data/jobs/{job_id}/attempts/{attempt_id}"
        try:
            status, ref = self._read(base + "/status.json")
        except FileNotFoundError:
            return self._response("inspect_attempt", [], gaps=("attempt_status_unavailable",))
        if (status.get("run_id"), status.get("job_id"), status.get("attempt_id")) != (
                self.run_id, job_id, attempt_id):
            raise ValueError("attempt identity differs from selected run/job/attempt")
        if status.get("status") not in _STATUSES:
            raise ValueError("unsupported attempt status")
        result = {"job_id": job_id, "attempt_id": attempt_id, "status": status["status"],
                  "status_reference": ref}
        error = status.get("error")
        if error is not None:
            if not isinstance(error, dict):
                raise ValueError("invalid attempt error")
            kind = error.get("type")
            result["failure"] = {
                "error_type": kind if isinstance(kind, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", kind)
                else "unavailable",
                "message": "withheld_protected_content",
                "protected_reference": {**ref, "content_available": False},
            }
        trace = safe_path(self._root(), base + "/logs/traceback.txt")
        if trace.exists():
            if not trace.is_file():
                raise ValueError("invalid protected traceback")
            result["traceback_reference"] = {"path": base + "/logs/traceback.txt",
                                              "content_available": False, "acceptance": "not_asserted"}
        orchestration = status.get("orchestration", {})
        if isinstance(orchestration, dict) and orchestration.get("system") == "dagster":
            from uuid import UUID
            dispatch_id = orchestration.get("run_id")
            if not isinstance(dispatch_id, str) or str(UUID(dispatch_id)) != dispatch_id:
                raise ValueError("invalid Dagster dispatch identity in attempt")
            result["dagster_dispatch_id"] = dispatch_id
        return self._response("inspect_attempt", [result], gaps=(
            "status_is_not_an_accepted_handoff", "raw_failure_messages_and_streams_are_not_exposed"))

    def _event(self, payload: bytes, offset: int) -> dict[str, Any]:
        event = json.loads(payload)
        if (not isinstance(event, dict) or event.get("schema") != "appsec-review/telemetry-event/1"
                or event.get("run_id") != self.run_id or type(event.get("sequence")) is not int
                or event["sequence"] < 1):
            raise ValueError("invalid pipeline event schema or run identity")
        event_type = event.get("event_type")
        if not isinstance(event_type, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", event_type):
            raise ValueError("invalid pipeline event type")
        return event

    @staticmethod
    def _event_reference(payload: bytes, offset: int) -> dict[str, Any]:
        return {"path": LOG_PATH, "offset": offset, "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest()}

    def _event_projection(self, event: Mapping[str, Any], payload: bytes, offset: int) -> dict[str, Any]:
        result = {"sequence": event["sequence"], "event_type": event["event_type"],
                  "reference": self._event_reference(payload, offset)}
        for field, pattern in (("job_id", _JOB), ("attempt_id", _ATTEMPT)):
            value = event.get(field)
            if value is not None and value != "-":
                if not isinstance(value, str) or not pattern.fullmatch(value):
                    raise ValueError("invalid pipeline event scope")
                result[field] = value
        if event.get("level") not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("invalid pipeline event level")
        result["level"] = event["level"]
        return result

    def read_logs(self, **arguments: Any) -> dict[str, Any]:
        path = safe_path(self._root(), LOG_PATH)
        if not path.exists():
            return self._response("read_logs", [], gaps=("pipeline_log_unavailable",))
        scope = self._scope("read_logs", arguments)
        filters = {key: value for key, value in arguments.items() if key not in {"limit", "cursor"}}
        results, gaps = [], []
        with _open_regular(path) as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("pipeline log is not a regular file")
            snapshot = _identity(before)
            position = self.cursors.decode(arguments["cursor"], scope) if "cursor" in arguments else {
                "offset": 0, "sequence": 0, "snapshot": snapshot}
            if position["snapshot"] != snapshot:
                raise ValueError("pipeline log changed; restart pagination")
            stream.seek(position["offset"])
            scanned, sequence = 0, position["sequence"]
            while len(results) < arguments.get("limit", 20) and scanned < MAX_SCAN_BYTES:
                offset = stream.tell()
                if scanned >= MAX_SCAN_BYTES and offset < before.st_size:
                    gaps.append("log_scan_byte_bound_reached")
                payload = stream.readline(min(MAX_RECORD_BYTES + 1, MAX_SCAN_BYTES - scanned + 1))
                if not payload:
                    break
                if len(payload) > MAX_RECORD_BYTES:
                    raise ValueError("pipeline event exceeds byte bound")
                if scanned + len(payload) > MAX_SCAN_BYTES:
                    stream.seek(offset)
                    gaps.append("log_scan_byte_bound_reached")
                    break
                scanned += len(payload)
                if not payload.endswith(b"\n"):
                    gaps.append("incomplete_final_log_record_withheld")
                    break
                event = self._event(payload, offset)
                if event["sequence"] != sequence + 1:
                    raise ValueError("pipeline sequence mismatch")
                sequence = event["sequence"]
                projection = self._event_projection(event, payload, offset)
                if all(projection.get(key) == value for key, value in filters.items()):
                    results.append(projection)
            offset = stream.tell()
            if _identity(os.fstat(stream.fileno())) != snapshot or _identity(path.stat()) != snapshot:
                raise ValueError("pipeline log changed during page read")
        cursor = self.cursors.encode(scope, {"offset": offset, "sequence": sequence, "snapshot": snapshot}) \
            if offset < before.st_size else None
        if not results:
            gaps.append("no_matching_events_in_page_not_proof_of_absence")
        gaps.append("messages_details_and_raw_streams_withheld")
        return self._response("read_logs", results, gaps=tuple(gaps), cursor=cursor)

    def inspect_recovery_plan(self, offset: int, sha256: str) -> dict[str, Any]:
        path = safe_path(self._root(), LOG_PATH)
        with _open_regular(path) as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("pipeline log is not a regular file")
            if offset:
                stream.seek(offset - 1)
                if stream.read(1) != b"\n":
                    raise ValueError("plan offset is not an event boundary")
            payload = stream.readline(MAX_RECORD_BYTES + 1)
        if len(payload) > MAX_RECORD_BYTES or not payload.endswith(b"\n") or hashlib.sha256(payload).hexdigest() != sha256:
            raise ValueError("recorded recovery plan integrity mismatch")
        event = self._event(payload, offset)
        if event["event_type"] != "RESUME_PLANNED":
            raise ValueError("selected event is not a recorded recovery plan")
        details = event.get("details")
        decisions = details.get("decisions") if isinstance(details, dict) else None
        if not isinstance(decisions, list):
            return self._response("inspect_recovery_plan", [], gaps=("recorded_plan_decisions_unavailable",))
        projected = []
        for decision in decisions[:200]:
            if (not isinstance(decision, dict) or not isinstance(decision.get("job_id"), str)
                    or not _JOB.fullmatch(decision["job_id"])
                    or decision.get("action") not in {"RUN", "REUSE", "INVALIDATE"}):
                raise ValueError("unsupported recorded resume decision")
            item = {"job_id": decision["job_id"], "action": decision["action"]}
            digest = decision.get("handoff_sha256")
            if digest is not None:
                if not isinstance(digest, str) or not _HASH.fullmatch(digest):
                    raise ValueError("invalid recorded handoff hash")
                item["handoff_sha256"] = digest
            projected.append(item)
        result = {"decisions": projected, "reference": self._event_reference(payload, offset),
                  "sequence": event["sequence"], "executes": False,
                  "references": {"unit_regression": "tests/test_wave1_resume.py",
                                 "procedure": "docs/operations/retrieval-mcp.md#triage-and-recovery",
                                 "manual_plan": "appsec-review plan-resume",
                                 "manual_replay": "appsec-review replay-build-recipe"},
                  "remaining_decisions": max(0, len(decisions) - len(projected))}
        return self._response("inspect_recovery_plan", [result], gaps=(
            "historical_plan_not_current_restart_admission", "original_reason_text_withheld",
            "exact_repair_test_and_build_replay_inputs_require_operator_selection",
            *(("recorded_plan_is_empty",) if not projected else ()),
            *(("recorded_plan_truncated",) if len(decisions) > 200 else ())))

    def inspect_dagster(self, dispatch_id: str) -> dict[str, Any]:
        if self.dagster is None:
            return self._response("inspect_dagster", [], gaps=("trusted_dagster_endpoint_not_configured",))
        result = self.dagster.inspect(dispatch_id)
        return self._response("inspect_dagster", [result], gaps=tuple(result["gaps"]))

    def _workbench_pointer(self) -> str | None:
        try:
            pointer, _ = self._read("data/indexes/owasp/accepted.json")
        except FileNotFoundError:
            return None
        digest = pointer.get("manifest_sha256")
        if (pointer.get("run_id") != self.run_id or not isinstance(digest, str)
                or not _HASH.fullmatch(digest) or not isinstance(pointer.get("manifest_path"), str)):
            raise RetrievalIntegrityError("invalid accepted workbench pointer")
        safe_path(self._root(), pointer["manifest_path"])
        if self._workbench_identity is not None and digest != self._workbench_identity:
            raise RetrievalIntegrityError("accepted workbench manifest changed during operator session")
        return digest

    def call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        validator = self._schemas.get(name)
        if validator is None or not isinstance(arguments, Mapping):
            raise ValueError("unknown tool or invalid arguments")
        if not validator.is_valid(arguments):
            raise ValueError("arguments do not match the tool schema")
        self._root()
        if name in {tool["name"] for tool in OPERATOR_TOOLS}:
            return getattr(self, name)(**arguments)
        core = self._core()
        query = dict(arguments)
        scope = self._scope(name, query)
        if "cursor" in query:
            query["cursor"] = self.cursors.decode(query["cursor"], scope)
        workbench_pin = self._workbench_pointer() if name == "query_owasp_workbench" else None
        result = RetrievalMcpAdapter(core).call(name, query)
        if name == "query_owasp_workbench" and result.get("manifest_identity") is not None:
            if workbench_pin is None or self._workbench_pointer() != workbench_pin:
                raise RetrievalIntegrityError("accepted workbench pointer changed during read")
            self._workbench_identity = workbench_pin
            result["manifest_identity"]["sha256"] = workbench_pin
        if not result.get("results") and not result.get("coverage_gaps"):
            result["coverage_gaps"] = ["no_matching_accepted_records_not_proof_of_absence"]
        cursor = result.get("pagination", {}).get("next_cursor")
        if cursor is not None:
            result["pagination"]["next_cursor"] = self.cursors.encode(scope, cursor)
        return result

    def mcp_result(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        result = self.call(name, arguments)
        return {"content": [{"type": "text", "text": json.dumps(result, sort_keys=True)}],
                "structuredContent": result, "isError": False}
