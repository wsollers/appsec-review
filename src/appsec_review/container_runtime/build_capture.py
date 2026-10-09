from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.config import BuildCaptureConfig
from appsec_review.storage import atomic_json, canonical_json


SCHEMA = "appsec-review/build-execution-record/1"
EVENT_SCHEMA = "appsec-review/build-syscall-event/1"
REQUIRED_EVENT_KINDS = frozenset({"process_fork", "process_exec", "process_exit", "file_open", "connect"})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class CaptureScope:
    run_id: str
    job_id: str
    attempt_id: str
    build_unit_id: str
    family: str

    def __post_init__(self) -> None:
        for name, value in (("run_id", self.run_id), ("job_id", self.job_id),
                            ("attempt_id", self.attempt_id),
                            ("build_unit_id", self.build_unit_id), ("family", self.family)):
            if not _IDENTIFIER.fullmatch(value):
                raise ValueError(f"capture scope {name} is invalid")


@dataclass(slots=True)
class BuildExecutionRecorder:
    """Write bounded raw syscall evidence and its versioned job record."""

    root: Path
    scope: CaptureScope
    limits: BuildCaptureConfig
    collector: Mapping[str, Any]
    _stream: Any = field(init=False, repr=False, default=None)
    _observed: int = field(init=False, default=0)
    _retained: int = field(init=False, default=0)
    _invalid: int = field(init=False, default=0)
    _counts: dict[str, int] = field(init=False, default_factory=dict)
    _started_at: str = field(init=False)

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=False)
        if not self.collector.get("backend") or not self.collector.get("image_id"):
            raise ValueError("collector backend and image identity are required")
        captured = self.collector.get("event_kinds")
        if not isinstance(captured, Sequence) or not REQUIRED_EVENT_KINDS <= set(captured):
            raise ValueError("collector must enable every required event kind")
        self._started_at = datetime.now(UTC).isoformat()
        self._stream = (self.root / "events.jsonl").open("xb")

    def add(self, event: Mapping[str, Any]) -> bool:
        """Retain an event if valid and below the cap; always count observations."""
        self._observed += 1
        try:
            normalized = self._normalize(event)
        except (TypeError, ValueError):
            self._invalid += 1
            return False
        kind = normalized["kind"]
        self._counts[kind] = self._counts.get(kind, 0) + 1
        if self._retained >= self.limits.event_count_limit:
            return False
        self._stream.write(canonical_json(normalized))
        self._retained += 1
        return True

    def _normalize(self, event: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(event, Mapping):
            raise TypeError("event must be an object")
        kind = event.get("kind")
        if kind not in REQUIRED_EVENT_KINDS:
            raise ValueError("unknown event kind")
        monotonic_ns = event.get("monotonic_ns")
        pid, tid = event.get("pid"), event.get("tid")
        if not all(isinstance(value, int) and value >= 0 for value in (monotonic_ns, pid, tid)):
            raise ValueError("event timestamp and process identities must be non-negative integers")
        normalized: dict[str, Any] = {
            "schema": EVENT_SCHEMA, "ordinal": self._observed, "kind": kind,
            "timestamp_ns": monotonic_ns, "pid": pid, "tid": tid,
        }
        if kind == "process_exec":
            argv = event.get("argv")
            if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)):
                raise ValueError("exec argv must be an array")
            values = [str(item) for item in argv[:self.limits.argv_count_limit]]
            encoded = canonical_json(values)
            argv_truncated = len(argv) > len(values) or len(encoded) > self.limits.argument_bytes_limit
            while values and len(canonical_json(values)) > self.limits.argument_bytes_limit:
                values.pop()
            normalized.update(argv=values, argv_truncated=argv_truncated)
        elif kind == "file_open":
            path = event.get("path")
            if not isinstance(path, str):
                raise ValueError("open path must be a string")
            raw = path.encode("utf-8", "replace")
            clipped = raw[:self.limits.path_bytes_limit].decode("utf-8", "ignore")
            normalized.update(path=clipped, path_truncated=len(raw) > len(clipped.encode()))
        elif kind == "connect":
            normalized.update(
                address_family=int(event.get("address_family", -1)),
                address=str(event.get("address", "")),
                port=int(event.get("port", 0)),
                result=int(event.get("result", 0)),
            )
        elif kind == "process_fork":
            normalized["child_pid"] = int(event.get("child_pid", -1))
        else:
            normalized["exit_code"] = int(event.get("exit_code", 0))
        return normalized

    def finish(self, *, argv: Sequence[str], working_directory: str,
               exit_code: int | None, timed_out: bool, stdout_path: Path,
               stderr_path: Path, collector_dropped: int = 0,
               collector_errors: Sequence[str] = ()) -> Path:
        if self._stream is None:
            raise RuntimeError("capture recorder is already finished")
        self._stream.close()
        self._stream = None
        events_path = self.root / "events.jsonl"
        capped = self._observed > self._retained
        gaps = []
        if capped:
            gaps.append("syscall event retention limit reached")
        if collector_dropped:
            gaps.append("kernel collector reported dropped events")
        if self._invalid:
            gaps.append("collector emitted invalid events")
        gaps.extend(str(value) for value in collector_errors)
        record = {
            "schema": SCHEMA,
            "scope": {
                "run_id": self.scope.run_id, "job_id": self.scope.job_id,
                "attempt_id": self.scope.attempt_id, "build_unit_id": self.scope.build_unit_id,
                "family": self.scope.family,
            },
            "collector": dict(self.collector),
            "limits": {
                "event_count_limit": self.limits.event_count_limit,
                "argv_count_limit": self.limits.argv_count_limit,
                "argument_bytes_limit": self.limits.argument_bytes_limit,
                "path_bytes_limit": self.limits.path_bytes_limit,
                "tool_call_count_limit": self.limits.tool_call_count_limit,
                "tool_stream_bytes_limit": self.limits.tool_stream_bytes_limit,
            },
            "started_at": self._started_at,
            "completed_at": datetime.now(UTC).isoformat(),
            "command": {"argv": list(argv), "working_directory": working_directory,
                        "exit_code": exit_code, "timed_out": timed_out},
            "events": {
                "uri": events_path.name, "sha256": _sha256(events_path),
                "observed": self._observed, "retained": self._retained,
                "invalid": self._invalid, "collector_dropped": collector_dropped,
                "capped": capped, "counts": dict(sorted(self._counts.items())),
            },
            "streams": {
                "stdout": {"uri": stdout_path.name, "sha256": _sha256(stdout_path),
                           "bytes": stdout_path.stat().st_size},
                "stderr": {"uri": stderr_path.name, "sha256": _sha256(stderr_path),
                           "bytes": stderr_path.stat().st_size},
            },
            "coverage": {"complete": not gaps, "gaps": gaps},
        }
        call_records = sorted((self.root / "tool-calls").glob("*/record.json"))
        observed_path = self.root / "tool-call-counter"
        observed_calls = int(observed_path.read_text(encoding="utf-8").strip() or "0") \
            if observed_path.is_file() else 0
        call_capped = observed_calls > len(call_records)
        record["tool_calls"] = {
            "observed": observed_calls, "retained": len(call_records), "capped": call_capped,
            "records": [{"uri": item.relative_to(self.root).as_posix(), "sha256": _sha256(item)}
                        for item in call_records],
        }
        if call_capped:
            record["coverage"]["complete"] = False
            record["coverage"]["gaps"].append("tool call retention limit reached")
        path = self.root / "record.json"
        atomic_json(path, record)
        return path


_TRACE = re.compile(r"^(?P<time>[0-9]+(?:\.[0-9]+)?) (?P<call>[a-z0-9_]+)\((?P<body>.*)\) += (?P<result>.*)$")
_QUOTED = re.compile(r'^"((?:[^"\\]|\\.)*)"')


def _trace_string(value: str) -> str:
    match = _QUOTED.match(value.strip())
    if not match:
        return ""
    try:
        return json.loads('"' + match.group(1) + '"')
    except json.JSONDecodeError:
        return match.group(1)


def _exec_argv(body: str, executable: str) -> list[str]:
    start = body.find("[")
    end = body.rfind("]")
    if start < 0 or end < start:
        return [executable]
    values = []
    for match in re.finditer(r'"((?:[^"\\]|\\.)*)"', body[start:end + 1]):
        try:
            values.append(json.loads('"' + match.group(1) + '"'))
        except json.JSONDecodeError:
            values.append(match.group(1))
    return values or [executable]


def record_strace_files(paths: Iterable[Path], recorder: BuildExecutionRecorder) -> tuple[str, ...]:
    """Normalize bounded strace output; malformed rows become explicit collector errors."""
    errors: list[str] = []
    for path in sorted(paths, key=lambda item: item.name):
        suffix = path.name.rsplit(".", 1)[-1]
        pid = int(suffix) if suffix.isdigit() else 0
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line_number, line in enumerate(stream, 1):
                if recorder._observed >= recorder.limits.event_count_limit + 1:
                    return tuple(errors)
                match = _TRACE.match(line.rstrip("\n"))
                if not match:
                    if ("unfinished ...>" not in line and "resumed>" not in line and
                            "--- SIG" not in line and "+++ exited with" not in line):
                        errors.append(f"unparsed trace row: {path.name}:{line_number}")
                    continue
                call, body, result = match.group("call"), match.group("body"), match.group("result")
                timestamp_ns = int(float(match.group("time")) * 1_000_000_000)
                base = {"timestamp_ns": timestamp_ns, "monotonic_ns": timestamp_ns,
                        "pid": pid, "tid": pid}
                if call in {"execve", "execveat"}:
                    executable = _trace_string(body.split(",", 1)[0] if call == "execve" else body.split(",", 2)[1])
                    recorder.add({**base, "kind": "process_exec", "argv": _exec_argv(body, executable)})
                elif call in {"clone", "clone3", "fork", "vfork"}:
                    child = result.split(" ", 1)[0]
                    if child.isdigit():
                        recorder.add({**base, "kind": "process_fork", "child_pid": int(child)})
                elif call in {"exit", "exit_group"}:
                    code = body.split(",", 1)[0].strip()
                    recorder.add({**base, "kind": "process_exit",
                                  "exit_code": int(code) if code.lstrip("-").isdigit() else 0})
                elif call in {"openat", "openat2"}:
                    parts = body.split(",", 2)
                    recorder.add({**base, "kind": "file_open",
                                  "path": _trace_string(parts[1]) if len(parts) > 1 else ""})
                elif call == "connect":
                    family = re.search(r"sa_family=AF_([A-Z0-9_]+)", body)
                    port = re.search(r"sin6?_port=htons\(([0-9]+)\)", body)
                    address = re.search(r"inet_(?:addr|pton)\(\"([^\"]+)\"", body)
                    outcome = result.split(" ", 1)[0]
                    recorder.add({**base, "kind": "connect",
                                  "address_family": {"INET": 2, "INET6": 10, "UNIX": 1}.get(
                                      family.group(1) if family else "", 0),
                                  "address": address.group(1) if address else "",
                                  "port": int(port.group(1)) if port else 0,
                                  "result": int(outcome) if outcome.lstrip("-").isdigit() else -1})
    return tuple(errors)
