"""Tree-sitter invocation receipts and a stdlib-only, in-container resource supervisor."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Any, Mapping
from uuid import uuid4


RESOURCE_SCHEMA = "appsec-review/container-resource-snapshot/1"
INVOCATION_SCHEMA = "appsec-review/tree-sitter-invocation/1"
COUNTERS = ("cpu_usage_usec", "cpu_user_usec", "cpu_system_usec", "memory_peak_bytes",
            "io_read_bytes", "io_write_bytes", "io_read_operations", "io_write_operations",
            "oom_events", "oom_kill_events")
LIMIT_FILES = ("cpu.max", "memory.max", "memory.swap.max", "pids.max")
SUPERVISOR_PATH = "/opt/appsec/measurement.py"


def _stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def unavailable_resources(reason: str) -> dict[str, Any]:
    return {"schema": RESOURCE_SCHEMA, "captured_at": None, "final_snapshot": False,
            **dict.fromkeys(COUNTERS), "local_limits": dict.fromkeys(LIMIT_FILES),
            "limit_scope": "container_cgroup", "ancestor_limits_visible": False,
            "unavailable": {"snapshot": reason}}


def capture_resources(root: Path = Path("/sys/fs/cgroup")) -> dict[str, Any]:
    result = unavailable_resources("not_captured")
    result.update(captured_at=_stamp(), final_snapshot=True, unavailable={})

    def read(name: str) -> str | None:
        try:
            return (root / name).read_text(encoding="ascii").strip()
        except OSError as exc:
            result["unavailable"][name] = type(exc).__name__
            return None

    for name in LIMIT_FILES:
        result["local_limits"][name] = read(name)
    for name, mapping in (
        ("cpu.stat", {"usage_usec": "cpu_usage_usec", "user_usec": "cpu_user_usec",
                      "system_usec": "cpu_system_usec"}),
        ("memory.events", {"oom": "oom_events", "oom_kill": "oom_kill_events"}),
    ):
        text = read(name)
        if text is not None:
            values = dict(line.split() for line in text.splitlines())
            for key, destination in mapping.items():
                if key in values:
                    result[destination] = int(values[key])
                else:
                    result["unavailable"][destination] = "counter_absent"
    peak = read("memory.peak")
    if peak is not None:
        result["memory_peak_bytes"] = int(peak)
    io = read("io.stat")
    if io is not None:
        values = {"rbytes": 0, "wbytes": 0, "rios": 0, "wios": 0}
        for line in io.splitlines():
            fields = dict(field.split("=", 1) for field in line.split()[1:])
            for key in values:
                if key not in fields:
                    result["unavailable"]["io.stat"] = "counter_absent"
                    break
                values[key] += int(fields[key])
        if "io.stat" not in result["unavailable"]:
            for source, destination in zip(values, COUNTERS[4:8]):
                result[destination] = values[source]
    return result


def supervise(argv: list[str], output: Path, *, cgroup_root: Path = Path("/sys/fs/cgroup")) -> int:
    """Keep the cgroup alive until its final counters are retained, even if the parser is OOM-killed."""
    child = None
    signaled_at = None
    forwarded = []

    def forward(number, _frame):
        nonlocal signaled_at
        forwarded.append(number)
        signaled_at = signaled_at or time.monotonic()
        if child is not None:
            try:
                os.killpg(child.pid, number)
            except ProcessLookupError:
                pass  # The child exited between receipt and forwarding of the signal.

    previous = {number: signal.signal(number, forward)
                for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    started = _stamp()
    code = None
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, start_new_session=True)
        if forwarded:
            forward(forwarded[-1], None)
        while True:
            try:
                code = child.wait(timeout=0.1)
                break
            except subprocess.TimeoutExpired:
                if signaled_at is not None and time.monotonic() - signaled_at >= 2:
                    os.killpg(child.pid, signal.SIGKILL)
                    code = child.wait(timeout=1)
                    break
        return code if code >= 0 else 128 - code
    finally:
        try:
            if child is not None and child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=1)
            snapshot = capture_resources(cgroup_root)
            snapshot.update(parser_started_at=started, parser_completed_at=_stamp(),
                            parser_returncode=code, forwarded_signals=forwarded)
            temporary = output.with_suffix(".tmp")
            temporary.write_text(json.dumps(snapshot, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(temporary, output)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)


@dataclass(frozen=True)
class TreeSitterInvocation:
    invocation_id: str
    run_id: str
    job_id: str
    attempt_id: str
    unit_id: str
    scope_id: str
    language: str
    files: tuple[Mapping[str, str], ...]

    @classmethod
    def for_unit(cls, unit, request: Mapping[str, Any]) -> TreeSitterInvocation:
        return cls(uuid4().hex, unit.job.run_id, unit.job.config.job_id, unit.job.attempt_id,
                   unit.unit_id, str(request["scope_id"]), str(request["language"]),
                   tuple({"path": item["path"], "sha256": item["sha256"]} for item in request["files"]))

    def event(self, root: Path, event: str, **details) -> None:
        from appsec_review.observability.events import PipelineLog
        step, task = self.unit_id.split(".", 1)
        PipelineLog(root).write(event, run_id=self.run_id, job_id=self.job_id, attempt_id=self.attempt_id,
                               step_id=step, task_id=task, details={
                                   "tool_id": "tool-tree-sitter", "tool_invocation_id": self.invocation_id,
                                   "scope_id": self.scope_id, "language": self.language, **details})

    def record_output(self, root: Path, output: Mapping[str, Any]) -> None:
        records = output.get("records", ())
        counts = {"files_requested": len(self.files), "files_accounted": len(records),
                  "files_parsed": sum("nodes" in record for record in records),
                  "nodes_emitted": sum(len(record.get("nodes", ())) for record in records),
                  "truncated_files": sum(record.get("status") == "TRUNCATED" or bool(record.get("truncated"))
                                         for record in records)}
        receipt = _receipt(root, self.invocation_id, "output", {
            "schema": "appsec-review/tree-sitter-output-metrics/1",
            "invocation_id": self.invocation_id, **counts})
        self.event(root, "TREE_SITTER_OUTPUT_VALIDATED", metrics_receipt=receipt)


def record_reuse(unit, scope_id: str, fingerprint: str, invocation_id: str | None) -> None:
    from appsec_review.observability.events import PipelineLog
    identity = hashlib.sha256(json.dumps(
        [unit.job.run_id, unit.job.config.job_id, unit.job.attempt_id, unit.unit_id, scope_id, fingerprint]
    ).encode()).hexdigest()
    PipelineLog(unit.job.run_root).write("TREE_SITTER_REUSED", run_id=unit.job.run_id,
        job_id=unit.job.config.job_id, attempt_id=unit.job.attempt_id,
        step_id=unit.step_id, task_id=unit.task_id, details={
            "tool_id": "tool-tree-sitter", "reuse_id": identity, "scope_id": scope_id,
            "fingerprint": fingerprint, "source_invocation_id": invocation_id})


def _receipt(root: Path, invocation_id: str, name: str, value: Mapping[str, Any]) -> dict[str, Any]:
    from appsec_review.storage import canonical_json, file_sha256
    from appsec_review.storage.shared import immutable_bytes
    relative = f"data/telemetry/tree-sitter/{invocation_id}/{name}.json"
    immutable_bytes(root, relative, canonical_json(value))
    path = root / relative
    return {"path": relative, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}


class InvocationMeasurement:
    def __init__(self, root: Path, scratch: Path, context: TreeSitterInvocation):
        from appsec_review.storage.shared import immutable_bytes
        if len(context.invocation_id) != 32 or any(char not in "0123456789abcdef" for char in context.invocation_id):
            raise ValueError("invalid Tree-sitter invocation identity")
        self.root, self.scratch, self.context = root, scratch, context
        payload = Path(__file__).read_bytes()
        self.supervisor_sha256 = hashlib.sha256(payload).hexdigest()
        relative = f"data/telemetry/supervisors/{self.supervisor_sha256}.py"
        immutable_bytes(root, relative, payload)
        self.supervisor = root / relative
        self.supervisor.chmod(0o444)
        self.output = scratch / f"resources-{context.invocation_id}.json"
        if self.output.exists():
            raise FileExistsError("Tree-sitter invocation resource output already exists")
        self.started_at = ""
        self.started = {}
        self.receipt = None

    def start(self, started_at: str, *, image_id: str, container_name: str, limits: Mapping[str, Any]) -> None:
        self.started_at = started_at
        self.started = {"schema": INVOCATION_SCHEMA, **asdict(self.context), "started_at": started_at,
                        "image_id": image_id, "container_name": container_name, "configured_limits": dict(limits),
                        "supervisor_sha256": self.supervisor_sha256,
                        "execution_receipt_path": (self.scratch / "execution.json").relative_to(self.root).as_posix()}
        receipt = _receipt(self.root, self.context.invocation_id, "start", self.started)
        self.context.event(self.root, "TOOL_INVOCATION_STARTED", metrics_receipt=receipt)

    def finish(self, outcome=None, *, error: BaseException | None = None, cleanup: Mapping[str, Any] | None = None):
        if self.receipt is not None:
            return self.receipt
        if self.output.is_symlink():
            raise ValueError("Tree-sitter resource snapshot is a symbolic link")
        resources = json.loads(self.output.read_text()) if self.output.is_file() else unavailable_resources(
            "supervisor_final_snapshot_unavailable")
        if (resources.get("schema") != RESOURCE_SCHEMA or
                any(value is not None and (type(value) is not int or value < 0)
                    for value in (resources.get(key) for key in COUNTERS))):
            raise ValueError("invalid Tree-sitter resource counters")
        completed = _stamp()
        observed_oom = resources.get("oom_kill_events")
        oom_killed = (observed_oom > 0 if observed_oom is not None
                      else outcome.oom_killed if outcome is not None else None)
        status = ("CANCELED" if isinstance(error, (KeyboardInterrupt, SystemExit)) or
                  type(error).__name__ in {"ReviewStopped", "DagsterExecutionInterruptedError"}
                  else "FAILED" if error is not None else "TIMEOUT" if outcome.timed_out
                  else "OOM" if oom_killed else "SUCCEEDED" if outcome.exit_code == 0 else "FAILED")
        receipt = _receipt(self.root, self.context.invocation_id, "execution", {
            **self.started, "completed_at": completed,
            "duration_ms": max(0, int((datetime.fromisoformat(completed) -
                                     datetime.fromisoformat(self.started_at)).total_seconds() * 1000)),
            "status": status, "exit_code": outcome.exit_code if outcome is not None else None,
            "timed_out": outcome.timed_out if outcome is not None else None,
            "oom_killed": oom_killed,
            "oom_evidence": "cgroup" if observed_oom is not None else "executor_exit_heuristic",
            "error_type": type(error).__name__ if error is not None else None,
            "resources": resources, "termination": cleanup,
            "resource_accounting_complete": (resources.get("final_snapshot") is True
                                            and all(resources.get(key) is not None for key in COUNTERS)
                                            and not resources.get("unavailable")),
        })
        self.receipt = receipt
        self.context.event(self.root, "TOOL_INVOCATION_COMPLETED", metrics_receipt=receipt,
                           disposition=status, checkpoint_reused=False)
        return receipt


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    if command[:2] != ["/opt/appsec/parser.py", "parse"]:
        parser.error("measurement supervisor only executes the Tree-sitter parser")
    sys.exit(supervise(command, arguments.output))
