from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
from typing import Any

from appsec_review.container_runtime import VerifiedCapture
from appsec_review.storage import canonical_json


_REDACTED = "<redacted"


@dataclass(frozen=True, slots=True)
class ToolIdentity:
    """The language-specific meaning of an executable that the kernel started."""

    name: str
    kind: str


ToolClassifier = Callable[[str, Sequence[str]], ToolIdentity | None]
InvocationBuilder = Callable[
    [str, str, Sequence[str], Path, str, str], dict[str, Any]
]


@dataclass(frozen=True, slots=True)
class CapturedBuildDescriptor:
    """Only the variation needed to interpret a generic captured build."""

    family: str
    capture_identity: str
    provenance_schema: str
    catalog_label: str
    classify_tool: ToolClassifier
    build_invocation: InvocationBuilder
    link_kinds: frozenset[str] = frozenset()
    required_tool_kind: str | None = "compiler"
    missing_tool_gap: str | None = None

    def __post_init__(self) -> None:
        if not self.family or not self.capture_identity or not self.provenance_schema:
            raise ValueError("captured-build descriptor identities are required")
        if self.required_tool_kind is not None and not self.missing_tool_gap:
            raise ValueError("a required captured-build tool needs an explicit gap")


@dataclass(frozen=True, slots=True)
class ReconciliationLimits:
    invocation_count: int = 16384
    event_ordinals_per_invocation: int = 8
    envp_redacted_name_count: int = 256

    def __post_init__(self) -> None:
        if min(self.invocation_count, self.event_ordinals_per_invocation,
               self.envp_redacted_name_count) < 1:
            raise ValueError("captured-build reconciliation limits must be positive")


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    rows: tuple[dict[str, Any], ...]
    facts: Mapping[str, Any]
    gaps: tuple[str, ...]


def _argv(value: object) -> list[str] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return None
    return [str(item) for item in value]


def _identity_key(identity: ToolIdentity, argv: Sequence[str]) -> str:
    # PATH wrappers, toolchain proxies, and resolved binaries differ only in argv[0].
    return hashlib.sha256(canonical_json(
        [identity.name, *[str(value) for value in argv[1:]]]
    )).hexdigest()


def _tool_call_evidence(call: Mapping[str, Any], document: Mapping[str, Any]) -> dict[str, Any]:
    stdout = document.get("stdout")
    stderr = document.get("stderr")
    return {
        "uri": call.get("uri"),
        "sha256": call.get("sha256"),
        "exit_code": document.get("exit_code"),
        "stdout_sha256": stdout.get("sha256") if isinstance(stdout, Mapping) else None,
        "stderr_sha256": stderr.get("sha256") if isinstance(stderr, Mapping) else None,
    }


def reconcile_captured_build(
        captures: Sequence[tuple[int, VerifiedCapture]], workspace: Path, directory: str,
        descriptor: CapturedBuildDescriptor, *,
        limits: ReconciliationLimits = ReconciliationLimits()) -> ReconciliationResult:
    """Reconcile all captured build tools through one syscall-authoritative algorithm.

    A successful ``process_exec`` is the only event that can create a row. Wrapper records are
    optional secondary evidence and are attached only after matching such a row. Invalid,
    redacted, failed, capped, and unmatched inputs are counted and surfaced as gaps.
    """
    rows: dict[str, dict[str, Any]] = {}
    facts: dict[str, Any] = {
        "process_exec_events": 0,
        "failed_exec_events": 0,
        "redacted_exec_events": 0,
        "tool_call_records": 0,
        "redacted_tool_calls": 0,
        "unreconciled_tool_calls": 0,
        "malformed_records": 0,
        "connect_events": 0,
        "envp_events": 0,
        "envp_redacted_names": [],
        "capture_gap_count": 0,
        "event_records_observed": 0,
        "event_records_retained": 0,
        "event_records_lost": 0,
        "tool_call_records_observed": 0,
        "tool_call_records_retained": 0,
        "tool_call_records_lost": 0,
    }
    redacted_names: set[str] = set()
    truncated = False

    for ordinal, capture in captures:
        label = f"execution-capture:command-{ordinal:03d}"
        record_sha = str(capture.identity["sha256"])
        facts["capture_gap_count"] += len(capture.gaps)
        event_summary = capture.document.get("events")
        tool_summary = capture.document.get("tool_calls")
        if isinstance(event_summary, Mapping):
            observed = event_summary.get("observed")
            retained = event_summary.get("retained")
            if type(observed) is int and type(retained) is int:
                facts["event_records_observed"] += observed
                facts["event_records_retained"] += retained
                facts["event_records_lost"] += max(0, observed - retained)
        if isinstance(tool_summary, Mapping):
            observed = tool_summary.get("observed")
            retained = tool_summary.get("retained")
            if type(observed) is int and type(retained) is int:
                facts["tool_call_records_observed"] += observed
                facts["tool_call_records_retained"] += retained
                facts["tool_call_records_lost"] += max(0, observed - retained)

        for event in capture.events():
            if not isinstance(event, Mapping):
                facts["malformed_records"] += 1
                continue
            if event.get("kind") == "connect":
                facts["connect_events"] += 1
                continue
            if event.get("kind") != "process_exec":
                continue
            facts["process_exec_events"] += 1
            argv = _argv(event.get("argv"))
            executable_value = event.get("executable", "")
            result = event.get("result", 0)
            if argv is None or not isinstance(executable_value, str) or type(result) is not int:
                facts["malformed_records"] += 1
                continue
            executable = executable_value
            if event.get("envp_captured") is True:
                names = event.get("envp_redacted_names", ())
                if not isinstance(names, Sequence) or isinstance(names, (str, bytes)):
                    facts["malformed_records"] += 1
                    continue
                facts["envp_events"] += 1
                redacted_names.update(str(name) for name in names)
            if executable.startswith(_REDACTED) or (argv and argv[0].startswith(_REDACTED)):
                facts["redacted_exec_events"] += 1
                continue
            if result != 0:
                facts["failed_exec_events"] += 1
                continue
            identity = descriptor.classify_tool(
                PurePosixPath(executable or (argv[0] if argv else "")).name, argv
            )
            if identity is None:
                continue
            key = _identity_key(identity, argv)
            row = rows.get(key)
            if row is None:
                if len(rows) >= limits.invocation_count:
                    truncated = True
                    continue
                row = descriptor.build_invocation(
                    identity.name, identity.kind, argv, workspace, directory,
                    f"{label}:event-{event.get('ordinal')}",
                )
                row["evidence"] = {
                    "capture_record_sha256": record_sha,
                    "tool_call": None,
                    "process_exec": {
                        "count": 0,
                        "event_ordinals": [],
                        "executable": executable,
                    },
                }
                rows[key] = row
            observed_exec = row["evidence"]["process_exec"]
            observed_exec["count"] += 1
            if len(observed_exec["event_ordinals"]) < limits.event_ordinals_per_invocation:
                observed_exec["event_ordinals"].append(event.get("ordinal"))

        for call in capture.tool_calls:
            facts["tool_call_records"] += 1
            if not isinstance(call, Mapping) or not isinstance(call.get("record"), Mapping):
                facts["malformed_records"] += 1
                continue
            document = call["record"]
            argv = _argv(document.get("argv"))
            tool = document.get("tool", "")
            if argv is None or not isinstance(tool, str):
                facts["malformed_records"] += 1
                continue
            if argv and argv[0].startswith(_REDACTED):
                facts["redacted_tool_calls"] += 1
                continue
            identity = descriptor.classify_tool(PurePosixPath(tool).name, argv)
            if identity is None:
                continue
            row = rows.get(_identity_key(identity, argv))
            if row is None:
                facts["unreconciled_tool_calls"] += 1
                continue
            if row["evidence"]["tool_call"] is None:
                row["evidence"]["tool_call"] = _tool_call_evidence(call, document)

    for row in rows.values():
        row["mapping"] = (
            "syscall-process-exec+tool-call"
            if row["evidence"]["tool_call"] else "syscall-process-exec"
        )
    facts["envp_redacted_names"] = sorted(redacted_names)[:limits.envp_redacted_name_count]

    gaps: list[str] = []
    if facts["redacted_exec_events"]:
        gaps.append(
            f"{facts['redacted_exec_events']} process-exec events were redacted by the secret "
            "scan; their tool provenance is unavailable"
        )
    if facts["redacted_tool_calls"]:
        gaps.append(
            f"{facts['redacted_tool_calls']} tool-call records were redacted by the secret scan"
        )
    if facts["unreconciled_tool_calls"]:
        gaps.append(
            f"{facts['unreconciled_tool_calls']} tool-call records had no matching successful "
            "process-exec event and are not claimed as tool execution"
        )
    if facts["malformed_records"]:
        gaps.append(
            f"{facts['malformed_records']} captured build records were malformed and ignored"
        )
    if truncated:
        gaps.append(
            f"{descriptor.catalog_label} tool invocation catalog truncated at its row bound"
        )
    return ReconciliationResult(tuple(rows.values()), facts, tuple(gaps))


def link_rows(rows: Sequence[Mapping[str, Any]],
              descriptor: CapturedBuildDescriptor) -> list[Mapping[str, Any]]:
    return [row for row in rows if row.get("tool_kind") in descriptor.link_kinds]
