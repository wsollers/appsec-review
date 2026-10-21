"""The ``poc_writer`` model turn: request, bounded in-process retrieval, answer and receipt.

The model is granted no tools. It sees the brief once and answers with a closed turn: either
``retrieve`` (read a window of an accepted source file, or look up a declaration; the application
answers from the hash-verified accepted workspace, in process) or ``final`` (the compact answer of
review-judge-and-poc.md section 5.2, or a decline). The transport, the turn schema, the tolerant
parsing and the model recording are the review cells' (``appsec_review.inference``); the loop is
this job's own because the review cell executor is bound to the review roles and manifest-scoped
capabilities.

A denied retrieval is feedback with the corrected shape and costs one query; the second identical
denial ends the attempt, as in review-protocol-v2.md section 5.5. Receipts hold hashes and counts,
never raw prompts or retrieved text.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
from typing import Any, Protocol

from appsec_review.guidance.skills import load_runtime_skill
from appsec_review.inference import ModelOutputError, ReviewModelRequest
from appsec_review.storage import atomic_bytes, canonical_json

from .brief import ANSWER_SCHEMA, Brief
from .settings import ModelProfile, PocGenerationSettings
from .source import answer_errors

ROLE = "poc_writer"
SKILL = "poc-writer"
TURN_SCHEMA = "appsec-review/worker-turn/1"
PROTOCOL = "poc-writer/1"
RECEIPT_SCHEMA = "appsec-review/poc-writer-receipt/1"
GOVERNING = Path("pipeline") / "prompt-fragments" / "governing-rules.md"
ROLE_FILE = Path("pipeline") / "prompt-fragments" / "roles" / "poc_writer.md"
MAX_REQUESTS_PER_TURN = 3
MAX_WINDOW_LINES = 120
MAX_RESPONSE_BYTES = 12_000
TOOLS = ("read_source", "find_declaration")
ANSWER_NAME = "writer-answer"


class Reader(Protocol):
    """Read-only access to the accepted workspace for the writer's retrieval requests."""

    def read_source(self, path: str, start_line: int, end_line: int) -> dict[str, Any] | None: ...

    def find_declaration(self, name: str) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class Guidance:
    text: str
    sha256: str


def load_guidance(repository_root: Path, run_root: Path, job_id: str, profile: ModelProfile) -> Guidance:
    """The shared rules, the role and the runtime skill, pinned under ``data/guidance/<sha256>/``."""
    root = Path(repository_root)
    skill = load_runtime_skill(root, SKILL, job_id=job_id)
    files = {"governing-rules.md": (root / GOVERNING).read_text(encoding="utf-8"),
             "role.md": (root / ROLE_FILE).read_text(encoding="utf-8"), "skill.md": skill.text}
    identity = {"provider": profile.provider, "model": profile.model, "reasoning": profile.reasoning,
                "role": ROLE, "runtime_skill_sha256": skill.sha256}
    digest = hashlib.sha256(b"\0".join([*(files[name].encode() for name in sorted(files)),
                                        canonical_json(identity)])).hexdigest()
    destination = Path(run_root) / "data" / "guidance" / digest
    for name, text in sorted(files.items()):
        path = destination / name
        payload = text.encode()
        if path.exists() and path.read_bytes() != payload:
            raise ValueError("poc writer guidance changed after pinning")
        if not path.exists():
            atomic_bytes(path, payload)
    metadata = canonical_json({**identity, "guidance_sha256": digest})
    pinned = destination / "model-identity.json"
    if pinned.exists() and pinned.read_bytes() != metadata:
        raise ValueError("poc writer model identity changed after pinning")
    if not pinned.exists():
        atomic_bytes(pinned, metadata)
    return Guidance("\n\n".join((files["governing-rules.md"], files["role.md"], files["skill.md"])), digest)


@dataclass(slots=True)
class Attempt:
    number: int
    status: str = "answered"              # answered | declined | invalid | timed_out | failed | cap_reached
    reason: str = ""
    result: Mapping[str, Any] | None = None
    repair_errors: tuple[str, ...] = ()
    turns: list[dict[str, Any]] = field(default_factory=list)
    queries: int = 0
    denials: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    denied: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class WriterOutcome:
    status: str                           # answered | declined | failed
    result: Mapping[str, Any] | None
    reason: str
    attempts: tuple[Attempt, ...]

    def receipt(self, claim_id: str, brief_sha256: str, guidance_sha256: str, profile: ModelProfile) -> dict[str, Any]:
        return {"schema": RECEIPT_SCHEMA, "claim_id": claim_id, "brief_sha256": brief_sha256,
                "guidance_bundle_sha256": guidance_sha256,
                "model": {"provider": profile.provider, "model": profile.model, "reasoning": profile.reasoning},
                "status": self.status, "reason": self.reason or None,
                "attempts": [{"attempt": item.number, "status": item.status, "reason": item.reason or None,
                              "turns": item.turns, "queries": item.queries, "denials": item.denials,
                              "input_tokens": item.input_tokens, "output_tokens": item.output_tokens,
                              "repair_errors": list(item.repair_errors)} for item in self.attempts],
                "result_sha256": (hashlib.sha256(canonical_json(self.result)).hexdigest()
                                  if self.result is not None else None)}


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(json.loads(json.dumps(value, default=str)))).hexdigest()


def _tool_catalog() -> list[dict[str, Any]]:
    return [
        {"name": "read_source", "description": "Read a window of a source or header file of the accepted build. "
         "path is a workspace-relative path shown in the brief; at most 120 lines.",
         "parameters": {"type": "object", "required": ["path", "start_line", "end_line"],
                        "properties": {"path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1},
                                       "end_line": {"type": "integer", "minimum": 1}}}},
        {"name": "find_declaration", "description": "Prototype or type declaration lines of a name in the project "
         "headers on the translation unit's include path.",
         "parameters": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}}},
    ]


def _parse_turn(value: Any) -> tuple[dict[str, Any], str | None]:
    if not isinstance(value, Mapping):
        return {}, "the turn must be a JSON object"
    turn = {key: item for key, item in value.items() if key != "schema"}
    if "schema" in value and value["schema"] != TURN_SCHEMA:
        return {}, f"the turn schema must be {TURN_SCHEMA}"
    action = turn.get("action")
    if action == "retrieve" and set(turn) == {"action", "requests"}:
        requests = turn["requests"]
        if not isinstance(requests, list) or not 1 <= len(requests) <= MAX_REQUESTS_PER_TURN:
            return {}, f"requests must be a list of 1 to {MAX_REQUESTS_PER_TURN} requests"
        return {"action": "retrieve", "requests": json.loads(json.dumps(requests))}, None
    if action == "final" and set(turn) == {"action", "result"} and isinstance(turn["result"], Mapping):
        return {"action": "final", "result": json.loads(json.dumps(turn["result"]))}, None
    return {}, 'a turn is exactly {"action": "retrieve", "requests": [...]} or {"action": "final", "result": {...}}'


def _answer_request(attempt: Attempt, request: Any, reader: Reader) -> tuple[dict[str, Any], str | None]:
    """One retrieval request answered in process; the second element is a denial code, if any."""
    tool = request.get("tool") if isinstance(request, Mapping) else None
    parameters = request.get("parameters") if isinstance(request, Mapping) else None
    if tool not in TOOLS or not isinstance(parameters, Mapping):
        return {"status": "denied", "code": "unknown_tool", "reason": "name one of the listed tools with parameters",
                "corrected": {"tool": "find_declaration", "parameters": {"name": "<function or type name>"}}}, \
            "unknown_tool"
    if tool == "read_source":
        path, start, end = parameters.get("path"), parameters.get("start_line"), parameters.get("end_line")
        if (not isinstance(path, str) or type(start) is not int or type(end) is not int or start < 1 or end < start
                or end - start + 1 > MAX_WINDOW_LINES):
            return {"status": "denied", "code": "malformed_request",
                    "reason": f"give path, start_line and end_line with at most {MAX_WINDOW_LINES} lines",
                    "corrected": {"tool": "read_source",
                                  "parameters": {"path": "<path from the brief>", "start_line": 1, "end_line": 40}}}, \
                "malformed_request"
        window = reader.read_source(path, start, end)
        if window is None:
            return {"status": "denied", "code": "path_not_available",
                    "reason": "that path is not a file of the accepted build workspace",
                    "corrected": {"tool": "read_source", "parameters": {"path": "<a path shown in the brief>",
                                                                        "start_line": 1, "end_line": 40}}}, \
                "path_not_available"
        return {"status": "ok", "tool": tool, **window}, None
    name = parameters.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        return {"status": "denied", "code": "malformed_request", "reason": "give a name",
                "corrected": {"tool": "find_declaration", "parameters": {"name": "<name>"}}}, "malformed_request"
    return {"status": "ok", "tool": tool, "name": name, "rows": reader.find_declaration(name)[:8]}, None


def _bounded(response: dict[str, Any]) -> dict[str, Any]:
    while len(canonical_json(response)) > MAX_RESPONSE_BYTES:
        rows = response.get("rows") or response.get("text")
        if not rows:
            break
        if "rows" in response:
            response["rows"] = response["rows"][:-1]
        else:
            response["text"] = response["text"][:-1]
        response["truncated"] = True
    return response


def _attempt(number: int, brief: Brief, guidance: Guidance, profile: ModelProfile, infer: Callable[..., Any],
             reader: Reader, schemas: Any, repair: tuple[str, ...], claim_id: str) -> Attempt:
    attempt = Attempt(number)
    transcript: list[dict[str, Any]] = []
    task_input = {
        "protocol": PROTOCOL, "task": "write_poc_function", "input": brief.document, "output_schema": ANSWER_SCHEMA,
        "turn_protocol": {"schema": TURN_SCHEMA, "actions": ["retrieve", "final"],
                          "max_requests_per_turn": MAX_REQUESTS_PER_TURN,
                          "retrieve_shape": {"action": "retrieve", "requests": [
                              {"tool": "find_declaration", "parameters": {"name": "<name>"}}]},
                          "tool_catalog": _tool_catalog(), "max_queries": profile.max_queries}}
    for turn_number in range(1, profile.max_turns + 1):
        final_required = turn_number == profile.max_turns or attempt.queries >= profile.max_queries
        request = ReviewModelRequest(
            schema=TURN_SCHEMA, role=ROLE, persona="", stack_profile="", guidance_bundle_sha256=guidance.sha256,
            guidance_text=guidance.text, task_input=task_input, transcript=tuple(transcript),
            provider=profile.provider, model=profile.model, reasoning=profile.reasoning,
            max_input_tokens=profile.max_input_tokens, max_output_tokens=profile.max_output_tokens,
            repair_errors=repair if turn_number == 1 else (), cell_id=f"poc-writer:{claim_id}")
        entry: dict[str, Any] = {"turn": turn_number, "request_sha256": _sha(asdict(request)),
                                 "final_required": final_required, "action": None, "response_sha256": None,
                                 "retrievals": []}
        attempt.turns.append(entry)
        try:
            response = infer(request, timeout_seconds=profile.timeout_seconds)
        except ModelOutputError:
            attempt.status, attempt.reason = "invalid", "model_output_unparseable"
            attempt.repair_errors = (f"the reply was not exactly one {TURN_SCHEMA} object",)
            return attempt
        except (TimeoutError, subprocess.TimeoutExpired):
            attempt.status, attempt.reason = "timed_out", "provider_timeout"
            return attempt
        except Exception as exc:  # every provider failure is an ordinary, named outcome
            attempt.status, attempt.reason = "failed", f"provider_error:{type(exc).__name__}"
            return attempt
        entry["input_tokens"] = int(response.input_tokens or 0)
        entry["output_tokens"] = int(response.output_tokens or 0)
        attempt.input_tokens += entry["input_tokens"]
        attempt.output_tokens += entry["output_tokens"]
        entry["response_sha256"] = _sha(response.raw_response if response.raw_response is not None
                                        else response.proposal)
        turn, error = _parse_turn(response.proposal)
        if error:
            attempt.status, attempt.reason, attempt.repair_errors = "invalid", "malformed_turn", (error,)
            return attempt
        entry["action"] = turn["action"]
        if turn["action"] == "final":
            result = turn["result"]
            errors = [*schemas.errors(ANSWER_NAME, result), *answer_errors(result)]
            if errors:
                attempt.status, attempt.reason = "invalid", "final_result_rejected"
                attempt.repair_errors = tuple(str(item)[:240] for item in errors[:20])
                return attempt
            attempt.result = result
            attempt.status = "declined" if isinstance(result.get("decline"), Mapping) else "answered"
            return attempt
        if final_required:
            attempt.status, attempt.reason = "cap_reached", "cap_reached_without_final"
            attempt.repair_errors = ("the turn or query cap was reached; the next turn must be final",)
            return attempt
        responses = []
        for index, item in enumerate(turn["requests"]):
            if attempt.queries >= profile.max_queries:
                responses.append({"index": index, "status": "denied", "code": "query_cap_exceeded",
                                  "reason": "the query budget is spent; answer with a final turn"})
                continue
            attempt.queries += 1
            outcome, denial = _answer_request(attempt, item, reader)
            call = {"index": index, "tool": item.get("tool") if isinstance(item, Mapping) else None,
                    "status": outcome["status"], "code": outcome.get("code")}
            entry["retrievals"].append(call)
            if denial:
                attempt.denials += 1
                key = f"{denial}:{_sha(item)}"
                attempt.denied[key] = attempt.denied.get(key, 0) + 1
                if attempt.denied[key] >= 2:
                    attempt.status, attempt.reason = "invalid", f"repeated_denial:{denial}"
                    attempt.repair_errors = ("the same request was denied twice",)
                    return attempt
            responses.append({"index": index, **_bounded(outcome)})
        transcript.append({"turn": turn_number, "from": "worker", "content": turn})
        transcript.append({"turn": turn_number, "from": "application", "responses": responses,
                           "remaining_queries": max(0, profile.max_queries - attempt.queries),
                           "remaining_turns": profile.max_turns - turn_number,
                           "final_required": turn_number + 1 == profile.max_turns
                           or attempt.queries >= profile.max_queries})
    raise AssertionError("unreachable: the last permitted turn always ends the attempt")


def run_writer(brief: Brief, *, guidance: Guidance, settings: PocGenerationSettings, infer: Callable[..., Any],
               reader: Reader, schemas: Any, claim_id: str) -> WriterOutcome:
    """Run the writer to one terminal outcome, repairing per the retry policy without widening it."""
    profile = settings.writer
    attempts: list[Attempt] = []
    repair: tuple[str, ...] = ()
    for number in range(1, settings.max_attempts + 1):
        attempt = _attempt(number, brief, guidance, profile, infer, reader, schemas, repair, claim_id)
        attempts.append(attempt)
        if attempt.status in {"answered", "declined"}:
            return WriterOutcome("answered" if attempt.status == "answered" else "declined", attempt.result, "",
                                 tuple(attempts))
        retry = ((attempt.status == "timed_out" and settings.retry_on_timeout)
                 or (attempt.status == "failed" and settings.retry_on_provider_error)
                 or (attempt.status in {"invalid", "cap_reached"} and settings.retry_on_invalid_output))
        if not retry:
            break
        repair = attempt.repair_errors
    last = attempts[-1]
    return WriterOutcome("failed", None, f"writer_{last.status}:{last.reason}", tuple(attempts))


class WorkspaceReader:
    """The writer's retrieval over the hash-verified accepted workspace (read-only, path-scoped)."""

    def __init__(self, workspace: Path, manifest: Mapping[str, str], allowed_directories: Sequence[str],
                 finder: Callable[[str], list[dict[str, Any]]]) -> None:
        self.workspace = Path(workspace)
        self.manifest = manifest
        self.allowed = tuple(allowed_directories)
        self.finder = finder

    def read_source(self, path: str, start_line: int, end_line: int) -> dict[str, Any] | None:
        logical = PurePosixPath(path)
        if logical.is_absolute() or ".." in logical.parts or logical.as_posix() not in self.manifest:
            return None
        if not any(d == "." or logical.as_posix().startswith(d.rstrip("/") + "/") for d in self.allowed):
            return None
        source = self.workspace.joinpath(*logical.parts)
        try:
            if source.is_symlink() or source.stat().st_size > 2 * 1024 * 1024:
                return None
            data = source.read_bytes()
            if hashlib.sha256(data).hexdigest() != self.manifest[logical.as_posix()]:
                return None                      # the accepted workspace changed; nothing is shown from it
            lines = data.decode("utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            return None
        end = min(end_line, len(lines))
        return {"path": logical.as_posix(), "lines": f"{start_line}-{end}",
                "text": [f"{number}| {lines[number - 1].rstrip()[:200]}" for number in range(start_line, end + 1)]}

    def find_declaration(self, name: str) -> list[dict[str, Any]]:
        return self.finder(name)


__all__ = ["ANSWER_NAME", "Guidance", "Reader", "WorkspaceReader", "WriterOutcome", "load_guidance", "run_writer"]
