"""Bounded, application-mediated review cell executor (design R1, R2).

A cell is one role's bounded question about one package. The model is granted no tools: every
turn it returns exactly one closed object, either

    {"action": "retrieve", "requests": [{"tool": ..., "parameters": {...}}, ...]}
    {"action": "final", "result": {...}}

(transports also carry `"schema": TURN_SCHEMA`). The application authorizes each request against
the cell's `CellCapability`, runs it in-process on `RetrievalCore`, and returns bounded rows with
their identities in the next turn. A final result may cite only identities from this cell's own
retrieval transcript or its package.

Every attempt writes one receipt, atomically, at `<receipts_root>/<cell_id>/attempt-<n>.json`. It
holds request, transcript, and response hashes, never raw prompts or retrieved text. Ordinary
failures end in exactly one terminal `CellStatus` with a typed gap; only a framework-integrity
failure raises.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
import sqlite3
import subprocess
from typing import Any, Callable, Iterator, Mapping, Sequence

from appsec_review.inference import ModelOutputError, ModelResult, ReviewModelRequest
from appsec_review.retrieval.core import RetrievalGap, RetrievalIntegrityError
from appsec_review.review.capability import GRAPH_ROW_KINDS, AuthorityDenied, CellCapability, TOOL_SCHEMAS
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import (
    CellRecord, CellStatus, Gap, GapClass, IntegrityError, Lane, Role,
)
from appsec_review.storage import atomic_json, file_sha256

TURN_SCHEMA = "appsec-review/worker-turn/1"
RECEIPT_SCHEMA = "appsec-review/cell-attempt-receipt/1"
EXECUTOR_VERSION = "review-cell-executor/1"
MAX_REQUESTS_PER_TURN = 16
MAX_REPAIR_ERRORS = 20
_LOGICAL_ID = re.compile(r"^asr:[a-z][a-z0-9_]*:[0-9a-f]{64}$")
_ATTEMPT_FILE = re.compile(r"^attempt-([1-9][0-9]{0,5})\.json$")
# Response fields that vary with wall-clock time; they never enter a receipt hash.
_VOLATILE_RESPONSE_FIELDS = frozenset({"duration_ms"})

Infer = Callable[..., ModelResult]
ValidateFinal = Callable[[Mapping[str, Any]], Sequence[str]]


class CellBudgetExceeded(Exception):
    """Raised by an infer wrapper when a cell reaches its wall-clock deadline or token cap.

    The cell ends ``timed_out`` with a ``budget_gap``; it is never retried.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = str(reason)[:200]


@dataclass(frozen=True, slots=True)
class CellSpec:
    """Everything semantic about one cell. Capacity settings (workers, teams, pools) are absent."""

    manifest_sha256: str
    lane: Lane
    package_id: str
    package_sha256: str
    claim_id: str | None
    role: Role
    persona: str                         # "" when the cell has no persona
    stack_profile: str
    strategy: str | None
    task: str
    task_input: Mapping[str, Any]
    round: int
    round_delta_sha256: str | None
    evidence_set: tuple[str, ...]        # package-supplied identities the cell may cite
    guidance_bundle_sha256: str
    guidance_text: str
    provider: str
    model: str
    reasoning: str
    max_input_tokens: int
    max_output_tokens: int
    timeout_seconds: int
    output_schema: str
    validator_version: str
    # When set, replaces the whole-manifest and package identities in the fingerprint with the
    # hash of the accepted shards and package content this cell can read (selective invalidation).
    reuse_basis: str | None = None


@dataclass(frozen=True, slots=True)
class CellOutcome:
    record: CellRecord
    result: Mapping[str, Any] | None
    gaps: tuple[Gap, ...]
    security_events: tuple[Mapping[str, Any], ...]
    receipt_paths: tuple[Path, ...]
    reused: bool
    counts: Mapping[str, int]


def cell_fingerprint(spec: CellSpec, capability: CellCapability) -> str:
    """The `cell/v1` identity. Retry and concurrency settings are deliberately not inputs."""
    semantic = capability.semantic_body()
    inputs: dict[str, Any] = ({"run_input_manifest": spec.manifest_sha256,
                               "package": {"id": spec.package_id, "sha256": spec.package_sha256}}
                              if spec.reuse_basis is None else {"reuse_basis": spec.reuse_basis})
    return make_id("cell", 1, {
        "schema": "cell/v1",
        **inputs,
        "lane": Lane(spec.lane).value,
        "claim": spec.claim_id,
        "role": Role(spec.role).value,
        "persona": spec.persona,
        "stack_profile": spec.stack_profile,
        "strategy": spec.strategy,
        "task": {"id": spec.task, "input_sha256": sha256_hex(_plain(spec.task_input))},
        "round": spec.round,
        "round_delta": spec.round_delta_sha256,
        "readable_evidence_set": sorted(set(spec.evidence_set)),
        "guidance_bundle": spec.guidance_bundle_sha256,
        "model": {"provider": spec.provider, "model": spec.model, "reasoning": spec.reasoning},
        "tool_capabilities": {key: semantic[key] for key in ("tools", "indexes", "entities",
                                                              "entity_prefixes", "graph_scopes")},
        "budgets": {**{key: semantic[key] for key in ("max_queries", "max_turns", "page_size",
                                                       "max_depth", "max_result_bytes")},
                    "max_input_tokens": spec.max_input_tokens,
                    "max_output_tokens": spec.max_output_tokens,
                    "timeout_seconds": spec.timeout_seconds},
        "output_schema": spec.output_schema,
        "validator_version": {"executor": EXECUTOR_VERSION, "result": spec.validator_version},
    })


@dataclass(slots=True)
class _Attempt:
    number: int
    status: CellStatus = CellStatus.SUCCEEDED
    gap_class: GapClass | None = None
    reason: str = ""
    result: Mapping[str, Any] | None = None
    repair_errors: tuple[str, ...] = ()
    turns: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    security_events: list[dict[str, Any]] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)
    queries: int = 0
    denials: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def end(self, status: CellStatus, gap_class: GapClass, reason: str) -> None:
        self.status, self.gap_class, self.reason = status, gap_class, reason[:256]


def run_cell(spec: CellSpec, *, infer: Infer, core: Any, capability: CellCapability,
             receipts_root: Path, validate_final: ValidateFinal, max_attempts: int = 1,
             retry_on_timeout: bool = True, retry_on_provider_error: bool = True,
             retry_on_invalid_output: bool = False) -> CellOutcome:
    """Run one cell to exactly one terminal status, retrying per policy without widening it."""
    cell_id = _bind(spec, capability, core)
    cell_root = Path(receipts_root) / cell_id
    number = max(_attempt_numbers(cell_root), default=0)
    attempts: list[_Attempt] = []
    paths: list[Path] = []
    repair: tuple[str, ...] = ()
    for _ in range(max(1, int(max_attempts))):
        number += 1
        attempt = _run_attempt(spec, cell_id, number, infer=infer, core=core, capability=capability,
                               validate_final=validate_final, repair_errors=repair)
        attempts.append(attempt)
        paths.append(_write_receipt(cell_root, spec, cell_id, capability, attempt))
        if attempt.status is CellStatus.SUCCEEDED or not _retryable(
                attempt, retry_on_timeout, retry_on_provider_error, retry_on_invalid_output):
            break
        repair = attempt.repair_errors
    final = attempts[-1]
    gaps = [gap for attempt in attempts for gap in attempt.gaps
            if gap.gap_class is GapClass.AUTHORITY_ERROR or attempt is final]
    if final.status is not CellStatus.SUCCEEDED:
        gaps.append(_gap(cell_id, spec, final.number, "terminal", final.gap_class, final.reason))
    gaps = list({gap.gap_id: gap for gap in gaps}.values())
    counts = {"attempts": len(attempts),
              "turns": sum(len(item.turns) for item in attempts),
              "queries": sum(item.queries for item in attempts),
              "denials": sum(item.denials for item in attempts),
              "input_tokens": sum(item.input_tokens for item in attempts),
              "output_tokens": sum(item.output_tokens for item in attempts)}
    return CellOutcome(
        record=_record(spec, cell_id, final.status, final.number, gaps, paths[-1]),
        result=final.result if final.status is CellStatus.SUCCEEDED else None,
        gaps=tuple(gaps),
        security_events=tuple(event for attempt in attempts for event in attempt.security_events),
        receipt_paths=tuple(paths), reused=False, counts=counts)


def reuse_or_run(spec: CellSpec, *, infer: Infer, core: Any, capability: CellCapability,
                 receipts_root: Path, validate_final: ValidateFinal, **retry: Any) -> CellOutcome:
    """Reuse a succeeded, revalidated receipt with this fingerprint; otherwise run the cell."""
    cell_id = _bind(spec, capability, core)
    cell_root = Path(receipts_root) / cell_id
    for number in sorted(_attempt_numbers(cell_root), reverse=True):
        path = cell_root / f"attempt-{number}.json"
        receipt = _load_receipt(path, cell_id, number)
        if receipt["status"] != CellStatus.SUCCEEDED.value:
            continue
        if (receipt["executor_version"], receipt["validator_version"]) != (
                EXECUTOR_VERSION, spec.validator_version):
            break
        result = receipt["result"]
        citable = set(receipt["seen_identities"]) | set(spec.evidence_set)
        if _citation_errors(result, citable) or list(validate_final(result)):
            break
        gaps = tuple(Gap(item["gap_id"], GapClass(item["gap_class"]), cell_id, item["reason"],
                         round=spec.round) for item in receipt["gaps"])
        return CellOutcome(
            record=_record(spec, cell_id, CellStatus.SUCCEEDED, number, gaps, path),
            result=result, gaps=gaps, security_events=tuple(receipt["security_events"]),
            receipt_paths=(path,), reused=True, counts={**receipt["counts"], "attempts": 0})
    return run_cell(spec, infer=infer, core=core, capability=capability, receipts_root=receipts_root,
                    validate_final=validate_final, **retry)


def _tool_catalog(capability: CellCapability) -> list[dict[str, Any]]:
    """The granted tools with their exact parameter schemas, so a worker never has to guess a parameter name."""

    from appsec_review.mcp.schema import TOOLS

    by_name = {tool["name"]: tool for tool in TOOLS}
    return [{"name": name, "description": by_name[name].get("description", ""),
             "parameters": by_name[name]["inputSchema"]} for name in sorted(capability.tools) if name in by_name]


def _request_example(capability: CellCapability) -> dict[str, Any]:
    """One well-formed request for the first granted tool, with placeholders for its required parameters."""

    catalog = _tool_catalog(capability)
    if not catalog:
        return {"tool": "<a tool from tool_catalog>", "parameters": {}}
    first = catalog[0]
    required = first["parameters"].get("required", [])
    return {"tool": first["name"], "parameters": {name: f"<{name}>" for name in required}}


def _bind(spec: CellSpec, capability: CellCapability, core: Any) -> str:
    """The application must have issued this exact capability for this exact cell."""
    capability.verify()
    expected = (spec.manifest_sha256, spec.package_id, spec.package_sha256, Role(spec.role), spec.round)
    actual = (capability.manifest_sha256, capability.package_id, capability.package_sha256,
              capability.role, capability.round)
    if expected != actual:
        raise IntegrityError("cell capability is not bound to this cell's manifest, package, role, or round")
    if getattr(core, "manifest_sha256", None) != capability.manifest_sha256:
        raise IntegrityError("retrieval core is pinned to a different accepted manifest")
    return cell_fingerprint(spec, capability)


def _run_attempt(spec: CellSpec, cell_id: str, number: int, *, infer: Infer, core: Any,
                 capability: CellCapability, validate_final: ValidateFinal,
                 repair_errors: tuple[str, ...]) -> _Attempt:
    attempt = _Attempt(number)
    transcript: list[dict[str, Any]] = []
    citable_package = set(spec.evidence_set)
    task_input = {
        "task": spec.task, "round": spec.round, "input": _plain(spec.task_input),
        "output_schema": spec.output_schema, "package_identities": sorted(citable_package),
        "capability": capability.public_view(),
        "turn_protocol": {"schema": TURN_SCHEMA, "actions": ["retrieve", "final"],
                          "max_requests_per_turn": MAX_REQUESTS_PER_TURN,
                          "retrieve_shape": {"action": "retrieve", "requests": [_request_example(capability)]},
                          "request_rule": "each request is exactly {tool, parameters}; use only the parameter names "
                                          "listed for that tool in tool_catalog",
                          "tool_catalog": _tool_catalog(capability)},
    }
    for turn_number in range(1, capability.max_turns + 1):
        final_required = turn_number == capability.max_turns or attempt.queries >= capability.max_queries
        request = ReviewModelRequest(
            schema=TURN_SCHEMA, role=Role(spec.role).value, persona=spec.persona,
            stack_profile=spec.stack_profile, guidance_bundle_sha256=spec.guidance_bundle_sha256,
            guidance_text=spec.guidance_text, task_input=task_input, transcript=tuple(transcript),
            provider=spec.provider, model=spec.model, reasoning=spec.reasoning,
            max_input_tokens=spec.max_input_tokens, max_output_tokens=spec.max_output_tokens,
            repair_errors=repair_errors if turn_number == 1 else (), cell_id=cell_id)
        entry: dict[str, Any] = {"turn": turn_number, "request_sha256": sha256_hex(asdict(request)),
                                 "transcript_sha256": sha256_hex(transcript),
                                 "final_required": final_required, "action": None,
                                 "response_sha256": None, "input_tokens": 0, "output_tokens": 0,
                                 "retrievals": []}
        attempt.turns.append(entry)
        try:
            response = infer(request, timeout_seconds=spec.timeout_seconds)
        except IntegrityError:
            raise
        except CellBudgetExceeded as exc:
            attempt.end(CellStatus.TIMED_OUT, GapClass.BUDGET_GAP, f"cell_budget_exceeded:{exc.reason}")
            return attempt
        except ModelOutputError:
            attempt.end(CellStatus.INVALID, GapClass.SCHEMA_ERROR, "model_output_unparseable")
            attempt.repair_errors = (f"the reply was not exactly one {TURN_SCHEMA} object",)
            return attempt
        except (TimeoutError, subprocess.TimeoutExpired):
            attempt.end(CellStatus.TIMED_OUT, GapClass.WORKER_GAP, "provider_timeout")
            return attempt
        except Exception as exc:  # every provider failure is an ordinary cell gap
            attempt.end(CellStatus.FAILED, GapClass.WORKER_GAP, f"provider_error:{type(exc).__name__}")
            return attempt
        entry["input_tokens"] = int(response.input_tokens or 0)
        entry["output_tokens"] = int(response.output_tokens or 0)
        attempt.input_tokens += entry["input_tokens"]
        attempt.output_tokens += entry["output_tokens"]
        entry["response_sha256"] = sha256_hex(response.raw_response if response.raw_response is not None
                                              else _plain(response.proposal))
        turn, error = _parse_turn(response.proposal)
        if error:
            attempt.end(CellStatus.INVALID, GapClass.SCHEMA_ERROR, "malformed_turn")
            attempt.repair_errors = (error,)
            return attempt
        entry["action"] = turn["action"]
        if turn["action"] == "final":
            errors = _citation_errors(turn["result"], attempt.seen | citable_package)
            errors.extend(str(item)[:256] for item in validate_final(turn["result"]))
            if errors:
                attempt.end(CellStatus.INVALID, GapClass.SCHEMA_ERROR, "final_result_rejected")
                attempt.repair_errors = tuple(errors[:MAX_REPAIR_ERRORS])
                return attempt
            attempt.result = turn["result"]
            return attempt
        if final_required:
            attempt.end(CellStatus.TIMED_OUT, GapClass.BUDGET_GAP, "cap_reached_without_final")
            attempt.repair_errors = ("the cell's query or turn cap was reached; the next turn must be final",)
            return attempt
        responses = [_retrieve(spec, cell_id, attempt, capability, core, turn_number, index, item, entry)
                     for index, item in enumerate(turn["requests"])]
        transcript.append({"turn": turn_number, "from": "worker", "content": turn})
        transcript.append({
            "turn": turn_number, "from": "application", "responses": responses,
            "remaining_queries": max(0, capability.max_queries - attempt.queries),
            "remaining_turns": capability.max_turns - turn_number,
            "final_required": (turn_number + 1 == capability.max_turns or
                               attempt.queries >= capability.max_queries)})
    raise AssertionError("unreachable: the last permitted turn always ends the attempt")


def _retrieve(spec: CellSpec, cell_id: str, attempt: _Attempt, capability: CellCapability, core: Any,
              turn: int, index: int, request: Any, entry: dict[str, Any]) -> dict[str, Any]:
    decision = capability.authorize(request, queries_used=attempt.queries, granted=attempt.seen)
    tool = request.get("tool") if isinstance(request, Mapping) else None
    tool = tool if isinstance(tool, str) and tool in TOOL_SCHEMAS else "<unknown>"
    call: dict[str, Any] = {"index": index, "tool": tool, "filter_sha256": decision.filter_sha256}
    entry["retrievals"].append(call)
    if isinstance(decision, AuthorityDenied):
        attempt.denials += 1
        call.update(status="denied", denial_code=decision.code)
        attempt.gaps.append(_gap(cell_id, spec, attempt.number, f"{turn}/{index}",
                                 GapClass.AUTHORITY_ERROR, f"denied:{decision.code}"))
        attempt.security_events.append({
            "event": "REVIEW_CELL_AUTHORITY_DENIED", "cell_id": cell_id, "attempt": attempt.number,
            "turn": turn, "request_index": index, "tool": tool, "denial_code": decision.code,
            "filter_sha256": decision.filter_sha256,
            "capability_sha256": capability.capability_sha256})
        return {"index": index, "status": "denied", "code": decision.code, "reason": decision.reason}
    attempt.queries += 1
    try:
        response = getattr(core, decision.tool)(**dict(decision.parameters))
    except IntegrityError:
        raise
    except RetrievalIntegrityError as exc:
        raise IntegrityError(f"retrieval core integrity failure: {type(exc).__name__}") from exc
    except (RetrievalGap, ValueError, LookupError, OSError, RuntimeError, sqlite3.Error) as exc:
        call.update(status="tool_error", error_class=type(exc).__name__)
        attempt.gaps.append(_gap(cell_id, spec, attempt.number, f"{turn}/{index}",
                                 GapClass.COVERAGE_GAP, f"tool_error:{decision.tool}:{type(exc).__name__}"))
        return {"index": index, "status": "tool_error", "tool": decision.tool,
                "error_class": type(exc).__name__}
    granted: set[str] = set()
    bounded, withheld = _bound(decision.tool, response, capability, attempt.seen, granted)
    seen = {identity for identity in _identities(bounded["results"])
            if capability.entity_in_scope(identity) or identity in attempt.seen or identity in granted}
    attempt.seen |= seen
    call.update(status="executed", result_count=len(bounded["results"]), withheld_count=withheld,
                gap_count=len(bounded["coverage_gaps"]), truncated=bounded["truncated"],
                response_sha256=sha256_hex({key: value for key, value in _plain(response).items()
                                            if key not in _VOLATILE_RESPONSE_FIELDS}),
                bytes=len(json.dumps(bounded, sort_keys=True, default=str).encode()))
    return {"index": index, "status": "ok", **bounded}


def _bound(tool: str, response: Mapping[str, Any], capability: CellCapability,
           seen: set[str] | frozenset[str] = frozenset(), granted: set[str] | None = None
           ) -> tuple[dict[str, Any], int]:
    """Withhold out-of-scope rows and trim to the cell byte cap; identities are retained.

    A graph row of a granted CodeQL scope (``CellCapability.graph_row_in_scope``) is in scope, and its
    identity plus the graph-kind identities its payload references (facts and symbols of the same
    scope) are added to ``granted`` so the cell may address and cite them.
    """
    granted = set() if granted is None else granted
    rows = [_plain(row) for row in response.get("results", ()) or ()]
    for row in rows:
        _grant_graph_row(row, capability, granted)
        if isinstance(row, dict) and isinstance(row.get("entity"), dict):
            _grant_graph_row(row["entity"], capability, granted)
    known = set(seen) | granted
    kept: list[Any] = []
    withheld = 0
    for row in rows:
        scoped, dropped = _scope_row(tool, row, capability, known)
        withheld += dropped
        if scoped is not None:
            kept.append(scoped)
    manifest = response.get("index_manifest") if isinstance(response.get("index_manifest"), Mapping) else {}
    pagination = response.get("pagination") if isinstance(response.get("pagination"), Mapping) else {}
    bounded = {"tool": tool, "index_manifest_sha256": manifest.get("sha256"),
               "results": kept, "withheld_out_of_scope": withheld,
               "coverage_gaps": [str(item)[:256] for item in list(response.get("coverage_gaps", ()) or ())[:20]],
               "truncated": bool(response.get("truncated")),
               "next_cursor": pagination.get("next_cursor") if not withheld else None}
    while kept and len(json.dumps(bounded, sort_keys=True, default=str).encode()) > capability.max_result_bytes:
        kept.pop()
        bounded["truncated"] = True
        bounded["next_cursor"] = None
    return bounded, withheld


def _grant_graph_row(row: Any, capability: CellCapability, granted: set[str]) -> None:
    if not isinstance(row, dict) or not capability.graph_row_in_scope(row):
        return
    granted.add(row["identity"])
    granted.update(identity for identity in _identities(row.get("payload"))
                   if identity.split(":", 2)[1] in GRAPH_ROW_KINDS)


def _scope_row(tool: str, row: Any, capability: CellCapability,
               known: set[str] | frozenset[str] = frozenset()) -> tuple[Any, int]:
    if not isinstance(row, dict):
        return None, 1
    if tool == "resolve_evidence":
        dropped = 0
        entity = row.get("entity")
        if isinstance(entity, dict) and not _endpoints_in_scope(entity, capability, known):
            entity, dropped = None, 1
        relationships = [item for item in row.get("relationships", ()) or ()
                         if isinstance(item, dict) and _endpoints_in_scope(item, capability, known)]
        dropped += len(row.get("relationships", ()) or ()) - len(relationships)
        return {**row, "entity": entity, "relationships": relationships}, dropped
    return (row, 0) if _endpoints_in_scope(row, capability, known) else (None, 1)


def _endpoints_in_scope(row: Mapping[str, Any], capability: CellCapability,
                        known: set[str] | frozenset[str] = frozenset()) -> bool:
    return all(capability.entity_in_scope(row[key]) or row[key] in known
               for key in ("identity", "source_id", "target_id")
               if isinstance(row.get(key), str) and _LOGICAL_ID.fullmatch(row[key]))


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
            return {}, f"requests must be a list of 1 to {MAX_REQUESTS_PER_TURN} retrieval requests"
        return {"action": "retrieve", "requests": _plain(requests)}, None
    if action == "final" and set(turn) == {"action", "result"}:
        if not isinstance(turn["result"], Mapping):
            return {}, "a final result must be a JSON object"
        return {"action": "final", "result": _plain(turn["result"])}, None
    return {}, 'a turn is exactly {"action": "retrieve", "requests": [...]} or {"action": "final", "result": {...}}'


def _citation_errors(result: Any, citable: set[str]) -> list[str]:
    unseen = sorted(set(_identities(result)) - citable)
    return [f"cites {len(unseen)} identities not returned in this cell's transcript or package"] if unseen else []


def _identities(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        if _LOGICAL_ID.fullmatch(value):
            yield value
    elif isinstance(value, Mapping):
        for key, child in value.items():
            yield from _identities(key)
            yield from _identities(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _identities(child)


def _plain(value: Any) -> Any:
    """JSON-plain copy, so receipts and hashes never depend on mapping or tuple types."""
    return json.loads(json.dumps(value, default=str))


def _retryable(attempt: _Attempt, on_timeout: bool, on_provider: bool, on_invalid: bool) -> bool:
    if attempt.reason.startswith("cell_budget_exceeded:"):
        return False
    if attempt.status is CellStatus.TIMED_OUT:
        return on_timeout if attempt.gap_class is GapClass.WORKER_GAP else on_invalid
    if attempt.status is CellStatus.FAILED:
        return on_provider
    return attempt.status is CellStatus.INVALID and on_invalid


def _gap(cell_id: str, spec: CellSpec, attempt: int, position: str, gap_class: GapClass | None,
         reason: str) -> Gap:
    gap_class = gap_class or GapClass.WORKER_GAP
    return Gap(make_id("gap", 1, {"cell_id": cell_id, "attempt": attempt, "position": position,
                                  "gap_class": gap_class.value, "reason": reason}),
               gap_class, cell_id, reason[:256], round=spec.round)


def _record(spec: CellSpec, cell_id: str, status: CellStatus, attempts: int, gaps: Sequence[Gap],
            receipt: Path) -> CellRecord:
    return CellRecord(cell_id=cell_id, lane=Lane(spec.lane), package_id=spec.package_id,
                      role=Role(spec.role), persona=spec.persona, stack_profile=spec.stack_profile,
                      task=spec.task, claim_id=spec.claim_id, status=status, attempts=attempts,
                      gap_ids=tuple(sorted(gap.gap_id for gap in gaps)),
                      receipt_sha256=file_sha256(receipt))


def _attempt_numbers(cell_root: Path) -> list[int]:
    if not cell_root.is_dir():
        return []
    return [int(match.group(1)) for path in cell_root.iterdir()
            if (match := _ATTEMPT_FILE.fullmatch(path.name))]


def _write_receipt(cell_root: Path, spec: CellSpec, cell_id: str, capability: CellCapability,
                   attempt: _Attempt) -> Path:
    path = cell_root / f"attempt-{attempt.number}.json"
    if path.exists():
        raise IntegrityError("a cell attempt receipt already exists; attempts are never overwritten")
    gaps = list(attempt.gaps)
    if attempt.status is not CellStatus.SUCCEEDED:
        gaps.append(_gap(cell_id, spec, attempt.number, "terminal", attempt.gap_class, attempt.reason))
    atomic_json(path, {
        "schema": RECEIPT_SCHEMA, "cell_id": cell_id, "attempt": attempt.number,
        "attempt_id": f"{cell_id}/attempt-{attempt.number}",
        "executor_version": EXECUTOR_VERSION, "validator_version": spec.validator_version,
        "capability_sha256": capability.capability_sha256,
        "guidance_bundle_sha256": spec.guidance_bundle_sha256,
        "provider": spec.provider, "model": spec.model,
        "status": attempt.status.value,
        "gap_class": attempt.gap_class.value if attempt.gap_class else None,
        "reason": attempt.reason or None,
        "turns": attempt.turns,
        "counts": {"turns": len(attempt.turns), "queries": attempt.queries, "denials": attempt.denials,
                   "input_tokens": attempt.input_tokens, "output_tokens": attempt.output_tokens},
        "gaps": [{"gap_id": gap.gap_id, "gap_class": gap.gap_class.value, "reason": gap.reason}
                 for gap in gaps],
        "security_events": attempt.security_events,
        "seen_identities": sorted(attempt.seen),
        "result": attempt.result,
        "result_sha256": sha256_hex(attempt.result) if attempt.result is not None else None,
    })
    return path


_RECEIPT_KEYS = frozenset({"schema", "cell_id", "attempt", "attempt_id", "executor_version",
                           "validator_version", "capability_sha256", "guidance_bundle_sha256",
                           "provider", "model", "status", "gap_class", "reason", "turns", "counts",
                           "gaps", "security_events", "seen_identities", "result", "result_sha256"})


def _load_receipt(path: Path, cell_id: str, number: int) -> Mapping[str, Any]:
    """A receipt that cannot be verified is an integrity failure, never a cache miss."""
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cell receipt is unreadable: {path.name}") from exc
    if not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS or \
            receipt["schema"] != RECEIPT_SCHEMA or receipt["cell_id"] != cell_id or \
            receipt["attempt"] != number:
        raise IntegrityError(f"cell receipt does not match its fingerprint: {path.name}")
    if receipt["status"] == CellStatus.SUCCEEDED.value and (
            not isinstance(receipt["result"], dict) or receipt["result_sha256"] != sha256_hex(receipt["result"])):
        raise IntegrityError(f"cell receipt result hash mismatch: {path.name}")
    return receipt


__all__ = ["CellBudgetExceeded", "CellOutcome", "CellSpec", "EXECUTOR_VERSION", "RECEIPT_SCHEMA", "TURN_SCHEMA",
           "cell_fingerprint", "reuse_or_run", "run_cell"]
