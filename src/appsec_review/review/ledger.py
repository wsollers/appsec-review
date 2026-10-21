"""Append-only, hash-chained claim ledger, canonical shard merge, and pure projection (design R8).

Each unit appends events to one in-memory stream and seals it once as an immutable JSONL shard.
Every event carries ``sequence``, ``prev_event_sha256`` and ``event_id``. Merging verifies every
chain and sorts events by (claim id, kind order, subject id, round, content hash). The ledger head
is the SHA-256 of the canonical content list, so it does not depend on shard enumeration or on the
order in which a unit appended its events.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from enum import StrEnum
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.models import (
    Admissibility, CellRecord, CellStatus, Claim, ClaimState, EvidenceRelation, Gap, GapClass,
    IntegrityError, JudgePredicateVerdict, JudgeVerdict, JudgeVerdictValue, Lane, Predicate, RelationKind, Role,
    SecurityPredicate,
)
from appsec_review.storage.atomic import atomic_bytes, canonical_json

EVENT_SCHEMA = "appsec-review/ledger-event/1"
CLAIM_SCHEMA = "appsec-review/claim/1"
RELATION_SCHEMA = "appsec-review/evidence-relation/1"
GAP_SCHEMA = "appsec-review/gap/1"
CELL_SCHEMA = "appsec-review/cell-record/1"
MAX_REASON = 2000


class EventKind(StrEnum):
    """Closed event kinds; declaration order is the canonical merge order within a claim."""

    CLAIM_PROPOSED = "claim_proposed"
    RELATION_ADDED = "relation_added"
    EVIDENCE_REQUEST_OPENED = "evidence_request_opened"
    EVIDENCE_REQUEST_CLOSED = "evidence_request_closed"
    DUPLICATE_MARKED = "duplicate_marked"
    STATE_TRANSITION = "state_transition"
    GAP_RECORDED = "gap_recorded"
    CELL_TERMINAL = "cell_terminal"
    JUDGE_VERDICT = "judge_verdict"


class EvidenceRequestOutcome(StrEnum):
    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    SUPERSEDED = "superseded"
    WITHDRAWN = "withdrawn"


KIND_ORDER = {kind: index for index, kind in enumerate(EventKind)}
_S = ClaimState
LEGAL_TRANSITIONS: Mapping[ClaimState, frozenset[ClaimState]] = {
    _S.PROPOSED: frozenset({_S.DUPLICATE, _S.OUT_OF_SCOPE, _S.COVERAGE_GAP, _S.CONTRADICTED,
                            _S.INSUFFICIENT_EVIDENCE, _S.SUPPORTED}),
    _S.SUPPORTED: frozenset({_S.CONFIRMED, _S.CONTRADICTED, _S.NOT_REACHABLE,
                             _S.NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION, _S.INSUFFICIENT_EVIDENCE}),
    _S.CONFIRMED: frozenset({_S.SUPPORTED, _S.CONTRADICTED, _S.NOT_REACHABLE,
                             _S.NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION}),
}


def check_transition(from_state: ClaimState, to_state: ClaimState) -> None:
    if to_state not in LEGAL_TRANSITIONS.get(from_state, frozenset()):
        raise IntegrityError(f"illegal claim transition {from_state} -> {to_state}")


# Record <-> JSON. Enum members serialize as their values; tuples as arrays.

def claim_json(claim: Claim) -> dict[str, Any]:
    return {"schema": CLAIM_SCHEMA, "claim_id": claim.claim_id, "lane": claim.lane.value,
            "package_id": claim.package_id, "affected_entities": list(claim.affected_entities),
            "weakness_cwe": claim.weakness_cwe, "security_predicate": SecurityPredicate(claim.security_predicate).value,
            "preconditions": list(claim.preconditions), "statement": claim.statement,
            "state": claim.state.value, "duplicate_of": claim.duplicate_of,
            "origin_cell_ids": list(claim.origin_cell_ids)}


def claim_from_json(value: Mapping[str, Any]) -> Claim:
    return Claim(claim_id=value["claim_id"], lane=Lane(value["lane"]), package_id=value["package_id"],
                 affected_entities=tuple(value["affected_entities"]), weakness_cwe=value["weakness_cwe"],
                 security_predicate=SecurityPredicate(value["security_predicate"]), preconditions=tuple(value["preconditions"]),
                 statement=value["statement"], state=ClaimState(value["state"]),
                 duplicate_of=value["duplicate_of"], origin_cell_ids=tuple(value["origin_cell_ids"]))


def relation_json(relation: EvidenceRelation) -> dict[str, Any]:
    document = {"schema": RELATION_SCHEMA, "relation_id": relation.relation_id, "claim_id": relation.claim_id,
                "predicate": relation.predicate.value, "kind": relation.kind.value,
                "entity_id": relation.entity_id, "entity_kind": relation.entity_kind,
                "admissibility": relation.admissibility.value, "shard_id": relation.shard_id,
                "content_sha256": relation.content_sha256, "locator": relation.locator,
                "complete": relation.complete, "producing_cell_id": relation.producing_cell_id,
                "retrieval_receipt_sha256": relation.retrieval_receipt_sha256, "reason": relation.reason}
    if relation.provenance is not None:          # present only on relations derived from a judge's citations
        document["provenance"] = relation.provenance
    return document


def relation_from_json(value: Mapping[str, Any]) -> EvidenceRelation:
    return EvidenceRelation(
        relation_id=value["relation_id"], claim_id=value["claim_id"], predicate=Predicate(value["predicate"]),
        kind=RelationKind(value["kind"]), entity_id=value["entity_id"], entity_kind=value["entity_kind"],
        admissibility=Admissibility(value["admissibility"]), shard_id=value["shard_id"],
        content_sha256=value["content_sha256"], locator=value["locator"], complete=value["complete"],
        producing_cell_id=value["producing_cell_id"], retrieval_receipt_sha256=value["retrieval_receipt_sha256"],
        reason=value.get("reason"),
        provenance=value.get("provenance"))


def gap_json(gap: Gap) -> dict[str, Any]:
    return {"schema": GAP_SCHEMA, "gap_id": gap.gap_id, "gap_class": gap.gap_class.value,
            "subject_id": gap.subject_id, "reason": gap.reason,
            "predicate": gap.predicate.value if gap.predicate else None, "round": gap.round}


def gap_from_json(value: Mapping[str, Any]) -> Gap:
    predicate = value["predicate"]
    return Gap(gap_id=value["gap_id"], gap_class=GapClass(value["gap_class"]), subject_id=value["subject_id"],
               reason=value["reason"], predicate=Predicate(predicate) if predicate else None,
               round=value["round"])


def cell_json(cell: CellRecord) -> dict[str, Any]:
    document = {"schema": CELL_SCHEMA, "cell_id": cell.cell_id, "lane": cell.lane.value,
                "package_id": cell.package_id, "role": cell.role.value, "persona": cell.persona,
                "stack_profile": cell.stack_profile, "task": cell.task, "claim_id": cell.claim_id,
                "status": cell.status.value, "attempts": cell.attempts, "gap_ids": list(cell.gap_ids),
                "receipt_sha256": cell.receipt_sha256}
    if cell.side_map is not None:                # judge cells only
        document["side_map"] = dict(cell.side_map)
    return document


def cell_from_json(value: Mapping[str, Any]) -> CellRecord:
    side_map = value.get("side_map")
    return CellRecord(cell_id=value["cell_id"], lane=Lane(value["lane"]), package_id=value["package_id"],
                      role=Role(value["role"]), persona=value["persona"], stack_profile=value["stack_profile"],
                      task=value["task"], claim_id=value["claim_id"], status=CellStatus(value["status"]),
                      attempts=value["attempts"], gap_ids=tuple(value["gap_ids"]),
                      receipt_sha256=value["receipt_sha256"],
                      side_map=tuple(sorted(side_map.items())) if side_map is not None else None)


def judge_verdict_json(verdict: JudgeVerdict) -> dict[str, Any]:
    return {"verdict_id": verdict.verdict_id, "claim_id": verdict.claim_id, "verdict": verdict.verdict.value,
            "per_predicate": [{"predicate": item.predicate.value, "verdict": item.verdict.value,
                               "cites": list(item.cites)} for item in verdict.per_predicate],
            "citations": sorted({ref for item in verdict.per_predicate for ref in item.cites}),
            "reason": verdict.reason, "cell_id": verdict.cell_id,
            "judge_model_distinct": verdict.judge_model_distinct}


def judge_verdict_from_json(value: Mapping[str, Any]) -> JudgeVerdict:
    return JudgeVerdict(
        verdict_id=value["verdict_id"], claim_id=value["claim_id"], verdict=JudgeVerdictValue(value["verdict"]),
        per_predicate=tuple(JudgePredicateVerdict(Predicate(item["predicate"]), JudgeVerdictValue(item["verdict"]),
                                                  tuple(item["cites"])) for item in value["per_predicate"]),
        reason=value["reason"], cell_id=value["cell_id"], judge_model_distinct=bool(value["judge_model_distinct"]))


# Events.

def event_sha256(event: Mapping[str, Any]) -> str:
    return sha256_hex(dict(event))


def _event_id(stream: str, sequence: int, prev: str | None, kind: str, subject_id: str,
              body: Mapping[str, Any]) -> str:
    return make_id("event", 1, {"stream": stream, "sequence": sequence, "prev_event_sha256": prev,
                                "kind": kind, "subject_id": subject_id, "body": dict(body)})


def _plain(value: Any) -> Any:
    return json.loads(canonical_json(value))


def _bounded(reason: str) -> str:
    if not isinstance(reason, str) or len(reason) > MAX_REASON:
        raise ValueError("reason must be a string of at most 2000 characters")
    return reason


@dataclass(frozen=True, slots=True)
class ShardReceipt:
    path: str
    stream: str
    event_count: int
    head_event_sha256: str | None
    content_sha256: str


class LedgerWriter:
    """Builds one unit's hash-chained event stream and seals it once as an immutable JSONL shard."""

    def __init__(self, path: Path, stream: str) -> None:
        if not stream or len(stream) > 200:
            raise ValueError("stream must be 1..200 characters")
        self.path, self.stream = Path(path), stream
        self._events: list[dict[str, Any]] = []
        self._sealed: ShardReceipt | None = None

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    def append(self, kind: EventKind | str, subject_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if self._sealed is not None:
            raise IntegrityError("ledger shard is sealed")
        kind = EventKind(kind)
        if not subject_id:
            raise ValueError("subject_id is required")
        body = _plain(dict(body))
        sequence = len(self._events)
        prev = event_sha256(self._events[-1]) if self._events else None
        event = {"schema": EVENT_SCHEMA, "stream": self.stream, "sequence": sequence,
                 "prev_event_sha256": prev, "kind": kind.value, "subject_id": subject_id, "body": body,
                 "event_id": _event_id(self.stream, sequence, prev, kind.value, subject_id, body)}
        self._events.append(event)
        return event

    def propose_claim(self, claim: Claim, *, round: int = 0) -> dict[str, Any]:
        if claim.state is not ClaimState.PROPOSED or claim.duplicate_of is not None:
            raise IntegrityError("a claim enters the ledger only as proposed")
        return self.append(EventKind.CLAIM_PROPOSED, claim.claim_id, {"claim": claim_json(claim), "round": round})

    def add_relation(self, relation: EvidenceRelation, *, round: int = 0) -> dict[str, Any]:
        return self.append(EventKind.RELATION_ADDED, relation.relation_id,
                           {"relation": relation_json(relation), "round": round})

    def transition(self, claim_id: str, from_state: ClaimState, to_state: ClaimState, *, reason: str,
                   round: int = 0, adjudication_id: str | None = None) -> dict[str, Any]:
        if to_state is ClaimState.DUPLICATE:
            raise IntegrityError("duplicate state is entered only through mark_duplicate")
        check_transition(from_state, to_state)
        return self.append(EventKind.STATE_TRANSITION, claim_id, {
            "from_state": from_state.value, "to_state": to_state.value, "reason": _bounded(reason),
            "round": round, "adjudication_id": adjudication_id})

    def mark_duplicate(self, claim_id: str, duplicate_of: str, *, reason: str, round: int = 0) -> dict[str, Any]:
        if claim_id == duplicate_of:
            raise IntegrityError("a claim cannot duplicate itself")
        return self.append(EventKind.DUPLICATE_MARKED, claim_id,
                           {"duplicate_of": duplicate_of, "reason": _bounded(reason), "round": round})

    def open_request(self, request_id: str, claim_id: str, predicate: Predicate, requested_kind: str, *,
                     round: int = 0, origin_cell_id: str | None = None) -> dict[str, Any]:
        return self.append(EventKind.EVIDENCE_REQUEST_OPENED, request_id, {
            "claim_id": claim_id, "predicate": Predicate(predicate).value, "requested_kind": requested_kind,
            "round": round, "origin_cell_id": origin_cell_id})

    def close_request(self, request_id: str, claim_id: str, outcome: EvidenceRequestOutcome, *, reason: str,
                      round: int = 0) -> dict[str, Any]:
        return self.append(EventKind.EVIDENCE_REQUEST_CLOSED, request_id, {
            "claim_id": claim_id, "outcome": EvidenceRequestOutcome(outcome).value,
            "reason": _bounded(reason), "round": round})

    def record_gap(self, gap: Gap) -> dict[str, Any]:
        return self.append(EventKind.GAP_RECORDED, gap.gap_id, {"gap": gap_json(gap)})

    def cell_terminal(self, cell: CellRecord) -> dict[str, Any]:
        return self.append(EventKind.CELL_TERMINAL, cell.cell_id, {"cell": cell_json(cell)})

    def judge_verdict(self, verdict: JudgeVerdict, *, round: int = 0) -> dict[str, Any]:
        """Record a judge's verdict. It is a proposal and a routing signal; no claim state follows from it."""
        return self.append(EventKind.JUDGE_VERDICT, verdict.verdict_id,
                           {"verdict": judge_verdict_json(verdict), "round": round})

    def seal(self) -> ShardReceipt:
        """Write the shard once. Re-sealing identical bytes is idempotent; differing bytes are not."""
        if self._sealed is not None:
            return self._sealed
        payload = b"".join(canonical_json(event) for event in self._events)
        if self.path.exists():
            if self.path.read_bytes() != payload:
                raise IntegrityError(f"ledger shard already exists with different content: {self.path}")
        else:
            atomic_bytes(self.path, payload)
        self._sealed = ShardReceipt(str(self.path), self.stream, len(self._events),
                                    event_sha256(self._events[-1]) if self._events else None,
                                    sha256_hex([event for event in self._events]))
        return self._sealed


def verify_events(events: Sequence[Mapping[str, Any]], *, expected_head: str | None = None) -> None:
    stream, prev = None, None
    for index, event in enumerate(events):
        if not isinstance(event, Mapping) or set(event) != {
                "schema", "stream", "sequence", "prev_event_sha256", "event_id", "kind", "subject_id", "body"}:
            raise IntegrityError(f"ledger event {index} has an invalid shape")
        if event["schema"] != EVENT_SCHEMA:
            raise IntegrityError(f"ledger event {index} has an unknown schema")
        stream = event["stream"] if stream is None else stream
        if event["stream"] != stream:
            raise IntegrityError(f"ledger event {index} changes stream")
        if event["sequence"] != index:
            raise IntegrityError(f"ledger event {index} is out of sequence")
        if event["prev_event_sha256"] != prev:
            raise IntegrityError(f"ledger event {index} breaks the hash chain")
        try:
            EventKind(event["kind"])
        except ValueError as exc:
            raise IntegrityError(f"ledger event {index} has an unknown kind") from exc
        if not isinstance(event["body"], dict) or not isinstance(event["subject_id"], str):
            raise IntegrityError(f"ledger event {index} has an invalid body or subject")
        if event["event_id"] != _event_id(stream, index, prev, event["kind"], event["subject_id"], event["body"]):
            raise IntegrityError(f"ledger event {index} identity does not match its content")
        prev = event_sha256(event)
    if expected_head is not None and prev != expected_head:
        raise IntegrityError("ledger shard head does not match the expected head")


def verify_chain(path: Path, *, expected_head: str | None = None) -> tuple[dict[str, Any], ...]:
    """Re-read a shard from bytes and verify canonical encoding, sequence, chain, and identities."""
    events: list[dict[str, Any]] = []
    raw = Path(path).read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise IntegrityError(f"ledger shard is truncated: {path}")
    for index, line in enumerate(raw.splitlines(keepends=True)):
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"ledger event {index} is not JSON: {path}") from exc
        if not isinstance(event, dict) or canonical_json(event) != line:
            raise IntegrityError(f"ledger event {index} is not canonical: {path}")
        events.append(event)
    verify_events(events, expected_head=expected_head)
    return tuple(events)


# Canonical merge.

def event_content(event: Mapping[str, Any]) -> dict[str, Any]:
    """The order-independent part of an event: chain metadata is excluded."""
    return {"stream": event["stream"], "kind": event["kind"], "subject_id": event["subject_id"],
            "body": event["body"]}


def _claim_key(event: Mapping[str, Any]) -> str:
    kind, body = EventKind(event["kind"]), event["body"]
    if kind in (EventKind.CLAIM_PROPOSED, EventKind.STATE_TRANSITION, EventKind.DUPLICATE_MARKED):
        return event["subject_id"]
    if kind is EventKind.RELATION_ADDED:
        return body["relation"]["claim_id"]
    if kind in (EventKind.EVIDENCE_REQUEST_OPENED, EventKind.EVIDENCE_REQUEST_CLOSED):
        return body["claim_id"]
    if kind is EventKind.GAP_RECORDED:
        subject = body["gap"]["subject_id"]
        return subject if subject.startswith("claim-") else ""
    if kind is EventKind.JUDGE_VERDICT:
        return body["verdict"]["claim_id"]
    return body["cell"]["claim_id"] or ""


def _round(event: Mapping[str, Any]) -> int:
    body = event["body"]
    if event["kind"] == EventKind.GAP_RECORDED:
        return body["gap"]["round"]
    return body.get("round", 0)


def canonical_key(event: Mapping[str, Any]) -> tuple[str, int, str, int, str]:
    return (_claim_key(event), KIND_ORDER[EventKind(event["kind"])], event["subject_id"], _round(event),
            sha256_hex(event_content(event)))


def ledger_head(events: Iterable[Mapping[str, Any]]) -> str:
    return sha256_hex([event_content(event) for event in sorted(events, key=canonical_key)])


@dataclass(frozen=True, slots=True)
class MergedLedger:
    events: tuple[dict[str, Any], ...]   # full events in canonical order
    head: str
    streams: tuple[str, ...]


def merge_shards(paths: Iterable[Path]) -> MergedLedger:
    """Verify every shard and merge in canonical order, independent of shard enumeration order."""
    events: list[dict[str, Any]] = []
    streams: set[str] = set()
    for path in paths:
        shard = verify_chain(path)
        if not shard:
            continue
        if shard[0]["stream"] in streams:
            raise IntegrityError(f"ledger stream appears in more than one shard: {shard[0]['stream']}")
        streams.add(shard[0]["stream"])
        events.extend(shard)
    try:
        ordered = tuple(sorted(events, key=canonical_key))
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityError("ledger event body is malformed") from exc
    return MergedLedger(ordered, ledger_head(ordered), tuple(sorted(streams)))


# Projection.

@dataclass(frozen=True, slots=True)
class StateChange:
    from_state: ClaimState
    to_state: ClaimState
    round: int
    reason: str
    event_content_sha256: str        # order-independent; event ids depend on stream position
    adjudication_id: str | None = None


@dataclass(frozen=True, slots=True)
class ClaimView:
    claim: Claim                         # current state and duplicate_of
    history: tuple[StateChange, ...]
    proposal_sha256s: tuple[str, ...]
    # Lane of every proposal of this claim id, sorted; more than one entry means duplicate proposals
    # that merged into this claim (lead lane wins, then lowest package_id).
    proposal_lanes: tuple[Lane, ...] = ()

    @property
    def duplicate_proposals(self) -> dict[Lane, int]:
        """Proposals beyond the canonical one, counted by the lane that made them."""
        counts = {lane: 0 for lane in Lane}
        remaining = list(self.proposal_lanes)
        if self.claim.lane in remaining:
            remaining.remove(self.claim.lane)
        for lane in remaining:
            counts[lane] += 1
        return counts


@dataclass(frozen=True, slots=True)
class EvidenceRequestView:
    request_id: str
    claim_id: str
    predicate: Predicate | None
    requested_kind: str | None
    opened: int                          # number of open events
    outcomes: tuple[EvidenceRequestOutcome, ...]


@dataclass(frozen=True, slots=True)
class Projection:
    head: str
    claims: Mapping[str, ClaimView]
    relations: Mapping[str, tuple[EvidenceRelation, ...]]
    gaps: tuple[Gap, ...]
    cells: Mapping[str, tuple[CellRecord, ...]]
    evidence_requests: Mapping[str, EvidenceRequestView] = field(default_factory=dict)
    # claim id -> its judge verdicts, ordered by verdict id (review-judge-and-poc.md section 3.4).
    judge_verdicts: Mapping[str, tuple[JudgeVerdict, ...]] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        document = self._base_json()
        if self.judge_verdicts:               # a review without a judge projects exactly as before
            document["judge_verdicts"] = {claim_id: [judge_verdict_json(item) for item in items]
                                          for claim_id, items in sorted(self.judge_verdicts.items())}
        return document

    def _base_json(self) -> dict[str, Any]:
        return {
            "schema": "appsec-review/claim-projection/1", "ledger_head_sha256": self.head,
            "claims": [{**claim_json(view.claim), "state_history": [
                {"from_state": change.from_state.value, "to_state": change.to_state.value, "round": change.round,
                 "reason": change.reason, "event_content_sha256": change.event_content_sha256,
                 "adjudication_id": change.adjudication_id}
                for change in view.history]} for _, view in sorted(self.claims.items())],
            "relations": {claim_id: [relation_json(item) for item in items]
                          for claim_id, items in sorted(self.relations.items())},
            "gaps": [gap_json(gap) for gap in self.gaps],
            "cells": {cell_id: [cell_json(item) for item in items] for cell_id, items in sorted(self.cells.items())},
            "evidence_requests": [{"request_id": view.request_id, "claim_id": view.claim_id,
                                   "predicate": view.predicate.value if view.predicate else None,
                                   "requested_kind": view.requested_kind, "opened": view.opened,
                                   "outcomes": [outcome.value for outcome in view.outcomes]}
                                  for _, view in sorted(self.evidence_requests.items())],
        }

    def sha256(self) -> str:
        return sha256_hex(self.to_json())


_IDENTITY_FIELDS = ("affected_entities", "weakness_cwe", "security_predicate", "preconditions")
_LANE_ORDER = {lane: index for index, lane in enumerate(Lane)}


def _merge_proposals(proposals: list[tuple[Claim, str]]) -> tuple[Claim, tuple[str, ...]]:
    first = proposals[0][0]
    for claim, _ in proposals[1:]:
        if any(getattr(claim, name) != getattr(first, name) for name in _IDENTITY_FIELDS):
            raise IntegrityError(f"claim identity collision with unequal content: {first.claim_id}")
    canonical = min((claim for claim, _ in proposals),
                    key=lambda claim: (_LANE_ORDER[claim.lane], claim.package_id, claim.statement))
    cells = tuple(sorted({cell for claim, _ in proposals for cell in claim.origin_cell_ids}))
    return replace(canonical, origin_cell_ids=cells), tuple(sorted(digest for _, digest in proposals))


def _walk(claim_id: str, transitions: list[tuple[int, ClaimState, ClaimState, str | None, dict[str, Any]]]
          ) -> tuple[ClaimState, str | None, tuple[StateChange, ...]]:
    """Apply transitions round by round, following from_state; order-independent and strict."""
    state, duplicate_of, history = ClaimState.PROPOSED, None, []
    by_round: dict[int, list] = defaultdict(list)
    for item in transitions:
        by_round[item[0]].append(item)
    for round_ in sorted(by_round):
        pending = by_round[round_]
        while pending:
            matches = [item for item in pending if item[1] is state]
            if not matches:
                raise IntegrityError(f"claim {claim_id} has a transition that does not follow state {state}")
            if len({(item[2], item[3]) for item in matches}) > 1:
                raise IntegrityError(f"claim {claim_id} has ambiguous transitions from {state}")
            item = min(matches, key=lambda candidate: sha256_hex(event_content(candidate[4])))
            pending.remove(item)
            check_transition(state, item[2])
            state, event = item[2], item[4]
            if state is ClaimState.DUPLICATE:
                duplicate_of = item[3]
            elif duplicate_of is not None:
                raise IntegrityError(f"duplicate claim {claim_id} cannot transition further")
            history.append(StateChange(item[1], item[2], round_, event["body"]["reason"],
                                       sha256_hex(event_content(event)), event["body"].get("adjudication_id")))
    return state, duplicate_of, tuple(history)


def project(events: Iterable[Mapping[str, Any]]) -> Projection:
    """Pure deterministic projection of ledger events; the input order does not matter."""
    try:
        ordered = sorted(events, key=canonical_key)
        proposals: dict[str, list[tuple[Claim, str]]] = defaultdict(list)
        transitions: dict[str, list] = defaultdict(list)
        relations: dict[str, EvidenceRelation] = {}
        gaps: dict[str, Gap] = {}
        cells: dict[str, list[CellRecord]] = defaultdict(list)
        opened: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        closed: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        verdicts: dict[str, JudgeVerdict] = {}
        for event in ordered:
            kind, subject, body = EventKind(event["kind"]), event["subject_id"], event["body"]
            if kind is EventKind.CLAIM_PROPOSED:
                claim = claim_from_json(body["claim"])
                if claim.claim_id != subject or claim.state is not ClaimState.PROPOSED or claim.duplicate_of:
                    raise IntegrityError(f"claim proposal {subject} is not a proposed claim")
                proposals[subject].append((claim, sha256_hex(event_content(event))))
            elif kind is EventKind.STATE_TRANSITION:
                to_state = ClaimState(body["to_state"])
                if to_state is ClaimState.DUPLICATE:
                    raise IntegrityError("duplicate state is entered only through duplicate_marked")
                transitions[subject].append((body["round"], ClaimState(body["from_state"]), to_state, None, event))
            elif kind is EventKind.DUPLICATE_MARKED:
                if body["duplicate_of"] == subject:
                    raise IntegrityError(f"claim {subject} duplicates itself")
                transitions[subject].append((body["round"], ClaimState.PROPOSED, ClaimState.DUPLICATE,
                                             body["duplicate_of"], event))
            elif kind is EventKind.RELATION_ADDED:
                relation = relation_from_json(body["relation"])
                if relation.relation_id != subject or relations.get(subject, relation) != relation:
                    raise IntegrityError(f"evidence relation identity collision: {subject}")
                relations[subject] = relation
            elif kind is EventKind.GAP_RECORDED:
                gap = gap_from_json(body["gap"])
                if gap.gap_id != subject or gaps.get(subject, gap) != gap:
                    raise IntegrityError(f"gap identity collision: {subject}")
                gaps[subject] = gap
            elif kind is EventKind.CELL_TERMINAL:
                cell = cell_from_json(body["cell"])
                if cell.cell_id != subject:
                    raise IntegrityError(f"cell record does not match its subject: {subject}")
                cells[subject].append(cell)
            elif kind is EventKind.EVIDENCE_REQUEST_OPENED:
                opened[subject].append(body)
            elif kind is EventKind.JUDGE_VERDICT:
                verdict = judge_verdict_from_json(body["verdict"])
                if verdict.verdict_id != subject or verdicts.get(subject, verdict) != verdict:
                    raise IntegrityError(f"judge verdict identity collision: {subject}")
                verdicts[subject] = verdict
            else:
                EvidenceRequestOutcome(body["outcome"])
                closed[subject].append(body)
    except (KeyError, TypeError, ValueError) as exc:
        raise IntegrityError(f"ledger event body is malformed: {exc}") from exc

    claims: dict[str, ClaimView] = {}
    for claim_id, items in proposals.items():
        claim, event_ids = _merge_proposals(items)
        state, duplicate_of, history = _walk(claim_id, transitions.pop(claim_id, []))
        claims[claim_id] = ClaimView(replace(claim, state=state, duplicate_of=duplicate_of), history, event_ids,
                                     tuple(sorted((item.lane for item, _ in items), key=_LANE_ORDER.__getitem__)))
    if transitions:
        raise IntegrityError(f"state transition for unknown claim: {sorted(transitions)[0]}")
    by_claim: dict[str, list[EvidenceRelation]] = defaultdict(list)
    for relation in relations.values():
        if relation.claim_id not in claims:
            raise IntegrityError(f"evidence relation for unknown claim: {relation.relation_id}")
        by_claim[relation.claim_id].append(relation)
    judged: dict[str, list[JudgeVerdict]] = defaultdict(list)
    for verdict in verdicts.values():
        if verdict.claim_id not in claims:
            raise IntegrityError(f"judge verdict for unknown claim: {verdict.verdict_id}")
        judged[verdict.claim_id].append(verdict)
    requests: dict[str, EvidenceRequestView] = {}
    for request_id in sorted(set(opened) | set(closed)):
        first = (opened.get(request_id) or closed[request_id])[0]
        if any(body["claim_id"] != first["claim_id"] for body in opened[request_id] + closed[request_id]):
            raise IntegrityError(f"evidence request changes claim: {request_id}")
        if first["claim_id"] not in claims:
            raise IntegrityError(f"evidence request for unknown claim: {request_id}")
        source = opened[request_id][0] if opened.get(request_id) else None
        requests[request_id] = EvidenceRequestView(
            request_id, first["claim_id"], Predicate(source["predicate"]) if source else None,
            source["requested_kind"] if source else None, len(opened.get(request_id, ())),
            tuple(sorted(EvidenceRequestOutcome(body["outcome"]) for body in closed.get(request_id, ()))))
    return Projection(
        head=ledger_head(ordered),
        claims=dict(sorted(claims.items())),
        relations={claim_id: tuple(sorted(items, key=lambda item: item.relation_id))
                   for claim_id, items in sorted(by_claim.items())},
        gaps=tuple(sorted(gaps.values(), key=lambda gap: gap.gap_id)),
        cells={cell_id: tuple(sorted(items, key=lambda item: sha256_hex(cell_json(item))))
               for cell_id, items in sorted(cells.items())},
        evidence_requests=requests,
        judge_verdicts={claim_id: tuple(sorted(items, key=lambda item: item.verdict_id))
                        for claim_id, items in sorted(judged.items())},
    )


def state_counts(projection: Projection) -> Counter[ClaimState]:
    return Counter(view.claim.state for view in projection.claims.values())
