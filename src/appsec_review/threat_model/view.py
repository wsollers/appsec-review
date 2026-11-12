"""The one interface lanes read accepted evidence through (T-107).

A lane never opens a shard, a handoff or the target tree. It asks an ``EvidenceView`` bounded
questions; the job supplies a view over the attempt's admitted inputs, tests supply an in-memory
one. ``open_input`` turns an input's state into the ledger row and gaps of the design's gap table,
so every lane reports absence the same way.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.threat_model.contract import EvidenceRecord, InputLedgerRow, InputState


@dataclass(frozen=True, slots=True)
class InputStatus:
    """What the claim says about one declared input before any record is read."""
    state: InputState
    handoff_sha256: str | None = None
    coverage_disposition: str | None = None
    upstream_gap_count: int = 0


@dataclass(frozen=True, slots=True)
class Page:
    """A bounded answer. ``truncated`` means more records exist than ``limit`` allowed."""
    records: tuple[EvidenceRecord, ...] = ()
    truncated: bool = False


class EvidenceView(Protocol):
    def input_status(self, producer: str, output_kind: str) -> InputStatus:
        """State of a declared input; never raises for an absent optional producer."""

    def entities(self, producer: str, output_kind: str, kind: str, *, limit: int) -> Page:
        """Entities of one kind published by one producer output, in entity-id order."""

    def search_calls(self, name: str, *, limit: int) -> Page:
        """Tree-sitter ``call_expression`` nodes whose written callee name is exactly ``name``."""


@dataclass(frozen=True, slots=True)
class OpenedInput:
    readable: bool
    row: InputLedgerRow
    gaps: tuple[Mapping[str, Any], ...]


# No input gap is retryable. ``retryable`` asks whether running THIS job again could close the gap,
# and the runtime never reuses an accepted attempt that has a retryable gap. An absent, empty or
# partial input is closed only by its producer publishing a new accepted handoff, which changes a
# pinned upstream digest and reruns this job by itself; rerunning over the same pins repeats the gap.
_UNREADABLE = {
    InputState.ABSENT: "has no accepted handoff in this attempt's claim",
    InputState.DISABLED: "is disabled in configuration",
    InputState.NOT_REGISTERED: "producer is not registered",
}


def open_input(view: EvidenceView, producer: str, output_kind: str, *, unit_id: str) -> OpenedInput:
    """The ledger row and gaps for one input; ``readable`` says whether records may be asked for."""
    status = view.input_status(producer, output_kind)
    scope = f"{producer}/{output_kind}"
    row = InputLedgerRow(producer, output_kind, status.state, status.handoff_sha256,
                         status.coverage_disposition, status.upstream_gap_count)
    if status.state in _UNREADABLE:
        return OpenedInput(False, row, (producer_gap(
            GapCode.INPUT_UNAVAILABLE, f"{scope} {_UNREADABLE[status.state]}", unit_id=unit_id,
            scope_id=producer),))
    if status.state is InputState.EMPTY:
        return OpenedInput(False, row, (producer_gap(
            GapCode.OUTPUT_MISSING, f"{scope} was declared but nothing was published", unit_id=unit_id,
            scope_id=scope),))
    if status.state is InputState.PARTIAL:
        return OpenedInput(True, row, (producer_gap(
            GapCode.PRODUCER_REPORTED_GAP,
            f"{scope} was accepted with {status.upstream_gap_count} upstream gaps "
            f"(coverage {status.coverage_disposition or 'unstated'})",
            unit_id=unit_id, scope_id=scope),))
    return OpenedInput(True, row, ())


def truncated_gap(query: str, limit: int, *, unit_id: str) -> Mapping[str, Any]:
    return producer_gap(GapCode.TRUNCATED, f"{query} reached its bound of {limit}; the result is not complete",
                        unit_id=unit_id, scope_id=query)


def empty_gap(lane: str, *, unit_id: str) -> Mapping[str, Any]:
    return producer_gap(GapCode.EMPTY_RESULT, f"{lane} read its inputs and established nothing",
                        unit_id=unit_id, scope_id=lane)


def with_count(row: InputLedgerRow, records_read: int) -> InputLedgerRow:
    return InputLedgerRow(row.producer, row.output_kind, row.state, row.handoff_sha256,
                          row.coverage_disposition, row.upstream_gap_count, records_read)
