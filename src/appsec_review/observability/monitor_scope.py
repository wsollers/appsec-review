"""Dispatch ownership shared by epoch selection and current lifecycle accounting."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence
from uuid import UUID

from appsec_review.reporting.telemetry.inputs import RUN_TERMINALS


@dataclass(frozen=True)
class DispatchIdentity:
    kind: str
    value: str | None = None


def event_dispatch(event: Mapping[str, Any]) -> DispatchIdentity:
    details = event["details"]
    orchestration = details.get("orchestration")
    system = orchestration.get("system") if isinstance(orchestration, Mapping) else None
    values = [details.get("dagster_run_id")]
    if system == "dagster":
        values.append(orchestration.get("run_id"))
    identifiers = set()
    for value in values:
        if value is not None:
            try:
                identifiers.add(str(UUID(value)))
            except (ValueError, TypeError, AttributeError):
                return DispatchIdentity("invalid")
    if len(identifiers) > 1 or identifiers and system in {"application", "local"}:
        return DispatchIdentity("conflicting")
    if identifiers:
        return DispatchIdentity("dagster", next(iter(identifiers)))
    if system == "dagster" or event.get("orchestrator") == "dagster":
        return DispatchIdentity("missing")
    if event.get("orchestrator") in {"application", "local"} and system in {None, "application", "local"}:
        return DispatchIdentity("application")
    return DispatchIdentity("missing")


def owns_event(event: Mapping[str, Any], dispatch: str | None, *, admitted_attempt: bool = False) -> bool:
    """Only untagged progress can inherit an exact current admission; starts/reuse/terminals cannot."""
    identity = event_dispatch(event)
    if identity.kind == "dagster":
        return identity.value == dispatch
    if identity.kind in {"invalid", "conflicting"}:
        return False
    if dispatch is not None:
        return admitted_attempt
    return identity.kind == "application"


@dataclass(frozen=True)
class ObservationEpoch:
    sequence: int
    dispatch: str | None
    owner_known: bool
    graph_event: Mapping[str, Any] | None
    gaps: tuple[str, ...]


def observation_epoch(events: Sequence[Mapping[str, Any]]) -> ObservationEpoch:
    epoch = last_sequence = 0
    dispatch = None
    owner_known = started = terminal = False
    selection = None
    seen_dispatches: set[str] = set()
    gaps: set[str] = set()
    for event in events:
        kind, details, sequence = event["event_type"], event["details"], event["sequence"]
        identity = event_dispatch(event)
        known = identity.kind in {"dagster", "application"}
        selector = kind == "RUN_GRAPH_SNAPSHOT" or kind == "GRAPH_STARTED" and details.get("graph_reference")
        if kind == "RUN_STARTED" or selector:
            if identity.value is not None and identity.value != dispatch and identity.value in seen_dispatches:
                gaps.add("late_foreign_dispatch_boundary_ignored")
                last_sequence = sequence
                continue
        if kind == "RUN_STARTED":
            keep_selection = (selection is not None and known and owner_known
                              and identity.value == dispatch and not terminal
                              and (not started or selection["sequence"] == last_sequence))
            selection = selection if keep_selection else None
            epoch, dispatch, owner_known = sequence, identity.value, known
            started, terminal = True, False
            gaps = set() if known else {"run_start_dispatch_identity_unconfirmed"}
        elif selector:
            same_owner = known and owner_known and identity.value == dispatch
            if not epoch or terminal or known and owner_known and not same_owner:
                epoch, dispatch, owner_known = sequence, identity.value, known
                started, terminal, gaps = False, False, set()
                selection = None
            elif not same_owner:
                gaps.add("graph_dispatch_identity_unconfirmed")
            if (selection is not None and same_owner
                    and selection["details"].get("graph_reference") != details.get("graph_reference")):
                gaps.add("conflicting_graph_selection_in_epoch")
            # The first snapshot can follow RUN_STARTED/JOB_STARTED for an allocated application ID.
            # It enriches that owned epoch; it is not another run start.
            selection = event
        elif kind in RUN_TERMINALS and owns_event(event, dispatch):
            terminal = True
        if known and identity.value is not None and (kind == "RUN_STARTED" or selector):
            seen_dispatches.add(identity.value)
        last_sequence = sequence
    return ObservationEpoch(epoch, dispatch, owner_known, selection, tuple(sorted(gaps)))
