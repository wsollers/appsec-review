"""Lane B review units: deterministic partitioning and ranking from accepted signals.

A review unit is an accepted component, then its trust boundary when an accepted producer names
one (none does yet, so it is ``None``), then build unit, then a stable range of sorted source
paths. Units are ranked by ``review-unit-rank/2`` from the signals that are available: review
prioritization (LPS), source-history instability (SII), hotspots, security-tag density,
medium/low/info lead hints, and the reference context of the unit's dependency/artifact advisories:
``advisory_kev`` (``KEV_POINTS`` when any advisory is KEV-listed) and ``advisory_epss`` (the highest
EPSS percentile times ``EPSS_POINTS``). A missing signal, including an advisory whose KEV or EPSS
feed was unavailable, is recorded as ``unknown``; it is never read as zero.
Only the top ``hunt_max_units`` units receive hunt packages; every other unit is a coverage gap
with reason ``below_hunt_cutoff``.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import math
from typing import Any

from appsec_review.retrieval.model import LogicalIdentity
from appsec_review.review.lead_families import ADVISORY_FAMILIES, Lead, LeadCollection
from appsec_review.review.scope import AcceptedScope, ScopeGap


RANK_RULE = "appsec-review/review-unit-rank/2"
SIGNALS = ("lps", "sii", "hotspot", "tag_density", "lead_hints", "advisory_kev", "advisory_epss")
# Reference-context weights (points of the 0-1000 signal scale). KEV is a binary catalog fact; EPSS
# percentile is scaled. Both are deliberately below a full LPS/SII signal: they order hunting, they
# are not evidence that the target is affected.
KEV_POINTS = 250
EPSS_POINTS = 250
CUTOFF_REASON = "below_hunt_cutoff"
_UNLOCATED = "unlocated"
# Ranked-selection producers publish only selected items: no record for a unit is unknown, not zero.
# Exhaustive producers (tags, normalized leads) make an absent record a true zero.
_SIGNAL_PRODUCERS = {"lps": "review_prioritization", "sii": "source_history", "hotspot": "source_history",
                     "tag_density": "security_tagging"}
_EXHAUSTIVE = frozenset({"tag_density", "lead_hints"})


@dataclass(frozen=True, slots=True)
class ContextEntry:
    id: str
    kind: str
    role: str
    shard_sha256: str | None = None

    def record(self) -> dict[str, str]:
        return {"id": self.id, "kind": self.kind, "role": self.role}


def context_entry(identity: str, role: str, shard_sha256: str | None = None) -> ContextEntry:
    return ContextEntry(identity, LogicalIdentity.parse(identity).kind.value, role, shard_sha256)


@dataclass(frozen=True, slots=True)
class Signal:
    signal: str
    value: int | None                 # integer points in [0, 1000]; None when unknown
    reason: str | None                # None, "producer_unavailable", "no_record" or "feed_unavailable"

    @property
    def state(self) -> str:
        return "unknown" if self.value is None else "available"

    def record(self) -> dict[str, Any]:
        return {"signal": self.signal, "value": self.value, "state": self.state, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class ReviewUnit:
    key: str
    component_id: str
    trust_boundary_id: str | None
    build_unit_id: str | None
    range_label: str
    paths: tuple[str, ...]
    source_ids: tuple[str, ...]
    leads: tuple[Lead, ...]
    context: tuple[ContextEntry, ...]
    signals: tuple[Signal, ...]

    @property
    def score(self) -> int:
        return sum(item.value for item in self.signals if item.value is not None)

    @property
    def known_signals(self) -> int:
        return sum(1 for item in self.signals if item.value is not None)

    @property
    def lead_ids(self) -> tuple[str, ...]:
        return tuple(lead.observation_id for lead in self.leads)


@dataclass(frozen=True, slots=True)
class RankedUnit:
    unit: ReviewUnit
    position: int
    unit_count: int

    def rank_record(self) -> dict[str, Any]:
        return {"position": self.position, "unit_count": self.unit_count, "score": self.unit.score,
                "rule": RANK_RULE, "basis": [item.record() for item in self.unit.signals]}


def _points(value: Any, scale: float) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return min(1000, int(round(number * scale)))


def _unit_score(value: Any) -> int | None:
    """Scores in [0, 1] scale to 1000; scores in (1, 100] are percentages."""
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return _points(number, 1000.0 if number <= 1.0 else 10.0)


def _path(row: Mapping[str, Any]) -> str | None:
    location = row.get("location")
    if location is not None:
        return str(location["path"])
    payload = row["payload"]
    subject = payload.get("subject") if isinstance(payload.get("subject"), Mapping) else {}
    value = payload.get("path") or subject.get("path")
    return str(value) if isinstance(value, str) and value else None


def _unit_key(component: str, boundary: str | None, build_unit: str | None, label: str) -> str:
    return f"unit:{component}:{boundary or '-'}:{build_unit or '-'}:{label}"


def build_units(scope: AcceptedScope, collection: LeadCollection, *, unit_max_files: int) -> tuple[ReviewUnit, ...]:
    """Partition the accepted scope into review units with their signals, in key order."""
    if unit_max_files < 1:
        raise ValueError("unit_max_files must be positive")

    def locate(path: str | None, hint: str | None = None) -> tuple[str, str | None]:
        component = scope.component_for(path)
        unit = scope.build_unit_for(path)
        return (component.component_id if component else hint or "unassigned",
                unit.build_unit_id if unit else None)

    groups: dict[tuple[str, str | None], set[str]] = defaultdict(set)
    for item in scope.source_files:
        groups[locate(item.path)].add(item.path)
    unlocated: dict[tuple[str, str | None], list[Lead]] = defaultdict(list)
    for lead in collection.leads:
        if lead.path is None:
            unlocated[locate(None, lead.component_hint)].append(lead)
        else:
            groups[locate(lead.path, lead.component_hint)].add(lead.path)

    by_path: dict[str, list[Lead]] = defaultdict(list)
    for lead in collection.leads:
        if lead.path is not None:
            by_path[lead.path].append(lead)
    rows = _signal_rows(scope)
    lead_families_available = any(collection.available.values())
    components = {item.component_id: item for item in scope.components}
    build_units = {item.build_unit_id: item for item in scope.build_units}

    units: list[ReviewUnit] = []
    keys = sorted(set(groups) | set(unlocated), key=lambda item: (item[0], item[1] or ""))
    for component_id, build_unit_id in keys:
        paths = sorted(groups.get((component_id, build_unit_id), ()))
        ranges: list[tuple[str, list[str], list[Lead]]] = [
            (f"r{number:04d}", paths[offset:offset + unit_max_files], [])
            for number, offset in enumerate(range(0, len(paths), unit_max_files))]
        if unlocated.get((component_id, build_unit_id)):
            ranges.append((_UNLOCATED, [], list(unlocated[(component_id, build_unit_id)])))
        for label, members, extra in ranges:
            leads = sorted([lead for path in members for lead in by_path.get(path, ())] + extra,
                           key=lambda lead: lead.observation_id)
            context: list[ContextEntry] = []
            if component_id in components:
                context.append(context_entry(components[component_id].identity, "component"))
            if build_unit_id in build_units:
                context.append(context_entry(build_units[build_unit_id].identity, "build_unit"))
            sources = sorted({source.identity for path in members if (source := scope.source_for(path))})
            signals: list[Signal] = []
            member_set = set(members)
            for signal in ("lps", "sii", "hotspot", "tag_density"):
                producer = _SIGNAL_PRODUCERS[signal]
                if not scope.producer(producer).shards:
                    signals.append(Signal(signal, None, "producer_unavailable"))
                    continue
                matched = [row for row in rows[signal] if row["path"] in member_set]
                context.extend(context_entry(row["identity"], row["role"], row["shard_sha256"]) for row in matched)
                if signal == "tag_density":
                    value = min(1000, (len(matched) * 1000) // (4 * max(1, len(members)))) if members else None
                    signals.append(Signal(signal, value, None if value is not None else "no_record"))
                    continue
                values = [row["value"] for row in matched if row["value"] is not None]
                signals.append(Signal(signal, max(values), None) if values else Signal(signal, None, "no_record"))
            if lead_families_available:
                hints = {severity: sum(1 for lead in leads if lead.reported_severity == severity)
                         for severity in ("medium", "low", "info")}
                signals.append(Signal("lead_hints", min(1000, 100 * hints["medium"] + 30 * hints["low"]
                                                         + 10 * hints["info"]), None))
            else:
                signals.append(Signal("lead_hints", None, "producer_unavailable"))
            signals.extend(_advisory_signals(scope, leads))
            unique = {(item.role, item.id): item for item in context}
            units.append(ReviewUnit(
                key=_unit_key(component_id, None, build_unit_id, label), component_id=component_id,
                trust_boundary_id=None, build_unit_id=build_unit_id, range_label=label, paths=tuple(members),
                source_ids=tuple(sources), leads=tuple(leads),
                context=tuple(unique[key] for key in sorted(unique)), signals=tuple(signals)))
    units.sort(key=lambda item: item.key)
    return tuple(units)


def _advisory_signals(scope: AcceptedScope, leads: Iterable[Lead]) -> tuple[Signal, Signal]:
    """KEV and EPSS rank signals of a unit's advisory leads; a missing feed is unknown, not zero."""
    if not scope.producer("dependency_advisories").shards:
        return (Signal("advisory_kev", None, "producer_unavailable"),
                Signal("advisory_epss", None, "producer_unavailable"))
    advisory = [lead for lead in leads if lead.family in ADVISORY_FAMILIES]
    if not advisory:
        return Signal("advisory_kev", 0, None), Signal("advisory_epss", 0, None)
    def reason(feed: str) -> str:
        missing = any(lead.advisory is None or any(item["joins"][feed] == "unavailable"
                                                   for item in lead.advisory["advisories"]) for lead in advisory)
        return "feed_unavailable" if missing else "no_record"

    listed = [lead.kev_listed for lead in advisory]
    if any(value is True for value in listed):
        kev = Signal("advisory_kev", KEV_POINTS, None)
    elif all(value is False for value in listed):
        kev = Signal("advisory_kev", 0, None)
    else:
        kev = Signal("advisory_kev", None, reason("kev"))
    percentiles = [value for value in (lead.epss_percentile for lead in advisory) if value is not None]
    epss = (Signal("advisory_epss", _points(max(percentiles), EPSS_POINTS), None) if percentiles
            else Signal("advisory_epss", None, reason("epss")))
    return kev, epss


def _signal_rows(scope: AcceptedScope) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {signal: [] for signal in ("lps", "sii", "hotspot", "tag_density")}
    store = scope.store
    for shard in scope.producer("review_prioritization").shards:
        for row in store.entities((shard,), kinds=("priority_item",)):
            rows["lps"].append({"identity": row["identity"], "path": _path(row), "role": "priority",
                                "value": _unit_score(row["payload"].get("score")),
                                "shard_sha256": scope.shard_sha256(shard)})
    for shard in scope.producer("source_history").shards:
        for row in store.entities((shard,), kinds=("history_signal", "hotspot")):
            native = str(row["native_id"])
            if row["kind"] == "history_signal" and native.startswith("file:"):
                sii = row["payload"].get("sii") if isinstance(row["payload"].get("sii"), Mapping) else {}
                rows["sii"].append({"identity": row["identity"], "path": _path(row), "role": "history",
                                    "value": _unit_score(sii.get("score")), "shard_sha256": scope.shard_sha256(shard)})
            elif row["kind"] == "hotspot":
                rows["hotspot"].append({"identity": row["identity"], "path": _path(row), "role": "hotspot",
                                        "value": _unit_score(row["payload"].get("score")),
                                        "shard_sha256": scope.shard_sha256(shard)})
    for shard in scope.producer("security_tagging").shards:
        for row in store.entities((shard,), kinds=("tag_assignment",)):
            rows["tag_density"].append({"identity": row["identity"], "path": _path(row), "role": "tag",
                                        "value": None, "shard_sha256": scope.shard_sha256(shard)})
    for values in rows.values():
        values.sort(key=lambda item: (str(item["path"]), item["identity"]))
    return rows


def rank_units(units: Iterable[ReviewUnit]) -> tuple[RankedUnit, ...]:
    """Deterministic rank: total available points, then count of known signals, then unit key."""
    ordered = sorted(units, key=lambda item: (-item.score, -item.known_signals, item.key))
    return tuple(RankedUnit(unit, position, len(ordered)) for position, unit in enumerate(ordered, 1))


def select_hunts(ranked: Iterable[RankedUnit], hunt_max_units: int
                 ) -> tuple[tuple[RankedUnit, ...], tuple[ScopeGap, ...]]:
    """Top units by rank receive hunt packages; every other unit is a ``below_hunt_cutoff`` gap."""
    if hunt_max_units < 0:
        raise ValueError("hunt_max_units must not be negative")
    ordered = sorted(ranked, key=lambda item: item.position)
    gaps = tuple(ScopeGap("lane_b_hunt", item.unit.key, "skipped",
                          f"{CUTOFF_REASON}: rank {item.position} of {item.unit_count} exceeds "
                          f"hunt_max_units={hunt_max_units}") for item in ordered[hunt_max_units:])
    return tuple(ordered[:hunt_max_units]), gaps
