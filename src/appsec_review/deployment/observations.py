"""Read-only imported endpoint assertions and bounded static/observed comparison."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
import ipaddress
from typing import Literal

from jsonschema import Draft202012Validator

from .builder import Builder
from .model import (
    Evidence, Gap, Inventory, Limits, OBSERVATION_SCHEMA, Outcome, Source, SourceDocument,
)
from .parsing import ParseError
from .schemas import bounded_json, observations_schema, valid_service_id


@dataclass(frozen=True)
class ObservedEndpoint:
    id: str
    service_id: str | None
    address: str
    port: int
    transport: Literal["tcp", "udp"]
    role: Literal["container", "published", "service", "node", "configuration"]
    observed_at: str
    expires_at: str
    owner: str | None
    banner: str | None
    reachability: Literal["not_tested", "succeeded", "failed"]
    vantage_point: str | None


@dataclass(frozen=True)
class ObservationBatch:
    target_snapshot: str
    environment: str
    endpoints: tuple[ObservedEndpoint, ...]
    schema: str = OBSERVATION_SCHEMA


@dataclass(frozen=True)
class ImportedEndpoint:
    endpoint: ObservedEndpoint
    time_state: Literal["current", "expired", "future"]
    evidence: str
    authority: Literal["imported_observation"] = "imported_observation"
    evidence_class: Literal["observed_listener"] = "observed_listener"


@dataclass
class ObservationImport:
    outcome: Outcome
    target_snapshot: str
    environment: str
    source: Source | None = None
    endpoints: list[ImportedEndpoint] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)


@dataclass(frozen=True)
class Drift:
    service_id: str | None
    static_listener_id: str | None
    observation_id: str | None
    state: Literal[
        "matched_declaration", "port_matches_bind_unknown", "observed_only", "static_only",
        "bind_differs", "unbound", "stale",
    ]
    evidence: tuple[str, ...]


def _time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ParseError("invalid_time", "invalid observation timestamp") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise ParseError("invalid_time", "observation timestamp requires a timezone")
    return result


def import_observations(document: SourceDocument, *, target_snapshot: str, environment: str,
                        as_of: datetime, limits: Limits = Limits()) -> ObservationImport:
    """Validate an imported operator snapshot, not its collector's truthfulness or authority.

    Reachability outcomes remain reported measurements; this function never promotes them
    to proven reachability, product identity, vulnerability or permission to access a target.
    """
    if not target_snapshot or not environment or as_of.tzinfo is None or as_of.utcoffset() is None:
        raise ValueError("explicit target, environment and timezone-aware comparison time are required")
    result = ObservationImport("complete", target_snapshot, environment,
                               source=document.reference(target_snapshot))
    try:
        if document.scope != "target":
            raise ParseError("platform_scope", "analysis-platform observations are excluded", "unsupported")
        if document.format != "observations":
            raise ParseError("unsupported_format", "expected an imported observation document", "unsupported")
        if len(document.data) > limits.max_document_bytes:
            raise ParseError("input_limit", "observation source exceeds byte bound", "partial")
        if hashlib.sha256(document.data).hexdigest() != document.sha256:
            raise ParseError("source_identity", "observation source differs from admitted SHA-256")
        value = bounded_json(document.data, limits)
        if isinstance(value, dict) and isinstance(value.get("schema"), str) and value["schema"] != OBSERVATION_SCHEMA:
            raise ParseError("unsupported_schema", "unsupported observation schema version", "unsupported")
        errors = list(Draft202012Validator(observations_schema()).iter_errors(value))
        if errors:
            raise ParseError("invalid_contract", "observation document violates its closed schema")
        if value["target_snapshot"] != target_snapshot or value["environment"] != environment:
            raise ParseError("foreign_observation", "observation target or environment differs")
        if document.deployment != environment:
            raise ParseError("foreign_observation", "admitted source deployment differs from observation environment")
        if len(value["endpoints"]) > limits.max_records:
            raise ParseError("record_limit", "observation record bound exceeded", "partial")
        builder = Builder(document, target_snapshot, limits)
        static_ev = builder.evidence((1, len(builder.lines)), "observation.import.v1")
        original = builder.graph.evidence[0]
        from dataclasses import replace

        evidence = replace(original, authority="imported_observation")
        endpoints = []
        ids = set()
        gaps = []
        if not value["endpoints"]:
            gaps.append(Gap("no_observations", "snapshot contains no observed endpoints", builder.source.id))
        for raw in value["endpoints"]:
            endpoint = ObservedEndpoint(**raw)
            if not endpoint.id or endpoint.id in ids:
                raise ParseError("duplicate_endpoint", "observation identifiers must be nonempty and unique")
            ids.add(endpoint.id)
            if endpoint.service_id is not None and not valid_service_id(endpoint.service_id):
                raise ParseError("invalid_service", "invalid observation service identity")
            try:
                ipaddress.ip_address(endpoint.address)
            except ValueError as exc:
                raise ParseError("invalid_address", "observed bind must be an IP address") from exc
            if endpoint.reachability != "not_tested" and not endpoint.vantage_point:
                raise ParseError("missing_vantage", "reported reachability requires its vantage point")
            start, end = _time(endpoint.observed_at), _time(endpoint.expires_at)
            if not start < end or end - start > timedelta(days=7):
                raise ParseError("invalid_window", "observation validity must be positive and at most seven days")
            state: Literal["future", "expired", "current"] = (
                "future" if start > as_of else "expired" if end <= as_of else "current"
            )
            if state != "current":
                gaps.append(Gap("observation_" + state, "observation is outside its validity window",
                                builder.source.id, evidence=(static_ev,)))
            endpoints.append(ImportedEndpoint(endpoint, state, static_ev))
        result.endpoints, result.evidence, result.gaps = endpoints, [evidence], gaps
        result.outcome = "partial" if gaps else "complete"
    except ParseError as exc:
        result.outcome = exc.outcome
        result.gaps = [Gap(exc.code, exc.message, result.source.id if result.source else None)]
    return result


def compare_observations(inventory: Inventory, observations: ObservationImport) -> list[Drift]:
    """Presence comparison only; missing observations do not prove closed ports or absence."""
    if inventory.target_snapshot != observations.target_snapshot:
        raise ValueError("cannot compare observations from another target snapshot")
    if observations.outcome in {"malformed", "unsupported"}:
        raise ValueError("cannot compare rejected observations")
    services = {item.id: item for item in inventory.services if item.deployment == observations.environment}
    listeners = [item for item in inventory.listeners if item.service_id in services]
    seen: set[str] = set()
    result = []
    for item in observations.endpoints:
        endpoint = item.endpoint
        if item.time_state != "current":
            result.append(Drift(endpoint.service_id, None, endpoint.id, "stale", (item.evidence,)))
            continue
        if endpoint.service_id not in services:
            result.append(Drift(endpoint.service_id, None, endpoint.id, "unbound", (item.evidence,)))
            continue
        matches = [listener for listener in listeners if listener.service_id == endpoint.service_id
                   and listener.port == endpoint.port and listener.transport == endpoint.transport
                   and listener.role == endpoint.role]
        if not matches:
            result.append(Drift(endpoint.service_id, None, endpoint.id, "observed_only", (item.evidence,)))
        for listener in matches:
            seen.add(listener.id)
            state: Literal["matched_declaration", "port_matches_bind_unknown", "bind_differs"]
            try:
                bind = ipaddress.ip_address(listener.address) if listener.address is not None else None
            except ValueError:
                bind = None
            state = ("port_matches_bind_unknown" if bind is None else "matched_declaration"
                     if bind == ipaddress.ip_address(endpoint.address) else "bind_differs")
            result.append(Drift(endpoint.service_id, listener.id, endpoint.id, state,
                                (*listener.evidence, item.evidence)))
    for listener in listeners:
        if listener.id not in seen:
            result.append(Drift(listener.service_id, listener.id, None, "static_only", listener.evidence))
    return sorted(result, key=lambda item: (item.service_id or "", item.static_listener_id or "",
                                           item.observation_id or "", item.state))
