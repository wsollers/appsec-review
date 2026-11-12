"""Plain JSON back to contract records (T-107): the exact inverse of ``contract.canonical``.

The job's units pass records to later units through attempt-owned files, so every record that
crosses a unit boundary is written with ``contract.canonical`` and read back here. For each record
type ``from_plain(json.loads(canonical(x))) == x``. Reading is strict: an unknown or missing key, a
value outside a closed vocabulary or an identity that does not match its content raises
``ValueError`` (the dataclasses re-check their own invariants, so a changed file cannot produce a
record the contract would not have built).
"""
from __future__ import annotations

from dataclasses import fields
from typing import Any, Callable, Mapping, Sequence, TypeVar

from appsec_review.threat_model.assemble import Assembly
from appsec_review.threat_model.contract import (
    Actor, Asset, Basis, Boundary, BoundaryKind, Element, ElementKind, EntryPoint, EvidenceRef, Fact, FactKind, Flow,
    InputLedgerRow, InputState, Interaction, LaneResult, Mitigation, MitigationState, NameBasis, Origin, Publication,
    Stride, Threat, ThreatState, Unknown, UnknownKind,
)

T = TypeVar("T")


def _object(value: Any, kind: type) -> Mapping[str, Any]:
    expected = {item.name for item in fields(kind)}
    if not isinstance(value, Mapping) or set(value) != expected:
        found = set(value) if isinstance(value, Mapping) else set()
        raise ValueError(f"{kind.__name__} record has the wrong keys: unknown={sorted(map(str, found - expected))}, "
                         f"missing={sorted(expected - found)}")
    return value


def _array(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{label} must be an array")
    return value


def _each(value: Any, label: str, read: Callable[[Any], T]) -> tuple[T, ...]:
    return tuple(read(item) for item in _array(value, label))


def _texts(value: Any, label: str) -> tuple[str, ...]:
    items = _array(value, label)
    if any(not isinstance(item, str) for item in items):
        raise ValueError(f"{label} must be an array of text")
    return tuple(items)


def _gaps(value: Any, label: str) -> tuple[Mapping[str, Any], ...]:
    items = _array(value, label)
    if any(not isinstance(item, Mapping) for item in items):
        raise ValueError(f"{label} must be an array of gap records")
    return tuple(dict(item) for item in items)


def publication_from_plain(value: Any) -> Publication:
    return Publication(**_object(value, Publication))


def evidence_ref_from_plain(value: Any) -> EvidenceRef:
    record = _object(value, EvidenceRef)
    return EvidenceRef(**{**record, "publication": publication_from_plain(record["publication"]),
                          "basis": Basis(record["basis"])})


def _evidence(value: Any) -> tuple[EvidenceRef, ...]:
    return _each(value, "evidence", evidence_ref_from_plain)


def fact_from_plain(value: Any) -> Fact:
    record = _object(value, Fact)
    return Fact(FactKind(record["kind"]), record["native_identity"], record["name"], Basis(record["basis"]),
                _evidence(record["evidence"]), record["attributes"])


def unknown_from_plain(value: Any) -> Unknown:
    record = _object(value, Unknown)
    return Unknown(record["id"], UnknownKind(record["kind"]), _texts(record["subject_ids"], "subject_ids"),
                   record["statement"], _texts(record["would_resolve"], "would_resolve"))


def ledger_row_from_plain(value: Any) -> InputLedgerRow:
    record = _object(value, InputLedgerRow)
    return InputLedgerRow(**{**record, "state": InputState(record["state"])})


def lane_result_from_plain(value: Any) -> LaneResult:
    record = _object(value, LaneResult)
    return LaneResult(_each(record["facts"], "facts", fact_from_plain), _gaps(record["gaps"], "gaps"),
                      _each(record["ledger"], "ledger", ledger_row_from_plain),
                      _each(record["unknowns"], "unknowns", unknown_from_plain))


def element_from_plain(value: Any) -> Element:
    record = _object(value, Element)
    return Element(record["id"], ElementKind(record["kind"]), record["name"], NameBasis(record["name_basis"]),
                   Basis(record["basis"]), _evidence(record["evidence"]), record["attributes"],
                   _texts(record["component_ids"], "component_ids"))


def flow_from_plain(value: Any) -> Flow:
    record = _object(value, Flow)
    return Flow(record["id"], record["source"], record["target"], Interaction(record["interaction"]),
                Basis(record["basis"]), _evidence(record["evidence"]), _texts(record["crosses"], "crosses"),
                record["data"], record["attributes"])


def boundary_from_plain(value: Any) -> Boundary:
    record = _object(value, Boundary)
    return Boundary(record["id"], BoundaryKind(record["kind"]), _texts(record["inside"], "inside"),
                    Basis(record["basis"]), _evidence(record["evidence"]))


def entry_point_from_plain(value: Any) -> EntryPoint:
    record = _object(value, EntryPoint)
    return EntryPoint(record["id"], record["process"], Interaction(record["interaction"]), record["source_class"],
                      record["enclosing_symbol"], Basis(record["basis"]), _evidence(record["evidence"]))


def actor_from_plain(value: Any) -> Actor:
    record = _object(value, Actor)
    return Actor(record["id"], record["external_entity"],
                 _texts(record["attacker_position_candidates"], "attacker_position_candidates"),
                 _evidence(record["evidence"]))


def asset_from_plain(value: Any) -> Asset:
    record = _object(value, Asset)
    return Asset(record["id"], record["name"], _texts(record["held_by"], "held_by"), Basis(record["basis"]),
                 _evidence(record["evidence"]))


def mitigation_from_plain(value: Any) -> Mitigation:
    record = _object(value, Mitigation)
    return Mitigation(MitigationState(record["state"]), _evidence(record["evidence"]))


def threat_from_plain(value: Any) -> Threat:
    record = _object(value, Threat)
    return Threat(record["id"], ThreatState(record["state"]), Stride(record["stride"]), record["template_id"],
                  record["title"], record["question"], _texts(record["element_ids"], "element_ids"),
                  _texts(record["flow_ids"], "flow_ids"), _texts(record["boundary_ids"], "boundary_ids"),
                  _evidence(record["evidence"]), _texts(record["obligations"], "obligations"),
                  mitigation_from_plain(record["mitigation"]),
                  tuple(_array(record["related_controls"], "related_controls")), record["crosswalk"])


def threats_from_plain(value: Any) -> tuple[Threat, ...]:
    return _each(value, "threats", threat_from_plain)


def origin_from_plain(value: Any) -> Origin:
    return Origin(**_object(value, Origin))


def assembly_from_plain(value: Any) -> Assembly:
    record = _object(value, Assembly)
    return Assembly(_each(record["elements"], "elements", element_from_plain),
                    _each(record["flows"], "flows", flow_from_plain),
                    _each(record["boundaries"], "boundaries", boundary_from_plain),
                    _each(record["entry_points"], "entry_points", entry_point_from_plain),
                    _each(record["actors"], "actors", actor_from_plain),
                    _each(record["unknowns"], "unknowns", unknown_from_plain), _gaps(record["gaps"], "gaps"))


__all__ = [
    "actor_from_plain", "assembly_from_plain", "asset_from_plain", "boundary_from_plain", "element_from_plain",
    "entry_point_from_plain", "evidence_ref_from_plain", "fact_from_plain", "flow_from_plain", "lane_result_from_plain",
    "ledger_row_from_plain", "mitigation_from_plain", "origin_from_plain", "publication_from_plain",
    "threat_from_plain", "threats_from_plain", "unknown_from_plain",
]
