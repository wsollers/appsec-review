"""Citation resolution and document validation of the generated threat model (T-107).

Design: docs/architecture/dfd-and-threat-model-generation.md sections 6.4, 7 and 11. Both functions
are pure: the caller supplies ``resolves``, the only thing here that knows the accepted evidence.

``resolve_citations`` (step ``validation.resolve_citations``) asks once per distinct reference. A
record keeps the references that resolve. An element, flow, entry point, actor or threat left with
none is removed and demoted to a ``citation_unresolved`` unknown with a ``location_unresolved`` gap
scoped to its former id. Removal then cascades, and the cascaded records are counted in the reason
of the gap that caused them (the smallest causing id when there are several), not reported as gaps:

- a flow with a removed endpoint is removed;
- a derived element (external entity, data store) whose flows are all removed is removed;
- a boundary keeps its existing members and the evidence of its surviving crossing flows, and is
  removed when no crossing flow survives. A boundary is derived, so it is never demoted directly;
- entry points of a removed process and actors of a removed external entity are removed;
- a threat with a removed flow is removed;
- an unknown about a removed record is dropped, the demotion unknown replaces it.

``validate_documents`` checks the plain published forms before publication and raises ``ValueError``
naming the first violation. A violation rejects the attempt; nothing is repaired.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable, Mapping, Sequence

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.threat_model import schemas
from appsec_review.threat_model.assemble import Assembly, bounded_evidence
from appsec_review.threat_model.contract import (
    ElementKind, EvidenceRef, Mitigation, MitigationState, Threat, UnknownKind, unknown,
)


def resolve_citations(assembly: Assembly, threats: Sequence[Threat], resolves: Callable[[EvidenceRef], bool], *,
                      unit_id: str = "validation.resolve_citations"
                      ) -> tuple[Assembly, tuple[Threat, ...], tuple[Mapping[str, Any], ...]]:
    """The assembly and threats with only resolving citations, and the gaps of the demoted records."""
    records = (*assembly.elements, *assembly.flows, *assembly.boundaries, *assembly.entry_points, *assembly.actors,
               *threats)
    cited: dict[str, EvidenceRef] = {}
    for record in records:
        mitigation = record.mitigation.evidence if isinstance(record, Threat) else ()
        for item in (*record.evidence, *mitigation):
            cited.setdefault(item.ref, item)
    resolved = {ref for ref in sorted(cited) if resolves(cited[ref])}

    def kept(record: Any) -> tuple[EvidenceRef, ...]:
        return tuple(item for item in record.evidence if item.ref in resolved)

    # Direct demotions: records whose own citations all failed. ``cause`` maps a removed id to the
    # demoted id that caused it (itself for a direct demotion).
    cause: dict[str, str] = {}
    citations: dict[str, int] = {}
    for record in (*assembly.elements, *assembly.flows, *assembly.entry_points, *assembly.actors, *threats):
        if not kept(record):
            cause[record.id], citations[record.id] = record.id, len(record.evidence)

    def cascade(identity: str, causes: Sequence[str]) -> None:
        found = sorted(cause[item] for item in causes if item in cause)
        if identity not in cause and found:
            cause[identity] = found[0]

    for flow in assembly.flows:
        cascade(flow.id, (flow.source, flow.target))
    for element in assembly.elements:
        touching = [flow.id for flow in assembly.flows if element.id in (flow.source, flow.target)]
        if element.kind is not ElementKind.PROCESS and touching and all(item in cause for item in touching):
            cascade(element.id, touching)
    for boundary in assembly.boundaries:
        crossing = [flow.id for flow in assembly.flows if boundary.id in flow.crosses]
        if all(item in cause for item in crossing):
            cascade(boundary.id, crossing)
    for entry_point in assembly.entry_points:
        cascade(entry_point.id, (entry_point.process,))
    for actor in assembly.actors:
        cascade(actor.id, (actor.external_entity,))
    for threat in threats:
        cascade(threat.id, threat.flow_ids)

    elements = tuple(replace(item, evidence=kept(item)) for item in assembly.elements if item.id not in cause)
    existing = {item.id for item in elements}
    flows = tuple(replace(item, evidence=kept(item)) for item in assembly.flows if item.id not in cause)
    boundaries = []
    for boundary in assembly.boundaries:
        crossing = [flow for flow in flows if boundary.id in flow.crosses]
        if boundary.id in cause or not crossing:
            cause.setdefault(boundary.id, "")  # never crossed: removed, caused by no demotion
            continue
        surviving = {item.ref for flow in crossing for item in flow.evidence}
        evidence = tuple(item for item in kept(boundary) if item.ref in surviving) or bounded_evidence(
            (item for flow in crossing for item in flow.evidence), len(boundary.evidence))
        boundaries.append(replace(boundary, evidence=evidence,
                                  inside=tuple(item for item in boundary.inside if item in existing)))
    present = {item.id for item in boundaries}
    flows = tuple(replace(flow, crosses=tuple(item for item in flow.crosses if item in present)) for flow in flows)
    entry_points = tuple(replace(item, evidence=kept(item)) for item in assembly.entry_points if item.id not in cause)
    actors = tuple(replace(item, evidence=kept(item)) for item in assembly.actors if item.id not in cause)
    remaining = []
    for threat in threats:
        if threat.id in cause:
            continue
        found = tuple(item for item in threat.mitigation.evidence if item.ref in resolved)
        mitigation = threat.mitigation if found == threat.mitigation.evidence else (
            Mitigation(MitigationState.EVIDENCE_FOUND, found) if found else Mitigation(MitigationState.NOT_EXAMINED))
        remaining.append(replace(threat, evidence=kept(threat), mitigation=mitigation,
                                 boundary_ids=tuple(item for item in threat.boundary_ids if item in present)))

    unknowns = {item.id: item for item in assembly.unknowns if not any(subject in cause for subject in item.subject_ids)}
    gaps = []
    for identity in sorted(citations):
        count = citations[identity]
        cascaded = sum(1 for removed, by in cause.items() if by == identity and removed != identity)
        demoted = unknown(UnknownKind.CITATION_UNRESOLVED,
                          f"{identity} was removed from the model: none of its {count} citations resolved")
        unknowns[demoted.id] = demoted
        reason = f"none of the {count} citations of {identity} resolved; the record was removed"
        if cascaded:
            reason += f" and {cascaded} records that depend on it were removed with it"
        gaps.append(producer_gap(GapCode.LOCATION_UNRESOLVED, reason, unit_id=unit_id, scope_id=identity))

    return (Assembly(elements, flows, tuple(boundaries), entry_points, actors,
                     tuple(unknowns[identity] for identity in sorted(unknowns)), assembly.gaps),
            tuple(remaining), tuple(gaps))


def _fail(message: str) -> None:
    raise ValueError(f"generated model documents are invalid: {message}")


def _sorted(label: str, keys: Sequence[Any]) -> None:
    for index in range(1, len(keys)):
        if keys[index - 1] > keys[index]:
            _fail(f"{label} is not sorted at index {index}")


def _unique(label: str, groups: Mapping[str, Sequence[Mapping[str, Any]]]) -> None:
    seen: dict[str, str] = {}
    for name, records in groups.items():
        for record in records:
            if record["id"] in seen:
                _fail(f"{label} repeats the id {record['id']} ({seen[record['id']]}, {name})")
            seen[record["id"]] = name


def _exists(label: str, identity: Any, known: Any, what: str) -> None:
    if identity not in known:
        _fail(f"{label} names {identity}, which is not {what}")


def validate_documents(dfd: Mapping[str, Any], threat_model: Mapping[str, Any], evidence: Mapping[str, Any],
                       result: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` naming the first violation of the four plain published documents."""
    for document in (dfd, threat_model, evidence, result):
        schemas.validate_document(document)
    for name, document in (("threat model", threat_model), ("evidence", evidence), ("result", result)):
        if document["origin"] != dfd["origin"]:
            _fail(f"the origin of the {name} document differs from the DFD's")

    dfd_arrays = {key: list(dfd[key]) for key in ("elements", "flows", "boundaries", "unknowns")}
    model_arrays = {key: list(threat_model[key]) for key in ("assets", "actors", "entry_points", "threats", "unknowns")}
    for label, arrays in (("dfd", dfd_arrays), ("threat model", model_arrays)):
        for key, records in arrays.items():
            _sorted(f"{label} {key}", [record["id"] for record in records])
        _unique(f"the {label} document", arrays)
    references = [item["ref"] for item in evidence["references"]]
    _sorted("evidence references", references)
    _sorted("result input_ledger", [(row["producer"], row["output_kind"]) for row in result["input_ledger"]])

    kinds = {item["id"]: item["kind"] for item in dfd_arrays["elements"]}
    flows = {item["id"] for item in dfd_arrays["flows"]}
    boundaries = {item["id"] for item in dfd_arrays["boundaries"]}
    for flow in dfd_arrays["flows"]:
        for end in ("source", "target"):
            _exists(f"flow {flow['id']} {end}", flow[end], kinds, "an element")
        for crossed in flow["crosses"]:
            _exists(f"flow {flow['id']} crosses", crossed, boundaries, "a boundary")
    for boundary in dfd_arrays["boundaries"]:
        for member in boundary["inside"]:
            _exists(f"boundary {boundary['id']} inside", member, kinds, "an element")
    processes = {identity for identity, kind in kinds.items() if kind == ElementKind.PROCESS.value}
    externals = {identity for identity, kind in kinds.items() if kind == ElementKind.EXTERNAL_ENTITY.value}
    for entry_point in model_arrays["entry_points"]:
        _exists(f"entry point {entry_point['id']} process", entry_point["process"], processes, "a process")
    for actor in model_arrays["actors"]:
        _exists(f"actor {actor['id']} external_entity", actor["external_entity"], externals, "an external entity")
    for asset in model_arrays["assets"]:
        for holder in asset["held_by"]:
            _exists(f"asset {asset['id']} held_by", holder, kinds, "an element")
    for threat in model_arrays["threats"]:
        for key, known, what in (("element_ids", kinds, "an element"), ("flow_ids", flows, "a flow"),
                                 ("boundary_ids", boundaries, "a boundary")):
            for identity in threat[key]:
                _exists(f"threat {threat['id']} {key}", identity, known, what)

    listed = set(references)
    if len(references) != len(listed):
        _fail(f"the evidence document repeats the reference {min(r for r in listed if references.count(r) > 1)}")
    cited: set[str] = set()
    for label, arrays in (("dfd", dfd_arrays), ("threat model", model_arrays)):
        for key, records in arrays.items():
            for record in records:
                groups = [record.get("evidence") or ()]
                if key == "threats":
                    groups.append(record["mitigation"].get("evidence") or ())
                for item in (item for group in groups for item in group):
                    if item["ref"] not in listed:
                        _fail(f"{label} {key} {record['id']} cites {item['ref']}, which is not in the evidence document")
                    cited.add(item["ref"])
    uncited = sorted(listed - cited)
    if uncited:
        _fail(f"the evidence document lists {uncited[0]}, which no record cites")
