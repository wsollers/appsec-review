"""The four published documents of the generated threat model (T-107), built from contract records.

Design: docs/architecture/dfd-and-threat-model-generation.md sections 6 and 7. ``build_documents``
is a pure function; ``plain`` gives the published JSON form. Every array is sorted (records by
``id``, evidence by ``ref``, the ledger by producer and output kind, gaps by ``gap_id``), so the
bytes do not depend on the order of the inputs.

``assets`` is empty in the first slice: a deterministic asset is limited to what evidence names
(section 6.3), and no accepted input names one yet (no secrets observation, no ``data:*`` tag, no
deployment store product). Each data store therefore gets an ``asset_sensitivity_unknown`` in the
threat model. The DFD carries the assembly's unknowns unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.threat_model.assemble import Assembly
from appsec_review.threat_model.contract import (
    BASIS_PRECEDENCE, DFD_SCHEMA, EVIDENCE_SCHEMA, RESULT_SCHEMA, THREAT_MODEL_SCHEMA, ElementKind, EvidenceRef,
    InputLedgerRow, Origin, Threat, UnknownKind, canonical, sorted_records, unknown,
)

RESOLVE_ASSET = ("job_dependency_intelligence/dependency_context", "job_deployment_inventory/deployment_inventory")


@dataclass(frozen=True, slots=True)
class Documents:
    """The four documents, holding contract dataclasses; ``plain`` gives each published form."""
    dfd: Mapping[str, Any]
    threat_model: Mapping[str, Any]
    evidence: Mapping[str, Any]
    result: Mapping[str, Any]


def plain(document: Any) -> dict[str, Any]:
    """The published JSON form of a document: ``json.loads(contract.canonical(document))``."""
    return json.loads(canonical(document))


def _references(records: Iterable[Any]) -> list[EvidenceRef]:
    """Every distinct reference the records cite, once, sorted by ``ref``."""
    cited: dict[str, EvidenceRef] = {}
    for record in records:
        groups = [record.evidence]
        if isinstance(record, Threat):
            groups.append(record.mitigation.evidence)
        for item in (item for group in groups for item in group):
            kept = cited.get(item.ref)
            if kept is None or _reading(item) < _reading(kept):
                cited[item.ref] = item
    return [cited[ref] for ref in sorted(cited)]


def _reading(item: EvidenceRef) -> tuple[int, str, bytes]:
    return (BASIS_PRECEDENCE.index(item.basis), item.rule, canonical(item))


def _ledger(rows: Sequence[InputLedgerRow]) -> list[InputLedgerRow]:
    """One row per input; an input several lanes read keeps one row with the summed record count."""
    groups: dict[tuple[str, str], list[InputLedgerRow]] = {}
    for row in rows:
        groups.setdefault((row.producer, row.output_kind), []).append(row)
    merged = []
    for key in sorted(groups):
        lead = min(groups[key], key=canonical)
        merged.append(InputLedgerRow(lead.producer, lead.output_kind, lead.state, lead.handoff_sha256,
                                     lead.coverage_disposition, lead.upstream_gap_count,
                                     sum(row.records_read for row in groups[key])))
    return merged


def _gaps(gaps: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    unique = {canonical(dict(gap)): gap for gap in gaps}
    return sorted(unique.values(), key=lambda gap: (str(gap.get("gap_id")), canonical(dict(gap))))


def build_documents(origin: Origin, assembly: Assembly, threats: Sequence[Threat], ledger: Sequence[InputLedgerRow],
                    gaps: Sequence[Mapping[str, Any]], *, artifacts: Mapping[str, Mapping[str, Any]] | None = None,
                    supplied_documents: Sequence[str] = ()) -> Documents:
    """The DFD, threat model, evidence and result documents of one attempt."""
    stores = [element for element in assembly.elements if element.kind is ElementKind.DATA_STORE]
    model_unknowns = [unknown(UnknownKind.ASSET_SENSITIVITY_UNKNOWN,
                              f"how sensitive the data held by {store.name} is, is not established",
                              subject_ids=(store.id,), would_resolve=RESOLVE_ASSET) for store in stores]
    dfd = {"schema": DFD_SCHEMA, "origin": origin, "elements": sorted_records(assembly.elements),
           "flows": sorted_records(assembly.flows), "boundaries": sorted_records(assembly.boundaries),
           "unknowns": sorted_records(assembly.unknowns)}
    threat_model = {"schema": THREAT_MODEL_SCHEMA, "origin": origin, "assets": [],
                    "actors": sorted_records(assembly.actors), "entry_points": sorted_records(assembly.entry_points),
                    "threats": sorted_records(threats), "supplied_documents": sorted(set(supplied_documents)),
                    "unknowns": sorted_records(model_unknowns)}
    references = _references((*assembly.elements, *assembly.flows, *assembly.boundaries, *assembly.actors,
                              *assembly.entry_points, *threats))
    evidence = {"schema": EVIDENCE_SCHEMA, "origin": origin, "references": references}
    joined = _gaps(gaps)
    kinds = [element.kind for element in assembly.elements]
    counts = {
        "processes": kinds.count(ElementKind.PROCESS),
        "data_stores": kinds.count(ElementKind.DATA_STORE),
        "external_entities": kinds.count(ElementKind.EXTERNAL_ENTITY),
        "flows": len(dfd["flows"]),
        "boundaries": len(dfd["boundaries"]),
        "entry_points": len(threat_model["entry_points"]),
        "actors": len(threat_model["actors"]),
        "assets": len(threat_model["assets"]),
        "threats": len(threat_model["threats"]),
        "unknowns": len(dfd["unknowns"]) + len(threat_model["unknowns"]),
        "gaps": len(joined),
        "evidence_references": len(references),
    }
    result = {"schema": RESULT_SCHEMA, "origin": origin, "input_ledger": _ledger(ledger), "counts": counts,
              "gaps": joined, "artifacts": {name: dict(artifacts[name]) for name in sorted(artifacts or {})}}
    return Documents(dfd, threat_model, evidence, result)
