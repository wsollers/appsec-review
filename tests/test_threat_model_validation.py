"""Citation resolution and document validation (T-107): demotion, cascade and rejected documents."""
from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from appsec_review.interchange import GapCode
from appsec_review.threat_model.assemble import Assembly
from appsec_review.threat_model.contract import (
    Basis, ElementKind, EvidenceRef, Fact, Interaction, Threat, UnknownKind, canonical, cite,
)
from appsec_review.threat_model.documents import build_documents
from appsec_review.threat_model.threats import enumerate_threats
from appsec_review.threat_model.validate import resolve_citations, validate_documents
from tests.test_threat_model_assembly import LIMITS, built, pid, process, reference, site
from tests.test_threat_model_documents import documents, origin, plains
from tests.threat_model_support import record


def _model(*facts: Fact) -> tuple[Assembly, tuple[Threat, ...]]:
    assembly = built(*facts)
    return assembly, enumerate_threats(assembly, reference(), LIMITS)[0]


def _failing(*facts: Fact) -> Any:
    failed = {item.ref for fact in facts for item in fact.evidence}
    return lambda item: item.ref not in failed


def _validated(assembly: Assembly, threats: tuple[Threat, ...], gaps: tuple[Any, ...]) -> None:
    """What validation returns must still be a publishable model."""
    validate_documents(*plains(build_documents(origin(), assembly, threats, (), gaps)))


def test_unresolved_citation_demotes_the_element_to_an_unknown_with_a_gap() -> None:
    server, stale = process("server", roots=("server/",)), process("stale", unit="unit-b", roots=("stale/",))
    assembly, threats = _model(server, stale, site(Interaction.NETWORK_RECEIVE, "server/net.c", 40))
    asked: list[str] = []

    def resolves(item: EvidenceRef) -> bool:
        asked.append(item.ref)
        return item.ref != stale.evidence[0].ref

    after, kept, gaps = resolve_citations(assembly, threats, resolves)

    cited = {item.ref for group in (assembly.elements, assembly.flows, assembly.boundaries, assembly.entry_points,
                                    assembly.actors, threats) for found in group for item in found.evidence}
    assert sorted(asked) == sorted(cited)  # once per distinct reference
    assert pid(stale) not in {item.id for item in after.elements} and pid(server) in {item.id for item in after.elements}
    (demoted,) = [item for item in after.unknowns if item.kind is UnknownKind.CITATION_UNRESOLVED]
    assert pid(stale) in demoted.statement and demoted.subject_ids == ()
    assert not [item for item in after.unknowns if pid(stale) in item.subject_ids]  # its own unknowns left with it
    (gap,) = gaps
    assert (gap["code"], gap["scope_id"], gap["unit_id"], gap["retryable"]) == (
        GapCode.LOCATION_UNRESOLVED.value, pid(stale), "validation.resolve_citations", False)
    assert "depend on it" not in gap["reason"]
    assert (after.flows, after.boundaries, after.entry_points, after.actors, kept) == (
        assembly.flows, assembly.boundaries, assembly.entry_points, assembly.actors, threats)
    _validated(after, kept, gaps)


def test_everything_resolving_changes_nothing() -> None:
    assembly, threats = _model(process("server"), site(Interaction.NETWORK_RECEIVE, "server/net.c", 40),
                               site(Interaction.DATASTORE_QUERY, "server/db.c", 7))

    assert resolve_citations(assembly, threats, lambda item: True) == (assembly, threats, ())


def test_partially_resolving_record_keeps_only_resolving_references() -> None:
    first, second = process("server"), process("server", entity="ent:second-reading")
    assembly, threats = _model(first, second)
    (before,) = assembly.elements
    assert len(before.evidence) == 2

    after, kept, gaps = resolve_citations(assembly, threats, _failing(second))

    (element,) = after.elements
    assert element.id == before.id and element.evidence == first.evidence
    assert gaps == () and kept == ()
    assert after.unknowns == assembly.unknowns


def test_removal_cascades_to_flows_boundaries_entry_points_and_threats() -> None:
    server, other = process("server", roots=("server/",)), process("other", unit="unit-b", roots=("other/",))
    assembly, threats = _model(server, other, site(Interaction.NETWORK_RECEIVE, "server/net.c", 40),
                               site(Interaction.DATASTORE_QUERY, "server/db.c", 7),
                               site(Interaction.FILE_READ, "other/load.c", 3))
    mine = [item for item in threats if pid(server) in item.element_ids]
    assert len(mine) == 6 and len(threats) == 6 + 4

    after, kept, gaps = resolve_citations(assembly, threats, _failing(server))

    assert [item.id for item in after.elements if item.kind is ElementKind.PROCESS] == [pid(other)]
    assert len(after.elements) == 2  # the other process and its file supplier; the store and the peer went too
    assert [flow.interaction for flow in after.flows] == [Interaction.FILE_READ]
    (boundary,) = after.boundaries
    assert after.flows[0].crosses == (boundary.id,) and boundary.inside == (pid(other),)
    assert [item.process for item in after.entry_points] == [pid(other)]
    assert [item.external_entity for item in after.actors] == [after.flows[0].source]
    assert kept == tuple(item for item in threats if pid(server) not in item.element_ids) and len(kept) == 4
    (gap,) = gaps  # the cascade is counted in the one gap, not reported as gaps
    assert gap["scope_id"] == pid(server)
    # two flows, the peer, the store, the network boundary, one entry point, one actor, six threats
    assert "13 records that depend on it were removed with it" in gap["reason"]
    assert [item.kind for item in after.unknowns if item.kind is UnknownKind.CITATION_UNRESOLVED] == [
        UnknownKind.CITATION_UNRESOLVED]
    assert not [item for item in after.unknowns if pid(server) in item.subject_ids]
    assert not [item for item in after.unknowns if item.kind is UnknownKind.DATASTORE_UNIDENTIFIED]
    _validated(after, kept, gaps)


def test_unresolved_crossing_evidence_removes_the_boundary_with_its_flow() -> None:
    server = process("server")
    receive, read = site(Interaction.NETWORK_RECEIVE, "server/net.c", 40), site(Interaction.FILE_READ, "server/cfg.c", 3)
    assembly, threats = _model(server, receive, read)

    after, kept, gaps = resolve_citations(assembly, threats, _failing(receive))

    assert [item.id for item in after.elements if item.kind is ElementKind.PROCESS] == [pid(server)]
    assert [flow.interaction for flow in after.flows] == [Interaction.FILE_READ]
    assert [item.kind.value for item in after.boundaries] == ["file_content"]
    assert all(item.flow_ids == (after.flows[0].id,) for item in kept) and len(kept) == 4
    demoted = {gap["scope_id"] for gap in gaps}
    removed_flow = next(flow for flow in assembly.flows if flow.interaction is Interaction.NETWORK_RECEIVE)
    assert removed_flow.id in demoted and removed_flow.source in demoted
    assert removed_flow.crosses[0] not in demoted  # the boundary is derived: removed by cascade, never demoted
    assert len(gaps) == 1 + 1 + 1 + 1 + 6  # flow, peer, entry point, actor and six threats cite the failed site
    assert sum("1 records that depend on it" in gap["reason"] for gap in gaps) == 1  # the boundary, counted once
    _validated(after, kept, gaps)


def _published() -> list[dict[str, Any]]:
    return [copy.deepcopy(item) for item in plains(documents())]


def test_valid_documents_pass() -> None:
    validate_documents(*_published())


def test_dangling_flow_endpoint_is_rejected() -> None:
    for end in ("source", "target"):
        dfd, model, evidence, result = _published()
        dfd["flows"][0][end] = "proc:" + "0" * 16
        with pytest.raises(ValueError, match=f"flow {dfd['flows'][0]['id']} {end} names proc:0000000000000000"):
            validate_documents(dfd, model, evidence, result)

    dfd, model, evidence, result = _published()
    crossing = next(flow for flow in dfd["flows"] if flow["crosses"])
    crossing["crosses"] = [crossing["source"]]
    with pytest.raises(ValueError, match="which is not a boundary"):
        validate_documents(dfd, model, evidence, result)


@pytest.mark.parametrize(("array", "field", "value", "message"), [
    ("actors", "external_entity", "ext:" + "0" * 16, "not an external entity"),
    ("entry_points", "process", "proc:" + "0" * 16, "not a process"),
    ("threats", "boundary_ids", ["tb:" + "0" * 16], "not a boundary"),
    ("threats", "element_ids", ["proc:" + "0" * 16], "not an element"),
    ("threats", "flow_ids", ["flow:" + "0" * 16], "not a flow"),
], ids=["actor", "entry-point", "threat-boundary", "threat-element", "threat-flow"])
def test_dangling_threat_model_reference_is_rejected(array: str, field: str, value: Any, message: str) -> None:
    dfd, model, evidence, result = _published()
    model[array][0][field] = value
    with pytest.raises(ValueError, match=message):
        validate_documents(dfd, model, evidence, result)


def test_boundary_member_must_exist_and_origins_must_agree() -> None:
    dfd, model, evidence, result = _published()
    dfd["boundaries"][0]["inside"] = ["proc:" + "0" * 16]
    with pytest.raises(ValueError, match="inside names proc:0000000000000000"):
        validate_documents(dfd, model, evidence, result)

    dfd, model, evidence, result = _published()
    result["origin"]["run_id"] = "another-run"
    with pytest.raises(ValueError, match="origin of the result document differs"):
        validate_documents(dfd, model, evidence, result)


def test_duplicate_ids_are_rejected() -> None:
    dfd, model, evidence, result = _published()
    dfd["elements"].insert(1, copy.deepcopy(dfd["elements"][0]))
    with pytest.raises(ValueError, match=f"repeats the id {dfd['elements'][0]['id']}"):
        validate_documents(dfd, model, evidence, result)

    dfd, model, evidence, result = _published()
    model["threats"].insert(1, copy.deepcopy(model["threats"][0]))
    with pytest.raises(ValueError, match="threat model document repeats the id threat:"):
        validate_documents(dfd, model, evidence, result)


def test_uncited_or_missing_evidence_reference_is_rejected() -> None:
    dfd, model, evidence, result = _published()
    missing = evidence["references"].pop(0)["ref"]
    with pytest.raises(ValueError, match=f"cites {missing}, which is not in the evidence document"):
        validate_documents(dfd, model, evidence, result)

    dfd, model, evidence, result = _published()
    extra = cite(record("job_target_catalog", "build_units", "build_action", "ent:nobody-cites-this"),
                 Basis.DECLARED, "structure.declared_build_point")
    evidence["references"] = sorted([*evidence["references"], json.loads(canonical(extra))],
                                    key=lambda item: item["ref"])
    with pytest.raises(ValueError, match=f"lists {extra.ref}, which no record cites"):
        validate_documents(dfd, model, evidence, result)

    dfd, model, evidence, result = _published()
    evidence["references"].insert(1, copy.deepcopy(evidence["references"][0]))
    with pytest.raises(ValueError, match=f"repeats the reference {evidence['references'][0]['ref']}"):
        validate_documents(dfd, model, evidence, result)


@pytest.mark.parametrize(("document", "array"), [
    (0, "boundaries"), (0, "elements"), (0, "flows"), (0, "unknowns"), (1, "actors"), (1, "entry_points"),
    (1, "threats"), (2, "references"), (3, "input_ledger"),
], ids=["boundaries", "elements", "flows", "dfd-unknowns", "actors", "entry-points", "threats", "references", "ledger"])
def test_unsorted_array_is_rejected(document: int, array: str) -> None:
    published = _published()
    assert len(published[document][array]) > 1
    published[document][array].reverse()
    with pytest.raises(ValueError, match="is not sorted at index"):
        validate_documents(*published)


def test_schema_violation_is_rejected_before_the_cross_checks() -> None:
    dfd, model, evidence, result = _published()
    del dfd["elements"][0]["evidence"][:]
    with pytest.raises(ValueError, match="violates its schema"):
        validate_documents(dfd, model, evidence, result)
