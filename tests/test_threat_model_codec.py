"""The plain-JSON codec of the threat-model contract records (T-107): the inverse of ``canonical``."""
from __future__ import annotations

import json
from typing import Any, Callable

import pytest

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.threat_model import codec
from appsec_review.threat_model.assemble import Assembly
from appsec_review.threat_model.contract import (
    Actor, Asset, Basis, Boundary, BoundaryKind, Element, ElementKind, EntryPoint, Fact, FactKind, Flow,
    InputLedgerRow, InputState, Interaction, LaneResult, Mitigation, MitigationState, NameBasis, Origin, Stride,
    Threat, ThreatState, UnknownKind, canonical, cite, element_id, unknown,
)
from tests.threat_model_support import SHA_A, SHA_B, record, span

UNIT = "native-cmake-0001"
SOURCE = record("job_tree_sitter_ast", "tree_sitter_ast", "ast_node", "asr:ast_node:" + "1" * 64,
                {"syntax": {"written_name": "recv"}}, at=span("src/net.c", 12, 14))
BUILD = record("job_target_catalog", "build_units", "build_action", "asr:build_action:" + "2" * 64)
LOCATED = cite(SOURCE, Basis.OBSERVED_SYNTAX, "interactions.callee")
PLAIN = cite(BUILD, Basis.DECLARED, "structure.declared_build_point")
PROCESS, PEER = element_id("proc", {"build_unit_id": UNIT, "name": "server"}), element_id("ext", "peer")
BOUNDARY, FLOW = element_id("tb", "network"), element_id("flow", "receive")
GAP = producer_gap(GapCode.INPUT_UNAVAILABLE, "job_code_graph_index/code_graph_facts has no accepted handoff",
                   unit_id="facts.interactions", scope_id="job_code_graph_index", retryable=True)

FACT = Fact(FactKind.PROCESS, {"build_unit_id": UNIT, "name": "server"}, "server", Basis.DECLARED, (PLAIN,), {
    "build_unit_id": UNIT, "artifact_path": None, "component_ids": ("component:0001",), "source_paths": ("src/net.c",),
    "source_roots": ("",), "built": False, "test_only": True})
INTERACTION = Fact(
    FactKind.INTERACTION, {"path": "src/net.c", "line": 12, "interaction": "network_receive"}, "recv",
    Basis.OBSERVED_SYNTAX, (LOCATED,), {
        "interaction": "network_receive", "path": "src/net.c", "source_class": None, "sink_class": None,
        "callee": "recv", "enclosing_symbol": "serve", "build_unit_id": UNIT, "component_id": None})
ENDS = {"input": {"build_unit_id": UNIT, "name": "net"}, "output": {"build_unit_id": UNIT, "name": "server"}}
LINK = Fact(FactKind.LINK, ENDS, "net -> server", Basis.DECLARED, (PLAIN,), ENDS)
UNKNOWN = unknown(UnknownKind.RUNTIME_ROLE_UNKNOWN, "role of server is not established", subject_ids=(PROCESS,),
                  would_resolve=("job_deployment_inventory/deployment_inventory",))
ROW = InputLedgerRow("job_tree_sitter_ast", "tree_sitter_ast", InputState.PARTIAL, SHA_A, "partial", 2, 17)
ELEMENT = Element(PROCESS, ElementKind.PROCESS, "server", NameBasis.DECLARED_NAME, Basis.DECLARED, (PLAIN, LOCATED),
                  {"built": False, "build_unit_id": UNIT, "artifact_path": None, "libraries": ("net",)},
                  ("component:0001",))
EXTERNAL = Element(PEER, ElementKind.EXTERNAL_ENTITY, "Remote network peer", NameBasis.DERIVED, Basis.DERIVED,
                   (LOCATED,), {"external_key": "remote_network_peer", "process": PROCESS})
FLOW_RECORD = Flow(FLOW, PEER, PROCESS, Interaction.NETWORK_RECEIVE, Basis.OBSERVED_SYNTAX, (LOCATED,), (BOUNDARY,),
                   None, {"direction": "inbound", "site_count": 1, "ownership": "source_path"})
BOUNDARY_RECORD = Boundary(BOUNDARY, BoundaryKind.NETWORK, (PROCESS,), Basis.DERIVED, (LOCATED,))
ENTRY = EntryPoint(element_id("ep", "receive"), PROCESS, Interaction.NETWORK_RECEIVE, None, "serve",
                   Basis.OBSERVED_SYNTAX, (LOCATED,))
ACTOR = Actor(element_id("actor", PEER), PEER, ("client_to_server", "peer_to_peer"), (LOCATED,))
ASSET = Asset(element_id("asset", "store"), "Session store", (PROCESS,), Basis.DECLARED, (PLAIN,))
THREAT = Threat(element_id("threat", "tampering"), ThreatState.CANDIDATE, Stride.TAMPERING, "network-receive-tampering",
                "Tampered input to server", "Is every length checked before use?", (PEER, PROCESS), (FLOW,),
                (BOUNDARY,), (LOCATED,), ("bounds are checked",), Mitigation(MitigationState.EVIDENCE_FOUND, (PLAIN,)),
                ({"catalog": "asvs", "id": "V1", "weights": [1, 2]},),
                {"attacker_positions": ["client_to_server"], "cwe": ["CWE-20"]})
ELABORATED = Threat(element_id("threat", "elaborated"), ThreatState.ELABORATED, Stride.SPOOFING, None, "t", "q", (), (),
                    (), (LOCATED,), (), Mitigation(MitigationState.NOT_EXAMINED))
ORIGIN = Origin("2026-11-12-0001", "attempt_0001", "target-sha256:" + "7" * 64,
                {"interaction_catalog_sha256": SHA_A, "threat_templates_sha256": SHA_B, "crosswalk_sha256": SHA_A})
ELABORATED_ORIGIN = Origin("r", "a", "s", {}, {"provider": "p", "model": "m", "guidance_bundle_sha256": SHA_B})
LANE = LaneResult((FACT, INTERACTION, LINK), (GAP,), (ROW,), (UNKNOWN,))
ASSEMBLY = Assembly((ELEMENT, EXTERNAL), (FLOW_RECORD,), (BOUNDARY_RECORD,), (ENTRY,), (ACTOR,), (UNKNOWN,), (GAP,))

RECORDS: dict[str, tuple[Any, Callable[[Any], Any]]] = {
    "actor": (ACTOR, codec.actor_from_plain),
    "assembly": (ASSEMBLY, codec.assembly_from_plain),
    "assembly-empty": (Assembly(), codec.assembly_from_plain),
    "asset": (ASSET, codec.asset_from_plain),
    "boundary": (BOUNDARY_RECORD, codec.boundary_from_plain),
    "element": (ELEMENT, codec.element_from_plain),
    "element-external": (EXTERNAL, codec.element_from_plain),
    "entry-point": (ENTRY, codec.entry_point_from_plain),
    "evidence-located": (LOCATED, codec.evidence_ref_from_plain),
    "evidence-plain": (PLAIN, codec.evidence_ref_from_plain),
    "fact-interaction": (INTERACTION, codec.fact_from_plain),
    "fact-link": (LINK, codec.fact_from_plain),
    "fact-process": (FACT, codec.fact_from_plain),
    "flow": (FLOW_RECORD, codec.flow_from_plain),
    "lane-result": (LANE, codec.lane_result_from_plain),
    "lane-result-empty": (LaneResult(), codec.lane_result_from_plain),
    "ledger-row": (ROW, codec.ledger_row_from_plain),
    "ledger-row-absent": (InputLedgerRow("job_x", "kind", InputState.NOT_REGISTERED), codec.ledger_row_from_plain),
    "mitigation": (Mitigation(MitigationState.NOT_FOUND_IN_EVIDENCE), codec.mitigation_from_plain),
    "origin": (ORIGIN, codec.origin_from_plain),
    "origin-elaborated": (ELABORATED_ORIGIN, codec.origin_from_plain),
    "publication": (LOCATED.publication, codec.publication_from_plain),
    "threat": (THREAT, codec.threat_from_plain),
    "threat-elaborated": (ELABORATED, codec.threat_from_plain),
    "threats": ((THREAT, ELABORATED), codec.threats_from_plain),
    "unknown": (UNKNOWN, codec.unknown_from_plain),
}


@pytest.mark.parametrize("name", sorted(RECORDS))
def test_from_plain_is_the_inverse_of_canonical(name: str) -> None:
    value, read = RECORDS[name]
    restored = read(json.loads(canonical(value)))
    assert restored == value and type(restored) is type(value)
    assert canonical(restored) == canonical(value)


def test_nested_values_come_back_as_the_contract_types() -> None:
    lane = codec.lane_result_from_plain(json.loads(canonical(LANE)))
    fact = lane.facts[0]
    assert fact.kind is FactKind.PROCESS and fact.basis is Basis.DECLARED and isinstance(fact.evidence, tuple)
    assert fact.evidence[0].basis is Basis.DECLARED and fact.evidence[0].publication == PLAIN.publication
    assert fact.attributes["component_ids"] == ("component:0001",), "arrays inside a frozen mapping are tuples"
    assert fact.native_identity == {"build_unit_id": UNIT, "name": "server"}
    with pytest.raises(TypeError):
        fact.attributes["built"] = True  # type: ignore[index]
    assert lane.ledger[0].state is InputState.PARTIAL and lane.unknowns[0].kind is UnknownKind.RUNTIME_ROLE_UNKNOWN
    assert lane.gaps == (GAP,) and isinstance(lane.gaps[0], dict)
    threat = codec.threat_from_plain(json.loads(canonical(THREAT)))
    assert threat.stride is Stride.TAMPERING and threat.mitigation.state is MitigationState.EVIDENCE_FOUND
    assert threat.related_controls[0]["weights"] == (1, 2) and threat.crosswalk["cwe"] == ("CWE-20",)
    flow = codec.flow_from_plain(json.loads(canonical(FLOW_RECORD)))
    assert flow.interaction is Interaction.NETWORK_RECEIVE and flow.crosses == (BOUNDARY,) and flow.data is None


REJECTED: dict[str, tuple[Callable[[Any], Any], Callable[[dict[str, Any]], Any]]] = {
    "extra-key": (codec.element_from_plain, lambda value: {**value, "trusted": True}),
    "missing-key": (codec.flow_from_plain, lambda value: {key: item for key, item in value.items() if key != "crosses"}),
    "not-an-object": (codec.fact_from_plain, lambda value: [value]),
    "ref-identity": (codec.evidence_ref_from_plain, lambda value: {**value, "entity_id": "asr:ast_node:" + "9" * 64}),
    "supplied-origin": (codec.origin_from_plain, lambda value: {**value, "target_supplied": True}),
    "text-for-array": (codec.boundary_from_plain, lambda value: {**value, "inside": "proc:0000000000000000"}),
    "uncited-element": (codec.element_from_plain, lambda value: {**value, "evidence": []}),
    "unknown-basis": (codec.element_from_plain, lambda value: {**value, "basis": "owner_statement"}),
    "unknown-identity": (codec.unknown_from_plain, lambda value: {**value, "statement": "edited"}),
    "unknown-state": (codec.ledger_row_from_plain, lambda value: {**value, "state": "verified"}),
}
SOURCES = {codec.element_from_plain: ELEMENT, codec.flow_from_plain: FLOW_RECORD, codec.fact_from_plain: FACT,
           codec.evidence_ref_from_plain: LOCATED, codec.boundary_from_plain: BOUNDARY_RECORD,
           codec.unknown_from_plain: UNKNOWN, codec.ledger_row_from_plain: ROW, codec.origin_from_plain: ORIGIN}


@pytest.mark.parametrize("name", sorted(REJECTED))
def test_a_changed_or_malformed_record_is_refused(name: str) -> None:
    read, change = REJECTED[name]
    with pytest.raises(ValueError):
        read(change(json.loads(canonical(SOURCES[read]))))
