"""Deterministic threat enumeration (T-107): candidate threats from the real template catalog."""
from __future__ import annotations

import json

from appsec_review.interchange import GapCode
from appsec_review.threat_model.assemble import Assembly
from appsec_review.threat_model.contract import (
    Interaction, Limits, Mitigation, MitigationState, ThreatState, canonical, element_id,
)
from appsec_review.threat_model.threats import enumerate_threats
from tests.test_threat_model_assembly import LIMITS, built, process, reference, site


def _assembly() -> Assembly:
    return built(process("server"), site(Interaction.NETWORK_RECEIVE, "server/net.c", 40),
                 site(Interaction.NETWORK_RECEIVE, "server/net.c", 90), site(Interaction.NETWORK_CONNECT, "server/up.c", 9),
                 site(Interaction.ARGUMENT_READ, "server/main.c", 3), site(Interaction.DATASTORE_QUERY, "server/db.c", 7),
                 site(Interaction.FILE_WRITE, "server/log.c", 2))


def test_each_crossing_gets_exactly_the_templates_the_catalog_selects() -> None:
    assembly = _assembly()
    threats, gaps = enumerate_threats(assembly, reference(), LIMITS)

    kinds = {boundary.id: boundary.kind for boundary in assembly.boundaries}
    expected = 0
    for flow in assembly.flows:
        selected = {item.template_id: item for item in reference().templates_for(
            flow.interaction, kinds[flow.crosses[0]], flow.attributes["direction"])} if flow.crosses else {}
        raised = [item for item in threats if item.flow_ids == (flow.id,)]
        assert sorted(item.template_id for item in raised) == sorted(selected)
        for threat in raised:
            template = selected[threat.template_id]
            assert threat.id == element_id("threat", {"template": template.template_id, "flow": flow.id})
            assert (threat.state, threat.stride, threat.title, threat.question, threat.obligations) == (
                ThreatState.CANDIDATE, template.stride, template.title, template.question, template.obligations)
            assert threat.element_ids == tuple(sorted((flow.source, flow.target)))
            assert threat.boundary_ids == flow.crosses and threat.related_controls == ()
            assert json.loads(canonical(threat.crosswalk)) == {
                key: list(values) for key, values in reference().crosswalk_for(template.template_id).items()}
        expected += len(selected)
    assert len(threats) == expected and expected == 6 + 5 + 3  # receive, connect and argument templates
    assert [item.id for item in threats] == sorted(item.id for item in threats)
    assert gaps == ()


def test_candidate_threat_cites_the_flow_evidence() -> None:
    assembly = _assembly()
    threats, _ = enumerate_threats(assembly, reference(), LIMITS)

    flows = {flow.id: flow for flow in assembly.flows}
    assert threats
    for threat in threats:
        assert threat.evidence == flows[threat.flow_ids[0]].evidence and threat.evidence
    receive = next(flow for flow in assembly.flows if flow.interaction is Interaction.NETWORK_RECEIVE)
    assert len(receive.evidence) == 2  # both receive sites are cited by each of its threats


def test_mitigation_state_is_never_absent() -> None:
    threats, _ = enumerate_threats(_assembly(), reference(), LIMITS)

    assert threats and all(item.mitigation == Mitigation(MitigationState.NOT_EXAMINED) for item in threats)
    published = {json.loads(canonical(item))["mitigation"]["state"] for item in threats}
    assert published == {"not_examined"}
    # The closed vocabulary cannot claim that a control does not exist.
    assert {item.value for item in MitigationState} == {"evidence_found", "not_found_in_evidence", "not_examined"}


def test_attacker_position_is_offered_as_candidates_only() -> None:
    assembly = _assembly()
    threats, _ = enumerate_threats(assembly, reference(), LIMITS)

    assert assembly.actors
    by_peer = {actor.external_entity: actor for actor in assembly.actors}
    for peer, actor in by_peer.items():
        offered = {position for threat in threats if peer in threat.element_ids
                   for position in threat.crosswalk["attacker_positions"]}
        assert set(actor.attacker_position_candidates) == offered and offered
    for record in (*assembly.flows, *assembly.elements, *assembly.entry_points, *threats):
        published = json.loads(canonical(record))
        assert "attacker_position" not in published and "attacker_positions" not in published
        assert "attacker_position" not in published.get("attributes", {})
    for flow in assembly.flows:
        assert set(flow.attributes) == {"direction", "site_count", "ownership"}


def test_flows_without_a_crossing_yield_no_threat() -> None:
    assembly = built(process("server"), site(Interaction.DATASTORE_QUERY, "server/db.c", 7),
                     site(Interaction.FILE_WRITE, "server/log.c", 2))

    assert len(assembly.flows) == 2 and all(flow.crosses == () for flow in assembly.flows)
    assert enumerate_threats(assembly, reference(), LIMITS) == ((), ())


def test_threat_limit_reached_is_a_truncated_gap() -> None:
    assembly = _assembly()
    full, _ = enumerate_threats(assembly, reference(), LIMITS)
    threats, gaps = enumerate_threats(assembly, reference(), Limits(max_threats=2))

    assert threats == full[:2]
    (gap,) = gaps
    assert (gap["code"], gap["scope_id"], gap["unit_id"]) == (GapCode.TRUNCATED.value, "threats.max_threats",
                                                             "threats.enumerate")
    assert enumerate_threats(assembly, reference(), Limits(max_threats=len(full)))[1] == ()
