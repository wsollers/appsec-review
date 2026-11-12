"""The shared contract of the generated DFD and threat model (T-107): ids, bytes, closed records."""
from __future__ import annotations

from dataclasses import replace

import pytest

from appsec_review.interchange import GAP_SCHEMA, GapCode
from appsec_review.threat_model import contract
from appsec_review.threat_model.contract import (
    Basis, Boundary, BoundaryKind, Element, ElementKind, Fact, FactKind, Flow, InputState, Interaction, Limits,
    Mitigation, MitigationState, NameBasis, Origin, Stride, Threat, ThreatState, UnknownKind, canonical, cite,
    element_id, merge_evidence, strongest, unknown,
)
from appsec_review.threat_model.view import open_input, truncated_gap
from tests.threat_model_support import SHA_A, FakeEvidenceView, record, span

ENUMS = sorted(name for name in ("Basis", "BoundaryKind", "ElementKind", "FactKind", "InputState", "Interaction",
                                 "MitigationState", "NameBasis", "Stride", "ThreatState", "UnknownKind"))


def _ref(entity_id: str = "artifact:server", basis: Basis = Basis.DECLARED, *, line: int = 3):
    return cite(record("job_target_catalog", "build_units", "build_unit", entity_id, at=span("server/main.c", line)),
                basis, "test.rule")


def _process(name: str = "server") -> Element:
    return Element(element_id("proc", ["unit", name]), ElementKind.PROCESS, name, NameBasis.ARTIFACT_NAME,
                   Basis.DECLARED, (_ref(),))


def test_element_ids_are_stable_and_independent_of_content_hashes() -> None:
    first = element_id("proc", {"build_unit_id": "unit-1", "artifact_path": "bin/server"})
    again = element_id("proc", {"artifact_path": "bin/server", "build_unit_id": "unit-1"})
    assert first == again and first.startswith("proc:") and len(first) == len("proc:") + 16
    assert element_id("store", {"build_unit_id": "unit-1", "artifact_path": "bin/server"}) != first
    assert element_id("proc", {"build_unit_id": "unit-2", "artifact_path": "bin/server"}) != first
    changed_file = cite(record("job_target_catalog", "build_units", "build_unit", "artifact:server",
                               at=span("server/main.c", 3, file_sha256="d" * 64)), Basis.DECLARED, "test.rule")
    assert changed_file.ref != _ref().ref, "a citation names the bytes it cites"
    assert _process().id == replace(_process(), evidence=(changed_file,)).id, "an element id does not"


def test_canonical_bytes_do_not_depend_on_insertion_order() -> None:
    assert canonical({"b": [1, 2], "a": {"y": None, "x": "é"}}) == canonical({"a": {"x": "é", "y": None}, "b": [1, 2]})
    assert canonical(_process()) == canonical(_process())
    assert canonical({"a": 1}) == b'{"a":1}\n'


def test_an_element_without_evidence_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one evidence reference"):
        Element(element_id("proc", "x"), ElementKind.PROCESS, "x", NameBasis.DERIVED, Basis.DERIVED, ())
    process = _process()
    with pytest.raises(ValueError, match="at least one evidence reference"):
        Flow(element_id("flow", "f"), process.id, process.id, Interaction.FILE_READ, Basis.DERIVED, ())
    with pytest.raises(ValueError, match="at least one evidence reference"):
        Boundary(element_id("tb", "b"), BoundaryKind.NETWORK, (process.id,), Basis.DERIVED, ())
    with pytest.raises(ValueError, match="at least one evidence reference"):
        Fact(FactKind.PROCESS, "x", "x", Basis.DECLARED, ())


@pytest.mark.parametrize("name", ENUMS)
def test_closed_vocabularies_reject_unknown_values(name: str) -> None:
    vocabulary = getattr(contract, name)
    assert len(set(vocabulary)) == len(list(vocabulary)) > 1
    with pytest.raises(ValueError):
        vocabulary("not-a-member")


def test_records_refuse_values_outside_their_vocabularies() -> None:
    with pytest.raises(ValueError):
        Element(element_id("proc", "x"), "process", "x", NameBasis.DERIVED, Basis.DERIVED, (_ref(),))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        Fact(FactKind.INTERACTION, "x", "x", Basis.OBSERVED_SYNTAX, (_ref(),), {"interaction": "teleport"})
    with pytest.raises(ValueError, match="names its template"):
        Threat(element_id("threat", "t"), ThreatState.CANDIDATE, Stride.TAMPERING, None, "t", "q?", (), (), (),
               (_ref(),), (), Mitigation(MitigationState.NOT_EXAMINED))
    with pytest.raises(ValueError, match="exactly when evidence was found"):
        Mitigation(MitigationState.EVIDENCE_FOUND)
    with pytest.raises(ValueError, match="exactly when evidence was found"):
        Mitigation(MitigationState.NOT_FOUND_IN_EVIDENCE, (_ref(),))
    assert "absent" not in {item.value for item in MitigationState}


def test_origin_always_says_generated_and_not_target_supplied() -> None:
    origin = Origin("run", "attempt", "snapshot", {"interaction_catalog_sha256": SHA_A})
    assert (origin.kind, origin.target_supplied, origin.authority, origin.model) == (
        "generated", False, "routing_context", None)
    for change in ({"target_supplied": True}, {"kind": "supplied"}, {"authority": "producer_evidence"},
                   {"producer": "job_target_catalog"}):
        with pytest.raises(ValueError, match="never target-supplied"):
            replace(origin, **change)


def test_evidence_merges_strongest_first_deduplicated_and_bounded() -> None:
    syntax, semantic = _ref(basis=Basis.OBSERVED_SYNTAX, line=9), _ref("graph:entry", Basis.VERIFIED_SEMANTIC)
    merged = merge_evidence((syntax, semantic), (syntax,), limit=8)
    assert [item.basis for item in merged] == [Basis.VERIFIED_SEMANTIC, Basis.OBSERVED_SYNTAX]
    assert merge_evidence((syntax, semantic), limit=1) == (semantic,)
    assert strongest(Basis.OBSERVED_SYNTAX, Basis.DECLARED) is Basis.DECLARED


def test_unknowns_are_identified_by_their_content() -> None:
    first = unknown(UnknownKind.RUNTIME_ROLE_UNKNOWN, "role of server is not established",
                    subject_ids=("proc:0123456789abcdef",), would_resolve=("b", "a", "a"))
    assert first.would_resolve == ("a", "b")
    assert first == unknown(UnknownKind.RUNTIME_ROLE_UNKNOWN, "role of server is not established",
                            subject_ids=("proc:0123456789abcdef",), would_resolve=("a", "b"))


def test_limits_are_bounded_integers() -> None:
    assert Limits().max_query_rows == 2000
    for value in (0, -1, 100_001, True, "5"):
        with pytest.raises(ValueError):
            Limits(max_flows=value)  # type: ignore[arg-type]


@pytest.mark.parametrize(("state", "readable", "code", "retryable"), [
    (InputState.ABSENT, False, GapCode.INPUT_UNAVAILABLE, True),
    (InputState.DISABLED, False, GapCode.INPUT_UNAVAILABLE, False),
    (InputState.EMPTY, False, GapCode.OUTPUT_MISSING, True),
    (InputState.NOT_REGISTERED, False, GapCode.INPUT_UNAVAILABLE, False),
    (InputState.PARTIAL, True, GapCode.PRODUCER_REPORTED_GAP, True),
], ids=["absent", "disabled", "empty", "not_registered", "partial"])
def test_every_unusable_input_state_is_one_named_producer_gap(state, readable, code, retryable) -> None:
    view = FakeEvidenceView().set_status("job_code_graph_index", "code_graph_facts", state, upstream_gap_count=2)
    opened = open_input(view, "job_code_graph_index", "code_graph_facts", unit_id="facts.interactions")
    assert opened.readable is readable and opened.row.state is state
    (gap,) = opened.gaps
    assert (gap["schema"], gap["code"], gap["retryable"], gap["unit_id"]) == (
        GAP_SCHEMA, code.value, retryable, "facts.interactions")
    assert "job_code_graph_index" in gap["reason"]


def test_a_read_input_has_no_gap_and_a_reached_bound_names_its_query() -> None:
    view = FakeEvidenceView().add(record("job_target_catalog", "build_units", "build_unit", "u1"))
    opened = open_input(view, "job_target_catalog", "build_units", unit_id="facts.structure")
    assert opened.readable and opened.gaps == () and opened.row.state is InputState.READ
    gap = truncated_gap("graph.entry_point", 5, unit_id="facts.interactions")
    assert (gap["code"], gap["scope_id"]) == (GapCode.TRUNCATED.value, "graph.entry_point")
    page = view.entities("job_target_catalog", "build_units", "build_unit", limit=1)
    assert len(page.records) == 1 and page.truncated is False
