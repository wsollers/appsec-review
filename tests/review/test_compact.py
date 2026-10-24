"""Compact answers (``red-compact/1``, ``blue-compact/1``, ``verifier-compact/1``) and their expansion."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review import red_discovery
from appsec_review.review.compact import expand_blue, expand_red, expand_verifier
from appsec_review.review.evidence import classify, satisfies
from appsec_review.review.labels import LabelTable
from appsec_review.review.models import Admissibility, Predicate, Role
from appsec_review.review.red_discovery import RedInvocation, RedOutputLimits

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")


def _id(kind: str, digit: str) -> str:
    return f"asr:{kind}:{digit * 64}"


LEAD, SINK, GUARD = _id("tool_observation", "1"), _id("sink_site", "2"), _id("guard_fact", "3")
ENTRY, HOP, FUNCTION, TAG = _id("entry_point", "4"), _id("call_site", "5"), _id("symbol", "6"), _id("tag_assignment", "7")
OTHER_LEAD = _id("tool_observation", "8")
CLAIM = "claim-" + "a" * 64
BASIS = "b" * 64


def table() -> LabelTable:
    return LabelTable({"L1": LEAD, "L2": OTHER_LEAD, "K1": SINK, "G1": GUARD, "E1": ENTRY, "F1": HOP, "S1": FUNCTION,
                       "T1": TAG}, texts={"X1": "build_provenance: unavailable: no compile command for src/a.c"})


def invocation(*leads: str) -> RedInvocation:
    return RedInvocation(Role.RED_TEAM_ANALYST, 0, BASIS, tuple(leads or (LEAD,)))


def claim(**changes) -> dict:
    base = {"id": "c1", "leads": ["L1"], "cwe": "CWE-787", "security_predicate": "memory_corruption",
            "statement": "memcpy copies up to 65535 bytes into a 16 byte member.",
            "support": {"affected_construct": ["K1", "S1"], "attacker_input_control": ["E1"]},
            "counter": {"missing_or_ineffective_guard": ["G1"]}, "missing": ["X1"]}
    return {**base, **changes}


def red(answer: dict, *leads: str, labels: LabelTable | None = None):
    return expand_red(answer, labels or table(), invocation=invocation(*leads), schema_errors=SCHEMAS.errors)


def assert_admitted(expansion, *leads: str) -> dict:
    assert not expansion.errors, expansion.errors
    result = expansion.result
    assert SCHEMAS.errors("red-discovery-result", result) == []
    assert red_discovery.admission_errors(result, invocation(*leads), RedOutputLimits()) == []
    return result


# ------------------------------------------------------------------------------------------------ red


def test_red_affirmation_expands_into_the_existing_result_document() -> None:
    expansion = red({"claims": [claim()]})
    result = assert_admitted(expansion)
    assert result["schema"] == "appsec-review/red-discovery-result/1" and result["round_id"] == "0"
    assert result["package"] == {"basis_sha256": BASIS} and result["role"] == "red_team_analyst"
    [proposal] = result["proposals"]
    assert proposal["source_lead_ids"] == [LEAD] and proposal["weakness"] == {"namespace": "CWE", "id": "CWE-787"}
    assert proposal["affected_entities"] == [SINK, FUNCTION]
    refs = {item["local_id"]: item for item in result["evidence_refs"]}
    support = {(refs[name]["predicate"], refs[name]["entity_id"], refs[name]["relation"]) for name in proposal["evidence_ids"]}
    assert support == {("affected_construct", SINK, "supports"), ("affected_construct", FUNCTION, "supports"),
                       ("attacker_input_control", ENTRY, "supports")}
    assert [(refs[name]["predicate"], refs[name]["relation"]) for name in proposal["counterevidence_ids"]] == [
        ("missing_or_ineffective_guard", "qualifies")]               # red counterevidence is never a contradiction
    assert result["lead_accounting"] == [{"observation_id": LEAD, "outcome": "proposal", "proposal_ids": ["c1"],
                                          "gap_ids": [], "reason": "developed into a proposal"}]
    assert result["result_status"] == "partial" and result["gaps"][0]["scope"].startswith("build_provenance")


def test_expansion_is_deterministic_and_does_not_mutate_its_input() -> None:
    answer = {"claims": [claim()], "no_claim": []}
    before = copy.deepcopy(answer)
    assert red(answer).result == red(answer).result and answer == before


def test_an_omitted_lead_is_a_named_gap_never_a_clean_lead() -> None:
    expansion = red({"claims": []}, LEAD, OTHER_LEAD)
    result = assert_admitted(expansion, LEAD, OTHER_LEAD)
    assert {entry["outcome"] for entry in result["lead_accounting"]} == {"blocked"}
    assert len(result["gaps"]) == 2 and all(item["kind"] == "missing" for item in result["gaps"])
    assert any("not accounted for" in note for note in expansion.feedback)
    declared = red({"claims": [], "no_claim": [{"lead": "L1", "why": "no sink on this path"}],
                    "blocked": ["L2"]}, LEAD, OTHER_LEAD).result
    assert [entry["outcome"] for entry in declared["lead_accounting"]] == ["no_proposal", "blocked"]


def test_a_label_that_does_not_resolve_is_dropped_with_feedback_and_the_claim_loses_that_support() -> None:
    answer = {"claims": [claim(support={"affected_construct": ["K1", "K99", _id("sink_site", "9")]})]}
    expansion = red(answer)
    result = assert_admitted(expansion)
    assert [item["entity_id"] for item in result["evidence_refs"] if item["relation"] == "supports"] == [SINK]
    assert sum("does not resolve" in note for note in expansion.feedback) == 2
    # A raw identity the cell received resolves like its label.
    labels = table()
    labels.know([_id("sink_site", "9")])
    assert _id("sink_site", "9") in [item["entity_id"] for item in red(answer, labels=labels).result["evidence_refs"]]


def test_red_cannot_name_a_lead_outside_the_package() -> None:
    expansion = red({"claims": [claim(leads=["L1", "L2"])]})
    assert expansion.result["proposals"][0]["source_lead_ids"] == [LEAD]
    assert any("not a lead of this package" in note for note in expansion.feedback)


def test_a_claim_with_neither_affected_construct_nor_lead_is_rejected() -> None:
    expansion = red({"claims": [claim(leads=["L2"], support={})]})
    assert expansion.errors and expansion.result is None


# ------------------------------------------------------------------------------------------------ blue and verifier


def blue(answer: dict, labels: LabelTable | None = None):
    return expand_blue(answer, labels or table(), claim_id=CLAIM, task="blue_control", schema_errors=SCHEMAS.errors)


def test_blue_refutation_records_a_contradicts_relation_per_citation() -> None:
    expansion = blue({"claim": CLAIM, "stance": "contradicts", "predicate": "missing_or_ineffective_guard",
                      "cites": ["G1", "S1"], "why": "The guard at line 13 rejects short input."})
    result = expansion.result
    assert SCHEMAS.errors("blue-result", result) == []
    assert result["disposition"] == "contradicts" and result["task"] == "blue_control" and result["claim_id"] == CLAIM
    assert [(item["kind"], item["entity_id"]) for item in result["proposed_relations"]] == [
        ("contradicts", GUARD), ("contradicts", FUNCTION)]
    assert result["citations"] == {"missing_or_ineffective_guard": [GUARD, FUNCTION]}
    assert result["rationale"] == "The guard at line 13 rejects short input."


def test_a_contradiction_that_does_not_resolve_stays_unresolved() -> None:
    expansion = blue({"stance": "contradicts", "predicate": "missing_or_ineffective_guard", "cites": ["G77"], "why": "x"})
    assert expansion.result["disposition"] == "unresolved" and expansion.result["proposed_relations"] == []
    assert any("recorded as unresolved" in note for note in expansion.feedback)
    # A citation that resolves to an indirect row is recorded, but it can never satisfy a predicate (R3): the
    # contradiction does not stand unless the evidence rules say so.
    indirect = blue({"stance": "contradicts", "predicate": "missing_or_ineffective_guard", "cites": ["T1"], "why": "x"})
    [relation] = indirect.result["proposed_relations"]
    assert relation["kind"] == "contradicts"
    assert classify("tag_assignment", Predicate.MISSING_OR_INEFFECTIVE_GUARD) is Admissibility.INDIRECT


def test_blue_support_is_rejected_and_qualification_is_expanded() -> None:
    supports = blue({"stance": "supports", "predicate": "affected_construct", "cites": ["K1"], "why": "same sink"})
    assert supports.result is None and supports.errors
    nested = blue({"stance": "unresolved", "per_predicate": {
        "affected_construct": {"stance": "supports", "cites": ["K1"]}}})
    assert nested.result is None and nested.errors
    qualifies = blue({"stance": "qualifies", "predicate": "attacker_input_control", "cites": ["E1"], "why": "only local"})
    assert qualifies.result["proposed_relations"][0]["kind"] == "qualifies"
    assert SCHEMAS.errors("blue-result", qualifies.result) == []


def test_blue_answers_for_its_own_claim_and_has_no_poc_basis() -> None:
    # The cell is bound to one claim: the application fills claim_id whatever the answer calls it.
    assert blue({"claim": "c1", "stance": "unresolved"}).result["claim_id"] == CLAIM
    rejected = blue({"stance": "unresolved", "poc_basis": {"entry": ["E1"]}})
    assert rejected.result is None and any("poc_basis" in error for error in rejected.errors)


def verifier(answer: dict, labels: LabelTable | None = None):
    return expand_verifier(answer, labels or table(), claim_id=CLAIM, schema_errors=SCHEMAS.errors)


def test_verifier_confirm_refute_and_unresolved() -> None:
    confirm = verifier({"disposition": "confirmed", "per_predicate": {
        "affected_construct": {"stance": "supports", "cites": ["K1"]},
        "attacker_input_control": {"stance": "supports", "cites": ["E1"]}}, "why": "re-resolved both"}).result
    assert SCHEMAS.errors("verifier-result", confirm) == []
    assert confirm["proposed_disposition"] == "confirmed"
    assert {(item["predicate"], item["kind"]) for item in confirm["proposed_relations"]} == {
        ("affected_construct", "supports"), ("attacker_input_control", "supports")}
    refute = verifier({"disposition": "contradicted", "per_predicate": {
        "missing_or_ineffective_guard": {"stance": "contradicts", "cites": ["G1"], "why": "dominating bound"}}}).result
    assert [item["kind"] for item in refute["proposed_relations"]] == ["contradicts"]
    open_ = verifier({"disposition": "insufficient_evidence", "per_predicate": {
        "missing_or_ineffective_guard": {"stance": "unresolved", "cites": ["G1", "S1"],
                                         "missing": ["the guard does not mention the destination capacity"]}}}).result
    assert open_["proposed_relations"] == [] and open_["citations"]["missing_or_ineffective_guard"] == [GUARD, FUNCTION]
    assert "destination capacity" in open_["rationale"]
    assert SCHEMAS.errors("verifier-result", open_) == []


def test_a_verifier_stance_without_a_resolvable_citation_is_unresolved() -> None:
    expansion = verifier({"disposition": "supported", "per_predicate": {
        "affected_construct": {"stance": "supports", "cites": ["K404"]}}})
    assert expansion.result["proposed_relations"] == [] and expansion.feedback


# ------------------------------------------------------------------------------------------------ poc_basis


def basis(**changes) -> dict:
    base = {"entry": ["E1"], "path": ["F1"], "input_format": "length-prefixed header, then name bytes",
            "trigger": [{"field": "header.length", "where": "bytes 2..3", "constraint": "greater than 16",
                         "why": "exceeds out.name capacity"}],
            "preconditions": ["attacker_controls_file_content", "the file is opened by the relay"],
            "expected_observation": "AddressSanitizer stack-buffer-overflow WRITE in memcpy",
            "unknowns": ["X1"]}
    return {**base, **changes}


def test_poc_basis_is_expanded_into_closed_fields_and_a_bounded_brief() -> None:
    result = assert_admitted(red({"claims": [claim(poc_basis=basis())]}))
    [proposal] = result["proposals"]
    assert proposal["attacker_entry"]["entity_id"] == ENTRY
    assert proposal["attacker_entry"]["preconditions"] == ["attacker_controls_file_content"]
    brief = proposal["poc_basis"]
    assert brief["entry"] == [ENTRY] and brief["path"] == [HOP]
    assert brief["unknowns"] == ["build_provenance: unavailable: no compile command for src/a.c"]
    assert brief["preconditions"][1] == "the file is opened by the relay"
    assert brief["trigger"][0] == {"field": "header.length", "where": "bytes 2..3", "constraint": "greater than 16",
                                   "why": "exceeds out.name capacity"}


def test_poc_basis_labels_that_do_not_resolve_or_have_the_wrong_kind_are_dropped() -> None:
    expansion = red({"claims": [claim(poc_basis=basis(entry=["E1", "E9", "K1"], path=["F1", "G1"], unknowns=["X1", "X9"]))]})
    brief = assert_admitted(expansion)["proposals"][0]["poc_basis"]
    assert brief["entry"] == [ENTRY] and brief["path"] == [HOP] and len(brief["unknowns"]) == 1
    assert sum("poc_basis" in note for note in expansion.feedback) >= 3


def test_poc_basis_bounds_are_enforced_by_the_compact_schema() -> None:
    long = "x" * 241
    for changed in (basis(input_format=long), basis(expected_observation=long), basis(preconditions=[long]),
                    basis(trigger=[{"field": long, "where": "w", "constraint": "c", "why": "y"}]),
                    basis(entry=["E1"] * 9), basis(path=[f"F{n}" for n in range(1, 18)]),
                    basis(trigger=[{"field": "f", "where": "w", "constraint": "c"}])):
        expansion = red({"claims": [claim(poc_basis=changed)]})
        assert expansion.result is None and expansion.errors, changed


def test_a_poc_basis_without_an_entry_point_becomes_a_named_gap() -> None:
    expansion = red({"claims": [claim(poc_basis=basis(entry=[]))]})
    result = assert_admitted(expansion)
    assert result["proposals"][0]["attacker_entry"]["entity_id"] is None
    assert any("no entry point is cited" in item["scope"] for item in result["gaps"])
    unreachable = red({"claims": [claim(poc_basis=basis(entry=["E9"]))]}).result
    assert any("no entry point is cited" in item["scope"] for item in unreachable["gaps"])


def test_the_compact_schemas_are_closed() -> None:
    assert SCHEMAS.errors("red-compact", {"claims": [], "extra": 1})
    assert SCHEMAS.errors("red-compact", {"claims": [claim(security_predicate="not_a_predicate")]})
    assert SCHEMAS.errors("verifier-compact", {"disposition": "maybe", "per_predicate": {}})
    assert SCHEMAS.errors("blue-compact", {"stance": "contradicts", "extra": 1})
    assert not SCHEMAS.errors("blue-compact", {"schema": "appsec-review/blue-compact/1", "stance": "unresolved"})


def test_a_claim_may_use_any_local_id_without_colliding_with_named_gaps() -> None:
    result = assert_admitted(red({"claims": [claim(id="g1", missing=["X1"]), claim(id="g2", missing=["X1"])]}))
    ids = [item["local_id"] for item in result["proposals"]] + [item["local_id"] for item in result["gaps"]]
    assert len(ids) == len(set(ids)) and {"g1", "g2"} <= set(ids)


def investigation_path(*, basis: str = "accepted_tool_path", cites: list[str] | None = None) -> dict:
    return {"source": "input", "sink": "copy", "nodes": [
        {"id": "input", "role": "source", "label": "E1", "why": "file input"},
        {"id": "copy", "role": "sink", "label": "K1", "why": "copy length"}],
        "edges": [{"from": "input", "to": "copy", "kind": "data", "basis": basis,
                   "cites": ["F1"] if cites is None else cites}]}


def request(**changes) -> dict:
    return {"predicate": "configuration_enables", "requested_kind": "configuration", "anchors": ["S1"],
            "question": "Which deployed profile enables this route?", "specialist": "cloud_container_deployment",
            **changes}


def test_investigation_details_survive_expansion_and_admission() -> None:
    answer = {"claims": [claim(id="e1", missing=[], taint_paths=[investigation_path()],
                              obligations=[{"predicate": "missing_or_ineffective_guard",
                                            "question": "Does this guard bound the destination?", "cites": ["G1"]}],
                              evidence_requests=[request()])]}
    result = assert_admitted(red(answer))
    [proposal] = result["proposals"]
    [obligation] = result["proof_obligations"]
    [path] = result["taint_paths"]
    assert proposal["obligation_ids"] == [obligation["local_id"]]
    assert proposal["taint_path_ids"] == [path["local_id"]]
    assert path["basis"] == "reported"
    assert {node["entity_id"] for node in path["nodes"]} == {ENTRY, SINK}
    assert any(cite.via == "taint_edge" and cite.entity_id == HOP
               for cite in red_discovery.proposal_citations(result, proposal))
    assert red_discovery.proposal_requests(result, "e1") == [{
        "predicate": "missing_or_ineffective_guard", "requested_kind": "other", "anchors": [SINK, FUNCTION],
        "question": "Does this guard bound the destination?"},
        {
        "predicate": "configuration_enables", "requested_kind": "configuration", "anchors": [FUNCTION],
        "question": request()["question"], "specialist": "cloud_container_deployment"}]
    ids = [item["local_id"] for key in ("proposals", "proof_obligations", "taint_paths", "evidence_refs",
                                      "evidence_requests", "gaps") for item in result[key]]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("basis,cites", [
    ("analyst_hypothesis", ["F1"]), ("accepted_tool_path", []), ("source_mapped_analysis", ["F99"])])
def test_unproven_hop_stays_hypothetical_with_request_and_gap(basis: str, cites: list[str]) -> None:
    result = assert_admitted(red({"claims": [claim(missing=[], taint_paths=[investigation_path(basis=basis, cites=cites)])]}))
    [path] = result["taint_paths"]
    assert path["basis"] == "hypothesized" and path["gap_ids"]
    assert path["edges"][0]["basis"] == "analyst_hypothesis"
    assert result["evidence_requests"][0]["requested_kind"] == "dataflow"
    assert result["evidence_requests"][0]["scope_entity_ids"] == [ENTRY, SINK]
    assert result["result_status"] == "partial"
    assert not any(cite.via == "taint_edge" for cite in
                   red_discovery.proposal_citations(result, result["proposals"][0]))


def test_missing_obligation_evidence_opens_a_request_without_asserting_support() -> None:
    result = assert_admitted(red({"claims": [claim(missing=[], obligations=[
        {"predicate": "security_impact", "question": "What privilege does this worker hold?", "cites": []}])]}))
    assert result["proof_obligations"][0]["candidate_evidence_ids"] == []
    assert result["evidence_requests"][0]["predicate"] == "security_impact"
    assert result["gaps"]


@pytest.mark.parametrize("role", ["blue", "verifier"])
def test_challenge_requests_preserve_scope_question_and_specialist(role: str) -> None:
    body = {"stance": "unresolved"} if role == "blue" else {"disposition": "insufficient_evidence", "per_predicate": {}}
    invoke = blue if role == "blue" else verifier
    expansion = invoke({**body, "evidence_requests": [request()]})
    assert not expansion.errors
    assert expansion.result["evidence_requests"] == [{**request(), "anchors": [FUNCTION]}]
    assert SCHEMAS.errors(f"{role}-result", expansion.result) == []
    assert invoke({**body, "evidence_requests": [request(anchors=["S99"])]}).errors
    assert invoke({**body, "evidence_requests": [request(specialist="unregistered_agent")]}).errors


def test_chain_seed_is_preserved_but_is_not_evidence_for_an_accepted_chain() -> None:
    seed = {"objective": "Cross two trust boundaries", "steps": [
        {"id": "first", "claim": "c1", "description": "Read the record", "prerequisite": "ordinary account",
         "resulting_state": "record known", "anchors": ["S1"]},
        {"id": "second", "claim": None, "description": "Use the record in a worker", "prerequisite": "record known",
         "resulting_state": "unknown worker effect", "anchors": ["K1"]}],
        "links": [{"from": "first", "to": "second", "continuity_dimensions": ["identity"],
                   "cites": [], "questions": ["Does the worker consume the same record?"]}]}
    result = assert_admitted(red({"claims": [claim()], "chain_seeds": [seed]}))
    [expanded] = result["chain_seeds"]
    assert expanded["steps"][0]["proposal_id"] == "c1"
    assert expanded["steps"][0]["entity_ids"] == [FUNCTION]
    assert expanded["links"][0]["open_questions"] == ["Does the worker consume the same record?"]
    assert expanded["gap_ids"]


def test_path_topology_and_configured_output_limits_are_still_enforced() -> None:
    path = investigation_path()
    path["edges"][0]["to"] = "unknown"
    result = red({"claims": [claim(taint_paths=[path])]}).result
    assert any("unknown node" in error for error in red_discovery.admission_errors(result, invocation(), RedOutputLimits()))
    valid_result = red({"claims": [claim(evidence_requests=[request(), request(question="Is the feature enabled?")])]}).result
    assert any("evidence_requests" in error for error in red_discovery.admission_errors(
        valid_result, invocation(), RedOutputLimits(max_evidence_requests=1)))
