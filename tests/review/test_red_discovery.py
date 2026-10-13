"""Admission rules and normalization views of red-discovery-result/1 (design decision 10)."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable

import pytest

from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.accounting import exact_accounting
from appsec_review.review.ledger import project
from appsec_review.review.models import Lane, Predicate, RelationKind, Role
from appsec_review.review.red_discovery import (
    RedInvocation, RedOutputLimits, admission_errors, cited_entities, hypothesized_hops, proposal_citations,
    proposal_requests, summarize_lead,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = SchemaSet(ROOT / "docs" / "schemas" / "inference-security-review")
BASIS = "b" * 64
LEAD_A = "asr:tool_observation:" + "1" * 64
LEAD_B = "asr:tool_observation:" + "2" * 64
SINK = "asr:sink_site:" + "3" * 64
PATH = "asr:dataflow_path:" + "4" * 64
SPAN = "asr:source_span:" + "5" * 64
LIMITS = RedOutputLimits()


def invocation(role: Role = Role.RED_TEAM_ANALYST, leads=(LEAD_A, LEAD_B)) -> RedInvocation:
    return RedInvocation(role, 0, BASIS, tuple(leads))


def ref(local: str, entity: str, predicate: str = "affected_construct", relation: str = "supports") -> dict:
    return {"local_id": local, "entity_id": entity, "shard_id": None, "shard_sha256": None, "relation": relation,
            "predicate": predicate, "locator": {"kind": "unresolved", "reason": "re-resolved by the validator"}}


def result() -> dict[str, Any]:
    """A valid result: LEAD_A developed into p1 (with a partial taint path and a chain seed), LEAD_B not."""
    return {
        "schema": "appsec-review/red-discovery-result/1", "package": {"basis_sha256": BASIS},
        "role": "red_team_analyst", "round_id": "0", "result_status": "partial",
        "lead_accounting": [
            {"observation_id": LEAD_A, "outcome": "proposal", "proposal_ids": ["p1"], "gap_ids": [],
             "reason": "developed"},
            {"observation_id": LEAD_B, "outcome": "no_proposal", "proposal_ids": [], "gap_ids": [],
             "reason": "this lens found nothing to develop"}],
        "proposals": [{
            "local_id": "p1", "source_lead_ids": [LEAD_A], "affected_entities": [SINK],
            "statement": "the environment length bounds a memcpy into a fixed buffer",
            "mechanism": "unchecked length", "weakness": {"namespace": "CWE", "id": "CWE-120"},
            "security_predicate": "memory_corruption",
            "attacker_entry": {"entity_id": None, "control": "environment variable",
                               "preconditions": ["attacker_controls_environment_variable"]},
            "trigger": "set a long INPUT_LEN", "suspected_consequence": "stack overwrite",
            "assumptions": ["the debug build is deployed"], "evidence_ids": ["e-sink", "e-nominate"],
            "counterevidence_ids": ["e-guard"], "obligation_ids": ["o1"], "taint_path_ids": ["t1"]}],
        "proof_obligations": [{"local_id": "o1", "proposal_id": "p1", "predicate": "taint_continuity",
                               "question": "does getenv reach the length?", "candidate_evidence_ids": ["e-lead"]}],
        "taint_paths": [{
            "local_id": "t1", "proposal_id": "p1", "source_node": "src", "sink_node": "dst", "basis": "partial",
            "nodes": [{"local_id": "src", "role": "source", "entity_id": None, "description": "getenv"},
                      {"local_id": "mid", "role": "transform", "entity_id": PATH, "description": "length"},
                      {"local_id": "dst", "role": "sink", "entity_id": SINK, "description": "memcpy"}],
            "edges": [{"from_node": "src", "to_node": "mid", "kind": "data", "basis": "analyst_hypothesis",
                       "evidence_ids": ["e-lead"], "open_question": "is getenv the only writer?"},
                      {"from_node": "mid", "to_node": "dst", "kind": "data", "basis": "accepted_tool_path",
                       "evidence_ids": ["e-path"], "open_question": None}],
            "gap_ids": ["g1"]}],
        "chain_seeds": [{
            "local_id": "c1", "objective": "corrupt the stack",
            "steps": [{"local_id": "s1", "description": "set the variable", "proposal_id": None,
                       "prerequisite": "local shell", "resulting_state": "long length", "entity_ids": []},
                      {"local_id": "s2", "description": "overflow", "proposal_id": "p1",
                       "prerequisite": "long length", "resulting_state": "overwrite", "entity_ids": [SINK]}],
            "links": [{"from_step": "s1", "to_step": "s2", "continuity_dimensions": ["identity"],
                       "evidence_ids": [], "open_questions": []}],
            "gap_ids": []}],
        "evidence_refs": [ref("e-sink", SINK), ref("e-path", PATH, "source_to_sink_reachability"),
                          ref("e-lead", LEAD_A, "attacker_input_control"),
                          ref("e-guard", SPAN, "missing_or_ineffective_guard", "contradicts"),
                          ref("e-nominate", LEAD_A, "affected_construct", "nominates")],
        "evidence_requests": [{"local_id": "r1", "proposal_id": "p1", "predicate": "attacker_input_control",
                               "requested_kind": "dataflow", "scope_entity_ids": [PATH], "reason": "first hop"}],
        "gaps": [{"local_id": "g1", "kind": "unresolved", "scope": "getenv hop", "reason": "no accepted path"}],
    }


def test_the_example_is_schema_valid_and_admitted() -> None:
    assert SCHEMAS.errors("red-discovery-result", result()) == []
    assert admission_errors(result(), invocation(), LIMITS) == []


def _set(path: str, value: Any) -> Callable[[dict], None]:
    def mutate(document: dict) -> None:
        *parents, last = path.split(".")
        node: Any = document
        for part in parents:
            node = node[int(part)] if part.isdigit() else node[part]
        node[int(last) if last.isdigit() else last] = value
    return mutate


MUTATIONS = [
    # echo checks against the invocation
    ("echo_package", _set("package.basis_sha256", "c" * 64), "package echo"),
    ("echo_role", _set("role", "hypothesis_hunter"), "role echo"),
    ("echo_round", _set("round_id", "1"), "round echo"),
    # exact lead accounting
    ("lead_missing", lambda d: d["lead_accounting"].pop(1), "omits 1 package leads"),
    ("lead_twice", lambda d: d["lead_accounting"].append(copy.deepcopy(d["lead_accounting"][1])), "more than once"),
    ("lead_extra", _set("lead_accounting.1.observation_id", "asr:tool_observation:" + "9" * 64), "outside the package"),
    ("no_proposal_names_proposal", _set("lead_accounting.1.proposal_ids", ["p1"]), "names proposals"),
    ("blocked_without_gap", _set("lead_accounting.1.outcome", "blocked"), "blocked without naming a gap"),
    ("proposal_without_id", _set("lead_accounting.0.proposal_ids", []), "without a proposal id"),
    ("proposal_not_in_entry", lambda d: d["proposals"][0]["source_lead_ids"].append(LEAD_B), "missing from its source"),
    ("lead_analyst_without_lead", lambda d: (d["proposals"][0].update(source_lead_ids=[]),
                                             d["lead_accounting"][0].update(outcome="no_proposal", proposal_ids=[])),
     "names its lead"),
    ("unknown_gap", _set("lead_accounting.1.gap_ids", ["nope"]), "unknown gap"),
    # local-ID uniqueness
    ("duplicate_local", _set("gaps.0.local_id", "p1"), "not unique"),
    ("duplicate_node", _set("taint_paths.0.nodes.1.local_id", "src"), "repeats a node"),
    # reference closure
    ("unknown_evidence", _set("proposals.0.evidence_ids", ["e-sink", "e-missing"]), "unknown evidence e-missing"),
    ("support_cites_counter", _set("proposals.0.evidence_ids", ["e-guard"]), "relation is contradicts"),
    ("counter_cites_support", _set("proposals.0.counterevidence_ids", ["e-sink"]), "relation is supports"),
    ("obligation_unlisted", _set("proposals.0.obligation_ids", []), "not listed by its proposal"),
    ("path_unlisted", _set("proposals.0.taint_path_ids", []), "not listed by its proposal"),
    ("request_orphan", _set("evidence_requests.0.proposal_id", "p9"), "unknown proposal"),
    ("locator_backwards", _set("evidence_refs.0.locator", {"kind": "source_line", "path": "a.c", "file_sha256": "d" * 64,
                                                           "start_line": 9, "end_line": 3}), "ends before it starts"),
    # ordered, acyclic and cited taint edges
    ("taint_back_edge", _set("taint_paths.0.edges.1", {"from_node": "dst", "to_node": "mid", "kind": "data",
                                                       "basis": "accepted_tool_path", "evidence_ids": ["e-path"],
                                                       "open_question": None}), "not ordered forward"),
    ("taint_unknown_node", _set("taint_paths.0.edges.0.to_node", "elsewhere"), "unknown node"),
    ("observed_uncited", _set("taint_paths.0.edges.1.evidence_ids", []), "without a citation"),
    ("reported_with_hypothesis", _set("taint_paths.0.basis", "reported"), "hypothesized hop"),
    ("wrong_source_role", _set("taint_paths.0.source_node", "mid"), "source nodes"),
    # ordered and acyclic chain links
    ("chain_cycle", _set("chain_seeds.0.links.0", {"from_step": "s2", "to_step": "s1", "continuity_dimensions": [],
                                                   "evidence_ids": [], "open_questions": []}), "not ordered forward"),
    ("chain_unknown_step", _set("chain_seeds.0.links.0.to_step", "s9"), "unknown step"),
    ("chain_unknown_proposal", _set("chain_seeds.0.steps.0.proposal_id", "p9"), "unknown proposal"),
    # partial results name gaps
    ("partial_without_gaps", lambda d: (d.update(gaps=[]), d["taint_paths"][0].update(gap_ids=[])),
     "partial result must name"),
]


@pytest.mark.parametrize("name,mutate,expected", MUTATIONS, ids=[item[0] for item in MUTATIONS])
def test_each_admission_rule_rejects_its_violation(name: str, mutate, expected: str) -> None:
    document = result()
    mutate(document)
    assert SCHEMAS.errors("red-discovery-result", document) == [], "the violation must be schema-valid"
    errors = admission_errors(document, invocation(), LIMITS)
    assert any(expected in error for error in errors), errors


def test_reported_path_must_connect_source_to_sink() -> None:
    document = result()
    path = document["taint_paths"][0]
    path["basis"] = "reported"
    path["edges"] = [{"from_node": "mid", "to_node": "dst", "kind": "data", "basis": "accepted_tool_path",
                      "evidence_ids": ["e-path"], "open_question": None}]
    errors = admission_errors(document, invocation(), LIMITS)
    assert any("do not connect source to sink" in error for error in errors), errors
    path["edges"].insert(0, {"from_node": "src", "to_node": "mid", "kind": "data", "basis": "source_mapped_analysis",
                             "evidence_ids": ["e-lead"], "open_question": None})
    assert admission_errors(document, invocation(), LIMITS) == []


@pytest.mark.parametrize("limits,expected", [
    (RedOutputLimits(max_proposals=1, max_chain_seeds=1), None),
    (RedOutputLimits(max_text_chars=10), "text value has"),
    (RedOutputLimits(max_result_bytes=1024), "bytes; the limit"),
    (RedOutputLimits(max_path_nodes=2), "nodes; the limit"),
    (RedOutputLimits(max_chain_steps=1), "steps; the limit"),
    (RedOutputLimits(max_evidence_refs=4), "evidence_refs holds 5"),
    (RedOutputLimits(max_evidence_requests=1, max_gaps=1, max_obligations=1, max_taint_paths=1), None),
])
def test_closed_limits_come_from_the_resolved_configuration(limits: RedOutputLimits, expected: str | None) -> None:
    errors = admission_errors(result(), invocation(), limits)
    assert (errors == []) if expected is None else any(expected in error for error in errors), errors


def test_limits_are_typed_bounded_and_reject_unknown_keys() -> None:
    assert RedOutputLimits.from_mapping({"max_proposals": 3}).max_proposals == 3
    with pytest.raises(ValueError, match="unknown settings"):
        RedOutputLimits.from_mapping({"max_claims": 3}, "x.red_output")
    with pytest.raises(ValueError, match="x.red_output.max_proposals"):
        RedOutputLimits.from_mapping({"max_proposals": 33}, "x.red_output")
    with pytest.raises(ValueError):
        RedOutputLimits(max_gaps=0)


def test_a_hunter_may_propose_without_a_source_lead_but_still_accounts_for_every_lead() -> None:
    document = result()
    document.update(role="hypothesis_hunter")
    document["proposals"][0]["source_lead_ids"] = []
    document["lead_accounting"][0].update(outcome="no_proposal", proposal_ids=[])
    assert admission_errors(document, invocation(Role.HYPOTHESIS_HUNTER), LIMITS) == []
    assert admission_errors(document, invocation(Role.HYPOTHESIS_HUNTER, (LEAD_A,)), LIMITS)


def test_a_blocked_lead_names_its_gap() -> None:
    document = result()
    document["lead_accounting"][1].update(outcome="blocked", gap_ids=["g1"])
    assert admission_errors(document, invocation(), LIMITS) == []


# ------------------------------------------------------------------------------------------------ views


def test_citations_follow_observed_hops_but_never_hypothesized_ones() -> None:
    document = result()
    proposal = document["proposals"][0]
    citations = {item.local_id: item for item in proposal_citations(document, proposal)}
    # proposal evidence and counterevidence, plus the accepted_tool_path hop's citation
    assert set(citations) == {"e-sink", "e-nominate", "e-guard", "e-path"}
    assert citations["e-path"].via == "taint_edge" and citations["e-path"].predicate is Predicate.SOURCE_TO_SINK_REACHABILITY
    assert citations["e-sink"].kind is RelationKind.SUPPORTS
    assert citations["e-guard"].kind is RelationKind.QUALIFIES        # red has no contradiction authority
    assert citations["e-nominate"].kind is None                       # nominations never become relations
    assert "e-lead" not in citations                                  # cited only by an analyst_hypothesis hop
    assert hypothesized_hops(document, proposal) == 1
    # A citation reached directly and through a hop is counted once, as the proposal's own.
    proposal["evidence_ids"].append("e-lead")
    assert [item.via for item in proposal_citations(document, proposal) if item.local_id == "e-lead"] == ["proposal"]


def test_cited_entities_and_requests() -> None:
    document = result()
    proposal = document["proposals"][0]
    assert cited_entities(document, proposal) == {SINK, PATH, LEAD_A, SPAN}
    assert proposal_requests(document, "p1") == [{"predicate": "attacker_input_control", "requested_kind": "dataflow",
                                                  "anchors": [PATH]}]
    assert proposal_requests(document, "p2") == []


def test_lead_summary_never_reads_no_proposal_as_clean() -> None:
    assert summarize_lead(["no_proposal", "proposal"]) == "proposal"
    assert summarize_lead(["no_proposal", "blocked"]) == "blocked"
    assert summarize_lead(["no_proposal", "no_proposal"]) == "no_proposal"
    assert summarize_lead([]) == "unaccounted"


def test_lead_accounting_feeds_exact_accounting() -> None:
    projection = project([])
    packages = {"lead-pkg": Lane.LEAD, "hunt-pkg": Lane.HUNT}
    accounting = exact_accounting(projection, {}, packages, incomplete_gap_ratio=0.5, lead_accounting={
        "lead-pkg": {LEAD_A: {"outcome": "proposal"}},
        "hunt-pkg": {LEAD_A: {"outcome": "no_proposal"}, LEAD_B: {"outcome": "unaccounted"}}})
    assert accounting.exact
    lanes = {item["lane"]: item for item in accounting.to_json()["lanes"]}
    assert lanes["lead"]["leads_expected"] == 1 and lanes["lead"]["leads_by_outcome"]["proposal"] == 1
    assert lanes["hunt"]["leads_by_outcome"] == {"proposal": 0, "no_proposal": 1, "blocked": 0, "unaccounted": 1}
    broken = exact_accounting(projection, {}, packages, incomplete_gap_ratio=0.5, lead_accounting={
        "ghost-pkg": {LEAD_A: {"outcome": "proposal"}}, "lead-pkg": {LEAD_A: {"outcome": "clean"}}})
    assert {gap.reason for gap in broken.violations} == {"lead_package_unexpected", "lead_outcome_invalid"}


def test_the_repository_configuration_resolves_the_red_output_limits() -> None:
    from appsec_review.config import load_config

    settings = load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").typed_settings
    assert settings.red_output == RedOutputLimits()
    assert settings.as_document()["red_output"]["max_proposals"] == settings.red_output.max_proposals
