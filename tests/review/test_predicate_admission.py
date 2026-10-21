"""Predicate admission (``predicate-admission/1``): a genuine citation is not evidence for every predicate.

Authenticity (the citation resolves), relevance (this kind of content can bear on this predicate) and
support (it establishes the proposition) are separate. Every cell of the (kind x predicate) table is
written out literally here, independent of ``review.admission``, so a change to the policy is a
visible change to this file.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.graph.contract import Family
from appsec_review.jobs.job_inference_security_review import job as review_job
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.review import admission, obligations, tool_rules
from appsec_review.review.adjudication import DecidingRow, PredicateOutcome, adjudicate
from appsec_review.review.claims import normalize_claim
from appsec_review.review.evidence import DIRECT_KINDS, classify, resolve_relation, satisfies
from appsec_review.review.identity import make_id
from appsec_review.review.models import (
    Admissibility, ClaimState, EvidenceRelation, Lane, Predicate, RelationKind,
)
from tests.review.test_evidence import _accepted_fixture, _ident
from tests.review.test_graph_admissibility import RECEIPT, RUN_ID, accepted_graph_run

P = Predicate
D, A, I = Admissibility.DIRECT, Admissibility.ANALYST_ASSESSED, Admissibility.INDIRECT
ORDER = (P.AFFECTED_CONSTRUCT, P.ATTACKER_INPUT_CONTROL, P.SOURCE_TO_SINK_REACHABILITY,
         P.MISSING_OR_INEFFECTIVE_GUARD, P.CONFIGURATION_ENABLES, P.SECURITY_IMPACT)
#                              AC AIC S2S GRD CFG IMP
EXPECTED = {
    "source_span":       (D, A, A, A, A, A),
    "ast_node":          (D, A, A, A, A, A),
    "symbol":            (D, A, A, A, I, A),
    "ir_entity":         (D, A, A, A, I, I),
    "build_action":      (D, I, I, I, D, I),
    "compile_unit":      (D, I, I, I, D, I),
    "object_file":       (D, I, I, I, I, I),
    "library":           (D, I, I, I, I, I),
    "executable":        (D, I, I, I, A, I),
    "build_artifact":    (D, I, I, I, A, I),
    "package":           (D, I, I, I, I, I),
    "archive_member":    (D, I, I, I, I, I),
    "bytecode_module":   (D, I, I, I, I, I),
    "managed_assembly":  (D, I, I, I, I, I),
    "wasm_module":       (D, I, I, I, I, I),
    "evidence_artifact": (D, A, A, A, A, A),
}
CELLS = [(kind, predicate, row[index]) for kind, row in sorted(EXPECTED.items())
         for index, predicate in enumerate(ORDER)]


def test_the_literal_table_covers_exactly_the_admitted_kinds() -> None:
    assert {EntityKind(kind) for kind in EXPECTED} == DIRECT_KINDS == admission.ADMITTED_KINDS
    assert set(ORDER) == set(Predicate) and admission.COLUMNS == ORDER


@pytest.mark.parametrize(("kind", "predicate", "expected"), CELLS, ids=[f"{k}-{p.value}" for k, p, _ in CELLS])
def test_every_cell_of_the_admission_table(kind: str, predicate: Predicate, expected: Admissibility) -> None:
    assert admission.admission(kind, predicate) is expected
    assert classify(kind, predicate) is expected
    # A tool-rule mapping never widens a structured-content kind.
    assert classify(kind, predicate, tuple(Predicate)) is expected


def test_no_kind_is_direct_for_security_impact_and_source_content_is_direct_only_for_the_construct() -> None:
    assert all(classify(kind, P.SECURITY_IMPACT) is not D for kind in DIRECT_KINDS)
    for kind in ("source_span", "symbol", "ast_node", "ir_entity"):
        assert {p for p in Predicate if classify(kind, p) is D} == {P.AFFECTED_CONSTRUCT}
    for kind in ("package", "archive_member"):       # component presence only
        assert {p for p in Predicate if classify(kind, p) is not I} == {P.AFFECTED_CONSTRUCT}


def test_configuration_is_direct_only_for_build_configuration_facts() -> None:
    assert {kind for kind in DIRECT_KINDS if classify(kind, P.CONFIGURATION_ENABLES) is D} == {
        EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT}


def test_the_table_hash_and_version_are_pinned_in_the_obligation_policy() -> None:
    document = obligations._policy_document()
    assert document["predicate_admission"] == {"version": "predicate-admission/1",
                                               "table_sha256": admission.TABLE_SHA256}
    assert review_job.EVIDENCE_RULES["predicate_admission"] == "predicate-admission/1"
    assert review_job.EVIDENCE_RULES["rule_predicates"] == "tool-rule-predicates/2"
    assert obligations.POLICY_SHA256 == obligations.sha256_hex(document)


# ------------------------------------------------------------------------------------------------
# Adjudication: relevant-but-unsupported citations never satisfy an obligation

ENTITY = LogicalIdentity.derive(EntityKind.SYMBOL, "snap", {"n": "relay::parse_header"}).value
CLAIM = normalize_claim(lane=Lane.LEAD, package_id="p", affected_entities=[ENTITY], weakness_cwe="CWE-120",
                        security_predicate="memory_corruption", preconditions=["attacker_controls_request_field"],
                        statement="s", accepted_cwe_ids={"CWE-120"}).claim


def relation(predicate: Predicate, kind_name: str, admissibility: Admissibility, *, complete: bool = True,
             tag: str = "red", claim=CLAIM) -> EvidenceRelation:
    body = {"p": predicate.value, "k": kind_name, "a": admissibility.value, "c": complete, "t": tag}
    return EvidenceRelation(make_id("evidence_relation", 1, body), claim.claim_id, predicate, RelationKind.SUPPORTS,
                            ENTITY, kind_name, admissibility, "analysis/default", "0" * 64, "src/a.c:1-1", complete,
                            f"cell-{tag}", RECEIPT)


def cited(kind: str, predicate: Predicate, **kwargs) -> EvidenceRelation:
    """The relation the application records for a ``kind`` citation, classified by the real policy."""
    return relation(predicate, kind, classify(kind, predicate), **kwargs)


def adjudicate_all(relations, *, independent: bool = True, claim=CLAIM):
    return adjudicate(claim, relations, independent, {ENTITY}, (), ClaimState.PROPOSED)


def test_source_spans_cited_for_every_predicate_cannot_confirm() -> None:
    relations = [cited("source_span", p) for p in obligations.required_predicates_for(CLAIM)]
    result = adjudicate_all(relations)
    assert result.state is ClaimState.SUPPORTED and result.deciding_row is DecidingRow.SUPPORTED
    outcomes = {s.predicate: s.outcome for s in result.predicates if s.required}
    assert outcomes[P.AFFECTED_CONSTRUCT] is PredicateOutcome.SATISFIED
    assert {p for p, o in outcomes.items() if o is PredicateOutcome.UNRESOLVED} == {
        P.ATTACKER_INPUT_CONTROL, P.SOURCE_TO_SINK_REACHABILITY, P.MISSING_OR_INEFFECTIVE_GUARD}
    assert {gap.predicate for gap in result.gaps} == {
        P.ATTACKER_INPUT_CONTROL, P.SOURCE_TO_SINK_REACHABILITY, P.MISSING_OR_INEFFECTIVE_GUARD}


def test_a_claim_resting_only_on_analyst_assessed_relations_is_insufficient_evidence() -> None:
    relations = [relation(p, "source_span", A) for p in obligations.required_predicates_for(CLAIM)]
    assert not any(satisfies(item) for item in relations)
    result = adjudicate_all(relations)
    assert result.state is ClaimState.INSUFFICIENT_EVIDENCE and result.counted_relation_ids == ()
    assert result.deciding_row is DecidingRow.INSUFFICIENT_EVIDENCE


def test_an_irrelevant_but_authentic_citation_cannot_satisfy_the_obligation() -> None:
    """A real package version says nothing about attacker control; a real span of an unrelated function
    is DIRECT only for the construct it is, not for any other predicate."""
    assert cited("package", P.ATTACKER_INPUT_CONTROL).admissibility is I
    assert cited("package", P.SOURCE_TO_SINK_REACHABILITY).admissibility is I
    assert cited("package", P.MISSING_OR_INEFFECTIVE_GUARD).admissibility is I
    result = adjudicate_all([cited("package", p) for p in (P.ATTACKER_INPUT_CONTROL, P.SOURCE_TO_SINK_REACHABILITY,
                                                           P.MISSING_OR_INEFFECTIVE_GUARD)])
    assert result.state is ClaimState.INSUFFICIENT_EVIDENCE and result.counted_relation_ids == ()
    unrelated = adjudicate_all([cited("source_span", p, tag=f"u{i}") for i, p in enumerate(
        (P.ATTACKER_INPUT_CONTROL, P.SOURCE_TO_SINK_REACHABILITY, P.MISSING_OR_INEFFECTIVE_GUARD))])
    assert unrelated.state is ClaimState.INSUFFICIENT_EVIDENCE and unrelated.counted_relation_ids == ()


def test_an_incomplete_direct_relation_cannot_satisfy_or_confirm() -> None:
    incomplete = [relation(p, "source_span", D, complete=False) for p in obligations.required_predicates_for(CLAIM)]
    assert not any(satisfies(item) for item in incomplete)
    assert adjudicate_all(incomplete).state is ClaimState.INSUFFICIENT_EVIDENCE


def test_source_only_reasoning_is_supported_never_confirmed() -> None:
    required = obligations.required_predicates_for(CLAIM)
    result = adjudicate_all([cited("source_span", p) for p in sorted(required, key=lambda item: item.value)])
    assert result.state is ClaimState.SUPPORTED
    full = [relation(p, "source_span", D) for p in required]      # what the old policy would have recorded
    assert adjudicate_all(full).state is ClaimState.CONFIRMED     # only genuinely direct support confirms


# ------------------------------------------------------------------------------------------------
# Resolution against an accepted manifest records the analyst-assessed member


def test_a_resolved_source_span_is_analyst_assessed_for_attacker_control_and_direct_for_the_construct(tmp_path) -> None:
    runs, ids, _ = _accepted_fixture(tmp_path)
    core = RetrievalCore(runs, RUN_ID)
    construct = resolve_relation(core, claim_id=CLAIM.claim_id, predicate=P.AFFECTED_CONSTRUCT,
                                 kind=RelationKind.SUPPORTS, entity_id=ids["span"], producing_cell_id="cell-" + "d" * 64,
                                 retrieval_receipt_sha256=RECEIPT)
    control = resolve_relation(core, claim_id=CLAIM.claim_id, predicate=P.ATTACKER_INPUT_CONTROL,
                               kind=RelationKind.SUPPORTS, entity_id=ids["span"], producing_cell_id="cell-" + "d" * 64,
                               retrieval_receipt_sha256=RECEIPT)
    assert isinstance(construct, EvidenceRelation) and isinstance(control, EvidenceRelation)
    assert construct.admissibility is D and satisfies(construct)
    assert control.admissibility is A and control.complete and not satisfies(control)
    assert control.relation_id != construct.relation_id


# ------------------------------------------------------------------------------------------------
# Producer-specific tool-rule mapping


def lead(family: str, scanner: str, rule: str, flows=()) -> dict:
    return {"lead_family": family, "scanner": scanner, "rule_id": rule, "flow_ids": list(flows)}


@pytest.mark.parametrize(("lead_record", "expected"), [
    (lead("codeql", "codeql", "cpp/tainted-buffer", ["flow-1"]), (P.AFFECTED_CONSTRUCT, P.SOURCE_TO_SINK_REACHABILITY)),
    (lead("codeql", "codeql", "cpp/use-of-gets"), (P.AFFECTED_CONSTRUCT,)),                 # not a path query
    (lead("codeql", "codeql", "cpp/unknown-rule"), (P.AFFECTED_CONSTRUCT,)),
    (lead("codeql", "semgrep", "cpp/tainted-buffer", ["flow-1"]), ()),                       # producer mismatch
    (lead("source_sast", "semgrep", "any.rule", ["flow-1"]), (P.AFFECTED_CONSTRUCT,)),       # flows never widen
    (lead("artifact_scanner", "grype", "CVE-1"), (P.AFFECTED_CONSTRUCT,)),
    (lead("dependency_advisory", "osv", "GHSA-1"), (P.AFFECTED_CONSTRUCT,)),
    (lead("ci_rule", "zizmor", "pull-request-target"), (P.AFFECTED_CONSTRUCT, P.CONFIGURATION_ENABLES)),
    (lead("post_build_hardening", "build-rules", "no-relro"), (P.AFFECTED_CONSTRUCT, P.CONFIGURATION_ENABLES)),
    (lead("owasp_control", "owasp-workbench", "ASVS-1"), (P.MISSING_OR_INEFFECTIVE_GUARD,)),
    (lead("unheard_of_family", "x", "y", ["flow-1"]), ()),
    ({}, ()),
])
def test_lead_predicates_are_keyed_by_producer_rule_and_result_kind(lead_record: dict, expected: tuple) -> None:
    assert tool_rules.lead_predicates(lead_record) == expected


def test_a_non_path_codeql_result_cannot_make_reachability_admissible() -> None:
    mapped = tool_rules.lead_predicates(lead("codeql", "codeql", "cpp/use-of-gets"))
    assert classify("tool_observation", P.SOURCE_TO_SINK_REACHABILITY, mapped) is I
    assert classify("tool_observation", P.AFFECTED_CONSTRUCT, mapped) is Admissibility.DIRECT_FOR_MAPPED_PREDICATE
    result = adjudicate_all([relation(P.SOURCE_TO_SINK_REACHABILITY, "tool_observation",
                                      classify("tool_observation", P.SOURCE_TO_SINK_REACHABILITY, mapped))])
    assert result.state is ClaimState.INSUFFICIENT_EVIDENCE
    path = tool_rules.lead_predicates(lead("codeql", "codeql", "cpp/tainted-buffer", ["f"]))
    assert classify("tool_observation", P.SOURCE_TO_SINK_REACHABILITY, path) is Admissibility.DIRECT_FOR_MAPPED_PREDICATE


def test_rule_table_is_ordered_first_match_wins_and_hash_pinned() -> None:
    rows = (tool_rules.RuleRow("codeql", "codeql", "cpp/special-*", "*", (P.MISSING_OR_INEFFECTIVE_GUARD,)),
            *tool_rules.RULES)
    assert tool_rules.predicates_for("codeql", "codeql", "cpp/special-1", "point", rows) == (
        P.MISSING_OR_INEFFECTIVE_GUARD,)
    assert tool_rules.predicates_for("codeql", "codeql", "cpp/other", "point", rows) == (P.AFFECTED_CONSTRUCT,)
    assert len(tool_rules.TABLE_SHA256) == 64
    assert tool_rules.table_record(rows) != tool_rules.table_record()


# ------------------------------------------------------------------------------------------------
# Family-specific obligations

SECRET = normalize_claim(lane=Lane.LEAD, package_id="p", affected_entities=[ENTITY], weakness_cwe="CWE-798",
                         security_predicate="authn_bypass", preconditions=[], statement="s",
                         accepted_cwe_ids={"CWE-798"}).claim


def claim_of(security_predicate: str, cwe: str | None = None, preconditions=(), entities=(ENTITY,)):
    return normalize_claim(lane=Lane.LEAD, package_id="p", affected_entities=entities, weakness_cwe=cwe,
                           security_predicate=security_predicate, preconditions=preconditions, statement="s",
                           accepted_cwe_ids={cwe} if cwe else ()).claim


@pytest.mark.parametrize(("claim", "family", "required"), [
    (CLAIM, "memory_and_input", {P.AFFECTED_CONSTRUCT, P.ATTACKER_INPUT_CONTROL, P.SOURCE_TO_SINK_REACHABILITY,
                                 P.MISSING_OR_INEFFECTIVE_GUARD}),
    (claim_of("sql_injection", "CWE-89"), "memory_and_input", None),
    (claim_of("command_injection"), "memory_and_input", None),
    (SECRET, "secrets", {P.AFFECTED_CONSTRUCT, P.MISSING_OR_INEFFECTIVE_GUARD}),
    (claim_of("crypto_weakness", "CWE-327"), "cryptography", {P.AFFECTED_CONSTRUCT, P.MISSING_OR_INEFFECTIVE_GUARD}),
    (claim_of("insecure_configuration", "CWE-16"), "configuration", {P.AFFECTED_CONSTRUCT, P.CONFIGURATION_ENABLES}),
    (claim_of("supply_chain_compromise", "CWE-1104"), "supply_chain", {P.AFFECTED_CONSTRUCT, P.CONFIGURATION_ENABLES}),
])
def test_required_predicates_depend_on_the_claim_family(claim, family: str, required) -> None:
    assert obligations.obligation_family(claim.security_predicate, claim.weakness_cwe).value == family
    got = obligations.required_predicates_for(claim)
    assert got == (required if required is not None else frozenset(obligations.ALWAYS_REQUIRED))
    assert P.SECURITY_IMPACT not in got       # derived, never cited (obligations.DERIVED_PREDICATES)


def test_injection_style_claims_keep_the_source_to_sink_obligation() -> None:
    for name in ("injection", "command_injection", "sql_injection", "code_injection", "path_traversal", "ssrf",
                 "deserialization", "memory_corruption", "out_of_bounds_read", "use_after_free", "integer_error"):
        assert P.SOURCE_TO_SINK_REACHABILITY in obligations.required_predicates_for(claim_of(name))


def test_configuration_follows_the_family_and_the_affected_build_not_only_the_listed_preconditions() -> None:
    build = LogicalIdentity.derive(EntityKind.BUILD_ACTION, "snap", {"n": "cc -O0"}).value
    unit = LogicalIdentity.derive(EntityKind.COMPILE_UNIT, "snap", {"n": "main.o"}).value
    assert P.CONFIGURATION_ENABLES in obligations.required_predicates_for(claim_of("memory_corruption", entities=(build,)))
    assert P.CONFIGURATION_ENABLES in obligations.required_predicates_for(claim_of("memory_corruption", entities=(unit,)))
    assert P.CONFIGURATION_ENABLES not in obligations.required_predicates_for(claim_of("memory_corruption"))
    assert P.CONFIGURATION_ENABLES in obligations.required_predicates_for(
        claim_of("crypto_weakness", preconditions=["debug_mode_enabled"]))


def test_a_secret_claim_confirms_on_its_own_family_obligations() -> None:
    relations = [relation(P.AFFECTED_CONSTRUCT, "source_span", D, claim=SECRET),
                 relation(P.MISSING_OR_INEFFECTIVE_GUARD, "tool_observation", Admissibility.DIRECT_FOR_MAPPED_PREDICATE,
                          claim=SECRET)]
    assert adjudicate_all(relations, claim=SECRET).state is ClaimState.CONFIRMED
    assert adjudicate_all(relations[:1], claim=SECRET).state is ClaimState.SUPPORTED


def test_the_family_tables_are_pinned_in_the_policy_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    before = obligations.sha256_hex(obligations._policy_document())
    changed = {**obligations.REQUIRED_BY_FAMILY,
               obligations.ObligationFamily.SECRETS: (P.AFFECTED_CONSTRUCT,)}
    monkeypatch.setattr(obligations, "REQUIRED_BY_FAMILY", changed)
    assert obligations.sha256_hex(obligations._policy_document()) != before


# ------------------------------------------------------------------------------------------------
# Regression: the cpp-multivuln packet.cpp:16 claim shape


def test_packet_cpp_claim_is_supported_not_confirmed_on_sink_fact_and_source_text(tmp_path: Path) -> None:
    """The sink_site fact is direct for the construct; the source text for attacker control and
    reachability is analyst-assessed; guard facts keep their graph-branch classification."""
    runs, graph_ids = accepted_graph_run(tmp_path / "graph")
    graph = RetrievalCore(runs, RUN_ID)
    sources_runs, source_ids, _ = _accepted_fixture(tmp_path / "source")
    source = RetrievalCore(sources_runs, RUN_ID)

    def resolve(core, entity, predicate, kind=RelationKind.SUPPORTS):
        found = resolve_relation(core, claim_id=CLAIM.claim_id, predicate=predicate, kind=kind, entity_id=entity,
                                 producing_cell_id="cell-" + "d" * 64, retrieval_receipt_sha256=RECEIPT)
        assert isinstance(found, EvidenceRelation), found
        return found

    sink = resolve(graph, graph_ids["sink"], P.AFFECTED_CONSTRUCT)
    control = resolve(source, source_ids["span"], P.ATTACKER_INPUT_CONTROL)
    reach = resolve(source, source_ids["span"], P.SOURCE_TO_SINK_REACHABILITY)
    guard = resolve(graph, graph_ids["guard"], P.MISSING_OR_INEFFECTIVE_GUARD)       # graph branch, unchanged
    assert sink.admissibility is Admissibility.DIRECT_FOR_MAPPED_PREDICATE
    assert control.admissibility is A and reach.admissibility is A
    assert guard.admissibility is Admissibility.DIRECT_FOR_MAPPED_PREDICATE
    relations = [sink, control, reach, guard]
    result = adjudicate_all(relations)
    assert result.state is ClaimState.SUPPORTED          # not confirmed: two required predicates are not direct
    assert {s.predicate: s.outcome for s in result.predicates if s.required} == {
        P.AFFECTED_CONSTRUCT: PredicateOutcome.SATISFIED, P.MISSING_OR_INEFFECTIVE_GUARD: PredicateOutcome.SATISFIED,
        P.ATTACKER_INPUT_CONTROL: PredicateOutcome.UNRESOLVED, P.SOURCE_TO_SINK_REACHABILITY: PredicateOutcome.UNRESOLVED}
    assert set(result.counted_relation_ids) == {sink.relation_id, guard.relation_id}
    assert {gap.predicate for gap in result.gaps} == {P.ATTACKER_INPUT_CONTROL, P.SOURCE_TO_SINK_REACHABILITY}
    # With the source-to-sink path and the entry point as graph facts, the same claim confirms.
    entry = resolve(graph, graph_ids["entry"], P.ATTACKER_INPUT_CONTROL)
    path = resolve(graph, graph_ids["path"], P.SOURCE_TO_SINK_REACHABILITY)
    confirmed = adjudicate_all([sink, entry, path, guard])
    assert confirmed.state is ClaimState.CONFIRMED
    assert Family.DATAFLOW_PATH.value == path.entity_kind
