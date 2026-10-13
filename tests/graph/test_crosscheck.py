from __future__ import annotations

import pytest

from appsec_review.graph import contract as c
from appsec_review.graph.crosscheck import (
    METHOD_AST_NAME, METHOD_CLANGD_SPAN, METHOD_IR_NAME, CrossCheckInputs, SourceFile, cross_check, link_symbols,
)
from appsec_review.retrieval import IndexBuilder
from appsec_review.retrieval.model import RelationKind
from tests.fixtures.graph.secondary.builder import SCOPE, SNAPSHOT, build_secondary


def _facts(fixture):
    return {
        "agree": fixture.call("helper", "process", "helper(n)"),
        "disagree": fixture.call("other", "process", "other(a)"),
        "external": fixture.call("memcpy", "process", "memcpy(dst, src, b)", dispatch="external_undefined",
                                 callee_symbol=None),
    }


def _run(fixture, facts, **inputs):
    return cross_check(list(facts.values()), CrossCheckInputs(**inputs), target_snapshot=SNAPSHOT, scope=SCOPE,
                       sources=fixture.sources)


def _by_identity(result):
    return {fact.identity.value: fact for fact in result.facts}


def _producer(fact, name):
    return next(item for item in fact.payload["cross_check"]["producers"] if item["name"] == name)


def test_clangd_agreement_in_the_exact_call_span_is_agree_and_eligible(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    facts = _facts(fixture)
    result = _run(fixture, facts, clangd=(fixture.read("clangd"),))
    fact = _by_identity(result)[facts["agree"].identity.value]
    assert fact.payload["cross_check"]["state"] == "agree"
    assert _producer(fact, "clangd") == {"name": "clangd", "state": "agree", "method": METHOD_CLANGD_SPAN}
    assert fact.payload["admissibility"]["direct_eligible"] is True
    assert any(item["shard_id"] == "clangd-native" for item in fact.payload["upstream"])
    derived = [r for r in result.relations if r.kind is RelationKind.DERIVED_FROM and r.source_id == fact.identity.value]
    assert [(r.target_id, r.exact) for r in derived] == [(fixture.ids["clangd:helper"], True)]
    fact.to_entity()  # the updated payload still satisfies the shared contract


def test_clangd_different_callee_at_the_same_span_is_disagree_with_contradiction(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    facts = _facts(fixture)
    result = _run(fixture, facts, clangd=(fixture.read("clangd"),))
    fact = _by_identity(result)[facts["disagree"].identity.value]
    assert fact.payload["cross_check"]["state"] == "disagree"
    assert fact.payload["admissibility"]["direct_eligible"] is False
    assert "cross_check_disagree" in fact.payload["admissibility"]["ineligibility_reasons"]
    contradictions = [r for r in result.relations if r.kind is RelationKind.CONTRADICTS]
    assert len(contradictions) == 1
    relation = contradictions[0]
    assert (relation.source_id, relation.target_id) == (fact.identity.value, fixture.ids["clangd:helper"])
    assert relation.exact is False and "src/net.c:6:13" in relation.ambiguity and "other" in relation.ambiguity
    fact.to_entity()


def test_clangd_edge_without_codeql_counterpart_is_an_ineligible_secondary_only_fact(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    facts = _facts(fixture)
    result = _run(fixture, facts, clangd=(fixture.read("clangd"),))
    secondary = [f for f in result.facts if f.payload["result"]["callee"]["dispatch"] == "secondary_only"]
    assert len(secondary) == 1
    fact = secondary[0]
    assert fact.payload["producer"]["name"] == "clangd"
    assert fact.payload["admissibility"]["direct_eligible"] is False
    assert fact.payload["exact"] is False and fact.payload["coverage_status"] == "partial"
    assert any("not a CodeQL negative" in gap for gap in fact.payload["gaps"])
    assert fact.location.start_line == 8 and fact.location.ambiguous
    assert fact.payload["result"]["callee"]["symbol"] == fixture.ids["clangd:helper"]
    entity = fact.to_entity()
    assert entity.identity.kind.value == "call_site"
    kinds = {(r.kind, r.source_id, r.target_id) for r in result.relations}
    assert (RelationKind.CONTAINS, fixture.ids["clangd:process"], fact.identity.value) in kinds
    assert (RelationKind.CALLS, fact.identity.value, fixture.ids["clangd:helper"]) in kinds
    assert result.summary["secondary_only"] == {"clangd": 1}


def test_external_call_without_clangd_reference_is_not_covered(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    facts = _facts(fixture)
    result = _run(fixture, facts, clangd=(fixture.read("clangd"),))
    fact = _by_identity(result)[facts["external"].identity.value]
    assert fact.payload["cross_check"]["state"] == "not_covered"
    assert fact.payload["admissibility"]["direct_eligible"] is True


def test_dynamic_dispatch_candidate_clangd_cannot_confirm_is_partial(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    virtual = fixture.call("other", "process", "other(a)", dispatch="virtual_resolved")
    result = cross_check([virtual], CrossCheckInputs(clangd=(fixture.read("clangd"),)), target_snapshot=SNAPSHOT,
                         scope=SCOPE, sources=fixture.sources)
    fact = _by_identity(result)[virtual.identity.value]
    assert fact.payload["cross_check"]["state"] == "partial"
    assert not [r for r in result.relations if r.kind is RelationKind.CONTRADICTS]


def test_ir_name_only_agreement_is_agree_with_method(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    facts = _facts(fixture)
    result = _run(fixture, facts, llvm_ir=(fixture.read("ir"),))
    by_id = _by_identity(result)
    agree = by_id[facts["agree"].identity.value]
    assert agree.payload["cross_check"]["state"] == "agree"
    assert agree.payload["cross_check"]["producers"] == [
        {"name": "llvm-ir", "state": "agree", "method": METHOD_IR_NAME}]
    assert agree.payload["admissibility"]["direct_eligible"] is True
    derived = [r for r in result.relations if r.source_id == agree.identity.value]
    assert [(r.kind, r.target_id, r.exact) for r in derived] == [
        (RelationKind.DERIVED_FROM, fixture.ids["ir:helper"], False)]
    # IR cannot see external callees: absence is never a contradiction.
    external = by_id[facts["external"].identity.value]
    assert external.payload["cross_check"]["state"] == "not_covered"
    assert not [f for f in result.facts if f.payload["result"]["callee"]["dispatch"] == "secondary_only"]


def test_ir_edge_codeql_never_reports_is_secondary_only(tmp_path) -> None:
    fixture = build_secondary(tmp_path, ir_calls=(("process", "helper"), ("process", "other"), ("helper", "other")))
    facts = _facts(fixture)
    facts["helper_body"] = fixture.call("other", "helper", "x + 1", callee_symbol=None, callee_display="unrelated")
    result = _run(fixture, facts, llvm_ir=(fixture.read("ir"),))
    secondary = [f for f in result.facts if f.payload["result"]["callee"]["dispatch"] == "secondary_only"]
    assert [(f.payload["producer"]["name"], f.payload["result"]["caller"]["display"],
             f.payload["result"]["callee"]["display"]) for f in secondary] == [("llvm-ir", "helper", "other")]
    assert secondary[0].payload["admissibility"]["direct_eligible"] is False
    secondary[0].to_entity()


def test_clangd_disagreement_dominates_ir_agreement(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    facts = _facts(fixture)
    result = _run(fixture, facts, clangd=(fixture.read("clangd"),), llvm_ir=(fixture.read("ir"),))
    fact = _by_identity(result)[facts["disagree"].identity.value]
    assert fact.payload["cross_check"]["state"] == "disagree"
    assert [item["state"] for item in fact.payload["cross_check"]["producers"]] == ["disagree", "agree"]


def test_ast_call_expr_without_referenced_decl_is_not_covered(tmp_path) -> None:
    fixture = build_secondary(tmp_path, ast_calls=((None, 5), (None, 6)))
    facts = _facts(fixture)
    result = _run(fixture, facts, clang_ast=(fixture.read("ast"),))
    for fact in result.facts:
        assert fact.payload["cross_check"]["state"] == "not_covered"
        assert _producer(fact, "clang-ast")["detail"] == "Clang AST CallExpr nodes carry no referencedDecl"
        assert fact.payload["admissibility"]["direct_eligible"] is True


def test_ast_referenced_decl_name_agrees(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    facts = _facts(fixture)
    result = _run(fixture, facts, clang_ast=(fixture.read("ast"),))
    fact = _by_identity(result)[facts["agree"].identity.value]
    assert _producer(fact, "clang-ast") == {"name": "clang-ast", "state": "agree", "method": METHOD_AST_NAME}
    assert _by_identity(result)[facts["disagree"].identity.value].payload["cross_check"]["state"] == "not_covered"


def test_absent_secondary_shards_leave_every_fact_not_covered_and_eligible(tmp_path) -> None:
    fixture = build_secondary(tmp_path, clangd=None, ir_calls=None, ast_calls=None)
    facts = _facts(fixture)
    sink = fixture.sink("k")
    result = cross_check([*facts.values(), sink], CrossCheckInputs(), target_snapshot=SNAPSHOT, scope=SCOPE,
                         sources=fixture.sources)
    assert len(result.facts) == 4 and not result.relations
    for fact in result.facts:
        assert fact.payload["cross_check"] == {"rule": c.CROSS_CHECK_RULE, "state": "not_covered", "producers": []}
        assert fact.payload["admissibility"] == {"rule": c.ADMISSIBILITY_RULE, "direct_eligible": True,
                                                 "ineligibility_reasons": []}
        assert fact.payload["gaps"] == []


def test_non_call_families_are_never_cross_checked(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    sink = fixture.sink("k")
    stale = c.GraphFact(sink.identity, sink.name, {**sink.payload, "cross_check": {
        "rule": c.CROSS_CHECK_RULE, "state": "agree", "producers": ["clangd"]}}, sink.location)
    result = cross_check([stale], CrossCheckInputs(clangd=(fixture.read("clangd"),)), target_snapshot=SNAPSHOT,
                         scope=SCOPE, sources=fixture.sources)
    fact = _by_identity(result)[sink.identity.value]
    assert fact.payload["cross_check"]["state"] == "not_covered" and fact.payload["cross_check"]["producers"] == []


def test_codeql_symbols_link_to_clangd_by_definition_span_or_name(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    exact = fixture.symbol("helper")
    loose = fixture.symbol("other", needle="other", nth=1)  # same name and file, different span
    links, relations = link_symbols([exact, loose], (fixture.read("clangd"),), sources=fixture.sources)
    same_as = {(r.source_id, r.target_id): r for r in relations}
    assert same_as[(exact.identity.value, fixture.ids["clangd:helper"])].exact is True
    ambiguous = same_as[(loose.identity.value, fixture.ids["clangd:other"])]
    assert ambiguous.exact is False and ambiguous.payload["method"] == "name-and-file"
    assert links[(exact.identity.value, fixture.ids["clangd:helper"])] is True

    # Facts whose symbols are CodeQL-exported identities agree through the exact SAME_AS link.
    process = fixture.symbol("process")
    fact = fixture.call("helper", "process", "helper(n)", caller_symbol=process.identity.value,
                        callee_symbol=exact.identity.value)
    result = cross_check([fact], CrossCheckInputs(clangd=(fixture.read("clangd"),)), target_snapshot=SNAPSHOT,
                         scope=SCOPE, sources=fixture.sources, graph_symbols=[exact, process])
    assert _by_identity(result)[fact.identity.value].payload["cross_check"]["state"] == "agree"
    assert sum(1 for r in result.relations if r.kind is RelationKind.SAME_AS) == 2


def test_name_only_symbol_match_is_partial_not_agree(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    unknown = "asr:symbol:" + "c" * 64
    fact = fixture.call("helper", "process", "helper(n)", callee_symbol=unknown)
    result = cross_check([fact], CrossCheckInputs(clangd=(fixture.read("clangd"),)), target_snapshot=SNAPSHOT,
                         scope=SCOPE, sources=fixture.sources)
    assert _by_identity(result)[fact.identity.value].payload["cross_check"]["state"] == "partial"


def test_cross_check_is_deterministic_under_input_order_and_shard_row_order(tmp_path) -> None:
    first_fixture = build_secondary(tmp_path / "a")
    second_fixture = build_secondary(tmp_path / "b", seed=7)
    facts = list(_facts(first_fixture).values())
    inputs_a = CrossCheckInputs(clangd=(first_fixture.read("clangd"),), llvm_ir=(first_fixture.read("ir"),),
                                clang_ast=(first_fixture.read("ast"),))
    inputs_b = CrossCheckInputs(clangd=(second_fixture.read("clangd"),), llvm_ir=(second_fixture.read("ir"),),
                                clang_ast=(second_fixture.read("ast"),))
    one = cross_check(facts, inputs_a, target_snapshot=SNAPSHOT, scope=SCOPE, sources=first_fixture.sources)
    two = cross_check(list(reversed(facts)), inputs_b, target_snapshot=SNAPSHOT, scope=SCOPE,
                      sources=second_fixture.sources)
    assert [f.identity.value for f in one.facts] == [f.identity.value for f in two.facts]
    assert [dict(f.payload) for f in one.facts] == [dict(f.payload) for f in two.facts]
    assert [r.relation_id for r in one.relations] == [r.relation_id for r in two.relations]
    assert [r.relation_id for r in one.relations] == sorted(r.relation_id for r in one.relations)


def test_results_publish_into_a_graph_shard(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    result = _run(fixture, _facts(fixture), clangd=(fixture.read("clangd"),), llvm_ir=(fixture.read("ir"),))
    builder = IndexBuilder(tmp_path / "graph.sqlite", name="graph", fingerprint="f" * 64, target_snapshot=SNAPSHOT,
                           shard_id="graph-call-site")
    for fact in result.facts:
        builder.add_entity(fact.to_entity())
    for relation in result.relations:
        builder.add_relation(relation)
    assert len(builder.build()) == 64


def test_unlocated_clangd_occurrences_are_a_named_gap(tmp_path) -> None:
    fixture = build_secondary(tmp_path, clangd_occurrence_extra=2)
    result = _run(fixture, _facts(fixture), clangd=(fixture.read("clangd"),))
    assert any("2 clangd call references" in gap for gap in result.summary["gaps"])


def test_source_file_rejects_changed_bytes_and_maps_utf16_columns() -> None:
    source = SourceFile.from_bytes("aé\U0001F600b\n".encode())
    assert source.offset(1, 1) == 0 and source.offset(1, 2) == 1 and source.offset(1, 3) == 3
    assert source.offset(1, 5) == 7 and source.offset(1, 6) == 8 and source.offset(1, 7) is None
    with pytest.raises(ValueError):
        SourceFile("0" * 64, b"x")
    with pytest.raises(ValueError):
        cross_check([], CrossCheckInputs(), target_snapshot=SNAPSHOT, scope={}, sources={})
