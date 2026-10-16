"""SVF cross-check of CodeQL graph facts over a shard the SVF job publishes from recorded tool output."""

from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.graph import contract as c
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.svf_crosscheck import (
    METHOD_ALIAS, METHOD_CALL, SVF_RULE, function_tail, read_svf, svf_cross_check,
)
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_svf_alias_analysis.job import _analyze_scope
from appsec_review.retrieval.model import RelationKind
from tests.fixtures.graph.secondary.builder import SCOPE, SNAPSHOT, payload, span
from tests.fixtures.svf.builder import FILES, LINK_COMMANDS, SOURCE, ReplayExecutor, scope, unit


SOURCES = {f"native/{name}": SourceFile.from_bytes((SOURCE / name).read_bytes()) for name in FILES}


@pytest.fixture()
def svf(tmp_path: Path):
    run_root = tmp_path / "run"
    executor = ReplayExecutor(run_root)
    result = _analyze_scope(unit(run_root), scope(run_root), LINK_COMMANDS, lambda _unit: executor)
    shard = dict(result["index_identity"])
    return read_svf(ShardSet(run_root, [shard]), shard)


def _call(needle: str, path: str, callee: str, dispatch: str, caller: str = "dispatch") -> c.GraphFact:
    location = span(SOURCES, path, needle)
    caller_symbol = "asr:symbol:" + "1" * 64
    identity = c.fact_identity(c.Family.CALL_SITE, SNAPSHOT, {
        "scope_id": SCOPE["scope_id"], "caller_symbol": caller_symbol, "path": path,
        "start_byte": location.start_byte, "end_byte": location.end_byte, "callee_name": callee})
    result = {"caller": {"symbol": caller_symbol, "display": caller},
              "callee": {"symbol": None, "display": callee, "dispatch": dispatch, "candidate_count": 1},
              "argument_count": 2, "in_loop": False}
    return c.GraphFact(identity, f"{caller} -> {callee}", payload(c.Family.CALL_SITE, result), location)


def _sink(needle: str) -> c.GraphFact:
    location = span(SOURCES, "native/guard.c", needle)
    identity = c.fact_identity(c.Family.SINK_SITE, SNAPSHOT, {
        "scope_id": SCOPE["scope_id"], "path": location.path, "start_byte": location.start_byte,
        "end_byte": location.end_byte, "sink_class": "memory_write", "argument_index": -1})
    result = {"sink_class": "memory_write", "cwe_family": "CWE-787", "api": {"display": needle, "declared_in": None},
              "argument_index": -1, "display": needle, "operand": {"location": None, "exact": False},
              "enclosing_function": {"symbol": None, "display": "guarded"}, "dominating_sanitizer_count": 0,
              "catalog_rule": "fixture", "model": "fixture"}
    return c.GraphFact(identity, needle, payload(c.Family.SINK_SITE, result), location)


def _guard(condition: str, sink: c.GraphFact, constrains) -> c.GraphFact:
    location = span(SOURCES, "native/guard.c", condition)
    identity = c.fact_identity(c.Family.GUARD_FACT, SNAPSHOT, {
        "scope_id": SCOPE["scope_id"], "sink_identity": sink.identity.value, "condition_path": location.path,
        "condition_start_byte": location.start_byte, "condition_end_byte": location.end_byte})
    result = {"sink": {"sink_site": sink.identity.value, "sink_class": "memory_write"}, "guard_state": "dominating",
              "polarity": "true_branch", "condition": {"display": condition, "location": None, "in_macro": False},
              "constrains_sink_operand": constrains, "comparison": {"operator": "!=", "bound_display": "NULL"}}
    return c.GraphFact(identity, condition, payload(c.Family.GUARD_FACT, result), location)


def _run(facts, shards):
    result = svf_cross_check(facts, shards, target_snapshot=SNAPSHOT, scope=SCOPE)
    return result, {fact.identity.value: fact for fact in result.facts}


def _svf_entry(fact: c.GraphFact) -> dict:
    return next(item for item in fact.payload["cross_check"]["producers"] if item["name"] == "svf")


CALL = "commands[index].handler(buffer, input)"


def test_resolved_target_inside_the_svf_set_agrees_and_stays_eligible(svf) -> None:
    fact = _call(CALL, "native/callbacks.c", "copy_handler", "function_pointer_resolved")
    result, by_id = _run([fact], [svf])
    updated = by_id[fact.identity.value]
    entry = _svf_entry(updated)
    assert (entry["state"], entry["method"], entry["rule"]) == ("agree", METHOD_CALL, SVF_RULE)
    assert updated.payload["cross_check"]["state"] == "agree"
    assert updated.payload["cross_check"]["rule"] == c.CROSS_CHECK_RULE
    assert updated.payload["admissibility"]["direct_eligible"] is True
    assert any(item["shard_id"] == svf.shard_id for item in updated.payload["upstream"])
    assert result.summary["states"] == {"agree": 1}
    updated.to_entity()


def test_target_outside_a_closed_world_set_disagrees_with_a_contradiction(svf) -> None:
    fact = _call(CALL, "native/callbacks.c", "unused_handler", "function_pointer_resolved")
    result, by_id = _run([fact], [svf])
    updated = by_id[fact.identity.value]
    assert updated.payload["cross_check"]["state"] == "disagree"
    assert updated.payload["admissibility"]["direct_eligible"] is False
    assert "cross_check_disagree" in updated.payload["admissibility"]["ineligibility_reasons"]
    contradictions = [r for r in result.relations if r.kind is RelationKind.CONTRADICTS]
    assert len(contradictions) == 1 and contradictions[0].source_id == fact.identity.value
    assert contradictions[0].target_id.startswith("asr:indirect_call_targets:")
    assert "unused_handler" in contradictions[0].ambiguity
    updated.to_entity()


def test_unresolved_codeql_call_gains_ineligible_secondary_only_svf_targets(svf) -> None:
    fact = _call(CALL, "native/callbacks.c", "<unresolved>", "unresolved_indirect")
    result, by_id = _run([fact], [svf])
    original = by_id[fact.identity.value]
    assert _svf_entry(original)["state"] == "not_covered" and "SVF resolves 2" in _svf_entry(original)["detail"]
    assert original.payload["cross_check"]["state"] == "not_covered"
    secondary = [f for f in result.facts if f.payload["producer"]["name"] == "svf"]
    assert sorted(f.payload["result"]["callee"]["display"] for f in secondary) == ["copy_handler", "length_handler"]
    for item in secondary:
        assert item.payload["result"]["callee"]["dispatch"] == "secondary_only"
        assert item.payload["admissibility"]["direct_eligible"] is False and item.payload["exact"] is False
        assert item.payload["result"]["secondary"]["unresolved_codeql_fact"] == fact.identity.value
        assert any("not a CodeQL negative" in gap for gap in item.payload["gaps"])
        item.to_entity()
    derived = [r for r in result.relations if r.kind is RelationKind.DERIVED_FROM]
    assert {r.source_id for r in derived} == {f.identity.value for f in secondary}
    assert result.summary["secondary_only"] == 2


def test_open_world_module_never_contradicts(svf) -> None:
    fact = _call("entry()", "native/plugin.c", "plugin_entry", "function_pointer_resolved", caller="load_plugin")
    _result, by_id = _run([fact], [svf])
    entry = _svf_entry(by_id[fact.identity.value])
    assert entry["state"] == "not_covered" and "open-world" in entry["detail"]
    assert by_id[fact.identity.value].payload["cross_check"]["state"] == "not_covered"
    assert by_id[fact.identity.value].payload["admissibility"]["direct_eligible"] is True


def test_guard_on_an_alias_of_the_written_pointer_agrees(svf) -> None:
    sink = _sink("*value->left = input")
    guard = _guard("alias != NULL", sink, True)
    _result, by_id = _run([sink, guard], [svf])
    entry = _svf_entry(by_id[guard.identity.value])
    assert (entry["state"], entry["method"]) == ("agree", METHOD_ALIAS)
    assert by_id[guard.identity.value].payload["cross_check"]["state"] == "agree"
    assert "cross_check" in by_id[sink.identity.value].payload  # the sink itself is not SVF-covered
    assert not any(p["name"] == "svf" for p in by_id[sink.identity.value].payload["cross_check"]["producers"])


def test_guard_claimed_to_constrain_a_disjoint_closed_world_pointer_disagrees(svf) -> None:
    sink = _sink("*written = input")
    guard = _guard("checked != NULL", sink, True)
    result, by_id = _run([sink, guard], [svf])
    updated = by_id[guard.identity.value]
    assert updated.payload["cross_check"]["state"] == "disagree"
    assert updated.payload["admissibility"]["direct_eligible"] is False
    contradictions = [r for r in result.relations if r.kind is RelationKind.CONTRADICTS]
    assert contradictions and all(r.target_id.startswith("asr:points_to_set:") for r in contradictions)
    updated.to_entity()


def test_unknown_codeql_constraint_is_only_annotated_never_upgraded(svf) -> None:
    sink = _sink("*written = input")
    guard = _guard("checked != NULL", sink, "unknown")
    _result, by_id = _run([sink, guard], [svf])
    updated = by_id[guard.identity.value]
    entry = _svf_entry(updated)
    assert entry["state"] == "not_covered" and "no_alias" in entry["detail"]
    assert updated.payload["cross_check"]["state"] == "not_covered"
    assert updated.payload["result"]["constrains_sink_operand"] == "unknown"


def test_codeql_no_constraint_agrees_with_a_disjoint_set_and_doubts_an_alias(svf) -> None:
    disjoint_sink = _sink("*written = input")
    disjoint = _guard("checked != NULL", disjoint_sink, False)
    alias_sink = _sink("*value->left = input")
    alias = _guard("alias != NULL", alias_sink, False)
    _result, by_id = _run([disjoint_sink, disjoint, alias_sink, alias], [svf])
    assert _svf_entry(by_id[disjoint.identity.value])["state"] == "agree"
    assert _svf_entry(by_id[alias.identity.value])["state"] == "partial"


def test_without_svf_shards_or_matching_rows_facts_are_unchanged(svf) -> None:
    fact = _call(CALL, "native/callbacks.c", "copy_handler", "function_pointer_resolved")
    result, by_id = _run([fact], [])
    assert by_id[fact.identity.value] is fact and result.relations == ()
    direct = _call("strcpy(buffer, input)", "native/callbacks.c", "strcpy", "external_undefined")
    _result, by_id = _run([direct], [svf])
    assert by_id[direct.identity.value] is direct


def test_cross_check_is_deterministic_under_fact_order(svf) -> None:
    sink = _sink("*written = input")
    facts = [_call(CALL, "native/callbacks.c", "unused_handler", "function_pointer_resolved"), sink,
             _guard("checked != NULL", sink, True)]
    first, _ = _run(facts, [svf])
    second, _ = _run(list(reversed(facts)), [svf])
    assert [f.payload for f in first.facts] == [f.payload for f in second.facts]
    assert first.relations == second.relations and first.summary == second.summary


def test_graph_job_routes_only_svf_scope_shards_to_the_svf_cross_check() -> None:
    from appsec_review.jobs.job_code_graph_index import scopes

    def shard(shard_id: str, job: str = "job_svf_alias_analysis", name: str = "analysis") -> dict:
        return {"name": name, "shard_id": shard_id, "sha256": "0" * 64, "producer": {"job": job}}

    assert scopes.secondary_producer(shard("svf-cpp-scope-abc")) is c.Producer.SVF
    assert scopes.secondary_producer(shard("svf-coverage-attempt_0001")) is None
    assert scopes.secondary_producer(shard("svf-cpp-scope-abc", name="observations")) is None
    assert scopes.secondary_producer(shard("svf-cpp-scope-abc", job="job_cpp_symbol_index")) is None
    assert "job_svf_alias_analysis" in scopes.SECONDARY_JOBS
    assert c.Producer.SVF in scopes.SECONDARY_PRODUCERS and c.Producer.SVF not in scopes.CALL_EDGE_PRODUCERS


@pytest.mark.parametrize(("name", "tail"), [
    ("copy_handler", "copy_handler"),
    ("calibration::(anonymous namespace)::select_four(unsigned long)", "select_four"),
    ("ns::Widget::draw(int) const", "draw"),
    ("ns::make<std::pair<int, int>>", "make"),
    ("operator()(int)", "operator()"),
    ("", ""),
])
def test_function_tail_survives_anonymous_namespaces_and_parameter_lists(name: str, tail: str) -> None:
    assert function_tail(name) == tail
