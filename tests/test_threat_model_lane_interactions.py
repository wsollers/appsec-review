"""The interaction lane (T-107): graph facts, call sites and signals become interaction facts."""
from __future__ import annotations

import random
from typing import Any

from appsec_review.interchange import GAP_SCHEMA, GapCode
from appsec_review.threat_model.contract import (
    Basis, EvidenceRecord, FactKind, InputState, Interaction, LaneResult, Limits, canonical,
)
from appsec_review.threat_model.lanes.interactions import interactions
from tests.threat_model_support import FakeEvidenceView, record, span

GRAPH = ("job_code_graph_index", "code_graph_facts")
SYNTAX = ("job_tree_sitter_ast", "tree_sitter_ast")
SIGNALS = ("job_review_prioritization", "priority_items")
UNIT = "facts.interactions"


class FakeRules:
    """A literal interaction catalog; nothing here names a target."""

    sources = {"remote": Interaction.NETWORK_LISTEN, "file": Interaction.FILE_READ, "argv": Interaction.ARGUMENT_READ}
    sinks = {"command_execution": Interaction.PROCESS_SPAWN, "sql_query": Interaction.DATASTORE_QUERY}
    signals = {("ingress", "route_handler"): Interaction.NETWORK_RECEIVE,
               ("privilege_shift", None): Interaction.PRIVILEGE_CHANGE,
               ("semantic_path", "dataflow"): Interaction.NETWORK_RECEIVE}
    callees = {"accept": Interaction.NETWORK_LISTEN, "connect": Interaction.NETWORK_CONNECT,
               "recv": Interaction.NETWORK_RECEIVE}

    def interaction_for_source_class(self, source_class: str) -> Interaction | None:
        return self.sources.get(source_class)

    def interaction_for_sink_class(self, sink_class: str) -> Interaction | None:
        return self.sinks.get(sink_class)

    def interaction_for_signal(self, category: str, surface: str | None) -> Interaction | None:
        return self.signals.get((category, surface), self.signals.get((category, None)))

    def callee_names(self) -> tuple[str, ...]:
        return tuple(sorted(self.callees))

    def interaction_for_callee(self, name: str) -> Interaction | None:
        return self.callees.get(name)


def _scope(build_unit_id: str | None = "unit-server", component_id: str | None = "component-net") -> dict[str, Any]:
    return {"scope_id": "scope-1", "language": "cpp", "build_unit_id": build_unit_id, "component_id": component_id}


def entry_point(entity_id: str, source_class: str, path: str, line: int, *, function: str = "net::serve",
                api: str | None = "recv") -> EvidenceRecord:
    payload = {"family": "entry_point", "scope": _scope(), "exact": True, "result": {
        "source_class": source_class,
        "api_or_parameter": {"display": f"call to {api}", "node_kind": "call", "api": api, "index": 1},
        "enclosing_function": {"symbol": f"symbol:{function}", "display": function},
        "exposure": {"basis": "catalog", "contract_id": None}, "catalog_rule": "rule-1", "model": "remote",
        "source_type": None}}
    return record(*GRAPH, "entry_point", entity_id, payload, at=span(path, line))


def sink_site(entity_id: str, sink_class: str, path: str, line: int, *, function: str = "run_job",
              api: str = "system") -> EvidenceRecord:
    payload = {"family": "sink_site", "scope": _scope("unit-worker", None), "exact": True, "result": {
        "sink_class": sink_class, "cwe_family": "CWE-78", "api": {"display": api, "declared_in": "stdlib.h"},
        "argument_index": 0, "display": f"{api}(...)", "enclosing_function": {"symbol": None, "display": function},
        "dominating_sanitizer_count": 0, "catalog_rule": "rule-2", "model": "command", "models": ["command"]}}
    return record(*GRAPH, "sink_site", entity_id, payload, at=span(path, line))


def call_site(entity_id: str, written_name: str, path: str | None, line: int = 1, *,
              enclosing: str | None = "handle_client", build_unit_id: str | None = "unit-server") -> EvidenceRecord:
    payload = {"grammar_native_type": "call_expression", "language": "c", "syntax_only": True,
               "build_unit_id": build_unit_id, "scope_id": "scope-ts",
               "syntax": {"category": "call_expression", "written_name": written_name,
                          "enclosing_definition": f"ast_node:{enclosing}" if enclosing else None,
                          "syntactic_qualifiers": [enclosing] if enclosing else [],
                          "resolution": "unresolved", "syntax_only": True}}
    return record(*SYNTAX, "ast_node", entity_id, payload, at=span(path, line) if path else None)


def signal(entity_id: str, rule_id: str, category: str, surface: str | None, path: str, line: int, *,
           basis: str = "observed_syntax", function: str | None = "Api.handle") -> EvidenceRecord:
    payload = {"rule_id": rule_id, "producer": "tree-sitter", "basis": basis, "category": category, "path": path,
               "function_id": f"{path}#{function}@{line}:1" if function else None, "detail": {},
               "authority": "review lead; not a finding"}
    if surface is not None:
        payload["surface"] = surface
    return record(*SIGNALS, "review_signal", entity_id, payload, at=span(path, line))


def run(view: FakeEvidenceView, limits: Limits = Limits()) -> LaneResult:
    return interactions(view, FakeRules(), limits)


def codes(result: LaneResult) -> list[tuple[str, str | None]]:
    return [(gap["code"], gap["scope_id"]) for gap in result.gaps]


def test_graph_entry_point_yields_a_verified_semantic_fact_with_its_source_class() -> None:
    result = run(FakeEvidenceView().add(entry_point("entry:1", "remote", "src/net/server.cpp", 42)))
    (fact,) = result.facts
    assert (fact.kind, fact.basis) == (FactKind.INTERACTION, Basis.VERIFIED_SEMANTIC)
    assert dict(fact.attributes) == {
        "interaction": "network_listen", "path": "src/net/server.cpp", "source_class": "remote", "sink_class": None,
        "callee": "recv", "enclosing_symbol": "net::serve", "build_unit_id": "unit-server",
        "component_id": "component-net"}
    assert dict(fact.native_identity) == {"interaction": "network_listen", "path": "src/net/server.cpp",
                                          "start_line": 42, "enclosing_symbol": "net::serve"}
    (evidence,) = fact.evidence
    assert (evidence.entity_id, evidence.entity_kind, evidence.basis, evidence.rule) == (
        "entry:1", "entry_point", Basis.VERIFIED_SEMANTIC, "graph.entry_point.remote")
    assert evidence.locator is not None and evidence.locator.startswith("src/net/server.cpp:42-42@")
    graph_row = result.ledger[0]
    assert (graph_row.producer, graph_row.state, graph_row.records_read) == (GRAPH[0], InputState.READ, 1)


def test_graph_sink_site_maps_through_its_sink_class_and_an_unmapped_class_yields_nothing() -> None:
    view = FakeEvidenceView().add(
        sink_site("sink:1", "command_execution", "src/worker/job.c", 17),
        sink_site("sink:2", "memory_write", "src/worker/copy.c", 9, api="memcpy"),
        entry_point("entry:9", "internal", "src/worker/job.c", 3))
    result = run(view)
    (fact,) = result.facts
    assert fact.basis is Basis.VERIFIED_SEMANTIC
    assert dict(fact.attributes) == {
        "interaction": "process_spawn", "path": "src/worker/job.c", "source_class": None,
        "sink_class": "command_execution", "callee": "system", "enclosing_symbol": "run_job",
        "build_unit_id": "unit-worker", "component_id": None}
    assert [item.rule for item in fact.evidence] == ["graph.sink_site.command_execution"]
    assert result.ledger[0].records_read == 3, "unmapped records were read, they just establish nothing"


def test_call_site_by_name_yields_an_observed_syntax_fact_only() -> None:
    result = run(FakeEvidenceView().add_call("recv", call_site("ast:1", "recv", "src/io.c", 12)))
    (fact,) = result.facts
    assert fact.basis is Basis.OBSERVED_SYNTAX
    assert dict(fact.attributes) == {
        "interaction": "network_receive", "path": "src/io.c", "source_class": None, "sink_class": None,
        "callee": "recv", "enclosing_symbol": "handle_client", "build_unit_id": "unit-server", "component_id": None}
    assert [(item.basis, item.rule) for item in fact.evidence] == [(Basis.OBSERVED_SYNTAX, "syntax.call.recv")]
    syntax_row = result.ledger[1]
    assert (syntax_row.producer, syntax_row.output_kind, syntax_row.records_read) == (*SYNTAX, 1)


def test_graph_fact_wins_over_a_syntax_fact_at_the_same_location() -> None:
    view = FakeEvidenceView().add(entry_point("entry:1", "remote", "src/net/server.cpp", 42, api="accept"))
    view.add_call("accept", call_site("ast:7", "accept", "src/net/server.cpp", 42, enclosing="serve",
                                      build_unit_id="unit-other"))
    result = run(view)
    (fact,) = result.facts
    assert fact.basis is Basis.VERIFIED_SEMANTIC
    assert (fact.attributes["source_class"], fact.attributes["enclosing_symbol"], fact.attributes["build_unit_id"]) == (
        "remote", "net::serve", "unit-server")
    assert fact.native_identity["enclosing_symbol"] == "net::serve"
    assert [(item.basis, item.rule) for item in fact.evidence] == [
        (Basis.VERIFIED_SEMANTIC, "graph.entry_point.remote"), (Basis.OBSERVED_SYNTAX, "syntax.call.accept")]
    bounded = run(view, Limits(max_evidence_refs_per_element=1))
    assert [item.basis for item in bounded.facts[0].evidence] == [Basis.VERIFIED_SEMANTIC]


def test_prioritization_signal_maps_by_category_and_surface() -> None:
    view = FakeEvidenceView().add(
        signal("sig:1", "route.handler", "ingress", "route_handler", "app/routes.ts", 30),
        signal("sig:2", "ingress.request-property", "ingress", "untrusted_input", "app/routes.ts", 31),
        signal("sig:3", "privilege.insecure_verification.verify", "privilege_shift", "insecure_verification",
               "app/tls.ts", 8, basis="heuristic_inference", function=None),
        signal("sig:4", "cpp/path-injection", "semantic_path", "dataflow", "app/files.ts", 77,
               basis="verified_semantic_path", function=None),
        signal("sig:5", "suppression.nolint", "suppression", None, "app/tls.ts", 2))
    result = run(view)
    found = {fact.evidence[0].rule: fact for fact in result.facts}
    assert sorted(found) == ["signal.cpp/path-injection", "signal.privilege.insecure_verification.verify",
                             "signal.route.handler"]
    handler = found["signal.route.handler"]
    assert (handler.basis, handler.attributes["interaction"], handler.attributes["enclosing_symbol"]) == (
        Basis.OBSERVED_SYNTAX, "network_receive", "Api.handle")
    assert (handler.attributes["build_unit_id"], handler.attributes["callee"]) == (None, None)
    privilege = found["signal.privilege.insecure_verification.verify"]
    assert (privilege.basis, privilege.attributes["interaction"], privilege.attributes["enclosing_symbol"]) == (
        Basis.OBSERVED_SYNTAX, "privilege_change", None)
    assert found["signal.cpp/path-injection"].basis is Basis.VERIFIED_SEMANTIC
    signal_row = result.ledger[2]
    assert (signal_row.producer, signal_row.records_read) == (SIGNALS[0], 5)


def test_without_graph_facts_the_lane_reports_the_gap_and_uses_syntax() -> None:
    view = FakeEvidenceView().add_call("connect", call_site("ast:3", "connect", "src/client.c", 5))
    view.set_status(*SIGNALS, InputState.DISABLED)
    result = run(view)
    assert [(fact.basis, fact.attributes["interaction"]) for fact in result.facts] == [
        (Basis.OBSERVED_SYNTAX, "network_connect")]
    assert codes(result) == [(GapCode.INPUT_UNAVAILABLE.value, GRAPH[0]), (GapCode.INPUT_UNAVAILABLE.value, SIGNALS[0])]
    assert all(gap["schema"] == GAP_SCHEMA and gap["unit_id"] == UNIT for gap in result.gaps)
    assert [gap["retryable"] for gap in result.gaps] == [False, False]
    assert [(row.producer, row.output_kind, row.state, row.records_read) for row in result.ledger] == [
        (*GRAPH, InputState.ABSENT, 0), (*SYNTAX, InputState.READ, 1), (*SIGNALS, InputState.DISABLED, 0)]
    assert not [query for query in view.queries if query[0] == "entities"], "an unreadable input is never queried"


def test_query_bound_reached_is_a_truncated_gap_naming_the_query() -> None:
    view = FakeEvidenceView().add(
        *(entry_point(f"entry:{index}", "remote", "src/a.c", 10 + index) for index in range(3)),
        sink_site("sink:1", "sql_query", "src/db.c", 4, api="sqlite3_exec"),
        *(signal(f"sig:{index}", "route.handler", "ingress", "route_handler", "app/r.ts", 5 + index)
          for index in range(3)))
    view.add_call("recv", *(call_site(f"ast:{index}", "recv", "src/b.c", 20 + index) for index in range(3)))
    view.add_call("accept", call_site("ast:9", "accept", "src/b.c", 2), call_site("ast:8", "accept", None))
    result = run(view, Limits(max_query_rows=2))
    assert codes(result) == [
        (GapCode.TRUNCATED.value, "graph.entry_point"), (GapCode.TRUNCATED.value, "syntax.call.recv"),
        (GapCode.LOCATION_UNRESOLVED.value, "syntax.call"), (GapCode.TRUNCATED.value, "signal.review_signal")]
    assert "bound of 2" in result.gaps[0]["reason"]
    assert "1 records without a source span" in result.gaps[2]["reason"]
    assert [row.records_read for row in result.ledger] == [3, 4, 2], "the tree-sitter row totals every name query"
    assert len(result.facts) == 2 + 1 + 2 + 1 + 2
    assert all(query[-1] == 2 for query in view.queries)


def test_entry_point_limit_reached_is_a_truncated_gap() -> None:
    view = FakeEvidenceView().add(entry_point("entry:1", "remote", "src/z.c", 90),
                                  sink_site("sink:1", "command_execution", "src/y.c", 80))
    view.add_call("recv", *(call_site(f"ast:{index}", "recv", "src/a.c", index + 1) for index in range(4)))
    result = run(view, Limits(max_entry_points=3))
    assert codes(result) == [(GapCode.INPUT_UNAVAILABLE.value, SIGNALS[0]),
                             (GapCode.TRUNCATED.value, "interactions.max_entry_points")]
    assert "bound of 3" in result.gaps[-1]["reason"]
    kept = [(fact.basis, fact.attributes["path"], fact.native_identity["start_line"]) for fact in result.facts]
    assert sorted(kept) == sorted([(Basis.VERIFIED_SEMANTIC, "src/z.c", 90), (Basis.VERIFIED_SEMANTIC, "src/y.c", 80),
                                   (Basis.OBSERVED_SYNTAX, "src/a.c", 1)]), "the strongest basis is kept first"
    assert [canonical(fact.native_identity) for fact in result.facts] == sorted(
        canonical(fact.native_identity) for fact in result.facts)


def test_a_callee_name_outside_the_catalog_yields_nothing() -> None:
    view = FakeEvidenceView()
    view.add_call("memcpy", call_site("ast:1", "memcpy", "src/a.c", 3))
    view.add_call("recv", call_site("ast:2", "recvfrom", "src/a.c", 4), call_site("ast:3", "RECV", "src/a.c", 5))
    result = run(view)
    assert result.facts == ()
    assert [query[1] for query in view.queries if query[0] == "search_calls"] == ["accept", "connect", "recv"]
    assert result.ledger[1].records_read == 2
    assert codes(result)[-1] == (GapCode.EMPTY_RESULT.value, "interactions")


def _populated(order: random.Random | None) -> FakeEvidenceView:
    graph = [entry_point("entry:1", "remote", "src/net/server.cpp", 42, api="accept"),
             entry_point("entry:2", "file", "src/conf.c", 7, function="load", api="fread"),
             entry_point("entry:3", "argv", "src/main.c", 3, function="main", api=None),
             sink_site("sink:1", "command_execution", "src/worker/job.c", 17),
             sink_site("sink:2", "sql_query", "src/db.c", 4, api="sqlite3_exec")]
    calls = {"accept": [call_site("ast:1", "accept", "src/net/server.cpp", 42, enclosing="serve"),
                        call_site("ast:2", "accept", "src/net/admin.c", 11, enclosing=None)],
             "recv": [call_site("ast:3", "recv", "src/io.c", 12), call_site("ast:4", "recv", "src/io.c", 19),
                      call_site("ast:5", "recv", None)]}
    signals = [signal("sig:1", "route.handler", "ingress", "route_handler", "src/io.c", 12),
               signal("sig:2", "annotation.route", "ingress", "route_handler", "src/io.c", 12),
               signal("sig:3", "privilege.setuid", "privilege_shift", "setuid", "src/main.c", 30)]
    groups = [graph, signals, *calls.values()]
    for group in groups:
        group.reverse() if order is None else order.shuffle(group)
    view = FakeEvidenceView().add(*graph, *signals)
    for name in sorted(calls, reverse=order is None):
        view.add_call(name, *calls[name])
    return view


def test_result_is_independent_of_record_order() -> None:
    expected = canonical(run(_populated(random.Random(0))))
    assert canonical(run(_populated(None))) == expected
    for seed in (1, 2, 3):
        assert canonical(run(_populated(random.Random(seed)))) == expected
    result = run(_populated(None))
    identities = [canonical(fact.native_identity) for fact in result.facts]
    assert identities == sorted(identities) and len(set(identities)) == len(identities) == 9
    merged = next(fact for fact in result.facts if fact.attributes["path"] == "src/io.c"
                  and fact.native_identity["start_line"] == 12)
    assert len(merged.evidence) == 3 and {item.rule for item in merged.evidence} == {"signal.annotation.route", "signal.route.handler",
                                                       "syntax.call.recv"}
    assert codes(result) == [(GapCode.LOCATION_UNRESOLVED.value, "syntax.call")]


def test_nothing_established_is_an_empty_result_gap() -> None:
    view = FakeEvidenceView().add(sink_site("sink:2", "memory_write", "src/copy.c", 9, api="memcpy"))
    view.set_status(*SYNTAX, InputState.PARTIAL, coverage="partial", upstream_gap_count=2)
    result = run(view)
    assert result.facts == ()
    assert codes(result) == [(GapCode.PRODUCER_REPORTED_GAP.value, "/".join(SYNTAX)),
                             (GapCode.INPUT_UNAVAILABLE.value, SIGNALS[0]), (GapCode.EMPTY_RESULT.value, "interactions")]
    assert [row.state for row in result.ledger] == [InputState.READ, InputState.PARTIAL, InputState.ABSENT]
    nothing_read = run(FakeEvidenceView())
    assert nothing_read.facts == () and [code for code, _ in codes(nothing_read)] == [GapCode.INPUT_UNAVAILABLE.value] * 3
