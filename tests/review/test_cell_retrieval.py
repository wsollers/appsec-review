"""Locator, ``expand`` authorization, denial shapes and the forgiving ``query_code_graph`` interface."""
from __future__ import annotations

import pytest

from appsec_review.review.capability import (
    FORBIDDEN_PARAMETERS, AuthorityDenied, Authorized, CellCapability,
)
from appsec_review.review.cell_retrieval import adapt_graph_request, corrected_shape, expand_plan

SYMBOL = "asr:symbol:" + "1" * 64
CALLEE = "asr:symbol:" + "2" * 64
CALL = "asr:call_site:" + "3" * 64
SINK = "asr:sink_site:" + "4" * 64
GUARD = "asr:guard_fact:" + "5" * 64
OBSERVATION = "asr:tool_observation:" + "6" * 64


def capability() -> CellCapability:
    return CellCapability.issue(
        run_id="2026-10-12-0001", manifest_sha256="1" * 64, package_id="p", package_sha256="2" * 64,
        role="red_team_analyst", round=0, tools=("find", "expand", "query_observations", "query_codeql",
                                                 "query_code_graph", "search"),
        indexes=("source", "observations", "graph", "precomputed"), entities=(SYMBOL, CALL, SINK, GUARD, OBSERVATION),
        max_queries=8, max_turns=4, page_size=10, max_depth=3, max_result_bytes=16384)


def authorize(request, **kwargs):
    return capability().authorize(request, **kwargs)


@pytest.mark.parametrize("name", sorted(FORBIDDEN_PARAMETERS))
def test_filesystem_regex_and_query_language_parameters_stay_forbidden(name: str) -> None:
    decision = authorize({"tool": "find", "parameters": {name: "src/a.c"}}, locator_paths={"src/a.c"})
    assert isinstance(decision, AuthorityDenied) and decision.code == "forbidden_parameter"


def test_a_locator_is_resolved_only_inside_the_package_scope() -> None:
    paths = {"src/a.c"}
    ok = authorize({"tool": "find", "parameters": {"locator": {"path": "src/a.c", "line": 16}}}, locator_paths=paths)
    assert isinstance(ok, Authorized) and ok.line == 16
    assert ok.parameters["path"] == "src/a.c" and "locator" not in ok.parameters
    observed = authorize({"tool": "query_observations", "parameters": {"locator": {"path": "src/a.c", "line": 16}}},
                         locator_paths=paths)
    assert observed.parameters["start_line"] == observed.parameters["end_line"] == 16
    assert authorize({"tool": "query_codeql", "parameters": {"locator": {"path": "src/a.c", "line": 2}}},
                     locator_paths=paths).parameters["path"] == "src/a.c"
    cases = {
        "entity_out_of_scope": {"locator": {"path": "src/b.c", "line": 1}},
        "path_like_value": {"locator": {"path": "../etc/passwd", "line": 1}},
        "invalid_locator": {"locator": {"path": "src/a.c"}},
    }
    for code, parameters in cases.items():
        decision = authorize({"tool": "find", "parameters": parameters}, locator_paths=paths)
        assert isinstance(decision, AuthorityDenied) and decision.code == code, code
    assert authorize({"tool": "search", "parameters": {"query": "x", "locator": {"path": "src/a.c", "line": 1}}},
                     locator_paths=paths).code == "schema_violation"
    assert authorize({"tool": "find", "parameters": {"locator": {"path": "src/a.c", "line": 1}}}).code == "entity_out_of_scope"


def test_expand_takes_exactly_one_of_label_ref_or_files() -> None:
    labels = {"K1": SINK}
    by_label = authorize({"tool": "expand", "parameters": {"label": "K1"}}, labels=labels)
    assert isinstance(by_label, Authorized) and by_label.parameters == {"ref": SINK}
    assert authorize({"tool": "expand", "parameters": {"label": "K2"}}, labels=labels).code == "unknown_label"
    assert authorize({"tool": "expand", "parameters": {"ref": "asr:sink_site:" + "9" * 64}}).code == "entity_out_of_scope"
    assert authorize({"tool": "expand", "parameters": {}}).code == "schema_violation"
    assert authorize({"tool": "expand", "parameters": {"ref": SINK, "files": "gaps.jsonl"}}).code == "schema_violation"
    assert isinstance(authorize({"tool": "expand", "parameters": {"files": "gaps.jsonl", "offset": 5}}), Authorized)


def test_corrected_shapes_name_a_well_formed_request() -> None:
    assert corrected_shape({"tool": "find", "parameters": {"path": "src/a.c"}}, "forbidden_parameter", ("find",)) == {
        "tool": "find", "parameters": {"locator": {"path": "src/a.c", "line": "<line number>"}}}
    assert corrected_shape({"tool": "shell"}, "unknown_tool", ("find", "expand"))["use_one_of"] == ["expand", "find"]
    shape = corrected_shape({"tool": "query_code_graph", "parameters": {"mode": "guards", "subject": CALL}},
                            "schema_violation", ("query_code_graph",))
    assert shape["parameters"]["mode"] == "guards" and "sink_site" in shape["parameters"]["subject"]
    assert corrected_shape("nonsense", "malformed_request", ("find",))["use_one_of"] == ["find"]


class GraphCore:
    """find() answers for a call site, a sink, a guard and a located tool observation."""

    def __init__(self, sinks_on_line=1) -> None:
        self.sinks_on_line = sinks_on_line

    def find(self, **parameters):
        identity = parameters.get("identity")
        rows = {
            CALL: {"identity": CALL, "kind": "call_site", "payload": {"result": {
                "caller": {"symbol": SYMBOL}, "callee": {"symbol": CALLEE}}}},
            SINK: {"identity": SINK, "kind": "sink_site", "payload": {"result": {"enclosing_function": {"symbol": SYMBOL}}}},
            GUARD: {"identity": GUARD, "kind": "guard_fact", "payload": {"result": {"sink": {"sink_site": SINK}}}},
            OBSERVATION: {"identity": OBSERVATION, "kind": "tool_observation", "payload": {},
                          "location": {"path": "src/a.c", "start_line": 16, "end_line": 16}}}
        if identity:
            return {"results": [rows[identity]] if identity in rows else []}
        sinks = [{"identity": f"asr:sink_site:{index:064x}", "location": {"start_line": 16}}
                 for index in range(self.sinks_on_line)]
        return {"results": sinks}


def adapted(mode: str, subject: str, core=None, **extra):
    return adapt_graph_request(core or GraphCore(), {"tool": "query_code_graph",
                                                    "parameters": {"mode": mode, "subject": subject, **extra}})


def test_query_code_graph_repairs_only_what_is_deterministic() -> None:
    request, notes = adapted("callers", CALL)
    assert request["parameters"]["subject"] == CALLEE and "call_site" in notes[0]
    assert adapted("callees", CALL)[0]["parameters"]["subject"] == SYMBOL
    assert adapted("callers", SINK)[0]["parameters"]["subject"] == SYMBOL
    assert adapted("guards", GUARD)[0]["parameters"]["subject"] == SINK
    mapped = adapted("guards", OBSERVATION)[0]["parameters"]["subject"]
    assert mapped.startswith("asr:sink_site:")
    assert adapted("guards", OBSERVATION, GraphCore(sinks_on_line=2))[1] == []            # two sinks: ambiguous
    request, notes = adapted("guards", SINK, depth=2)
    assert "depth" not in request["parameters"] and "depth applies only" in notes[0]
    assert adapted("callers", SYMBOL, depth=2)[1] == []                                    # already well formed
    assert adapt_graph_request(GraphCore(), {"tool": "find", "parameters": {}}) == ({"tool": "find", "parameters": {}}, [])


def test_expand_runs_typed_queries_for_the_kind_of_item() -> None:
    assert [step[0] for step in expand_plan(SINK, max_depth=4)] == ["find"] + ["query_code_graph"] * 3
    plan = expand_plan(SYMBOL, max_depth=2)
    assert [params.get("mode") for _tool, params in plan[1:]] == ["callers", "callees", "sinks"]
    assert plan[1][1]["depth"] == 2
    assert expand_plan(GUARD, max_depth=2) == [("find", {"identity": GUARD})]
