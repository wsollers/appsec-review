"""list_codeql_databases and query_codeql_neighborhood (docs/architecture/seeded-codeql-neighborhoods.md 7-8).

The run is the ``test_retrieval_code_graph`` fixture (cpp-main: main -> handle -> parse -> helper, plus
sinks, entry points, paths, guards and ranges) with hand-made ``codeql_database`` cards in the
``graph-<scope>-database`` shards ``job_code_graph_index`` publishes. No CodeQL runs anywhere.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Mapping

import pytest

from appsec_review.graph import contract as c
from appsec_review.mcp import RetrievalMcpAdapter, TOOLS
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.retrieval import EntityKind, EntityRecord, LogicalIdentity, RetrievalCore
from appsec_review.retrieval.neighborhood import GAP_NAMES, SUMMARY_KIND
from appsec_review.review.capability import TOOL_INDEXES, AuthorityDenied, Authorized, CellCapability
from appsec_review.review.models import Role

from tests.test_retrieval_code_graph import RUN_ID, SCOPE, SNAPSHOT, build_graph_run

OTHER = "py-other"
SECRET = b"n" * 32
OBSERVATION = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"codeql": "bridged"}).value
STRANGER = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"codeql": "stranger"}).value


def _seed(path: str, start: int, end: int, status: str, functions: list[str], *, observation: str | None = None):
    sources = [{"scanner": "cppcheck", "rule": "bufferAccessOutOfBounds", "severity": "high",
                "observation_id": observation}] if observation else []
    return {"path": path, "start_line": start, "end_line": end, "status": status, "functions": functions,
            "sources": sources}


def _card(scope_id: str, *, language: str = "c/c++", mode: str = "seeded", depth: int | None = 2,
          coverage: str = "partial", seeds: list[dict[str, Any]] | None = None) -> EntityRecord:
    seeds = [] if seeds is None else seeds
    resolved = sum(1 for seed in seeds if seed["status"] == "resolved")
    identity = LogicalIdentity.derive(EntityKind.CODEQL_DATABASE, SNAPSHOT, {
        "scope_id": scope_id, "database_identity": "db-" + scope_id, "export_identity": "ex-" + scope_id,
        "export_status": "SUCCEEDED"})
    payload = {
        "schema": "appsec-review/codeql-database/1",
        "scope": {"scope_id": scope_id, "language": language, "build_unit_id": "native-main",
                  "component_id": "cmp-net"},
        "scope_id": scope_id, "language": language, "source_languages": [language], "root": "src",
        "build_unit_id": "native-main", "component_id": "cmp-net", "database_identity": "db-" + scope_id,
        "export_identity": "ex-" + scope_id, "export_status": "SUCCEEDED", "mode": mode, "seed_depth": depth,
        "seed_limit": 200, "seed_count": len(seeds), "resolved_seed_count": resolved,
        "neighborhood_function_count": 4,
        "seeded": {"mode": mode, "depth": depth, "seed_limit": 200, "seed_count": len(seeds),
                   "resolved_seed_count": resolved, "neighborhood_function_count": 4,
                   "depth_histogram": {"0": 1, "1": 2, "2": 1}, "seeds": seeds, "gaps": []},
        "coverage": coverage, "families": {"call_site": {"status": coverage, "facts": 5, "counts": {}}},
        "gaps": ["seeded_neighborhood: facts cover functions within 2 call steps of 1 finding locations; "
                 "absence outside it is not evidence"] if coverage != "complete" else []}
    return EntityRecord(identity, "db-" + scope_id, f"{language} database {scope_id}", f"codeql database {scope_id}",
                        payload)


def _shard(card: EntityRecord):
    scope_id = card.payload["scope_id"]
    return (f"graph-{scope_id}-database", [card],
            {"job": "job_code_graph_index", "kind": "codeql_database", "scope_id": scope_id},
            [(f"graph:{scope_id}:database", card.payload["coverage"], None)])


MAIN_SEEDS = [_seed("src/net.c", 3, 3, "resolved", ["parse"], observation=OBSERVATION),
              _seed("src/net.c", 1, 1, "unresolved", []),
              _seed("src/gone.c", 7, 7, "resolved", ["not_exported"], observation=STRANGER)]


@pytest.fixture()
def neighborhood_run(tmp_path: Path):
    main = _card(SCOPE, seeds=MAIN_SEEDS)
    other = _card(OTHER, language="python", depth=1, seeds=[])
    wide = _card("wide", mode="whole_program", depth=None, coverage="complete")
    runs, ids = build_graph_run(tmp_path, extra_graph_shards=[_shard(main), _shard(other), _shard(wide)])
    ids["db_main"], ids["db_other"], ids["db_wide"] = main.identity.value, other.identity.value, wide.identity.value
    return RetrievalCore(runs, RUN_ID), ids


def _rows(response: Mapping[str, Any]) -> list[dict[str, Any]]:
    return response["results"]


def _stable(response: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in response.items() if key != "duration_ms"}


def _query(core: RetrievalCore, ids: Mapping[str, str], **arguments: Any) -> dict[str, Any]:
    return core.query_codeql_neighborhood(database=ids.get("db_main"), **arguments)


def _summary(response: Mapping[str, Any]) -> dict[str, Any]:
    first = _rows(response)[0]
    assert first["kind"] == SUMMARY_KIND and "identity" not in first
    return first


def _gap_names(response: Mapping[str, Any]) -> set[str]:
    return {gap.split(":", 1)[0] for gap in response["coverage_gaps"]} & set(GAP_NAMES)


# ------------------------------------------------------------------------------ list_codeql_databases


def test_list_returns_every_card_in_scope_order_with_the_bounded_ledger(neighborhood_run) -> None:
    core, ids = neighborhood_run
    response = core.list_codeql_databases()
    assert {row["identity"] for row in _rows(response)} == {ids[key] for key in ("db_main", "db_other", "db_wide")}
    assert [row["payload"]["scope_id"] for row in _rows(response)] == sorted([SCOPE, OTHER, "wide"])
    main = next(row for row in _rows(response) if row["identity"] == ids["db_main"])
    assert main["kind"] == "codeql_database" and main["index"] == "graph"
    assert main["payload"]["seeded"]["seeds"][0]["path"] == "src/net.c"
    assert main["payload"]["seeded"]["seeds_omitted"] == 0
    assert main["payload"]["mode"] == "seeded" and main["payload"]["seed_depth"] == 2
    assert main["payload"]["coverage"] == "partial"
    assert any("seeded_neighborhood" in gap for gap in response["coverage_gaps"])


def test_list_filters_by_language_and_visible_scope_and_pages_deterministically(neighborhood_run) -> None:
    core, ids = neighborhood_run
    assert [row["payload"]["scope_id"] for row in _rows(core.list_codeql_databases(language="python"))] == [OTHER]
    assert [row["payload"]["scope_id"] for row in _rows(core.list_codeql_databases(graph_scopes=[SCOPE]))] == [SCOPE]
    empty = core.list_codeql_databases(graph_scopes=[])
    assert _rows(empty) == [] and any("no accepted CodeQL database card" in gap for gap in empty["coverage_gaps"])
    first = core.list_codeql_databases(limit=2)
    assert len(_rows(first)) == 2 and first["pagination"]["next_cursor"]
    second = core.list_codeql_databases(limit=2, cursor=first["pagination"]["next_cursor"])
    assert [row["identity"] for row in _rows(first) + _rows(second)] == [
        row["identity"] for row in _rows(core.list_codeql_databases())]
    assert _stable(core.list_codeql_databases()) == _stable(core.list_codeql_databases())


def test_list_bounds_and_validation(neighborhood_run) -> None:
    core, _ = neighborhood_run
    for limit in (0, 101):
        with pytest.raises(ValueError, match="result limit exceeds bound"):
            core.list_codeql_databases(limit=limit)
    with pytest.raises(ValueError, match="schema_violation"):
        core.list_codeql_databases(language="c++; drop")


def test_a_card_is_a_normal_graph_entity_the_core_can_find(neighborhood_run) -> None:
    core, ids = neighborhood_run
    found = core.find(identity=ids["db_main"], limit=1)["results"][0]
    assert found["kind"] == "codeql_database" and found["payload"]["scope"]["scope_id"] == SCOPE
    assert LogicalIdentity.parse(ids["db_main"]).kind is EntityKind.CODEQL_DATABASE


# ------------------------------------------------------------------------------ database resolution


def test_unknown_database_is_a_named_gap_never_an_empty_success(neighborhood_run) -> None:
    core, ids = neighborhood_run
    unknown = LogicalIdentity.derive(EntityKind.CODEQL_DATABASE, SNAPSHOT, {"scope_id": "nope"}).value
    response = core.query_codeql_neighborhood(database=unknown, symbol=ids["sym_parse"])
    assert _summary(response)["status"] == "unavailable" and _summary(response)["gap_names"] == ["database_unknown"]
    assert _gap_names(response) == {"database_unknown"} and len(_rows(response)) == 1


def test_an_ungranted_database_is_indistinguishable_from_an_unknown_one(neighborhood_run) -> None:
    core, ids = neighborhood_run
    granted = core.query_codeql_neighborhood(database=ids["db_main"], symbol=ids["sym_parse"], graph_scopes=[SCOPE])
    assert len(_rows(granted)) > 1
    hidden = core.query_codeql_neighborhood(database=ids["db_main"], symbol=ids["sym_parse"], graph_scopes=[OTHER])
    unknown = core.query_codeql_neighborhood(database=ids["db_other"], symbol=ids["sym_parse"], graph_scopes=[SCOPE])
    assert _stable(hidden)["results"] == [{**_rows(hidden)[0]}] and _gap_names(hidden) == {"database_unknown"}
    assert {k: v for k, v in _summary(hidden).items() if k != "database"} == {
        k: v for k, v in _summary(unknown).items() if k != "database"}
    assert OTHER not in json.dumps([hidden["results"], hidden["coverage_gaps"]])


def test_a_card_without_call_graph_names_an_outside_gap(neighborhood_run) -> None:
    core, ids = neighborhood_run
    response = core.query_codeql_neighborhood(database=ids["db_other"], symbol=ids["sym_parse"])
    assert _summary(response)["status"] == "unavailable" and "outside_precomputed_neighborhood" in _gap_names(response)


# ------------------------------------------------------------------------------ subjects and closure


def test_seed_subject_resolves_through_the_ledger_and_walks_both_directions(neighborhood_run) -> None:
    core, ids = neighborhood_run
    response = _query(core, ids, seed="src/net.c:3")
    summary = _summary(response)
    assert summary["subject"]["symbols"] == [{"identity": ids["sym_parse"], "name": "parse"}]
    assert summary["depth"] == {"applied": 2, "maximum": 2, "precomputed": 2}
    calls = [row for row in _rows(response)[1:] if row["kind"] == "call_site"]
    assert {(row["direction"], row["depth"]): row["identity"] for row in calls} == {
        ("callees", 1): ids["call_parse_helper"], ("callers", 1): ids["call_handle_parse"],
        ("callers", 2): ids["call_main_handle"]}
    for row in _rows(response)[1:]:
        assert row["identity"] and row["index"] == "graph" and row["location"]["path"] == "src/net.c"
        assert row["payload"]["schema"] == c.GRAPH_FACT_SCHEMA and row["database"] == ids["db_main"]
    # main has no known callers: it is the boundary of a seeded export, named rather than hidden.
    assert "frontier" in _gap_names(response) and ids["sym_main"] in summary["frontier"]["symbols"]
    assert summary["status"] == "partial" and "frontier" in summary["gap_names"]


def test_symbol_subject_by_identity_or_qualified_name_and_observation_agree(neighborhood_run) -> None:
    core, ids = neighborhood_run
    by_identity = _query(core, ids, symbol=ids["sym_parse"])
    by_name = _query(core, ids, symbol="parse")
    by_seed = _query(core, ids, seed="src/net.c:3")
    by_observation = _query(core, ids, observation=OBSERVATION)
    assert [row.get("identity") for row in _rows(by_identity)] == [row.get("identity") for row in _rows(by_name)] \
        == [row.get("identity") for row in _rows(by_seed)] == [row.get("identity") for row in _rows(by_observation)]


def test_subjects_outside_the_neighborhood_are_named_never_empty_success(neighborhood_run) -> None:
    core, ids = neighborhood_run
    cases = [dict(seed="src/net.c:99"),                    # not in the ledger
             dict(seed="src/net.c:1"),                     # in the ledger, unresolved: seeded no function
             dict(seed="src/gone.c:7"),                    # resolved, but the function is not in the export
             dict(symbol="not_exported"),
             dict(symbol=LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"function": "ghost"}).value),
             dict(observation=LogicalIdentity.derive(
                 EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"codeql": "unseeded"}).value)]
    for options in cases:
        response = _query(core, ids, **options)
        assert len(_rows(response)) == 1 and _summary(response)["status"] == "unavailable", options
        assert "outside_precomputed_neighborhood" in _gap_names(response), options


def test_requested_depth_beyond_the_precomputed_depth_is_clamped_and_named(neighborhood_run) -> None:
    core, ids = neighborhood_run
    deep = _query(core, ids, symbol=ids["sym_parse"], depth=4)
    assert "depth_exceeds_precomputed" in _gap_names(deep) and _summary(deep)["depth"]["applied"] == 2
    exact = _query(core, ids, symbol=ids["sym_parse"], depth=2)
    assert "depth_exceeds_precomputed" not in _gap_names(exact)
    assert [row.get("identity") for row in _rows(deep)] == [row.get("identity") for row in _rows(exact)]


def test_depth_reached_names_unexpanded_call_sites(neighborhood_run) -> None:
    core, ids = neighborhood_run
    response = _query(core, ids, symbol=ids["sym_handle"], direction="callees", depth=1, include=["calls"])
    assert "depth_reached" in _gap_names(response)
    assert {row["identity"] for row in _rows(response)[1:]} == {ids["call_handle_parse"], ids["call_handle_helper"]}
    zero = _query(core, ids, symbol=ids["sym_handle"], depth=0)
    assert _rows(zero)[0]["kind"] == SUMMARY_KIND
    assert not [row for row in _rows(zero) if row["kind"] == "call_site"]


def test_direction_filters_the_closure(neighborhood_run) -> None:
    core, ids = neighborhood_run
    callees = _query(core, ids, symbol=ids["sym_handle"], direction="callees", include=["calls"])
    callers = _query(core, ids, symbol=ids["sym_handle"], direction="callers", include=["calls"])
    assert {row["direction"] for row in _rows(callees)[1:]} == {"callees"}
    assert {row["direction"] for row in _rows(callers)[1:]} == {"callers"}
    # The unresolved indirect call in main is returned as a candidate caller, as query_code_graph does.
    assert {row["identity"] for row in _rows(callers)[1:]} == {ids["call_main_handle"], ids["call_main_indirect"]}


def test_whole_program_card_never_marks_a_frontier(neighborhood_run) -> None:
    core, ids = neighborhood_run
    response = core.query_codeql_neighborhood(database=ids["db_wide"], symbol=ids["sym_handle"], depth=3)
    assert "frontier" not in _gap_names(response) and _summary(response)["frontier"] == {"count": 0, "symbols": []}


# ------------------------------------------------------------------------------ facts


def test_attached_fact_families_keep_identity_location_and_scope(neighborhood_run) -> None:
    core, ids = neighborhood_run
    response = _query(core, ids, symbol=ids["sym_parse"], direction="callees", depth=1,
                      include=["sinks", "entry_points", "guards", "ranges", "paths"])
    kinds = [row["fact"] for row in _rows(response)[1:]]
    assert kinds == sorted(kinds, key=["sinks", "entry_points", "guards", "ranges", "paths"].index)
    by_fact = {fact: [row["identity"] for row in _rows(response)[1:] if row["fact"] == fact] for fact in set(kinds)}
    assert set(by_fact["sinks"]) >= {ids["sink_memcpy"], ids["sink_odd"], ids["sink_printf"]}
    assert set(by_fact["guards"]) == {ids["guard_none"], ids["guard_dominating"]}
    assert set(by_fact["ranges"]) == {ids["range_op0"], ids["range_op2"]}
    assert set(by_fact["paths"]) >= {ids["path_remote"], ids["path_internal"]}
    for row in _rows(response)[1:]:
        assert row["location"]["path"] == "src/net.c" and row["payload"]["scope"]["scope_id"] == SCOPE
    assert _summary(response)["counts"]["sinks"] == len(by_fact["sinks"])


def test_default_include_is_calls_and_sinks(neighborhood_run) -> None:
    core, ids = neighborhood_run
    response = _query(core, ids, symbol=ids["sym_parse"])
    assert {row.get("fact", "calls") for row in _rows(response)[1:]} == {"calls", "sinks"}
    assert _summary(response)["include"] == ["calls", "sinks"]


# ------------------------------------------------------------------------------ bounds, paging, determinism


def test_limit_reached_pages_by_cursor_and_concatenates_to_the_full_answer(neighborhood_run) -> None:
    core, ids = neighborhood_run
    full = _query(core, ids, symbol=ids["sym_parse"], limit=100)
    assert full["pagination"]["next_cursor"] is None and "limit_reached" not in _gap_names(full)
    first = _query(core, ids, symbol=ids["sym_parse"], limit=3)
    assert len(_rows(first)) == 3 and first["pagination"]["next_cursor"] and "limit_reached" in _gap_names(first)
    collected = list(_rows(first))
    cursor = first["pagination"]["next_cursor"]
    while cursor:
        page = _query(core, ids, symbol=ids["sym_parse"], limit=3, cursor=cursor)
        collected += _rows(page)
        cursor = page["pagination"]["next_cursor"]
    assert [row.get("identity") for row in collected[1:]] == [row.get("identity") for row in _rows(full)[1:]]


def test_a_cursor_is_bound_to_its_request(neighborhood_run) -> None:
    core, ids = neighborhood_run
    cursor = _query(core, ids, symbol=ids["sym_parse"], limit=2)["pagination"]["next_cursor"]
    with pytest.raises(ValueError):
        _query(core, ids, symbol=ids["sym_handle"], limit=2, cursor=cursor)


@pytest.mark.parametrize("options", [
    dict(limit=0), dict(limit=101), dict(depth=5), dict(depth=-1), dict(depth=True), dict(direction="up"),
    dict(include=[]), dict(include=["calls", "calls"]), dict(include=["flows"]), dict(include="calls"),
    dict(seed="no-line"), dict(seed="/etc/passwd:3"), dict(seed="../x.c:3"),
    dict(symbol="a", seed="src/net.c:3"), dict(observation="asr:symbol:" + "1" * 64),
])
def test_invalid_requests_are_rejected_before_any_read(neighborhood_run, options) -> None:
    core, ids = neighborhood_run
    options = {"symbol": ids["sym_parse"], **options} if not {"seed", "observation"} & set(options) \
        and "symbol" not in options else options
    with pytest.raises(ValueError):
        _query(core, ids, **options)


def test_exactly_one_subject_and_a_codeql_database_identity_are_required(neighborhood_run) -> None:
    core, ids = neighborhood_run
    with pytest.raises(ValueError, match="exactly one"):
        _query(core, ids)
    with pytest.raises(ValueError, match="database must be"):
        core.query_codeql_neighborhood(database=ids["sym_parse"], symbol=ids["sym_parse"])


def test_results_are_deterministic(neighborhood_run) -> None:
    core, ids = neighborhood_run
    options = dict(symbol=ids["sym_parse"], include=["calls", "sinks", "guards", "ranges"])
    assert _stable(_query(core, ids, **options)) == _stable(_query(core, ids, **options))
    by_seed = _rows(_query(core, ids, seed="src/net.c:3"))
    by_observation = _rows(_query(core, ids, observation=OBSERVATION))
    assert by_seed[1:] == by_observation[1:] and by_seed[0]["subject"]["symbols"] == by_observation[0]["subject"]["symbols"]


def test_every_named_gap_is_a_stable_prefix(neighborhood_run) -> None:
    core, ids = neighborhood_run
    seen: set[str] = set()
    for response in (_query(core, ids, symbol=ids["sym_parse"], depth=4, limit=3),
                     _query(core, ids, symbol=ids["sym_handle"], direction="callees", depth=1),
                     _query(core, ids, symbol="ghost"),
                     core.query_codeql_neighborhood(database=ids["db_main"], symbol="x", graph_scopes=[])):
        seen |= _gap_names(response)
    assert seen == set(GAP_NAMES)


# ------------------------------------------------------------------------------ MCP schema and adapters


def _tool(name: str) -> Mapping[str, Any]:
    return next(tool for tool in TOOLS if tool["name"] == name)


def test_schema_is_closed_bounded_and_matches_the_published_catalog() -> None:
    catalog = json.loads((Path(__file__).resolve().parents[1] / "docs" / "schemas" /
                          "retrieval-mcp-tools.json").read_text(encoding="utf-8"))
    for name, required in (("list_codeql_databases", []), ("query_codeql_neighborhood", ["database"])):
        schema = _tool(name)["inputSchema"]
        assert schema["additionalProperties"] is False and schema["required" if required else "properties"]
        assert schema.get("required", []) == required
        assert schema["properties"]["limit"]["maximum"] == c.MAX_TOOL_LIMIT
        assert {"name": name, "required": required, "properties": list(schema["properties"])} in catalog["tools"]
        assert not {"path", "graph_scopes", "scope", "sql", "query"} & set(schema["properties"])
    schema = _tool("query_codeql_neighborhood")["inputSchema"]["properties"]
    assert schema["depth"]["maximum"] == c.MAX_TOOL_DEPTH and schema["depth"]["minimum"] == 0
    assert schema["direction"]["enum"] == ["callers", "callees", "both"]
    assert schema["include"]["items"]["enum"] == ["calls", "sinks", "entry_points", "guards", "ranges", "paths", "flow", "diagnostics", "symbols", "cpg"]
    assert TOOL_INDEXES["list_codeql_databases"] == TOOL_INDEXES["query_codeql_neighborhood"] == {"graph"}


def test_adapter_dispatches_and_rejects_unknown_arguments(neighborhood_run) -> None:
    core, ids = neighborhood_run
    adapter = RetrievalMcpAdapter(core)
    assert adapter.call("list_codeql_databases", {"language": "python"})["results"][0]["identity"] == ids["db_other"]
    assert len(adapter.call("query_codeql_neighborhood", {"database": ids["db_main"], "symbol": "parse"})["results"]) > 1
    for name, arguments in (("list_codeql_databases", {"graph_scopes": [SCOPE]}),
                            ("query_codeql_neighborhood", {"database": ids["db_main"], "symbol": "parse",
                                                           "graph_scopes": [OTHER]}),
                            ("query_codeql_neighborhood", {"database": ids["db_main"], "symbol": "parse",
                                                           "path": "src/net.c"})):
        with pytest.raises(ValueError, match="unknown tool arguments"):
            adapter.call(name, arguments)
    with pytest.raises(ValueError, match="graph_scopes applies only"):
        adapter.call("query_code_graph", {"mode": "sinks", "subject": ids["sym_parse"]}, graph_scopes=[SCOPE])


def _package(core: RetrievalCore, scopes: list[str]) -> dict[str, Any]:
    return {"run_id": core.run_id, "manifest_sha256": core.manifest_sha256, "package_id": "pkg",
            "retrieval": {"indexes": ["graph"], "query_sets": [], "entity_ids": [], "graph_scopes": scopes,
                          "max_page_size": 50, "max_pages": 4, "max_depth": 3, "max_response_bytes": 1 << 20}}


def _scoped(core: RetrievalCore, scopes: list[str], role: str = "red") -> ScopedRetrievalMcpAdapter:
    package = _package(core, scopes)
    token = issue_capability(package, role=role, round_id="1", secret=SECRET, expires_at=int(time.time()) + 300)
    return ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), package, capability=token, secret=SECRET,
                                     role=role, round_id="1")


def test_scoped_adapter_shows_only_granted_databases_and_requires_them_to_be_listed_first(neighborhood_run) -> None:
    core, ids = neighborhood_run
    scoped = _scoped(core, [SCOPE])
    with pytest.raises(ValueError, match="outside review package"):
        scoped.call("query_codeql_neighborhood", {"database": ids["db_main"], "symbol": "parse"})
    listed = scoped.call("list_codeql_databases", {})
    assert [row["identity"] for row in listed["results"]] == [ids["db_main"]]
    result = scoped.call("query_codeql_neighborhood", {"database": ids["db_main"], "seed": "src/net.c:3"})
    assert len(result["results"]) > 1 and result["results"][0]["kind"] == SUMMARY_KIND
    # A database of an ungranted scope is not reachable even by guessing its identity.
    with pytest.raises(ValueError, match="outside review package"):
        scoped.call("query_codeql_neighborhood", {"database": ids["db_other"], "symbol": "parse"})
    with pytest.raises(ValueError, match="outside review package"):
        scoped.call("query_codeql_neighborhood", {"database": ids["db_main"], "symbol": "parse", "path": "x"})
    with pytest.raises(ValueError, match="depth exceeds"):
        scoped.call("query_codeql_neighborhood", {"database": ids["db_main"], "symbol": "parse", "depth": 4})
    with pytest.raises(ValueError, match="page exceeds"):
        scoped.call("list_codeql_databases", {"limit": 51})


def test_scoped_adapter_with_no_graph_scope_sees_no_database(neighborhood_run) -> None:
    core, _ = neighborhood_run
    listed = _scoped(core, []).call("list_codeql_databases", {})
    assert listed["results"] == [] and any("no accepted CodeQL database card" in gap for gap in listed["coverage_gaps"])


def test_cell_capability_gates_the_database_identity_and_depth(neighborhood_run) -> None:
    _, ids = neighborhood_run
    capability = CellCapability.issue(
        run_id=RUN_ID, manifest_sha256="m" * 64, package_id="p", package_sha256="p" * 64, role=Role.RED_TEAM_ANALYST
        if hasattr(Role, "RED_TEAM_ANALYST") else Role.INDEPENDENT_VERIFIER, round=0,
        tools=("list_codeql_databases", "query_codeql_neighborhood"), indexes=("graph",), graph_scopes=(SCOPE,),
        max_queries=9, max_turns=4, page_size=10, max_depth=3, max_result_bytes=1 << 16)
    request = {"tool": "query_codeql_neighborhood", "parameters": {"database": ids["db_main"], "symbol": "parse"}}
    denied = capability.authorize(request)
    assert isinstance(denied, AuthorityDenied) and denied.code == "entity_out_of_scope"
    allowed = capability.authorize(request, granted={ids["db_main"]})
    assert isinstance(allowed, Authorized) and allowed.parameters["limit"] == 10
    too_deep = capability.authorize({**request, "parameters": {**request["parameters"], "depth": 4}},
                                    granted={ids["db_main"]})
    assert isinstance(too_deep, AuthorityDenied) and too_deep.code in {"depth_cap_exceeded", "schema_violation"}
    assert isinstance(capability.authorize({"tool": "list_codeql_databases", "parameters": {}}), Authorized)
    for parameters in ({"database": ids["db_main"], "seed": "/etc/passwd:3"},
                       {"database": ids["db_main"], "symbol": "a || b"},
                       {"database": ids["db_main"], "path": "src/net.c", "symbol": "a"}):
        assert isinstance(capability.authorize({"tool": "query_codeql_neighborhood", "parameters": parameters},
                                               granted={ids["db_main"]}), AuthorityDenied)


def test_cell_capability_scopes_card_rows_by_their_scope_block(neighborhood_run) -> None:
    core, ids = neighborhood_run
    capability = CellCapability.issue(
        run_id=RUN_ID, manifest_sha256="m" * 64, package_id="p", package_sha256="p" * 64,
        role=Role.INDEPENDENT_VERIFIER, round=0, tools=("list_codeql_databases",), indexes=("graph",),
        graph_scopes=(SCOPE,), max_queries=9, max_turns=4, page_size=10, max_depth=3, max_result_bytes=1 << 16)
    rows = {row["payload"]["scope_id"]: row for row in core.list_codeql_databases()["results"]}
    assert capability.graph_row_in_scope(rows[SCOPE]) and not capability.graph_row_in_scope(rows[OTHER])
