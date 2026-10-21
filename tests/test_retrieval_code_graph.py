"""query_code_graph (docs/architecture/code-graph-precomputation.md section 5, chunk C6).

The fixture builds accepted ``graph`` shards with the real ``IndexBuilder`` from contract
``GraphFact``s, one shard per ``(scope, family)`` with ``producer = {family, scope_id}``, the layout
``job_code_graph_index`` publishes. ``build_graph_run`` is reusable by later chunks.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

import pytest

from appsec_review.graph import contract as c
from appsec_review.mcp import RetrievalMcpAdapter, TOOLS
from appsec_review.mcp.capability import _ROLE_TOOLS
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    RetrievalCore, RetrievalLimits, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.review.capability import TOOL_INDEXES, AuthorityDenied, Authorized, CellCapability
from appsec_review.review.models import Role
from appsec_review.storage import atomic_json, file_sha256

RUN_ID = "2026-10-12-0001"
SNAPSHOT = "target-sha256:" + "2" * 64
SCOPE = "cpp-main"
SOURCE = "int main(void) { handle(); }\nvoid handle(void) { parse(); }\nvoid parse(void) { helper(); memcpy(d, s, n); }\n" \
         "void helper(void) { printf(fmt); }\n"


def _span(start_line: int, start_byte: int, end_byte: int, *, path: str = "src/net.c",
          sha: str = "0" * 64) -> SourceLocation:
    return SourceLocation(SNAPSHOT, path, sha, start_byte, end_byte, start_line, start_line, 1, 2, {},
                          "codeql-location-exact", 1.0)


def _payload(family: c.Family, result: Mapping[str, Any], *, coverage: str = "complete",
             gaps: Iterable[str] = ()) -> dict[str, Any]:
    payload = {
        "schema": c.GRAPH_FACT_SCHEMA, "family": family.value,
        "producer": {"name": "codeql-export", "tool_version": "2.27.0", "export_pack_sha256": "e" * 64,
                     "catalog_version": c.CATALOG_SCHEMA, "rule_version": c.NORMALIZE_RULE},
        "scope": {"scope_id": SCOPE, "language": "c/c++", "build_unit_id": "native-main", "component_id": "cmp-net"},
        "exact": True, "coverage_status": coverage, "gaps": list(gaps),
        "cross_check": {"rule": c.CROSS_CHECK_RULE, "state": "not_covered", "producers": []},
        "result": dict(result), "upstream": [{"index": "observations", "shard_id": "codeql-cpp", "sha256": "f" * 64}],
        "authority": c.AUTHORITY,
    }
    payload["admissibility"] = c.admissibility(payload)
    return payload


def _fact(family: c.Family, native: Mapping[str, Any], name: str, result: Mapping[str, Any],
          location: SourceLocation, **payload_options: Any) -> EntityRecord:
    identity = c.fact_identity(family, SNAPSHOT, native)
    return c.GraphFact(identity, name, _payload(family, result, **payload_options), location).to_entity()


def _relation(kind: RelationKind, source: str, target: str, **payload: Any) -> RelationRecord:
    return RelationRecord(kind, source, target, True, 1.0, payload=payload or None)


def build_graph_run(tmp_path: Path, *, omit: Iterable[str] = (),
                    extra_graph_shards: Iterable[tuple[str, list[EntityRecord], Mapping[str, Any],
                                                       list[tuple[str, str, str | None]]]] = ()
                    ) -> tuple[Path, dict[str, str]]:
    """Stage an accepted run with source, component, CodeQL observation and per-family graph shards.

    Returns ``(runs_dir, ids)``. ``omit`` drops whole graph families (their shards are not published).
    ``extra_graph_shards`` publishes further ``graph`` shards as ``(shard_id, entities, producer, coverage)``,
    e.g. the CodeQL database cards of ``tests/test_codeql_neighborhood_tools.py``.
    """
    omit = set(omit)
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    source = target / "src" / "net.c"
    source.write_text(SOURCE, encoding="utf-8")
    sha = file_sha256(source)

    def at(line: int, start: int, end: int) -> SourceLocation:
        return _span(line, start, end, sha=sha)

    sym = {name: LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"scope_id": SCOPE, "function": name}).value
           for name in ("main", "handle", "parse", "helper")}
    ids: dict[str, str] = {f"sym_{name}": value for name, value in sym.items()}
    ids["file"] = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": "src/net.c"}).value
    ids["component"] = LogicalIdentity.derive(EntityKind.COMPONENT, SNAPSHOT, {"component_id": "cmp-net"}).value
    for name in ("bridged", "broken", "lonely"):
        ids[f"obs_{name}"] = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, SNAPSHOT, {"codeql": name}).value

    def call(caller: str, callee: str | None, start: int, dispatch: str = "direct") -> EntityRecord:
        native = {"scope_id": SCOPE, "caller_symbol": sym[caller], "path": "src/net.c", "start_byte": start,
                  "end_byte": start + 6, "callee_name": callee or "<indirect>"}
        return _fact(c.Family.CALL_SITE, native, f"{caller}->{callee or '?'}", {
            "caller": {"symbol": sym[caller], "display": caller},
            "callee": {"symbol": sym.get(callee or ""), "display": callee or "(*fp)", "dispatch": dispatch,
                       "candidate_count": 1 if callee else 0},
            "argument_count": 0, "in_loop": False}, at(1, start, start + 6))

    calls = {"main_handle": call("main", "handle", 17), "handle_parse": call("handle", "parse", 49),
             "parse_helper": call("parse", "helper", 79), "handle_helper": call("handle", "helper", 57),
             "main_indirect": call("main", None, 23, "unresolved_indirect")}
    for key, record in calls.items():
        ids[f"call_{key}"] = record.identity.value

    def sink(name: str, function: str, start: int, sink_class: str) -> EntityRecord:
        native = {"scope_id": SCOPE, "path": "src/net.c", "start_byte": start, "end_byte": start + 8,
                  "sink_class": sink_class, "argument_index": 2}
        return _fact(c.Family.SINK_SITE, native, name, {
            "sink_class": sink_class, "cwe_family": "CWE-787", "api": {"display": name, "declared_in": "string.h"},
            "argument_index": 2, "enclosing_function": {"symbol": sym[function]}, "dominating_sanitizer_count": 0,
            "catalog_rule": "fixture"}, at(3, start, start + 8))

    sinks = {"memcpy": sink("memcpy", "parse", 89, "memory_write"),
             "printf": sink("printf", "helper", 125, "format_string"),
             "odd": sink("odd", "parse", 95, "unclassified")}
    for key, record in sinks.items():
        ids[f"sink_{key}"] = record.identity.value

    def entry(name: str, function: str, start: int, source_class: str) -> EntityRecord:
        native = {"scope_id": SCOPE, "path": "src/net.c", "start_byte": start, "end_byte": start + 4,
                  "source_class": source_class}
        return _fact(c.Family.ENTRY_POINT, native, name, {
            "source_class": source_class, "api_or_parameter": {"display": name},
            "enclosing_function": {"symbol": sym[function]},
            "exposure": {"basis": "codeql-model", "contract_id": None}, "catalog_rule": "fixture"},
            at(1, start, start + 4))

    entries = {"recv": entry("recv", "main", 4, "remote"), "config": entry("config", "handle", 34, "internal")}
    for key, record in entries.items():
        ids[f"entry_{key}"] = record.identity.value

    def path(name: str, source_key: str, source_class: str, symbols: list[str]) -> EntityRecord:
        steps = [{"n": index, "role": "source" if index == 0 else "sink" if index == len(symbols) - 1 else "step",
                  "symbol": sym[function], "display": function,
                  "location": {"path": "src/net.c", "start_line": index + 1, "end_line": index + 1}}
                 for index, function in enumerate(symbols)]
        native = {"scope_id": SCOPE, "source_identity": ids[f"entry_{source_key}"],
                  "sink_identity": ids["sink_memcpy"], "step_locations_sha256": format(len(symbols), "064x")}
        return _fact(c.Family.DATAFLOW_PATH, native, name, {
            "source": {"entry_point": ids[f"entry_{source_key}"], "source_class": source_class},
            "sink": {"sink_site": ids["sink_memcpy"], "sink_class": "memory_write", "cwe_family": "CWE-787"},
            "steps": steps, "hop_count": len(symbols) - 1, "call_depth": len(symbols) - 1, "guards": [],
            "sanitizers": [], "truncated_steps": False, "selection": "shortest-k"}, at(3, 89, 97))

    paths = {"remote": path("recv->memcpy", "recv", "remote", ["main", "handle", "parse"]),
             "internal": path("config->memcpy", "config", "internal", ["handle", "parse"])}
    for key, record in paths.items():
        ids[f"path_{key}"] = record.identity.value

    def guard(state: str, start: int) -> EntityRecord:
        native = {"scope_id": SCOPE, "sink_identity": ids["sink_memcpy"], "condition_path": "src/net.c",
                  "condition_start_byte": start, "condition_end_byte": start + 3}
        return _fact(c.Family.GUARD_FACT, native, f"guard-{state}", {
            "sink": {"sink_site": ids["sink_memcpy"]}, "guard_state": state, "polarity": "true_branch",
            "condition": {"display": "n < 8", "location": {"path": "src/net.c", "start_line": 3}},
            "constrains_sink_operand": True, "comparison": None,
            "destination": {"object_bytes": None}}, at(3, start, start + 3))

    guards = {"none": guard("none", 70), "dominating": guard("dominating", 72)}
    for key, record in guards.items():
        ids[f"guard_{key}"] = record.identity.value

    def value_range(operand: int) -> EntityRecord:
        native = {"scope_id": SCOPE, "sink_identity": ids["sink_memcpy"], "operand_index": operand}
        return _fact(c.Family.RANGE_FACT, native, f"range-{operand}", {
            "sink": {"sink_site": ids["sink_memcpy"]}, "operand_index": operand,
            "type": {"display": "size_t", "signed": False, "bits": 64}, "interval": "unknown", "conversions": [],
            "analysis": "codeql-simple-range-analysis"}, at(3, 96, 97))

    ranges = {"op2": value_range(2), "op0": value_range(0)}
    for key, record in ranges.items():
        ids[f"range_{key}"] = record.identity.value
    summary = _fact(c.Family.FLOW_SUMMARY, {"scope_id": SCOPE, "function_symbol": sym["parse"],
                                            "rule_version": c.NORMALIZE_RULE}, "parse summary", {
        "function": {"symbol": sym["parse"]}, "pairs": [], "sanitizes": [], "k_limited": False,
        "recursion_collapsed": False}, at(3, 62, 120))
    ids["summary_parse"] = summary.identity.value

    symbols = [EntityRecord(LogicalIdentity.parse(value), name, name, f"function {name}",
                            {"producer": "codeql-export", "scope": {"scope_id": SCOPE}}, at(1, 0, 10))
               for name, value in sym.items()]
    families: dict[c.Family, tuple[list[EntityRecord], list[RelationRecord], str, str | None]] = {
        c.Family.CALL_SITE: (symbols + list(calls.values()), [
            relation for record in calls.values() for relation in (
                [_relation(RelationKind.CONTAINS, record.payload["result"]["caller"]["symbol"], record.identity.value)]
                + ([_relation(RelationKind.CALLS, record.identity.value, record.payload["result"]["callee"]["symbol"])]
                   if record.payload["result"]["callee"]["symbol"] else []))],
            "partial", "unresolved indirect calls present"),
        c.Family.SINK_SITE: (list(sinks.values()), [
            _relation(RelationKind.CONTAINS, record.payload["result"]["enclosing_function"]["symbol"],
                      record.identity.value) for record in sinks.values()] + [
            # graph-sarif-correlation/1: a flow whose sink matched but no path joins it hangs on the sink.
            RelationRecord(RelationKind.DERIVED_FROM, ids["sink_memcpy"], ids["obs_broken"], False, 0.0,
                           "code_flow 0.0 broken (no_path)", {
                               "rule": "graph-sarif-correlation/1", "state": "broken", "code_flows": [
                                   {"code_flow": 0, "thread_flow": 0, "state": "broken", "matched_steps": [],
                                    "ambiguous_steps": [], "unmatched_steps": [0, 1], "reason": "no_path"}]})],
            "complete", None),
        c.Family.ENTRY_POINT: (list(entries.values()), [
            _relation(RelationKind.CONTAINS, record.payload["result"]["enclosing_function"]["symbol"],
                      record.identity.value) for record in entries.values()], "complete", None),
        c.Family.DATAFLOW_PATH: (list(paths.values()), [
            # graph-sarif-correlation/1 (graph/correlate.py): one relation per (path, observation) listing
            # every correlated code flow in order.
            _relation(RelationKind.DERIVED_FROM, ids["path_remote"], ids["obs_bridged"],
                      rule="graph-sarif-correlation/1", state="bridged", code_flows=[
                          {"code_flow": 0, "thread_flow": 0, "state": "bridged",
                           "matched_steps": [{"ordinal": n, "path_step": n, "method": "sarif-step-byte-span"}
                                             for n in range(3)],
                           "ambiguous_steps": [], "unmatched_steps": []}])], "complete", None),
        c.Family.GUARD_FACT: (list(guards.values()), [
            _relation(RelationKind.GUARDS, record.identity.value, ids["sink_memcpy"]) for record in guards.values()],
            "complete", None),
        c.Family.RANGE_FACT: (list(ranges.values()), [
            _relation(RelationKind.DERIVED_FROM, record.identity.value, ids["sink_memcpy"])
            for record in ranges.values()], "complete", None),
        c.Family.FLOW_SUMMARY: ([summary], [_relation(RelationKind.DERIVED_FROM, ids["summary_parse"], sym["parse"])],
                                "complete", None),
    }

    index_values: list[IndexIdentity] = []

    def build(name: str, shard_id: str, entities: list[EntityRecord], relations: list[RelationRecord],
              producer: Mapping[str, Any], coverage: list[tuple[str, str, str | None]]) -> None:
        fingerprint = index_fingerprint(
            name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"sha256": "a" * 64, "shard": shard_id}],
            tool_identity={"tool": "fixture"}, parser_identity="fixture/1", normalizer_identity="fixture/1",
            mapping_identity="fixture/1")
        location = run_root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(location, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT,
                               shard_id=shard_id)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        for area, status, gap in coverage:
            builder.add_coverage(area, status, gap)
        sha = builder.build()
        index_values.append(IndexIdentity(name, "appsec-review/retrieval-index/2", sha, fingerprint,
                                          location.relative_to(run_root).as_posix(), dict(producer), (), shard_id))

    build("source", "default", [EntityRecord(LogicalIdentity.parse(ids["file"]), "src/net.c", "src/net.c", SOURCE,
                                             {}, _span(1, 0, len(SOURCE), sha=sha))], [], {"fixture": "source"},
          [("source", "complete", None)])
    build("components", "default", [EntityRecord(LogicalIdentity.parse(ids["component"]), "cmp-net", "cmp-net",
                                                  "component", {"component_id": "cmp-net"})], [],
          {"fixture": "components"}, [("components", "complete", None)])
    build("observations", "codeql-cpp-main", [
        EntityRecord(LogicalIdentity.parse(ids[f"obs_{name}"]), f"codeql:{name}", "cpp/overflow", "alert",
                     {"producer": "codeql"}, at(3, 89, 97)) for name in ("bridged", "broken", "lonely")], [],
          {"fixture": "codeql"}, [("observations", "complete", None)])
    for family, (entities, relations, status, gap) in families.items():
        if family.value in omit:
            continue
        build(c.GRAPH_INDEX, f"{SCOPE}.{family.value}", entities, relations,
              {"job": "job_code_graph_index", "family": family.value, "scope_id": SCOPE},
              [(f"graph:{SCOPE}:{family.value}", status, gap)])

    for shard_id, entities, producer, coverage in extra_graph_shards:
        build(c.GRAPH_INDEX, shard_id, list(entities), [], producer, list(coverage))

    manifest_path = run_root / "data" / "indices" / "manifests" / "graph-fixture.json"
    write_manifest(manifest_path, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=index_values)
    artifact = {"path": manifest_path.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest_path),
                "size_bytes": manifest_path.stat().st_size}
    handoff = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001" / "handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED", "job_id": "fixture",
                          "attempt_id": "attempt_0001", "artifacts": [artifact], "outputs": {}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": artifact["path"], "manifest_sha256": artifact["sha256"]})
    return runs, ids


@pytest.fixture()
def graph_run(tmp_path: Path) -> tuple[RetrievalCore, dict[str, str]]:
    runs, ids = build_graph_run(tmp_path)
    return RetrievalCore(runs, RUN_ID), ids


def _identities(response: Mapping[str, Any]) -> list[str]:
    return [row["identity"] for row in response["results"]]


ENVELOPE = {"identity", "kind", "native_id", "name", "payload", "index", "shard_id"}


@pytest.mark.parametrize(("mode", "subject", "options", "expected", "kind"), [
    ("callees", "sym_handle", {}, ["call_handle_helper", "call_handle_parse"], "call_site"),
    ("sinks", "sym_parse", {}, ["sink_memcpy", "sink_odd"], "sink_site"),
    ("sinks", "file", {"sink_class": "format_string"}, ["sink_printf"], "sink_site"),
    ("sinks", "component", {"sink_class": "memory_write"}, ["sink_memcpy"], "sink_site"),
    ("entry_points", "sym_main", {}, ["entry_recv"], "entry_point"),
    ("entry_points", "file", {"source_class": "internal"}, ["entry_config"], "entry_point"),
    ("paths", "sink_memcpy", {}, ["path_internal", "path_remote"], "dataflow_path"),
    ("paths", "entry_recv", {}, ["path_remote"], "dataflow_path"),
    ("paths", "sym_main", {}, ["path_remote"], "dataflow_path"),
    ("paths", "sink_memcpy", {"source_class": "remote", "sink_class": "memory_write"}, ["path_remote"],
     "dataflow_path"),
    ("guards", "sink_memcpy", {}, ["guard_dominating", "guard_none"], "guard_fact"),
    ("ranges", "sink_memcpy", {}, ["range_op0", "range_op2"], "range_fact"),
    ("summary", "sym_parse", {}, ["summary_parse"], "flow_summary"),
    ("sarif_path", "obs_bridged", {}, ["path_remote"], "dataflow_path"),
])
def test_every_mode_returns_ordered_standard_entity_rows(graph_run, mode, subject, options, expected, kind) -> None:
    core, ids = graph_run
    response = core.query_code_graph(mode=mode, subject=ids[subject], **options)
    expected_ids = [ids[key] for key in expected]
    if mode in {"callees", "sinks", "entry_points", "summary"}:
        expected_ids.sort()
    assert _identities(response) == expected_ids
    for row in response["results"]:
        assert ENVELOPE <= set(row) and row["kind"] == kind and row["index"] == "graph"
        assert row["location"]["path"] == "src/net.c" and row["payload"]["schema"] == c.GRAPH_FACT_SCHEMA
        assert row["shard_id"] == f"{SCOPE}.{c.MODE_FAMILY[c.Mode(mode)].value}"
        # Every returned identity re-resolves through find, so a cell can cite it.
        assert core.find(identity=row["identity"], limit=1)["results"][0]["identity"] == row["identity"]
    family = c.MODE_FAMILY[c.Mode(mode)].value
    assert any(f"coverage graph:{SCOPE}:{family}: " in gap for gap in response["coverage_gaps"])


def test_paths_keep_resolvable_step_locations_and_sarif_rows_carry_their_correlation(graph_run) -> None:
    core, ids = graph_run
    path = core.query_code_graph(mode="paths", subject=ids["entry_recv"])["results"][0]
    assert [step["location"]["path"] for step in path["payload"]["result"]["steps"]] == ["src/net.c"] * 3
    bridged = core.query_code_graph(mode="sarif_path", subject=ids["obs_bridged"])["results"][0]
    assert bridged["correlation"]["state"] == "bridged" and bridged["correlation"]["code_flow"] == 0
    assert bridged["correlation"]["relation_id"].startswith("rel:")


def test_broken_or_missing_sarif_correlation_is_a_gap_never_a_fabricated_path(graph_run) -> None:
    core, ids = graph_run
    broken = core.query_code_graph(mode="sarif_path", subject=ids["obs_broken"])
    assert broken["results"] == []
    assert any("code_flow 0 is broken" in gap and "unmatched 2" in gap for gap in broken["coverage_gaps"])
    lonely = core.query_code_graph(mode="sarif_path", subject=ids["obs_lonely"])
    assert lonely["results"] == [] and any("no accepted SARIF correlation" in gap for gap in lonely["coverage_gaps"])


def test_callers_closure_is_ordered_by_depth_and_lists_unresolved_frontier_rows(graph_run) -> None:
    core, ids = graph_run
    response = core.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=3)
    rows = response["results"]
    level_one = sorted([ids["call_parse_helper"], ids["call_handle_helper"], ids["call_main_indirect"]])
    assert [row["depth"] for row in rows] == [1, 1, 1, 2, 2]
    assert _identities(response)[:3] == level_one
    assert sorted(_identities(response)[3:]) == _identities(response)[3:]
    assert set(_identities(response)[3:]) == {ids["call_handle_parse"], ids["call_main_handle"]}
    unresolved = next(row for row in rows if row["identity"] == ids["call_main_indirect"])
    assert unresolved["closure_role"] == "unresolved_indirect_candidate"
    assert unresolved["payload"]["result"]["callee"]["dispatch"] == "unresolved_indirect"
    assert any("callers closure is unsound" in gap for gap in response["coverage_gaps"])
    assert any("coverage graph:cpp-main:call_site: partial: unresolved indirect calls present" in gap
               for gap in response["coverage_gaps"])
    assert not response["truncated"]


def test_callers_closure_stops_at_limit_and_depth_with_named_gaps(graph_run) -> None:
    core, ids = graph_run
    limited = core.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=3, limit=2)
    assert len(limited["results"]) == 2 and limited["truncated"]
    assert any("result limit 2 reached" in gap for gap in limited["coverage_gaps"])
    cursor = limited["pagination"]["next_cursor"]
    rest = core.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=3, limit=2, cursor=cursor)
    assert [row["depth"] for row in rest["results"]] == [1, 2]
    shallow = core.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=1)
    assert shallow["truncated"] and any("depth bound 1 reached" in gap for gap in shallow["coverage_gaps"])
    leaf = core.query_code_graph(mode="callees", subject=ids["sym_helper"], depth=2)
    assert leaf["results"] == [] and not leaf["truncated"]


@pytest.mark.parametrize(("mode", "subject", "extra", "message"), [
    ("guards", "file", {}, "does not accept a source_file subject"),
    ("summary", "sink_memcpy", {}, "does not accept a sink_site subject"),
    ("sarif_path", "sym_main", {}, "does not accept a symbol subject"),
    ("sinks", "sym_main", {"depth": 2}, "depth applies only to callers and callees"),
    ("guards", "sink_memcpy", {"sink_class": "memory_write"}, "sink_class does not apply"),
    ("sinks", "sym_main", {"source_class": "remote"}, "source_class does not apply"),
    ("sinks", "sym_main", {"sink_class": "nonsense"}, "sink_class is not in the closed set"),
    ("teleport", "sym_main", {}, "mode is not in the closed set"),
])
def test_ill_formed_requests_are_schema_violations_in_core_and_capability(graph_run, mode, subject, extra,
                                                                           message) -> None:
    core, ids = graph_run
    with pytest.raises(ValueError, match="schema_violation") as raised:
        core.query_code_graph(mode=mode, subject=ids[subject], **extra)
    assert message in str(raised.value)
    decision = _capability(ids).authorize({"tool": "query_code_graph",
                                           "parameters": {"mode": mode, "subject": ids[subject], **extra}})
    assert isinstance(decision, AuthorityDenied) and decision.code == "schema_violation"


def test_depth_is_capped_by_settings_limits_and_the_cell(tmp_path: Path) -> None:
    from appsec_review.graph.contract import GraphSettings
    runs, ids = build_graph_run(tmp_path)
    core = RetrievalCore(runs, RUN_ID, graph_settings=GraphSettings(max_call_depth=2))
    with pytest.raises(ValueError, match="depth exceeds bound 2"):
        core.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=3)
    assert core.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=2)["results"]
    with pytest.raises(ValueError, match="schema_violation"):
        core.query_code_graph(mode="callers", subject=ids["sym_helper"], depth=5)
    capability = _capability(ids, max_depth=2)
    request = {"tool": "query_code_graph", "parameters": {"mode": "callers", "subject": ids["sym_helper"], "depth": 3}}
    assert capability.authorize(request).code == "depth_cap_exceeded"


def test_cursor_is_bound_to_the_exact_request(graph_run) -> None:
    core, ids = graph_run
    first = core.query_code_graph(mode="paths", subject=ids["sink_memcpy"], sink_class="memory_write", limit=1)
    cursor = first["pagination"]["next_cursor"]
    assert cursor and first["truncated"]
    second = core.query_code_graph(mode="paths", subject=ids["sink_memcpy"], sink_class="memory_write", limit=1,
                                   cursor=cursor)
    assert _identities(first) + _identities(second) == [ids["path_internal"], ids["path_remote"]]
    with pytest.raises(ValueError, match="cursor"):
        core.query_code_graph(mode="paths", subject=ids["sink_memcpy"], sink_class="format_string", limit=1,
                              cursor=cursor)


def test_unavailable_family_gap_names_family_and_scope(tmp_path: Path) -> None:
    runs, ids = build_graph_run(tmp_path, omit={"range_fact"})
    core = RetrievalCore(runs, RUN_ID)
    response = core.query_code_graph(mode="ranges", subject=ids["sink_memcpy"])
    assert response["results"] == []
    assert f"accepted graph range_fact index is unavailable for {SCOPE}" in response["coverage_gaps"]


def test_empty_result_with_complete_coverage_states_absence_is_a_gap(graph_run) -> None:
    core, ids = graph_run
    response = core.query_code_graph(mode="entry_points", subject=ids["sym_parse"])
    assert response["results"] == []
    assert any("absence is a gap" in gap for gap in response["coverage_gaps"])


def test_limits_and_response_byte_bound_are_enforced_and_named(tmp_path: Path) -> None:
    runs, ids = build_graph_run(tmp_path)
    capped = RetrievalCore(runs, RUN_ID, limits=RetrievalLimits(max_results=1))
    with pytest.raises(ValueError, match="result limit"):
        capped.query_code_graph(mode="guards", subject=ids["sink_memcpy"], limit=2)
    small = RetrievalCore(runs, RUN_ID, limits=RetrievalLimits(max_response_bytes=6000))
    response = small.query_code_graph(mode="paths", subject=ids["sink_memcpy"])
    assert len(response["results"]) < 2 and response["truncated"]
    assert any("response byte budget reached" in gap for gap in response["coverage_gaps"])


def test_mcp_adapter_dispatches_with_core_parity_and_schema_matches_the_contract(graph_run) -> None:
    core, ids = graph_run
    adapter = RetrievalMcpAdapter(core)
    arguments = {"mode": "guards", "subject": ids["sink_memcpy"]}
    via_adapter, direct = adapter.call("query_code_graph", arguments), core.query_code_graph(**arguments)
    assert via_adapter["results"] == direct["results"] and via_adapter["tool"] == "query_code_graph"
    schema = next(tool for tool in TOOLS if tool["name"] == c.QUERY_CODE_GRAPH)["inputSchema"]
    assert schema["required"] == ["mode", "subject"] and schema["additionalProperties"] is False
    assert schema["properties"]["mode"]["enum"] == [mode.value for mode in c.Mode]
    assert schema["properties"]["depth"]["maximum"] == c.MAX_TOOL_DEPTH
    assert schema["properties"]["limit"]["maximum"] == c.MAX_TOOL_LIMIT
    assert "unclassified" in schema["properties"]["sink_class"]["enum"]
    assert not {"path", "name", "language"} & set(schema["properties"])
    catalog = json.loads((Path(__file__).resolve().parents[1] / "docs" / "schemas" /
                          "retrieval-mcp-tools.json").read_text(encoding="utf-8"))
    assert {"name": "query_code_graph", "required": ["mode", "subject"],
            "properties": list(schema["properties"])} in catalog["tools"]


def _capability(ids: Mapping[str, str], **overrides: Any) -> CellCapability:
    values = dict(run_id=RUN_ID, manifest_sha256="m" * 64, package_id="package-1", package_sha256="p" * 64,
                  role=Role.INDEPENDENT_VERIFIER, round=0, tools=("query_code_graph",), indexes=("graph",),
                  entities=tuple(ids.values()), max_queries=5, max_turns=4, page_size=10, max_depth=3,
                  max_result_bytes=8192)
    values.update(overrides)
    return CellCapability.issue(**values)


def test_cell_capability_grants_graph_index_scope_and_denies_path_like_subjects(graph_run) -> None:
    core, ids = graph_run
    assert TOOL_INDEXES["query_code_graph"] == {"graph"}
    capability = _capability(ids)
    allowed = capability.authorize({"tool": "query_code_graph",
                                    "parameters": {"mode": "callers", "subject": ids["sym_helper"], "depth": 2}})
    assert isinstance(allowed, Authorized) and allowed.parameters["limit"] == 10
    for subject in ("../../etc/passwd", "/src/net.c", "src/net.c"):
        denied = capability.authorize({"tool": "query_code_graph", "parameters": {"mode": "sinks", "subject": subject}})
        assert isinstance(denied, AuthorityDenied) and denied.code == "schema_violation"
    assert capability.authorize({"tool": "query_code_graph", "parameters": {
        "mode": "sinks", "subject": ids["sym_main"], "path": "src/net.c"}}).code == "forbidden_parameter"
    outside = "asr:symbol:" + "9" * 64
    assert capability.authorize({"tool": "query_code_graph", "parameters": {
        "mode": "sinks", "subject": outside}}).code == "entity_out_of_scope"
    no_graph = _capability(ids, indexes=("source",))
    assert no_graph.authorize({"tool": "query_code_graph", "parameters": {
        "mode": "sinks", "subject": ids["sym_main"]}}).code == "index_not_granted"


def test_mcp_review_roles_include_the_graph_tool() -> None:
    for role in ("hypothesis_hunter", "red_team_analyst", "blue_team_refuter", "independent_verifier",
                 "adjudication_judge", "red", "blue", "verifier"):
        assert "query_code_graph" in _ROLE_TOOLS[role]
