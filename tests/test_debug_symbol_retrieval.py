"""Both producer lanes use the same immutable, capability-scoped query contract."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import time

import pytest

from appsec_review.debug_symbols.contract import QueryMode, RecordKind
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.mcp.schema import TOOLS
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind,
    RelationRecord, RetrievalCore, RetrievalLimits, write_manifest,
)
from appsec_review.retrieval.core import RetrievalIntegrityError
from appsec_review.retrieval.debug_symbol_index import address_prefixes, interval_prefixes
from appsec_review.review.capability import Authorized, AuthorityDenied, CellCapability
from appsec_review.review.cells import _bound

RUN = "2026-10-28-0001"
SNAPSHOT = "target:" + "1" * 64


def _id(kind, name):
    return LogicalIdentity.derive(kind, SNAPSHOT, {"fixture": name})


def build_run(tmp_path, target="clang", *, debug=True, partial=False, graph=True, empty=False):
    root = tmp_path / "runs" / RUN
    target_root = tmp_path / "target"
    target_root.mkdir(parents=True)
    identities = {
        "artifact": _id(EntityKind.EXECUTABLE, "a"),
        "other_artifact": _id(EntityKind.EXECUTABLE, "b"),
        "source": _id(EntityKind.SOURCE_FILE, "s"),
        "symbol": _id(EntityKind.SYMBOL, "function"),
        "symbol2": _id(EntityKind.SYMBOL, "function2"),
        "type": _id(EntityKind.SYMBOL, "type"),
        "inline": _id(EntityKind.SYMBOL, "inline"),
        "unit": _id(EntityKind.COMPILE_UNIT, "unit"),
        "source_range": _id(EntityKind.SOURCE_SPAN, "line"),
        "other": _id(EntityKind.SYMBOL, "other"),
        "sink": _id(EntityKind.SINK_SITE, "sink"),
    }
    ids = {key: value.value for key, value in identities.items()}
    indexes = []

    def publish(name, records, relations=()):
        path = root / "data" / "indices" / f"{name}.sqlite"
        fingerprint = ("a" if name == "debug_symbols" else "b") * 64
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT)
        for record in records:
            builder.add_entity(record)
        for relation in relations:
            builder.add_relation(relation)
        areas = [ids["artifact"], ids["other_artifact"]] if name == "debug_symbols" else ["symbols"]
        for area in areas:
            status = "unavailable" if empty else "partial" if partial else "complete"
            gap = "no paired symbols" if empty else "optimized variable locations unavailable" if partial else None
            if area == ids["other_artifact"]:
                status, gap = "unavailable", "foreign artifact gap must not escape"
            builder.add_coverage(area, status, gap)
        digest = builder.build()
        indexes.append(IndexIdentity(name, "appsec-review/retrieval-index/2", digest, fingerprint,
                                      path.relative_to(root).as_posix(), {"compiler_target": target}))

    def record(key, kind, ranges=(), **data):
        artifact = ids["other_artifact"] if key == "other" else ids["artifact"]
        return EntityRecord(identities[key], key, "private-" + key, "", {
            "record_kind": kind.value, "artifact_identity": artifact,
            "artifact_sha256": "c" * 64, "debug_sha256": "d" * 64,
            "compiler_target": target, "native_key": key, "parent_key": None,
            "address_ranges": [{"start": start, "end": end} for start, end in ranges], **data,
        })

    if debug:
        publish("debug_symbols", [
            record("symbol", RecordKind.SYMBOL, [(0, 16), (2**64 - 16, 2**64)],
                   source_identity=ids["source"], signature="int f(int)"),
            record("symbol2", RecordKind.SYMBOL, [(16, 32)], parent_identity=ids["source"]),
            record("type", RecordKind.TYPE_LAYOUT, size_bytes=8, members=[{"offset": 0}]),
            record("inline", RecordKind.INLINE_FRAME, [(2, 4)], parent_key="symbol"),
            record("unit", RecordKind.COMPILATION_UNIT),
            record("source_range", RecordKind.SOURCE_RANGE, [(0, 4)], source_identity=ids["source"]),
            record("other", RecordKind.SYMBOL, [(0, 16)]),
        ] if not empty else [], [
            RelationRecord(RelationKind.SAME_AS, ids["symbol"], ids["sink"], True, 1.0),
            RelationRecord(RelationKind.SAME_AS, ids["symbol2"], ids["sink"], False, 0.5,
                           ambiguity="name only"),
        ] if graph and not empty else [])
    publish("source", [EntityRecord(identities["source"], "source", "", "", {})])
    if graph:
        publish("graph", [EntityRecord(identities["sink"], "sink", "", "",
                                        {"exact": True, "scope": {"scope_id": "native"}})])
    manifest = root / "data" / "indices" / "manifest.json"
    write_manifest(manifest, run_id=RUN, target_snapshot=SNAPSHOT, target_root=target_root, indexes=indexes)
    return RetrievalCore(root.parent, RUN, manifest_path=manifest), ids


@pytest.fixture(params=["clang", "msvc"])
def symbols(tmp_path, request):
    return build_run(tmp_path, request.param)


@pytest.mark.parametrize("mode,key,parameters", [
    ("symbol", "symbol", {"subject": "symbol"}),
    ("address", "symbol", {"artifact_identity": "artifact", "address": 15}),
    ("source_ranges", "source_range", {"subject": "source"}),
    ("type_layout", "type", {"subject": "type"}),
    ("inline_frames", "inline", {"subject": "symbol"}),
    ("compilation_units", "unit", {"artifact_identity": "artifact"}),
    ("coverage", "artifact", {"artifact_identity": "artifact"}),
    ("graph_links", "symbol", {"subject": "symbol"}),
])
def test_every_mode_preserves_evidence(symbols, mode, key, parameters):
    core, ids = symbols
    params = {name: ids.get(value, value) if isinstance(value, str) else value
              for name, value in parameters.items()}
    result = core.query_debug_symbols(mode=mode, **params)
    assert ids[key] in {row["identity"] for row in result["results"]}
    assert result["index_manifest"]["sha256"] == core.manifest_sha256
    assert result["tool"] == "query_debug_symbols"
    row = result["results"][0]
    assert row["index"] == "debug_symbols"
    assert row["artifact_reference"]["identity"]
    if mode == "graph_links":
        assert row["graph_links"][0]["target_id"] == ids["sink"]
        assert row["graph_links"][0]["exact"] is True
    elif mode != "coverage":
        assert row["payload"]["artifact_sha256"] == "c" * 64


def test_unsigned_half_open_interval_queries_are_indexed(symbols):
    core, ids = symbols
    for address, expected in [(0, "symbol"), (15, "symbol"), (16, "symbol2"),
                               (31, "symbol2"), (2**64 - 1, "symbol")]:
        rows = core.query_debug_symbols(mode="address", artifact_identity=ids["artifact"],
                                         address=address)["results"]
        assert ids[expected] in {row["identity"] for row in rows}
        assert ids["other"] not in {row["identity"] for row in rows}
    assert not core.query_debug_symbols(mode="address", artifact_identity=ids["artifact"],
                                         address=32)["results"]
    path = core.run_root / core.indexes["debug_symbols"][0]["relative_path"]
    with sqlite3.connect(path) as database:
        plan = database.execute("EXPLAIN QUERY PLAN SELECT identity FROM debug_symbol_addresses "
                                "WHERE artifact_identity=? AND prefix=? LIMIT 101",
                                (ids["artifact"], "0:0000000000000000")).fetchall()
    assert any("SEARCH" in row[3] for row in plan)
    assert not any("SCAN" in row[3] for row in plan)


@pytest.mark.parametrize("start,end", [
    (0, 2**64), (2**64 - 1, 2**64), (2**63 - 1, 2**63 + 1), (3, 4097), (0, 1),
])
def test_radix_cover_includes_last_u64_byte_without_signed_sqlite_values(start, end):
    cover = set(interval_prefixes(start, end))
    assert 1 <= len(cover) <= 128
    for point in {0, start, max(0, start - 1), end - 1, min(2**64 - 1, end), 2**64 - 1}:
        assert bool(cover & set(address_prefixes(point))) == (start <= point < end)


@pytest.mark.parametrize("bound", ["MAX_PREFIXES_PER_RECORD", "MAX_LOOKUP_ROWS"])
def test_offline_address_lookup_expansion_is_bounded(tmp_path, monkeypatch, bound):
    from appsec_review.retrieval import debug_symbol_index
    monkeypatch.setattr(debug_symbol_index, bound, 1)
    with pytest.raises(ValueError, match="bound exceeded"):
        build_run(tmp_path)


def test_address_query_plan_does_not_scan_artifact_entities(symbols, monkeypatch):
    core, ids = symbols
    open_database = core._database
    plans = []

    class CheckedConnection:
        def __init__(self, database):
            self.database = database

        def execute(self, query, parameters=()):
            if query.startswith("SELECT e.*"):
                plans.extend(row[3] for row in self.database.execute("EXPLAIN QUERY PLAN " + query, parameters))
            return self.database.execute(query, parameters)

        def close(self):
            self.database.close()

    monkeypatch.setattr(core, "_database", lambda shard, deadline: CheckedConnection(open_database(shard, deadline)))
    assert core.query_debug_symbols(mode="address", artifact_identity=ids["artifact"], address=15)["results"]
    assert any("debug_symbol_addresses" in step and "SEARCH" in step for step in plans)
    assert not any("SCAN d" in step or "SCAN e" in step for step in plans)


def test_source_parent_and_cross_artifact_binding(symbols):
    core, ids = symbols
    assert core.query_debug_symbols(mode="inline_frames", subject=ids["symbol"])["results"][0][
        "payload"]["parent_identity"] == ids["symbol"]
    assert core.query_debug_symbols(mode="source_ranges", subject=ids["source"])["results"]
    assert not core.query_debug_symbols(mode="symbol", subject=ids["symbol"],
                                         artifact_identity=ids["other_artifact"])["results"]
    assert not core.query_debug_symbols(mode="graph_links", subject=ids["symbol2"])["results"]


def test_graph_links_require_present_accepted_facts(tmp_path):
    core, ids = build_run(tmp_path, graph=False)
    response = core.query_debug_symbols(mode="graph_links", subject=ids["symbol"])
    assert not response["results"] and any("graph index is unavailable" in gap for gap in response["coverage_gaps"])


def test_deterministic_pages_query_bound_cursors(symbols):
    core, ids = symbols
    query = {"mode": "symbol", "artifact_identity": ids["artifact"], "limit": 1}
    first = core.query_debug_symbols(**query)
    again = core.query_debug_symbols(**query)
    assert first["results"] == again["results"]
    assert first["pagination"] == again["pagination"]
    cursor = first["pagination"]["next_cursor"]
    assert cursor
    second = core.query_debug_symbols(**query, cursor=cursor)
    assert second["results"][0]["identity"] != first["results"][0]["identity"]
    for change in ({"mode": "type_layout"}, {"artifact_identity": ids["other_artifact"]}, {"limit": 2}):
        with pytest.raises(ValueError, match="cursor"):
            core.query_debug_symbols(**{**query, **change, "cursor": cursor})
    with pytest.raises(ValueError, match="cursor"):
        core.query_debug_symbols(**query, cursor="invalid")
    core.limits = RetrievalLimits(max_results=1)
    with pytest.raises(ValueError, match="result bound"):
        core.query_debug_symbols(**{**query, "limit": 2})


@pytest.mark.parametrize("parameters", [
    {}, {"mode": "invented"}, {"mode": "address", "address": 1},
    {"mode": "address", "artifact_identity": "artifact", "address": -1},
    {"mode": "address", "artifact_identity": "artifact", "address": 2**64},
    {"mode": "address", "artifact_identity": "artifact", "address": True},
    {"mode": "symbol", "subject": "symbol", "address": 1},
    {"mode": "source_ranges", "subject": "artifact"},
    {"mode": "compilation_units", "subject": "symbol"},
    {"mode": "coverage", "subject": "symbol"},
    {"mode": "graph_links", "artifact_identity": "artifact"},
    {"mode": "symbol", "subject": "symbol", "limit": 0},
    {"mode": "symbol", "subject": "symbol", "limit": 101},
    {"mode": "symbol", "subject": "symbol", "limit": True},
])
def test_mode_specific_validation(symbols, parameters):
    core, ids = symbols
    parameters = {key: ids.get(value, value) if isinstance(value, str) else value
                  for key, value in parameters.items()}
    with pytest.raises((ValueError, TypeError)):
        core.query_debug_symbols(**parameters)


def test_unavailable_empty_and_partial_are_distinct(tmp_path):
    missing, ids = build_run(tmp_path / "missing", debug=False)
    unavailable = missing.query_debug_symbols(mode="symbol", artifact_identity=ids["artifact"])
    assert not unavailable["results"] and any("unavailable" in gap for gap in unavailable["coverage_gaps"])
    core, ids = build_run(tmp_path / "present", partial=True)
    empty = core.query_debug_symbols(mode="address", artifact_identity=ids["artifact"], address=64)
    assert not empty["results"]
    assert any("optimized variable" in gap for gap in empty["coverage_gaps"])
    assert any("no matching" in gap for gap in empty["coverage_gaps"])
    unavailable, ids = build_run(tmp_path / "empty", empty=True)
    coverage = unavailable.query_debug_symbols(mode="coverage", artifact_identity=ids["artifact"])
    assert coverage["results"][0]["payload"]["coverage"][0]["status"] == "unavailable"
    assert "foreign artifact" not in json.dumps(coverage)


def test_hash_timeout_byte_bounds_and_private_telemetry(tmp_path):
    core, ids = build_run(tmp_path)
    adapter = RetrievalMcpAdapter(core)
    query = {"mode": "symbol", "artifact_identity": ids["artifact"]}
    assert adapter.call("query_debug_symbols", query)["results"]
    events = [json.loads(line) for path in core.run_root.rglob("*.jsonl")
              for line in path.read_text(encoding="utf-8").splitlines()]
    event = next(item for item in events if item.get("event_type") == "DEBUG_SYMBOL_QUERY_COMPLETED")
    details = event["details"]
    assert details["compiler_target"] == "clang" and details["mode"] == "symbol"
    assert details["returned_count"] == 2 and details["duration_ms"] >= 0
    assert not any("private" in str(item) for item in details.values())
    core.limits = RetrievalLimits(max_response_bytes=2200)
    bounded = core.query_debug_symbols(**query)
    assert len(json.dumps(bounded, separators=(",", ":"), sort_keys=True).encode()) <= 2200
    assert bounded["truncated"]
    core.limits = RetrievalLimits()
    core.clock = iter([0.0, 3.0, 3.0, 3.0, 3.0, 3.0]).__next__
    timed = core.query_debug_symbols(**query)
    assert timed["truncated"] and any("execution-time" in gap for gap in timed["coverage_gaps"])
    core.clock = time.monotonic
    path = core.run_root / core.indexes["debug_symbols"][0]["relative_path"]
    with path.open("ab") as stream:
        stream.write(b"drift")
    with pytest.raises(RetrievalIntegrityError):
        core.query_debug_symbols(**query)
    events = [json.loads(line) for path in core.run_root.rglob("*.jsonl")
              for line in path.read_text(encoding="utf-8").splitlines()]
    completed = [item["details"] for item in events if item.get("event_type") == "DEBUG_SYMBOL_QUERY_COMPLETED"]
    assert completed[-1]["terminal_status"] == "FAILED"
    assert completed[-1]["gap_count"] == 1 and completed[-1]["compiler_target"] == "clang"


def _cap(ids, **overrides):
    return CellCapability.issue(
        run_id=RUN, manifest_sha256="a" * 64, package_id="p", package_sha256="b" * 64,
        role="independent_verifier", round=0, tools=["query_debug_symbols"],
        indexes=overrides.get("indexes", ["debug_symbols"]),
        entities=overrides.get("entities", [ids["artifact"]]),
        graph_scopes=overrides.get("graph_scopes", ()),
        max_queries=5, max_turns=3, page_size=2, max_depth=2, max_result_bytes=100000)


def test_cell_and_mcp_capabilities_close_over_artifact_not_other_artifacts(symbols):
    core, ids = symbols
    query = {"mode": "symbol", "artifact_identity": ids["artifact"], "limit": 2}
    cap = _cap(ids)
    assert isinstance(cap.authorize({"tool": "query_debug_symbols", "parameters": query}), Authorized)
    assert isinstance(cap.authorize({"tool": "query_debug_symbols", "parameters": {
        **query, "artifact_identity": ids["other_artifact"]}}), AuthorityDenied)
    assert isinstance(_cap(ids, indexes=[]).authorize({
        "tool": "query_debug_symbols", "parameters": query}), AuthorityDenied)
    assert isinstance(cap.authorize({"tool": "query_debug_symbols", "parameters": {
        **query, "address": 1}}), AuthorityDenied)
    response = core.query_debug_symbols(**query)
    bounded, withheld = _bound("query_debug_symbols", response, cap, granted=set())
    assert not withheld and bounded["results"]
    foreign = core.query_debug_symbols(mode="symbol", artifact_identity=ids["other_artifact"])
    assert _bound("query_debug_symbols", foreign, cap)[1] == 1
    package = {"run_id": RUN, "manifest_sha256": core.manifest_sha256, "package_id": "p",
               "retrieval": {"indexes": ["debug_symbols"], "entity_ids": [ids["artifact"]],
                             "query_sets": [], "max_page_size": 2, "max_pages": 2, "max_depth": 2,
                             "max_response_bytes": 100000}}
    secret = b"s" * 32
    token = issue_capability(package, role="verifier", round_id="1", secret=secret,
                             expires_at=int(time.time()) + 300)
    scoped = ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), package, capability=token,
                                       secret=secret, role="verifier", round_id="1")
    assert scoped.call("query_debug_symbols", query)["results"]
    assert scoped.call("query_debug_symbols", {"mode": "inline_frames", "subject": ids["symbol"], "limit": 2})["results"]
    with pytest.raises(ValueError, match="outside review package"):
        scoped.call("query_debug_symbols", {**query, "artifact_identity": ids["other_artifact"]})


def test_source_and_parent_closure_do_not_grant_unrelated_rows(symbols):
    core, ids = symbols
    capability = CellCapability.issue(
        run_id=RUN, manifest_sha256=core.manifest_sha256, package_id="p", package_sha256="b" * 64,
        role="independent_verifier", round=0, tools=["query_debug_symbols"], indexes=["debug_symbols"],
        entities=[ids["source"]], max_queries=5, max_turns=3, page_size=2, max_depth=2,
        max_result_bytes=100000)
    granted = set()
    source = core.query_debug_symbols(mode="source_ranges", subject=ids["source"])
    assert _bound("query_debug_symbols", source, capability, granted=granted)[1] == 0
    assert ids["source_range"] in granted
    unrelated = core.query_debug_symbols(mode="symbol", subject=ids["symbol2"])
    assert _bound("query_debug_symbols", unrelated, capability, granted=granted)[1] == 1


def test_graph_link_scope_needs_graph_grant_and_exact_fact_scope(symbols):
    core, ids = symbols
    response = core.query_debug_symbols(mode="graph_links", subject=ids["symbol"])
    no_graph = _cap(ids, entities=[ids["symbol"]])
    request = {"tool": "query_debug_symbols", "parameters": {"mode": "graph_links", "subject": ids["symbol"]}}
    assert isinstance(no_graph.authorize(request), AuthorityDenied)
    assert _bound("query_debug_symbols", response, no_graph)[1] == 1
    wrong = _cap(ids, indexes=["debug_symbols", "graph"], entities=[ids["symbol"]], graph_scopes=["foreign"])
    assert _bound("query_debug_symbols", response, wrong)[1] == 1
    granted = set()
    right = _cap(ids, indexes=["debug_symbols", "graph"], entities=[ids["symbol"]], graph_scopes=["native"])
    assert _bound("query_debug_symbols", response, right, granted=granted)[1] == 0
    assert ids["sink"] in granted
    package = {"run_id": RUN, "manifest_sha256": core.manifest_sha256, "package_id": "p",
               "retrieval": {"indexes": ["debug_symbols", "graph"], "entity_ids": [ids["symbol"]],
                             "graph_scopes": ["foreign"], "query_sets": [], "max_page_size": 2,
                             "max_pages": 2, "max_depth": 2, "max_response_bytes": 100000}}
    secret = b"s" * 32

    def scoped():
        token = issue_capability(package, role="verifier", round_id="1", secret=secret,
                                 expires_at=int(time.time()) + 300)
        return ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), package, capability=token,
                                         secret=secret, role="verifier", round_id="1")

    with pytest.raises(ValueError, match="escaped review package"):
        scoped().call("query_debug_symbols", {**request["parameters"], "limit": 2})
    package["retrieval"]["graph_scopes"] = ["native"]
    assert scoped().call("query_debug_symbols", {**request["parameters"], "limit": 2})["results"]


def test_public_schema_closed_modes_and_no_name_or_paths():
    schema = next(tool["inputSchema"] for tool in TOOLS if tool["name"] == "query_debug_symbols")
    assert schema["required"] == ["mode"]
    assert set(schema["properties"]["mode"]["enum"]) == {mode.value for mode in QueryMode}
    assert not set(schema["properties"]) & {"name", "path", "sql", "regex", "url"}
