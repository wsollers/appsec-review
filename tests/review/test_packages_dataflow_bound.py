"""Dataflow-path-bounded lead neighborhoods (``package-neighborhood/3``), their slices and slice-only views.

parse.c (from the inference-review fixture)::

    1  #include <string.h>
    2  void p(char *s) {
    3    char b[8]; strcpy(b, s);
    4  }
    5  int q(int n) { return n * 4; }

The CodeQL-correlated path runs from the entry point ``n`` in q, through the ``n * 4`` call into p, to the
``strcpy`` sink in p; the SAST lead on line 3 correlates it. Call sites: q -> p (on the path), p -> strcpy (a
library call, off the path) and outer -> q (outer is not on the path; call-depth BFS would reach it).
"""
from __future__ import annotations

from dataclasses import asdict
import json
from typing import Any

import jsonschema
import pytest

from appsec_review.graph.contract import Family
from appsec_review.retrieval import EntityKind, EntityRecord, RelationKind as IndexRelation, RelationRecord
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.retrieval.model import LogicalIdentity
from appsec_review.review import package_view
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import IntegrityError
from appsec_review.review.neighborhood import NEIGHBORHOOD_RULE
from appsec_review.review.package_view import VIEW_RULE, VIEW_SCHEMA, ViewLimits, build_view
from appsec_review.review.packages import (
    ASSEMBLY_RULE, MANIFEST_SCHEMA, PACKAGE_SCHEMA, GraphContext, GraphSettings, assemble_packages,
    publish_packages, slice_gap, trim_slice, verify_package_manifest,
)
from appsec_review.review.schemas import (
    MANIFEST_SCHEMA_FILE, VIEW_SCHEMA_FILE, schema_path, validate as validate_schema, validator,
)
from appsec_review.review.scope import accept_manifest
from appsec_review.review.slicing.contract import SLICE_PRODUCER, SLICE_RULE
from appsec_review.review.slicing.sources import AcceptedSliceSources, UnavailableSliceSources
from tests.fixtures.inference_review.builder import SNAPSHOT, build_accepted_index_set
from tests.review.test_graph_admissibility import SCOPE_ID, graph_entity, results_for
from tests.review.test_packages_graph_context import PARSE, SCHEMA, _location, _span
from tests.review.test_packages_memory_context import _publish

LIMITS = ViewLimits(48 * 1024, 160, 6)
GRAPH_PRODUCER = {"job": "job_code_graph_index", "build_unit_id": "native-main"}


def _symbol(fixture, name: str, needle: str) -> EntityRecord:
    identity = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"qualified_name": name, "scope_id": SCOPE_ID})
    return EntityRecord(identity, name, name, f"function {name}", {
        "producer": "codeql-export", "scope": {"scope_id": SCOPE_ID, "build_unit_id": "native-main"},
        "kind": "function", "qualified_name": name, "exact": True, "gaps": []}, _location(fixture, PARSE, needle))


def _call(fixture, caller: tuple[str, str], callee: tuple[str | None, str], needle: str) -> EntityRecord:
    location = _location(fixture, PARSE, needle)
    return graph_entity(Family.CALL_SITE, {**_span(location), "caller_symbol": caller[0], "callee_name": callee[1]},
                        {"caller": {"symbol": caller[0], "display": caller[1]},
                         "callee": {"symbol": callee[0], "display": callee[1], "dispatch": "direct",
                                    "candidate_count": 1}}, location, snapshot=SNAPSHOT)


def publish_dataflow(fixture) -> dict[str, str]:
    """Symbols p and q, three call sites, an entry point, a sink, a guard and one path correlated to the
    SAST lead on parse.c:3; returns their identities."""
    p, q = _symbol(fixture, "p", "p(char"), _symbol(fixture, "q", "q(int")
    outer = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"qualified_name": "outer", "scope_id": SCOPE_ID}).value
    into_p = _call(fixture, (q.identity.value, "q"), (p.identity.value, "p"), "n * 4")
    out_of_p = _call(fixture, (p.identity.value, "p"), (None, "strcpy"), "strcpy(b, s)")
    into_q = _call(fixture, (outer, "outer"), (q.identity.value, "q"), "string.h")
    param_n, multiply = _location(fixture, PARSE, "int n"), _location(fixture, PARSE, "n * 4")
    strcpy, param_s = _location(fixture, PARSE, "strcpy(b, s)"), _location(fixture, PARSE, "char *s")
    entry = graph_entity(Family.ENTRY_POINT, {**_span(param_n), "source_class": "remote"},
                         {**results_for(Family.ENTRY_POINT, "remote"),
                          "enclosing_function": {"symbol": q.identity.value, "display": "q"}}, param_n, snapshot=SNAPSHOT)
    sink = graph_entity(Family.SINK_SITE, {**_span(strcpy), "sink_class": "memory_write", "argument_index": 0},
                        {**results_for(Family.SINK_SITE), "api": {"display": "strcpy"},
                         "enclosing_function": {"symbol": p.identity.value, "display": "p"}}, strcpy, snapshot=SNAPSHOT)
    sink_id, entry_id = sink.identity.value, entry.identity.value
    guard = graph_entity(Family.GUARD_FACT, {"sink_identity": sink_id, "condition_path": PARSE,
                                             "condition_start_byte": param_s.start_byte,
                                             "condition_end_byte": param_s.end_byte},
                         results_for(Family.GUARD_FACT, sink=sink_id), param_s, snapshot=SNAPSHOT)
    steps = [{"n": 0, "role": "source", "location": asdict(param_n), "symbol": q.identity.value, "display": "n"},
             {"n": 1, "role": "call", "location": asdict(multiply), "symbol": q.identity.value, "display": "n * 4"},
             {"n": 2, "role": "sink", "location": asdict(strcpy), "symbol": p.identity.value, "display": "strcpy"}]
    path = graph_entity(Family.DATAFLOW_PATH, {"source_identity": entry_id, "sink_identity": sink_id,
                                               "step_locations_sha256": "3" * 64},
                        {**results_for(Family.DATAFLOW_PATH, "remote", sink=sink_id, entry=entry_id),
                         "steps": steps, "hop_count": 2, "guards": [guard.identity.value]}, strcpy, snapshot=SNAPSHOT)
    relations = [
        RelationRecord(IndexRelation.DERIVED_FROM, path.identity.value, fixture.ids["sast_critical"], True, 1.0,
                       payload={"code_flow": 0, "state": "bridged", "matched_steps": 3, "ambiguous_steps": 0,
                                "unmatched_steps": 0}),
        RelationRecord(IndexRelation.GUARDS, guard.identity.value, sink_id, True, 1.0)]
    _publish(fixture, [
        ("graph", "cpp-native-symbols", GRAPH_PRODUCER, [p, q], [], ("graph:native:symbols", "complete", None)),
        ("graph", "cpp-native-dataflow", {**GRAPH_PRODUCER, "family": "dataflow_path"},
         [entry, sink, guard, path, into_p, out_of_p, into_q], relations,
         ("graph:native:dataflow_path", "complete", None))])
    return {"p": p.identity.value, "q": q.identity.value, "outer": outer, "into_p": into_p.identity.value,
            "out_of_p": out_of_p.identity.value, "into_q": into_q.identity.value, "entry": entry_id,
            "sink": sink_id, "guard": guard.identity.value, "path": path.identity.value}


@pytest.fixture(scope="module")
def dataflow(tmp_path_factory):
    fixture = build_accepted_index_set(tmp_path_factory.mktemp("dfbound"))
    ids = publish_dataflow(fixture)
    scope = accept_manifest(fixture.run_root)
    return fixture, ids, scope, assemble_packages(scope), RetrievalCore(fixture.runs_dir, fixture.run_id)


def _package(assembly, fixture, key: str) -> dict[str, Any]:
    [document] = [item.document() for item in assembly.packages
                  if item.kind == "finding_lead" and item.lead_ids == (fixture.ids[key],)]
    return document


def _refs(neighborhood: dict[str, Any]) -> set[str]:
    sections = ("sinks", "ranges", "guards", "callers", "callees", "flows", "entries")
    return ({row["ref"] for name in sections for row in neighborhood[name]}
            | {row["ref"] for row in neighborhood["chain"]["hops"]})


def _slice_gaps(package: dict[str, Any]) -> list[dict[str, Any]]:
    return [gap for gap in package["coverage_gaps"] if gap["producer"] == SLICE_PRODUCER]


# ------------------------------------------------------------------------------------------------ bound selection


def test_a_lead_with_a_correlated_path_is_bounded_by_it_and_carries_a_slice(dataflow) -> None:
    fixture, ids, _scope, assembly, _core = dataflow
    neighborhood = _package(assembly, fixture, "sast_critical")["neighborhood"]
    assert neighborhood["rule"] == NEIGHBORHOOD_RULE == "appsec-review/package-neighborhood/3"
    assert neighborhood["bound"] == {"kind": "dataflow_path", "paths": [ids["path"]], "call_depth": None}
    assert neighborhood["function"]["symbol"] == ids["p"]
    assert [row["ref"] for row in neighborhood["flows"]] == [ids["path"]]
    assert [row["ref"] for row in neighborhood["sinks"]] == [ids["sink"]]
    assert [row["ref"] for row in neighborhood["guards"]] == [ids["guard"]]
    # Only calls between functions on the path: q -> p. The library call out of p and outer -> q are not.
    assert [row["ref"] for row in neighborhood["callers"]] == [ids["into_p"]]
    assert neighborhood["callees"] == []
    assert neighborhood["chain"]["reached"] and [row["ref"] for row in neighborhood["chain"]["hops"]] == [ids["into_p"]]
    assert [row["ref"] for row in neighborhood["chain"]["entries"]] == [ids["entry"]]

    found = neighborhood["slice"]
    assert found["rule"] == SLICE_RULE and found["paths"] == [ids["path"]]
    by_line = {(item["path"], line["line"]): line for item in found["functions"] for line in item["lines"]}
    assert "sink" in by_line[(PARSE, 3)]["reasons"] and by_line[(PARSE, 3)]["precision"] == "path"
    assert "guard" in by_line[(PARSE, 2)]["reasons"]            # the guard anchors through its resolved location
    assert "source" in by_line[(PARSE, 5)]["reasons"]
    assert {item["function"] for item in found["functions"]} <= {ids["p"], ids["q"]}


def test_the_path_bound_does_not_walk_call_depth_beyond_the_path(dataflow) -> None:
    fixture, ids, scope, assembly, _core = dataflow
    bounded = _package(assembly, fixture, "sast_critical")["neighborhood"]
    graph = GraphContext(scope)
    walked, _context, _gaps = graph.call_depth_neighborhood(PARSE, 3, GraphSettings(), "subject")
    # The call-depth walk from p reaches outer -> q (a caller of a caller) and the library call out of p.
    assert {ids["into_q"], ids["out_of_p"]} <= _refs(walked)
    assert not {ids["into_q"], ids["out_of_p"]} & _refs(bounded)
    assert walked["bound"] == {"kind": "call_depth", "paths": [], "call_depth": GraphSettings().max_call_depth}
    assert walked["slice"] is None


def test_a_lead_without_a_path_keeps_call_depth_and_names_the_unavailable_path(dataflow) -> None:
    fixture, ids, _scope, assembly, _core = dataflow
    package = _package(assembly, fixture, "codeql_high")                 # parse.c:5 in q, no correlated path
    neighborhood = package["neighborhood"]
    assert neighborhood["bound"]["kind"] == "call_depth" and neighborhood["bound"]["paths"] == []
    assert neighborhood["bound"]["call_depth"] == neighborhood["call_depth"] and neighborhood["slice"] is None
    assert ids["into_q"] in {row["ref"] for row in neighborhood["callers"]}      # call-depth behaviour unchanged
    [gap] = _slice_gaps(package)
    assert gap["state"] == "unavailable" and gap["reason"].startswith(
        "dataflow_path_unavailable: no correlated dataflow path for this lead; the neighborhood is bounded by "
        f"call depth {neighborhood['call_depth']}")


def test_slice_gaps_become_named_package_gaps(dataflow) -> None:
    fixture, _ids, _scope, assembly, _core = dataflow
    package = _package(assembly, fixture, "sast_critical")
    stored = {(gap["state"], gap["reason"]) for gap in _slice_gaps(package)}
    assert {reason for _state, reason in stored} == set(package["neighborhood"]["slice"]["gaps"])
    # No compiler or syntax producer is accepted in the fixture: those strategies are not applicable.
    assert any(state == "unavailable" and reason.startswith("slice_strategy_not_applicable: llvm_ir_def_use")
               for state, reason in stored)
    assert not any(reason.startswith("dataflow_path_unavailable") for _state, reason in stored)
    states = {item["name"]: item["state"] for item in package["neighborhood"]["slice"]["strategies"]}
    assert states["lexical_identifiers"] == "applied"
    assert states["llvm_ir_def_use"] == states["svf_points_to"] == states["tree_sitter_references"] == "not_applicable"


@pytest.mark.parametrize(("reason", "state"), [
    ("slice_truncated: 3 lines", "truncated"),
    ("slice_strategy_failed: svf_points_to: RuntimeError", "failed"),
    ("dataflow_path_unavailable: x", "unavailable"),
    ("slice_strategy_not_applicable: llvm_ir_def_use: no IR", "unavailable"),
    ("slice_source_unavailable: a.c: gone", "unavailable"),
    ("slice_function_unresolved: a.c:3: none", "unavailable"),
    ("slice_strategy_partial: tree_sitter_references: a.c", "partial"),
    ("slice_lexical_only: a.c:1-4", "partial"),
    ("slice_function_fallback: tree_sitter rows for a.c could not be read (RuntimeError)", "partial"),
    ("asr:dataflow_path:x: truncated_steps: 9 steps", "partial"),
])
def test_slice_gap_states_are_consistent(reason: str, state: str) -> None:
    gap = slice_gap(reason, "subject")
    assert (gap.producer, gap.scope, gap.state, gap.reason) == (SLICE_PRODUCER, "subject", state, reason)
    assert len(slice_gap("x" * 5000, "s").reason) == 1000


# ------------------------------------------------------------------------------------------------ isolation


class _RaisingSyntax(AcceptedSliceSources):
    def syntax_rows(self, path: str):
        raise RuntimeError("syntax index exploded")


class _RaisingSource(AcceptedSliceSources):
    def source_lines(self, path: str, file_sha256: str):
        raise RuntimeError("source custody exploded")


def test_a_failing_strategy_is_isolated_and_the_package_stays_valid(dataflow) -> None:
    fixture, _ids, scope, _assembly, _core = dataflow
    assembly = assemble_packages(scope, slice_sources=_RaisingSyntax(scope))
    package = _package(assembly, fixture, "sast_critical")
    jsonschema.Draft202012Validator(SCHEMA).validate(package)
    found = package["neighborhood"]["slice"]
    states = {item["name"]: item["state"] for item in found["strategies"]}
    assert states["tree_sitter_references"] == "failed" and states["lexical_identifiers"] == "applied"
    assert found["functions"] and {item["span_basis"] for item in found["functions"]} == {"graph_symbol"}
    assert ("failed", "slice_strategy_failed: tree_sitter_references: RuntimeError") in {
        (gap["state"], gap["reason"]) for gap in _slice_gaps(package)}
    assert any(gap["reason"].startswith("slice_function_fallback: tree_sitter rows for ")
               and gap["state"] == "partial" for gap in _slice_gaps(package))


def test_a_failing_source_facade_never_fails_assembly(dataflow) -> None:
    fixture, ids, scope, _assembly, _core = dataflow
    assembly = assemble_packages(scope, slice_sources=_RaisingSource(scope))
    package = _package(assembly, fixture, "sast_critical")
    jsonschema.Draft202012Validator(SCHEMA).validate(package)
    found = package["neighborhood"]["slice"]
    assert package["neighborhood"]["bound"]["kind"] == "dataflow_path"
    assert found["paths"] == [ids["path"]] and found["functions"] == []
    assert any(gap["state"] == "failed" and gap["reason"].startswith("slice_strategy_failed: compose: RuntimeError")
               for gap in _slice_gaps(package))


def test_without_sources_a_slice_keeps_no_text_and_names_the_gap(dataflow) -> None:
    fixture, _ids, scope, _assembly, _core = dataflow
    assembly = assemble_packages(scope, slice_sources=UnavailableSliceSources("slice sources unavailable: test"))
    package = _package(assembly, fixture, "sast_critical")
    jsonschema.Draft202012Validator(SCHEMA).validate(package)
    assert package["neighborhood"]["slice"]["functions"] == []
    assert any(gap["state"] == "unavailable" and gap["reason"].startswith("slice_source_unavailable")
               and "slice sources unavailable: test" in gap["reason"] for gap in _slice_gaps(package))


# ------------------------------------------------------------------------------------------------ schema / manifest


def test_every_package_validates_and_the_schema_rejects_a_malformed_bound(dataflow) -> None:
    fixture, _ids, _scope, assembly, _core = dataflow
    validator = jsonschema.Draft202012Validator(SCHEMA)
    for package in assembly.packages:
        validator.validate(package.document())
    bad = _package(assembly, fixture, "sast_critical")
    bad["neighborhood"]["bound"]["kind"] = "everything"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(bad)
    extra = _package(assembly, fixture, "sast_critical")
    extra["neighborhood"]["bound"]["extra"] = 1
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(extra)
    old = _package(assembly, fixture, "codeql_high")
    old["neighborhood"]["rule"] = "appsec-review/package-neighborhood/1"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(old)


def test_the_manifest_counts_finding_leads_by_bound(dataflow) -> None:
    _fixture, _ids, _scope, assembly, _core = dataflow
    counts = assembly.manifest["counts"]
    bounds = counts["neighborhood_bounds"]
    assert bounds["dataflow_path"] == 1
    assert bounds["call_depth"] + bounds["dataflow_path"] == counts["packages"]["finding_lead"]
    assert assembly.manifest["rules"]["slice"] == SLICE_RULE
    kinds = [item.document()["neighborhood"]["bound"]["kind"] for item in assembly.packages
             if item.kind == "finding_lead"]
    assert kinds.count("dataflow_path") == 1 and kinds.count("call_depth") == bounds["call_depth"]


def test_the_view_and_manifest_schemas_pin_the_emitted_versions() -> None:
    view, manifest = validator(VIEW_SCHEMA_FILE).schema, validator(MANIFEST_SCHEMA_FILE).schema
    assert view["properties"]["schema"]["const"] == VIEW_SCHEMA
    assert view["properties"]["rule"]["const"] == VIEW_RULE
    assert manifest["properties"]["schema"]["const"] == MANIFEST_SCHEMA
    assert manifest["properties"]["assembly_rule"]["const"] == ASSEMBLY_RULE
    assert manifest["properties"]["package_schema"]["const"] == PACKAGE_SCHEMA
    rules = manifest["properties"]["rules"]["properties"]
    assert rules["neighborhood"]["const"] == NEIGHBORHOOD_RULE and rules["slice"]["const"] == SLICE_RULE
    with pytest.raises(ValueError):
        schema_path("../review-packages.schema.json")


def test_every_view_and_the_manifest_validate_and_violations_raise(dataflow) -> None:
    fixture, _ids, _scope, assembly, core = dataflow
    views = [build_view(package.document(), core, LIMITS).document for package in assembly.packages]
    for document in views:
        validator(VIEW_SCHEMA_FILE).validate(document)
    assert any(row["role"] == "slice" for document in views for row in document["source"])
    validator(MANIFEST_SCHEMA_FILE).validate(assembly.manifest)

    broken = json.loads(json.dumps(views[0]))
    broken["neighborhood"]["slice"] = {"paths": 1, "lines": 2, "omitted_lines": 0, "strategies": {"x": "done"}}
    with pytest.raises(IntegrityError, match="package view violates"):
        validate_schema(VIEW_SCHEMA_FILE, broken, "package view")
    manifest = json.loads(json.dumps(assembly.manifest))
    del manifest["counts"]["neighborhood_bounds"]["dataflow_path"]
    with pytest.raises(IntegrityError, match="neighborhood_bounds"):
        validate_schema(MANIFEST_SCHEMA_FILE, manifest, "package manifest")


def test_build_view_refuses_a_view_its_schema_rejects(dataflow, monkeypatch) -> None:
    fixture, _ids, _scope, assembly, core = dataflow
    package = _package(assembly, fixture, "sast_critical")
    monkeypatch.setattr(package_view, "VIEW_RULE", "appsec-review/package-view/3")
    with pytest.raises(IntegrityError, match="review-package-view.schema.json"):
        build_view(package, core, LIMITS)


def test_verify_refuses_a_rehashed_manifest_its_schema_rejects(dataflow, tmp_path) -> None:
    _fixture, _ids, _scope, assembly, _core = dataflow
    path = publish_packages(assembly, tmp_path / "out")
    document = json.loads(path.read_text(encoding="utf-8"))
    document.pop("content_sha256")
    document["counts"]["neighborhood_bounds"]["everything"] = 1
    document["content_sha256"] = sha256_hex(document)
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(IntegrityError, match="review-package-manifest.schema.json"):
        verify_package_manifest(path)


# ------------------------------------------------------------------------------------------------ trimming


def _slice_record(lines: list[tuple[int, str]]) -> dict[str, Any]:
    return {"slice": {"rule": SLICE_RULE, "paths": ["asr:dataflow_path:x"], "omitted": {"lines": 0}, "gaps": [],
                      "strategies": [],
                      "functions": [{"path": "a.c", "file_sha256": "a" * 64, "function": None, "first": 1, "last": 20,
                                     "truncated": False,
                                     "lines": [{"line": line, "reasons": ["interacter"], "basis": "b",
                                                "precision": precision} for line, precision in lines]}]}}


def test_trim_slice_drops_lowest_precision_then_highest_line_and_keeps_path_anchors() -> None:
    record = _slice_record([(2, "path"), (4, "syntax"), (6, "lexical"), (9, "lexical")])
    assert trim_slice(record)
    assert [line["line"] for line in record["slice"]["functions"][0]["lines"]] == [2, 4, 6]
    assert trim_slice(record) and trim_slice(record)
    assert [line["line"] for line in record["slice"]["functions"][0]["lines"]] == [2]
    assert not trim_slice(record)
    assert record["slice"]["omitted"]["lines"] == 3
    assert record["slice"]["gaps"] == ["slice_truncated: slice lines omitted to respect max_package_bytes"]
    emptied = _slice_record([(3, "lexical")])
    assert trim_slice(emptied) and emptied["slice"]["functions"] == []
    assert not trim_slice({"slice": None})


# ------------------------------------------------------------------------------------------------ view


def test_the_view_shows_only_slice_lines_with_elisions_and_the_lead_line(dataflow) -> None:
    fixture, ids, _scope, assembly, core = dataflow
    package = _package(assembly, fixture, "sast_critical")
    view = build_view(package, core, LIMITS)
    assert view.document["rule"] == VIEW_RULE == "appsec-review/package-view/5"
    rows = [row for row in view.document["source"] if row["role"] == "slice"]
    by_ref = {row["ref"]: row for row in rows}
    p_row = by_ref[ids["p"]]
    assert p_row["path"] == PARSE and p_row["lines"] == "2-4"
    shown = [item for item in p_row["text"] if not item.startswith("...|")]
    assert any(item.startswith("3| ") and "strcpy(b, s)" in item for item in shown)
    assert "4| }" not in p_row["text"] and p_row["text"][-1] == "...| 1 line(s) elided"
    sliced = {line["line"] for item in package["neighborhood"]["slice"]["functions"]
              if item["function"] == ids["p"] for line in item["lines"]}
    assert {int(item.split("|", 1)[0]) for item in shown} == sliced | {3}
    assert set(p_row["reasons"]) == {str(line) for line in sliced | {3}}
    assert all(row["role"] != "function" for row in view.document["source"])
    summary = view.document["neighborhood"]
    assert summary["bound"]["kind"] == "dataflow_path" and summary["slice"]["paths"] == 1
    assert summary["slice"]["strategies"]["lexical_identifiers"] == "applied"
    assert PARSE in view.locator_paths


def test_a_call_depth_view_keeps_the_whole_function_extent(dataflow) -> None:
    fixture, ids, _scope, assembly, core = dataflow
    view = build_view(_package(assembly, fixture, "codeql_high"), core, LIMITS)
    [span] = [row for row in view.document["source"] if row["role"] == "function"]
    assert span["ref"] == ids["q"] and span["lines"] == "5-5"
    assert view.document["neighborhood"]["slice"] is None
    assert view.document["neighborhood"]["bound"]["kind"] == "call_depth"


LEAD = "asr:observation:" + "1" * 64
FN = "asr:symbol:" + "2" * 64
SHA = "c" * 64
SOURCE = [f"line {number}" for number in range(1, 13)]
SOURCE[6] = 'key = "hunter2-Xq9v"'


class _FakeCore:
    """The accepted-index boundary of the view: one lead in ``a.c`` at line 7 and its function symbol."""

    def __init__(self, sha: str = SHA, source: list[str] = SOURCE):
        self.location = {"path": "a.c", "file_sha256": sha, "start_line": 7, "end_line": 7}
        self.source = source

    def find(self, **query: Any) -> dict[str, Any]:
        if query.get("identity") == LEAD:
            return {"results": [{"identity": LEAD, "name": "lead", "location": self.location}]}
        return {"results": []}

    def read_source_lines(self, *, identity: str):
        if identity in {LEAD, FN}:
            return {"location": dict(self.location), "lines": list(self.source)}, None
        return None, "not accepted"


def _sliced_package(lines: list[int], *, first: int = 2, last: int = 11, family: str = "sast",
                    function_sha: str = SHA) -> dict[str, Any]:
    return {"kind": "finding_lead", "scope": {}, "context": [], "coverage_gaps": [], "retrieval": {"entity_ids": []},
            "lead_menu": [{"observation_id": LEAD, "lead_family": family}],
            "neighborhood": {
                "rule": NEIGHBORHOOD_RULE, "call_depth": 2, "chain": {}, "function": {
                    "symbol": FN, "name": "f", "path": "a.c", "start_line": first, "file_sha256": function_sha,
                    "basis": "enclosing_fact_on_line"},
                "bound": {"kind": "dataflow_path", "paths": ["asr:dataflow_path:x"], "call_depth": None},
                "slice": {"rule": SLICE_RULE, "paths": ["asr:dataflow_path:x"], "omitted": {"lines": 0}, "gaps": [],
                          "strategies": [{"name": "lexical_identifiers", "precision": "lexical", "state": "applied",
                                          "lines": len(lines), "gaps": []}],
                          "functions": [{"path": "a.c", "file_sha256": SHA, "function": FN, "first": first,
                                         "last": last, "truncated": False,
                                         "lines": [{"line": line, "reasons": ["path_step"], "basis": "path",
                                                    "precision": "path"} for line in lines]}]}}}


def test_slice_rendering_elides_between_runs_and_always_shows_the_lead_line() -> None:
    view = build_view(_sliced_package([3, 4, 10]), _FakeCore(), LIMITS)
    [row] = [item for item in view.document["source"] if item["role"] == "slice"]
    assert row["ref"] == FN and row["lines"] == "2-11"
    assert row["text"] == ["...| 1 line(s) elided", "3| line 3", "4| line 4", "...| 2 line(s) elided",
                           f"7| {SOURCE[6]}", "...| 2 line(s) elided", "10| line 10", "...| 1 line(s) elided"]
    assert row["reasons"] == {"3": "path_step", "4": "path_step", "7": "lead", "10": "path_step"}


def test_a_lead_outside_every_slice_function_gets_its_own_line_row() -> None:
    view = build_view(_sliced_package([2, 3], first=2, last=4), _FakeCore(), LIMITS)
    rows = [item for item in view.document["source"] if item["role"] == "slice"]
    assert rows[0]["ref"] == LEAD and rows[0]["text"] == [f"7| {SOURCE[6]}"] and rows[0]["reasons"] == {"7": "lead"}
    assert rows[1]["text"] == ["2| line 2", "3| line 3", "...| 1 line(s) elided"]


def test_a_slice_of_another_file_version_falls_back_to_the_function_extent() -> None:
    source = [*SOURCE[:1], "int f(void) {", *SOURCE[2:10], "}", *SOURCE[11:]]
    view = build_view(_sliced_package([3, 10], function_sha="d" * 64), _FakeCore(sha="d" * 64, source=source), LIMITS)
    assert not [item for item in view.document["source"] if item["role"] == "slice"]
    [span] = [item for item in view.document["source"] if item["role"] == "function"]
    assert span["lines"] == "2-11" and span["text"][0] == "2| int f(void) {"
    assert any("dataflow slice of a.c names a different file hash" in item["text"]
               for item in view.document["material_gaps"])


def test_slice_rendering_keeps_secret_redaction() -> None:
    package = _sliced_package([3, 10], family="secret")
    view = build_view(package, _FakeCore(), LIMITS)
    [row] = [item for item in view.document["source"] if item["role"] == "slice"]
    assert "hunter2" not in str(row["text"]) and any(item.startswith("7| key = ") for item in row["text"])
    assert "3| line 3" in row["text"]


# ------------------------------------------------------------------------------------------------ facade


def test_the_facade_answers_none_for_absent_producers_and_reads_verified_source(dataflow) -> None:
    fixture, _ids, scope, _assembly, _core = dataflow
    sources = AcceptedSliceSources(scope)
    assert sources.ir_flows(PARSE) is None
    assert sources.svf_records(PARSE, 3) is None
    assert sources.syntax_rows(PARSE) is None
    lines, reason = sources.source_lines(PARSE, _location(fixture, PARSE, "strcpy").file_sha256)
    assert reason is None and lines[2] == "  char b[8]; strcpy(b, s);"
    assert sources.source_lines(PARSE, "0" * 64) == (
        None, "the verified file hash differs from the path fact's file hash")
    assert sources.source_lines("native/src/absent.c", "0" * 64)[0] is None
    assert sources.gaps() == ()


def test_the_facade_reads_tree_sitter_rows_and_producer_flows_of_the_file(tmp_path) -> None:
    fixture = build_accepted_index_set(tmp_path)
    location = _location(fixture, PARSE, "strcpy")
    node = EntityRecord(LogicalIdentity.derive(EntityKind.AST_NODE, SNAPSHOT, {"node": "strcpy"}), "0/1/2", "strcpy",
                        "strcpy", {"schema": "appsec-review/tree-sitter-normalizer/1",
                                   "grammar_native_type": "identifier", "field": None}, location)
    flow = EntityRecord(LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAPSHOT, {"flow": "b"}), "flow:b", "b", "b",
                        {"fact": "flow", "from": "%s", "to": "%b"}, location)
    other = EntityRecord(LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAPSHOT, {"value": "b"}), "value:b", "b", "b",
                         {"fact": "value"}, location)
    _publish(fixture, [
        ("analysis", "tree-sitter-native", {"job": "job_tree_sitter_ast"}, [node], [],
         ("tree_sitter:native", "complete", None)),
        ("graph", "cpp-native-producers", {**GRAPH_PRODUCER, "kind": "producer_neighborhood"}, [flow, other], [],
         ("graph:native:producers", "complete", None))])
    sources = AcceptedSliceSources(accept_manifest(fixture.run_root))
    [row] = sources.syntax_rows(PARSE)
    assert row["identity"] == node.identity.value and row["native_id"] == "0/1/2"
    assert row["payload"]["grammar_native_type"] == "identifier" and row["location"]["start_line"] == 3
    assert sources.syntax_rows("native/src/absent.c") == []
    assert [item["identity"] for item in sources.ir_flows(PARSE)] == [flow.identity.value]
    assert sources.ir_flows("native/src/absent.c") == []
    capped = AcceptedSliceSources(accept_manifest(fixture.run_root), max_syntax_rows=1)
    assert capped.syntax_rows(PARSE) == [capped.syntax_rows(PARSE)[0]]
