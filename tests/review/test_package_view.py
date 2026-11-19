"""The model-facing package view (``package-view/6``) and package neighborhood (``package-neighborhood/3``)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.identity import sha256_hex
from appsec_review.review.neighborhood import function_extent, type_names
from appsec_review.review.package_view import ViewLimits, build_view, file_bytes, is_material_gap
from appsec_review.review.packages import PackageSettings, assemble_packages
from appsec_review.review.scope import accept_manifest
from tests.fixtures.inference_review.builder import build_accepted_index_set
from tests.review.test_packages_graph_context import attach_graph

ALONE = PackageSettings(lead_cluster_lines=0)   # per-lead context: leads of one site do not share a package here

LIMITS = ViewLimits(48 * 1024, 160, 6)


@pytest.fixture(scope="module")
def graph(tmp_path_factory):
    fixture = build_accepted_index_set(tmp_path_factory.mktemp("viewpkg"))
    ids = attach_graph(fixture)
    assembly = assemble_packages(accept_manifest(fixture.run_root), ALONE)
    core = RetrievalCore(fixture.runs_dir, fixture.run_id)
    return fixture, ids, assembly, core


def _package(assembly, fixture, key: str) -> dict:
    [document] = [item.document() for item in assembly.packages
                  if item.kind == "finding_lead" and fixture.ids[key] in item.lead_ids]
    return document


def test_lead_view_is_labelled_deterministic_and_complete(graph) -> None:
    fixture, ids, assembly, core = graph
    package = _package(assembly, fixture, "sast_critical")
    first = build_view(package, core, LIMITS)
    again = build_view(package, core, LIMITS)
    assert first.document == again.document and first.labels == again.labels
    document = first.document
    assert document["protocol"] == "review-protocol/2" and document["leads"][0]["label"] == "L1"
    assert first.labels["L1"] == fixture.ids["sast_critical"]
    sinks = {row["ref"]: row for row in document["neighborhood"]["sinks"]}
    assert ids["sink_strcpy"] in sinks and sinks[ids["sink_strcpy"]]["label"].startswith("K")
    guard = next(row for row in document["neighborhood"]["guards"] if row["ref"] == ids["guard_strcpy"])
    assert guard["label"].startswith("G") and "adequate" not in guard["summary"] and "sufficient" not in guard["summary"]
    assert "connects" not in guard["summary"] and "constrains" not in guard["summary"]
    # The source excerpt is read through the accepted index, hash-verified, line-numbered.
    [span] = [item for item in document["source"] if item["role"] == "function"]
    assert span["label"] == "S1" and any("strcpy(b, s)" in line for line in span["text"])
    assert span["file_sha256"] == core.find(identity=fixture.ids["sast_critical"])["results"][0]["location"]["file_sha256"]
    # No identities leak outside labelled rows; the entity list is not part of the view.
    assert "entity_ids" not in json.dumps(document) and "package_id" not in document


def test_every_label_the_view_presents_is_inside_the_package_entity_scope(graph) -> None:
    """The capability a cell is issued grants the package's ``retrieval.entity_ids``; a label the view presents
    for an identity outside them is a request the cell can only be denied (run 2026-11-16-0005, E1)."""
    fixture, ids, assembly, core = graph
    checked = 0
    for item in assembly.packages:
        package = item.resolved()
        view = build_view(package, core, LIMITS)
        granted = set(package["retrieval"]["entity_ids"])
        outside = sorted(f"{label}={ref[:40]}" for label, ref in view.labels.items() if ref not in granted)
        assert outside == [], (item.package_id, outside)
        checked += len(view.labels)
    assert checked > 0


def test_trimming_a_neighborhood_row_keeps_the_context_entry_the_chain_still_shows() -> None:
    from appsec_review.review.packages import _Assembler
    from appsec_review.review.units import context_entry
    entry_point, hop, guard = "asr:entry_point:" + "1" * 64, "asr:call_site:" + "2" * 64, "asr:guard_fact:" + "3" * 64
    record = {name: [] for name in ("sinks", "ranges", "guards", "callers", "callees", "flows", "entries", "corroboration")}
    record["entries"] = [{"ref": entry_point, "role": "entry_point"}]
    record["guards"] = [{"ref": guard, "role": "guard"}]
    record["chain"] = {"reached": True, "depth_limit": 3, "hops": [{"ref": hop, "role": "caller"}],
                       "entries": [{"ref": entry_point, "role": "entry_point"}]}
    record["omitted"] = {name: 0 for name in record if name not in ("chain", "omitted")}
    record["slice"] = None
    entries = [context_entry(entry_point, "entry_point"), context_entry(hop, "caller"), context_entry(guard, "guard")]
    # Guards go before entries (trim order); nothing else shows the guard, so its entry goes with the row.
    assert _Assembler.trim_neighborhood(record, entries) == "guards"
    assert record["guards"] == [] and record["omitted"]["guards"] == 1
    assert {item.id for item in entries} == {entry_point, hop}
    # The entries row goes next, but the chain still shows the entry point: its entry stays.
    assert _Assembler.trim_neighborhood(record, entries) == "entries"
    assert record["entries"] == [] and record["omitted"]["entries"] == 1 and {item.id for item in entries} == {entry_point, hop}
    assert _Assembler.trim_neighborhood(record, entries) is None


def test_the_anchor_floor_is_trimmed_last_and_the_cut_is_named() -> None:
    """Item 1 of the run 2026-11-16-0005 audit: every neighborhood section was trimmed to nothing before a single
    context entry. Rows in the floor (the anchor's sinks, their guards, every entry and the chain) survive until
    nothing else is left, and cutting into them is a named gap."""
    from collections import Counter
    from appsec_review.review.packages import _Assembler
    from appsec_review.review.units import context_entry
    sink, other_sink = "asr:sink_site:" + "1" * 64, "asr:sink_site:" + "2" * 64
    guard, callee = "asr:guard_fact:" + "3" * 64, "asr:call_site:" + "4" * 64
    record = {name: [] for name in ("sinks", "ranges", "guards", "callers", "callees", "flows", "entries", "corroboration")}
    record["sinks"] = [{"ref": sink, "role": "sink", "line": 10}, {"ref": other_sink, "role": "sink", "line": 20}]
    record["guards"] = [{"ref": guard, "role": "guard"}]
    record["callees"] = [{"ref": callee, "role": "callee"}]
    record["chain"] = {"reached": False, "depth_limit": 3, "hops": [], "entries": []}
    record["omitted"] = {name: 0 for name in record if name not in ("chain", "omitted")}
    record["slice"] = None
    entries = [context_entry(sink, "sink"), context_entry(other_sink, "sink"), context_entry(guard, "guard"),
               context_entry(callee, "callee")]
    floor = frozenset({sink, guard})
    assert _Assembler.trim_neighborhood(record, entries, floor) == "callees"
    assert _Assembler.trim_neighborhood(record, entries, floor) == "sinks"      # the other sink, never the anchor's
    assert [row["ref"] for row in record["sinks"]] == [sink] and record["guards"] == [{"ref": guard, "role": "guard"}]
    assert _Assembler.trim_neighborhood(record, entries, floor) is None       # only floor rows remain
    assert _Assembler.trim_neighborhood(record, entries) == "guards"            # the caller breaches the floor knowingly
    gaps = _Assembler.trim_gaps("source_sast", "lead/x", Counter({"tag": 12, "caller": 2}), Counter({"callees": 1, "sinks": 1}),
                                Counter({"guards": 1}))
    assert [gap.state for gap in gaps] == ["truncated"] * 3
    assert "by role: caller=2, tag=12" in gaps[0].reason and gaps[0].producer == "source_sast"
    assert "by section: callees=1, sinks=1" in gaps[1].reason and gaps[1].producer == "code_graph_neighborhood"
    assert "anchor floor was cut" in gaps[2].reason and "guards=1" in gaps[2].reason


def test_context_is_trimmed_before_the_neighborhood_tags_first_and_the_package_records_what_went(graph) -> None:
    """A package whose body exceeds max_package_bytes loses tag and precomputed context before any sink, entry,
    guard or chain row, and names what it trimmed and why."""
    from appsec_review.review.lead_families import collect_leads
    from appsec_review.review.packages import _Assembler
    from appsec_review.review.units import context_entry
    fixture, ids, assembly, core = graph
    [stored] = [item for item in assembly.packages if item.kind == "finding_lead" and fixture.ids["sast_critical"] in item.lead_ids]
    full, size = stored.document(), len(stored.body)
    tags = [entry for entry in full["context"] if entry["role"] == "tag"]
    assert tags, "the fixture lead carries tag context to trim"
    # Only this lead's package is bounded below its own size; other packages of the fixture are larger still.
    scope = accept_manifest(fixture.run_root)
    collection = collect_leads(scope)
    lead = next(item for item in collection.leads if item.observation_id == fixture.ids["sast_critical"])
    assembler = _Assembler(scope, PackageSettings(lead_cluster_lines=0, max_package_bytes=size - 1), collection)
    package = assembler.finding_leads((lead,)).document()
    assert len(package["context"]) < len(full["context"])
    assert len([entry for entry in package["context"] if entry["role"] == "tag"]) < len(tags)
    for section in ("sinks", "entries", "guards", "ranges", "flows", "callers", "callees", "corroboration"):
        assert package["neighborhood"][section] == full["neighborhood"][section], section
    assert package["neighborhood"]["chain"] == full["neighborhood"]["chain"]
    [gap] = [gap for gap in package["coverage_gaps"] if "max_package_bytes" in gap["reason"]]
    assert gap["state"] == "truncated" and "by role: " in gap["reason"] and "tag=1" in gap["reason"]
    assert package["truncation"]["omitted_context"] == len(full["context"]) - len(package["context"])
    # The trim order itself: tags, precomputed signals, then derived graph context, the component last.
    capped = [context_entry("asr:component:" + "1" * 64, "component"), context_entry("asr:tag_assignment:" + "2" * 64, "tag"),
              context_entry("asr:call_site:" + "3" * 64, "caller"), context_entry("asr:priority_item:" + "4" * 64, "priority")]
    assert [_Assembler.trim_context(capped) for _ in range(5)] == ["tag", "priority", "caller", "component", None]


def test_every_stored_gap_is_accounted_inline_or_in_the_hash_referenced_file(graph) -> None:
    fixture, _ids, assembly, core = graph
    for package in (_package(assembly, fixture, "sast_critical"), _package(assembly, fixture, "codeql_high")):
        view = build_view(package, core, LIMITS)
        counts = view.document["gap_counts"]
        assert counts["stored"] == len(package["coverage_gaps"]) == counts["inline"] + counts["file"]
        if view.files.get("gaps.jsonl"):
            entry = view.document["files"]["gaps.jsonl"]
            assert entry["count"] == len(view.files["gaps.jsonl"]) == counts["file"]
            assert entry["sha256"] == sha256_hex(file_bytes(view.files["gaps.jsonl"]).decode("utf-8"))
        stored = {gap["gap_id"] for gap in package["coverage_gaps"]}
        inline = [text for text in (item["text"] for item in view.document["material_gaps"])]
        assert len(inline) >= counts["inline"] and counts["inline"] + counts["file"] == len(stored)


def test_view_byte_budget_drops_least_valuable_rows_and_names_the_omission(graph) -> None:
    fixture, _ids, assembly, core = graph
    package = _package(assembly, fixture, "sast_critical")
    wide = build_view(package, core, LIMITS)
    size = len(json.dumps(wide.document, sort_keys=True))
    narrow = build_view(package, core, ViewLimits(size - 200, 160, 6))
    assert narrow.document["omitted"] and not wide.document["omitted"]
    assert any("view byte budget" in item["text"] for item in narrow.document["material_gaps"])
    # What the narrow view shows is a labelled subset of the wide view.
    assert set(narrow.labels.values()) <= set(wide.labels.values())


def test_hunt_view_labels_the_unit_leads_sinks_and_entries(graph) -> None:
    fixture, ids, assembly, core = graph
    hunts = [item.resolved() for item in assembly.packages
             if item.kind == "hunt" and item.document()["scope"]["build_unit_id"] == "native-main"]
    [hunt] = [item for item in hunts if item["scope"].get("operation") is None]
    operations = [item for item in hunts if item["scope"].get("operation") is not None]
    assert len(operations) == 7
    for package in operations:
        operation = package["scope"]["operation"]
        operation_view = build_view(package, core, LIMITS)
        [span] = operation_view.document["source"]
        assert span["role"] == "cited_source" and span["text"]
        assert span["ref"] == operation["source_id"]
        assert span["file_sha256"] == operation["file_sha256"]
        assert operation_view.labels[span["label"]] == operation["source_id"]
        assert set(operation_view.labels.values()) <= set(package["retrieval"]["entity_ids"])
    view = build_view(hunt, core, LIMITS)
    assert [item["label"] for item in view.document["leads"]][:2] == ["L1", "L2"]
    assert [view.labels[item["label"]] for item in view.document["leads"]] == [
        item["observation_id"] for item in hunt["lead_menu"]]
    assert not view.document["source"]
    refs = set(view.labels.values())
    assert {ids["sink_strcpy"], ids["entry_s"]} <= refs


def test_material_gap_rule_keeps_package_scoped_gaps_inline() -> None:
    gap = {"producer": "code_graph", "scope": "lead/x", "state": "partial", "reason": "r"}
    assert is_material_gap(gap, partition_key="lead/x", unit_key=None, terms=())
    other = {"producer": "codeql", "scope": "shard/a", "state": "partial", "reason": "unrelated"}
    assert not is_material_gap(other, partition_key="lead/x", unit_key=None, terms=("src/a.c",))
    named = {"producer": "codeql", "scope": "shard/a", "state": "partial", "reason": "src/a.c is partial"}
    assert is_material_gap(named, partition_key="lead/x", unit_key=None, terms=("src/a.c",))


def test_function_extent_and_type_names_are_deterministic_text_helpers() -> None:
    lines = ["#include <string.h>", "struct Header { char name[16]; };", "int parse(const Header &h, int n) {",
             "  if (n > 3) { return 1; }  // } not a brace", "  char *s = \"}\";", "  return 0;", "}", "int other() {}"]
    assert function_extent(lines, 3, "a.cpp") == (3, 7, False)
    assert function_extent(["def f(x):", "    return x", "", "def g():", "    pass"], 1, "a.py")[:2] == (1, 2)
    assert function_extent(["int f(int);", "int g() {", "}"], 1, "a.c") == (1, 1, False)
    assert type_names(lines, 3, 7) == ["Header"]


# ------------------------------------------------------------------------------------------------ function scope


@pytest.fixture(scope="module")
def scoped(tmp_path_factory):
    """parse.c with function symbols, a sink that names its function, and call sites q -> p -> strcpy."""
    from appsec_review.graph.contract import Family
    from appsec_review.retrieval import EntityKind, EntityRecord
    from appsec_review.retrieval.model import LogicalIdentity
    from tests.review.test_graph_admissibility import SCOPE_ID, graph_entity, results_for
    from tests.review.test_packages_graph_context import PARSE, SNAPSHOT, _location, _span
    from tests.review.test_packages_memory_context import _publish

    fixture = build_accepted_index_set(tmp_path_factory.mktemp("scoped"))
    graph_ids = attach_graph(fixture)

    def symbol(name: str, needle: str) -> EntityRecord:
        identity = LogicalIdentity.derive(EntityKind.SYMBOL, SNAPSHOT, {"qualified_name": name, "scope_id": SCOPE_ID})
        return EntityRecord(identity, name, name, f"function {name}", {
            "producer": "codeql-export", "scope": {"scope_id": SCOPE_ID, "build_unit_id": "native-main"},
            "kind": "function", "qualified_name": name, "exact": True, "gaps": []}, _location(fixture, PARSE, needle))

    p, q = symbol("p", "p(char"), symbol("q", "q(int")
    strcpy = _location(fixture, PARSE, "strcpy(b, s)")
    result = {**results_for(Family.SINK_SITE), "enclosing_function": {"symbol": p.identity.value, "display": "p"},
              "api": {"display": "strcpy"}}
    sink = graph_entity(Family.SINK_SITE, {**_span(strcpy), "sink_class": "memory_write", "argument_index": 7}, result,
                        strcpy, snapshot=SNAPSHOT)

    def call(caller: EntityRecord, callee: str, callee_symbol: str | None, needle: str) -> EntityRecord:
        location = _location(fixture, PARSE, needle)
        return graph_entity(Family.CALL_SITE, {**_span(location), "caller_symbol": caller.identity.value,
                                               "callee_name": callee},
                            {"caller": {"symbol": caller.identity.value, "display": caller.name},
                             "callee": {"symbol": callee_symbol, "display": callee, "dispatch": "direct",
                                        "candidate_count": 1}}, location, snapshot=SNAPSHOT)
    into_p = call(q, "p", p.identity.value, "n * 4")
    entry_location = _location(fixture, PARSE, "q(int")
    entry_q = graph_entity(Family.ENTRY_POINT, {**_span(entry_location), "source_class": "remote"},
                           {**results_for(Family.ENTRY_POINT, "remote"),
                            "enclosing_function": {"symbol": q.identity.value, "display": "q"}},
                           entry_location, snapshot=SNAPSHOT)
    out_of_p = call(p, "strcpy", None, "strcpy(b, s)")
    _publish(fixture, [
        ("graph", "cpp-native-symbols", {"job": "job_code_graph_index", "build_unit_id": "native-main"},
         [p, q], [], ("graph:native:symbols", "complete", None)),
        ("graph", "cpp-native-scoped", {"job": "job_code_graph_index", "family": "call_site",
                                        "build_unit_id": "native-main"},
         [sink, into_p, out_of_p, entry_q], [], ("graph:native:call_site", "complete", None))])
    assembly = assemble_packages(accept_manifest(fixture.run_root), ALONE)
    return fixture, assembly, RetrievalCore(fixture.runs_dir, fixture.run_id), {
        "p": p.identity.value, "q": q.identity.value, "sink": sink.identity.value, "into_p": into_p.identity.value,
        "out_of_p": out_of_p.identity.value, "entry_q": entry_q.identity.value, "entry_n": graph_ids["entry_n"],
        "path_bridged": graph_ids["path_bridged"]}


def test_neighborhood_is_selected_by_function_scope_with_callers_and_callees(scoped) -> None:
    fixture, assembly, core, ids = scoped
    package = _package(assembly, fixture, "sast_critical")
    neighborhood = package["neighborhood"]
    assert neighborhood["function"]["symbol"] == ids["p"] and neighborhood["function"]["basis"] == "enclosing_fact_on_line"
    assert ids["sink"] in {row["ref"] for row in neighborhood["sinks"]}
    assert {row["ref"] for row in neighborhood["callers"]} == {ids["into_p"]}
    assert {row["ref"] for row in neighborhood["callees"]} == {ids["out_of_p"]}
    assert all(row["ref"] in package["retrieval"]["entity_ids"]
               for name in ("sinks", "callers", "callees") for row in neighborhood[name])
    assert ids["p"] in package["retrieval"]["entity_ids"]

    view = build_view(package, core, LIMITS)
    [span] = [item for item in view.document["source"] if item["role"] == "function"]
    assert span["ref"] == ids["p"] and span["lines"] == "2-4"
    # q -> p is also the first hop of the entry chain, so it is labelled once, in the chain.
    hop = view.document["neighborhood"]["chain"]["hops"][0]
    assert hop["summary"].startswith("q -> p") and view.document["neighborhood"]["callers"] == []
    assert view.document["neighborhood"]["function"]["name"] == "p"
    assert view.labels[span["label"]] == ids["p"]


def test_the_entry_chain_runs_from_the_lead_function_up_to_the_nearest_entry_point(scoped) -> None:
    fixture, assembly, core, ids = scoped
    package = _package(assembly, fixture, "sast_critical")                 # in p; q calls p; q holds an entry point
    chain = package["neighborhood"]["chain"]
    assert chain["reached"] and [row["ref"] for row in chain["hops"]] == [ids["into_p"]]
    assert [row["ref"] for row in chain["entries"]] == [ids["entry_q"]] and chain["hops"][0]["depth"] == 1
    assert not [gap for gap in package["coverage_gaps"] if "no entry_point fact is reachable" in gap["reason"]]
    view = build_view(package, core, LIMITS)
    shown = view.document["neighborhood"]["chain"]
    assert shown["reached"] and shown["hops"][0]["label"] == "F1" and shown["entries"][0]["label"] == "E1"
    assert view.labels["F1"] == ids["into_p"] and view.labels["E1"] == ids["entry_q"]
    # The CodeQL lead in q correlates a dataflow path, so its neighborhood is bounded by that path: the chain's
    # entries are the path's source entry point rather than every entry point found by walking callers.
    own = _package(assembly, fixture, "codeql_high")["neighborhood"]
    assert own["bound"] == {"kind": "dataflow_path", "paths": [ids["path_bridged"]], "call_depth": None}
    assert own["chain"]["reached"] and own["chain"]["hops"] == []
    assert [row["ref"] for row in own["chain"]["entries"]] == [ids["entry_n"]]


def test_an_unreachable_entry_point_is_a_material_gap_the_cell_can_see(graph) -> None:
    fixture, _ids, assembly, core = graph
    package = _package(assembly, fixture, "sast_critical")
    assert not package["neighborhood"]["chain"]["reached"]
    view = build_view(package, core, LIMITS)
    assert any("no entry_point fact is reachable" in item["text"] for item in view.document["material_gaps"])


def test_a_second_lead_resolves_its_own_function(scoped) -> None:
    fixture, assembly, core, ids = scoped
    package = _package(assembly, fixture, "codeql_high")           # parse.c:5, inside q
    assert package["neighborhood"]["function"]["symbol"] == ids["q"]
    view = build_view(package, core, LIMITS)
    [span] = [item for item in view.document["source"] if item["role"] == "function"]
    assert span["ref"] == ids["q"] and span["lines"] == "5-5" and view.document["neighborhood"]["function"]["name"] == "q"


class _FakeCore:
    """find/read_source_lines doubles: a header declaring ``Header``; ``Missing`` has no declaration."""

    HEADER = ["#pragma once", "struct Header {", "  unsigned short kind;", "  char name[16];", "};"]
    IDENTITY = "asr:ast_node:" + "a" * 64
    LEAD = "asr:tool_observation:" + "b" * 64
    SOURCE = ["int parse(const Header &h, const Missing &m) {", "  return 0;", "}"]

    def find(self, **kwargs):
        if kwargs.get("identity") == self.LEAD:
            return {"results": [{"identity": self.LEAD, "name": "rule", "location": {
                "path": "src/a.cpp", "start_line": 2, "end_line": 2, "file_sha256": "1" * 64}}]}
        if kwargs.get("kind") == "ast_node" and kwargs.get("name") == "Header":
            return {"results": [{"identity": self.IDENTITY, "payload": {"kind": "RecordDecl"}, "location": {
                "path": "include/a.hpp", "start_line": 2, "end_line": 5, "file_sha256": "2" * 64}}]}
        return {"results": []}

    def read_source_lines(self, *, identity):
        if identity == self.LEAD:
            return {"location": {"path": "src/a.cpp", "start_line": 2, "end_line": 2, "file_sha256": "1" * 64},
                    "lines": self.SOURCE}, None
        if identity == self.IDENTITY:
            return {"location": {"path": "include/a.hpp", "start_line": 2, "end_line": 5, "file_sha256": "2" * 64},
                    "lines": self.HEADER}, None
        return None, "unknown"


def test_type_declarations_are_read_from_the_index_and_a_missing_one_is_a_named_gap() -> None:
    package = {"kind": "finding_lead", "lane": "lead", "lead_family": "source_sast", "scope": {"partition_key": "lead/x"},
               "lead_menu": [{"observation_id": _FakeCore.LEAD, "lead_family": "source_sast", "scanner": "s", "rule_id": "r",
                              "reported_severity": "high", "rule_cwe": [], "weaknesses": []}],
               "context": [], "coverage_gaps": [], "proof_obligations": [], "retrieval": {"entity_ids": [_FakeCore.IDENTITY]},
               "neighborhood": {"function": {"symbol": "asr:symbol:" + "c" * 64, "name": "parse", "path": "src/a.cpp",
                                             "start_line": 1, "file_sha256": "1" * 64,
                                             "basis": "enclosing_fact_on_line"}}}
    view = build_view(package, _FakeCore(), LIMITS)
    roles = {item["role"]: item for item in view.document["source"]}
    assert roles["type:Header"]["text"][0].startswith("2| struct Header") and roles["type:Header"]["ref"] == _FakeCore.IDENTITY
    assert "type:Missing" not in roles
    assert any("type Missing was not found" in item["text"] for item in view.document["material_gaps"])


def test_source_lines_are_read_through_an_accepted_entity_and_hash_verified(graph) -> None:
    fixture, _ids, _assembly, core = graph
    found, reason = core.read_source_lines(identity=fixture.ids["sast_critical"])
    assert reason is None and found["location"]["path"] == "native/src/parse.c"
    assert found["lines"][2].strip().startswith("char b[8]")
    missing, reason = core.read_source_lines(identity="asr:tool_observation:" + "0" * 64)
    assert missing is None and "not found" in reason


def test_guard_summaries_state_the_fact_and_never_judge_it() -> None:
    from appsec_review.review.fact_summary import summarize_fact

    payload = {"result": {"guard_state": "dominating", "polarity": "false_branch", "constrains_sink_operand": "true",
                          "condition": {"display": "size < 4u + out.length"},
                          "comparison": {"operator": "<", "bound_display": "4u + out.length"}}}
    text = summarize_fact("guard_fact", payload, line=13)
    assert text == ("dominating guard, polarity false_branch: size < 4u + out.length "
                    "(operator <, operand 4u + out.length), L13")
    for word in ("adequate", "sufficient", "effective", "bounds", "constrains", "protect", "safe"):
        assert word not in text


def test_guard_summaries_with_operands_state_the_texts_and_the_destination_size_only() -> None:
    from appsec_review.review.fact_summary import summarize_fact

    def operand(role, kind, value, text):
        return {"role": role, "kind": kind, "value": value, "text": text, "location": None}

    payload = {"result": {"guard_state": "dominating", "polarity": "false_branch", "constrains_sink_operand": "unknown",
                          "condition": {"display": "size < 4u + out.length"},
                          "comparison": {"operator": "<", "bound_display": "4u + out.length", "operands": [
                              operand("lhs", "variable", None, "size"),
                              operand("rhs", "other", None, "4u + out.length")]},
                          "destination": {"object_bytes": 16}}}
    text = summarize_fact("guard_fact", payload, line=13)
    assert text == ("dominating guard, polarity false_branch: size < 4u + out.length "
                    "(operator <, lhs size, rhs 4u + out.length); destination object 16 bytes, L13")
    unknown = {"result": {**payload["result"], "destination": {"object_bytes": None}}}
    assert "destination" not in summarize_fact("guard_fact", unknown)
    for word in ("adequate", "sufficient", "effective", "bounds", "protect", "safe"):
        assert word not in text


# -- item 2: a clustered package renders its source from the anchor lead ----------------------------------------

def test_a_clustered_package_renders_the_anchor_source_and_labels_it(graph) -> None:
    """Run 2026-11-16-0005: six of eight clustered packages showed the model no function span, slice or type
    declarations and emitted no gap, because the view rendered source only for a single-lead package."""
    fixture, ids, assembly, core = graph
    clustered = assemble_packages(accept_manifest(fixture.run_root), PackageSettings())
    [package] = [item.document() for item in clustered.packages
                 if item.kind == "finding_lead" and fixture.ids["sast_critical"] in item.lead_ids]
    assert len(package["lead_menu"]) >= 2 and fixture.ids["sast_duplicate"] in {item["observation_id"] for item in package["lead_menu"]}
    view = build_view(package, core, LIMITS)
    document = view.document
    assert [item["label"] for item in document["leads"]][:2] == ["L1", "L2"]
    assert document["leads"][1]["where"]["function"] is None      # the neighborhood function is the anchor's own
    source = document["source"]
    assert source and source[0]["label"] == "S1" and source[0]["role"] in {"function", "slice"}
    assert any("strcpy(b, s)" in line for row in source for line in row["text"])
    assert view.labels["S1"] == source[0]["ref"] and view.labels["S1"] in set(package["retrieval"]["entity_ids"]) | {
        lead["observation_id"] for lead in package["lead_menu"]}
    assert not [text for text in (item["text"] for item in document["material_gaps"]) if "no source text" in text]


def test_a_clustered_package_without_readable_source_names_the_gap(graph) -> None:
    fixture, ids, assembly, core = graph
    clustered = assemble_packages(accept_manifest(fixture.run_root), PackageSettings())
    [package] = [item.document() for item in clustered.packages
                 if item.kind == "finding_lead" and fixture.ids["sast_critical"] in item.lead_ids]

    class Blind:
        def find(self, **_kwargs):
            return {"results": []}

        def read_source_lines(self, *, identity):
            raise LookupError(f"not indexed: {identity[:12]}")

    view = build_view(package, Blind(), LIMITS)
    assert view.document["source"] == []
    [gap] = [item["text"] for item in view.document["material_gaps"] if "no source text for the lead" in item["text"]]
    assert "LookupError" in gap


def test_member_lines_join_the_slice_and_members_outside_the_span_get_a_window() -> None:
    from appsec_review.review.package_view import _Builder
    lines = [f"line {number}" for number in range(1, 41)]
    anchor, member, far = "asr:tool_observation:" + "a" * 64, "asr:tool_observation:" + "b" * 64, "asr:tool_observation:" + "c" * 64
    sha = "f" * 64

    class Core:
        def find(self, **kwargs):
            identity = kwargs.get("identity")
            line = {anchor: 5, member: 7, far: 30}.get(identity)
            if line is None:
                return {"results": []}
            return {"results": [{"identity": identity, "location": {"path": "src/a.c", "start_line": line, "end_line": line,
                                                                     "file_sha256": sha}, "payload": {}}]}

        def read_source_lines(self, *, identity):
            line = {anchor: 5, member: 7, far: 30}[identity]
            return {"location": {"path": "src/a.c", "start_line": line, "end_line": line, "file_sha256": sha},
                    "lines": lines}, None

    package = {"kind": "finding_lead", "lead_menu": [], "neighborhood": {"function": None, "bound": {"kind": "dataflow_path"},
               "slice": {"functions": [{"path": "src/a.c", "file_sha256": sha, "function": None, "first": 3, "last": 9,
                                        "lines": [{"line": 4, "reasons": ["def_use"]}], "truncated": False}]}}}
    builder = _Builder(package, Core(), LIMITS)
    leads = [{"ref": anchor, "where": {"path": "src/a.c", "line": 5}}, {"ref": member, "where": {"path": "src/a.c", "line": 7}},
             {"ref": far, "where": {"path": "src/a.c", "line": 30}}]
    rows, gaps = builder.source_rows(leads)
    [slice_row] = [row for row in rows if row["role"] == "slice"]
    assert slice_row["reasons"] == {"4": "def_use", "5": "lead", "7": "lead"}
    [window] = [row for row in rows if row["role"] == "member"]
    assert window["ref"] == far and window["lines"] == "18-40" and gaps == []
