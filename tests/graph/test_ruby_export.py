"""Offline tests for the Ruby code-graph export pack, its catalog section and the ruby-synthetic recording.

The recording under tests/fixtures/graph/codeql_export/ruby-synthetic is hand-authored over
``source/synthetic.rb``; the live tier (tests/live/test_codeql_graph_export_ruby_live.py) holds the
pinned-image export to the same expected-facts.json. The normalized golden lives in
tests/fixtures/graph/expected/ruby-synthetic/normalized.json; regenerate it with
``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`` after an intended rule change and review the diff.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
import pytest

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import FAMILY_QUERIES, export_columns, normalize_scope
from tests.fixtures.graph.expectations import load_expectations, unmet

ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = ROOT / "rules" / "codeql-graph-export"
PACK = PACK_ROOT / "ruby"
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "ruby-synthetic"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "ruby-synthetic" / "normalized.json"
COLUMNS = json.loads((PACK_ROOT / "columns.json").read_text(encoding="utf-8"))
CATALOG = json.loads((PACK_ROOT / "catalog.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
QUERIES = COLUMNS["languages"]["ruby"]["queries"]
QUERY_IDS = [query["query_id"] for query in QUERIES]
SCOPE_REPORT_QUERIES = {"seed_functions", "neighborhood"}
TARGET_PATH = "src/synthetic.rb"
SOURCE = SourceFile.from_bytes((FIXTURE / "source" / "synthetic.rb").read_bytes())
SCOPE = {"scope_id": "codeql-unit-ruby-synthetic", "language": "ruby", "build_unit_id": "ruby-synthetic",
         "component_id": "component:ruby-synthetic", "root": "src",
         "files": [{"path": TARGET_PATH, "sha256": SOURCE.sha256}]}


def _runner():
    spec = importlib.util.spec_from_file_location(
        "appsec_review_codeql_export_runner_ruby", ROOT / "containers" / "tools" / "codeql" / "codeql_runner.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _exports() -> dict[str, dict[str, Any]]:
    loaded = load_graph_exports(FIXTURE / "exports", bytes_limit=c.GraphSettings().max_export_bytes)
    return json.loads(json.dumps(loaded))


def _rows(document: dict) -> list[dict]:
    return [dict(zip(document["columns"], row)) for row in document["rows"]]


def _rules(kind: str) -> list[dict]:
    return CATALOG["languages"]["ruby"][kind]


@pytest.fixture(scope="module")
def normalized():
    return normalize_scope(_exports(), scope=SCOPE, target_snapshot="target-sha256:" + "3" * 64,
                           sources={TARGET_PATH: SOURCE}, catalog=load_catalog(), settings=c.GraphSettings(),
                           tool_version="2.27.0", export_pack_sha256="e" * 64)


def _family(result, family: str) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family.value == family]


# --------------------------------------------------------------------------- pack and columns contract


def _query_predicates() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    found = {}
    for path in sorted(PACK.glob("*.ql")):
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", path.read_text(encoding="utf-8")):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    return found


def test_ruby_columns_equal_the_ql_query_predicates_and_the_cpp_contract_shape() -> None:
    ruby, cpp = COLUMNS["languages"]["ruby"], COLUMNS["languages"]["cpp"]
    assert ruby["query_pack"] == "appsec-review/graph-export-ruby" == CATALOG["languages"]["ruby"]["export_pack"]
    assert _runner().export_queries(COLUMNS, "ruby") == QUERIES
    assert [(q["query_id"], q["query_file"], [col["name"] for col in q["columns"]],
             [col["type"] for col in q["columns"]]) for q in QUERIES] == [
        (q["query_id"], q["query_file"], [col["name"] for col in q["columns"]],
         [col["type"] for col in q["columns"]]) for q in cpp["queries"]]
    assert set(export_columns("ruby")) == set(QUERY_IDS) == {
        query_id for queries in FAMILY_QUERIES.values() for query_id in queries} | SCOPE_REPORT_QUERIES
    predicates = _query_predicates()
    assert sorted(predicates) == sorted(QUERY_IDS)
    for query in QUERIES:
        assert all(set(column) == {"name", "type", "meaning"} and column["meaning"] for column in query["columns"])
        assert predicates[query["query_id"]] == (
            query["query_file"], [(column["type"], column["name"]) for column in query["columns"]])
    suite = (PACK / "graph-export.qls").read_text(encoding="utf-8")
    assert sorted(re.findall(r"- query: (\S+)", suite)) == sorted({query["query_file"] for query in QUERIES})
    for path in PACK.glob("*.ql"):
        text = path.read_text(encoding="utf-8")
        assert "LIVE-UNVERIFIED" in text and "@kind table" in text and "select " not in text
    qlpack = (PACK / "qlpack.yml").read_text(encoding="utf-8")
    assert "name: appsec-review/graph-export-ruby\n" in qlpack and "version: 1.0.0\n" in qlpack
    assert "codeql/ruby-all" in qlpack


def test_ruby_pack_declares_the_scope_externals_and_restricts_every_query_by_exported() -> None:
    library = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
    assert "external predicate exportScope(string mode, int depth);" in library
    assert "external predicate exportSeed(string path, int startLine, int endLine);" in library
    for name in ("seedFunction", "near", "exported", "wholeProgram"):
        assert re.search(rf"\bpredicate {name}\(", library), name
    assert "exportedExpr(sinkExpr)" in library and "exportedNode(n)" in library
    for name in ("CallSites.ql", "FlowSummaries.ql"):
        assert "GraphExport::exported(" in (PACK / name).read_text(encoding="utf-8"), name
    assert "GraphExport::exportedNode(n)" in (PACK / "Paths.ql").read_text(encoding="utf-8")
    for name in ("Seeds.ql", "Neighborhood.ql"):
        assert "not GraphExport::wholeProgram()" in (PACK / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- catalog


def _emitted_sink_models() -> set[str]:
    library = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
    return set(re.findall(r'model = "([\w.]+)"', library)) - {"RemoteFlowSource", "LocalFlowSource"}


def test_ruby_catalog_validates_and_its_rules_equal_what_the_queries_can_emit() -> None:
    Draft202012Validator(SCHEMA).validate(CATALOG)
    library = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
    for predicate in ("apiSinkArgument", "apiSourceArgument"):
        body = library.split(f"predicate {predicate}(", 1)[1].split("\n  }\n", 1)[0]
        assert not re.findall(r'name = "(\w+)" and arg = (-?\d+)', body), predicate
    assert not [rule for kind in ("sinks", "sources") for rule in _rules(kind) if "api" in rule["match"]]
    sanitizers = set(re.findall(r'"(\w+)"', library.split("predicate sanitizerApi(", 1)[1].split("}", 1)[0]))
    assert sanitizers == {rule["api"] for rule in _rules("sanitizers")} == {"basename", "shellescape"}
    emitted = _emitted_sink_models()
    classified = {rule["match"]["model"] for rule in _rules("sinks")}
    assert classified < emitted and emitted - classified == {"HttpResponse"}
    schema_models = SCHEMA["$defs"]["models_ruby"]
    assert set(json.dumps(schema_models)) and emitted <= set(re.findall(r'"([\w.]+)"', json.dumps(schema_models)))
    assert {rule["match"]["model"] for rule in _rules("sources")} == {"RemoteFlowSource", "LocalFlowSource"}
    rule_ids = [rule["rule_id"] for kind in ("sinks", "sources", "sanitizers") for rule in _rules(kind)]
    assert len(rule_ids) == len(set(rule_ids)) and all(rule_id.startswith("ruby.") for rule_id in rule_ids)


@pytest.mark.parametrize("mutate", [
    lambda doc: doc["languages"]["ruby"]["sinks"][0]["match"].update(model="SomethingElse"),
    lambda doc: doc["languages"]["ruby"]["sources"][0]["match"].update(model="SomethingElse"),
    lambda doc: doc["languages"]["ruby"]["sinks"][0].update(sink_class="unclassified"),
    lambda doc: doc["languages"]["ruby"]["sinks"][0]["match"].update(model="RemoteFlowSinkFunction"),
])
def test_ruby_catalog_schema_rejects_unknown_models_and_open_classes(mutate) -> None:
    document = copy.deepcopy(CATALOG)
    mutate(document)
    with pytest.raises(ValidationError):
        Draft202012Validator(SCHEMA).validate(document)


# --------------------------------------------------------------------------- recording


def test_ruby_recording_resolves_against_its_source_and_meets_every_expectation() -> None:
    exports = _exports()
    assert sorted(exports) == sorted(QUERY_IDS)
    lines = (FIXTURE / "source" / "synthetic.rb").read_text(encoding="utf-8").split("\n")
    for query_id, document in exports.items():
        names = document["columns"]
        assert tuple(names) == tuple(export_columns("ruby")[query_id])
        for row in document["rows"]:
            for prefix in {name[:-5] for name in names if name.endswith("_path")}:
                path, line = row[names.index(f"{prefix}_path")], row[names.index(f"{prefix}_start_line")]
                if path == "":
                    assert line == 0
                    continue
                assert path == "synthetic.rb"
                column = row[names.index(f"{prefix}_start_column")]
                assert 1 <= line <= len(lines) and 1 <= column <= len(lines[line - 1]), (query_id, prefix, row)
    manifest = json.loads((FIXTURE / "exports" / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["language"] == "ruby" and manifest["pack"]["query_id"] == "graph-export-ruby"
    assert unmet(exports, load_expectations(FIXTURE)) == []


def test_every_ruby_provenance_case_has_an_expectation() -> None:
    provenance = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))
    expectations = load_expectations(FIXTURE)
    assert provenance["fixture"] == expectations["fixture"] == "ruby-synthetic"
    assert set(provenance["cases"]) == {item["case"] for item in expectations["expectations"]}


def test_ruby_recording_covers_dispatch_guard_and_sanitizer_cases() -> None:
    exports = {query_id: _rows(document) for query_id, document in _exports().items()}
    calls = exports["call_sites"]
    virtual = [row for row in calls if row["dispatch"] == "virtual_resolved"]
    assert len(virtual) == 2 and {row["candidate_count"] for row in virtual} == {2}
    assert any(row["dispatch"] == "unresolved_indirect" and row["callee_name"] == "<dynamic:send>" for row in calls)
    assert all(row["in_loop"] in {"true", "false"} for row in calls)
    assert {row["applicability"] for row in exports["ranges"]} == {"not_applicable"}
    assert exports["range_conversions"] == []
    assert {row["in_macro"] for row in exports["guards"]} == {"false"}
    assert {row["destination_object_bytes"] for row in exports["guards"]} == {-1}


# --------------------------------------------------------------------------- normalization


def test_ruby_recording_normalizes_into_every_graph_family(normalized) -> None:
    produced = normalized.to_json()
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(produced)
    assert GOLDEN.read_bytes() == produced
    counts = {family.value: len(_family(normalized, family.value)) for family in c.Family}
    assert all(counts[family] > 0 for family in counts), counts
    for fact in normalized.facts:
        entity = fact.to_entity()
        assert entity.payload["admissibility"] == c.admissibility(fact.payload)


def test_ruby_sinks_and_sources_classify_through_the_catalog(normalized) -> None:
    sinks = {fact.location.start_line: fact.payload["result"]["sink_class"]
             for fact in _family(normalized, "sink_site")}
    assert sinks == {8: "path_access", 14: "path_access", 21: "sql_query", 27: "command_execution",
                     29: "command_execution", 34: "server_side_request", 39: "deserialization",
                     48: "unsafe_reflection", 64: "sql_query", 66: "command_execution"}
    sources = {fact.location.start_line: fact.payload["result"]["source_class"]
               for fact in _family(normalized, "entry_point")}
    assert sources[20] == "remote" and sources[64] == "argv" and sources[65] == "environment"


def test_ruby_range_facts_are_honest_not_applicable_gaps(normalized) -> None:
    ranges = _family(normalized, "range_fact")
    assert len(ranges) == 10
    for fact in ranges:
        assert fact.payload["result"]["applicability"] == "not_applicable"
        assert fact.payload["result"]["interval"] is None
        assert [gap for gap in fact.payload["gaps"] if gap.startswith("not_applicable:")]
        assert "range_not_applicable" in fact.payload["admissibility"]["ineligibility_reasons"]
