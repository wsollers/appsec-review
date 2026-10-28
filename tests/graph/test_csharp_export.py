"""C# graph-export pack: the csharp-synthetic recording, its normalization and the catalog contract.

The recording under ``tests/fixtures/graph/codeql_export/csharp-synthetic`` is hand-authored to the
``appsec-review/graph-export-csharp`` column contract and normalized against its source staged at
``src/Program.cs`` with scope root ``src``. The golden output lives in
``tests/fixtures/graph/expected/csharp-synthetic/normalized.json``; regenerate it with
``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`` after an intended rule change and review the diff.
"""
from __future__ import annotations

import copy
import json
import os
import re
from collections import Counter
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import export_columns, normalize_scope
from tests.fixtures.graph.expectations import load_expectations, unmet

ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = ROOT / "rules" / "codeql-graph-export"
PACK = PACK_ROOT / "csharp"
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "csharp-synthetic"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "csharp-synthetic" / "normalized.json"
TARGET_PATH = "src/Program.cs"
SOURCE = SourceFile.from_bytes((FIXTURE / "source" / "Program.cs").read_bytes())
SCOPE = {"scope_id": "codeql-unit-csharp-synthetic", "language": "csharp", "build_unit_id": "csharp-synthetic",
         "component_id": "component:csharp-synthetic", "root": "src",
         "files": [{"path": TARGET_PATH, "sha256": SOURCE.sha256}]}
CATALOG_DOCUMENT = json.loads((PACK_ROOT / "catalog.json").read_text(encoding="utf-8"))
QUERY_IDS = ("call_sites", "sink_sites", "source_sites", "flow_summaries", "path_flows", "path_edges",
             "path_sanitizers", "guards", "ranges", "range_conversions", "seed_functions", "neighborhood")


def _recording() -> dict:
    loaded = load_graph_exports(FIXTURE / "exports", bytes_limit=c.GraphSettings().max_export_bytes)
    return json.loads(json.dumps(loaded))


def _rules(kind: str) -> list[dict]:
    return CATALOG_DOCUMENT["languages"]["csharp"][kind]


def _ql_pairs(predicate: str) -> set[tuple[str, int]]:
    library = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
    body = library.split(f"predicate {predicate}(", 1)[1].split("}", 1)[0]
    return {(name, int(arg)) for name, arg in re.findall(r'name = "(\w+)" and arg = (-?\d+)', body)}


@pytest.fixture(scope="module")
def normalized():
    return normalize_scope(_recording(), scope=SCOPE, target_snapshot="target-sha256:" + "4" * 64,
                           sources={TARGET_PATH: SOURCE}, catalog=load_catalog(), settings=c.GraphSettings(),
                           tool_version="2.27.0", export_pack_sha256="e" * 64)


def _family(result, family: str) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family.value == family]


# --------------------------------------------------------------------------- recording and expectations


def test_recording_holds_every_query_with_the_csharp_column_contract() -> None:
    exports = _recording()
    assert set(exports) == set(QUERY_IDS)
    columns = export_columns("csharp")
    for query_id, document in exports.items():
        assert tuple(document["columns"]) == columns[query_id], query_id


def test_recording_meets_every_expectation() -> None:
    assert unmet(_recording(), load_expectations(FIXTURE)) == []


def test_every_provenance_case_has_an_expectation() -> None:
    cases = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))["cases"]
    assert {item["case"] for item in load_expectations(FIXTURE)["expectations"]} == set(cases)


def test_a_dropped_flow_is_reported_as_unmet() -> None:
    exports = _recording()
    exports["path_flows"]["rows"] = [row for row in exports["path_flows"]["rows"] if row[1] != 124]
    failures = unmet(exports, load_expectations(FIXTURE))
    assert failures == ['argv_env_to_path: no path_flows row has '
                        '{"argument_index": 0, "sink_start_line": 125, "source_start_line": 124}']


# --------------------------------------------------------------------------- normalization


def test_normalized_output_matches_the_golden(normalized) -> None:
    produced = normalized.to_json()
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(produced)
    assert GOLDEN.read_bytes() == produced


def test_every_family_is_produced_and_satisfies_the_contract(normalized) -> None:
    counts = Counter(fact.family.value for fact in normalized.facts)
    assert counts == {"call_site": 31, "sink_site": 11, "entry_point": 10, "flow_summary": 10,
                      "dataflow_path": 11, "guard_fact": 14, "range_fact": 11}
    for fact in normalized.facts:
        entity = fact.to_entity()
        assert entity.payload["admissibility"] == c.admissibility(fact.payload)
    assert not [symbol.name for symbol in normalized.symbols if symbol.payload["gaps"]]
    coverage = {row.family.value: row for row in normalized.coverage}
    assert coverage["call_site"].status.value == "partial"
    assert coverage["call_site"].gaps == ("unresolved_indirect: 1 call sites have no resolved target",)
    assert {name for name, row in coverage.items() if row.status.value == "complete"} == {
        "sink_site", "entry_point", "flow_summary", "dataflow_path", "guard_fact", "range_fact"}


def test_sinks_and_sources_classify_through_the_csharp_catalog(normalized) -> None:
    sinks = Counter((fact.location.start_line, fact.payload["result"]["sink_class"])
                    for fact in _family(normalized, "sink_site"))
    assert sinks == Counter({(20, "path_access"): 1, (65, "sql_query"): 1, (74, "command_execution"): 1,
                             (76, "command_execution"): 1, (83, "server_side_request"): 1,
                             (89, "path_access"): 1, (97, "unsafe_reflection"): 1, (98, "deserialization"): 1,
                             (107, "allocation_size"): 1, (110, "allocation_size"): 1, (125, "path_access"): 1})
    sources = Counter(fact.payload["result"]["source_class"] for fact in _family(normalized, "entry_point"))
    assert sources == Counter({"remote": 8, "argv": 1, "environment": 1})


def test_paths_carry_source_classes_and_the_path_sanitizer(normalized) -> None:
    paths = {(fact.payload["result"]["source"]["source_class"], fact.location.start_line,
              tuple(item["api"] for item in fact.payload["result"]["sanitizers"]))
             for fact in _family(normalized, "dataflow_path")}
    assert ("argv", 125, ()) in paths and ("environment", 125, ()) in paths
    assert ("remote", 89, ("GetFileName",)) in paths
    assert ("remote", 98, ()) in paths and ("remote", 83, ()) in paths
    [read] = [fact for fact in _family(normalized, "flow_summary") if fact.name.startswith("Synthetic.ItemsController.Read")]
    assert read.payload["result"]["sanitizes"] == ["System.IO.Path.GetFileName"]


def test_range_facts_are_integral_only_for_allocation_lengths(normalized) -> None:
    ranges = _family(normalized, "range_fact")
    integral = [fact for fact in ranges if not fact.payload["gaps"]]
    assert sorted(fact.location.start_line for fact in integral) == [107, 110]
    for fact in ranges:
        if fact.payload["gaps"]:
            assert fact.payload["gaps"] == ["not_applicable: the operand is not integral; no interval is computed"]


# --------------------------------------------------------------------------- catalog and schema contract


def test_catalog_api_and_model_rules_equal_what_the_queries_can_emit() -> None:
    sink_api = {(rule["match"]["api"], rule["match"]["argument_index"]) for rule in _rules("sinks")
                if "api" in rule["match"]}
    source_api = {(rule["match"]["api"], rule["match"]["index"]) for rule in _rules("sources")
                  if "api" in rule["match"]}
    assert sink_api == _ql_pairs("apiSinkArgument")
    assert source_api == _ql_pairs("apiSourceArgument")
    library = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
    sanitizers = set(re.findall(r'"(\w+)"', library.split("predicate sanitizerApi(", 1)[1].split("}", 1)[0]))
    assert sanitizers == {rule["api"] for rule in _rules("sanitizers")}
    emitted = set(re.findall(r'(?:model|result) = "([A-Z][\w.]+)"', library))
    sink_models = {rule["match"]["model"] for rule in _rules("sinks") if "model" in rule["match"]}
    source_models = {rule["match"]["model"] for rule in _rules("sources") if "model" in rule["match"]}
    assert sink_models <= emitted and source_models <= emitted
    schema = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))["$defs"]["models_csharp"]
    schema_sinks = set(schema["properties"]["sinks"]["items"]["properties"]["match"]["properties"]["model"]["enum"])
    schema_sources = set(schema["properties"]["sources"]["items"]["properties"]["match"]["properties"]["model"]["enum"])
    assert schema_sinks | schema_sources == emitted
    assert sink_models <= schema_sinks and source_models <= schema_sources


@pytest.mark.parametrize("mutate", [
    lambda doc: doc["languages"]["csharp"]["sinks"][-1]["match"].update(model="SomethingElse"),
    lambda doc: next(rule for rule in doc["languages"]["csharp"]["sources"] if "model" in rule["match"])[
        "match"].update(model="UnknownSource"),
])
def test_schema_rejects_an_unknown_csharp_model(mutate) -> None:
    schema = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.validate(CATALOG_DOCUMENT)
    document = copy.deepcopy(CATALOG_DOCUMENT)
    mutate(document)
    with pytest.raises(ValidationError):
        validator.validate(document)


def test_pack_query_predicates_and_suite_equal_the_column_contract() -> None:
    columns = json.loads((PACK_ROOT / "columns.json").read_text(encoding="utf-8"))["languages"]["csharp"]
    assert columns["query_pack"] == "appsec-review/graph-export-csharp"
    found = {}
    for path in sorted(PACK.glob("*.ql")):
        text = path.read_text(encoding="utf-8")
        assert "LIVE-UNVERIFIED" in text and "@kind table" in text and "select " not in text, path.name
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", text):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    assert sorted(found) == sorted(QUERY_IDS)
    for query in columns["queries"]:
        assert query["result_set"] == query["query_id"]
        assert found[query["query_id"]] == (
            query["query_file"], [(column["type"], column["name"]) for column in query["columns"]])
    cpp = json.loads((PACK_ROOT / "columns.json").read_text(encoding="utf-8"))["languages"]["cpp"]["queries"]
    assert [(q["query_id"], [col["name"] for col in q["columns"]]) for q in columns["queries"]] == [
        (q["query_id"], [col["name"] for col in q["columns"]]) for q in cpp]
    suite = (PACK / "graph-export.qls").read_text(encoding="utf-8")
    assert sorted(re.findall(r"- query: (\S+)", suite)) == sorted({q["query_file"] for q in columns["queries"]})
    qlpack = (PACK / "qlpack.yml").read_text(encoding="utf-8")
    assert "name: appsec-review/graph-export-csharp" in qlpack and "codeql/csharp-all" in qlpack
