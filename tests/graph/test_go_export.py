"""Go code-graph export pack (appsec-review/graph-export-go): contract, catalog and the go-synthetic fixture.

The recording under ``tests/fixtures/graph/codeql_export/go-synthetic/`` is hand-authored over
``source/main.go``; it is normalized here against that source staged at ``src/main.go`` with CodeQL
scope root ``src``. The golden output lives in ``tests/fixtures/graph/expected/go-synthetic/``;
regenerate it with ``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`` after an intended rule change.
"""
from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, ValidationError

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import FAMILY_QUERIES, export_columns, normalize_scope
from tests.fixtures.graph.expectations import load_expectations, unmet

ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = ROOT / "rules" / "codeql-graph-export"
PACK = PACK_ROOT / "go"
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "go-synthetic"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "go-synthetic" / "normalized.json"
COLUMNS = json.loads((PACK_ROOT / "columns.json").read_text(encoding="utf-8"))
CATALOG_DOC = json.loads((PACK_ROOT / "catalog.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
GO = COLUMNS["languages"]["go"]
TARGET_PATH = "src/main.go"
SOURCE = SourceFile.from_bytes((FIXTURE / "source" / "main.go").read_bytes())
SCOPE = {"scope_id": "codeql-unit-go-synthetic", "language": "go", "build_unit_id": "go-synthetic",
         "component_id": "component:go-synthetic", "root": "src",
         "files": [{"path": TARGET_PATH, "sha256": SOURCE.sha256}]}


def _exports() -> dict[str, dict[str, Any]]:
    loaded = load_graph_exports(FIXTURE / "exports", bytes_limit=c.GraphSettings().max_export_bytes)
    return json.loads(json.dumps(loaded))


@pytest.fixture(scope="module")
def normalized():
    return normalize_scope(_exports(), scope=SCOPE, target_snapshot="target-sha256:" + "3" * 64,
                           sources={TARGET_PATH: SOURCE}, catalog=load_catalog(), settings=c.GraphSettings(),
                           tool_version="2.27.0", export_pack_sha256="e" * 64)


def _family(result, family: str) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family.value == family]


def _at_line(result, family: str, line: int) -> list[c.GraphFact]:
    return [fact for fact in _family(result, family) if fact.location.start_line == line]


# --------------------------------------------------------------------------- pack and column contract


def _query_predicates() -> dict[str, tuple[str, list[tuple[str, ...]]]]:
    found = {}
    for path in sorted(PACK.glob("*.ql")):
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", path.read_text(encoding="utf-8")):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    return found


def test_go_columns_mirror_cpp_and_equal_the_ql_query_predicates() -> None:
    cpp = COLUMNS["languages"]["cpp"]
    assert GO["pack_root"] == "go" and GO["query_pack"] == "appsec-review/graph-export-go"
    assert GO["query_pack"] == CATALOG_DOC["languages"]["go"]["export_pack"]
    shape = lambda section: [(q["query_id"], q["query_file"], q["result_set"], q.get("family"),
                              [(col["name"], col["type"]) for col in q["columns"]]) for q in section["queries"]]
    assert shape(GO) == shape(cpp)
    assert export_columns("go") == export_columns("cpp")
    predicates = _query_predicates()
    assert sorted(predicates) == sorted(q["query_id"] for q in GO["queries"])
    for query in GO["queries"]:
        assert all(column["meaning"] for column in query["columns"])
        assert predicates[query["query_id"]] == (
            query["query_file"], [(column["type"], column["name"]) for column in query["columns"]])
    suite = (PACK / "graph-export.qls").read_text(encoding="utf-8")
    assert sorted(re.findall(r"- query: (\S+)", suite)) == sorted({q["query_file"] for q in GO["queries"]})
    for path in PACK.glob("*.ql"):
        text = path.read_text(encoding="utf-8")
        assert "LIVE-UNVERIFIED" in text and "@kind table" in text and "select " not in text
        assert f"@id appsec-review/graph-export/go/" in text
    qlpack = (PACK / "qlpack.yml").read_text(encoding="utf-8")
    assert "name: appsec-review/graph-export-go" in qlpack and "version: 1.0.0" in qlpack
    assert "codeql/go-all" in qlpack


def test_go_pack_declares_the_scope_externals_and_restricts_every_query_by_exported() -> None:
    library = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
    assert "external predicate exportScope(string mode, int depth);" in library
    assert "external predicate exportSeed(string path, int startLine, int endLine);" in library
    for name in ("seedFunction", "near", "exported", "wholeProgram"):
        assert re.search(rf"\bpredicate {name}\(", library), name
    assert "exportedCall(call)" in library and "exportedNode(n)" in library
    for name in ("CallSites.ql", "FlowSummaries.ql"):
        assert "GraphExport::exported(" in (PACK / name).read_text(encoding="utf-8"), name
    assert "GraphExport::exportedNode(n)" in (PACK / "Paths.ql").read_text(encoding="utf-8")
    for name in ("Seeds.ql", "Neighborhood.ql"):
        assert "not GraphExport::wholeProgram()" in (PACK / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- catalog


def _rules(kind: str) -> list[dict]:
    return CATALOG_DOC["languages"]["go"][kind]


def _ql_triples(predicate: str) -> set[tuple[str, str, int]]:
    text = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
    body = text.split(f"predicate {predicate}(", 1)[1].split("\n  }\n", 1)[0]
    return {(pkg, name, int(index)) for pkg, name, index in
            re.findall(r'pkg = "([\w/.]+)" and name = "(\w+)" and arg = (-?\d+)', body)}


def test_go_catalog_validates_and_its_rules_are_unique() -> None:
    Draft202012Validator(SCHEMA).validate(CATALOG_DOC)
    language = CATALOG_DOC["languages"]["go"]
    assert language["model_library"] == "codeql/go-all"
    rule_ids = [rule["rule_id"] for kind in ("sinks", "sources", "sanitizers") for rule in _rules(kind)]
    assert len(rule_ids) == len(set(rule_ids)) and all(rule_id.startswith("go.") for rule_id in rule_ids)
    for kind in ("sinks", "sources"):
        matches = [json.dumps(rule["match"], sort_keys=True) for rule in _rules(kind)]
        assert len(matches) == len(set(matches)), f"duplicate {kind} match"


def test_go_catalog_api_and_model_rules_equal_what_the_queries_can_emit() -> None:
    sink_api = {(rule["match"]["declared_in"][0], rule["match"]["api"], rule["match"]["argument_index"])
                for rule in _rules("sinks") if "api" in rule["match"]}
    source_api = {(rule["match"]["declared_in"][0], rule["match"]["api"], rule["match"]["index"])
                  for rule in _rules("sources") if "api" in rule["match"]}
    assert sink_api == _ql_triples("apiSinkArgument")
    assert source_api == _ql_triples("apiSourceArgument")
    library = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
    body = library.split("predicate sanitizerApi(", 1)[1].split("\n  }\n", 1)[0]
    pairs = set(re.findall(r'pkg = "([\w/.]+)" and name = "(\w+)"', body))
    assert pairs == {(rule["declared_in"][0], rule["api"]) for rule in _rules("sanitizers")}
    emitted_sink_models = set(re.findall(r'model = "([\w.:]+)"', library.split("private predicate modelOperand(")[1]
                                         .split("\n  }\n", 1)[0]))
    schema_models = SCHEMA["$defs"]["models_go"]["properties"]
    assert emitted_sink_models == set(schema_models["sinks"]["items"]["properties"]["match"]["properties"]
                                      ["model"]["enum"])
    catalog_models = {rule["match"]["model"] for rule in _rules("sinks") if "model" in rule["match"]}
    assert catalog_models < emitted_sink_models
    assert emitted_sink_models - catalog_models == {"UnmarshalingFunction"}
    source_body = library.split("predicate source(", 1)[1].split("\n  }\n", 1)[0]
    emitted_source_models = set(re.findall(r'model = "(\w+)"', source_body)) - {"api"}
    assert emitted_source_models == set(schema_models["sources"]["items"]["properties"]["match"]["properties"]
                                        ["model"]["enum"])
    assert {rule["match"]["model"] for rule in _rules("sources") if "model" in rule["match"]} == emitted_source_models


@pytest.mark.parametrize("mutate", [
    lambda doc: doc["languages"]["go"]["sinks"][-1]["match"].update(model="SomethingElse"),
    lambda doc: doc["languages"]["go"]["sources"][1]["match"].update(model="LocalFlowSource"),
    lambda doc: doc["languages"]["go"]["sinks"][0].update(sink_class="unclassified"),
])
def test_go_schema_rejects_an_unknown_model_or_class(mutate) -> None:
    document = copy.deepcopy(CATALOG_DOC)
    mutate(document)
    with pytest.raises(ValidationError):
        Draft202012Validator(SCHEMA).validate(document)


# --------------------------------------------------------------------------- fixture


def test_recording_meets_every_expectation_and_every_case_is_stated() -> None:
    document = load_expectations(FIXTURE)
    assert document["fixture"] == "go-synthetic"
    assert unmet(_exports(), document) == []
    provenance = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["fixture"] == "go-synthetic" and provenance["recording"] == "hand-authored"
    assert set(provenance["cases"]) == {item["case"] for item in document["expectations"]}
    manifest = json.loads((FIXTURE / "exports" / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["language"] == "go" and manifest["pack"]["query_id"] == "graph-export-go"
    assert {item["query_id"] for item in manifest["exports"]} == {q["query_id"] for q in GO["queries"]}


def test_recording_rows_lie_inside_the_source() -> None:
    lines = (FIXTURE / "source" / "main.go").read_text(encoding="utf-8").split("\n")
    for query_id, document in _exports().items():
        for row in document["rows"]:
            values = dict(zip(document["columns"], row))
            for name, value in values.items():
                if name.endswith("_path") and value:
                    prefix = name[:-len("_path")]
                    line = values[f"{prefix}_start_line"]
                    assert value == "main.go" and 1 <= line <= len(lines), (query_id, name, row)
                    end = values.get(f"{prefix}_end_column")
                    if end is not None and values[f"{prefix}_end_line"] == line:
                        assert end <= len(lines[line - 1]), (query_id, name, row)


def test_normalize_produces_every_family_from_the_go_recording(normalized) -> None:
    produced = normalized.to_json()
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(produced)
    assert GOLDEN.read_bytes() == produced
    counts = {family.value: len(_family(normalized, family.value)) for family in c.Family}
    assert counts == {"call_site": 33, "sink_site": 9, "entry_point": 5, "flow_summary": 5, "dataflow_path": 5,
                      "guard_fact": 10, "range_fact": 9}
    assert set(FAMILY_QUERIES) == set(c.Family)
    for fact in normalized.facts:
        assert fact.to_entity().payload["admissibility"] == c.admissibility(fact.payload)
    for family in ("call_site", "sink_site", "entry_point", "flow_summary", "dataflow_path"):
        assert normalized.coverage_for(family).status in (c.Coverage.COMPLETE, c.Coverage.PARTIAL)


def test_go_sinks_and_sources_are_classified_through_the_catalog(normalized) -> None:
    classes = {fact.location.start_line: fact.payload["result"]["sink_class"]
               for fact in _family(normalized, "sink_site")}
    assert classes == {42: "sql_query", 49: "command_execution", 50: "path_access", 52: "server_side_request",
                       53: "deserialization", 56: "allocation_size", 58: "allocation_size", 60: "unclassified",
                       69: "command_execution"}
    sources = sorted((fact.location.start_line, fact.payload["result"]["source_class"])
                     for fact in _family(normalized, "entry_point"))
    assert sources == [(47, "remote"), (53, "remote"), (54, "remote"), (69, "argv"), (69, "environment")]
    [sql] = _at_line(normalized, "dataflow_path", 42)
    assert sql.payload["result"]["source"]["source_class"] == "remote"
    assert sql.payload["result"]["call_depth"] == 2 and sql.payload["result"]["sink"]["cwe_family"] == "CWE-89"
    [opened] = _at_line(normalized, "dataflow_path", 50)
    assert [item["api"] for item in opened.payload["result"]["sanitizers"]] == ["Clean"]


def test_go_guards_ranges_calls_and_summaries_normalize(normalized) -> None:
    states = sorted((fact.location.start_line, fact.payload["result"]["guard_state"])
                    for fact in _family(normalized, "guard_fact"))
    assert (55, "dominating") in states and (55, "non_dominating") in states
    assert sum(state == "none" for _, state in states) == 8
    [bounded] = [fact for fact in _family(normalized, "range_fact")
                 if fact.payload["result"]["interval"] and fact.payload["result"]["interval"]["upper"] == 99]
    assert bounded.payload["result"]["type"] == {"display": "int", "signed": True, "bits": 64}
    [converted] = [fact for fact in _family(normalized, "range_fact") if fact.payload["result"]["conversions"]]
    assert [item["kind"] for item in converted.payload["result"]["conversions"]] == ["narrowing", "promotion"]
    assert sum(fact.payload["result"]["applicability"] == "not_applicable"
               for fact in _family(normalized, "range_fact")) == 7
    dispatch = {(fact.payload["result"]["callee"]["display"], fact.payload["result"]["callee"]["dispatch"])
                for fact in _family(normalized, "call_site")}
    assert {("Upper::Handle", "virtual_resolved"), ("Lower::Handle", "virtual_resolved"),
            ("<indirect:fn>", "unresolved_indirect"), ("quote", "function_pointer_resolved"),
            ("Value::Call", "external_undefined")} <= dispatch
    symbols = {record.name: record for record in normalized.symbols}
    for name in ("Upper::Handle", "quote", "serve", "main", "Apply"):
        assert symbols[name].location is not None and symbols[name].payload["exact"] is True, name
    summaries = {fact.payload["result"]["function"]["display"]: fact.payload["result"]
                 for fact in _family(normalized, "flow_summary")}
    assert summaries["serve"]["sanitizes"] == ["Clean"]
    assert "Value::Call" in summaries["serve"]["opaque_calls"]
    assert {pair["to"]["kind"] for pair in summaries["quote"]["pairs"]} == {"return"}
