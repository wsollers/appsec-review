"""Java/Kotlin code-graph export pack, catalog section and hand-authored recording.

The recording under ``tests/fixtures/graph/codeql_export/java-synthetic`` is normalized against its
source staged at ``src/app/*.java`` with CodeQL scope root ``src``. The golden output lives in
``tests/fixtures/graph/expected/java-synthetic/normalized.json``; regenerate it with
``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`` after an intended rule change and review the diff.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
import pytest

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.config import codeql as codeql_config
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import normalize_scope
from tests.fixtures.graph.expectations import load_expectations, unmet

ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = ROOT / "rules" / "codeql-graph-export"
PACK = PACK_ROOT / "java"
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "java-synthetic"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "java-synthetic" / "normalized.json"
COLUMNS = json.loads((PACK_ROOT / "columns.json").read_text(encoding="utf-8"))
CATALOG_DOC = json.loads((PACK_ROOT / "catalog.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
LIBRARY = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
SOURCES = {f"src/app/{path.name}": SourceFile.from_bytes(path.read_bytes())
           for path in sorted((FIXTURE / "source" / "app").glob("*.java"))}
SCOPE = {"scope_id": "codeql-unit-java-synthetic", "language": "java", "build_unit_id": "java-synthetic",
         "component_id": "component:java-synthetic", "root": "src",
         "files": [{"path": path, "sha256": source.sha256} for path, source in SOURCES.items()]}


def _exports() -> dict[str, dict[str, Any]]:
    loaded = load_graph_exports(FIXTURE / "exports", bytes_limit=c.GraphSettings().max_export_bytes)
    return json.loads(json.dumps(loaded))


def _rules(kind: str) -> list[dict]:
    return CATALOG_DOC["languages"]["java"][kind]


def _body(predicate: str) -> str:
    return LIBRARY.split(f"predicate {predicate}(", 1)[1].split("\n  }\n", 1)[0]


def _ql_pairs(predicate: str) -> set[tuple[str, int]]:
    return {(name, int(index)) for name, index in re.findall(r'name = "(\w+)" and arg = (-?\d+)', _body(predicate))}


def _family(result, family: str) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family.value == family]


@pytest.fixture(scope="module")
def normalized():
    return normalize_scope(_exports(), scope=SCOPE, target_snapshot="target-sha256:" + "3" * 64, sources=SOURCES,
                           catalog=load_catalog(), settings=c.GraphSettings(), tool_version="2.27.0",
                           export_pack_sha256="e" * 64)


# --------------------------------------------------------------------------- pack and columns


def test_pack_declares_the_shared_query_ids_and_the_ql_columns_equal_the_contract() -> None:
    assert "java" in codeql_config._EXPORT_LANGUAGES
    queries = COLUMNS["languages"]["java"]["queries"]
    assert [query["query_id"] for query in queries] == [
        query["query_id"] for query in COLUMNS["languages"]["cpp"]["queries"]]
    found = {}
    for path in sorted(PACK.glob("*.ql")):
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", path.read_text(encoding="utf-8")):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    assert sorted(found) == sorted(query["query_id"] for query in queries)
    for query in queries:
        file_name, params = found[query["query_id"]]
        assert file_name == query["query_file"] and query["result_set"] == query["query_id"]
        assert [name for _, name in params] == [column["name"] for column in query["columns"]]
        assert [kind for kind, _ in params] == [column["type"] for column in query["columns"]]
    cpp = {query["query_id"]: [(column["name"], column["type"]) for column in query["columns"]]
           for query in COLUMNS["languages"]["cpp"]["queries"]}
    assert {query["query_id"]: [(column["name"], column["type"]) for column in query["columns"]]
            for query in queries} == cpp
    qlpack = (PACK / "qlpack.yml").read_text(encoding="utf-8")
    assert "name: appsec-review/graph-export-java" in qlpack and "version: 1.0.0" in qlpack
    assert "codeql/java-all" in qlpack
    suite = (PACK / "graph-export.qls").read_text(encoding="utf-8")
    assert {query["query_file"] for query in queries} <= set(re.findall(r"(\w+\.ql)", suite))
    for name in ("exportScope", "exportSeed"):
        assert f"external predicate {name}(" in LIBRARY


# --------------------------------------------------------------------------- catalog and schema


def test_catalog_validates_and_the_java_models_vocabulary_is_closed() -> None:
    Draft202012Validator(SCHEMA).validate(CATALOG_DOC)
    section = CATALOG_DOC["languages"]["java"]
    assert section["model_library"] == "codeql/java-all"
    assert section["export_pack"] == "appsec-review/graph-export-java"
    models = SCHEMA["$defs"]["models_java"]
    assert models != {"not": {}}
    for kind, rule in (("sinks", {"rule_id": "java.sink.model.bogus", "match": {"model": "bogus-injection"},
                                  "sink_class": "sql_query", "cwe_family": "CWE-89"}),
                       ("sources", {"rule_id": "java.source.model.bogus", "match": {"model": "BogusSource"},
                                    "source_class": "remote"})):
        document = copy.deepcopy(CATALOG_DOC)
        document["languages"]["java"][kind].append(rule)
        with pytest.raises(ValidationError):
            Draft202012Validator(SCHEMA).validate(document)


def test_catalog_api_and_model_rules_equal_what_the_queries_can_emit() -> None:
    sink_api = {(rule["match"]["api"], rule["match"]["argument_index"]) for rule in _rules("sinks")
                if "api" in rule["match"]}
    source_api = {(rule["match"]["api"], rule["match"]["index"]) for rule in _rules("sources")
                  if "api" in rule["match"]}
    assert sink_api == _ql_pairs("apiSinkArgument")
    assert source_api == _ql_pairs("apiSourceArgument")
    declared = set(re.findall(r'name = "(\w+)" and type = "([\w.$]+)"', _body("apiDeclaringType")))
    assert declared == {(rule["match"]["api"], type_name) for kind in ("sinks", "sources") for rule in _rules(kind)
                        if "api" in rule["match"] for type_name in rule["match"]["declared_in"]}
    assert set(re.findall(r'"(\w+)"', _body("sanitizerApi"))) == {rule["api"] for rule in _rules("sanitizers")}
    sink_kinds = set(re.findall(r'"([\w-]+)"', _body("sinkModelKind")))
    model_enum = lambda kind: set(SCHEMA["$defs"]["models_java"]["properties"][kind]["items"]["properties"]
                                  ["match"]["properties"]["model"]["enum"])
    assert sink_kinds == {rule["match"]["model"] for rule in _rules("sinks") if "model" in rule["match"]}
    assert sink_kinds == model_enum("sinks")
    emitted_source_models = set(re.findall(r'result = "(\w+)"', LIBRARY.split("string modelClass(", 1)[1]
                                           .split("\n  }\n", 1)[0]))
    assert emitted_source_models == model_enum("sources")
    assert {rule["match"]["model"] for rule in _rules("sources") if "model" in rule["match"]} == emitted_source_models


# --------------------------------------------------------------------------- recording


def test_recording_loads_and_meets_every_expectation() -> None:
    exports = _exports()
    assert unmet(exports, load_expectations(FIXTURE)) == []
    provenance = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))
    expected = json.loads((FIXTURE / "expected-facts.json").read_text(encoding="utf-8"))
    assert provenance["recording"] == "hand-authored"
    assert {case for case in provenance["cases"]} == {item["case"] for item in expected["expectations"]}


def test_normalized_recording_yields_every_family_with_catalog_classes(normalized) -> None:
    produced = normalized.to_json()
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(produced)
    assert GOLDEN.read_bytes() == produced
    counts = {family.value: len(_family(normalized, family.value)) for family in c.Family}
    assert counts == {"call_site": 52, "sink_site": 10, "entry_point": 5, "flow_summary": 7, "dataflow_path": 13,
                      "guard_fact": 11, "range_fact": 10}
    for fact in normalized.facts:
        entity = fact.to_entity()
        assert entity.payload["admissibility"] == c.admissibility(fact.payload)
    sinks = {(fact.location.path, fact.location.start_line): fact.payload["result"]["sink_class"]
             for fact in _family(normalized, "sink_site")}
    assert "unclassified" not in sinks.values()
    assert set(sinks.values()) == {"sql_query", "command_execution", "path_access", "server_side_request",
                                   "deserialization", "unsafe_reflection", "log_output"}
    assert sinks[("src/app/Server.java", 42)] == "sql_query"
    assert sinks[("src/app/Server.java", 62)] == "server_side_request"
    sources = {(fact.location.path, fact.location.start_line): fact.payload["result"]["source_class"]
               for fact in _family(normalized, "entry_point")}
    assert sources == {("src/app/Server.java", 25): "remote", ("src/app/Server.java", 34): "remote",
                       ("src/app/Handler.java", 15): "remote", ("src/app/Cli.java", 4): "argv",
                       ("src/app/Cli.java", 5): "environment"}
    paths = _family(normalized, "dataflow_path")
    assert {(path.payload["result"]["source"]["source_class"], path.payload["result"]["sink"]["sink_class"])
            for path in paths} >= {("argv", "command_execution"), ("environment", "server_side_request"),
                                   ("remote", "sql_query"), ("remote", "deserialization")}
    [sanitized] = [path for path in paths if path.location.start_line == 58]
    assert [item["api"] for item in sanitized.payload["result"]["sanitizers"]] == ["getCanonicalPath"]
    states = [fact.payload["result"]["guard_state"] for fact in _family(normalized, "guard_fact")
              if fact.payload["result"]["guard_state"] != "none"]
    assert sorted(states) == ["dominating", "non_dominating"]
    ranges = _family(normalized, "range_fact")
    assert {fact.payload["result"]["applicability"] for fact in ranges} == {"not_applicable"}
    assert all(any(gap.startswith("not_applicable") for gap in fact.payload["gaps"]) for fact in ranges)
    dispatch = {fact.payload["result"]["callee"]["dispatch"] for fact in _family(normalized, "call_site")}
    assert {"virtual_resolved", "unresolved_indirect", "external_undefined", "direct"} <= dispatch
