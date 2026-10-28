"""Python code-graph export pack (rules/codeql-graph-export/python) held offline to its contract.

The pack cannot run here; the hand-authored recording under
``tests/fixtures/graph/codeql_export/python-synthetic`` is what the pack is written to export over
``source/app.py``. These tests hold the QL text, columns.json, catalog.json and the schema to one
another, the recording to the semantic floor in ``expected-facts.json``, and the normalizer to a
golden output (``tests/fixtures/graph/expected/python-synthetic/normalized.json``; regenerate it with
``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`` after an intended rule change and review the diff).
tests/live/test_codeql_graph_export_python_live.py holds the pinned-image export to the same floor.
"""
from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import CATALOG_PATH, CATALOG_SCHEMA_PATH, CatalogError, load_catalog, validate_catalog
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import normalize_scope
from tests.fixtures.graph.expectations import load_expectations, unmet

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "rules" / "codeql-graph-export" / "python"
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "python-synthetic"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "python-synthetic" / "normalized.json"
COLUMNS = json.loads((ROOT / "rules" / "codeql-graph-export" / "columns.json").read_text(encoding="utf-8"))
QUERIES = COLUMNS["languages"]["python"]["queries"]
CATALOG_DOCUMENT = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
SECTION = CATALOG_DOCUMENT["languages"]["python"]
LIBRARY = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
TARGET_PATH = "src/app.py"
SOURCE_BYTES = (FIXTURE / "source" / "app.py").read_bytes()
SOURCE = SourceFile.from_bytes(SOURCE_BYTES)
SCOPE = {"scope_id": "codeql-unit-python-synthetic", "language": "python", "build_unit_id": "python-synthetic",
         "component_id": "component:python-synthetic", "root": "src",
         "files": [{"path": TARGET_PATH, "sha256": SOURCE.sha256}]}
SOURCE_MODELS = {"RemoteFlowSource", "ThreatModelSource"}


def _exports() -> dict[str, dict[str, Any]]:
    loaded = load_graph_exports(FIXTURE / "exports", bytes_limit=c.GraphSettings().max_export_bytes)
    return json.loads(json.dumps(loaded))


def _query_predicates() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    found = {}
    for path in sorted(PACK.glob("*.ql")):
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", path.read_text(encoding="utf-8")):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    return found


def _ql_triples(predicate: str) -> set[tuple[str, str, int]]:
    body = LIBRARY.split(f"predicate {predicate}(", 1)[1].split("}", 1)[0]
    return {(module, name, int(arg)) for module, name, arg in
            re.findall(r'mod = "([\w.]+)" and name = "(\w+)" and arg = (-?\d+)', body)}


@pytest.fixture(scope="module")
def normalized():
    return normalize_scope(_exports(), scope=SCOPE, target_snapshot="target-sha256:" + "3" * 64,
                           sources={TARGET_PATH: SOURCE}, catalog=load_catalog(), settings=c.GraphSettings(),
                           tool_version="2.27.0", export_pack_sha256="e" * 64)


def _family(result, family: str) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family.value == family]


# --------------------------------------------------------------------------- pack, columns, catalog


def test_columns_equal_the_ql_query_predicates_and_the_suite_lists_every_query() -> None:
    cpp = {query["query_id"]: [column["name"] for column in query["columns"]]
           for query in COLUMNS["languages"]["cpp"]["queries"]}
    assert {query["query_id"]: [column["name"] for column in query["columns"]] for query in QUERIES} == cpp
    predicates = _query_predicates()
    assert sorted(predicates) == sorted(cpp)
    for query in QUERIES:
        query_file, params = predicates[query["query_id"]]
        assert query_file == query["query_file"] and query["result_set"] == query["query_id"]
        assert params == [(column["type"], column["name"]) for column in query["columns"]]
    suite = (PACK / "graph-export.qls").read_text(encoding="utf-8")
    assert sorted(re.findall(r"- query: (\w+\.ql)", suite)) == sorted({query["query_file"] for query in QUERIES})
    qlpack = (PACK / "qlpack.yml").read_text(encoding="utf-8")
    assert "name: appsec-review/graph-export-python" in qlpack and "version: 1.0.0" in qlpack
    assert "codeql/python-all: 7.2.5" in qlpack


def test_seeded_scope_matches_the_cpp_external_predicates() -> None:
    for text in ("external predicate exportScope(string mode, int depth);",
                 "external predicate exportSeed(string path, int startLine, int endLine);",
                 "predicate seedFunction(", "predicate near(", "predicate exported(", "predicate wholeProgram(",
                 "exportedNode(DataFlow::Node n)"):
        assert text in LIBRARY, text
    for name in ("CallSites.ql", "FlowSummaries.ql"):
        assert "GraphExport::exported(" in (PACK / name).read_text(encoding="utf-8")
    assert "GraphExport::exportedNode(n)" in (PACK / "Paths.ql").read_text(encoding="utf-8")
    for name in ("Seeds.ql", "Neighborhood.ql"):
        assert "not GraphExport::wholeProgram()" in (PACK / name).read_text(encoding="utf-8")


def test_catalog_api_and_model_rules_equal_what_the_queries_can_emit() -> None:
    validate_catalog(CATALOG_DOCUMENT)
    assert SECTION["model_library"] == "codeql/python-all"

    def api_rules(kind: str, index_key: str) -> set[tuple[str, str, int]]:
        return {(module, rule["match"]["api"], rule["match"][index_key]) for rule in SECTION[kind]
                if "api" in rule["match"] for module in rule["match"]["declared_in"]}

    assert api_rules("sinks", "argument_index") == _ql_triples("apiSinkArgument")
    assert api_rules("sources", "index") == _ql_triples("apiSourceArgument")
    body = LIBRARY.split("predicate sanitizerApi(", 1)[1].split("}", 1)[0]
    assert set(re.findall(r'mod = "([\w.]+)" and name = "(\w+)"', body)) == {
        (module, rule["api"]) for rule in SECTION["sanitizers"] for module in rule["declared_in"]}
    emitted = set(re.findall(r'model = "([\w.]+)"', LIBRARY)) - {"api"}
    sink_models = {rule["match"]["model"] for rule in SECTION["sinks"] if "model" in rule["match"]}
    assert sink_models < emitted - SOURCE_MODELS
    assert emitted - SOURCE_MODELS - sink_models == {"NoSqlExecution"}
    assert {rule["match"]["model"] for rule in SECTION["sources"] if "model" in rule["match"]} == SOURCE_MODELS
    schema = json.loads(CATALOG_SCHEMA_PATH.read_text(encoding="utf-8"))
    models = schema["$defs"]["models_python"]["properties"]
    assert set(models["sinks"]["items"]["properties"]["match"]["properties"]["model"]["enum"]) == emitted - SOURCE_MODELS
    assert set(models["sources"]["items"]["properties"]["match"]["properties"]["model"]["enum"]) == SOURCE_MODELS


@pytest.mark.parametrize("kind", ["sinks", "sources"])
def test_the_python_schema_rejects_an_unknown_model(kind: str) -> None:
    document = copy.deepcopy(CATALOG_DOCUMENT)
    rule = next(rule for rule in document["languages"]["python"][kind] if "model" in rule["match"])
    rule["match"]["model"] = "UnknownConcept"
    with pytest.raises(CatalogError, match="schema"):
        validate_catalog(document)


# --------------------------------------------------------------------------- recording


def test_the_recording_loads_and_meets_every_expectation() -> None:
    exports = _exports()
    manifest = json.loads((FIXTURE / "exports" / "export-manifest.json").read_text(encoding="utf-8"))
    assert manifest["language"] == "python" and manifest["pack"]["query_id"] == "graph-export-python"
    assert sorted(exports) == sorted(query["query_id"] for query in QUERIES)
    for query in QUERIES:
        assert exports[query["query_id"]]["columns"] == [column["name"] for column in query["columns"]]
    expectations = load_expectations(FIXTURE)
    assert expectations["fixture"] == "python-synthetic"
    assert unmet(exports, expectations) == []
    provenance = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["fixture"] == "python-synthetic" and provenance["recording"] == "hand-authored"
    assert set(provenance["cases"]) == {item["case"] for item in expectations["expectations"]}


def test_the_matcher_reports_a_missing_python_row() -> None:
    exports = _exports()
    exports["call_sites"]["rows"] = [row for row in exports["call_sites"]["rows"] if row[5] != 82]
    assert [message.split(":")[0] for message in unmet(exports, load_expectations(FIXTURE))] == [
        "unresolved_reflective_call"]


def test_every_recorded_location_lies_inside_the_source() -> None:
    lines = SOURCE_BYTES.decode("utf-8").split("\n")
    for document in _exports().values():
        rows = [dict(zip(document["columns"], row)) for row in document["rows"]]
        for row in rows:
            for prefix in ("sink", "operand", "source", "call", "from", "to", "condition", "lhs", "rhs", "sanitizer"):
                if row.get(f"{prefix}_path") == "app.py":
                    line, start, end = row[f"{prefix}_start_line"], row[f"{prefix}_start_column"], \
                        row[f"{prefix}_end_column"]
                    assert row[f"{prefix}_end_line"] == line and 1 <= start <= end <= len(lines[line - 1])


# --------------------------------------------------------------------------- normalization


def test_normalization_matches_the_golden_output(normalized) -> None:
    produced = normalized.to_json()
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(produced)
    assert GOLDEN.read_bytes() == produced


def test_normalization_produces_every_family_with_catalog_classes(normalized) -> None:
    counts = {family.value: len(_family(normalized, family.value)) for family in c.Family}
    assert all(counts[family] > 0 for family in ("call_site", "sink_site", "entry_point", "flow_summary",
                                                  "dataflow_path", "guard_fact", "range_fact")), counts
    for fact in normalized.facts:
        entity = fact.to_entity()
        assert entity.payload["admissibility"] == c.admissibility(fact.payload)
    sink_classes = {(fact.location.start_line, fact.payload["result"]["sink_class"])
                    for fact in _family(normalized, "sink_site")}
    assert {(18, "sql_query"), (32, "command_execution"), (40, "path_access"), (47, "server_side_request"),
            (53, "deserialization"), (34, "html_output"), (59, "unclassified")} <= sink_classes
    source_classes = {(fact.location.start_line, fact.payload["result"]["source_class"])
                      for fact in _family(normalized, "entry_point")}
    assert {(23, "remote"), (87, "argv"), (88, "local_user"), (89, "environment")} <= source_classes


def test_ranges_are_published_as_a_named_not_applicable_gap(normalized) -> None:
    ranges = _family(normalized, "range_fact")
    assert ranges and all(fact.payload["result"]["applicability"] == "not_applicable" for fact in ranges)
    assert all(fact.payload["result"]["interval"] is None for fact in ranges)
    assert all(any(gap.startswith("not_applicable:") for gap in fact.payload["gaps"]) for fact in ranges)


def test_method_symbols_sit_on_the_defining_name(normalized) -> None:
    by_name = {item.name: item for item in normalized.symbols}
    for name, text in (("run_query", b"run_query"), ("Handler.handle", b"handle"), ("Upper.run", b"run"),
                       ("Handler.__init__", b"__init__")):
        symbol = by_name[name]
        assert SOURCE_BYTES[symbol.location.start_byte:symbol.location.end_byte] == text
        assert symbol.payload["exact"] is True
