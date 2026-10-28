"""Rust code-graph export (appsec-review/graph-export-rust): pack, catalog and offline recording.

The hand-authored recording under tests/fixtures/graph/codeql_export/rust-synthetic is held to the
fixture's expected-facts.json (the same floor the live tier applies to a pinned-image export) and
normalized against its source staged under the target path ``crate/`` with CodeQL scope root
``crate``. The golden output lives in tests/fixtures/graph/expected/rust-synthetic/normalized.json;
regenerate it with ``APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN=1`` after an intended rule change and
review the diff.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from appsec_review.codeql.runtime import load_graph_exports
from appsec_review.graph import contract as c
from appsec_review.graph.catalog import load_catalog
from appsec_review.graph.crosscheck import SourceFile
from appsec_review.graph.normalize import FAMILY_QUERIES, export_columns, normalize_scope
from tests.fixtures.graph.expectations import load_expectations, unmet

ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = ROOT / "rules" / "codeql-graph-export"
PACK = PACK_ROOT / "rust"
FIXTURE = ROOT / "tests" / "fixtures" / "graph" / "codeql_export" / "rust-synthetic"
GOLDEN = ROOT / "tests" / "fixtures" / "graph" / "expected" / "rust-synthetic" / "normalized.json"
COLUMNS = json.loads((PACK_ROOT / "columns.json").read_text(encoding="utf-8"))
CATALOG = json.loads((PACK_ROOT / "catalog.json").read_text(encoding="utf-8"))
QUERIES = COLUMNS["languages"]["rust"]["queries"]
SCOPE_REPORT_QUERIES = {"seed_functions", "neighborhood"}
LIBRARY = (PACK / "GraphExport.qll").read_text(encoding="utf-8")
SOURCE_FILES = ("src/main.rs", "vendor/reqwest/src/lib.rs", "vendor/rusqlite/src/lib.rs",
                "vendor/serde_json/src/lib.rs")
SOURCES = {f"crate/{path}": SourceFile.from_bytes((FIXTURE / "source" / path).read_bytes())
           for path in SOURCE_FILES}
SCOPE = {"scope_id": "codeql-unit-rust-synthetic", "language": "rust", "build_unit_id": "rust-synthetic",
         "component_id": "component:rust-synthetic", "root": "crate",
         "files": [{"path": path, "sha256": source.sha256} for path, source in SOURCES.items()]}


def _runner():
    spec = importlib.util.spec_from_file_location(
        "appsec_review_codeql_export_runner_rust", ROOT / "containers" / "tools" / "codeql" / "codeql_runner.py")
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
    return CATALOG["languages"]["rust"][kind]


@pytest.fixture(scope="module")
def normalized():
    return normalize_scope(_exports(), scope=SCOPE, target_snapshot="target-sha256:" + "3" * 64,
                           sources=SOURCES, catalog=load_catalog(), settings=c.GraphSettings(),
                           tool_version="2.27.0", export_pack_sha256="e" * 64)


def _family(result, family: str) -> list[c.GraphFact]:
    return [fact for fact in result.facts if fact.family.value == family]


# --------------------------------------------------------------------------- pack and columns


def _query_predicates() -> dict[str, tuple[str, list[tuple[str, str]]]]:
    found = {}
    for path in sorted(PACK.glob("*.ql")):
        for name, params in re.findall(r"query predicate (\w+)\(([^)]*)\)", path.read_text(encoding="utf-8")):
            found[name] = (path.name, [tuple(item.split()) for item in params.split(",") if item.strip()])
    return found


def test_columns_contract_equals_the_ql_query_predicates_and_the_cpp_shape() -> None:
    runner = _runner()
    assert runner.export_queries(COLUMNS, "rust") == QUERIES
    cpp = COLUMNS["languages"]["cpp"]["queries"]
    assert [query["query_id"] for query in QUERIES] == [query["query_id"] for query in cpp]
    for ours, theirs in zip(QUERIES, cpp):
        assert [(col["name"], col["type"]) for col in ours["columns"]] == [
            (col["name"], col["type"]) for col in theirs["columns"]], ours["query_id"]
        assert ours.get("family") == theirs.get("family") and ours["query_file"] == theirs["query_file"]
    assert set(export_columns("rust")) == {query["query_id"] for query in QUERIES}
    predicates = _query_predicates()
    assert sorted(predicates) == sorted(query["query_id"] for query in QUERIES)
    for query in QUERIES:
        assert predicates[query["query_id"]] == (
            query["query_file"], [(column["type"], column["name"]) for column in query["columns"]])
    suite = (PACK / "graph-export.qls").read_text(encoding="utf-8")
    assert sorted(re.findall(r"- query: (\S+)", suite)) == sorted({query["query_file"] for query in QUERIES})
    for path in PACK.glob("*.ql"):
        text = path.read_text(encoding="utf-8")
        assert "LIVE-UNVERIFIED" in text and "@kind table" in text and "select " not in text
    qlpack = (PACK / "qlpack.yml").read_text(encoding="utf-8")
    assert "name: appsec-review/graph-export-rust" in qlpack and "version: 1.0.0" in qlpack
    assert "codeql/rust-all" in qlpack


def test_pack_declares_the_scope_externals_and_restricts_every_query_by_exported() -> None:
    assert "external predicate exportScope(string mode, int depth);" in LIBRARY
    assert "external predicate exportSeed(string path, int startLine, int endLine);" in LIBRARY
    for name in ("seedFunction", "near", "exported", "wholeProgram", "exportedExpr", "exportedNode"):
        assert re.search(rf"\bpredicate {name}\(", LIBRARY), name
    for name in ("CallSites.ql", "FlowSummaries.ql"):
        assert "GraphExport::exported(" in (PACK / name).read_text(encoding="utf-8"), name
    assert "GraphExport::exportedNode(n)" in (PACK / "Paths.ql").read_text(encoding="utf-8")
    for name in ("Seeds.ql", "Neighborhood.ql"):
        assert "not GraphExport::wholeProgram()" in (PACK / name).read_text(encoding="utf-8"), name


# --------------------------------------------------------------------------- catalog


def _ql_pairs(predicate: str) -> set[tuple[str, int]]:
    body = LIBRARY.split(f"predicate {predicate}(", 1)[1].split("}", 1)[0]
    return {(name, int(index)) for name, index in re.findall(r'name = "(\w+)" and arg = (-?\d+)', body)}


def _ql_strings(predicate: str) -> set[str]:
    body = LIBRARY.split(f"predicate {predicate}(", 1)[1].split("}", 1)[0]
    return set(re.findall(r'"([\w:.-]+)"', body))


def test_catalog_api_and_model_rules_equal_what_the_queries_can_emit() -> None:
    sink_api = {(rule["match"]["api"], rule["match"]["argument_index"]) for rule in _rules("sinks")
                if "api" in rule["match"]}
    source_api = {(rule["match"]["api"], rule["match"]["index"]) for rule in _rules("sources")
                  if "api" in rule["match"]}
    assert sink_api == _ql_pairs("apiSinkArgument")
    assert source_api == _ql_pairs("apiSourceArgument")
    assert {name for rule in _rules("sinks") if "api" in rule["match"]
            for name in rule["match"]["declared_in"]} == _ql_strings("apiSinkModule")
    assert {name for rule in _rules("sources") if "api" in rule["match"]
            for name in rule["match"]["declared_in"]} == _ql_strings("apiSourceModule")
    assert {rule["api"] for rule in _rules("sanitizers")} == _ql_strings("sanitizerApi")
    model_sinks = {rule["match"]["model"] for rule in _rules("sinks") if "model" in rule["match"]}
    assert model_sinks == _ql_strings("sinkModelKind")
    schema = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
    models = schema["$defs"]["models_rust"]["properties"]
    assert set(models["sinks"]["items"]["properties"]["match"]["properties"]["model"]["enum"]) == model_sinks
    assert set(models["sources"]["items"]["properties"]["match"]["properties"]["model"]["enum"]) == {
        rule["match"]["model"] for rule in _rules("sources") if "model" in rule["match"]}


def test_catalog_validates_and_models_rust_rejects_an_unknown_model() -> None:
    schema = json.loads((PACK_ROOT / "catalog.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.validate(CATALOG)
    for kind in ("sinks", "sources"):
        document = copy.deepcopy(CATALOG)
        rule = next(rule for rule in document["languages"]["rust"][kind] if "model" in rule["match"])
        rule["match"]["model"] = "SomethingElse"
        with pytest.raises(ValidationError):
            validator.validate(document)
    document = copy.deepcopy(CATALOG)
    document["languages"]["rust"]["sinks"][0]["sink_class"] = "unclassified"
    with pytest.raises(ValidationError):
        validator.validate(document)


# --------------------------------------------------------------------------- recording


def test_recording_meets_every_expectation_and_every_case_is_expected() -> None:
    exports = _exports()
    assert sorted(exports) == sorted(query["query_id"] for query in QUERIES)
    document = load_expectations(FIXTURE)
    assert document["fixture"] == "rust-synthetic"
    assert unmet(exports, document) == []
    cases = json.loads((FIXTURE / "provenance.json").read_text(encoding="utf-8"))["cases"]
    assert {item["case"] for item in document["expectations"]} == set(cases)


def test_recorded_locations_resolve_against_the_fixture_source() -> None:
    by_id = {query["query_id"]: query for query in QUERIES}
    for query_id, document in _exports().items():
        assert document["columns"] == [column["name"] for column in by_id[query_id]["columns"]]
        names = document["columns"]
        for row in document["rows"]:
            for prefix in {name[:-5] for name in names if name.endswith("_path")}:
                path = row[names.index(f"{prefix}_path")]
                line = row[names.index(f"{prefix}_start_line")]
                if path == "":
                    assert line == 0
                    continue
                lines = (FIXTURE / "source" / path).read_text(encoding="utf-8").split("\n")
                column = row[names.index(f"{prefix}_start_column")]
                assert 1 <= line <= len(lines) and 1 <= column <= len(lines[line - 1]), (query_id, prefix, row)
                if f"{prefix}_end_line" in names:
                    end_line, end_column = row[names.index(f"{prefix}_end_line")], row[names.index(f"{prefix}_end_column")]
                    assert (end_line, end_column) >= (line, column) and end_column <= len(lines[end_line - 1])


def test_the_fixture_crate_is_offline_resolvable() -> None:
    lock = (FIXTURE / "source" / "Cargo.lock").read_text(encoding="utf-8")
    manifest = (FIXTURE / "source" / "Cargo.toml").read_text(encoding="utf-8")
    assert "source = " not in lock, "every locked package must be a path package"
    for name in ("reqwest", "rusqlite", "serde_json"):
        assert f'name = "{name}"' in lock and f'path = "vendor/{name}"' in manifest
        assert (FIXTURE / "source" / "vendor" / name / "Cargo.toml").is_file()


# --------------------------------------------------------------------------- normalization


def test_rust_recording_normalizes_into_every_family(normalized) -> None:
    counts = Counter(fact.family.value for fact in normalized.facts)
    assert set(counts) == {family.value for family in c.Family}
    assert set(FAMILY_QUERIES) == {family.value for family in c.Family}
    assert dict(counts) == {"call_site": 41, "sink_site": 7, "entry_point": 5, "flow_summary": 7,
                            "dataflow_path": 7, "guard_fact": 7, "range_fact": 7}
    sinks = Counter(fact.payload["result"]["sink_class"] for fact in _family(normalized, "sink_site"))
    assert sinks == {"command_execution": 2, "path_access": 2, "sql_query": 1, "server_side_request": 1,
                     "deserialization": 1}
    sources = Counter(fact.payload["result"]["source_class"] for fact in _family(normalized, "entry_point"))
    assert sources == {"remote": 1, "argv": 1, "environment": 1, "file": 2}
    pairs = {(fact.payload["result"]["source"]["source_class"], fact.payload["result"]["sink"]["sink_class"])
             for fact in _family(normalized, "dataflow_path")}
    assert pairs == {("remote", "sql_query"), ("remote", "command_execution"), ("remote", "server_side_request"),
                     ("remote", "deserialization"), ("argv", "command_execution"), ("argv", "path_access"),
                     ("environment", "path_access")}
    for fact in normalized.facts:
        entity = fact.to_entity()
        assert entity.payload["admissibility"] == c.admissibility(fact.payload)
        assert fact.payload["scope"]["language"] == "rust"


def test_guards_ranges_dispatch_and_sanitizers_are_published_honestly(normalized) -> None:
    states = Counter(fact.payload["result"]["guard_state"] for fact in _family(normalized, "guard_fact"))
    assert states == {"dominating": 1, "none": 6}
    ranges = _family(normalized, "range_fact")
    assert {fact.payload["result"]["applicability"] for fact in ranges} == {"not_applicable"}
    assert all(fact.payload["gaps"] for fact in ranges), "not_applicable is a named gap, never clean"
    calls = [fact.payload["result"]["callee"] for fact in _family(normalized, "call_site")]
    assert Counter(call["dispatch"] for call in calls)["virtual_resolved"] == 2
    assert any(call["dispatch"] == "unresolved_indirect" for call in calls)
    coverage = {row.family.value: row for row in normalized.coverage}
    assert coverage["call_site"].status is c.Coverage.PARTIAL
    sanitized = [fact for fact in _family(normalized, "sink_site")
                 if fact.payload["result"]["dominating_sanitizer_count"] == 1]
    assert len(sanitized) == 1 and sanitized[0].payload["result"]["sink_class"] == "path_access"
    summaries = {fact.payload["result"]["function"]["display"]: fact.payload["result"]
                 for fact in _family(normalized, "flow_summary")}
    assert {"kind": "return", "index": -1} == {
        key: summaries["rust_synthetic::as_owned"]["pairs"][0]["to"][key] for key in ("kind", "index")}


def test_rust_fixture_matches_the_golden_output(normalized) -> None:
    produced = normalized.to_json()
    if os.environ.get("APPSEC_REVIEW_REGENERATE_GRAPH_GOLDEN") == "1":
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_bytes(produced)
    assert GOLDEN.read_bytes() == produced
